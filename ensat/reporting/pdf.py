"""Executive and technical PDF reports (ReportLab)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .. import __version__
from ..compare import compare_scans
from ..db import Database
from ..models import SEVERITIES, STATUSES
from ..risk import risk_index

SEV_COLOR = {
    "Critical": colors.HexColor("#7f1d1d"), "High": colors.HexColor("#c2410c"), "Medium": colors.HexColor("#b45309"),
    "Low": colors.HexColor("#1d4ed8"), "Info": colors.HexColor("#4b5563"),
}
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
RULE = colors.HexColor("#d1d5db")
HEAD_BG = colors.HexColor("#1f2937")
ZEBRA = colors.HexColor("#f3f4f6")


def e(value) -> str:
    """Escape any value for ReportLab's mini-markup."""
    return escape("" if value is None else str(value))


def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=ss["BodyText"], fontName="Helvetica", fontSize=9, leading=12, textColor=INK)
    return {
        "title": ParagraphStyle("t", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=24, spaceAfter=4),
        "subtitle": ParagraphStyle("st", parent=base, fontSize=10, textColor=MUTED, spaceAfter=10),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=16, spaceBefore=10, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=14, spaceBefore=6, spaceAfter=3),
        "body": base,
        "small": ParagraphStyle("sm", parent=base, fontSize=7.5, leading=9.5),
        "cell": ParagraphStyle("c", parent=base, fontSize=7.5, leading=9.5, alignment=TA_LEFT),
        "cellb": ParagraphStyle("cb", parent=base, fontName="Helvetica-Bold", fontSize=7.5, leading=9.5),
        "headline": ParagraphStyle("hl", parent=base, fontName="Helvetica-Bold", fontSize=12, leading=16, spaceAfter=6),
        "mono": ParagraphStyle("m", parent=base, fontName="Courier", fontSize=7, leading=9),
    }


def _table(rows, widths, header=True, zebra=True, font=7.5):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.25, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("FONTSIZE", (0, 0), (-1, -1), font), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), HEAD_BG), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    t.setStyle(TableStyle(style))
    return t


def _sev_cell(sev: str, st) -> Paragraph:
    return Paragraph(f'<font color="{SEV_COLOR.get(sev, INK).hexval()}"><b>{e(sev)}</b></font>', st["cell"])


def _footer(label: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(14 * mm, 9 * mm, f"ENSAT {__version__} | {label} | CONFIDENTIAL - authorized assessment")
        canvas.drawRightString(A4[0] - 14 * mm, 9 * mm, f"Page {doc.page}")
        canvas.setStrokeColor(RULE)
        canvas.line(14 * mm, 12 * mm, A4[0] - 14 * mm, 12 * mm)
        canvas.restoreState()
    return draw


def _severity_chart(counts: dict[str, int]) -> Drawing:
    sevs = SEVERITIES[:4]
    d = Drawing(170 * mm, 38 * mm)
    ch = HorizontalBarChart()
    ch.x, ch.y, ch.width, ch.height = 22 * mm, 4 * mm, 135 * mm, 32 * mm
    ch.data = [[counts.get(s, 0) for s in reversed(sevs)]]
    ch.categoryAxis.categoryNames = list(reversed(sevs))
    ch.categoryAxis.labels.fontName = "Helvetica"
    ch.categoryAxis.labels.fontSize = 8
    ch.valueAxis.valueMin = 0
    ch.valueAxis.valueMax = max(4, max(ch.data[0]) + 1)
    ch.valueAxis.labels.fontSize = 7
    ch.valueAxis.visibleGrid = True
    ch.valueAxis.gridStrokeColor = RULE
    ch.bars.strokeColor = None
    ch.barWidth = 6
    for i, s in enumerate(reversed(sevs)):
        ch.bars[(0, i)].fillColor = SEV_COLOR[s]
    d.add(ch)
    for i, s in enumerate(reversed(sevs)):
        n = counts.get(s, 0)
        step = ch.height / len(sevs)
        x = ch.x + ch.width * n / ch.valueAxis.valueMax + 2
        d.add(String(x, ch.y + step * i + step / 2 - 3, str(n), fontName="Helvetica-Bold", fontSize=8, fillColor=INK))
    return d


def _overall_rating(counts):
    for s in SEVERITIES[:4]:
        if counts.get(s):
            return s
    return "Low"


def _headline(counts) -> str:
    c, h = counts.get("Critical", 0), counts.get("High", 0)
    if c:
        return f"{c} critical {'vulnerability requires' if c == 1 else 'vulnerabilities require'} immediate remediation" + \
               (f", followed by {h} high-risk {'issue' if h == 1 else 'issues'}." if h else ".")
    if h:
        return f"No critical issues were found; {h} high-risk {'issue requires' if h == 1 else 'issues require'} prompt remediation."
    if counts.get("Medium"):
        return "No critical or high-risk issues were found; medium-risk issues should be scheduled for remediation."
    return "No significant security issues were identified in the assessed scope."


STRATEGY = {
    "vulnerability": "Establish a patch-management cadence: vulnerable software versions were identified (prioritise CISA KEV items first).",
    "exposure": "Reduce attack surface: restrict management, database and file-sharing services to trusted networks with firewall allow-lists.",
    "tls": "Standardise TLS: renew/replace weak or untrusted certificates and allow only TLS 1.2+.",
    "web": "Harden web applications: enforce HTTPS, add security headers and remove exposed files/default content.",
    "misconfiguration": "Fix insecure service configurations (anonymous access, missing authentication, legacy protocols).",
    "inventory": "Improve asset management: investigate newly discovered, unrecognised devices.",
}


def _scan_context(db: Database, scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise ValueError(f"Scan #{scan_id} not found")
    findings = db.scan_findings(scan_id)
    services = db.scan_services(scan_id)
    hosts = [h for h in db.scan_hosts(scan_id) if h["status"] == "up"]
    counts = db.severity_counts(scan_id)
    return scan, findings, services, hosts, counts


def _header(story, st, title, scan, hosts, services, findings):
    story.append(Paragraph(e(title), st["title"]))
    when = (scan.get("finished_at") or scan["started_at"])[:19].replace("T", " ")
    story.append(Paragraph(f"Target: <b>{e(scan['target'])}</b> &nbsp;|&nbsp; Scan #{scan['id']} &nbsp;|&nbsp; {e(when)} UTC "
                           f"&nbsp;|&nbsp; Profile: {e(scan.get('profile'))} &nbsp;|&nbsp; Operator: {e(scan.get('operator'))}", st["subtitle"]))


def _kpis(st, hosts, services, findings, counts):
    kev = sum(1 for f in findings if f["kev"])
    cves = len({f["cve"] for f in findings if f["cve"]})
    cells = [("Assets", len(hosts)), ("Open services", len(services)), ("Findings", sum(counts[s] for s in SEVERITIES[:4])),
             ("Unique CVEs", cves), ("CISA KEV", kev), ("Risk index", f"{risk_index(counts):.0f}")]
    row1 = [Paragraph(f'<font size="16"><b>{e(v)}</b></font>', st["body"]) for _, v in cells]
    row2 = [Paragraph(f'<font color="#6b7280">{e(k)}</font>', st["small"]) for k, _ in cells]
    t = Table([row1, row2], colWidths=[30 * mm] * 6)
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.25, RULE),
                           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return t


def _asset_rows(db: Database, hosts, findings):
    by_host: dict[str, list] = {}
    for f in findings:
        by_host.setdefault(f["host"], []).append(f)
    inv = {a["address"]: a for a in db.assets()}
    rows = []
    for h in hosts:
        fs = by_host.get(h["address"], [])
        top = max((f["risk_score"] for f in fs), default=0.0)
        a = inv.get(h["address"], {})
        rows.append({"address": h["address"], "hostname": h.get("hostname") or "", "os": h.get("os_name") or "",
                     "mac": " ".join(x for x in (h.get("mac"), f'({h["vendor"]})' if h.get("vendor") else "") if x),
                     "criticality": a.get("criticality", "medium"), "internet": a.get("internet_exposed", False),
                     "risk": top, "severity": next((s for s in SEVERITIES if any(f["severity"] == s for f in fs)), "Info"),
                     "counts": Counter(f["severity"] for f in fs), "new": bool(h.get("is_new"))})
    return sorted(rows, key=lambda r: -r["risk"])


def build_executive(db: Database, scan_id: int, out: Path) -> Path:
    st = _styles()
    scan, findings, services, hosts, counts = _scan_context(db, scan_id)
    story: list = []
    _header(story, st, "Executive Security Assessment Report", scan, hosts, services, findings)
    rating = _overall_rating(counts)
    story.append(Paragraph(f'Overall risk rating: <font color="{SEV_COLOR[rating].hexval()}">{e(rating.upper())}</font>', st["headline"]))
    story.append(Paragraph(e(_headline(counts)), st["body"]))
    story.append(Spacer(1, 8))
    story.append(_kpis(st, hosts, services, findings, counts))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Risk distribution", st["h1"]))
    story.append(_severity_chart(counts))

    prev = db.previous_scan(scan_id)
    if prev:
        cmp = compare_scans(db, prev["id"], scan_id)
        story.append(Paragraph("Change since previous assessment", st["h1"]))
        story.append(Paragraph(f"<b>{e(cmp.headline)}</b> compared with scan #{prev['id']} ({e(prev['started_at'][:10])}): "
                               f"{len(cmp.resolved_findings)} issue(s) resolved, {len(cmp.new_findings)} new, "
                               f"{len(cmp.persisting_findings)} still open.", st["body"]))
        rows = [["Severity", "Before", "After", "Change"]]
        for s in SEVERITIES[:4]:
            d = cmp.delta(s)
            rows.append([s, str(cmp.before_counts.get(s, 0)), str(cmp.after_counts.get(s, 0)), f"{d:+d}" if d else "0"])
        rows.append(["Risk index", f"{cmp.before_index:.0f}", f"{cmp.after_index:.0f}", f"{cmp.risk_reduction_pct:+.0f}% reduction" if cmp.risk_reduction_pct >= 0 else f"{-cmp.risk_reduction_pct:.0f}% increase"])
        story.append(Spacer(1, 4))
        story.append(_table(rows, [40 * mm, 25 * mm, 25 * mm, 40 * mm]))

    story.append(Paragraph("Top priority risks", st["h1"]))
    top = [f for f in findings if f["severity"] in ("Critical", "High", "Medium")][:10]
    if top:
        rows = [["#", "Severity", "Asset", "Issue", "Action"]]
        for i, f in enumerate(top, 1):
            tag = " [KEV]" if f["kev"] else ""
            rows.append([str(i), _sev_cell(f["severity"], st), Paragraph(e(f"{f['host']}:{f['port'] or '-'}"), st["cell"]),
                         Paragraph(e(f["title"] + tag), st["cell"]), Paragraph(e(f["recommendation"][:220]), st["cell"])])
        story.append(_table(rows, [7 * mm, 17 * mm, 28 * mm, 60 * mm, 70 * mm]))
    else:
        story.append(Paragraph("No medium, high or critical risks were identified.", st["body"]))

    story.append(Paragraph("Most exposed assets", st["h1"]))
    assets = _asset_rows(db, hosts, findings)[:8]
    rows = [["Asset", "Hostname", "Criticality", "Internet", "Top risk", "C / H / M / L"]]
    for a in assets:
        c = a["counts"]
        rows.append([a["address"], Paragraph(e(a["hostname"]), st["cell"]), a["criticality"].title(), "Yes" if a["internet"] else "No",
                     _sev_cell(a["severity"], st) if a["risk"] else "-", f'{c["Critical"]} / {c["High"]} / {c["Medium"]} / {c["Low"]}'])
    story.append(_table(rows, [30 * mm, 42 * mm, 22 * mm, 18 * mm, 22 * mm, 48 * mm]))

    sc = Counter(f["status"] for f in findings)
    story.append(Paragraph("Remediation status", st["h1"]))
    story.append(_table([STATUSES, [str(sc.get(s, 0)) for s in STATUSES]], [30 * mm] * 6))

    cats = {f["category"] for f in findings if f["severity"] in ("Critical", "High", "Medium", "Low")}
    if cats:
        story.append(Paragraph("Strategic recommendations", st["h1"]))
        for cat in ["vulnerability", "exposure", "misconfiguration", "tls", "web", "inventory"]:
            if cat in cats:
                story.append(Paragraph("&bull; " + e(STRATEGY[cat]), st["body"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Findings reflect the state of the systems at scan time and should be validated by the system owner "
                           "before remediation. See the technical report for evidence and detailed guidance.", st["small"]))
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                            title=f"ENSAT Executive Report - Scan {scan_id}", author="ENSAT")
    doc.build(story, onFirstPage=_footer("Executive report"), onLaterPages=_footer("Executive report"))
    return out


def build_technical(db: Database, scan_id: int, out: Path) -> Path:
    st = _styles()
    scan, findings, services, hosts, counts = _scan_context(db, scan_id)
    opts = scan.get("options", {})
    story: list = []
    _header(story, st, "Technical Security Assessment Report", scan, hosts, services, findings)
    story.append(_kpis(st, hosts, services, findings, counts))

    story.append(Paragraph("1. Scope and methodology", st["h1"]))
    auth = scan.get("authorized_by") or "Target within configured scope file"
    rows = [
        ["Target scope", e(scan["target"])],
        ["Authorization", e(auth + (f" - {scan['authorization_note']}" if scan.get("authorization_note") else "")
                            + (" (outside scope file; operator-confirmed)" if scan.get("out_of_scope") else ""))],
        ["Start / duration", e(f"{scan['started_at']} UTC / {scan.get('duration_seconds') or 0:.1f}s")],
        ["Scanner", e(f"Nmap {scan.get('nmap_version') or ''} ({'privileged' if scan.get('privileged') else 'unprivileged'})")],
        ["Nmap arguments", e(scan.get("nmap_args") or "")],
        ["Checks performed", e(", ".join(x for x, on in [
            ("port & service discovery", True), ("service/version detection", opts.get("service_detection", True)),
            ("OS detection", opts.get("os_detection")), ("UDP", opts.get("udp")), ("safe NSE scripts", opts.get("nse_scripts", True)),
            ("TLS certificate & protocol checks", opts.get("tls_checks", True)), ("passive web checks", opts.get("web_checks", True)),
            ("NVD CVE correlation + FIRST EPSS + CISA KEV", opts.get("cve_lookup", True))] if on))],
        ["Risk model", "Base CVSS (or ENSAT rule score) adjusted for CISA KEV, EPSS, public exploits, internet exposure, "
                       "asset criticality and business impact. Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low > 0."],
    ]
    if scan.get("warnings"):
        rows.append(["Limitations", e(" ".join(scan["warnings"]))])
    story.append(_table([[Paragraph(f"<b>{k}</b>", st["cell"]), Paragraph(v, st["cell"])] for k, v in rows],
                        [35 * mm, 147 * mm], header=False))

    story.append(Paragraph("2. Risk summary", st["h1"]))
    story.append(Paragraph(e(_headline(counts)), st["body"]))
    story.append(_severity_chart(counts))

    story.append(CondPageBreak(60 * mm))
    story.append(Paragraph("3. Asset inventory", st["h1"]))
    rows = [["Address", "Hostname", "OS", "MAC / vendor", "Crit.", "Risk", "C/H/M/L"]]
    for a in _asset_rows(db, hosts, findings):
        c = a["counts"]
        rows.append([Paragraph(e(a["address"] + (" (new)" if a["new"] else "")), st["cell"]), Paragraph(e(a["hostname"]), st["cell"]),
                     Paragraph(e(a["os"]), st["cell"]), Paragraph(e(a["mac"]), st["cell"]), a["criticality"].title(),
                     f'{a["risk"]:.1f}', f'{c["Critical"]}/{c["High"]}/{c["Medium"]}/{c["Low"]}'])
    story.append(_table(rows, [26 * mm, 34 * mm, 36 * mm, 34 * mm, 16 * mm, 12 * mm, 24 * mm]))

    story.append(Paragraph("4. Service inventory", st["h1"]))
    rows = [["Host", "Port", "Service", "Product / version", "Notes"]]
    for s in services:
        notes = []
        if s.get("tls") and s["tls"].get("not_after"):
            notes.append(f"TLS cert until {str(s['tls']['not_after'])[:10]} ({s['tls'].get('issuer', '')})")
        if s.get("web") and s["web"].get("title"):
            notes.append(f"Title: {s['web']['title']}")
        if s.get("cpes"):
            notes.append(s["cpes"])
        rows.append([s["address"], f'{s["port"]}/{s["protocol"]}', Paragraph(e(s["service"]), st["cell"]),
                     Paragraph(e(" ".join(x for x in (s["product"], s["version"], s["extrainfo"]) if x)), st["cell"]),
                     Paragraph(e("; ".join(notes)[:300]), st["cell"])])
    story.append(_table(rows, [26 * mm, 16 * mm, 24 * mm, 50 * mm, 66 * mm]))

    story.append(PageBreak())
    story.append(Paragraph("5. Detailed findings", st["h1"]))
    if not findings:
        story.append(Paragraph("No findings were recorded.", st["body"]))
    for i, f in enumerate(findings, 1):
        sev_col = SEV_COLOR.get(f["severity"], INK)
        head = Table([[Paragraph(f'<font color="white"><b>{i}. {e(f["severity"].upper())} {f["risk_score"]:.1f}</b></font>', st["cell"]),
                       Paragraph(f'<font color="white"><b>{e(f["title"])}</b></font>', st["cell"])]], colWidths=[30 * mm, 152 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), sev_col), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        detail = [["Asset / service", f"{f['host']}:{f['port'] or '-'}/{f['protocol'] or '-'} {f['service'] or ''}"],
                  ["Status", f"{f['status']} (first seen {(f.get('first_seen_at') or '')[:10]}, ID {f['fingerprint'][:10]})"]]
        if f["cve"]:
            detail.append(["CVE", f["cve"]])
            detail.append(["CVSS", " ".join(x for x in (f"{f['base_score']:.1f}", f["cvss_version"] or "", f["cvss_vector"] or "") if x)])
            detail.append(["EPSS", f"{f['epss']:.2%} (percentile {f['epss_percentile']:.0%})" if f["epss"] is not None else "n/a"])
            detail.append(["CISA KEV", "YES - known exploited" if f["kev"] else "No"])
            detail.append(["Exploit available", "Yes" if f["exploit_available"] else "No public exploit referenced"])
        if f["cwe"]:
            detail.append(["CWE", f["cwe"]])
        if f["owasp"]:
            detail.append(["OWASP", f["owasp"]])
        detail.append(["Risk calculation", "; ".join(f["risk_factors"])])
        detail.append(["Evidence", f["evidence"]])
        if f["impact"]:
            detail.append(["Impact", f["impact"]])
        detail.append(["Recommendation", f["recommendation"]])
        if f["references"]:
            detail.append(["References", "\n".join(f["references"][:5])])
        rows = [[Paragraph(f"<b>{e(k)}</b>", st["cell"]), Paragraph(e(v).replace("\n", "<br/>"), st["cell"])] for k, v in detail]
        body = Table(rows, colWidths=[30 * mm, 152 * mm])
        body.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("BACKGROUND", (0, 0), (0, -1), ZEBRA)]))
        story.append(KeepTogether([head, body]) if len(detail) < 14 else head)
        if len(detail) >= 14:
            story.append(body)
        story.append(Spacer(1, 6))

    story.append(Paragraph("Appendix: status workflow", st["h1"]))
    story.append(Paragraph("OPEN &rarr; IN_PROGRESS &rarr; REMEDIATED &rarr; VERIFIED. ENSAT marks a REMEDIATED issue as VERIFIED "
                           "automatically when a later scan of the same scope no longer detects it, and reopens it if it reappears. "
                           "ACCEPTED_RISK and FALSE_POSITIVE are analyst decisions and are never changed automatically.", st["body"]))
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                            title=f"ENSAT Technical Report - Scan {scan_id}", author="ENSAT")
    doc.build(story, onFirstPage=_footer("Technical report"), onLaterPages=_footer("Technical report"))
    return out
