"""Vulnerability management: filter, search, sort, triage and track remediation."""
from __future__ import annotations

import streamlit as st

from ensat.config import settings
from ensat.dashboard.common import FINDING_COLUMNS, df, get_db, require_scans
from ensat.models import SEVERITIES, SEVERITY_RANK, STATUSES

SORTS = {
    "Priority (severity, risk)": lambda r: (SEVERITY_RANK.get(r["severity"], 9), -r["risk_score"]),
    "Risk score": lambda r: -r["risk_score"],
    "CVSS / base score": lambda r: -(r["base_score"] or 0),
    "EPSS": lambda r: -(r["epss"] or 0),
    "Asset": lambda r: (r["host"], r["port"] or 0),
    "Last seen": lambda r: r["last_seen_at"] or "",
}


def render():
    db = get_db()
    st.title("Vulnerability Management")
    scans = require_scans()

    view = st.segmented_control("View", ["Current issues", "Single scan"], default="Current issues", label_visibility="collapsed")
    if view == "Single scan":
        sid = st.selectbox("Scan", [s["id"] for s in scans], format_func=lambda i: next(f"#{s['id']} - {s['target']} - {s['started_at'][:16]}" for s in scans if s["id"] == i))
        rows = db.scan_findings(sid)
    else:
        rows = db.current_findings()

    with st.container(border=True):
        c1, c2, c3, c4 = st.columns([2, 2, 2, 3])
        sev = c1.multiselect("Severity", SEVERITIES, default=SEVERITIES[:4])
        default_status = [s for s in STATUSES if s not in ("VERIFIED", "FALSE_POSITIVE")]
        status = c2.multiselect("Status", STATUSES, default=default_status)
        hosts = sorted({r["host"] for r in rows})
        host = c3.multiselect("Asset", hosts)
        query = c4.text_input("Search", placeholder="title, CVE, service, evidence...")
        c1, c2, c3, c4 = st.columns([2, 2, 2, 3])
        cats = sorted({r["category"] for r in rows})
        cat = c1.multiselect("Category", cats)
        kev_only = c2.toggle("CISA KEV only")
        exploit_only = c3.toggle("Exploit available")
        sort = c4.selectbox("Sort by", list(SORTS))

    q = query.lower().strip()
    filtered = [r for r in rows
                if r["severity"] in sev and r["status"] in status and (not host or r["host"] in host)
                and (not cat or r["category"] in cat) and (not kev_only or r["kev"]) and (not exploit_only or r["exploit_available"])
                and (not q or q in " ".join(str(r.get(k) or "") for k in ("title", "cve", "service", "evidence", "host", "cwe", "check_id")).lower())]
    filtered.sort(key=SORTS[sort])
    st.caption(f"{len(filtered)} of {len(rows)} findings")
    if not filtered:
        st.success("No findings match the filters.")
        return

    cols = ["severity", "risk_score", "status", "host", "port", "service", "title", "cve", "base_score", "epss", "kev", "category", "fingerprint"]
    table = df(filtered)[cols].fillna({"cve": "", "service": ""})
    event = st.dataframe(table, hide_index=True, width="stretch", column_config=FINDING_COLUMNS,
                         on_select="rerun", selection_mode="multi-row", key="findings_table", height=420)
    selected = [filtered[i] for i in event.selection.rows] if event and event.selection else []

    st.download_button("Download filtered findings (CSV)", table.to_csv(index=False).encode(), "ensat_findings.csv", "text/csv",
                       icon=":material/download:")

    if not selected:
        st.info("Select one or more rows to see details or update their remediation status.")
        return

    with st.container(border=True):
        st.markdown(f"**Update {len(selected)} selected finding(s)**")
        c1, c2, c3 = st.columns([2, 4, 1])
        new_status = c1.selectbox("New status", STATUSES, index=STATUSES.index(selected[0]["status"]))
        note = c2.text_input("Note", placeholder="e.g. Patched in CHG-1234")
        c3.write("")
        if c3.button("Apply", type="primary", width="stretch"):
            n = db.update_status([r["fingerprint"] for r in selected], new_status, settings.operator, note)
            st.toast(f"Updated {n} finding(s) to {new_status}")
            st.rerun()

    f = selected[0]
    st.subheader(f["title"])
    a, b, c, d = st.columns(4)
    a.metric("Risk score", f"{f['risk_score']:.1f}", f["severity"], delta_color="off")
    b.metric("CVSS / base", f"{f['base_score']:.1f}", f["cvss_version"] or "ENSAT rule", delta_color="off")
    c.metric("EPSS", f"{f['epss']:.1%}" if f["epss"] is not None else "n/a",
             f"percentile {f['epss_percentile']:.0%}" if f["epss_percentile"] is not None else None, delta_color="off")
    d.metric("CISA KEV", "YES" if f["kev"] else "No", "exploit available" if f["exploit_available"] else None, delta_color="off")
    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"**Asset:** `{f['host']}:{f['port'] or '-'}/{f['protocol'] or '-'}` {f['service'] or ''}")
        if f["cve"]:
            st.markdown(f"**CVE:** [{f['cve']}](https://nvd.nist.gov/vuln/detail/{f['cve']})" + (f" | **CWE:** {f['cwe']}" if f["cwe"] else ""))
            if f["cvss_vector"]:
                st.markdown(f"**Vector:** `{f['cvss_vector']}`")
        if f["owasp"]:
            st.markdown(f"**OWASP:** {f['owasp']}")
        st.markdown("**Evidence**")
        st.code(f["evidence"] or "-", language=None, wrap_lines=True)
        if f["impact"]:
            st.markdown(f"**Impact:** {f['impact']}")
        st.markdown(f"**Recommendation:** {f['recommendation']}")
        if f["references"]:
            st.markdown("**References**  \n" + "  \n".join(f"- {u}" for u in f["references"][:6]))
    with right:
        st.markdown("**Risk calculation**")
        for factor in f["risk_factors"]:
            st.markdown(f"- {factor}")
        st.markdown(f"**Status:** {f['status']}  \nFirst seen {(f['first_seen_at'] or '')[:10]} (scan #{f['first_seen_scan']}), "
                    f"last seen {(f['last_seen_at'] or '')[:10]} (scan #{f['last_seen_scan']})")
        with st.form(f"issue_{f['fingerprint']}"):
            assignee = st.text_input("Assignee", value=f.get("assignee") or "")
            notes = st.text_area("Notes", value=f.get("notes") or "", height=90)
            if st.form_submit_button("Save"):
                db.update_issue(f["fingerprint"], assignee=assignee, notes=notes)
                st.toast("Saved")
        hist = db.finding_history(f["fingerprint"])
        if hist:
            st.markdown("**History**")
            st.dataframe([{"When": h["changed_at"][:16].replace("T", " "), "From": h["old_status"] or "", "To": h["new_status"],
                           "By": h["changed_by"] or "", "Note": h["note"] or ""} for h in hist], hide_index=True, width="stretch")
