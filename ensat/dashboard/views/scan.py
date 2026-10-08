"""New Scan: run the full assessment pipeline from the browser."""
from __future__ import annotations

import streamlit as st

from ensat.config import settings
from ensat.dashboard.common import get_db
from ensat.models import ScanOptions
from ensat.pipeline import AssessmentError, assess
from ensat.scanner import NmapError, ensure_nmap, is_privileged
from ensat.validation import AuthorizationError, ValidationError, check_authorization, load_scope, parse_targets, validate_ports


def render():
    st.title("New Assessment")
    try:
        ensure_nmap()
    except NmapError as exc:
        st.error(str(exc))
        st.stop()

    privileged = is_privileged()
    if not privileged:
        st.info("Running without root/Administrator: TCP connect scan is used, and OS detection, UDP and MAC/vendor "
                "discovery are unavailable. Start the dashboard from an elevated terminal to enable them.", icon=":material/info:")

    with st.form("scan"):
        target = st.text_input("Target(s)", placeholder="192.168.1.10, 10.0.0.0/24, 10.0.0.5-20, server.lab.local",
                               help="IP, CIDR, octet range or hostname. Separate multiple targets with commas or spaces.")
        c1, c2 = st.columns(2)
        profile = c1.selectbox("Profile", ["quick", "standard", "full"], index=1,
                               help="quick: top 100 ports, no scripts | standard: top 1000 ports + safe NSE scripts | full: all 65535 ports + extended safe scripts")
        ports = c2.text_input("Custom ports (optional)", placeholder="22,80,443 or 1-1024", help="Overrides the profile's port list")
        st.markdown("**Discovery & enumeration**")
        c1, c2, c3, c4 = st.columns(4)
        service_detection = c1.checkbox("Service/version detection", True)
        nse = c2.checkbox("Safe NSE scripts", True)
        os_detection = c3.checkbox("OS detection", False, disabled=not privileged)
        udp = c4.checkbox("Common UDP ports", False, disabled=not privileged)
        st.markdown("**Assessment**")
        c1, c2, c3, c4 = st.columns(4)
        tls = c1.checkbox("TLS checks", True)
        web = c2.checkbox("Web checks", True)
        cve = c3.checkbox("CVE / EPSS / KEV lookup", not settings.offline)
        no_ping = c4.checkbox("Skip host discovery (-Pn)", False, help="Treat every address as up. Automatic for single hosts.")

        st.markdown("**Authorization**")
        scope = load_scope(settings.scope_file)
        st.caption(f"Scope file: `{settings.scope_file}` ({len(scope)} entr{'y' if len(scope) == 1 else 'ies'}). "
                   "Targets inside the scope file (and localhost) need no extra confirmation.")
        confirm = st.checkbox("I confirm I have written authorization to assess these targets")
        c1, c2 = st.columns(2)
        operator = c1.text_input("Authorized by", value=settings.operator)
        note = c2.text_input("Authorization reference", placeholder="e.g. change ticket / engagement ID")
        submitted = st.form_submit_button("Start assessment", type="primary", icon=":material/play_arrow:")

    if not submitted:
        _recent()
        return

    try:
        targets = parse_targets(target, settings.max_hosts)
        validate_ports(ports)
        check_authorization(targets, scope, acknowledged=confirm)
    except (ValidationError, AuthorizationError) as exc:
        st.error(str(exc))
        return

    opts = ScanOptions(target=target.strip(), profile=profile, ports=ports or None, service_detection=service_detection,
                       os_detection=os_detection, udp=udp, skip_discovery=True if no_ping else None, nse_scripts=nse,
                       tls_checks=tls, web_checks=web, cve_lookup=cve, timeout=settings.scan_timeout,
                       authorized_by=(operator or settings.operator) if confirm else "", authorization_note=note)
    bar = st.progress(0.0, text="Starting")
    with st.status("Running assessment...", expanded=True) as status:
        log_box = st.empty()
        lines: list[str] = []

        def progress(msg: str, frac: float):
            bar.progress(min(max(frac, 0.0), 1.0), text=msg[:90])
            if not lines or lines[-1].split(":")[0] != msg.split(":")[0]:
                lines.append(msg)
            else:
                lines[-1] = msg
            log_box.code("\n".join(lines[-12:]), language=None)

        try:
            result = assess(opts, settings, get_db(), progress=progress, report_types=("executive", "technical"))
        except AssessmentError as exc:
            status.update(label=f"Scan #{exc.scan_id} failed", state="error")
            st.error(str(exc))
            return
        except (ValidationError, AuthorizationError) as exc:
            status.update(label="Not started", state="error")
            st.error(str(exc))
            return
        status.update(label=f"Scan #{result.scan_id} complete in {result.duration:.0f}s", state="complete", expanded=False)

    for w in result.warnings:
        st.warning(w)
    up = [h for h in result.hosts if h.status == "up"]
    counts = result.counts
    c = st.columns(6)
    c[0].metric("Live hosts", len(up))
    c[1].metric("Open services", sum(len(h.open_services) for h in up))
    for i, s in enumerate(["Critical", "High", "Medium", "Low"], 2):
        c[i].metric(s, counts.get(s, 0))
    t = result.transitions
    if t.get("verified") or t.get("reopened"):
        st.info(f"Remediation tracking: {t.get('verified', 0)} fix(es) verified, {t.get('reopened', 0)} issue(s) reopened.")
    cols = st.columns(len(result.reports) + 1)
    for i, (kind, path) in enumerate(result.reports.items()):
        cols[i].download_button(f"{kind.title()} report (PDF)", path.read_bytes(), file_name=path.name, mime="application/pdf",
                                icon=":material/download:")
    cols[-1].page_link(st.session_state["pages"]["findings"], label="Review findings", icon=":material/bug_report:")


def _recent():
    scans = get_db().list_scans(5)
    if scans:
        st.subheader("Recent scans")
        st.dataframe([{"Scan": s["id"], "Target": s["target"], "Started": s["started_at"][:16].replace("T", " "), "Status": s["status"],
                       "Critical": s["critical"], "High": s["high"], "Findings": s["findings"], "Error": s.get("error") or ""} for s in scans],
                     hide_index=True, width="stretch")
