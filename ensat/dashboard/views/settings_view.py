"""Settings and system status."""
from __future__ import annotations

import streamlit as st

from ensat import __version__
from ensat.config import settings
from ensat.intel import IntelUnavailable
from ensat.scanner import is_privileged, nmap_version
from ensat.validation import ValidationError, load_scope, parse_target


def render():
    st.title("Settings & Status")
    from ensat.dashboard.views.cves import _intel

    c1, c2, c3, c4 = st.columns(4)
    nv = nmap_version()
    c1.metric("Nmap", nv or "not found")
    c2.metric("Privileges", "elevated" if is_privileged() else "standard")
    c3.metric("NVD API key", "configured" if settings.nvd_api_key else "not set",
              help="Without a key NVD allows 5 requests / 30 s; with one, 50 / 30 s. Set NVD_API_KEY in .env")
    kev = _intel().kev
    age = kev.age_hours
    c4.metric("CISA KEV cache", f"{age:.0f} h old" if age is not None else "not downloaded")

    st.subheader("Threat intelligence")
    c1, c2 = st.columns(2)
    if c1.button("Refresh CISA KEV catalog", icon=":material/sync:"):
        try:
            with st.spinner("Downloading KEV catalog..."):
                n = kev.refresh()
            st.success(f"KEV catalog updated: {n} known exploited vulnerabilities")
        except IntelUnavailable as exc:
            st.error(str(exc))
    stats = _intel().cache.stats()
    c2.caption("Local intel cache: " + (", ".join(f"{k}: {v}" for k, v in stats.items()) or "empty"))
    if c2.button("Clear intel cache"):
        _intel().cache.clear()
        st.toast("Cache cleared")

    st.subheader("Authorized scope")
    st.caption(f"File: `{settings.scope_file}`. One IP, CIDR or hostname pattern per line; `#` starts a comment. "
               "Targets outside this list require explicit confirmation each time.")
    current = settings.scope_file.read_text(encoding="utf-8") if settings.scope_file.exists() else ""
    text = st.text_area("Scope entries", current, height=160, placeholder="192.168.56.0/24\n10.10.0.5\n*.lab.local")
    if st.button("Save scope", type="primary"):
        bad = []
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry and not entry.startswith("*"):
                try:
                    parse_target(entry)
                except ValidationError:
                    bad.append(entry)
        if bad:
            st.error("Invalid entries: " + ", ".join(bad))
        else:
            settings.scope_file.write_text(text.strip() + "\n", encoding="utf-8")
            st.success(f"Saved {len(load_scope(settings.scope_file))} scope entries")

    st.subheader("Configuration")
    st.dataframe([
        {"Setting": "Version", "Value": __version__},
        {"Setting": "Database", "Value": str(settings.db_path)},
        {"Setting": "Reports directory", "Value": str(settings.report_dir)},
        {"Setting": "Logs", "Value": str(settings.log_dir / "ensat.log")},
        {"Setting": "Operator", "Value": settings.operator},
        {"Setting": "Offline mode", "Value": str(settings.offline)},
        {"Setting": "Max hosts per scan", "Value": str(settings.max_hosts)},
        {"Setting": "Scan timeout (s)", "Value": str(settings.scan_timeout)},
    ], hide_index=True, width="stretch")
    st.caption("Change these with environment variables or a .env file (see .env.example).")
