"""Generate and download reports."""
from __future__ import annotations

import streamlit as st

from ensat.config import settings
from ensat.dashboard.common import get_db, require_scans, scan_label
from ensat.reporting import generate, report_path

KINDS = {
    "executive": ("Executive report", "PDF for management: risk rating, headline, top risks, trend vs previous scan.", "application/pdf"),
    "technical": ("Technical report", "PDF for engineers: methodology, inventory, every finding with CVE/CVSS/EPSS/KEV, evidence and fix.", "application/pdf"),
    "csv": ("Findings CSV", "Spreadsheet-friendly list of findings for this scan.", "text/csv"),
    "json": ("Full JSON export", "Machine-readable scan data (hosts, services, findings) for automation.", "application/json"),
}


def render():
    db = get_db()
    st.title("Reports")
    scans = require_scans()
    sid = st.selectbox("Scan", [s["id"] for s in scans], format_func=lambda i: scan_label(next(s for s in scans if s["id"] == i)))
    cols = st.columns(2)
    for i, (kind, (title, desc, mime)) in enumerate(KINDS.items()):
        with cols[i % 2].container(border=True):
            st.markdown(f"**{title}**")
            st.caption(desc)
            path = report_path(settings.report_dir, sid, kind)
            if st.button("Generate" if not path.exists() else "Regenerate", key=f"gen_{kind}", icon=":material/refresh:"):
                try:
                    with st.spinner(f"Building {title.lower()}..."):
                        path = generate(db, sid, kind, settings.report_dir)
                    st.toast(f"{title} ready")
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Could not build the report: {exc}")
            if path.exists():
                st.download_button(f"Download {path.suffix[1:].upper()}", path.read_bytes(), file_name=path.name, mime=mime,
                                   key=f"dl_{kind}", icon=":material/download:")
                st.caption(f"Saved to `{path}`")
