"""ENSAT Streamlit dashboard.

Run with either:
    python -m ensat dashboard
    streamlit run ensat/dashboard/app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # allow `streamlit run ensat/dashboard/app.py` from any directory
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from ensat import __version__  # noqa: E402
from ensat.config import setup_logging  # noqa: E402
from ensat.dashboard.views import assets, cves, findings, history, overview, reports, scan, services, settings_view  # noqa: E402

setup_logging()
st.set_page_config(page_title="ENSAT Security Dashboard", page_icon=":material/shield:", layout="wide")

pages = {
    "overview": st.Page(overview.render, title="Overview", icon=":material/dashboard:", default=True),
    "scan": st.Page(scan.render, title="New Scan", icon=":material/radar:", url_path="scan"),
    "findings": st.Page(findings.render, title="Vulnerabilities", icon=":material/bug_report:", url_path="findings"),
    "assets": st.Page(assets.render, title="Assets", icon=":material/dns:", url_path="assets"),
    "services": st.Page(services.render, title="Services", icon=":material/lan:", url_path="services"),
    "cves": st.Page(cves.render, title="CVE Search", icon=":material/search:", url_path="cves"),
    "history": st.Page(history.render, title="History & Compare", icon=":material/compare_arrows:", url_path="history"),
    "reports": st.Page(reports.render, title="Reports", icon=":material/description:", url_path="reports"),
    "settings": st.Page(settings_view.render, title="Settings", icon=":material/settings:", url_path="settings"),
}
st.session_state["pages"] = pages

nav = st.navigation({
    "Assessment": [pages["overview"], pages["scan"], pages["history"]],
    "Inventory": [pages["assets"], pages["services"]],
    "Vulnerability management": [pages["findings"], pages["cves"]],
    "Output": [pages["reports"], pages["settings"]],
})
with st.sidebar:
    st.markdown(f"**ENSAT {__version__}**  \nEnterprise Network Security Assessment Toolkit")
    st.caption("For authorized security assessments only.")
nav.run()
