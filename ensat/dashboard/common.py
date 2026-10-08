"""Shared helpers for the Streamlit dashboard."""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from ensat.config import settings
from ensat.db import Database
from ensat.models import SEVERITIES

SEV_COLORS = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#d97706", "Low": "#2563eb", "Info": "#6b7280"}
STATUS_COLORS = {"OPEN": "#b91c1c", "IN_PROGRESS": "#d97706", "REMEDIATED": "#2563eb", "VERIFIED": "#15803d",
                 "ACCEPTED_RISK": "#7c3aed", "FALSE_POSITIVE": "#6b7280"}


@st.cache_resource
def get_db() -> Database:
    return Database(settings.db_path)


def df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def severity_badge(sev: str) -> str:
    return f":{ {'Critical': 'red', 'High': 'orange', 'Medium': 'orange', 'Low': 'blue', 'Info': 'gray'}.get(sev, 'gray') }-badge[{sev}]"


def severity_chart(counts: dict[str, int], height: int = 220):
    data = pd.DataFrame({"Severity": SEVERITIES[:4], "Findings": [counts.get(s, 0) for s in SEVERITIES[:4]]})
    return (alt.Chart(data).mark_bar(cornerRadiusEnd=3)
            .encode(x=alt.X("Findings:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                    y=alt.Y("Severity:N", sort=SEVERITIES[:4], title=None),
                    color=alt.Color("Severity:N", scale=alt.Scale(domain=list(SEV_COLORS), range=list(SEV_COLORS.values())), legend=None),
                    tooltip=["Severity", "Findings"])
            .properties(height=height))


def scan_label(scan: dict) -> str:
    return f"#{scan['id']} - {scan['target']} - {scan['started_at'][:16].replace('T', ' ')} ({scan['status']})"


def require_scans() -> list[dict]:
    scans = [s for s in get_db().list_scans() if s["status"] == "completed"]
    if not scans:
        st.info("No completed scans yet. Open **New Scan** to run your first authorized assessment.")
        st.page_link(st.session_state["pages"]["scan"], label="Go to New Scan", icon=":material/radar:")
        st.stop()
    return scans


FINDING_COLUMNS = {
    "severity": st.column_config.TextColumn("Severity"),
    "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=10, format="%.1f"),
    "status": st.column_config.TextColumn("Status", width="medium"),
    "host": st.column_config.TextColumn("Asset"),
    "port": st.column_config.NumberColumn("Port", format="%d"),
    "service": "Service",
    "title": st.column_config.TextColumn("Finding", width="large"),
    "cve": "CVE",
    "base_score": st.column_config.NumberColumn("CVSS/base", format="%.1f"),
    "epss": st.column_config.NumberColumn("EPSS", format="percent"),
    "kev": st.column_config.CheckboxColumn("KEV"),
    "category": "Category",
    "fingerprint": st.column_config.TextColumn("ID"),
}
