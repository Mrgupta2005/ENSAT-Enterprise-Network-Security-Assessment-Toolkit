"""Overview: KPIs, risk distribution, top assets, trend."""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from ensat.compare import compare_scans
from ensat.dashboard.common import SEV_COLORS, STATUS_COLORS, df, get_db, require_scans, severity_chart
from ensat.models import SEVERITIES
from ensat.risk import risk_index


def render():
    db = get_db()
    st.title("Security Overview")
    scans = require_scans()
    latest = scans[0]
    current = db.current_findings(include_closed=False)
    counts = {s: sum(1 for f in current if f["severity"] == s) for s in SEVERITIES}
    assets = db.assets()
    inventory = db.service_inventory()

    prev = db.previous_scan(latest["id"])
    delta = {}
    if prev:
        c = compare_scans(db, prev["id"], latest["id"])
        delta = {s: c.delta(s) for s in SEVERITIES}

    k = st.columns(6)
    k[0].metric("Assets", len(assets), help="Live hosts recorded in the inventory")
    k[1].metric("Open services", len(inventory))
    k[2].metric("Open findings", sum(counts[s] for s in SEVERITIES[:4]))
    k[3].metric("Critical", counts["Critical"], delta=delta.get("Critical") or None, delta_color="inverse")
    k[4].metric("High", counts["High"], delta=delta.get("High") or None, delta_color="inverse")
    k[5].metric("CISA KEV", sum(1 for f in current if f["kev"]), help="Open findings listed in CISA's Known Exploited Vulnerabilities catalog")
    st.caption(f"Latest scan #{latest['id']} of **{latest['target']}** at {latest['started_at'][:16].replace('T', ' ')} UTC. "
               "Counts show open issues across all scans (closed statuses excluded).")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Risk distribution")
        st.altair_chart(severity_chart(counts), width="stretch")
    with right:
        st.subheader("Remediation status")
        sc = db.status_counts()
        data = pd.DataFrame({"Status": list(sc), "Issues": list(sc.values())})
        data = data[data["Issues"] > 0]
        if data.empty:
            st.caption("No issues tracked yet.")
        else:
            st.altair_chart(alt.Chart(data).mark_arc(innerRadius=55).encode(
                theta="Issues:Q", color=alt.Color("Status:N", scale=alt.Scale(domain=list(STATUS_COLORS), range=list(STATUS_COLORS.values()))),
                tooltip=["Status", "Issues"]).properties(height=220), width="stretch")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Top vulnerable assets")
        top = sorted([a for a in assets if a["open_findings"]], key=lambda a: -a["risk_score"])[:10]
        if top:
            st.dataframe(df(top)[["address", "hostname", "criticality", "internet_exposed", "risk_score", "critical", "high", "medium", "low"]],
                         hide_index=True, width="stretch",
                         column_config={"address": "Asset", "hostname": "Hostname", "criticality": "Criticality",
                                        "internet_exposed": st.column_config.CheckboxColumn("Internet"),
                                        "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=10, format="%.1f"),
                                        "critical": "C", "high": "H", "medium": "M", "low": "L"})
        else:
            st.success("No assets with open findings.")
    with right:
        st.subheader("Priority findings")
        for f in [f for f in current if f["severity"] in ("Critical", "High")][:8]:
            kev = " :red-badge[KEV]" if f["kev"] else ""
            st.markdown(f":{'red' if f['severity'] == 'Critical' else 'orange'}-badge[{f['severity']} {f['risk_score']:.1f}]{kev} "
                        f"**{f['title']}**  \n`{f['host']}:{f['port'] or '-'}`")
        if not any(f["severity"] in ("Critical", "High") for f in current):
            st.success("No open critical or high findings.")

    st.subheader("Risk trend")
    trend = []
    for s in reversed(scans[:30]):
        c = db.severity_counts(s["id"])
        trend.append({"Scan": f"#{s['id']}", "id": s["id"], "Risk index": risk_index(c), **{k: c[k] for k in SEVERITIES[:4]}})
    if len(trend) > 1:
        long = pd.DataFrame(trend).melt(id_vars=["Scan", "id"], value_vars=SEVERITIES[:4], var_name="Severity", value_name="Findings")
        st.altair_chart(alt.Chart(long).mark_line(point=True).encode(
            x=alt.X("Scan:N", sort=alt.SortField("id")), y="Findings:Q",
            color=alt.Color("Severity:N", scale=alt.Scale(domain=list(SEV_COLORS)[:4], range=list(SEV_COLORS.values())[:4])),
            tooltip=["Scan", "Severity", "Findings"]).properties(height=240), width="stretch")
    else:
        st.caption("Run more scans to see a trend.")
    new_assets = [a for a in assets if not a["known"]]
    if len(scans) > 1 and new_assets:
        st.warning(f"{len(new_assets)} asset(s) not yet marked as known: " + ", ".join(a["address"] for a in new_assets[:10]))
