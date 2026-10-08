"""Scan history and before/after comparison."""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from ensat.compare import compare_scans
from ensat.dashboard.common import FINDING_COLUMNS, df, get_db, require_scans, scan_label
from ensat.models import SEVERITIES


def render():
    db = get_db()
    st.title("Scan History & Comparison")
    require_scans()
    all_scans = db.list_scans()
    st.dataframe([{"Scan": s["id"], "Started (UTC)": s["started_at"][:16].replace("T", " "), "Target": s["target"], "Profile": s["profile"],
                   "Status": s["status"], "Duration (s)": round(s["duration_seconds"] or 0, 1), "Hosts": s["hosts_up"] or 0,
                   "Services": s["services"], "Critical": s["critical"], "High": s["high"], "Medium": s["medium"], "Low": s["low"],
                   "Authorized by": s["authorized_by"] or "(in scope)", "Error": s.get("error") or ""} for s in all_scans],
                 hide_index=True, width="stretch")

    completed = [s for s in all_scans if s["status"] == "completed"]
    st.subheader("Compare two scans")
    if len(completed) < 2:
        st.info("Run at least two scans (for example before and after patching) to compare them.")
        return
    ids = [s["id"] for s in completed]
    labels = {s["id"]: scan_label(s) for s in completed}
    c1, c2 = st.columns(2)
    after = c2.selectbox("After", ids, index=0, format_func=labels.get)
    prev = db.previous_scan(after)
    default_before = ids.index(prev["id"]) if prev and prev["id"] in ids else min(1, len(ids) - 1)
    before = c1.selectbox("Before", ids, index=default_before, format_func=labels.get)
    if before == after:
        st.warning("Choose two different scans.")
        return
    if before > after:
        before, after = after, before
    cmp = compare_scans(db, before, after)

    pct = cmp.risk_reduction_pct
    (st.success if pct > 0 else st.error if pct < 0 else st.info)(f"**{cmp.headline}** (risk index {cmp.before_index:.0f} -> {cmp.after_index:.0f})")
    k = st.columns(4)
    for i, s in enumerate(SEVERITIES[:4]):
        k[i].metric(s, cmp.after_counts[s], delta=cmp.delta(s) or None, delta_color="inverse")

    data = pd.DataFrame([{"Scan": f"Before #{before}", "Severity": s, "Findings": cmp.before_counts[s]} for s in SEVERITIES[:4]] +
                        [{"Scan": f"After #{after}", "Severity": s, "Findings": cmp.after_counts[s]} for s in SEVERITIES[:4]])
    st.altair_chart(alt.Chart(data).mark_bar().encode(
        x=alt.X("Scan:N", title=None, sort=[f"Before #{before}", f"After #{after}"]), y="Findings:Q", xOffset="Scan:N",
        column=alt.Column("Severity:N", sort=SEVERITIES[:4], title=None),
        color=alt.Color("Scan:N", scale=alt.Scale(domain=[f"Before #{before}", f"After #{after}"], range=["#9ca3af", "#2563eb"])), tooltip=["Scan", "Severity", "Findings"]
    ).properties(width=120, height=200))

    cols = ["severity", "risk_score", "host", "port", "title", "cve", "status"]
    t1, t2, t3, t4 = st.tabs([f"Resolved ({len(cmp.resolved_findings)})", f"New ({len(cmp.new_findings)})",
                              f"Persisting ({len(cmp.persisting_findings)})", "Assets & services"])
    for tab, items in ((t1, cmp.resolved_findings), (t2, cmp.new_findings), (t3, cmp.persisting_findings)):
        with tab:
            if items:
                st.dataframe(df(items)[cols], hide_index=True, width="stretch", column_config=FINDING_COLUMNS)
            else:
                st.caption("None.")
    with t4:
        c1, c2 = st.columns(2)
        c1.markdown("**New assets**  \n" + ("  \n".join(cmp.new_assets) or "none"))
        c1.markdown("**Assets no longer seen**  \n" + ("  \n".join(cmp.missing_assets) or "none"))
        c2.markdown("**New services**  \n" + ("  \n".join(cmp.new_services) or "none"))
        c2.markdown("**Closed services**  \n" + ("  \n".join(cmp.closed_services) or "none"))
