"""Asset inventory with editable business context."""
from __future__ import annotations

import streamlit as st

from ensat.dashboard.common import df, get_db, require_scans


def render():
    db = get_db()
    st.title("Asset Inventory")
    require_scans()
    rows = db.assets()
    if not rows:
        st.info("No live assets recorded yet.")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Assets", len(rows))
    c2.metric("Internet-exposed", sum(1 for a in rows if a["internet_exposed"]))
    c3.metric("Not yet known", sum(1 for a in rows if not a["known"]), help="Newly discovered assets nobody has acknowledged yet")
    c4.metric("With open findings", sum(1 for a in rows if a["open_findings"]))

    q = st.text_input("Search", placeholder="address, hostname, OS, vendor, owner, tag...").lower().strip()
    if q:
        rows = [a for a in rows if q in " ".join(str(a.get(k) or "") for k in ("address", "hostname", "os_name", "vendor", "mac", "owner", "tags")).lower()]

    st.caption("Edit **criticality**, **business impact**, **exposure**, **owner**, **tags** and **known** directly in the table, then save. "
               "Context changes are applied to the risk scores of open findings immediately.")
    cols = ["address", "hostname", "os_name", "mac", "vendor", "criticality", "business_impact", "exposure", "internet_exposed",
            "owner", "tags", "known", "risk_score", "open_findings", "open_services", "first_seen", "last_seen"]
    table = df(rows)[cols]
    table["known"] = table["known"].astype(bool)
    edited = st.data_editor(
        table, hide_index=True, width="stretch", key="assets_editor",
        disabled=["address", "hostname", "os_name", "mac", "vendor", "internet_exposed", "risk_score", "open_findings", "open_services", "first_seen", "last_seen"],
        column_config={
            "address": "Address", "hostname": "Hostname", "os_name": "OS", "mac": "MAC", "vendor": "Vendor",
            "criticality": st.column_config.SelectboxColumn("Criticality", options=["critical", "high", "medium", "low"], required=True),
            "business_impact": st.column_config.SelectboxColumn("Business impact", options=["high", "medium", "low"], required=True),
            "exposure": st.column_config.SelectboxColumn("Exposure", options=["auto", "internet", "internal"], required=True,
                                                         help="auto = internet-facing if the address is publicly routable"),
            "internet_exposed": st.column_config.CheckboxColumn("Internet"),
            "owner": "Owner", "tags": "Tags", "known": st.column_config.CheckboxColumn("Known"),
            "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=10, format="%.1f"),
            "open_findings": "Open findings", "open_services": "Services",
            "first_seen": st.column_config.TextColumn("First seen"), "last_seen": st.column_config.TextColumn("Last seen"),
        })
    if st.button("Save changes", type="primary", icon=":material/save:"):
        changed = 0
        before = {r["address"]: r for r in table.to_dict("records")}
        for r in edited.to_dict("records"):
            old = before[r["address"]]
            fields = {k: r[k] for k in ("criticality", "business_impact", "exposure", "owner", "tags", "known") if r[k] != old[k]}
            if fields:
                if "known" in fields:
                    fields["known"] = int(bool(fields["known"]))
                db.update_asset(r["address"], **fields)
                changed += 1
        if changed:
            n = db.rescore_open()
            st.toast(f"Saved {changed} asset(s); re-scored {n} open finding(s)")
            st.rerun()
        else:
            st.toast("No changes")

