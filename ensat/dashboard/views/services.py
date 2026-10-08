"""Service inventory (latest observation per asset) plus TLS and web details."""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from ensat.dashboard.common import df, get_db, require_scans


def render():
    db = get_db()
    st.title("Service Inventory")
    require_scans()
    rows = db.service_inventory()
    if not rows:
        st.info("No open services recorded.")
        return
    for r in rows:
        r["product_version"] = " ".join(x for x in (r["product"], r["version"]) if x)
        r["tls_expiry"] = str(r["tls"]["not_after"])[:10] if r.get("tls") and r["tls"].get("not_after") else ""
        r["tls_issuer"] = r["tls"].get("issuer", "") if r.get("tls") else ""
        r["web_title"] = r["web"].get("title", "") if r.get("web") else ""
        r["technologies"] = ", ".join(r["web"].get("technologies", [])) if r.get("web") else ""

    c1, c2, c3 = st.columns([2, 2, 3])
    proto = c1.multiselect("Protocol", sorted({r["protocol"] for r in rows}))
    names = c2.multiselect("Service", sorted({r["service"] or "unknown" for r in rows}))
    q = c3.text_input("Search", placeholder="product, version, CPE, banner...").lower().strip()
    rows = [r for r in rows if (not proto or r["protocol"] in proto) and (not names or (r["service"] or "unknown") in names)
            and (not q or q in " ".join(str(r.get(k) or "") for k in ("address", "product", "version", "cpes", "banner", "technologies", "web_title")).lower())]

    left, right = st.columns([3, 2])
    with left:
        st.dataframe(df(rows)[["address", "hostname", "port", "protocol", "service", "product_version", "cpes", "tls_expiry", "tls_issuer", "web_title", "technologies"]],
                     hide_index=True, width="stretch", height=460,
                     column_config={"address": "Asset", "hostname": "Hostname", "port": st.column_config.NumberColumn("Port", format="%d"),
                                    "protocol": "Proto", "service": "Service", "product_version": "Product / version", "cpes": "CPE",
                                    "tls_expiry": "TLS expiry", "tls_issuer": "TLS issuer", "web_title": "Page title", "technologies": "Technologies"})
    with right:
        st.subheader("Most common services")
        counts = pd.Series([r["service"] or "unknown" for r in rows]).value_counts().head(12).reset_index()
        counts.columns = ["Service", "Count"]
        if not counts.empty:
            st.altair_chart(alt.Chart(counts).mark_bar().encode(x="Count:Q", y=alt.Y("Service:N", sort="-x"), tooltip=["Service", "Count"])
                            .properties(height=320), width="stretch")
        banners = [r for r in rows if r.get("banner")]
        if banners:
            with st.expander(f"Service banners ({len(banners)})"):
                for r in banners[:50]:
                    st.markdown(f"`{r['address']}:{r['port']}`")
                    st.code(r["banner"][:500], language=None)
