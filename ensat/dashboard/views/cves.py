"""CVE search: findings in your estate, local intel cache, or live NVD."""
from __future__ import annotations

import streamlit as st

from ensat.config import settings
from ensat.dashboard.common import df, get_db
from ensat.intel import IntelUnavailable, ThreatIntel


@st.cache_resource
def _intel() -> ThreatIntel:
    return ThreatIntel(settings)


def render():
    db = get_db()
    st.title("CVE Search")
    tab_estate, tab_lookup = st.tabs(["CVEs in your environment", "Look up / search NVD"])

    with tab_estate:
        rows = [r for r in db.current_findings() if r["cve"]]
        if not rows:
            st.info("No CVEs have been correlated with discovered services yet. CVE matching needs service/version detection "
                    "and network access to the NVD API.")
        else:
            q = st.text_input("Filter", placeholder="CVE ID, product, CWE...", key="cve_filter").lower().strip()
            kev = st.toggle("CISA KEV only", key="cve_kev")
            by_cve: dict[str, dict] = {}
            for r in rows:
                e = by_cve.setdefault(r["cve"], {"cve": r["cve"], "cvss": r["base_score"], "epss": r["epss"], "kev": r["kev"], "cwe": r["cwe"],
                                                 "max_risk": r["risk_score"], "assets": set(), "product": r["title"].split(": ", 1)[-1], "open": 0})
                e["assets"].add(f"{r['host']}:{r['port']}")
                e["max_risk"] = max(e["max_risk"], r["risk_score"])
                e["open"] += r["status"] in ("OPEN", "IN_PROGRESS")
            items = []
            for e in by_cve.values():
                e["affected"] = len(e["assets"])
                e["assets"] = ", ".join(sorted(e["assets"]))
                if (not kev or e["kev"]) and (not q or q in " ".join(str(v) for v in e.values()).lower()):
                    items.append(e)
            items.sort(key=lambda e: (-e["kev"], -e["max_risk"]))
            st.dataframe(df(items)[["cve", "product", "cvss", "epss", "kev", "cwe", "max_risk", "affected", "open", "assets"]] if items else df([]),
                         hide_index=True, width="stretch",
                         column_config={"cve": st.column_config.TextColumn("CVE"), "product": "Product", "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
                                        "epss": st.column_config.NumberColumn("EPSS", format="percent"), "kev": st.column_config.CheckboxColumn("KEV"),
                                        "cwe": "CWE", "max_risk": st.column_config.ProgressColumn("Max risk", min_value=0, max_value=10, format="%.1f"),
                                        "affected": "Affected", "open": "Open", "assets": "Assets"})

    with tab_lookup:
        if settings.offline:
            st.warning("Offline mode is on (ENSAT_OFFLINE): only cached CVE data is available.")
        q = st.text_input("CVE ID or keyword", placeholder="CVE-2021-44228 or 'openssh 7.4'", key="cve_q")
        if not q:
            cached = _intel().nvd.cached_records()
            if cached:
                st.caption(f"{len(cached)} CVE records in the local cache")
            return
        intel = _intel()
        try:
            if q.strip().upper().startswith("CVE-"):
                with st.spinner("Querying NVD, EPSS and KEV..."):
                    res = intel.lookup(q)
                if not res:
                    st.warning("CVE not found.")
                    return
                r = res["record"]
                st.subheader(r.id)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric(r.score_source, f"{r.base_score:.1f}")
                c2.metric("EPSS", f"{res['epss'][0]:.1%}" if res["epss"] else "n/a")
                c3.metric("CISA KEV", "YES" if res["kev"] else "No")
                c4.metric("Published", r.published or "n/a")
                if r.vector:
                    st.code(r.vector, language=None)
                st.write(r.description)
                if r.cwes:
                    st.markdown("**CWE:** " + ", ".join(r.cwes))
                if res["kev"]:
                    st.error(f"Known exploited. CISA required action: {res['kev'].get('requiredAction', '')} "
                             f"(due {res['kev'].get('dueDate', 'n/a')})")
                hits = [f for f in db.current_findings() if f["cve"] == r.id]
                st.markdown(f"**Affected assets in your environment:** {', '.join(sorted({f['host'] for f in hits})) or 'none found'}")
                st.markdown(f"[View on NVD](https://nvd.nist.gov/vuln/detail/{r.id})")
            else:
                with st.spinner("Searching NVD..."):
                    recs = intel.nvd.search(q, 50)
                st.caption(f"{len(recs)} result(s)")
                st.dataframe([{"CVE": r.id, "Score": r.base_score, "Source": r.score_source, "Published": r.published,
                               "Description": r.description[:200]} for r in recs], hide_index=True, width="stretch")
        except IntelUnavailable as exc:
            st.error(f"{exc}. Check your internet connection or NVD_API_KEY.")
