"""
Streamlit dashboard for the AI Vulnerability Triage Assistant.

Run: streamlit run dashboard.py
Expects the FastAPI backend running at http://localhost:8000 (or set
API_BASE_URL env var).
"""
import os
import json
import requests
import streamlit as st
import pandas as pd

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

st.set_page_config(page_title="AI Vulnerability Triage Assistant", layout="wide")

st.title("🛡️ AI Vulnerability Triage Assistant")
st.caption(
    "Live CVE ingestion (NVD + EPSS + CISA KEV) → composite risk scoring → "
    "RAG-grounded LLM remediation recommendations."
)

# --- Sidebar controls ---
with st.sidebar:
    st.header("Pipeline controls")
    st.write("Run these once locally to populate/update data.")

    if st.button("🔄 Run ingestion (NVD/EPSS/KEV)"):
        with st.spinner("Ingesting live vulnerability data..."):
            resp = requests.post(f"{API_BASE_URL}/ingest")
        if resp.ok:
            st.success(f"Ingestion complete in {resp.json()['duration_seconds']}s")
        else:
            st.error(f"Failed: {resp.text}")

    if st.button("🔗 Generate findings (asset x CVE match)"):
        with st.spinner("Matching assets to vulnerabilities and scoring..."):
            resp = requests.post(f"{API_BASE_URL}/findings/generate")
        if resp.ok:
            st.success("Findings generated.")
        else:
            st.error(f"Failed: {resp.text}")

    triage_limit = st.number_input("Findings to triage with LLM", min_value=1, max_value=50, value=5)
    if st.button("🤖 Run LLM triage"):
        with st.spinner(f"Generating remediation for top {triage_limit} findings via Claude..."):
            resp = requests.post(f"{API_BASE_URL}/triage/run", params={"limit": triage_limit})
        if resp.ok:
            st.success(f"Triaged in {resp.json()['duration_seconds']}s")
        else:
            st.error(f"Failed: {resp.text} (do you have ANTHROPIC_API_KEY set?)")

    st.divider()
    st.header("Evaluation")
    if st.button("📊 Run retrieval eval"):
        st.session_state["retrieval_eval"] = requests.get(f"{API_BASE_URL}/eval/retrieval").json()
    if st.button("📊 Run remediation eval (LLM judge)"):
        with st.spinner("Judging triaged findings via Claude..."):
            st.session_state["remediation_eval"] = requests.get(
                f"{API_BASE_URL}/eval/remediation", params={"limit": 10}
            ).json()

    st.divider()
    st.caption("Backend: " + API_BASE_URL)


# --- Stats overview ---
try:
    stats = requests.get(f"{API_BASE_URL}/stats").json()
except Exception as e:
    st.error(f"Can't reach backend API at {API_BASE_URL}. Is it running? (`uvicorn app.api.main:app --reload`)")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total findings", stats["total_findings"])
col2.metric("Critical", stats["findings_by_tier"].get("critical", 0))
col3.metric("Tracked CVEs", stats["total_vulnerabilities"])
col4.metric("In CISA KEV", stats["kev_vulnerabilities"])

st.divider()

# --- Findings table with filters ---
st.subheader("Findings")

fcol1, fcol2 = st.columns(2)
with fcol1:
    tier_filter = st.selectbox("Risk tier", ["All", "critical", "high", "medium", "low"])
with fcol2:
    status_filter = st.selectbox("Status", ["All", "open", "triaged", "remediated", "accepted_risk"])

params = {"limit": 100}
if tier_filter != "All":
    params["tier"] = tier_filter
if status_filter != "All":
    params["status"] = status_filter

findings = requests.get(f"{API_BASE_URL}/findings", params=params).json()

if not findings:
    st.info("No findings match these filters. Run ingestion + generate findings from the sidebar first.")
else:
    df = pd.DataFrame(findings)
    display_df = df[["cve_id", "asset_name", "vendor", "cvss_base_score", "epss_score",
                      "in_kev", "risk_score", "risk_tier", "status"]]
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Finding detail")
    selected_id = st.selectbox(
        "Select a finding to view remediation",
        options=df["id"].tolist(),
        format_func=lambda fid: f"{df[df.id==fid].iloc[0]['cve_id']} on {df[df.id==fid].iloc[0]['asset_name']}"
    )
    row = df[df.id == selected_id].iloc[0]

    c1, c2 = st.columns([1, 2])
    with c1:
        st.metric("Risk score", f"{row['risk_score']}/100")
        st.write(f"**Tier:** {row['risk_tier']}")
        st.write(f"**CVSS:** {row['cvss_base_score']}")
        st.write(f"**EPSS:** {row['epss_score']:.1%}" if row['epss_score'] else "**EPSS:** n/a")
        st.write(f"**In CISA KEV:** {'Yes ⚠️' if row['in_kev'] else 'No'}")
        st.write(f"**Status:** {row['status']}")

    with c2:
        st.write("**Remediation recommendation:**")
        if row["remediation_text"]:
            st.write(row["remediation_text"])
            if row["remediation_sources"]:
                st.caption("Sources: " + ", ".join(row["remediation_sources"]))
        else:
            st.info("Not yet triaged. Use 'Run LLM triage' in the sidebar to generate a recommendation.")

# --- Eval results (if run this session) ---
if "retrieval_eval" in st.session_state or "remediation_eval" in st.session_state:
    st.divider()
    st.subheader("Evaluation results")

    if "retrieval_eval" in st.session_state:
        r = st.session_state["retrieval_eval"]
        st.write("**Retrieval eval**")
        c1, c2, c3 = st.columns(3)
        c1.metric("Hit rate@3", r["hit_rate_at_k"])
        c2.metric("MRR", r["mrr"])
        c3.metric("Keyword hit rate", r["keyword_hit_rate"])
        with st.expander("Per-query detail"):
            st.dataframe(pd.DataFrame(r["per_query"]), use_container_width=True, hide_index=True)

    if "remediation_eval" in st.session_state:
        r = st.session_state["remediation_eval"]
        st.write("**Remediation eval**")
        if r["num_evaluated"] == 0:
            st.info("No triaged findings yet — run LLM triage first.")
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Structural pass rate", r["structural_pass_rate"])
            if "mean_groundedness" in r:
                c2.metric("Mean groundedness", r["mean_groundedness"])
                c3.metric("Mean actionability", r["mean_actionability"])
            with st.expander("Per-finding detail"):
                st.json(r["results"])
