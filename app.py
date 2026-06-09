"""
SSL Certificate Expiry Watcher — Streamlit Dashboard
=====================================================
Run with:  streamlit run app.py
"""

import io
import pandas as pd
import streamlit as st

from ssl_checker import scan_domains
from database import upsert_results, get_all_results
from llm_service import generate_report

# ── Page Config ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SSL Certificate Expiry Watcher",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ──────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Import Google Font ───────────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    /* ── Root Tokens ──────────────────────────────────────────────────── */
    :root {
        --bg-primary: #0f1117;
        --bg-card: #1a1d29;
        --bg-card-hover: #22263a;
        --accent-blue: #6c63ff;
        --accent-glow: rgba(108, 99, 255, 0.35);
        --safe: #00e676;
        --warning: #ffab00;
        --critical: #ff1744;
        --text-primary: #e8eaed;
        --text-muted: #9aa0a6;
        --border-subtle: rgba(255,255,255,0.06);
        --font: 'Inter', -apple-system, sans-serif;
    }

    html, body, [data-testid="stAppViewContainer"] {
        font-family: var(--font) !important;
    }

    /* ── Hero Header ──────────────────────────────────────────────────── */
    .hero {
        text-align: center;
        padding: 2.5rem 1rem 1.5rem;
    }
    .hero h1 {
        font-size: 2.6rem;
        font-weight: 800;
        background: linear-gradient(135deg, #6c63ff 0%, #48c6ef 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.25rem;
    }
    .hero p {
        color: var(--text-muted);
        font-size: 1.05rem;
        margin-top: 0;
    }

    /* ── Metric Cards ─────────────────────────────────────────────────── */
    .metric-row {
        display: flex;
        gap: 1rem;
        justify-content: center;
        flex-wrap: wrap;
        margin: 1.5rem 0;
    }
    .metric-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 14px;
        padding: 1.2rem 2rem;
        min-width: 170px;
        text-align: center;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.35);
    }
    .metric-card .value {
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1.1;
    }
    .metric-card .label {
        font-size: 0.8rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-top: 0.3rem;
    }

    /* ── Status Badges ────────────────────────────────────────────────── */
    .badge {
        display: inline-block;
        padding: 3px 12px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
    }
    .badge-safe     { background: rgba(0,230,118,0.15); color: var(--safe); }
    .badge-warning  { background: rgba(255,171,0,0.15); color: var(--warning); }
    .badge-critical { background: rgba(255,23,68,0.12); color: var(--critical); }
    .badge-error    { background: rgba(255,255,255,0.06); color: var(--text-muted); }

    /* ── Report Box ───────────────────────────────────────────────────── */
    .report-box {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 14px;
        padding: 1.5rem 2rem;
        margin-top: 1rem;
    }
    .report-source {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 8px;
        background: var(--accent-glow);
        color: var(--accent-blue);
        font-size: 0.78rem;
        font-weight: 600;
        margin-bottom: 1rem;
    }

    /* ── Misc Tweaks ──────────────────────────────────────────────────── */
    .stDataFrame { border-radius: 12px; overflow: hidden; }
    div[data-testid="stHorizontalBlock"] { gap: 0.75rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Session State Init ──────────────────────────────────────────────────
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "ai_report" not in st.session_state:
    st.session_state.ai_report = None
if "ai_source" not in st.session_state:
    st.session_state.ai_source = None

# ── Hero ────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="hero">'
    "  <h1>🔒 SSL Certificate Expiry Watcher</h1>"
    "  <p>Scan · Monitor · Get AI-Powered Risk Reports</p>"
    "</div>",
    unsafe_allow_html=True,
)

# ── Domain Input ────────────────────────────────────────────────────────
st.markdown("---")
domain_input = st.text_area(
    "🌐 Enter domains (comma-separated)",
    placeholder="google.com, github.com, expired.badssl.com",
    height=80,
    key="domain_input",
)

# ── Action Buttons Row ──────────────────────────────────────────────────
col_scan, col_report, col_csv = st.columns([1, 1, 1])

with col_scan:
    scan_clicked = st.button("🔍  Scan SSL Certificates", use_container_width=True, type="primary")
with col_report:
    report_clicked = st.button("🤖  Generate AI Report", use_container_width=True)
with col_csv:
    csv_clicked = st.button("📥  Export CSV", use_container_width=True)

# ── Scan Handler ────────────────────────────────────────────────────────
if scan_clicked:
    raw = domain_input.strip()
    if not raw:
        st.warning("⚠️ Please enter at least one domain.")
    else:
        domains = [d.strip() for d in raw.split(",") if d.strip()]
        with st.spinner("Scanning certificates…"):
            results = scan_domains(domains)
            upsert_results(results)
            st.session_state.scan_results = results
            # Clear old report when new scan happens
            st.session_state.ai_report = None
            st.session_state.ai_source = None
        st.success(f"✅ Scanned {len(results)} domain(s)")

# ── Results Display ─────────────────────────────────────────────────────
results = st.session_state.scan_results

if results:
    # Metric summary cards
    n_safe = sum(1 for r in results if r["status"] == "SAFE")
    n_warn = sum(1 for r in results if r["status"] == "WARNING")
    n_crit = sum(1 for r in results if r["status"] == "CRITICAL")
    n_err = sum(1 for r in results if r["status"] == "ERROR")

    st.markdown(
        f"""
        <div class="metric-row">
            <div class="metric-card">
                <div class="value" style="color:var(--text-primary)">{len(results)}</div>
                <div class="label">Total Scanned</div>
            </div>
            <div class="metric-card">
                <div class="value" style="color:var(--safe)">{n_safe}</div>
                <div class="label">Safe</div>
            </div>
            <div class="metric-card">
                <div class="value" style="color:var(--warning)">{n_warn}</div>
                <div class="label">Warning</div>
            </div>
            <div class="metric-card">
                <div class="value" style="color:var(--critical)">{n_crit}</div>
                <div class="label">Critical</div>
            </div>
            <div class="metric-card">
                <div class="value" style="color:var(--text-muted)">{n_err}</div>
                <div class="label">Errors</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Build a styled dataframe
    def _badge(status: str) -> str:
        css = {
            "SAFE": "badge-safe",
            "WARNING": "badge-warning",
            "CRITICAL": "badge-critical",
        }.get(status, "badge-error")
        return f'<span class="badge {css}">{status}</span>'

    table_rows = []
    for r in results:
        table_rows.append(
            {
                "Domain": r["domain"],
                "Expiry Date": r.get("expiry_date") or "—",
                "Days Left": r.get("days_left") if r.get("days_left") is not None else "—",
                "Status": r["status"],
                "Error": r.get("error") or "",
            }
        )

    df = pd.DataFrame(table_rows)

    # Color-code the Status column
    def _color_status(val):
        color_map = {"SAFE": "#00e676", "WARNING": "#ffab00", "CRITICAL": "#ff1744", "ERROR": "#9aa0a6"}
        color = color_map.get(val, "#9aa0a6")
        return f"color: {color}; font-weight: 600"

    styled = df.style.map(_color_status, subset=["Status"])
    st.dataframe(styled, use_container_width=True, hide_index=True, height=min(400, 60 + 35 * len(df)))

# ── AI Report Handler ──────────────────────────────────────────────────
if report_clicked:
    if not results:
        st.warning("⚠️ Run a scan first before generating a report.")
    else:
        with st.spinner("Generating AI risk report…"):
            response = generate_report(results)
            st.session_state.ai_report = response["report"]
            st.session_state.ai_source = response["source"]

if st.session_state.ai_report:
    st.markdown("---")
    st.markdown(
        f'<div class="report-source">🧠 Source: {st.session_state.ai_source}</div>',
        unsafe_allow_html=True,
    )
    with st.container():
        st.markdown(st.session_state.ai_report)

# ── CSV Export Handler ──────────────────────────────────────────────────
if csv_clicked:
    if not results:
        st.warning("⚠️ No scan data to export.")
    else:
        df_export = pd.DataFrame(results)
        csv_data = df_export.to_csv(index=False)
        st.session_state["_csv_data"] = csv_data

if st.session_state.get("_csv_data"):
    st.download_button(
        label="💾 Download CSV",
        data=st.session_state["_csv_data"],
        file_name="ssl_scan_results.csv",
        mime="text/csv",
    )

# ── Sidebar — Historical Data ──────────────────────────────────────────
with st.sidebar:
    st.markdown("### 📜 Scan History")
    st.caption("Previously scanned domains stored in the database.")
    history = get_all_results()
    if history:
        df_hist = pd.DataFrame(history)
        st.dataframe(df_hist, use_container_width=True, hide_index=True)
    else:
        st.info("No historical data yet. Run a scan to populate.")

# ── Footer ──────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<p style="text-align:center; color:#9aa0a6; font-size:0.82rem;">'
    "SSL Certificate Expiry Watcher &nbsp;·&nbsp; Built with Streamlit &nbsp;·&nbsp; "
    "Groq + OpenRouter + Fallback AI"
    "</p>",
    unsafe_allow_html=True,
)
