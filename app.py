"""
SSL Certificate Expiry Watcher — Streamlit Dashboard
=====================================================
Run with:  streamlit run app.py
"""

import io
import os
import pandas as pd
import streamlit as st
import altair as alt
from datetime import datetime

import config
from ssl_checker import scan_domains, get_ssl_expiry
from database import (
    upsert_results,
    get_all_results,
    delete_domain,
    get_all_monitored_domains,
    get_domain_history,
    get_result_by_domain
)
from llm_service import generate_report
from alerts_service import check_and_send_alerts, send_slack_alert, send_email_alert

# ── Page Config ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SSL Certificate Expiry Watcher",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
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
        padding: 1.5rem 1rem 1rem;
    }
    .hero h1 {
        font-size: 2.4rem;
        font-weight: 800;
        background: linear-gradient(135deg, #6c63ff 0%, #48c6ef 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.25rem;
    }
    .hero p {
        color: var(--text-muted);
        font-size: 1.0rem;
        margin-top: 0;
    }

    /* ── Metric Cards ─────────────────────────────────────────────────── */
    .metric-row {
        display: flex;
        gap: 0.75rem;
        justify-content: flex-start;
        flex-wrap: wrap;
        margin: 1.0rem 0;
    }
    .metric-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.0rem 1.5rem;
        min-width: 130px;
        flex: 1;
        text-align: center;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.3);
    }
    .metric-card .value {
        font-size: 2.0rem;
        font-weight: 700;
        line-height: 1.1;
    }
    .metric-card .label {
        font-size: 0.75rem;
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
if "test_notification_status" not in st.session_state:
    st.session_state.test_notification_status = None

# ── Save Env Configuration Helper ──────────────────────────────────────
def save_settings(updates: dict):
    from pathlib import Path
    
    env_file = config.ENV_FILE
    env_data = {}
    
    # Read existing fields
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env_data[k.strip()] = v.strip()
                    
    # Update new fields
    for k, v in updates.items():
        env_data[k.strip()] = str(v).strip()
        
    # Write back
    with open(env_file, "w", encoding="utf-8") as f:
        for k, v in env_data.items():
            f.write(f"{k}={v}\n")
            
    # Apply to running process environment
    for k, v in updates.items():
        os.environ[k] = str(v)
        
    # Hot-reload in memory config module
    config.SLACK_WEBHOOK_URL = env_data.get("SLACK_WEBHOOK_URL", "")
    config.SMTP_SERVER = env_data.get("SMTP_SERVER", "")
    config.SMTP_PORT = int(env_data.get("SMTP_PORT", "587") or "587")
    config.SMTP_USER = env_data.get("SMTP_USER", "")
    config.SMTP_PASSWORD = env_data.get("SMTP_PASSWORD", "")
    config.EMAIL_TO = env_data.get("EMAIL_TO", "")
    config.EMAIL_FROM = env_data.get("EMAIL_FROM", "ssl-watcher@localhost")

# ── Scanning Core Logic ─────────────────────────────────────────────────
def trigger_scan_on_list(domains: list[str]):
    if not domains:
        st.warning("⚠️ Please specify at least one valid domain.")
        return
    
    with st.spinner("Retrieving SSL certificate details…"):
        results = scan_domains(domains)
        upsert_results(results)
        st.session_state.scan_results = results
        # Clear AI report to force update
        st.session_state.ai_report = None
        st.session_state.ai_source = None
        
        # Dispatch notifications
        alert_status = check_and_send_alerts(results)
        
        success_msg = f"✅ Scanned {len(results)} domain(s)."
        if alert_status.get("sent"):
            channels = []
            if alert_status.get("slack"): channels.append("Slack")
            if alert_status.get("email"): channels.append("Email")
            success_msg += f" Alerts sent via: {', '.join(channels)}"
        st.success(success_msg)

# ── Header ──────────────────────────────────────────────────────────────
st.markdown(
    '<div class="hero">'
    "  <h1>🔒 SSL Certificate Expiry Watcher</h1>"
    "  <p>Scan · Monitor · Manage Alerts · Get AI-Powered Reports</p>"
    "</div>",
    unsafe_allow_html=True,
)

# ── Sidebar — Monitored List Overview ──────────────────────────────────
with st.sidebar:
    st.markdown("### 📋 Quick Watchlist")
    st.caption("Active domains currently saved in the database.")
    
    monitored_list = get_all_results()
    
    if monitored_list:
        sidebar_rows = []
        for r in monitored_list:
            status_indicator = "🟢"
            if r["status"] == "WARNING":
                status_indicator = "🟡"
            elif r["status"] == "CRITICAL":
                status_indicator = "🔴"
            elif r["status"] == "ERROR":
                status_indicator = "❌"
            
            days_str = f"{r['days_left']}d" if r["days_left"] is not None else "—"
            sidebar_rows.append({
                "Domain": f"{status_indicator} {r['domain']}",
                "Remaining": days_str
            })
        
        st.dataframe(pd.DataFrame(sidebar_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No monitored domains in database.")
        
    st.markdown("---")
    if st.button("⚡ Re-scan All Monitored Domains", use_container_width=True, type="primary"):
        all_domains = get_all_monitored_domains()
        if all_domains:
            trigger_scan_on_list(all_domains)
            st.rerun()
        else:
            st.warning("No domains in database to re-scan.")

# ── Tabs Configuration ──────────────────────────────────────────────────
tab_dashboard, tab_manage, tab_settings = st.tabs([
    "📊 Monitor Dashboard", 
    "📥 Import & Manage", 
    "⚙️ Alert Settings"
])

# ════════════════════════════════════════════════════════════════════════
# ── TAB 1: Monitor Dashboard ───────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════
with tab_dashboard:
    results = get_all_results()
    
    if not results:
        st.info("💡 No domain data available. Go to the **Import & Manage** tab to add domains to check!")
    else:
        # ── Summary Layout ──────────────────────────────────────────────
        n_safe = sum(1 for r in results if r["status"] == "SAFE")
        n_warn = sum(1 for r in results if r["status"] == "WARNING")
        n_crit = sum(1 for r in results if r["status"] == "CRITICAL")
        n_err = sum(1 for r in results if r["status"] == "ERROR")
        
        col_metrics, col_chart = st.columns([3, 2])
        
        with col_metrics:
            st.markdown(
                f"""
                <div class="metric-row">
                    <div class="metric-card">
                        <div class="value" style="color:var(--text-primary)">{len(results)}</div>
                        <div class="label">Total Monitored</div>
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
            
        with col_chart:
            # Altair status donut chart
            status_df = pd.DataFrame([
                {"Status": "SAFE", "Count": n_safe, "Color": "#00e676"},
                {"Status": "WARNING", "Count": n_warn, "Color": "#ffab00"},
                {"Status": "CRITICAL", "Count": n_crit, "Color": "#ff1744"},
                {"Status": "ERROR", "Count": n_err, "Color": "#9aa0a6"}
            ])
            status_df = status_df[status_df["Count"] > 0]
            
            if not status_df.empty:
                donut = alt.Chart(status_df).mark_arc(innerRadius=45, outerRadius=70).encode(
                    theta=alt.Theta(field="Count", type="quantitative"),
                    color=alt.Color(field="Status", type="nominal", scale=alt.Scale(
                        domain=status_df["Status"].tolist(),
                        range=status_df["Color"].tolist()
                    ), legend=alt.Legend(orient="right")),
                    tooltip=["Status", "Count"]
                ).properties(height=140)
                st.altair_chart(donut, use_container_width=True)
                
        # ── Main Table ──────────────────────────────────────────────────
        st.markdown("### 🔒 Current Domain Expiry Status")
        
        table_rows = []
        for r in results:
            table_rows.append({
                "Domain": r["domain"],
                "Expiry Date": r.get("expiry_date") or "—",
                "Days Left": r.get("days_left") if r.get("days_left") is not None else "—",
                "Status": r["status"],
                "Valid": "Yes" if r.get("is_valid") == 1 else ("No" if r.get("expiry_date") else "Unknown"),
                "Last Checked": r.get("last_checked") or "—",
                "Error": r.get("error") or "None"
            })
            
        df = pd.DataFrame(table_rows)
        
        def _color_status(val):
            color_map = {
                "SAFE": "#00e676",
                "WARNING": "#ffab00",
                "CRITICAL": "#ff1744",
                "ERROR": "#9aa0a6"
            }
            color = color_map.get(val, "#9aa0a6")
            return f"color: {color}; font-weight: 700"
            
        styled_df = df.style.map(_color_status, subset=["Status"])
        st.dataframe(
            styled_df, 
            use_container_width=True, 
            hide_index=True, 
            column_config={
                "Days Left": st.column_config.NumberColumn("Days Left", format="%d days"),
                "Expiry Date": st.column_config.TextColumn("Expiry Date"),
                "Last Checked": st.column_config.TextColumn("Last Checked"),
                "Valid": st.column_config.TextColumn("Valid"),
                "Error": st.column_config.TextColumn("Handshake Error")
            }
        )
        
        # ── Action Buttons for Report & Export ──────────────────────────
        col_r1, col_r2, _ = st.columns([1, 1, 2])
        with col_r1:
            report_clicked = st.button("🤖 Generate AI Risk Report", use_container_width=True, type="primary")
        with col_r2:
            # CSV Download
            df_export = pd.DataFrame(results)
            csv_data = df_export.to_csv(index=False)
            st.download_button(
                label="📥 Export CSV Data",
                data=csv_data,
                file_name="ssl_watch_results.csv",
                mime="text/csv",
                use_container_width=True
            )
            
        # ── AI Report View ──────────────────────────────────────────────
        if report_clicked:
            with st.spinner("Analyzing data and generating risk report…"):
                response = generate_report(results)
                st.session_state.ai_report = response["report"]
                st.session_state.ai_source = response["source"]
                
        if st.session_state.ai_report:
            st.markdown(
                f'<div class="report-box">'
                f'  <div class="report-source">🧠 Source: {st.session_state.ai_source}</div>'
                f'  {st.session_state.ai_report}'
                f'</div>',
                unsafe_allow_html=True
            )
            
        # ── Certificate Inspector Section ───────────────────────────────
        st.markdown("---")
        st.markdown("### 🔍 Certificate Inspector")
        st.caption("Select a domain to inspect advanced details and view history charts.")
        
        inspector_domains = [r["domain"] for r in results]
        selected_domain = st.selectbox("Choose a domain:", ["Select a domain..."] + inspector_domains)
        
        if selected_domain and selected_domain != "Select a domain...":
            det = get_result_by_domain(selected_domain)
            if det:
                col_det_left, col_det_right = st.columns([1, 1])
                
                with col_det_left:
                    st.markdown("#### 📋 Metadata Details")
                    st.markdown(f"**Domain:** `{det['domain']}`")
                    st.markdown(f"**Valid Certificate:** `{'Yes' if det.get('is_valid') == 1 else 'No'}`")
                    st.markdown(f"**Expiry Date:** `{det.get('expiry_date') or '—'}`")
                    
                    days_left = det.get("days_left")
                    if days_left is not None:
                        days_color = "red" if days_left < 7 else ("orange" if days_left < 30 else "green")
                        st.markdown(f"**Days Left:** <span style='color:{days_color}; font-weight:700'>{days_left}</span>", unsafe_allow_html=True)
                    else:
                        st.markdown("**Days Left:** `—`")
                        
                    st.markdown(f"**Issuer:** `{det.get('issuer') or 'Unknown'}`")
                    st.markdown(f"**Subject:** `{det.get('subject') or 'Unknown'}`")
                    st.markdown(f"**Serial Number:** `{det.get('serial_number') or 'Unknown'}`")
                    st.markdown(f"**Last Checked:** `{det.get('last_checked') or '—'}`")
                    
                    if det.get("error"):
                        st.error(f"❌ **Error Details:** {det['error']}")
                        
                    if st.button("🔄 Force Re-scan This Domain", use_container_width=True):
                        with st.spinner(f"Re-scanning {selected_domain}…"):
                            new_r = get_ssl_expiry(selected_domain)
                            upsert_result(new_r)
                            st.success(f"Scanned {selected_domain}!")
                            st.rerun()
                            
                with col_det_right:
                    st.markdown("#### 📈 Scan History Trend")
                    hist = get_domain_history(selected_domain)
                    if hist:
                        df_hist = pd.DataFrame(hist)
                        df_plot = df_hist[df_hist["days_left"].notna()].copy()
                        
                        if not df_plot.empty:
                            df_plot["Checked Time"] = pd.to_datetime(df_plot["timestamp"])
                            
                            hist_chart = alt.Chart(df_plot).mark_line(point=True, color="#6c63ff").encode(
                                x=alt.X("Checked Time:T", title="Time Checked"),
                                y=alt.Y("days_left:Q", title="Days Left"),
                                tooltip=["timestamp", "days_left", "status"]
                            ).properties(height=200)
                            
                            st.altair_chart(hist_chart, use_container_width=True)
                        else:
                            st.info("No expiry days recorded in history yet (domain failed verification).")
                            
                        # Show raw history records
                        st.markdown("**Raw History Log**")
                        st.dataframe(
                            df_hist[["timestamp", "days_left", "status", "error"]],
                            use_container_width=True,
                            hide_index=True,
                            height=120
                        )
                    else:
                        st.info("No scan history recorded yet.")

# ════════════════════════════════════════════════════════════════════════
# ── TAB 2: Import & Manage ─────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════
with tab_manage:
    st.markdown("### ➕ Add Domains for Monitoring")
    st.caption("Input domains manually or upload a structured text or CSV file.")
    
    col_input_left, col_input_right = st.columns([1, 1])
    
    with col_input_left:
        text_domains = st.text_area(
            "🌐 Option A: Enter domains (comma-separated)",
            placeholder="example.com, myapp.org, invalid.badssl.com",
            height=120,
            help="Specify domain names separated by commas. Prefixes like https:// will be auto-trimmed."
        )
        
    with col_input_right:
        uploaded_file = st.file_uploader(
            "📁 Option B: Upload domains file (.txt or .csv)",
            type=["txt", "csv"],
            help="For text files, list one domain per line. For CSVs, any columns matching domain regex will be parsed."
        )
        
    # Compile inputs
    parsed_domains = []
    if text_domains.strip():
        parsed_domains.extend([d.strip() for d in text_domains.split(",") if d.strip()])
        
    if uploaded_file is not None:
        try:
            content = uploaded_file.read().decode("utf-8")
            if uploaded_file.name.endswith(".csv"):
                import csv
                reader = csv.reader(io.StringIO(content))
                for row in reader:
                    for val in row:
                        val_cleaned = val.strip()
                        if "." in val_cleaned and not val_cleaned.startswith("#") and " " not in val_cleaned:
                            parsed_domains.append(val_cleaned)
            else:
                for line in content.splitlines():
                    val_cleaned = line.strip()
                    if val_cleaned and not val_cleaned.startswith("#") and "." in val_cleaned:
                        parsed_domains.append(val_cleaned)
        except Exception as exc:
            st.error(f"Failed parsing file: {exc}")
            
    # Deduplicate domains list
    parsed_domains = list(dict.fromkeys(parsed_domains))
    
    if parsed_domains:
        st.info(f"📋 Ready to scan **{len(parsed_domains)}** unique domain(s).")
        if st.button("🔍 Run Scan & Monitor", type="primary", use_container_width=True):
            trigger_scan_on_list(parsed_domains)
            st.rerun()
            
    st.markdown("---")
    st.markdown("### 🗑️ Delete Monitored Domains")
    st.caption("Remove domains from the list of monitored certificates. This deletes their status and history.")
    
    all_domains = get_all_monitored_domains()
    if all_domains:
        domains_to_delete = st.multiselect("Select domains to delete:", all_domains)
        if domains_to_delete:
            st.warning(f"⚠️ Warning: This will delete status and history records for: {', '.join(domains_to_delete)}.")
            if st.button("🔴 Confirm Delete", use_container_width=True):
                for d in domains_to_delete:
                    delete_domain(d)
                st.success("Successfully deleted domains.")
                st.rerun()
    else:
        st.info("No domains in database to delete.")

# ════════════════════════════════════════════════════════════════════════
# ── TAB 3: Alert Settings ──────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════
with tab_settings:
    st.markdown("### ⚙️ Configure Alerts & Integrations")
    st.caption("Configure notification channels to receive warnings when certificates are expiring.")
    
    # Reload config variables into form state
    slack_webhook = st.text_input("Slack Webhook URL", value=config.SLACK_WEBHOOK_URL, placeholder="https://hooks.slack.com/services/...")
    
    st.markdown("#### 📧 SMTP Email Settings")
    smtp_srv = st.text_input("SMTP Server", value=config.SMTP_SERVER, placeholder="smtp.gmail.com")
    smtp_prt = st.text_input("SMTP Port", value=str(config.SMTP_PORT))
    smtp_usr = st.text_input("SMTP Username", value=config.SMTP_USER, placeholder="admin@example.com")
    smtp_pwd = st.text_input("SMTP Password", value=config.SMTP_PASSWORD, type="password", placeholder="••••••••••••••••")
    email_t = st.text_input("Recipient Email (To)", value=config.EMAIL_TO, placeholder="ops-alerts@example.com")
    email_f = st.text_input("Sender Email (From)", value=config.EMAIL_FROM)
    
    col_save, col_test = st.columns([1, 1])
    
    with col_save:
        if st.button("💾 Save Settings", use_container_width=True, type="primary"):
            try:
                port_int = int(smtp_prt.strip() or "587")
            except ValueError:
                port_int = 587
                
            save_settings({
                "SLACK_WEBHOOK_URL": slack_webhook.strip(),
                "SMTP_SERVER": smtp_srv.strip(),
                "SMTP_PORT": str(port_int),
                "SMTP_USER": smtp_usr.strip(),
                "SMTP_PASSWORD": smtp_pwd,
                "EMAIL_TO": email_t.strip(),
                "EMAIL_FROM": email_f.strip()
            })
            st.success("Saved notification configurations successfully!")
            st.rerun()
            
    with col_test:
        if st.button("🧪 Dispatch Test Alert", use_container_width=True):
            test_results = [{"domain": "test-alert.com", "days_left": 3, "status": "CRITICAL", "error": "This is a test notification."}]
            with st.spinner("Dispatching test notifications…"):
                slack_ok = False
                email_ok = False
                
                # Test Slack
                if slack_webhook.strip():
                    test_slack_msg = "🧪 *SSL Expiry Watcher Test Alert* 🧪\nThis test message verifies your Slack Webhook configuration is working correctly."
                    slack_ok = send_slack_alert(test_slack_msg, webhook_url=slack_webhook.strip())
                
                # Test Email
                if smtp_srv.strip() and email_t.strip():
                    test_cfg = {
                        "server": smtp_srv.strip(),
                        "port": smtp_prt.strip(),
                        "user": smtp_usr.strip(),
                        "password": smtp_pwd,
                        "to": email_t.strip(),
                        "from": email_f.strip()
                    }
                    email_ok = send_email_alert(
                        "[TEST] SSL Certificate Expiry Alert Test",
                        "This is a test notification to verify your SMTP settings are working correctly.",
                        smtp_config=test_cfg
                    )
                
                st.session_state.test_notification_status = {
                    "slack": slack_ok,
                    "slack_configured": bool(slack_webhook.strip()),
                    "email": email_ok,
                    "email_configured": bool(smtp_srv.strip() and email_t.strip())
                }
                
    if st.session_state.test_notification_status:
        st.markdown("#### 🔬 Test Dispatch Report")
        stat = st.session_state.test_notification_status
        if stat["slack_configured"]:
            if stat["slack"]:
                st.success("✅ Slack test message successfully delivered.")
            else:
                st.error("❌ Slack delivery failed. Verify webhook URL or check connection logs.")
        if stat["email_configured"]:
            if stat["email"]:
                st.success("✅ Email test message successfully delivered.")
            else:
                st.error("❌ Email delivery failed. Verify server name, port, authentication credentials, and recipients.")
        if not (stat["slack_configured"] or stat["email_configured"]):
            st.info("No credentials supplied. Configure fields and trigger test alert again.")

# ── Footer ──────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<p style="text-align:center; color:#9aa0a6; font-size:0.82rem;">'
    "SSL Certificate Expiry Watcher &nbsp;·&nbsp; Built with Streamlit &nbsp;·&nbsp; "
    "Groq + OpenRouter + Fallback AI"
    "</p>",
    unsafe_allow_html=True,
)
