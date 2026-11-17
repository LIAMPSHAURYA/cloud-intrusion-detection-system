"""
main.py — Cloud Intrusion Detection System Dashboard
Run with: streamlit run main.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from datetime import datetime

# ─── Local Modules ────────────────────────────────────────────────────────────
from simulator import generate_traffic_batch, generate_initial_history
from detector import run_detection, block_ip, flag_ip, filter_blocked_traffic
from utils import (
    alerts_to_csv, logs_to_csv, filter_alerts, filter_logs,
    compute_summary, severity_badge, attack_icon, SEVERITY_COLORS
)

# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Cloud IDS — Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* Google Font */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@400;600;700&display=swap');

/* Root theme */
:root {
    --bg-dark:    #0a0e1a;
    --bg-card:    #111827;
    --bg-panel:   #1a2035;
    --accent:     #00d4ff;
    --accent2:    #7c3aed;
    --danger:     #ff4b4b;
    --warning:    #ffa500;
    --success:    #00c49a;
    --text:       #e2e8f0;
    --text-muted: #64748b;
    --border:     rgba(0,212,255,0.15);
}

/* Hide Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1.5rem 2rem 2rem; }

/* Body */
body, .stApp {
    background-color: var(--bg-dark) !important;
    font-family: 'Rajdhani', sans-serif;
    color: var(--text);
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: var(--bg-card) !important;
    border-right: 1px solid var(--border);
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

/* Metric cards */
[data-testid="stMetric"] {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem 1.2rem;
    box-shadow: 0 0 20px rgba(0,212,255,0.05);
}
[data-testid="stMetricLabel"] { color: var(--text-muted) !important; font-size: 0.8rem; letter-spacing: 0.1em; text-transform: uppercase; }
[data-testid="stMetricValue"] { color: var(--accent) !important; font-family: 'JetBrains Mono', monospace; font-size: 2rem; }

/* Headings */
h1, h2, h3 { font-family: 'Rajdhani', sans-serif !important; color: var(--text) !important; }
h1 { color: var(--accent) !important; letter-spacing: 0.05em; }

/* Alert cards */
.alert-card {
    background: var(--bg-card);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.8rem;
    border-left: 4px solid;
    box-shadow: 0 2px 12px rgba(0,0,0,0.3);
    font-family: 'Rajdhani', sans-serif;
}
.alert-high   { border-color: #ff4b4b; }
.alert-medium { border-color: #ffa500; }
.alert-low    { border-color: #00c49a; }
.alert-title  { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.3rem; }
.alert-detail { font-size: 0.9rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
.alert-rec    { font-size: 0.85rem; color: #94a3b8; margin-top: 0.5rem; }

/* Tables */
[data-testid="stDataFrame"] { background: var(--bg-card); border-radius: 10px; }
.stDataFrame th { background: var(--bg-panel) !important; color: var(--accent) !important; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }
.stDataFrame td { color: var(--text) !important; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, var(--accent2), var(--accent)) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: 0.05em !important;
    transition: opacity 0.2s !important;
}
.stButton > button:hover { opacity: 0.85 !important; }

/* Status badge */
.status-dot {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 50%;
    margin-right: 6px;
    animation: pulse 1.5s infinite;
}
@keyframes pulse {
    0%,100% { opacity:1; }
    50% { opacity:0.4; }
}
.status-active   { background: var(--success); }
.status-inactive { background: var(--text-muted); animation: none; }

/* Section headers */
.section-header {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.4rem;
    margin-bottom: 1rem;
}

/* Plotly chart bg fix */
.js-plotly-plot { background: transparent !important; }

/* Scrollable alert container */
.alert-scroll {
    max-height: 480px;
    overflow-y: auto;
    padding-right: 4px;
}
</style>
""", unsafe_allow_html=True)


# ─── Session State Init ───────────────────────────────────────────────────────

def init_state():
    defaults = {
        "monitoring":   False,
        "logs":         generate_initial_history(40),
        "alerts":       [],
        "blocked_ips":  set(),
        "flagged_ips":  set(),
        "tick":         0,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ Cloud IDS")
    st.markdown("**Intrusion Detection System**")
    st.markdown("---")

    # Monitoring toggle
    mon_label = "⏹ Stop Monitoring" if st.session_state.monitoring else "▶ Start Monitoring"
    if st.button(mon_label, use_container_width=True):
        st.session_state.monitoring = not st.session_state.monitoring

    # Status indicator
    if st.session_state.monitoring:
        st.markdown('<p><span class="status-dot status-active"></span> <b>MONITORING ACTIVE</b></p>', unsafe_allow_html=True)
    else:
        st.markdown('<p><span class="status-dot status-inactive"></span> <b>MONITORING STOPPED</b></p>', unsafe_allow_html=True)

    st.markdown("---")

    # Attack rate slider
    st.markdown("### ⚙️ Simulation Settings")
    attack_ratio = st.slider("Attack Traffic Ratio", 0.0, 1.0, 0.25, 0.05,
                             help="Fraction of generated traffic that simulates attacks")
    batch_size = st.slider("Batch Size (logs/tick)", 5, 30, 10)
    refresh_interval = st.slider("Refresh Interval (sec)", 1, 10, 3)

    st.markdown("---")

    # Filters
    st.markdown("### 🔍 Filter Alerts")
    ip_filter   = st.text_input("Filter by IP", placeholder="e.g. 10.0.0")
    type_filter = st.selectbox("Attack Type", ["All", "DDoS", "Restricted Access", "Brute Force", "Anomaly"])
    sev_filter  = st.selectbox("Severity", ["All", "High", "Medium", "Low"])

    st.markdown("---")

    # Exports
    st.markdown("### 📥 Export Data")
    alert_csv = alerts_to_csv(st.session_state.alerts)
    st.download_button("Download Alerts CSV", alert_csv, "ids_alerts.csv", "text/csv", use_container_width=True)

    log_csv = logs_to_csv(st.session_state.logs)
    st.download_button("Download Logs CSV", log_csv, "ids_logs.csv", "text/csv", use_container_width=True)

    st.markdown("---")

    # Reset
    if st.button("🔄 Reset Dashboard", use_container_width=True):
        for k in ["logs", "alerts", "blocked_ips", "flagged_ips", "tick"]:
            del st.session_state[k]
        init_state()
        st.rerun()


# ─── Header ───────────────────────────────────────────────────────────────────

st.markdown("# 🛡️ CLOUD INTRUSION DETECTION SYSTEM")
st.markdown(f"<span style='color:#64748b; font-family:JetBrains Mono; font-size:0.85rem;'>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</span>", unsafe_allow_html=True)
st.markdown("---")

# ─── Monitoring Tick ──────────────────────────────────────────────────────────

if st.session_state.monitoring:
    # Generate new batch
    new_logs = generate_traffic_batch(n=batch_size, attack_ratio=attack_ratio)
    new_df   = pd.DataFrame(new_logs)

    # Filter out blocked IPs
    new_df = filter_blocked_traffic(new_df, st.session_state.blocked_ips)

    # Append to log history (keep last 500)
    st.session_state.logs = pd.concat(
        [st.session_state.logs, new_df], ignore_index=True
    ).tail(500)

    # Run detection on latest batch
    new_alerts = run_detection(new_df)
    st.session_state.alerts = (new_alerts + st.session_state.alerts)[:200]
    st.session_state.tick += 1


# ─── Summary Cards ────────────────────────────────────────────────────────────

summary = compute_summary(st.session_state.logs, st.session_state.alerts, st.session_state.blocked_ips)
c1, c2, c3, c4 = st.columns(4)
metrics = list(summary.items())
for col, (label, val) in zip([c1, c2, c3, c4], metrics):
    col.metric(label, f"{val:,}")

st.markdown("---")

# ─── Main Layout: Two Columns ─────────────────────────────────────────────────

left_col, right_col = st.columns([1.4, 1], gap="large")

# ══════════════════════════════════════════════════════════════════════════════
# LEFT: Traffic Monitoring + Charts
# ══════════════════════════════════════════════════════════════════════════════

with left_col:

    # ── Live Traffic Table ────────────────────────────────────────────────────
    st.markdown('<div class="section-header">📡 Live Traffic Monitor</div>', unsafe_allow_html=True)

    logs_df = st.session_state.logs.copy()
    display_cols = ["timestamp", "ip", "endpoint", "method", "status_code", "request_count"]
    filtered_logs = filter_logs(logs_df, ip_filter, "")

    st.dataframe(
        filtered_logs[display_cols].tail(15).iloc[::-1].reset_index(drop=True),
        use_container_width=True,
        height=230,
    )

    # ── Requests Over Time ────────────────────────────────────────────────────
    st.markdown('<div class="section-header">📈 Requests Over Time (by IP)</div>', unsafe_allow_html=True)

    if not logs_df.empty:
        top_ips = logs_df.groupby("ip")["request_count"].sum().nlargest(6).index.tolist()
        top_df  = logs_df[logs_df["ip"].isin(top_ips)].copy()
        top_df["timestamp"] = pd.to_datetime(top_df["timestamp"])
        top_df = top_df.sort_values("timestamp")

        fig_line = px.line(
            top_df, x="timestamp", y="request_count", color="ip",
            labels={"request_count": "Requests", "timestamp": "Time", "ip": "IP"},
            color_discrete_sequence=["#00d4ff","#7c3aed","#ff4b4b","#ffa500","#00c49a","#f472b6"],
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(17,24,39,0.9)",
            font_color="#e2e8f0",
            font_family="JetBrains Mono",
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0, r=0, t=10, b=0),
            height=240,
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        )
        st.plotly_chart(fig_line, use_container_width=True)

    # ── Attack Frequency Bar Chart ────────────────────────────────────────────
    st.markdown('<div class="section-header">⚔️ Attack Frequency by Type</div>', unsafe_allow_html=True)

    if st.session_state.alerts:
        alert_df = pd.DataFrame(st.session_state.alerts)
        freq = alert_df.groupby(["attack_type","severity"]).size().reset_index(name="count")
        color_map = {"High": "#ff4b4b", "Medium": "#ffa500", "Low": "#00c49a"}

        fig_bar = px.bar(
            freq, x="attack_type", y="count", color="severity",
            color_discrete_map=color_map,
            labels={"attack_type": "Attack Type", "count": "Count", "severity": "Severity"},
            barmode="stack",
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(17,24,39,0.9)",
            font_color="#e2e8f0",
            font_family="JetBrains Mono",
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0, r=0, t=10, b=0),
            height=220,
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    else:
        st.info("No attack data yet. Start monitoring to see charts.")

    # ── Top IPs Pie Chart ─────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🌐 Top Traffic Sources</div>', unsafe_allow_html=True)

    if not logs_df.empty:
        ip_totals = logs_df.groupby("ip")["request_count"].sum().nlargest(8).reset_index()
        fig_pie = px.pie(
            ip_totals, names="ip", values="request_count",
            color_discrete_sequence=px.colors.sequential.Plasma,
            hole=0.5,
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            font_family="JetBrains Mono",
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0, r=0, t=10, b=0),
            height=260,
        )
        st.plotly_chart(fig_pie, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# RIGHT: Alerts Panel + Prevention
# ══════════════════════════════════════════════════════════════════════════════

with right_col:

    # ── Alert Panel ───────────────────────────────────────────────────────────
    filtered_alerts = filter_alerts(
        st.session_state.alerts, ip_filter, type_filter, sev_filter
    )

    st.markdown(
        f'<div class="section-header">🚨 Alerts <span style="color:#64748b; font-size:0.85rem;">({len(filtered_alerts)} shown)</span></div>',
        unsafe_allow_html=True
    )

    if not filtered_alerts:
        if st.session_state.monitoring:
            st.success("✅ No intrusions detected. System clean.")
        else:
            st.info("▶ Press **Start Monitoring** to begin detection.")
    else:
        st.markdown('<div class="alert-scroll">', unsafe_allow_html=True)
        for alert in filtered_alerts[:30]:
            sev   = alert["severity"]
            atype = alert["attack_type"]
            css   = {"High":"alert-high","Medium":"alert-medium","Low":"alert-low"}[sev]
            icon  = attack_icon(atype)
            badge = severity_badge(sev)
            recs  = "<br>".join(alert["recommendations"][:2])
            blocked_tag = "🚫 <b>BLOCKED</b> · " if alert.get("blocked") else ""

            st.markdown(f"""
            <div class="alert-card {css}">
                <div class="alert-title">{icon} {atype} &nbsp;|&nbsp; {badge} {sev}</div>
                <div class="alert-detail">
                    {blocked_tag}🕐 {alert['timestamp']}<br>
                    📍 IP: <b>{alert['ip']}</b><br>
                    📝 {alert['detail']}
                </div>
                <div class="alert-rec">{recs}</div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")

    # ── Prevention Actions ────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🛠️ Prevention Actions</div>', unsafe_allow_html=True)

    # Get unique alert IPs for action selector
    alert_ips = list({a["ip"] for a in st.session_state.alerts})
    if alert_ips:
        selected_ip = st.selectbox("Select IP for action", alert_ips)
        btn_col1, btn_col2 = st.columns(2)
        with btn_col1:
            if st.button("🚫 Block IP", use_container_width=True):
                msg = block_ip(selected_ip, st.session_state.blocked_ips)
                # Mark alerts from this IP as blocked
                for a in st.session_state.alerts:
                    if a["ip"] == selected_ip:
                        a["blocked"] = True
                st.success(msg)
        with btn_col2:
            if st.button("🚩 Flag IP", use_container_width=True):
                msg = flag_ip(selected_ip, st.session_state.flagged_ips)
                st.warning(msg)
    else:
        st.info("No IPs to act on yet.")

    # Show blocked / flagged IPs
    if st.session_state.blocked_ips or st.session_state.flagged_ips:
        st.markdown("**Blocked IPs:**")
        for ip in sorted(st.session_state.blocked_ips):
            st.markdown(f"<span style='color:#ff4b4b; font-family:JetBrains Mono;'>🚫 {ip}</span>", unsafe_allow_html=True)
        st.markdown("**Flagged IPs:**")
        for ip in sorted(st.session_state.flagged_ips):
            st.markdown(f"<span style='color:#ffa500; font-family:JetBrains Mono;'>🚩 {ip}</span>", unsafe_allow_html=True)

    st.markdown("---")

    # ── Security Recommendations ──────────────────────────────────────────────
    st.markdown('<div class="section-header">💡 Security Recommendations</div>', unsafe_allow_html=True)

    attack_types_seen = list({a["attack_type"] for a in st.session_state.alerts})
    if attack_types_seen:
        tab_labels = attack_types_seen[:4]
        tabs = st.tabs(tab_labels)
        for tab, atype in zip(tabs, tab_labels):
            with tab:
                recs = next(
                    (a["recommendations"] for a in st.session_state.alerts if a["attack_type"] == atype),
                    []
                )
                for rec in recs:
                    st.markdown(f"- {rec}")
    else:
        st.markdown("""
        - 🔒 Keep all services patched and updated
        - 🛡️ Enable firewall rules for all cloud resources
        - 📊 Set up centralized log monitoring
        - 🔑 Enforce least-privilege IAM policies
        """)


# ─── Auto-Refresh ─────────────────────────────────────────────────────────────

if st.session_state.monitoring:
    time.sleep(refresh_interval)
    st.rerun()
