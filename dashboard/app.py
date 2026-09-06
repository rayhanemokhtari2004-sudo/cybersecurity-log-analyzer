import sys
import sqlite3
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Setup base directory and import paths
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from main import run_pipeline
from database.database import DB_PATH, create_database

# Set Streamlit page configuration
st.set_page_config(
    page_title="Cyber Sentinel — SSH Threat Detection & Security Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cyber Sentinel Dark SOC Theme
CSS_THEME = """
<style>
    /* Dark SOC Theme Colors */
    :root {
        --bg-dark: #0a0d14;
        --card-bg: #121722;
        --card-border: #1e293b;
        --cyan-neon: #00f0ff;
        --emerald-neon: #00ff88;
        --amber-neon: #ffb700;
        --crimson-neon: #ff0055;
        --text-bright: #f8fafc;
        --text-muted: #94a3b8;
    }
    
    /* Main Background & Container */
    .stApp {
        background-color: var(--bg-dark);
        color: var(--text-bright);
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    
    /* Header Card */
    .soc-header-card {
        background: linear-gradient(135deg, #121722 0%, #1a2333 100%);
        border: 1px solid #1e293b;
        border-left: 4px solid var(--cyan-neon);
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 240, 255, 0.05);
    }
    .soc-title {
        font-size: 28px;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: var(--text-bright);
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .soc-subtitle {
        font-size: 14px;
        color: var(--cyan-neon);
        margin-top: 4px;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    
    /* Badge styling */
    .soc-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.8px;
        text-transform: uppercase;
    }
    .badge-active {
        background: rgba(0, 255, 136, 0.15);
        color: var(--emerald-neon);
        border: 1px solid var(--emerald-neon);
    }
    .badge-critical {
        background: rgba(255, 0, 85, 0.2);
        color: var(--crimson-neon);
        border: 1px solid var(--crimson-neon);
    }
    .badge-high {
        background: rgba(255, 119, 0, 0.2);
        color: #ff7700;
        border: 1px solid #ff7700;
    }
    .badge-medium {
        background: rgba(255, 183, 0, 0.15);
        color: var(--amber-neon);
        border: 1px solid var(--amber-neon);
    }
    .badge-low {
        background: rgba(0, 240, 255, 0.15);
        color: var(--cyan-neon);
        border: 1px solid var(--cyan-neon);
    }
    .badge-success {
        background: rgba(0, 255, 136, 0.2);
        color: var(--emerald-neon);
    }
    .badge-failed {
        background: rgba(255, 0, 85, 0.2);
        color: var(--crimson-neon);
    }
    
    /* Metric Cards */
    .soc-metric-box {
        background-color: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    .soc-metric-title {
        font-size: 11px;
        font-weight: 700;
        color: var(--text-muted);
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 6px;
    }
    .soc-metric-val {
        font-size: 26px;
        font-weight: 800;
        color: var(--text-bright);
    }
    
    /* Security Score Box */
    .score-card {
        background: linear-gradient(180deg, #161f30 0%, #121722 100%);
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
    }
    .score-val {
        font-size: 48px;
        font-weight: 900;
        line-height: 1;
        margin: 10px 0;
    }
    
    /* Section Box Container */
    .soc-section {
        background-color: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .soc-section-title {
        font-size: 14px;
        font-weight: 800;
        color: var(--text-bright);
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 8px;
    }
    
    /* Alert Card */
    .alert-card {
        background: rgba(255, 0, 85, 0.08);
        border: 1px solid rgba(255, 0, 85, 0.4);
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 12px;
    }
    
    /* Empty State Box */
    .empty-state {
        background-color: var(--card-bg);
        border: 1px dashed var(--card-border);
        border-radius: 8px;
        padding: 40px;
        text-align: center;
        color: var(--text-muted);
    }
</style>
"""
st.markdown(CSS_THEME, unsafe_allow_html=True)


# Database helper functions
def load_db_data():
    """Loads logs, alerts, and ip_statistics from SQLite database into pandas DataFrames."""
    create_database(DB_PATH)
    conn = sqlite3.connect(DB_PATH)

    logs_df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
    alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn)
    stats_df = pd.read_sql_query("SELECT * FROM ip_statistics ORDER BY failed_attempts DESC", conn)

    conn.close()
    return logs_df, alerts_df, stats_df


def calculate_global_security_score(stats_df, alerts_df, logs_df):
    """Calculates a dynamic global security score (0-100) based on real threat metrics."""
    if logs_df.empty:
        return 100, "LOW", "#00ff88"

    failed_count = int((logs_df["status"] == "FAILED").sum())
    total_logs = len(logs_df)
    failure_rate = (failed_count / total_logs) if total_logs > 0 else 0

    critical_ips = int((stats_df["risk_level"] == "CRITICAL").sum()) if not stats_df.empty else 0
    high_ips = int((stats_df["risk_level"] == "HIGH").sum()) if not stats_df.empty else 0
    medium_ips = int((stats_df["risk_level"] == "MEDIUM").sum()) if not stats_df.empty else 0
    alert_count = len(alerts_df)

    # Dynamic deduction logic
    score = 100
    score -= critical_ips * 25
    score -= high_ips * 15
    score -= medium_ips * 8
    score -= alert_count * 10
    score -= int(failure_rate * 30)

    score = max(0, min(100, score))

    if score >= 85:
        level, color = "LOW", "#00ff88"
    elif score >= 65:
        level, color = "MEDIUM", "#ffb700"
    elif score >= 40:
        level, color = "HIGH", "#ff7700"
    else:
        level, color = "CRITICAL", "#ff0055"

    return score, level, color


# --- SIDEBAR CONTROL PANEL ---
with st.sidebar:
    st.markdown("""
        <div style='text-align: center; padding: 10px 0;'>
            <div style='font-size: 22px; font-weight: 900; letter-spacing: 2px; color: #00f0ff;'>CYBER SENTINEL</div>
            <div style='font-size: 11px; color: #94a3b8; margin-top: 2px;'>SECURITY OPERATIONS CENTER</div>
        </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("### SYSTEM STATUS")
    st.markdown("<span class='soc-badge badge-active'>● SYSTEM ONLINE</span>", unsafe_allow_html=True)
    st.markdown("**Data Source:** `data/auth.log`")
    st.markdown("**Database Engine:** `SQLite (security_logs.db)`")
    st.divider()

    st.markdown("### CONTROLS")
    if st.button("⚡ RUN ANALYSIS", use_container_width=True, type="primary"):
        with st.status("Executing Cyber Sentinel Analysis Pipeline...", expanded=True) as status:
            st.write("1. Verifying database schema...")
            st.write("2. Parsing SSH authentication logs...")
            st.write("3. Storing log events (idempotent)...")
            st.write("4. Computing IP statistics & risk scores...")
            st.write("5. Running 5-min sliding window brute force detection...")
            run_pipeline()
            status.update(label="Analysis Completed Successfully!", state="complete", expanded=False)
        st.cache_data.clear()
        st.rerun()

    if st.button("🔄 REFRESH DATA", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("""
        <div style='font-size: 11px; color: #64748b; text-align: center;'>
            Cyber Sentinel v1.0<br>SSH Threat Detection System
        </div>
    """, unsafe_allow_html=True)


# Load data from database
logs_df, alerts_df, stats_df = load_db_data()
score, threat_level, threat_color = calculate_global_security_score(stats_df, alerts_df, logs_df)
critical_threats_count = int((stats_df["risk_level"] == "CRITICAL").sum()) if not stats_df.empty else 0


# --- HEADER SECTION ---
col_head1, col_head2 = st.columns([3, 1])
with col_head1:
    st.markdown(f"""
        <div class="soc-header-card">
            <div class="soc-title">CYBER SENTINEL</div>
            <div class="soc-subtitle">SSH Threat Detection & Security Monitoring</div>
            <div style="margin-top: 12px; display: flex; gap: 10px; align-items: center;">
                <span class="soc-badge badge-active">● MONITORING ACTIVE</span>
                <span class="soc-badge badge-critical">CRITICAL THREATS: {critical_threats_count}</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

with col_head2:
    st.markdown(f"""
        <div class="score-card">
            <div class="soc-metric-title">GLOBAL SECURITY SCORE</div>
            <div class="score-val" style="color: {threat_color};">{score}<span style="font-size: 20px; color: #94a3b8;">/100</span></div>
            <div class="soc-metric-title" style="margin-top: 4px;">THREAT LEVEL</div>
            <div><span class="soc-badge" style="background: {threat_color}22; color: {threat_color}; border: 1px solid {threat_color}; font-size: 13px;">{threat_level}</span></div>
        </div>
    """, unsafe_allow_html=True)


# --- CHECK FOR EMPTY DATABASE ---
if logs_df.empty:
    st.markdown("""
        <div class="empty-state">
            <div style="font-size: 32px; margin-bottom: 10px;">🛡️</div>
            <div style="font-size: 20px; font-weight: 800; color: #f8fafc;">NO SECURITY EVENTS DETECTED</div>
            <div style="font-size: 14px; margin-top: 6px;">No SSH authentication logs are currently available in the database.</div>
            <div style="font-size: 13px; margin-top: 12px; color: #00f0ff;">Click <b>RUN ANALYSIS</b> in the sidebar to parse <code>auth.log</code> and generate security intelligence.</div>
        </div>
    """, unsafe_allow_html=True)
    st.stop()


# --- KPI METRICS CARDS ---
total_logs = len(logs_df)
failed_logins = int((logs_df["status"] == "FAILED").sum())
successful_logins = int((logs_df["status"] == "SUCCESS").sum())
unique_ips = logs_df["ip"].nunique()
alert_count = len(alerts_df)

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

with kpi1:
    st.markdown(f"""
        <div class="soc-metric-box">
            <div class="soc-metric-title">TOTAL LOGS</div>
            <div class="soc-metric-val">{total_logs}</div>
        </div>
    """, unsafe_allow_html=True)

with kpi2:
    st.markdown(f"""
        <div class="soc-metric-box">
            <div class="soc-metric-title">FAILED LOGINS</div>
            <div class="soc-metric-val" style="color: #ff0055;">{failed_logins}</div>
        </div>
    """, unsafe_allow_html=True)

with kpi3:
    st.markdown(f"""
        <div class="soc-metric-box">
            <div class="soc-metric-title">SUCCESS LOGINS</div>
            <div class="soc-metric-val" style="color: #00ff88;">{successful_logins}</div>
        </div>
    """, unsafe_allow_html=True)

with kpi4:
    st.markdown(f"""
        <div class="soc-metric-box">
            <div class="soc-metric-title">UNIQUE IPS</div>
            <div class="soc-metric-val" style="color: #00f0ff;">{unique_ips}</div>
        </div>
    """, unsafe_allow_html=True)

with kpi5:
    st.markdown(f"""
        <div class="soc-metric-box">
            <div class="soc-metric-title">ALERTS</div>
            <div class="soc-metric-val" style="color: #ffb700;">{alert_count}</div>
        </div>
    """, unsafe_allow_html=True)

with kpi6:
    st.markdown(f"""
        <div class="soc-metric-box">
            <div class="soc-metric-title">CRITICAL THREATS</div>
            <div class="soc-metric-val" style="color: #ff0055;">{critical_threats_count}</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)


# --- THREAT ACTIVITY VISUALIZATION ---
st.markdown("""
    <div class="soc-section-title">📊 THREAT ACTIVITY BY IP</div>
""", unsafe_allow_html=True)

if not stats_df.empty:
    fig_activity = go.Figure()
    fig_activity.add_trace(go.Bar(
        x=stats_df["ip"],
        y=stats_df["failed_attempts"],
        name="Failed Attempts",
        marker_color="#ff0055"
    ))
    fig_activity.add_trace(go.Bar(
        x=stats_df["ip"],
        y=stats_df["successful_attempts"],
        name="Successful Attempts",
        marker_color="#00ff88"
    ))
    fig_activity.update_layout(
        barmode='stack',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8'),
        margin=dict(l=20, r=20, t=20, b=30),
        height=320,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis=dict(gridcolor='#1e293b', title='IP Address'),
        yaxis=dict(gridcolor='#1e293b', title='Authentication Attempts')
    )
    st.plotly_chart(fig_activity, use_container_width=True)


# --- LIVE ACTIVITY & THREAT DETECTION (SPLIT 2 COLS) ---
col_act1, col_act2 = st.columns([3, 2])

with col_act1:
    st.markdown("<div class='soc-section-title'>⚡ LIVE SECURITY ACTIVITY</div>", unsafe_allow_html=True)
    recent_logs = logs_df.head(8)
    
    # Custom HTML list for live activity
    for _, row in recent_logs.iterrows():
        status_badge = "<span class='soc-badge badge-success'>SUCCESS</span>" if row["status"] == "SUCCESS" else "<span class='soc-badge badge-failed'>FAILED</span>"
        st.markdown(f"""
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: #161d2b; border-bottom: 1px solid #1e293b; border-radius: 4px; margin-bottom: 6px;">
                <div style="font-family: monospace; color: #94a3b8; font-size: 13px;">{row['timestamp']}</div>
                <div>{status_badge}</div>
                <div style="font-weight: 700; color: #00f0ff; font-family: monospace;">{row['ip']}</div>
                <div style="color: #f8fafc; font-size: 13px;">user: <span style="color: #ffb700;">{row['username']}</span></div>
                <div style="color: #64748b; font-size: 12px;">port {row['port']}</div>
            </div>
        """, unsafe_allow_html=True)

with col_act2:
    st.markdown("<div class='soc-section-title'>🔍 THREAT DETECTION SUMMARY</div>", unsafe_allow_html=True)
    suspicious_ips_count = int((stats_df["failed_attempts"] >= 3).sum()) if not stats_df.empty else 0
    brute_force_attacks_count = len(alerts_df)
    
    st.markdown(f"""
        <div style="background: #161d2b; padding: 16px; border-radius: 6px; border: 1px solid #1e293b;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                <span style="color: #94a3b8;">Brute Force Attacks</span>
                <span style="font-weight: 800; color: #ff0055;">{brute_force_attacks_count} DETECTED</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                <span style="color: #94a3b8;">Suspicious IPs</span>
                <span style="font-weight: 800; color: #ffb700;">{suspicious_ips_count} IDENTIFIED</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                <span style="color: #94a3b8;">Failed Logins Ratio</span>
                <span style="font-weight: 800; color: #f8fafc;">{(failed_logins / total_logs * 100):.1f}%</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #94a3b8;">Sliding Window Rule</span>
                <span style="font-weight: 700; color: #00f0ff;">5 failed / 5 min</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)


# --- TOP THREAT ACTORS ---
st.markdown("<div class='soc-section-title'>🎯 TOP THREAT ACTORS</div>", unsafe_allow_html=True)

if not stats_df.empty:
    top_actors = stats_df.sort_values(by=["failed_attempts", "risk_score"], ascending=False).head(5)
    cols = st.columns(min(len(top_actors), 5))

    for idx, (_, actor) in enumerate(top_actors.iterrows()):
        rank = idx + 1
        level = actor.get("risk_level", "LOW")
        score_val = actor.get("risk_score", 0)

        badge_class = f"badge-{level.lower()}"
        with cols[idx]:
            st.markdown(f"""
                <div style="background: #161d2b; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; text-align: center;">
                    <div style="font-size: 12px; font-weight: 800; color: #00f0ff;">#{rank} THREAT ACTOR</div>
                    <div style="font-size: 16px; font-weight: 800; color: #f8fafc; font-family: monospace; margin: 8px 0;">{actor['ip']}</div>
                    <div style="font-size: 13px; color: #ff0055; font-weight: 700;">{actor['failed_attempts']} failed attempts</div>
                    <div style="margin-top: 8px; font-size: 12px; color: #94a3b8;">Risk Score: <b style="color: #f8fafc;">{score_val}/100</b></div>
                    <div style="margin-top: 10px;"><span class="soc-badge {badge_class}">{level}</span></div>
                </div>
            """, unsafe_allow_html=True)

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)


# --- ALERT CENTER ---
st.markdown("<div class='soc-section-title'>🚨 ALERT CENTER</div>", unsafe_allow_html=True)

if alerts_df.empty:
    st.markdown("""
        <div style="background: #161d2b; border: 1px solid #1e293b; border-radius: 6px; padding: 16px; text-align: center; color: #00ff88;">
            ✔ NO ACTIVE SECURITY ALERTS DETECTED
        </div>
    """, unsafe_allow_html=True)
else:
    for _, alert in alerts_df.iterrows():
        lvl = alert.get("risk_level", "HIGH")
        st.markdown(f"""
            <div class="alert-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-weight: 800; color: #ff0055; letter-spacing: 1px;">🚨 {alert['attack_type']}</div>
                    <div><span class="soc-badge badge-critical">{lvl}</span></div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 12px; font-size: 13px;">
                    <div><span style="color: #94a3b8;">Target IP:</span> <b style="color: #00f0ff; font-family: monospace;">{alert['ip']}</b></div>
                    <div><span style="color: #94a3b8;">Failed Attempts:</span> <b style="color: #ff0055;">{alert['failed_attempts']}</b></div>
                    <div><span style="color: #94a3b8;">Risk Score:</span> <b style="color: #f8fafc;">{alert['risk_score']} / 100</b></div>
                    <div><span style="color: #94a3b8;">Time Window:</span> <span style="color: #f8fafc; font-family: monospace; font-size: 11px;">{alert['start_time']} - {alert['end_time']}</span></div>
                </div>
            </div>
        """, unsafe_allow_html=True)

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)


# --- IP INVESTIGATION ---
st.markdown("<div class='soc-section-title'>🔎 IP INVESTIGATION</div>", unsafe_allow_html=True)

if not stats_df.empty:
    selected_ip = st.selectbox("Select IP Address for Deep Threat Inspection:", stats_df["ip"].unique())
    ip_stats = stats_df[stats_df["ip"] == selected_ip].iloc[0]

    tot = ip_stats["total_attempts"]
    fail = ip_stats["failed_attempts"]
    succ = ip_stats["successful_attempts"]
    fail_rate = (fail / tot * 100) if tot > 0 else 0
    ip_score = ip_stats["risk_score"]
    ip_lvl = ip_stats["risk_level"]

    inv1, inv2, inv3, inv4, inv5, inv6 = st.columns(6)

    with inv1:
        st.markdown(f"<div class='soc-metric-box'><div class='soc-metric-title'>IP ADDRESS</div><div class='soc-metric-val' style='font-size: 16px; color: #00f0ff;'>{selected_ip}</div></div>", unsafe_allow_html=True)
    with inv2:
        st.markdown(f"<div class='soc-metric-box'><div class='soc-metric-title'>TOTAL ATTEMPTS</div><div class='soc-metric-val'>{tot}</div></div>", unsafe_allow_html=True)
    with inv3:
        st.markdown(f"<div class='soc-metric-box'><div class='soc-metric-title'>FAILED ATTEMPTS</div><div class='soc-metric-val' style='color: #ff0055;'>{fail}</div></div>", unsafe_allow_html=True)
    with inv4:
        st.markdown(f"<div class='soc-metric-box'><div class='soc-metric-title'>SUCCESS ATTEMPTS</div><div class='soc-metric-val' style='color: #00ff88;'>{succ}</div></div>", unsafe_allow_html=True)
    with inv5:
        st.markdown(f"<div class='soc-metric-box'><div class='soc-metric-title'>FAILURE RATE</div><div class='soc-metric-val'>{fail_rate:.0f}%</div></div>", unsafe_allow_html=True)
    with inv6:
        st.markdown(f"<div class='soc-metric-box'><div class='soc-metric-title'>RISK SCORE</div><div class='soc-metric-val'>{ip_score} ({ip_lvl})</div></div>", unsafe_allow_html=True)

    # Dynamic Threat Assessment Explanation
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    if fail >= 10:
        threat_assessment_text = f"CRITICAL THREAT: IP {selected_ip} generated an extremely high volume of failed authentication attempts ({fail} failures). Multiple brute force attempt patterns detected. Immediate IP block recommended."
        alert_bg = "rgba(255, 0, 85, 0.15)"
        alert_border = "#ff0055"
    elif fail >= 5:
        threat_assessment_text = f"HIGH THREAT: IP {selected_ip} generated {fail} failed authentication attempts within a short timeframe. Potential brute-force attack detected."
        alert_bg = "rgba(255, 119, 0, 0.15)"
        alert_border = "#ff7700"
    elif fail >= 3:
        threat_assessment_text = f"SUSPICIOUS ACTIVITY: IP {selected_ip} recorded {fail} failed login attempts. Flagged for security monitoring."
        alert_bg = "rgba(255, 183, 0, 0.15)"
        alert_border = "#ffb700"
    else:
        threat_assessment_text = f"NORMAL / LOW RISK: IP {selected_ip} shows standard user behavior ({succ} successful logins, {fail} failed attempts)."
        alert_bg = "rgba(0, 255, 136, 0.1)"
        alert_border = "#00ff88"

    st.markdown(f"""
        <div style="background: {alert_bg}; border: 1px solid {alert_border}; border-radius: 6px; padding: 14px 18px;">
            <div style="font-weight: 800; color: #f8fafc; font-size: 13px; text-transform: uppercase; margin-bottom: 4px;">THREAT ASSESSMENT</div>
            <div style="color: #f8fafc; font-size: 14px;">{threat_assessment_text}</div>
        </div>
    """, unsafe_allow_html=True)

    # IP Timeline Activity
    ip_logs = logs_df[logs_df["ip"] == selected_ip]
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    st.dataframe(
        ip_logs[["timestamp", "username", "port", "status"]],
        use_container_width=True,
        hide_index=True
    )

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)


# --- LOG EXPLORER WITH FILTERS ---
st.markdown("<div class='soc-section-title'>📂 LOG EXPLORER</div>", unsafe_allow_html=True)

col_f1, col_f2, col_f3 = st.columns(3)

with col_f1:
    ip_filter = st.multiselect("Filter by IP:", options=logs_df["ip"].unique(), default=[])
with col_f2:
    user_filter = st.multiselect("Filter by Username:", options=logs_df["username"].unique(), default=[])
with col_f3:
    status_filter = st.selectbox("Filter by Status:", options=["ALL", "FAILED", "SUCCESS"])

filtered_logs = logs_df.copy()

if ip_filter:
    filtered_logs = filtered_logs[filtered_logs["ip"].isin(ip_filter)]
if user_filter:
    filtered_logs = filtered_logs[filtered_logs["username"].isin(user_filter)]
if status_filter != "ALL":
    filtered_logs = filtered_logs[filtered_logs["status"] == status_filter]

st.dataframe(
    filtered_logs[["id", "timestamp", "username", "ip", "port", "status"]],
    use_container_width=True,
    hide_index=True
)
