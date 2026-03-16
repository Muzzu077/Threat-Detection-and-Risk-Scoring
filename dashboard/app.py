import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os
import time
from dotenv import load_dotenv

# 1️⃣ Get project root (one level above dashboard/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)

# 2️⃣ Load .env explicitly using absolute path
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# 3️⃣ Imports
from src.database import db
from utils.auth import check_password
from utils.constants import RISK_HIGH_THRESHOLD

st.set_page_config(page_title="ThreatPulse", layout="wide", page_icon="🛡️")

# Custom SOC CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;700&display=swap');

    /* Global Theme */
    .stApp {
        background-color: #09090b; /* Zinc 950 */
        font-family: 'Inter', sans-serif;
        color: #e4e4e7; /* Zinc 200 */
    }

    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', sans-serif !important;
        color: #ffffff !important;
        font-weight: 600;
        letter-spacing: -0.02em;
        text-transform: none !important;
    }

    /* Streamlit Components Override */
    .stButton>button {
        color: #09090b;
        background-color: #ffffff;
        border: none;
        border-radius: 6px;
        font-family: 'Inter', sans-serif;
        font-weight: 500;
        font-size: 14px;
        transition: all 0.2s;
    }
    .stButton>button:hover {
        background-color: #d4d4d8; /* Zinc 300 */
        box-shadow: 0 0 15px rgba(255, 255, 255, 0.1);
    }

    /* Card / Container Styling */
    div[data-testid="stMetric"] {
        background-color: #18181b; /* Zinc 900 */
        padding: 20px;
        border: 1px solid #27272a; /* Zinc 800 */
        border-radius: 8px;
    }
    div[data-testid="stMetricLabel"] {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #a1a1aa; /* Zinc 400 */
        letter-spacing: 0.1em;
        text-transform: uppercase;
    }
    div[data-testid="stMetricValue"] {
        font-family: 'Inter', sans-serif;
        font-weight: 300;
        color: #ffffff;
    }

    /* Incident Card */
    .incident-card {
        background-color: #18181b;
        border: 1px solid #27272a;
        border-left: 3px solid #ef4444; /* Red 500 */
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 12px;
        transition: transform 0.2s;
    }
    .incident-card:hover {
        border-color: #3f3f46;
        transform: translateX(4px);
    }
    .incident-card h4 {
        font-size: 16px;
        margin-bottom: 8px;
        font-family: 'JetBrains Mono', monospace !important;
    }
    .incident-card p {
        font-size: 13px;
        color: #a1a1aa;
        margin: 2px 0;
    }
    
    /* Stats Banner */
    .status-banner {
        background: linear-gradient(90deg, #18181b 0%, #09090b 100%);
        border: 1px solid #27272a;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        margin-bottom: 32px;
    }
    .status-critical { border-color: #ef4444; color: #f87171; }
    .status-safe { border-color: #10b981; color: #34d399; }

    /* Dataframe */
    [data-testid="stDataFrame"] {
        border: 1px solid #27272a;
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

# Session State
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'page' not in st.session_state:
    st.session_state.page = 'dashboard'
if 'selected_incident' not in st.session_state:
    st.session_state.selected_incident = None

def login():
    c1, c2, c3 = st.columns([1,2,1])
    with c2:
        st.title("🛡️ ThreatPulse ACCESS")
        username = st.text_input("Operator ID")
        password = st.text_input("Access Key", type="password")
        if st.button("AUTHENTICATE"):
            if check_password(username, password):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("ACCESS DENIED")

def investigation_page(incident_id):
    st.title(f"🕵️ INCIDENT INVESTIGATION | ID: {incident_id}")
    
    if st.button("⬅️ BACK TO DASHBOARD"):
        st.session_state.page = 'dashboard'
        st.rerun()
        
    incident, log_event = db.get_incident_details(incident_id)
    
    if not incident:
        st.error("Incident not found.")
        return

    # Header Metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("STATUS", incident.status)
    c2.metric("RISK SCORE", f"{incident.risk_score:.1f}")
    c3.metric("USER", incident.user)
    c4.metric("OWNER", incident.owner)
    
    st.markdown("---")
    
    # Context columns
    c1, c2 = st.columns([2, 1])
    
    with c1:
        st.subheader("📝 EVENT DETAILS")
        st.markdown(f"**TIMESTAMP:** {incident.timestamp}")
        st.markdown(f"**ACTION:** `{incident.action}`")
        if log_event:
            st.markdown(f"**IP ADDRESS:** `{log_event.ip}`")
            st.markdown(f"**ROLE:** `{log_event.role}`")
            st.markdown(f"**RESOURCE:** `{log_event.resource}`")
            
            st.subheader("💡 AI EXPLANATION")
            st.info(log_event.explanation)
        else:
            st.warning("Raw log event details unavailable.")
            
    with c2:
        st.subheader("⚙️ ACTIONS")
        status_options = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        # Default to current status or OPEN
        current_status = incident.status if incident.status in status_options else "OPEN"
        current_idx = status_options.index(current_status)
        new_status = st.selectbox("UPDATE STATUS", status_options, index=current_idx)
        
        if st.button("UPDATE INCIDENT"):
            db.update_incident_status(incident.id, new_status, owner="Admin")
            st.success("Status Updated")
            time.sleep(1)
            st.rerun()

def main_dashboard():
    st.title("🛡️ ThreatPulse DASHBOARD")
    # Auto-Refresh
    if st.checkbox("LIVE FEED ACTIVE", value=True):
        time.sleep(3)
        st.rerun()

    # Fetch Data
    incidents = db.fetch_incidents()
    active_incidents = [i for i in incidents if i.status in ["OPEN", "INVESTIGATING"]]
    resolved_incidents = [i for i in incidents if i.status == "RESOLVED"]
    events = db.fetch_all_events()
    
    # --- 1. LIVE STATUS BANNER ---
    if active_incidents:
        st.markdown(f"""
        <div class="status-banner status-critical">
            🚨 SYSTEM STATUS: CRITICAL - {len(active_incidents)} ACTIVE INCIDENTS
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-banner status-safe">
            ✅ SYSTEM STATUS: SECURE - MONITORING ACTIVE
        </div>
        """, unsafe_allow_html=True)
        
    # --- 2. KPI ROW ---
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("TOTAL EVENTS", len(events))
    c2.metric("OPEN INCIDENTS", len(active_incidents), delta_color="inverse")
    c3.metric("RESOLVED INCIDENTS", len(resolved_incidents))
    recent_risk = events[0].risk_score if events else 0
    c4.metric("LATEST RISK SCORE", f"{recent_risk:.1f}", delta=f"{recent_risk - 50:.1f}" if events else 0, delta_color="inverse")
    c5.metric("SYSTEM UPTIME", "99.9%")
    
    st.markdown("---")

    # --- 3. ANALYTICS & VISUALIZATIONS ---
    st.subheader("📊 THREAT ANALYTICS")
    c1, c2 = st.columns(2)
    
    # Data Prep
    df_events = pd.DataFrame([{
        'Risk Score': e.risk_score,
        'hour': e.timestamp.hour
    } for e in events])
    
    if not df_events.empty:
        with c1:
            # Chart 1: Event Frequency Distribution by Risk Severity
            # Create buckets
            def get_bucket(score):
                if score >= 85: return "Critical"
                if score >= 61: return "High"
                if score >= 31: return "Medium"
                return "Low"
            
            df_events['Severity'] = df_events['Risk Score'].apply(get_bucket)
            df_severity = df_events['Severity'].value_counts().reindex(["Low", "Medium", "High", "Critical"], fill_value=0).reset_index()
            df_severity.columns = ["Severity", "Count"]
            
            # Colors: Low=Blue, Med=Amber, High=Orange, Crit=Red
            sev_colors = {"Low": "#2563EB", "Medium": "#F59E0B", "High": "#F97316", "Critical": "#DC2626"}
            
            fig_bar = px.bar(
                df_severity, 
                x="Severity", 
                y="Count", 
                color="Severity",
                color_discrete_map=sev_colors,
                title="Event Frequency Distribution by Risk Severity",
                text="Count"
            )
            fig_bar.update_traces(marker_line_width=0)
            fig_bar.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", 
                paper_bgcolor="rgba(0,0,0,0)", 
                font_color="#e4e4e7",
                showlegend=False,
                xaxis_title="Risk Severity Level",
                yaxis_title="Number of Events",
                yaxis=dict(showgrid=True, gridcolor="#27272a")
            )
            st.plotly_chart(fig_bar, width="stretch")
            
        with c2:
            # Chart 2: Hourly Average Risk Trend
            hourly_risk = df_events.groupby('hour')['Risk Score'].mean().reset_index()
            # Ensure all hours 0-23 exist for correct trending
            full_hours = pd.DataFrame({'hour': range(24)})
            hourly_risk = full_hours.merge(hourly_risk, on='hour', how='left').fillna(0)

            fig_line = px.line(
                hourly_risk, 
                x='hour', 
                y='Risk Score', 
                title="Hourly Average Risk Trend", 
                markers=True
            )
            fig_line.update_traces(line_color="#ffffff", line_shape="spline", marker_color="#ffffff")
            
            # Critical Threshold Line
            fig_line.add_hline(y=85, line_dash="dash", line_color="#DC2626", annotation_text="Critical Alert Threshold", annotation_position="bottom right", annotation_font_color="#DC2626")
            
            fig_line.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", 
                paper_bgcolor="rgba(0,0,0,0)", 
                font_color="#e4e4e7",
                xaxis_title="Hour of Day (0-23)",
                yaxis_title="Average Risk Score",
                yaxis=dict(range=[0, 100], showgrid=True, gridcolor="#27272a"),
                xaxis=dict(showgrid=False)
            )
            st.plotly_chart(fig_line, width="stretch")
    
    st.markdown("---")

    # --- 4. INCIDENT COMMAND CENTER ---
    col_incidents, col_feed = st.columns([2, 3])
    
    with col_incidents:
        st.subheader("🛑 CRITICAL INCIDENTS")
        if not active_incidents:
            st.info("No active threats. Systems nominal.")
        
        for inc in active_incidents:
            with st.container():
                st.markdown(f"""
                <div class="incident-card">
                    <h4>INCIDENT #{inc.id} | {inc.status}</h4>
                    <p><b>User:</b> {inc.user} | <b>Risk:</b> {inc.risk_score}</p>
                    <p><b>Action:</b> {inc.action}</p>
                    <p><i>{inc.timestamp.strftime('%H:%M:%S')}</i></p>
                </div>
                """, unsafe_allow_html=True)
                
                # Management Actions
                c_a, c_b = st.columns(2)
                if c_a.button("INVESTIGATE", key=f"inv_{inc.id}"):
                    if inc.status == "OPEN":
                        db.update_incident_status(inc.id, "INVESTIGATING", owner="Admin")
                    st.session_state.selected_incident = inc.id
                    st.session_state.page = 'investigation'
                    st.rerun()
                if c_b.button("RESOLVE", key=f"res_{inc.id}"):
                    db.update_incident_status(inc.id, "RESOLVED")
                    st.rerun()
    
    with col_feed:
        st.subheader("📠 LIVE TELEMETRY FEED")
        
        # Convert events to DF for display
        if events:
            data = [{
                'TIME': e.timestamp.strftime('%H:%M:%S'),
                'USER': e.user,
                'ACTION': e.action,
                'RESOURCE': e.resource,
                'RISK': f"{e.risk_score:.0f}",
                'STATUS': e.status
            } for e in events]
            
            df_feed = pd.DataFrame(data)
            
            def highlight_row(row):
                if int(row['RISK']) > 80:
                    return ['background-color: #3f1818; color: #fca5a5']*len(row) # Dark Red bg / Light Red text
                elif int(row['RISK']) > 50:
                    return ['background-color: #27272a; color: #fcd34d']*len(row) # Zinc 800 bg / Amber text
                else:
                    return ['color: #e4e4e7']*len(row) # Zinc 200 text

            st.dataframe(
                df_feed.style.apply(highlight_row, axis=1),
                height=600,
                width="stretch" # Fix deprecation
            )

if not st.session_state.authenticated:
    login()
else:
    if st.session_state.page == 'investigation':
        investigation_page(st.session_state.selected_incident)
    else:
        main_dashboard()
