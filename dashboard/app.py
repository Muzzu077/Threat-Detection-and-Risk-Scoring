import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os
import time

# Add parent dir to path to import from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import db
from utils.auth import check_password
from utils.constants import RISK_HIGH_THRESHOLD

st.set_page_config(page_title="SOC Command Center", layout="wide", page_icon="🚨")

# Custom SOC CSS
st.markdown("""
<style>
    .reportview-container { background: #000000; }
    .main { background: #000000; color: #00ff41; font-family: 'Courier New', monospace; }
    h1, h2, h3 { color: #00ff41 !important; text-transform: uppercase; }
    .stButton>button { color: black; background-color: #00ff41; border: 1px solid #00ff41; font-weight: bold; }
    
    /* Metrics */
    .metric-container { background-color: #111; padding: 15px; border: 1px solid #333; }
    
    /* Status Banner */
    .status-banner {
        padding: 15px;
        text-align: center;
        font-size: 24px;
        font-weight: bold;
        margin-bottom: 20px;
        border: 2px solid;
    }
    .status-safe { background-color: #0b3d0b; color: #00ff41; border-color: #00ff41; }
    .status-critical { background-color: #3d0b0b; color: #ff4b4b; border-color: #ff4b4b; animation: blink 2s infinite; }
    
    @keyframes blink { 0% {opacity: 1;} 50% {opacity: 0.7;} 100% {opacity: 1;} }
    
    /* Incident Card */
    .incident-card {
        background-color: #1a1a1a;
        border-left: 5px solid #ff4b4b;
        padding: 15px;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Session State
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

def login():
    c1, c2, c3 = st.columns([1,2,1])
    with c2:
        st.title("🛡️ SOC ACCESS")
        username = st.text_input("Operator ID")
        password = st.text_input("Access Key", type="password")
        if st.button("AUTHENTICATE"):
            if check_password(username, password):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("ACCESS DENIED")

def main_dashboard():
    # Auto-Refresh
    if st.checkbox("LIVE FEED ACTIVE", value=True):
        time.sleep(3)
        st.rerun()

    # Fetch Data
    incidents = db.fetch_incidents()
    active_incidents = [i for i in incidents if i.status in ["OPEN", "INVESTIGATING"]]
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
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TOTAL EVENTS", len(events))
    c2.metric("OPEN INCIDENTS", len(active_incidents), delta_color="inverse")
    recent_risk = events[0].risk_score if events else 0
    c3.metric("LATEST RISK SCORE", f"{recent_risk:.1f}", delta=f"{recent_risk - 50:.1f}" if events else 0, delta_color="inverse")
    c4.metric("SYSTEM UPTIME", "99.9%")
    
    st.markdown("---")

    # --- 3. ANALYTICS & VISUALIZATIONS ---
    st.subheader("📊 THREAT ANALYTICS")
    c1, c2 = st.columns(2)
    
    # Data Prep for charts
    df_events = pd.DataFrame([{
        'Risk Score': e.risk_score,
        'hour': e.timestamp.hour
    } for e in events])
    
    if not df_events.empty:
        with c1:
            fig_hist = px.histogram(df_events, x="Risk Score", nbins=20, title="Event Frequency by Risk Score", color_discrete_sequence=['#ff4b4b'])
            fig_hist.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="#00ff41")
            st.plotly_chart(fig_hist, width="stretch")
            
        with c2:
            hourly_risk = df_events.groupby('hour')['Risk Score'].mean().reset_index()
            fig_line = px.line(hourly_risk, x='hour', y='Risk Score', title="Average Risk vs Hour", markers=True, color_discrete_sequence=['#00ff41'])
            fig_line.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="#00ff41")
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
                if inc.status == "OPEN":
                    if c_a.button("INVESTIGATE", key=f"inv_{inc.id}"):
                        db.update_incident_status(inc.id, "INVESTIGATING", owner="Admin")
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
                    return ['background-color: #3d0b0b; color: #ff4b4b']*len(row)
                elif int(row['RISK']) > 50:
                    return ['background-color: #3d2f0b; color: orange']*len(row)
                else:
                    return ['color: #00ff41']*len(row)

            st.dataframe(
                df_feed.style.apply(highlight_row, axis=1),
                height=600,
                width="stretch" # Fix deprecation
            )

if not st.session_state.authenticated:
    login()
else:
    main_dashboard()
