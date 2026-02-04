"""
ICS IDS Dashboard
Displays traffic overview and recent alerts from SQLite
"""

import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

# CONFIGURATION
st.set_page_config(
    page_title="IDS Monitor",
    page_icon="🛡️",
    layout="wide"
)

DB_PATH = "data/ids_events.db"

# # DASHBOARD
# Title
st.title("ICS Intrusion Detection System")

try:
    # Connect and fetch alerts
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 1000", conn)
    conn.close()
    
    # === TRAFFIC OVERVIEW ===
    st.header("Traffic Overview")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_alerts = len(df)
        st.metric("Total Alerts", f"{total_alerts:,}")
    
    with col2:
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            one_hour_ago = datetime.now() - timedelta(hours=1)
            recent_alerts = len(df[df['timestamp'] > one_hour_ago])
            st.metric("Last Hour", f"{recent_alerts:,}")
        else:
            st.metric("Last Hour", "0")
    
    with col3:
        if not df.empty:
            avg_conf = df['confidence'].mean() * 100
            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
        else:
            st.metric("Avg Confidence", "N/A")
        
    # === RECENT ALERTS TABLE ===
    st.header("Recent Alerts")
    
    if not df.empty:
        # Format for display
        recent = df.head(100).copy()
        recent['timestamp'] = pd.to_datetime(recent['timestamp'])
        recent['Time'] = recent['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        recent['Confidence'] = (recent['confidence'] * 100).round(1).astype(str) + '%'
        
        # Display table
        display_df = recent[['Time', 'src_ip', 'dst_ip', 'protocol', 'Confidence']].rename(columns={
            'src_ip': 'Source IP',
            'dst_ip': 'Destination IP',
            'protocol': 'Protocol'
        })
        
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No alerts yet. Waiting for sensor data...")

except Exception as e:
    st.error(f"Error: {e}")
    st.exception(e)

# Footer
st.caption("Auto-refresh every 5 seconds")

# Auto-refresh
import time
time.sleep(5)
st.rerun()