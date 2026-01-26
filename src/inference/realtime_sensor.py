"""
Real-Time Inference Pipeline for ICS Intrusion Detection System
Live Sensor with SQLite Persistence

Continuously monitors ICSFlowGenerator output and generates real-time alerts.
Stores all alerts and statistics in SQLite database for dashboard visualization.
"""

import sqlite3
import pandas as pd
import numpy as np
import joblib
import json
import time
from pathlib import Path
from datetime import datetime

# 1. DATABASE FUNCTIONS
# Create SQLite database and tables
def init_database(db_path="data/ids_events.db"):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            confidence REAL)""")

    conn.commit()
    print(f"Database ready: {db_path}")
    return conn

# Insert alert into database
def save_alert(conn, src_ip, dst_ip, protocol, confidence):
   cursor = conn.cursor()
   cursor.execute("""
        INSERT INTO alerts (timestamp, src_ip, dst_ip, protocol, confidence)
        VALUES (?,?,?,?,?)
    """, (datetime.now().isoformat(), src_ip, dst_ip, protocol, confidence)
   )
   conn.commit()

conn = init_database(db_path="data/ids_events.db")
save_alert(conn, '0','0', '0', 0.1)
  

