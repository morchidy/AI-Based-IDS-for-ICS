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

# 2. PREPROCESSING FUNCTIONS
# Load scaler, encoder, and feature list
def load_artifacts(artifacts_dir="models/artifacts"):
  artifacts_dir = Path(artifacts_dir)
  with open(artifacts_dir / "selected_features.json", 'r') as f:
        features = json.load(f)
  scaler = joblib.load(artifacts_dir / "minmax_scaler.pkl")    
  encoder = joblib.load(artifacts_dir / "protocol_encoder.pkl")

  print(f"Loaded {len(features)} features")
  return features, scaler, encoder

# Transform raw flow into model-ready vector
def preprocess_flow(flow, features, scaler, encoder):
    values = []

    for feature_name in features:
        if feature_name == 'protocol':
            protocol = flow.get('protocol', 'UNKNOWN')

            # Map ICSFlowGenerator format to training format
            protocol_map = {
                'IP:TCP': 'IPV4-TCP',
                'IP:UDP': 'IPV4-UDP',
                'IP:ICMP': 'IPV4-ICMP' 
            }
            protocol = protocol_map.get(protocol,protocol)

            try:
                encoded = encoder.transform([protocol])[0]
            except:
                encoded = 2 # Default
            values.append(encoded)

        else:
            val = flow.get(feature_name, 0)
            if pd.isna(val):
                val = 0
            values.append(float(val))
    
    # Normalize
    vector = np.array(values).reshape(1, -1)
    normalized = scaler.transform(vector)
    return normalized


flow = {'protocol': 'IP:TCP', 'rBytesAvg': 90.5}
features, scaler, encoder = load_artifacts(artifacts_dir="models/artifacts")
normalized = preprocess_flow(flow, features, scaler, encoder)
print(normalized)
print(encoder.classes_)
