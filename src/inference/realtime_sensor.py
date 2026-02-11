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
import argparse
from datetime import datetime

from model_adapters import load_model_adapter

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


# 3. INFERENCE FUNCTIONS
# Load trained model
def load_model(model_path="models/supervised/rf_model.pkl"):
    model_name, predict_fn = load_model_adapter(model_path)
    print(f"Model loaded: {model_name}")
    return predict_fn

# Predict if flow is attack
def predict_attack(flow, predict_fn, features, scaler, encoder):
    vector = preprocess_flow(flow, features, scaler, encoder)
    prediction, confidence = predict_fn(vector)
    return prediction, confidence


# 4. MONITORING FUNCTIONS
# Check if CSV has new flows
def check_new_flows(csv_path, last_row_count):
    csv_path = Path(csv_path)
    if not csv_path.exists():
        return None, last_row_count
    
    try:
        df = pd.read_csv(csv_path)
        current_rows = len(df)

        if current_rows <= last_row_count:
            return None, last_row_count
        
        new_flows = df.iloc[last_row_count:]
        return new_flows, current_rows
    except:
        return None, last_row_count

# Main monitoring loop    
def monitor_realtime(csv_path="output/sniffed.csv",
                    db_path="data/ids_events.db",
                    model_path="models/supervised/rf_model.pkl",
                    confidence_threshold=0.95,
                    poll_interval=2.0):
    # Initialize
    conn = init_database(db_path)
    features, scaler, encoder = load_artifacts()
    predict_fn = load_model(model_path)

    # State
    last_row_count = 0
    total_flows = 0
    attacks = 0

    print(f"\nMonitoring: {csv_path}")
    print(f"Database: {db_path}")
    print(f"Threshold: {confidence_threshold:.0%}")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            # Check for new flows
            new_flows, last_row_count = check_new_flows(csv_path, last_row_count)

            if new_flows is not None and len(new_flows) > 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Processing {len(new_flows)} flows...")

                for _, flow in new_flows.iterrows():
                    pred, conf = predict_attack(flow, predict_fn, features, scaler, encoder)
                    total_flows += 1

                    # High-confidence attack detected
                    if pred == 1 and conf >= confidence_threshold:
                        attacks += 1

                        src_ip = flow.get('sIPs', 'N/A')
                        dst_ip = flow.get('rIPs', 'N/A')
                        protocol = flow.get('protocol', 'N/A')

                        # Save to database
                        save_alert(conn, src_ip, dst_ip, protocol, conf)

                        # Log to console
                        print(f"    ATTACK: {src_ip} → {dst_ip} (conf: {conf:.1%})")
            
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("STOPPED")
        print(f"Total flows: {total_flows}")
        print(f"Attacks detected: {attacks}")
        print(f"Alerts saved to: {db_path}")
        conn.close()


# 5. MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ICS IDS Real-Time Sensor')
    parser.add_argument('-i', '--input', default='output/sniffed.csv', 
                        help='Path to sniffed CSV file (default: output/sniffed.csv)')
    parser.add_argument('-m', '--model', default='models/supervised/rf_model.pkl',
                        help='Path to model file (default: models/supervised/rf_model.pkl)')
    parser.add_argument('-t', '--threshold', type=float, default=0.95,
                        help='Confidence threshold (default: 0.95)')
    
    args = parser.parse_args()
    monitor_realtime(
        csv_path=args.input,
        confidence_threshold=args.threshold,
        poll_interval=2.0
    )