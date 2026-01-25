"""
Preprocessing Pipeline for ICS-Flow Dataset
Based on mRMR feature selection from the paper (23 features with mRMR >= 0.07)
Produces clean, normalized train/validation/test splits ready for model training
"""

import pandas as pd
import joblib
from pathlib import Path
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# 23 selected features from paper's mRMR analysis
SELECTED_FEATURES = [
    'rBytesAvg', 'sBytesAvg', 'sFinRate', 'rFinRate', 'sSynRate', 'rSynRate',
    'sRstRate', 'rRstRate', 'rttl', 'sttl', 'sAckRate', 'rAckRate',
    'sAckDelayMax', 'rAckDelayMax', 'sPackets', 'rPackets', 'protocol',
    'sWinTCP', 'rWinTCP', 'rPayloadAvg', 'sPayloadAvg', 
    'rInterPacketAvg', 'sInterPacketAvg'
]

# Paths
DATA_PATH = "../../data/raw/Dataset.csv"
OUTPUT_DIR = Path("../../data/processed")
ARTIFACTS_DIR = Path("../../models/artifacts")

# 1. Load data
print("Loading data...")
df = pd.read_csv(DATA_PATH)

# 2. Extract features and labels
X= df[SELECTED_FEATURES].copy()
y= df['NST_B_Label'].copy()

# 3. Encode protocol (Label Encoding (e.g., TCP=0, UDP=1, ICMP=2))
encoder = LabelEncoder()
X['protocol'] = encoder.fit_transform(X['protocol'].fillna('UNKNOWN'))

# 4. Fill missing values
X = X.fillna(0)

# 5. Split data (50% train, 20% val, 30% test)
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.5, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.6, random_state=42, stratify=y_temp
)

# 6. Normalize (fit on train only)
scaler = MinMaxScaler()
X_train = pd.DataFrame(scaler.fit_transform(X_train), columns=SELECTED_FEATURES)
X_val = pd.DataFrame(scaler.transform(X_val), columns=SELECTED_FEATURES)
X_test = pd.DataFrame(scaler.transform(X_test), columns=SELECTED_FEATURES)

# 7. Save processed data
X_train.to_csv(OUTPUT_DIR / "X_train.csv", index=False)
X_val.to_csv(OUTPUT_DIR / "X_val.csv", index=False)
X_test.to_csv(OUTPUT_DIR / "X_test.csv", index=False)
y_train.to_csv(OUTPUT_DIR / "y_train.csv", index=False)
y_val.to_csv(OUTPUT_DIR / "y_val.csv", index=False)
y_test.to_csv(OUTPUT_DIR / "y_test.csv", index=False)

# 8. Save artifacts
joblib.dump(scaler, ARTIFACTS_DIR / "minmax_scaler.pkl")
joblib.dump(encoder, ARTIFACTS_DIR / "protocol_encoder.pkl")

print(f"Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")
print("Done! Files saved to data/processed/ and models/artifacts/")
