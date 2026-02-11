"""
Isolation Forest Training for ICS-Flow IDS

Trains an Isolation Forest model on NORMAL traffic only to detect anomalies.
Complements supervised Random Forest models by catching unknown attacks.
Uses RobustScaler standardization (instead of MinMax normalization).
"""

import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, RobustScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Paths
MODEL_DIR = Path("models/unsupervised")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

with open("models/artifacts/selected_features.json", 'r') as f:
    SELECTED_FEATURES = json.load(f)

# 1. Load raw data
print("Loading raw data...")
df = pd.read_csv("data/raw/Dataset.csv")

# 2. Extract features and labels
X = df[SELECTED_FEATURES].copy()
y = df['NST_B_Label'].copy()

# 3. Encode protocol
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

# 6. Extract ONLY NORMAL samples for training
normal_mask = y_train == 0
X_train_normal = X_train[normal_mask]
print(f"Training on {len(X_train_normal):,} normal samples")

# 7. Standardize (fit on normal training data only)
scaler = RobustScaler()
X_train_normal_scaled = pd.DataFrame(scaler.fit_transform(X_train_normal), columns=SELECTED_FEATURES)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=SELECTED_FEATURES)

# 8. Train Isolation Forest
print("\nTraining Isolation Forest...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_normal_scaled)

# 9. Predict
print("\nEvaluating on test set...")
predictions = model.predict(X_test_scaled)
predictions = (predictions == -1).astype(int)  # -1=anomaly → 1=attack

# 10. Evaluate
accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)
cm = confusion_matrix(y_test, predictions)
tn, fp, fn, tp = cm.ravel()

print("\nTEST SET RESULTS")
print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f} (detected {tp}/{np.sum(y_test == 1)} attacks)")
print(f"F1-Score:  {f1:.4f}")
print(f"\nConfusion Matrix:")
print(f"  TN: {tn:5,}  FP: {fp:5,}")
print(f"  FN: {fn:5,}  TP: {tp:5,}")

print("\n\nDone!")