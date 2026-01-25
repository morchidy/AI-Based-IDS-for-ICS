"""
Isolation Forest Training for ICS-Flow IDS

Trains an Isolation Forest model on NORMAL traffic only to detect anomalies.
Complements supervised Random Forest models by catching unknown attacks.
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Paths
PROCESSED_DIR = Path("data/processed")
RAW_DATA = Path("data/raw/Dataset.csv")
MODEL_DIR = Path("models/unsupervised")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("Loading preprocessed features and labels...")
X_train = pd.read_csv(PROCESSED_DIR / "X_train.csv")
X_test = pd.read_csv(PROCESSED_DIR / "X_test.csv")
y_train = pd.read_csv(PROCESSED_DIR / "y_train.csv")
y_test = pd.read_csv(PROCESSED_DIR / "y_test.csv")

# Convert dataframe to 1D array/Series
y_train = y_train.iloc[:, 0]
y_test  = y_test.iloc[:, 0]


# Extract ONLY NORMAL samples for training
normal_mask = y_train == 0
X_train_normal = X_train[normal_mask]

# Create and train Isolation Forest
print("\nTraining Isolation Forest...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_normal)

# Compute anomaly scores (lower = more anomalous)
test_scores = model.decision_function(X_test)

# Determine threshold (10th percentile)
threshold = np.percentile(test_scores, 10)
print(f"\nAnomaly threshold: {threshold:.4f}")

# Make predictions: score < threshold => anomaly (1)
predictions = (test_scores < threshold).astype(int)

# Evaluate
accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)
cm = confusion_matrix(y_test, predictions)
tn, fp, fn, tp = cm.ravel()

print("TEST SET RESULTS")
print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f} (detected {tp}/{np.sum(y_test == 1)} attacks)")
print(f"F1-Score:  {f1:.4f}")
print(f"\nConfusion Matrix:")
print(f"  TN: {tn:5,}  FP: {fp:5,}")
print(f"  FN: {fn:5,}  TP: {tp:5,}")

# Save model
model_file = MODEL_DIR / "if_model.pkl"
joblib.dump(model, model_file)
print(f"\nModel saved to: {model_file}")
print("Done !")