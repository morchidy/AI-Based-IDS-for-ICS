"""
Random Forest Training for ICS-Flow IDS using NST Labels

Trains a Random Forest binary classifier following paper specifications:
- Number of trees: 10
- Predictors sampled per split: 17
- Maximum splits: 850
- Binary classification using NST (Network Security Tools) labels
"""

import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Paths
PROCESSED_DIR = Path("data/processed")
RAW_DATA = Path("data/raw/Dataset.csv")
MODEL_DIR = Path("models/supervised")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("Loading preprocessed features and labels...")
X_train = pd.read_csv(PROCESSED_DIR / "X_train.csv")
X_test = pd.read_csv(PROCESSED_DIR / "X_test.csv")
y_train = pd.read_csv(PROCESSED_DIR / "y_train.csv")
y_test = pd.read_csv(PROCESSED_DIR / "y_test.csv")

# Create and train model
print("\nTraining Random Forest...")
model = RandomForestClassifier(
    n_estimators=10,
    max_features=17,
    max_leaf_nodes=850,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)
print("Training complete")

# Evaluate on test set
print("\nEvaluating on test set...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print(f"\nTest Results:")
print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
print(f"  F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
print(f"\nConfusion Matrix:")
print(f"  TN: {cm[0,0]:6d}  FP: {cm[0,1]:6d}")
print(f"  FN: {cm[1,0]:6d}  TP: {cm[1,1]:6d}")

# Save model
print("\nSaving model...")
joblib.dump(model, MODEL_DIR / "rf_model.pkl")
print(f"Saved to models/supervised/rf_model.pkl")
print("\nDone!")
