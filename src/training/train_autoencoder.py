"""
Autoencoder Training for ICS-Flow IDS

Trains an autoencoder on NORMAL traffic only.
High reconstruction error on test data → anomaly (attack).
"""

import pandas as pd
import numpy as np
import json
import joblib
from pathlib import Path
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from tensorflow import keras

# Paths
MODEL_DIR = Path("models/unsupervised")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

with open("models/artifacts/selected_features.json", 'r') as f:
    SELECTED_FEATURES = json.load(f)

# 1. Load raw data
print("Loading raw data...")
df = pd.read_csv("data/raw/Dataset.csv")

X = df[SELECTED_FEATURES].copy()
y = df['NST_B_Label'].copy()

# 2. Encode protocol
from sklearn.preprocessing import LabelEncoder
encoder = LabelEncoder()
X['protocol'] = encoder.fit_transform(X['protocol'].fillna('UNKNOWN'))
X = X.fillna(0)

# 3. Split (same as other models: 50/20/30)
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.5, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.6, random_state=42, stratify=y_temp
)

# 4. Extract normal samples
X_train_normal = X_train[y_train == 0]
X_val_normal = X_val[y_val == 0]

print(f"Training on {len(X_train_normal):,} normal samples")
print(f"Validation on {len(X_val_normal):,} normal samples")
print(f"Test set: {len(X_test):,} samples ({np.sum(y_test == 1):,} attacks)")

# 5. Standardize (fit on normal training data only)
scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train_normal)
X_val_scaled = scaler.transform(X_val_normal)
X_test_scaled = scaler.transform(X_test)

# 6. Build autoencoder
input_dim = X_train_scaled.shape[1]  # 23 features

autoencoder = keras.Sequential([
    # Encoder
    keras.layers.Dense(16, activation='relu', input_shape=(input_dim,)),
    keras.layers.Dense(8, activation='relu'),
    keras.layers.Dense(4, activation='relu'),
    # Decoder
    keras.layers.Dense(8, activation='relu'),
    keras.layers.Dense(16, activation='relu'),
    keras.layers.Dense(input_dim, activation='linear')
])

autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.summary()

# 7. Train (on normal traffic only)
print("\nTraining autoencoder...")
history = autoencoder.fit(
    X_train_scaled, X_train_scaled,  # Input = Output (reconstruction)
    epochs=50,
    batch_size=64,
    validation_data=(X_val_scaled, X_val_scaled),
    callbacks=[
        keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
    ],
    verbose=1
)

# 8. Compute reconstruction errors
print("\nComputing reconstruction errors...")
reconstructed = autoencoder.predict(X_test_scaled, verbose=0)
mse = np.mean((X_test_scaled - reconstructed) ** 2, axis=1)

# 9. Find optimal threshold using validation set
val_reconstructed = autoencoder.predict(X_val_scaled, verbose=0)
val_mse = np.mean((X_val_scaled - val_reconstructed) ** 2, axis=1)
threshold = np.percentile(val_mse, 95)  # 95th percentile of normal errors

print(f"Anomaly threshold: {threshold:.6f}")

# 10. Predict
predictions = (mse > threshold).astype(int)

# 11. Evaluate
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

# 12. Save
autoencoder.save(MODEL_DIR / "autoencoder_model.keras")
joblib.dump(scaler, MODEL_DIR / "autoencoder_scaler.pkl")
joblib.dump(float(threshold), MODEL_DIR / "autoencoder_threshold.pkl")

print(f"\nModel saved to: {MODEL_DIR / 'autoencoder_model.keras'}")
print(f"Scaler saved to: {MODEL_DIR / 'autoencoder_scaler.pkl'}")
print(f"Threshold saved to: {MODEL_DIR / 'autoencoder_threshold.pkl'}")
print("Done!")