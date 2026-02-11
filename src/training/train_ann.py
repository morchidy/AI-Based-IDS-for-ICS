"""
Artificial Neural Network (ANN) Training for ICS IDS
Architecture: 1 fully connected layer, 79 neurons, Sigmoid activation
"""

import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from tensorflow import keras
from tensorflow.keras import layers

# LOAD DATA
print("Loading preprocessed data...")
X_train = pd.read_csv("data/processed/X_train.csv")
X_val = pd.read_csv("data/processed/X_val.csv")
X_test = pd.read_csv("data/processed/X_test.csv")
y_train = pd.read_csv("data/processed/y_train.csv")
y_val = pd.read_csv("data/processed/y_val.csv")
y_test = pd.read_csv("data/processed/y_test.csv")

print(f"Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")
print(f"Features: {X_train.shape[1]}")

# BUILD ANN MODEL
print("\nBuilding ANN model...")
print("Architecture: 1 fully connected layer, 79 neurons, Sigmoid activation")

model = keras.Sequential([
    layers.Input(shape=(23,)),           # Input layer (23 features)
    layers.Dense(79, activation='sigmoid'),  # Hidden layer: 79 neurons, sigmoid
    layers.Dense(1, activation='sigmoid')    # Output layer: 1 neuron, sigmoid
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

print(model.summary())

# TRAIN MODEL
print("\nTraining ANN...")
history = model.fit(
    X_train, y_train,
    validation_data=(X_val, y_val),
    epochs=20,
    batch_size=128,
    verbose=1
)

# EVALUATE MODEL
print("\nEvaluating on test set...")
y_pred_prob = model.predict(X_test, verbose=0)
y_pred = (y_pred_prob > 0.5).astype(int).flatten()

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print("\nTEST SET RESULTS")
print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-Score:  {f1:.4f}")
print(f"\nConfusion Matrix:")
print(f"  TN: {tn:6,}  FP: {fp:6,}")
print(f"  FN: {fn:6,}  TP: {tp:6,}")

# SAVE MODEL
print("\nSaving model...")
model.save("models/supervised/ann_model.keras")
print("Model saved to: models/deep_learning/ann_model.keras")
print("Training complete!")