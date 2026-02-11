"""
Model Adapters for ICS IDS
Unified interface for different ML model types
"""
import numpy as np
import joblib
from pathlib import Path

def load_model_adapter(model_path):
    """
    Load model and return prediction function
    
    Args:
        model_path: Path to model file (.pkl or .h5)
    
    Returns:
        tuple: (model_name, predict_function)
    """
    model_path = Path(model_path)

    # Load .pkl models (sklearn)
    if model_path.suffix == '.pkl':
        model = joblib.load(model_path)
        model_type = type(model).__name__

        # Isolation Forest
        if 'IsolationForest' in model_type:
            def predict(vector):
                raw_pred = model.predict(vector)[0]
                prediction = 1 if raw_pred == -1 else 0
                score = model.decision_function(vector)[0]
                confidence = float(1.0 / (1.0 + np.exp(score)))
                return int(prediction), confidence
            
            return model_type, predict
        
        # Random Forest / sklearn classifiers
        else:
            def predict(vector):
                prediction = model.predict(vector)[0]
                probabilities = model.predict_proba(vector)[0]
                confidence = float(probabilities[prediction])
                return int(prediction), confidence
            
            return model_type, predict
    
    # Load .h5 models (Keras/TensorFlow)
    elif model_path.suffix in ['.h5', '.keras']:
        from tensorflow import keras
        model = keras.models.load_model(model_path)

        # Autoencoder (by name convention)
        if 'autoencoder' in str(model_path).lower():
            ae_scaler = joblib.load("models/unsupervised/autoencoder_scaler.pkl")
            ae_threshold = joblib.load("models/unsupervised/autoencoder_threshold.pkl")
            def predict(vector):
                # Vector is already MinMax normalized from sensor
                # Re-scale with autoencoder's RobustScaler
                scaled = ae_scaler.transform(vector)
                reconstructed = model.predict(scaled, verbose=0)
                mse = float(np.mean((scaled - reconstructed) ** 2))
                prediction = 1 if mse > ae_threshold else 0
                confidence = min(mse / ae_threshold, 1.0) if prediction == 1 else 1 - (mse / ae_threshold)
                return int(prediction), float(confidence)
            
            return "Autoencoder", predict
        
        # Neural Network classifier
        else:
            def predict(vector):
                output = model.predict(vector, verbose=0)[0]
                prediction = int(output[0] > 0.5)
                confidence = float(output[0]) if prediction == 1 else float(1 - output[0])
                return int(prediction), confidence
            
            return "ANN", predict
        
    else:
        raise ValueError(f"Unsupported file format: {model_path.suffix}")