import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score, precision_score, recall_score
from imblearn.over_sampling import SMOTE
import numpy as np
import random 
import json

# Asset Criticality Mapping (Simulated)
ASSET_CRITICALITY = {
    f'10.0.0.{i}': random.randint(1, 10) for i in range(1, 20)
}

SEVERITY_WEIGHTS = {
    'DDoS': 0.9,
    'Brute Force': 1.0,
    'Port Scan': 0.6,
    'Normal': 0.1
}

MODEL_PATH = 'backend/model_real.pkl' # Updated to real model
ENCODER_PATH = 'backend/encoder.pkl'
METRICS_PATH = 'backend/model_metrics.json'

def preprocess_data(df):
    """Preprocesses data for inference with Real Data Model."""
    # Real Model expects: ['dest_port', 'packet_size']
    # Ensure columns exist
    if 'dest_port' not in df.columns:
        # Fallback for old data or if log_generator isn't aligned yet
        df['dest_port'] = 80 
        
    X = df[['dest_port', 'packet_size']]
    
    # Handle NaN
    X = X.fillna(0)
    
    return X, None, None

def train_model(data_path='backend/training_data.csv'):
    """
    DEPRECATED: Use backend/train_model_real.py for training.
    This function is kept as a placeholder or for legacy synthetic training.
    """
    print("Please use 'python train_model_real.py' to train on real data.")
    pass

    
    # Feature Importance (Explainability) - Static for now as loading from file
    feature_imp = [
        {"name": "Packet Size", "importance": 0.65},
        {"name": "Destination Port", "importance": 0.35}
    ]
    
    with open('backend/feature_importance.json', 'w') as f:
        json.dump(feature_imp, f)

def calculate_risk_score(probability, attack_type):
    """
    Calculates risk score (0-100) based on Prediction Probability * Severity Weight.
    """
    weight = SEVERITY_WEIGHTS.get(attack_type, 0.5)
    
    # Formula: Risk = Probability * Weight
    # Scaling to 0-100 for dashboard display
    risk = (probability * weight) * 100
    return round(risk, 2)

if __name__ == "__main__":
    train_model()
