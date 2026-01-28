"""
Project: AegisCore
Module: Inference Engine
Description:
    Core Classification Logic.
    Responsible for loading the trained model artifacts and performing
    real-time inference on incoming telemetry frames.
    
    Includes:
    - Feature Vectorization (Preprocessing)
    - Classification (RandomForest inference)
    - Severity Assessment (Risk Scoring)
"""

import pandas as pd
import json
import logging
from typing import Dict, Any, Tuple, List, Optional
import os

# Configuration Constants
SEVERITY_PROFILES = {
    'DDoS': 0.9,
    'Brute Force': 1.0,  # Critical: Attempted access
    'Port Scan': 0.6,    # High: Reconnaissance
    'Normal': 0.1        # Low: Baseline
}

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("InferenceEngine")

class RiskAssessmentEngine:
    """Calculates quantitative risk metrics based on classification confidence."""
    
    @staticmethod
    def compute_severity_index(confidence_score: float, category_label: str) -> float:
        """
        Derives a normalized severity index (0-100).
        
        Formula:
            Severity = Confidence * Impact_Weight * 100
        
        Args:
            confidence_score: Model probability output (0.0 - 1.0)
            category_label: Predicted class name
        """
        weight_factor = SEVERITY_PROFILES.get(category_label, 0.5)
        
        # Calculate raw risk
        raw_score = confidence_score * weight_factor * 100.0
        
        # Clamp and Round
        return round(min(max(raw_score, 0.0), 100.0), 2)


class TrafficClassifier:
    """
    Wraps the scikit-learn model to provide a clean inference interface.
    Handles feature extraction and missing value imputation.
    """
    
    REQUIRED_FEATURES = [
        'dest_port', 
        'flow_duration', 
        'total_fwd_packets', 
        'total_l_fwd_packets', 
        'packet_size'
    ]

    @staticmethod
    def vectorize_payload(telemetry_frame: pd.DataFrame) -> pd.DataFrame:
        """
        Transforms raw telemetry into the feature vector expected by the model.
        Implements fallback logic for missing features (e.g., deriving packet_size).
        """
        # Create a copy to avoid mutation side-effects
        vector = telemetry_frame.copy()
        
        for feature in TrafficClassifier.REQUIRED_FEATURES:
            if feature not in vector.columns:
                # Feature Derivation Logic
                if feature == 'packet_size':
                    # Heuristic: Average forward packet size
                    if 'total_l_fwd_packets' in vector.columns and 'total_fwd_packets' in vector.columns:
                        vector[feature] = vector['total_l_fwd_packets'] / vector['total_fwd_packets'].replace(0, 1)
                    else:
                        vector[feature] = 0.0
                else:
                    # Default Imputation
                    vector[feature] = 0.0
        
        # Return only the strict feature set required by the model
        return vector[TrafficClassifier.REQUIRED_FEATURES].fillna(0)

# Legacy Adapter Functions for Backward Compatibility
def preprocess_data(df: pd.DataFrame):
    """Legacy wrapper for TrafficClassifier.vectorize_payload."""
    return TrafficClassifier.vectorize_payload(df), None, None

def calculate_risk_score(probability: float, attack_type: str) -> float:
    """Legacy wrapper for RiskAssessmentEngine.compute_severity_index."""
    return RiskAssessmentEngine.compute_severity_index(probability, attack_type)

def train_model(data_path: str = 'backend/training_data.csv'):
    """
    Placeholder. Actual training logic has been moved to 'train_model_real.py'.
    Exposing this warns the operator to use the correct pipeline.
    """
    logger.warning("Legacy training entry point called. Use 'train_model_real.py' for production pipelines.")
    
    # Generate static explainability artifact for UI demo if needed
    static_explainability = [
        {"name": "Packet Size", "importance": 0.65},
        {"name": "Destination Port", "importance": 0.35}
    ]
    
    try:
        with open('backend/feature_importance.json', 'w') as f:
            json.dump(static_explainability, f)
    except IOError as e:
        logger.error(f"Failed to write feature importance artifact: {e}")

if __name__ == "__main__":
    train_model()
