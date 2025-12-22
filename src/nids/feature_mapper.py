from typing import Dict, Any, List, Optional, Callable
import numpy as np
import pandas as pd
import joblib


class FeatureMapper:
    # Default feature order matching the trained model
    REQUIRED_FEATURES = [
        # Flow-level
        'Flow Duration',
        'Flow Packets/s',
        'Flow Bytes/s',
        'Flow IAT Mean',
        'Flow IAT Max',
        'Flow IAT Std',
        
        # Forward features
        'Fwd Header Length',
        'Fwd IAT Total',
        'Fwd IAT Mean',
        'Fwd IAT Max',
        'Fwd IAT Std',
        'Fwd Packet Length Min',
        'Fwd Packet Length Max',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Subflow Fwd Bytes',
        'Total Fwd Packets',
        'Total Length of Fwd Packets',
        
        # Backward features
        'Bwd Header Length',
        'Bwd Packet Length Min',
        'Bwd Packet Length Max',
        'Bwd Packet Length Std',
        'Bwd Packets/s',
        'Init_Win_bytes_backward',
        
        # Packet-level
        'Packet Length Mean',
        'Packet Length Std',
        'Packet Length Variance',
        'Average Packet Size',
        'PSH Flag Count',
        'Init_Win_bytes_forward',
        'Max Packet Length',
    ]
    
    def __init__(
        self,
        feature_callback,
        scaler: Optional[Any] = None,
        ):

        self.feature_callback = feature_callback
        self.scaler = scaler
        self._features_mapped = 0
        
    
    def map_features(
        self, 
        features: Dict[str, Any], 
        flow: Any = None
    ):

        self._features_mapped += 1
        feature_array = self._to_array(features)

        scaled_array = self.scale(feature_array)
    
        # Forward to Anomaly Detector
        if self.feature_callback:
            self.feature_callback(scaled_array, flow)

    
    def _to_array(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert features dictionary to array, filling missing features with 0."""
        values = []
        for feature_name in self.REQUIRED_FEATURES:
            if feature_name in features:
                values.append(features[feature_name])
            else:
                # Log missing feature and use default value
                print(f"Warning: Missing feature '{feature_name}', using default value 0")
                values.append(0.0)
        return np.array([values], dtype=np.float64)
    
    def scale(self, features: np.ndarray) -> np.ndarray:
        if self.scaler is None:
            return features
        
        return self.scaler.transform(features)
    
    def set_scaler(self, scaler: Any) -> None:
        self.scaler = scaler
    

    def load_scaler(self, scaler_path: str) -> None:
        self.scaler = joblib.load(scaler_path)