from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
import time
import numpy as np
import joblib

@dataclass
class DetectionResult:
    prediction: str
    confidence: float
    is_attack: bool
    prediction_time: float = 0.0
    flow_metadata: Optional[Dict[str, Any]] = None
    probabilities: Optional[Dict[str, float]] = None

class AnomalyDetector:

    MULTICLASS_LABEL_MAP = {
        0: "DoS",
        1: "PortScan",
        2: "BruteForce",
        3: "WebAttack",
    }
    
    def __init__(
        self,
        binary_model: Optional[Any] = None,
        multi_class_model: Optional[Any] = None,
        detection_callback: Optional[Callable[[DetectionResult], None]] = None
    ):
        self.binary_model = binary_model
        self.multi_class_model = multi_class_model
        self.detection_callback = detection_callback
        
        # Statistics
        self._flows_analyzed = 0
        self._attacks_detected = 0
        self._attack_counts = {}


    def _is_attack(self, binary_pred) -> bool:
        return binary_pred == 1
    
    # Convert numeric multi-class predictions to string labels
    def _normalize_multiclass_prediction(self, pred) -> str:
        # Handle numeric predictions
        if isinstance(pred, (int, np.integer)):
            return self.MULTICLASS_LABEL_MAP.get(pred, "Unknown")
        # Handle string predictions
        return str(pred)

    def detect(
        self, 
        features: np.ndarray, 
        flow_metadata: Optional[Any] = None
    ) -> DetectionResult:
        start_time = time.perf_counter()
        
        self._flows_analyzed += 1
        
        # Default result
        prediction = "Unknown"
        confidence = 0.0
        is_attack = False
        probabilities = None
        
        try:
            X = features
        
            # Stage 1: Binary classification
            if self.binary_model is not None:
                binary_pred = self.binary_model.predict(X)[0]
                
                # Get confidence if model supports it
                if hasattr(self.binary_model, 'predict_proba'):
                    proba = self.binary_model.predict_proba(X)[0]
                    confidence = float(max(proba))
                
                # Apply threshold: if predicted as attack (1) and prob < 0.99, switch to benign (0)
                if binary_pred == 0 and max(proba) < 1.00:
                    binary_pred = 1 # swithc to attack
                    confidence = float(max(proba))  # Keep original confidence, or adjust if needed
                
                if self._is_attack(binary_pred):
                    is_attack = True
                    
                    # Stage 2: Multi-class classification
                    if self.multi_class_model is not None:
                        prediction, probabilities = self._classify_attack_type(X, flow_metadata)
                    if probabilities:
                        confidence = max(probabilities.values())
                    else:
                        prediction = "Attack"
                else:
                    prediction = "Benign"
                    is_attack = False
            
        except Exception as e:
            print(f"[DEBUG] Detection error: {type(e).__name__}: {e}")
            prediction = "Error"
            confidence = 0.0
        
        prediction_time = f"{(time.perf_counter() - start_time):.4f} seconds"
                
        # Update statistics
        if is_attack:
            self._attacks_detected += 1
            self._attack_counts[prediction] = self._attack_counts.get(prediction, 0) + 1
        
        # Create result
        result = DetectionResult(
            prediction=prediction,
            confidence=confidence,
            is_attack=is_attack,
            prediction_time=prediction_time,
            flow_metadata=self._extract_metadata(flow_metadata),
            probabilities=probabilities
        )
        
        # Forward to callback
        if self.detection_callback:
            self.detection_callback(result)
        
        return result
    
    def _classify_attack_type(
        self, 
        X: np.ndarray, 
        flow_metadata: Optional[Any]
    ) -> tuple[str, Optional[Dict[str, float]]]:
        raw_prediction = self.multi_class_model.predict(X)[0]
        
        probabilities = None
        # Get probabilities for all classes
        if hasattr(self.multi_class_model, 'predict_proba'):
            probs = self.multi_class_model.predict_proba(X)[0]
            class_names = ["DoS", "PortScan", "BruteForce", "WebAttack",]
            probabilities = {class_name: float(prob) for class_name, prob in zip(class_names, probs)}
        
        prediction = self._normalize_multiclass_prediction(raw_prediction)
        
        return prediction, probabilities
    
    def _extract_metadata(self, flow_metadata: Any) -> Optional[Dict[str, Any]]:
        if flow_metadata is None:
            return None
        
        if isinstance(flow_metadata, dict):
            return flow_metadata
        
        # Extract from Flow object
        try:
            return {
                "src_ip": getattr(flow_metadata, 'src_ip', None),
                "dst_ip": getattr(flow_metadata, 'dest_ip', None),
                "src_port": getattr(flow_metadata, 'src_port', None),
                "dst_port": getattr(flow_metadata, 'dest_port', None),
                "protocol": getattr(flow_metadata, 'protocol', None),
            }
        except Exception:
            return None
    
    def load_models(
        self,
        binary_model_path: Optional[str] = None,
        multi_class_model_path: Optional[str] = None,
    ) -> None:
        if binary_model_path:
            self.binary_model = joblib.load(binary_model_path)
        
        if multi_class_model_path:
            self.multi_class_model = joblib.load(multi_class_model_path)

    @property
    def attacks_detected(self) -> int:
        """Get the number of attacks detected."""
        return self._attacks_detected