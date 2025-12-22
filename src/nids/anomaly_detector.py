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

class AnomalyDetector:
    BINARY_ATTACK_VALUES = {1, "1", "Attack"}
    BINARY_BENIGN_VALUES = {0, "0", "Benign"}
    MULTICLASS_LABEL_MAP = {
        0: "DoS",
        1: "PortScan",
        2: "BruteForce",
        3: "WebAttack",
        4: "Bot",
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


    def _is_attack(self, binary_pred) -> bool:
        return binary_pred in self.BINARY_ATTACK_VALUES
    
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
        
        try:
            X = features
        
            # Stage 1: Binary classification
            if self.binary_model is not None:
                binary_pred = self.binary_model.predict(X)[0]
                
                # Get confidence if model supports it
                if hasattr(self.binary_model, 'predict_proba'):
                    proba = self.binary_model.predict_proba(X)[0]
                    confidence = float(max(proba))
                
                if self._is_attack(binary_pred):
                    is_attack = True
                    
                    # Stage 2: Multi-class classification
                    if self.multi_class_model is not None:
                        prediction = self._classify_attack_type(X, flow_metadata)
                        
                        # Get confidence from multi-class model
                        if hasattr(self.multi_class_model, 'predict_proba'):
                            proba = self.multi_class_model.predict_proba(X)[0]
                            confidence = float(max(proba))
                    else:
                        prediction = "Attack"
                else:
                    prediction = "Benign"
                    is_attack = False
            
        except Exception as e:
            print(f"[DEBUG] Detection error: {type(e).__name__}: {e}")
            prediction = "Error"
            confidence = 0.0
        
        prediction_time = time.perf_counter() - start_time
        
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
            flow_metadata=self._extract_metadata(flow_metadata)
        )
        
        # Forward to callback
        if self.detection_callback:
            self.detection_callback(result)
        
        return result
    
    def _classify_attack_type(
        self, 
        X: np.ndarray, 
        flow_metadata: Optional[Any]
    ) -> str:
        raw_prediction = self.multi_class_model.predict(X)[0]
        # prediction = self._normalize_multiclass_prediction(prediction)
        # # Apply domain knowledge heuristics
        # if flow_metadata is not None and hasattr(flow_metadata, 'dest_port'):
        #     dest_port = flow_metadata.dest_port
            
        #     # SSH/FTP ports with DoS/DDoS might actually be brute force
        #     if prediction in ("DoS", "DDoS"):
        #         if dest_port in (21, 22):  # FTP, SSH
        #             prediction = "Brute Force"
        
        prediction = self._normalize_multiclass_prediction(raw_prediction)
        
        return prediction
    
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