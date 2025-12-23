import threading
import time
from typing import Optional, Callable, Dict, Any

from nids.packet_capturer import PacketCapturer
from nids.packet_parser import PacketParser
from nids.feature_extractor import FeatureExtractor
from nids.feature_mapper import FeatureMapper
from nids.anomaly_detector import AnomalyDetector, DetectionResult
from nids.helper.other.flow import Flow
from nids.helper.other.writer import CSVWriter

class Main:
    def __init__(
        self,
        interface: str,
        binary_model_path: Optional[str] = None,
        multi_class_model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        output_path: Optional[str] = None,
        detection_callback: Optional[Callable[[DetectionResult], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None
    ):

        self.interface = interface
        self.output_path = output_path
        self.log_callback = log_callback
        
        # Statistics
        self._is_running = False
        self._start_time: Optional[float] = None
        
           # Initialize output writer
        self._output_writer =  CSVWriter(self.output_path)
        
        # Initialize Component 5: Anomaly Detector
        self.anomaly_detector = AnomalyDetector(
            detection_callback=self._on_detection
        )
        
        # Load ML models
        if any([binary_model_path, multi_class_model_path, scaler_path]):
            self.anomaly_detector.load_models(
                binary_model_path=binary_model_path,
                multi_class_model_path=multi_class_model_path,
            )
        
        # Store user's detection callback
        self._user_detection_callback = detection_callback
        self._scaler = None  # Scaler is not used in current implementation

        # Initialize Component 4: Feature Mapper
        self.feature_mapper = FeatureMapper(
            feature_callback=self._on_features_mapped,
        )

        if scaler_path:
            self.feature_mapper.load_scaler(scaler_path=scaler_path)
        
        # Initialize Component 3: Feature Extractor
        self.feature_extractor = FeatureExtractor(
            feature_callback=self._on_features_extracted
        )
        
        # Initialize Component 2: Packet Parser
        self.packet_parser = PacketParser(
            flow_callback=self._on_flow_ready
        )
        
        # Initialize Component 1: Packet Capturer
        self.packet_capturer = PacketCapturer(
            interface=interface,
            packet_callback=self._on_packet_captured
        )
        
        # Garbage collection thread
        self._gc_thread: Optional[threading.Thread] = None
        self._gc_stop = threading.Event()
    
    def start(self) -> None:
        if self._is_running:
            return
        
        self._log(f"[*] Starting NIDS on interface {self.interface}")
        
        # Start garbage collection thread
        self._gc_stop.clear()
        self._gc_thread = threading.Thread(target=self._gc_worker, daemon=True)
        self._gc_thread.start()
        
        # Start packet capture
        self.packet_capturer.start()
        
        self._is_running = True
        self._start_time = time.time()
        
        self._log("[*] NIDS started successfully")
    
    def stop(self) -> None:
        """
        Stop the NIDS .
        
        This stops packet capture and flushes any remaining flows.
        """
        if not self._is_running:
            return
        
        self._log("[*] Stopping NIDS ...")
        
        # Stop packet capture
        self.packet_capturer.stop()
        
        # Stop garbage collection
        self._gc_stop.set()
        if self._gc_thread:
            self._gc_thread.join(timeout=2.0)
        
        # Flush remaining flows
        self.packet_parser.flush_all_flows()
        
        # Clean up output writer
        if self._output_writer:
            try:
                del self._output_writer
                self._output_writer = None
            except Exception:
                pass
        
        self._is_running = False
        
        self._log(f"[*] NIDS stopped. Statistics:")
        self._log(f"    - Packets captured: {self.packet_capturer.packets_captured}")
        self._log(f"    - Flows processed: {self.packet_parser.flows_completed}")
        self._log(f"    - Attacks detected: {self.anomaly_detector.attacks_detected}")
    
    def _gc_worker(self) -> None:
        while not self._gc_stop.is_set():
            try:
                self.packet_parser.garbage_collect(time.time())
            except Exception:
                pass
            time.sleep(1.0)  # GC interval
    
    
    def _on_packet_captured(self, packet) -> None:
        self.packet_parser.parse_packet(packet)
    
    def _on_flow_ready(self, flow: Flow) -> None:
        self.feature_extractor.extract_features(flow)
    
    def _on_features_extracted(self, features: Dict[str, Any], flow: Flow) -> None:
        self.feature_mapper.map_features(features, flow)
    
    def _on_features_mapped(self, features: Dict[str, Any], flow: Flow) -> None:
        self.anomaly_detector.detect(features, flow)
    
    def _on_detection(self, result: DetectionResult) -> None:
        # Log attacks
        if result.is_attack and result.flow_metadata:
            src_ip = result.flow_metadata.get('src_ip', 'Unknown')
            self._log(f"[!][!][!] Detected Attack: {result.prediction} from IP Address {src_ip}")
        
        # Write to output
        if self._output_writer and result.flow_metadata:
            output_data = result.flow_metadata.copy()
            output_data['Prediction'] = result.prediction
            output_data['Prediction_Time'] = result.prediction_time
            output_data['Confidence'] = result.confidence
            if result.probabilities:
                for attack_type, prob in result.probabilities.items():
                    output_data[f'Prob_{attack_type}'] = prob
            self._output_writer.write(output_data)
        
        # Forward to user callback
        if self._user_detection_callback:
            self._user_detection_callback(result)
    
    def _log(self, message: str) -> None:
        """Internal logging method."""
        if self.log_callback:
            self.log_callback(message + "\n")
    