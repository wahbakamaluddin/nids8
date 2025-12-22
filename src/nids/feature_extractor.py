
from typing import Dict, List, Optional, Callable, Any

from .helper.other.flow import Flow
from nids.helper.context import PacketDirection
from nids.helper.features.flag_count import FlagCount
from nids.helper.features.flow_bytes import FlowBytes
from nids.helper.features.packet_count import PacketCount
from nids.helper.features.packet_length import PacketLength
from nids.helper.features.packet_time import PacketTime
from nids.helper.other.utils import get_statistics


class FeatureExtractor:
    def __init__(
        self,
        feature_callback: Callable[[Dict[str, Any], Flow], None],
    ):

        self.feature_callback = feature_callback

        # Statistics
        self._flows_processed = 0
        self._features_extracted = 0
    
    def extract_features(self, flow: Flow) -> Dict[str, Any]:

        self._flows_processed += 1
        
        # Initialize feature calculators
        flow_bytes = FlowBytes(flow)
        packet_count = PacketCount(flow)
        packet_length = PacketLength(flow)
        packet_time = PacketTime(flow)
        
        # Calculate inter-arrival time statistics
        flow_iat = get_statistics(flow.flow_interarrival_time)
        forward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.FORWARD)
        )
        backward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.REVERSE)
        )
        
        
        # Build complete feature dictionary - EXACTLY matching ML training features
        all_features = {
            # Flow-level
            'Flow Duration': flow.duration * 1_000_000,  # microseconds
            'Flow Packets/s': packet_count.get_rate(),
            'Flow Bytes/s': flow_bytes.get_rate(),
            'Flow IAT Mean': flow_iat["mean"] * 1_000_000,
            'Flow IAT Max': flow_iat["max"] * 1_000_000,
            'Flow IAT Std': flow_iat["std"] * 1_000_000,
            
            # Forward features
            'Fwd Header Length': flow_bytes.get_forward_header_bytes(),
            'Fwd IAT Total': forward_iat["total"] * 1_000_000,
            'Fwd IAT Mean': forward_iat["mean"] * 1_000_000,
            'Fwd IAT Max': forward_iat["max"] * 1_000_000,
            'Fwd IAT Std': forward_iat["std"] * 1_000_000,
            'Fwd Packet Length Min': packet_length.get_min(PacketDirection.FORWARD),
            'Fwd Packet Length Max': packet_length.get_max(PacketDirection.FORWARD),
            'Fwd Packet Length Mean': packet_length.get_mean(PacketDirection.FORWARD),
            'Fwd Packet Length Std': packet_length.get_std(PacketDirection.FORWARD),
            'Subflow Fwd Bytes': flow_bytes.get_bytes_sent(),
            'Total Fwd Packets': packet_count.get_total(PacketDirection.FORWARD),
            'Total Length of Fwd Packets': packet_length.get_total(PacketDirection.FORWARD),
            
            # Backward features
            'Bwd Header Length': flow_bytes.get_reverse_header_bytes(),
            'Bwd Packet Length Min': packet_length.get_min(PacketDirection.REVERSE),
            'Bwd Packet Length Max': packet_length.get_max(PacketDirection.REVERSE),
            'Bwd Packet Length Std': packet_length.get_std(PacketDirection.REVERSE),
            'Bwd Packets/s': packet_count.get_rate(PacketDirection.REVERSE),
            'Init_Win_bytes_backward': 0,  # TCP window size - requires deeper packet analysis
            
            # Packet-level
            'Packet Length Mean': packet_length.get_mean(),
            'Packet Length Std': packet_length.get_std(),
            'Packet Length Variance': packet_length.get_var(),
            'Average Packet Size': packet_length.get_mean(),
            'PSH Flag Count': 0,  # TCP flag count - requires deeper packet analysis  
            'Init_Win_bytes_forward': 0,  # TCP window size - requires deeper packet analysis
            'Max Packet Length': packet_length.get_max(),
            
            # Flow metadata (useful for logging/reporting)
            "Src IP": flow.src_ip,
            "Dst IP": flow.dest_ip,
            "Src Port": flow.src_port,
            "Dst Port": flow.dest_port,
            "Protocol": flow.protocol,
        }
        
        features = all_features
        
        self._features_extracted += len(features)
        
        # Forward features to the Feature Mapper
        if self.feature_callback:
            self.feature_callback(features, flow)
        
        return features