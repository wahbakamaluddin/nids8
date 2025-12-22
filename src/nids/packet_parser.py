import threading
from typing import Dict, Optional, Tuple, Callable

from scapy.packet import Packet

from nids.helper.other.constants import FLOW_TIMEOUT, PACKETS_PER_GC
from nids.helper.context import PacketDirection, get_packet_flow_key
from nids.helper.other.flow import Flow


# Type alias for flow key (5-tuple)
FlowKey = Tuple[Tuple[str, str, int, int], int]  # ((src_ip, dst_ip, src_port, dst_port), count)


class PacketParser:

    def __init__(
        self,
        flow_callback: Callable[[Flow], None],
        flow_timeout: float = FLOW_TIMEOUT
    ):
        self.flow_callback = flow_callback
        self.flow_timeout = flow_timeout
        
        # Flow storage: key is ((src_ip, dst_ip, src_port, dst_port), count)
        self.flows: Dict[FlowKey, Flow] = {}
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Statistics
        self._packets_processed = 0
        self._flows_created = 0
        self._flows_completed = 0
    
    def parse_packet(self, packet: Packet) -> Optional[Flow]:
        # Only process TCP and UDP packets
        if "TCP" not in packet and "UDP" not in packet:
            return None
        
        self._packets_processed += 1
        count = 0
        direction = PacketDirection.FORWARD
        
        try:
            packet_flow_key = get_packet_flow_key(packet, direction)
        except Exception:
            return None
        
        # Check for existing flow (forward direction)
        with self._lock:
            flow = self.flows.get((packet_flow_key, count))
        
        # If no forward flow exists, check reverse direction
        if flow is None:
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            with self._lock:
                flow = self.flows.get((packet_flow_key, count))
        
        # Create new flow if none exists
        if flow is None:
            direction = PacketDirection.FORWARD
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = Flow(packet, direction)
            
            with self._lock:
                self.flows[(packet_flow_key, count)] = flow
                self._flows_created += 1
        
        # Handle expired flows or FIN packets
        elif (packet.time - flow.latest_timestamp) > self.flow_timeout:
            expired = self.flow_timeout
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += self.flow_timeout
                
                with self._lock:
                    flow = self.flows.get((packet_flow_key, count))
                
                if flow is None:
                    flow = Flow(packet, direction)
                    with self._lock:
                        self.flows[(packet_flow_key, count)] = flow
                        self._flows_created += 1
                    break
        
        # Add packet to flow
        flow.add_packet(packet, direction)
        
        # Check for flow termination conditions
        if flow.should_terminate() or self._packets_processed % PACKETS_PER_GC == 0:
            self.garbage_collect(packet.time)
        
        return flow
    
    def garbage_collect(self, latest_time: Optional[float] = None) -> None:
        with self._lock:
            keys = list(self.flows.keys())
        
        for key in keys:
            with self._lock:
                flow = self.flows.get(key)
            
            if not flow:
                continue
            
            # Check if flow should be terminated
            should_terminate = (
                flow.should_terminate()  # RST or bidirectional FIN
                or (latest_time is not None and 
                    latest_time - flow.latest_timestamp >= self.flow_timeout)
                or flow.duration >= self.flow_timeout
            )
            
            if not should_terminate:
                continue
            
            # Remove flow from storage
            with self._lock:
                if key in self.flows:
                    del self.flows[key]
                    self._flows_completed += 1
            
            # Forward flow to Feature Extractor
            if self.flow_callback:
                self.flow_callback(flow)
    
    def flush_all_flows(self) -> None:
        with self._lock:
            flows = list(self.flows.values())
            self.flows.clear()
        
        for flow in flows:
            self._flows_completed += 1
            if self.flow_callback:
                self.flow_callback(flow)

    @property
    def flows_completed(self) -> int:
        """Get the number of completed flows."""
        return self._flows_completed
