"""
Packet Capturer Module (Component 1)

The packet capturer is responsible for capturing live network traffic from 
the device's network interface. It is implemented using the Scapy library, 
which allows low-level packet sniffing and handling.

The captured packets are then forwarded to the Packet Parser for processing.
"""

import threading
from typing import Callable, Optional

from scapy.sendrecv import AsyncSniffer
from scapy.packet import Packet

class PacketCapturer:
    def __init__(
        self,
        interface: str,
        packet_callback,
        bpf_filter: str = "ip and (tcp or udp)"
    ):

        self.interface = interface
        self.packet_callback = packet_callback
        self.bpf_filter = bpf_filter
        
        self._sniffer: AsyncSniffer
        self._is_capturing = False
        self._lock = threading.Lock()
        
        # Statistics
        self._packets_captured = 0
    
    def start(self) -> None:
        with self._lock:
            if self._is_capturing:
                return
            
            # Pass captured packets to _handle_packet (parse_packet in PacketParser)
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,  # Don't store packets in memory
            )
            
            self._sniffer.start()
            self._is_capturing = True
    
    def stop(self) -> None:
        with self._lock:
            if not self._is_capturing:
                return
            
            if self._sniffer:
                self._sniffer.stop()
                self._sniffer = None
            
            self._is_capturing = False
    
    def _handle_packet(self, packet: Packet) -> None:
        self._packets_captured += 1
        
        # Forward packet to the next component (Packet Parser)
        if self.packet_callback:
            self.packet_callback(packet)
    @property
    def is_capturing(self) -> bool:
        """Check if packet capture is currently active."""
        return self._is_capturing
    
    @property
    def packets_captured(self) -> int:
        """Get the number of packets captured."""
        return self._packets_captured