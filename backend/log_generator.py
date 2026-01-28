"""
Project: AegisCore
Module: Telemetry Synthesizer
Description:
    Generates synthetic network telemetry events ("artifacts") to continuously
    feed the inference engine. This component simulates various network traffic
    profiles including organic usage patterns and specific adversarial vectors.

    Architectural Note:
    This synthesizer separates payload generation from transmission logic,
    allowing for future extension into proper pcap playback if required.
"""

import pandas as pd
import random
import time
from datetime import datetime
from typing import Dict, Union, List

# Domain Constants: Protocol Definitions
class NetworkProtocol:
    TCP = 'TCP'
    UDP = 'UDP'
    ICMP = 'ICMP'
    ALL_PROTOCOLS = [TCP, UDP, ICMP]

# Domain Constants: Attack Vectors
class TrafficCategory:
    NORMAL = 'Normal'
    DDOS = 'DDoS'
    BRUTE_FORCE = 'Brute Force'
    PORT_SCAN = 'Port Scan'

# Simulation Configuration
# Pre-defined subnets for Source (External) and Destination (Internal) actors
EXTERNAL_ACTOR_POOL = [f'192.168.1.{i}' for i in range(1, 255)]
INTERNAL_ASSET_POOL = [f'10.0.0.{i}' for i in range(1, 20)]

# Port Profiles maps Category -> Likely Ports
TRAFFIC_PROFILES = {
    TrafficCategory.NORMAL: [80, 443, 53, 22, 21],
    TrafficCategory.DDOS: [80, 443],  # HTTP/S Flood
    TrafficCategory.BRUTE_FORCE: [22, 21, 3389],  # Admin interfaces
    TrafficCategory.PORT_SCAN: []  # Dynamic range 1-65535, handled in logic
}

class TelemetrySynthesizer:
    """
    Orchestrates the creation of synthetic network packets.
    Uses probabilistic weighting to maintain a realistic baseline vs. anomaly ratio.
    """

    def __init__(self):
        self._entropy_source = random.SystemRandom()

    def _select_port_for_category(self, category: str) -> int:
        """Determines destination port based on traffic intent."""
        if category == TrafficCategory.PORT_SCAN:
            return self._entropy_source.randint(1, 65535)
        
        target_ports = TRAFFIC_PROFILES.get(category)
        if target_ports:
            return self._entropy_source.choice(target_ports)
        
        # Fallback standard port
        return 80

    def _determine_packet_size(self, category: str) -> int:
        """Calculates packet size based on characteristic signatures."""
        if category == TrafficCategory.DDOS:
            # Syn flood (tiny) or HTTP flood (large)
            return self._entropy_source.choice([
                self._entropy_source.randint(0, 10), 
                self._entropy_source.randint(1000, 1500)
            ])
        elif category == TrafficCategory.BRUTE_FORCE:
            # Authentication attempts are typically small payloads
            return self._entropy_source.randint(0, 50)
        elif category == TrafficCategory.PORT_SCAN:
            # Reconnaissance probes are minimal
            return self._entropy_source.randint(0, 20)
        
        # Normal traffic variance
        return self._entropy_source.randint(40, 1500)

    def synthesize_packet(self, forced_category: str = None) -> Dict[str, Union[str, int, float]]:
        """
        Emits a single telemetry artifact representing one network flow event.
        
        Args:
            forced_category: Optional override to generate specific attack signatures (e.g., for drills).
            
        Returns:
            Dict containing the normalized schema for the Inference Engine.
        """
        timestamp_iso = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        origin = self._entropy_source.choice(EXTERNAL_ACTOR_POOL)
        target = self._entropy_source.choice(INTERNAL_ASSET_POOL)
        proto = self._entropy_source.choice(NetworkProtocol.ALL_PROTOCOLS)

        if forced_category:
            category = forced_category
        else:
            # Probabilistic Profile Selection
            # 85% Normal, 15% Malicious Distribution
            roll = self._entropy_source.random()
            
            if roll < 0.85:
                category = TrafficCategory.NORMAL
            elif roll < 0.90:
                category = TrafficCategory.DDOS
            elif roll < 0.95:
                category = TrafficCategory.BRUTE_FORCE
            else:
                category = TrafficCategory.PORT_SCAN

        # Construct Artifact
        dest_port = self._select_port_for_category(category)
        pkt_size = self._determine_packet_size(category)

        return {
            'timestamp': timestamp_iso,
            'source_ip': origin,
            'dest_ip': target,
            'protocol': proto,
            'packet_size': pkt_size,
            'dest_port': dest_port,
            'label': category
        }

    def generate_batch(self, count: int = 5000) -> pd.DataFrame:
        """Produce a batch of synthetic data for model training."""
        print(f"[Synthesizer] Generating batch of {count} events...")
        buffer = [self.synthesize_packet() for _ in range(count)]
        return pd.DataFrame(buffer)

# Singleton Export
_synthesizer = TelemetrySynthesizer()

def generate_log_entry():
    """Legacy Adapter: Exposed for compatibility with existing loops."""
    return _synthesizer.synthesize_packet()

def generate_training_data(num_samples=5000, filename='backend/training_data.csv'):
    """Utility entry point for CSV generation."""
    df = _synthesizer.generate_batch(num_samples)
    df.to_csv(filename, index=False)
    print(f"[Synthesizer] Artifacts persisted to {filename}")

if __name__ == "__main__":
    generate_training_data()
