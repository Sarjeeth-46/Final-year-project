import pandas as pd
import random
import time
from datetime import datetime

# Constants
PROTOCOLS = ['TCP', 'UDP', 'ICMP']
LABELS = ['Normal', 'DDoS', 'Brute Force', 'Port Scan']
SOURCE_IPS = [f'192.168.1.{i}' for i in range(1, 255)]
DEST_IPS = [f'10.0.0.{i}' for i in range(1, 20)]

# Common Ports for Simulation
PORTS = {
    'Normal': [80, 443, 53, 22, 21],
    'DDoS': [80, 443], # HTTP flood
    'Brute Force': [22, 21, 3389], # SSH, FTP, RDP
    'Port Scan': None # Random
}

def generate_log_entry():
    """Generates a single synthetic log entry."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    source_ip = random.choice(SOURCE_IPS)
    dest_ip = random.choice(DEST_IPS)
    protocol = random.choice(PROTOCOLS)
    
    # Logic to skew data towards Normal behavior, but include attacks
    # Calibrated to Real Data Signatures
    rand_val = random.random()
    if rand_val < 0.85:
        label = 'Normal'
        packet_size = random.randint(40, 1500)
        dest_port = random.choice(PORTS['Normal'])
    elif rand_val < 0.90:
        label = 'DDoS'
        packet_size = random.choice([random.randint(0, 10), random.randint(1000, 1500)]) # Syn vs HTTP Flood
        dest_port = random.choice(PORTS['DDoS'])
    elif rand_val < 0.95:
        label = 'Brute Force'
        packet_size = random.randint(0, 50) # Auth packets are small
        dest_port = random.choice(PORTS['Brute Force'])
    else:
        label = 'Port Scan'
        packet_size = random.randint(0, 20) # Scan probes are tiny
        dest_port = random.randint(1, 65535)

    return {
        'timestamp': timestamp,
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'protocol': protocol,
        'packet_size': packet_size,
        'dest_port': dest_port,
        'label': label
    }

def generate_training_data(num_samples=5000, filename='backend/training_data.csv'):
    """Generates a CSV file for training the ML model."""
    data = []
    print(f"Generating {num_samples} samples...")
    for _ in range(num_samples):
        data.append(generate_log_entry())
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Data saved to {filename}")

if __name__ == "__main__":
    generate_training_data()
