"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | RW Software Solutions
ML Benchmark Dataset Generator (CICIDS2017 Flow Benchmark Specification)
"""

import numpy as np
import pandas as pd
import os

FEATURE_COLUMNS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Fwd Header Length',
    'Bwd Header Length',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'Down/Up Ratio',
    'Average Packet Size',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'min_seg_size_forward'
]

ATTACK_CLASSES = [
    'BENIGN',
    'DoS',
    'DDoS',
    'PortScan',
    'Brute Force',
    'Botnet',
    'Web Attack'
]

def generate_flow_dataset(n_samples=18000, random_state=42):
    """
    Synthesizes a realistic CICIDS2017-style network flow dataset.
    Follows empirical traffic feature distributions documented in CICIDS2017 research.
    """
    np.random.seed(random_state)
    
    # Class distribution (realistic SOC environment: ~50% Benign, ~50% attacks across categories)
    class_weights = {
        'BENIGN': 0.48,
        'DoS': 0.12,
        'DDoS': 0.12,
        'PortScan': 0.10,
        'Brute Force': 0.07,
        'Botnet': 0.06,
        'Web Attack': 0.05
    }
    
    dfs = []
    
    for cls_name, weight in class_weights.items():
        count = int(n_samples * weight)
        data = {}
        
        if cls_name == 'BENIGN':
            # Typical legitimate HTTP/HTTPS, DNS, SSH traffic
            ports = np.random.choice([80, 443, 53, 22, 8080, 8443, 445, 123], size=count, p=[0.25, 0.45, 0.15, 0.05, 0.04, 0.03, 0.02, 0.01])
            duration = np.random.exponential(scale=120000, size=count) + 500
            fwd_pkts = np.random.geometric(p=0.15, size=count) + 1
            bwd_pkts = np.random.geometric(p=0.12, size=count) + 1
            fwd_len_mean = np.random.normal(loc=240, scale=80, size=count).clip(32, 1460)
            bwd_len_mean = np.random.normal(loc=520, scale=180, size=count).clip(40, 1460)
            flow_bytes_s = (fwd_pkts * fwd_len_mean + bwd_pkts * bwd_len_mean) / (duration / 1e6 + 1e-5)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
            flow_iat_mean = duration / (fwd_pkts + bwd_pkts + 1)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len_mean
            data['Total Length of Bwd Packets'] = bwd_pkts * bwd_len_mean
            data['Fwd Packet Length Max'] = fwd_len_mean * np.random.uniform(1.1, 1.8, count)
            data['Fwd Packet Length Min'] = np.random.choice([0, 32, 40, 52], count)
            data['Fwd Packet Length Mean'] = fwd_len_mean
            data['Fwd Packet Length Std'] = fwd_len_mean * np.random.uniform(0.1, 0.4, count)
            data['Bwd Packet Length Max'] = bwd_len_mean * np.random.uniform(1.2, 2.0, count)
            data['Bwd Packet Length Min'] = np.random.choice([0, 40, 52], count)
            data['Bwd Packet Length Mean'] = bwd_len_mean
            data['Bwd Packet Length Std'] = bwd_len_mean * np.random.uniform(0.1, 0.5, count)
            data['Flow Bytes/s'] = flow_bytes_s
            data['Flow Packets/s'] = flow_pkts_s
            data['Flow IAT Mean'] = flow_iat_mean
            data['Flow IAT Std'] = flow_iat_mean * np.random.uniform(0.2, 0.8, count)
            data['Flow IAT Max'] = flow_iat_mean * np.random.uniform(1.5, 3.5, count)
            data['Flow IAT Min'] = np.random.uniform(5, 50, count)
            data['Fwd IAT Total'] = duration * np.random.uniform(0.6, 0.95, count)
            data['Fwd IAT Mean'] = duration / (fwd_pkts + 1)
            data['Bwd IAT Total'] = duration * np.random.uniform(0.5, 0.9, count)
            data['Bwd IAT Mean'] = duration / (bwd_pkts + 1)
            data['Fwd Header Length'] = fwd_pkts * np.random.choice([20, 32], count)
            data['Bwd Header Length'] = bwd_pkts * np.random.choice([20, 32], count)
            data['Fwd Packets/s'] = fwd_pkts / (duration / 1e6 + 1e-5)
            data['Bwd Packets/s'] = bwd_pkts / (duration / 1e6 + 1e-5)
            data['Min Packet Length'] = np.random.choice([0, 20, 40], count)
            data['Max Packet Length'] = np.maximum(data['Fwd Packet Length Max'], data['Bwd Packet Length Max'])
            data['Packet Length Mean'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (fwd_pkts + bwd_pkts)
            data['Packet Length Std'] = data['Packet Length Mean'] * np.random.uniform(0.2, 0.6, count)
            data['FIN Flag Count'] = np.random.binomial(1, 0.08, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.12, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.02, count)
            data['PSH Flag Count'] = np.random.binomial(1, 0.45, count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.85, count)
            data['URG Flag Count'] = np.random.binomial(1, 0.01, count)
            data['Down/Up Ratio'] = np.random.uniform(0.8, 1.8, count)
            data['Average Packet Size'] = data['Packet Length Mean'] * np.random.uniform(0.95, 1.05, count)
            data['Init_Win_bytes_forward'] = np.random.choice([8192, 29200, 65535, 14600], count)
            data['Init_Win_bytes_backward'] = np.random.choice([8192, 29200, 65535, 14600], count)
            data['min_seg_size_forward'] = np.random.choice([20, 32], count)
            
        elif cls_name == 'DoS':
            # Denial of Service: e.g., Hulk, GoldenEye, Slowloris, Slowhttptest
            ports = np.random.choice([80, 443, 8080], size=count, p=[0.70, 0.20, 0.10])
            duration = np.random.exponential(scale=6500000, size=count) + 50000
            fwd_pkts = np.random.randint(4, 25, size=count)
            bwd_pkts = np.random.randint(0, 4, size=count)
            fwd_len_mean = np.random.normal(loc=180, scale=40, size=count).clip(40, 500)
            bwd_len_mean = np.random.normal(loc=30, scale=15, size=count).clip(0, 150)
            flow_bytes_s = (fwd_pkts * fwd_len_mean + bwd_pkts * bwd_len_mean) / (duration / 1e6 + 1e-5)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
            flow_iat_mean = duration / (fwd_pkts + bwd_pkts + 1)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len_mean
            data['Total Length of Bwd Packets'] = bwd_pkts * bwd_len_mean
            data['Fwd Packet Length Max'] = fwd_len_mean * np.random.uniform(1.1, 1.4, count)
            data['Fwd Packet Length Min'] = np.random.choice([0, 30], count)
            data['Fwd Packet Length Mean'] = fwd_len_mean
            data['Fwd Packet Length Std'] = fwd_len_mean * np.random.uniform(0.05, 0.25, count)
            data['Bwd Packet Length Max'] = bwd_len_mean * np.random.uniform(1.0, 1.5, count)
            data['Bwd Packet Length Min'] = np.zeros(count)
            data['Bwd Packet Length Mean'] = bwd_len_mean
            data['Bwd Packet Length Std'] = bwd_len_mean * np.random.uniform(0.05, 0.2, count)
            data['Flow Bytes/s'] = flow_bytes_s
            data['Flow Packets/s'] = flow_pkts_s
            data['Flow IAT Mean'] = flow_iat_mean
            data['Flow IAT Std'] = flow_iat_mean * np.random.uniform(0.4, 0.9, count)
            data['Flow IAT Max'] = flow_iat_mean * np.random.uniform(2.0, 4.5, count)
            data['Flow IAT Min'] = np.random.uniform(200, 10000, count)
            data['Fwd IAT Total'] = duration * np.random.uniform(0.85, 0.99, count)
            data['Fwd IAT Mean'] = duration / (fwd_pkts + 1)
            data['Bwd IAT Total'] = duration * np.random.uniform(0.1, 0.5, count)
            data['Bwd IAT Mean'] = np.where(bwd_pkts > 0, duration / (bwd_pkts + 1), 0)
            data['Fwd Header Length'] = fwd_pkts * 32
            data['Bwd Header Length'] = bwd_pkts * 32
            data['Fwd Packets/s'] = fwd_pkts / (duration / 1e6 + 1e-5)
            data['Bwd Packets/s'] = bwd_pkts / (duration / 1e6 + 1e-5)
            data['Min Packet Length'] = np.zeros(count)
            data['Max Packet Length'] = data['Fwd Packet Length Max']
            data['Packet Length Mean'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (fwd_pkts + bwd_pkts + 1e-5)
            data['Packet Length Std'] = data['Packet Length Mean'] * np.random.uniform(0.3, 0.7, count)
            data['FIN Flag Count'] = np.random.binomial(1, 0.02, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.45, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.25, count)
            data['PSH Flag Count'] = np.random.binomial(1, 0.65, count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.40, count)
            data['URG Flag Count'] = np.random.binomial(1, 0.01, count)
            data['Down/Up Ratio'] = (bwd_pkts / (fwd_pkts + 1e-5)).clip(0, 0.5)
            data['Average Packet Size'] = data['Packet Length Mean']
            data['Init_Win_bytes_forward'] = np.random.choice([256, 512, 1024, 2048, 8192], count)
            data['Init_Win_bytes_backward'] = np.random.choice([0, 256, 1024], count)
            data['min_seg_size_forward'] = np.full(count, 32)
            
        elif cls_name == 'DDoS':
            # Distributed Denial of Service: massive packet count, high flow rate, short IAT
            ports = np.random.choice([80, 443, 53, 19, 123], size=count, p=[0.55, 0.25, 0.10, 0.05, 0.05])
            duration = np.random.exponential(scale=1800000, size=count) + 1000
            fwd_pkts = np.random.randint(20, 150, size=count)
            bwd_pkts = np.random.randint(0, 5, size=count)
            fwd_len_mean = np.random.normal(loc=450, scale=120, size=count).clip(64, 1400)
            bwd_len_mean = np.random.normal(loc=15, scale=10, size=count).clip(0, 60)
            flow_bytes_s = (fwd_pkts * fwd_len_mean) / (duration / 1e6 + 1e-5) * np.random.uniform(3.0, 15.0, count)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5) * np.random.uniform(2.5, 10.0, count)
            flow_iat_mean = (duration / (fwd_pkts + bwd_pkts + 1)).clip(1, 200)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len_mean
            data['Total Length of Bwd Packets'] = bwd_pkts * bwd_len_mean
            data['Fwd Packet Length Max'] = fwd_len_mean * np.random.uniform(1.2, 1.5, count)
            data['Fwd Packet Length Min'] = np.random.choice([0, 54, 64], count)
            data['Fwd Packet Length Mean'] = fwd_len_mean
            data['Fwd Packet Length Std'] = fwd_len_mean * np.random.uniform(0.1, 0.3, count)
            data['Bwd Packet Length Max'] = bwd_len_mean * np.random.uniform(1.0, 1.3, count)
            data['Bwd Packet Length Min'] = np.zeros(count)
            data['Bwd Packet Length Mean'] = bwd_len_mean
            data['Bwd Packet Length Std'] = bwd_len_mean * np.random.uniform(0.01, 0.2, count)
            data['Flow Bytes/s'] = flow_bytes_s
            data['Flow Packets/s'] = flow_pkts_s
            data['Flow IAT Mean'] = flow_iat_mean
            data['Flow IAT Std'] = flow_iat_mean * np.random.uniform(0.1, 0.5, count)
            data['Flow IAT Max'] = flow_iat_mean * np.random.uniform(1.5, 3.0, count)
            data['Flow IAT Min'] = np.random.uniform(0.5, 15, count)
            data['Fwd IAT Total'] = duration * np.random.uniform(0.9, 0.99, count)
            data['Fwd IAT Mean'] = flow_iat_mean
            data['Bwd IAT Total'] = np.where(bwd_pkts > 0, duration * 0.1, 0)
            data['Bwd IAT Mean'] = np.where(bwd_pkts > 0, duration / (bwd_pkts + 1), 0)
            data['Fwd Header Length'] = fwd_pkts * 20
            data['Bwd Header Length'] = bwd_pkts * 20
            data['Fwd Packets/s'] = flow_pkts_s * 0.95
            data['Bwd Packets/s'] = flow_pkts_s * 0.05
            data['Min Packet Length'] = np.random.choice([0, 40, 54], count)
            data['Max Packet Length'] = data['Fwd Packet Length Max']
            data['Packet Length Mean'] = fwd_len_mean * 0.95
            data['Packet Length Std'] = fwd_len_mean * 0.25
            data['FIN Flag Count'] = np.random.binomial(1, 0.01, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.88, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.35, count)
            data['PSH Flag Count'] = np.random.binomial(1, 0.10, count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.15, count)
            data['URG Flag Count'] = np.random.binomial(1, 0.02, count)
            data['Down/Up Ratio'] = np.zeros(count)
            data['Average Packet Size'] = fwd_len_mean
            data['Init_Win_bytes_forward'] = np.random.choice([512, 1024, 2048], count)
            data['Init_Win_bytes_backward'] = np.zeros(count)
            data['min_seg_size_forward'] = np.full(count, 20)
            
        elif cls_name == 'PortScan':
            # Port Scanning: Nmap/Masscan style: single/few fwd packets, 0 bwd packets, rapid probe across wide port spectrum
            ports = np.random.randint(1, 65535, size=count)
            duration = np.random.uniform(10, 1500, size=count)
            fwd_pkts = np.random.choice([1, 2, 3], size=count, p=[0.75, 0.20, 0.05])
            bwd_pkts = np.random.choice([0, 1], size=count, p=[0.92, 0.08])
            fwd_len = np.random.choice([0, 40, 44, 60], count)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len
            data['Total Length of Bwd Packets'] = bwd_pkts * np.random.choice([0, 40], count)
            data['Fwd Packet Length Max'] = fwd_len
            data['Fwd Packet Length Min'] = fwd_len
            data['Fwd Packet Length Mean'] = fwd_len
            data['Fwd Packet Length Std'] = np.zeros(count)
            data['Bwd Packet Length Max'] = np.random.choice([0, 40], count)
            data['Bwd Packet Length Min'] = np.zeros(count)
            data['Bwd Packet Length Mean'] = np.random.choice([0, 20], count)
            data['Bwd Packet Length Std'] = np.zeros(count)
            data['Flow Bytes/s'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (duration / 1e6 + 1e-5)
            data['Flow Packets/s'] = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
            data['Flow IAT Mean'] = duration / (fwd_pkts + 1)
            data['Flow IAT Std'] = np.zeros(count)
            data['Flow IAT Max'] = duration
            data['Flow IAT Min'] = duration / fwd_pkts
            data['Fwd IAT Total'] = duration
            data['Fwd IAT Mean'] = duration / fwd_pkts
            data['Bwd IAT Total'] = np.zeros(count)
            data['Bwd IAT Mean'] = np.zeros(count)
            data['Fwd Header Length'] = fwd_pkts * np.random.choice([20, 32, 40], count)
            data['Bwd Header Length'] = bwd_pkts * 20
            data['Fwd Packets/s'] = fwd_pkts / (duration / 1e6 + 1e-5)
            data['Bwd Packets/s'] = bwd_pkts / (duration / 1e6 + 1e-5)
            data['Min Packet Length'] = fwd_len
            data['Max Packet Length'] = fwd_len
            data['Packet Length Mean'] = fwd_len
            data['Packet Length Std'] = np.zeros(count)
            data['FIN Flag Count'] = np.random.binomial(1, 0.05, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.95, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.15, count)
            data['PSH Flag Count'] = np.zeros(count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.05, count)
            data['URG Flag Count'] = np.zeros(count)
            data['Down/Up Ratio'] = np.zeros(count)
            data['Average Packet Size'] = fwd_len
            data['Init_Win_bytes_forward'] = np.random.choice([1024, 2048, 14600], count)
            data['Init_Win_bytes_backward'] = np.zeros(count)
            data['min_seg_size_forward'] = np.random.choice([20, 32], count)
            
        elif cls_name == 'Brute Force':
            # Credential Brute Force: SSH (22), FTP (21), Telnet (23), RDP (3389)
            ports = np.random.choice([22, 21, 23, 3389, 445], size=count, p=[0.50, 0.30, 0.08, 0.08, 0.04])
            duration = np.random.normal(loc=120000, scale=30000, size=count).clip(15000, 350000)
            fwd_pkts = np.random.randint(8, 22, size=count)
            bwd_pkts = np.random.randint(6, 18, size=count)
            fwd_len_mean = np.random.normal(loc=65, scale=20, size=count).clip(20, 150)
            bwd_len_mean = np.random.normal(loc=85, scale=25, size=count).clip(20, 200)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len_mean
            data['Total Length of Bwd Packets'] = bwd_pkts * bwd_len_mean
            data['Fwd Packet Length Max'] = fwd_len_mean * np.random.uniform(1.2, 1.8, count)
            data['Fwd Packet Length Min'] = np.full(count, 20)
            data['Fwd Packet Length Mean'] = fwd_len_mean
            data['Fwd Packet Length Std'] = fwd_len_mean * np.random.uniform(0.1, 0.35, count)
            data['Bwd Packet Length Max'] = bwd_len_mean * np.random.uniform(1.2, 1.8, count)
            data['Bwd Packet Length Min'] = np.full(count, 20)
            data['Bwd Packet Length Mean'] = bwd_len_mean
            data['Bwd Packet Length Std'] = bwd_len_mean * np.random.uniform(0.1, 0.35, count)
            data['Flow Bytes/s'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (duration / 1e6 + 1e-5)
            data['Flow Packets/s'] = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
            data['Flow IAT Mean'] = duration / (fwd_pkts + bwd_pkts + 1)
            data['Flow IAT Std'] = data['Flow IAT Mean'] * np.random.uniform(0.2, 0.5, count)
            data['Flow IAT Max'] = data['Flow IAT Mean'] * np.random.uniform(1.5, 2.5, count)
            data['Flow IAT Min'] = np.random.uniform(10, 80, count)
            data['Fwd IAT Total'] = duration * 0.95
            data['Fwd IAT Mean'] = duration / (fwd_pkts + 1)
            data['Bwd IAT Total'] = duration * 0.90
            data['Bwd IAT Mean'] = duration / (bwd_pkts + 1)
            data['Fwd Header Length'] = fwd_pkts * 32
            data['Bwd Header Length'] = bwd_pkts * 32
            data['Fwd Packets/s'] = fwd_pkts / (duration / 1e6 + 1e-5)
            data['Bwd Packets/s'] = bwd_pkts / (duration / 1e6 + 1e-5)
            data['Min Packet Length'] = np.full(count, 20)
            data['Max Packet Length'] = np.maximum(data['Fwd Packet Length Max'], data['Bwd Packet Length Max'])
            data['Packet Length Mean'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (fwd_pkts + bwd_pkts)
            data['Packet Length Std'] = data['Packet Length Mean'] * 0.3
            data['FIN Flag Count'] = np.random.binomial(1, 0.15, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.20, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.45, count)
            data['PSH Flag Count'] = np.random.binomial(1, 0.85, count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.90, count)
            data['URG Flag Count'] = np.zeros(count)
            data['Down/Up Ratio'] = (bwd_pkts / fwd_pkts).clip(0.5, 1.2)
            data['Average Packet Size'] = data['Packet Length Mean']
            data['Init_Win_bytes_forward'] = np.random.choice([29200, 65535], count)
            data['Init_Win_bytes_backward'] = np.random.choice([29200, 65535], count)
            data['min_seg_size_forward'] = np.full(count, 32)
            
        elif cls_name == 'Botnet':
            # Botnet C2 Communication (Ares, Zeus, Mirai beaconing): regular interval heartbeats, specific non-standard IRC/HTTP ports
            ports = np.random.choice([6667, 8000, 4444, 1080, 5555, 80, 443], size=count, p=[0.35, 0.20, 0.15, 0.10, 0.10, 0.05, 0.05])
            duration = np.random.normal(loc=850000, scale=100000, size=count).clip(100000, 2000000)
            fwd_pkts = np.random.randint(5, 15, size=count)
            bwd_pkts = np.random.randint(4, 12, size=count)
            fwd_len_mean = np.random.normal(loc=95, scale=25, size=count).clip(30, 220)
            bwd_len_mean = np.random.normal(loc=70, scale=20, size=count).clip(20, 180)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len_mean
            data['Total Length of Bwd Packets'] = bwd_pkts * bwd_len_mean
            data['Fwd Packet Length Max'] = fwd_len_mean * np.random.uniform(1.1, 1.4, count)
            data['Fwd Packet Length Min'] = np.random.choice([0, 24], count)
            data['Fwd Packet Length Mean'] = fwd_len_mean
            data['Fwd Packet Length Std'] = fwd_len_mean * np.random.uniform(0.05, 0.2, count)
            data['Bwd Packet Length Max'] = bwd_len_mean * np.random.uniform(1.1, 1.4, count)
            data['Bwd Packet Length Min'] = np.random.choice([0, 24], count)
            data['Bwd Packet Length Mean'] = bwd_len_mean
            data['Bwd Packet Length Std'] = bwd_len_mean * np.random.uniform(0.05, 0.2, count)
            data['Flow Bytes/s'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (duration / 1e6 + 1e-5)
            data['Flow Packets/s'] = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
            data['Flow IAT Mean'] = duration / (fwd_pkts + bwd_pkts + 1)
            data['Flow IAT Std'] = data['Flow IAT Mean'] * np.random.uniform(0.05, 0.15, count) # very low variance due to automated timer
            data['Flow IAT Max'] = data['Flow IAT Mean'] * 1.3
            data['Flow IAT Min'] = data['Flow IAT Mean'] * 0.7
            data['Fwd IAT Total'] = duration * 0.9
            data['Fwd IAT Mean'] = duration / (fwd_pkts + 1)
            data['Bwd IAT Total'] = duration * 0.85
            data['Bwd IAT Mean'] = duration / (bwd_pkts + 1)
            data['Fwd Header Length'] = fwd_pkts * 20
            data['Bwd Header Length'] = bwd_pkts * 20
            data['Fwd Packets/s'] = fwd_pkts / (duration / 1e6 + 1e-5)
            data['Bwd Packets/s'] = bwd_pkts / (duration / 1e6 + 1e-5)
            data['Min Packet Length'] = np.random.choice([0, 24], count)
            data['Max Packet Length'] = np.maximum(data['Fwd Packet Length Max'], data['Bwd Packet Length Max'])
            data['Packet Length Mean'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (fwd_pkts + bwd_pkts)
            data['Packet Length Std'] = data['Packet Length Mean'] * 0.2
            data['FIN Flag Count'] = np.random.binomial(1, 0.05, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.10, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.05, count)
            data['PSH Flag Count'] = np.random.binomial(1, 0.90, count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.85, count)
            data['URG Flag Count'] = np.zeros(count)
            data['Down/Up Ratio'] = (bwd_pkts / fwd_pkts).clip(0.6, 1.0)
            data['Average Packet Size'] = data['Packet Length Mean']
            data['Init_Win_bytes_forward'] = np.random.choice([8192, 65535], count)
            data['Init_Win_bytes_backward'] = np.random.choice([8192, 65535], count)
            data['min_seg_size_forward'] = np.full(count, 20)
            
        elif cls_name == 'Web Attack':
            # Web Attacks: SQL Injection, XSS, Path Traversal against HTTP/HTTPS endpoints
            ports = np.random.choice([80, 443, 8080, 8443], size=count, p=[0.55, 0.35, 0.07, 0.03])
            duration = np.random.exponential(scale=250000, size=count) + 15000
            fwd_pkts = np.random.randint(6, 30, size=count)
            bwd_pkts = np.random.randint(4, 25, size=count)
            # Long request payloads (SQL injection payloads, scripts)
            fwd_len_mean = np.random.normal(loc=720, scale=190, size=count).clip(200, 1460)
            bwd_len_mean = np.random.normal(loc=980, scale=280, size=count).clip(100, 1460)
            
            data['Destination Port'] = ports
            data['Flow Duration'] = duration
            data['Total Fwd Packets'] = fwd_pkts
            data['Total Backward Packets'] = bwd_pkts
            data['Total Length of Fwd Packets'] = fwd_pkts * fwd_len_mean
            data['Total Length of Bwd Packets'] = bwd_pkts * bwd_len_mean
            data['Fwd Packet Length Max'] = fwd_len_mean * np.random.uniform(1.3, 1.8, count)
            data['Fwd Packet Length Min'] = np.random.choice([0, 32, 54], count)
            data['Fwd Packet Length Mean'] = fwd_len_mean
            data['Fwd Packet Length Std'] = fwd_len_mean * np.random.uniform(0.2, 0.5, count)
            data['Bwd Packet Length Max'] = bwd_len_mean * np.random.uniform(1.2, 1.9, count)
            data['Bwd Packet Length Min'] = np.random.choice([0, 40], count)
            data['Bwd Packet Length Mean'] = bwd_len_mean
            data['Bwd Packet Length Std'] = bwd_len_mean * np.random.uniform(0.2, 0.5, count)
            data['Flow Bytes/s'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (duration / 1e6 + 1e-5)
            data['Flow Packets/s'] = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
            data['Flow IAT Mean'] = duration / (fwd_pkts + bwd_pkts + 1)
            data['Flow IAT Std'] = data['Flow IAT Mean'] * np.random.uniform(0.3, 0.8, count)
            data['Flow IAT Max'] = data['Flow IAT Mean'] * 3.0
            data['Flow IAT Min'] = np.random.uniform(10, 100, count)
            data['Fwd IAT Total'] = duration * 0.95
            data['Fwd IAT Mean'] = duration / (fwd_pkts + 1)
            data['Bwd IAT Total'] = duration * 0.90
            data['Bwd IAT Mean'] = duration / (bwd_pkts + 1)
            data['Fwd Header Length'] = fwd_pkts * 32
            data['Bwd Header Length'] = bwd_pkts * 32
            data['Fwd Packets/s'] = fwd_pkts / (duration / 1e6 + 1e-5)
            data['Bwd Packets/s'] = bwd_pkts / (duration / 1e6 + 1e-5)
            data['Min Packet Length'] = np.random.choice([0, 32, 54], count)
            data['Max Packet Length'] = np.maximum(data['Fwd Packet Length Max'], data['Bwd Packet Length Max'])
            data['Packet Length Mean'] = (data['Total Length of Fwd Packets'] + data['Total Length of Bwd Packets']) / (fwd_pkts + bwd_pkts)
            data['Packet Length Std'] = data['Packet Length Mean'] * 0.4
            data['FIN Flag Count'] = np.random.binomial(1, 0.05, count)
            data['SYN Flag Count'] = np.random.binomial(1, 0.15, count)
            data['RST Flag Count'] = np.random.binomial(1, 0.10, count)
            data['PSH Flag Count'] = np.random.binomial(1, 0.88, count)
            data['ACK Flag Count'] = np.random.binomial(1, 0.95, count)
            data['URG Flag Count'] = np.zeros(count)
            data['Down/Up Ratio'] = (bwd_pkts / fwd_pkts).clip(0.5, 2.5)
            data['Average Packet Size'] = data['Packet Length Mean']
            data['Init_Win_bytes_forward'] = np.random.choice([29200, 65535], count)
            data['Init_Win_bytes_backward'] = np.random.choice([29200, 65535], count)
            data['min_seg_size_forward'] = np.full(count, 32)
            
        df = pd.DataFrame(data)
        df['Label'] = cls_name
        dfs.append(df)
        
    final_df = pd.concat(dfs, ignore_index=True)
    # Shuffle
    final_df = final_df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return final_df

if __name__ == '__main__':
    out_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(out_dir, exist_ok=True)
    out_csv = os.path.join(out_dir, 'cicids2017_benchmark.csv')
    print("Generating CICIDS2017 flow benchmark dataset...")
    df = generate_flow_dataset(n_samples=20000, random_state=42)
    df.to_csv(out_csv, index=False)
    print(f"Dataset generated successfully at: {out_csv}")
    print(f"Shape: {df.shape}")
    print("Class breakdown:\n", df['Label'].value_counts())
