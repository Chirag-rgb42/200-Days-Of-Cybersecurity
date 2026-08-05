# ==========================================
# Day 20: Simulated SYN Flood / Traffic Anomaly Detector
# Purpose: Practice behavioral threshold monitoring and defensive scripting
# ==========================================

import time
from collections import defaultdict

print("=== SIMULATED TRAFFIC ANOMALY DETECTOR ===")

# Simulated stream of incoming connection attempts (Source IP, Packet Type)
# In a real tool, this would ingest live packet logs or network taps.
simulated_traffic_stream = [
    ("192.168.1.50", "SYN"),
    ("192.168.1.50", "SYN"),
    ("192.168.1.50", "SYN"),
    ("192.168.1.50", "SYN"),
    ("192.168.1.50", "SYN"), # Threshold crossed for this IP
    ("10.0.0.15", "SYN"),
    ("192.168.1.50", "SYN"), # Continuing flood pattern
    ("172.16.0.8", "SYN"),
]

# Dictionary to track request counts per IP address
ip_connection_counts = defaultdict(int)

# Security threshold: Max allowed connection requests before flagging
THRESHOLD = 4

def detect_anomalies(traffic_stream):
    print("[*] Analyzing incoming traffic stream for anomalous patterns...")
    print(f"[*] Alert Threshold set to: {THRESHOLD} requests per source.\n")
    
    for src_ip, packet_type in traffic_stream:
        if packet_type == "SYN":
            ip_connection_counts[src_ip] += 1
            print(f"[+] Received SYN packet from {src_ip} (Total: {ip_connection_counts[src_ip]})")
            
            # Check if the IP has breached our security threshold
            if ip_connection_counts[src_ip] > THRESHOLD:
                print(f"🚨 [ALERT]: Potential SYN Flood or Brute Force detected from IP: {src_ip}!")
        
        time.sleep(0.2) # Simulate processing delay

# Run the detector
detect_anomalies(simulated_traffic_stream)
print("\n==========================================")