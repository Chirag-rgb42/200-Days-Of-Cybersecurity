# ==========================================
# Day 47: Network Packet Exfiltration & Anomaly Detector
# Purpose: Practice network forensics and detection of abnormal data transfer volumes
# ==========================================

print("=== NETWORK PACKET EXFILTRATION DETECTOR ===")

# Simulated network packet log stream (Timestamp, Source IP, Dest IP, Protocol, Packet Size in Bytes)
network_packets = [
    {"time": "14:00:01", "src": "192.168.1.50", "dest": "10.0.0.1", "protocol": "DNS", "size": 128},
    {"time": "14:05:22", "src": "192.168.1.50", "dest": "142.250.190.46", "protocol": "HTTPS", "size": 1024},
    {"time": "14:10:15", "src": "192.168.1.100", "dest": "203.0.113.99", "protocol": "HTTPS", "size": 5242880}, # 5 MB transfer!
    {"time": "14:12:00", "src": "192.168.1.50", "dest": "10.0.0.1", "protocol": "HTTP", "size": 256}
]

def detect_exfiltration(packets, size_threshold_bytes=1048576): # Default 1 MB threshold
    print("[*] Analyzing network packet logs for unusual outbound data volumes...\n")
    alerts = 0
    
    for pkt in packets:
        size = pkt["size"]
        src = pkt["src"]
        dest = pkt["dest"]
        proto = pkt["protocol"]
        
        if size > size_threshold_bytes:
            alerts += 1
            print(f"  🚨 [EXFILTRATION ALERT]: Large outbound packet volume detected!")
            print(f"     ├─ Source IP: {src}")
            print(f"     ├─ Destination IP: {dest}")
            print(f"     ├─ Protocol: {proto}")
            print(f"     └─ Packet Size: {size / 1024 / 1024:.2f} MB (Threshold: {size_threshold_bytes / 1024 / 1024} MB)\n")
        else:
            print(f"  ✅ [NORMAL]: {src} -> {dest} ({proto}) [{size} bytes]")
            
    return alerts

# Run the packet exfiltration analysis
total_alerts = detect_exfiltration(network_packets, size_threshold_bytes=1048576)

print("\n--- NETWORK FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_alerts} potential data exfiltration event(s)!")
    print(f"     └─ Action Required: Inspect source host and trace destination IP destination.")
else:
    print("  ✅ [SECURE]: All network packet volumes are within normal operational limits.")

print("==========================================")