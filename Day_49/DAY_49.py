# ==========================================
# Day 49: TCP SYN Flood & DoS Detector
# Purpose: Practice network forensics and detection of volumetric denial-of-service traffic
# ==========================================

print("=== TCP SYN FLOOD & DOS DETECTOR ===")

# Simulated network packet logs (Timestamp, Source IP, Destination IP, TCP Flag)
packet_logs = [
    {"time": "16:00:01", "src": "192.168.1.50", "dest": "10.0.0.10", "flag": "SYN"},
    {"time": "16:00:02", "src": "203.0.113.77", "dest": "10.0.0.10", "flag": "SYN"},
    {"time": "16:00:02", "src": "203.0.113.77", "dest": "10.0.0.10", "flag": "SYN"},
    {"time": "16:00:03", "src": "203.0.113.77", "dest": "10.0.0.10", "flag": "SYN"},
    {"time": "16:00:03", "src": "203.0.113.77", "dest": "10.0.0.10", "flag": "SYN"},
    {"time": "16:00:04", "src": "203.0.113.77", "dest": "10.0.0.10", "flag": "SYN"},
    {"time": "16:00:05", "src": "192.168.1.20", "dest": "10.0.0.10", "flag": "ACK"}
]

def detect_syn_flood(logs, syn_threshold=3):
    print("[*] Analyzing network packet stream for TCP SYN flood patterns...\n")
    syn_counts = {}
    
    for pkt in logs:
        if pkt["flag"] == "SYN":
            src = pkt["src"]
            syn_counts[src] = syn_counts.get(src, 0) + 1
            
    alerts = []
    for ip, count in syn_counts.items():
        print(f"[*] IP {ip} sent {count} TCP SYN packet(s).")
        if count >= syn_threshold:
            alerts.append((ip, count))
            
    return alerts

# Run the SYN flood analysis
suspicious_attackers = detect_syn_flood(packet_logs, syn_threshold=3)

print("\n--- NETWORK INCIDENT SUMMARY ---")
if suspicious_attackers:
    for ip, count in suspicious_attackers:
        print(f"  🚨 [DoS ALERT]: Potential TCP SYN Flood detected from IP: {ip} ({count} SYN packets)!")
        print(f"     └─ Action Required: Apply rate limiting or drop traffic from source IP.\n")
else:
    print("  ✅ [SECURE]: No volumetric SYN flood anomalies detected.")

print("==========================================")