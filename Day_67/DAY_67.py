# ==========================================
# Day 67: Network Traffic & C2 Beacon Detector
# Purpose: Practice network forensics and detection of suspicious outbound C2 communications
# ==========================================

print("=== NETWORK TRAFFIC & C2 BEACON DETECTOR ===")

# Simulated firewall and network connection logs
network_logs = [
    {"timestamp": "2026-09-23 14:00:01", "source_ip": "192.168.1.50", "dest_ip": "142.250.190.46", "dest_port": 443, "bytes_sent": 1250},
    {"timestamp": "2026-09-23 14:05:15", "source_ip": "192.168.1.50", "dest_ip": "203.0.113.66", "dest_port": 4444, "bytes_sent": 45000},
    {"timestamp": "2026-09-23 14:10:30", "source_ip": "192.168.1.88", "dest_ip": "198.51.100.12", "dest_port": 8080, "bytes_sent": 120000},
    {"timestamp": "2026-09-23 14:15:00", "source_ip": "192.168.1.50", "dest_ip": "8.8.8.8", "dest_port": 53, "bytes_sent": 300}
]

# Known suspicious C2 ports and risky destination subnets
suspicious_ports = [4444, 1337, 8080, 6667]

def analyze_network_traffic(logs):
    print("[*] Parsing network connection logs for C2 beacon indicators and suspicious ports...\n")
    c2_alerts = 0
    
    for log in logs:
        time = log["timestamp"]
        src = log["source_ip"]
        dst = log["dest_ip"]
        port = log["dest_port"]
        bytes_transferred = log["bytes_sent"]
        
        if port in suspicious_ports:
            c2_alerts += 1
            print(f"  🚨 [C2 ALERT]: Suspicious outbound network connection detected!")
            print(f"     ├─ Timestamp: {time}")
            print(f"     ├─ Source Host: {src}")
            print(f"     ├─ Destination: {dst}:{port}")
            print(f"     └─ Payload Size: {bytes_transferred} bytes (Flagged: Non-standard C2 port)\n")
        else:
            print(f"  ✅ [NORMAL]: Connection from {src} to {dst}:{port} [{bytes_transferred} bytes]")
            
    return c2_alerts

# Run the network traffic analysis
total_alerts = analyze_network_traffic(network_logs)

print("--- NETWORK FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Found {total_alerts} suspicious network connection(s)!")
    print(f"     └─ Action Required: Isolate affected hosts and inspect packet captures (PCAPs) for exfiltration.")
else:
    print("  ✅ [SECURE]: All network connection logs verified clean.")

print("==========================================")