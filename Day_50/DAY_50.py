# ==========================================
# Day 50: All-in-One Network Forensics & Traffic Auditor (Milestone 2 Capstone)
# Purpose: Consolidate network packet analysis, exfiltration checks, DNS tunneling, and SYN flood detection
# ==========================================

print("==================================================")
print("=== ALL-IN-ONE NETWORK FORENSICS AUDITOR (DAY 50) ===")
print("==================================================\n")

# Simulated enterprise network traffic stream (Mixed packets, DNS queries, and TCP flags)
network_stream = [
    {"type": "packet", "time": "17:00:01", "src": "192.168.1.50", "dest": "10.0.0.1", "protocol": "HTTPS", "size": 1024, "flag": "ACK"},
    {"type": "dns", "time": "17:02:15", "src": "192.168.1.100", "domain": "aHR0cHM6Ly9zZWNyZXQuZmlsZS5jb20vY29udGVudA==.malicious-tunnel.com", "q_type": "TXT"},
    {"type": "packet", "time": "17:05:30", "src": "192.168.1.100", "dest": "203.0.113.99", "protocol": "HTTPS", "size": 5242880, "flag": "ACK"}, # 5 MB Exfiltration
    {"type": "packet", "time": "17:10:00", "src": "203.0.113.77", "dest": "10.0.0.10", "protocol": "TCP", "size": 64, "flag": "SYN"},
    {"type": "packet", "time": "17:10:01", "src": "203.0.113.77", "dest": "10.0.0.10", "protocol": "TCP", "size": 64, "flag": "SYN"},
    {"type": "packet", "time": "17:10:02", "src": "203.0.113.77", "dest": "10.0.0.10", "protocol": "TCP", "size": 64, "flag": "SYN"}
]

def run_network_audit(stream):
    print("[*] Ingesting network telemetry stream and executing forensic checks...\n")
    
    exfil_alerts = 0
    dns_alerts = 0
    syn_counts = {}
    
    for item in stream:
        if item.get("type") == "packet":
            src = item["src"]
            size = item["size"]
            flag = item["flag"]
            
            # Check for data exfiltration (> 1 MB)
            if size > 1048576:
                exfil_alerts += 1
                print(f"  🚨 [EXFILTRATION]: Large outbound transfer from {src} ({size / 1024 / 1024:.2f} MB)")
                
            # Track SYN packets for DoS detection
            if flag == "SYN":
                syn_counts[src] = syn_counts.get(src, 0) + 1
                
        elif item.get("type") == "dns":
            src = item["src"]
            domain = item["domain"]
            
            # Check for DNS tunneling (Subdomain length > 40)
            if len(domain) > 40:
                dns_alerts += 1
                print(f"  🚨 [DNS TUNNEL]: Long covert query from {src} -> {domain[:30]}...")

    # Evaluate SYN Flood counts
    dos_alerts = 0
    for ip, count in syn_counts.items():
        if count >= 3:
            dos_alerts += 1
            print(f"  🚨 [SYN FLOOD]: Volumetric DoS pattern detected from IP {ip} ({count} SYN packets)")

    return exfil_alerts, dns_alerts, dos_alerts

# Execute the comprehensive network audit
exfil_total, dns_total, dos_total = run_network_audit(network_stream)
total_incidents = exfil_total + dns_total + dos_total

print("\n--- NETWORK FORENSICS CAPSTONE SUMMARY ---")
print(f"  📊 Total Data Exfiltration Flags : {exfil_total}")
print(f"  🌐 Total DNS Tunneling Anomalies : {dns_total}")
print(f"  ⚡ Total SYN Flood DoS Alerts    : {dos_total}")
print("--------------------------------------------------")

if total_incidents > 0:
    print(f"⚠️ [AUDIT RESULT]: {total_incidents} critical network security anomaly(ies) detected!")
    print(f"   Recommendation: Initiate immediate incident response and quarantine flagged endpoints.")
else:
    print("✅ [AUDIT RESULT]: Network traffic is clean. No anomalies or threats detected.")

print("==================================================")