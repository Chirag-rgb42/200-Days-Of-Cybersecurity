# ==========================================
# Day 48: DNS Tunneling & Anomaly Detector
# Purpose: Practice network forensics and identification of covert DNS data exfiltration
# ==========================================

print("=== DNS TUNNELING & ANOMALY DETECTOR ===")

# Simulated DNS query logs (Timestamp, Source IP, Queried Domain Name, Query Type)
dns_logs = [
    {"time": "15:00:01", "src": "192.168.1.50", "domain": "www.google.com", "type": "A"},
    {"time": "15:01:12", "src": "192.168.1.50", "domain": "api.github.com", "type": "HTTPS"},
    {"time": "15:05:40", "src": "192.168.1.100", "domain": "aHR0cHM6Ly9zZWNyZXQuZmlsZS5jb20vY29udGVudA==.malicious-tunnel.com", "type": "TXT"},
    {"time": "15:05:42", "src": "192.168.1.100", "domain": "ZXhlY3V0ZV9wYXlsb2FkX3JlbW90ZWx5MTIzNDU2Nzg5.malicious-tunnel.com", "type": "TXT"},
    {"time": "15:10:00", "src": "192.168.1.20", "domain": "updates.microsoft.com", "type": "A"}
]

def detect_dns_tunneling(logs, length_threshold=40):
    print("[*] Parsing DNS query logs for abnormal subdomain lengths and tunneling patterns...\n")
    alerts = 0
    
    for log in logs:
        src = log["src"]
        domain = log["domain"]
        q_type = log["type"]
        
        # Check total domain string length as a primary tunneling indicator
        if len(domain) > length_threshold:
            alerts += 1
            print(f"  🚨 [DNS TUNNELING ALERT]: Suspicious long DNS query detected!")
            print(f"     ├─ Source IP: {src}")
            print(f"     ├─ Queried Domain: {domain}")
            print(f"     ├─ Query Type: {q_type}")
            print(f"     └─ Domain Length: {len(domain)} characters (Threshold: {length_threshold})\n")
        else:
            print(f"  ✅ [NORMAL]: {src} queried '{domain}' [{q_type}]")
            
    return alerts

# Run the DNS tunneling analysis
total_alerts = detect_dns_tunneling(dns_logs, length_threshold=40)

print("\n--- NETWORK FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_alerts} potential DNS tunneling event(s)!")
    print(f"     └─ Action Required: Block suspicious base domain and isolate host.")
else:
    print("  ✅ [SECURE]: All DNS queries adhere to standard length and format baselines.")

print("==========================================")