# ==========================================
# Day 58: Threat Intelligence & IOC Feed Matcher
# Purpose: Practice threat intelligence analysis and correlation of malicious indicators against logs
# ==========================================

print("=== THREAT INTELLIGENCE IOC FEED MATCHER ===")

# Simulated Threat Intelligence Feed (Known malicious IPs and domains)
threat_intelligence_feed = {
    "malicious_ips": ["198.51.100.99", "203.0.113.55", "185.199.108.153"],
    "malicious_domains": ["evil-command-center.com", "malware-drop-site.net"]
}

# Simulated internal server access logs
access_logs = [
    {"timestamp": "12:00:01", "client_ip": "192.168.1.50", "requested_domain": "api.github.com", "status": 200},
    {"timestamp": "12:05:14", "client_ip": "198.51.100.99", "requested_domain": "legitimate-site.org", "status": 200},
    {"timestamp": "12:12:30", "client_ip": "10.0.0.15", "requested_domain": "evil-command-center.com", "status": 403},
    {"timestamp": "12:20:45", "client_ip": "192.168.1.88", "requested_domain": "updates.microsoft.com", "status": 200}
]

def scan_logs_with_threat_intel(logs, feed):
    print("[*] Correlating access logs against global threat intelligence feed...\n")
    matches_found = 0
    
    for log in logs:
        timestamp = log["timestamp"]
        client_ip = log["client_ip"]
        domain = log["requested_domain"]
        status = log["status"]
        
        is_bad_ip = client_ip in feed["malicious_ips"]
        is_bad_domain = domain in feed["malicious_domains"]
        
        if is_bad_ip or is_bad_domain:
            matches_found += 1
            print(f"  🚨 [THREAT MATCH DETECTED]: Malicious indicator found in access logs!")
            print(f"     ├─ Timestamp: {timestamp}")
            print(f"     ├─ Client IP: {client_ip} {'(KNOWN THREAT IP)' if is_bad_ip else ''}")
            print(f"     ├─ Requested Domain: {domain} {'(KNOWN THREAT DOMAIN)' if is_bad_domain else ''}")
            print(f"     └─ HTTP Status: {status}\n")
        else:
            print(f"  ✅ [CLEAN]: {client_ip} -> {domain} [{status}]")
            
    return matches_found

# Run the threat intelligence match
total_matches = scan_logs_with_threat_intel(access_logs, threat_intelligence_feed)

print("\n--- THREAT INTEL AUDIT SUMMARY ---")
if total_matches > 0:
    print(f"  ⚠️ [ALERT]: Detected {total_matches} active connection(s) involving known malicious indicators!")
    print(f"     └─ Action Required: Isolate affected client IPs and block threat domains at the firewall.")
else:
    print("  ✅ [SECURE]: No malicious indicators matched current access logs.")

print("==========================================")