# ==========================================
# Day 45: Endpoint Outbound C2 Connection Monitor
# Purpose: Practice endpoint telemetry analysis and detection of suspicious network connections
# ==========================================

print("=== ENDPOINT OUTBOUND C2 CONNECTION MONITOR ===")

# Simulated endpoint network connection logs (Process NetworkConnect telemetry)
network_events = [
    {"process": "chrome.exe", "dest_ip": "142.250.190.46", "port": 443, "protocol": "HTTPS"},
    {"process": "update_service.exe", "dest_ip": "198.51.100.99", "port": 8080, "protocol": "HTTP"},
    {"process": "svchost.exe", "dest_ip": "203.0.113.50", "port": 4444, "protocol": "TCP"},
    {"process": "explorer.exe", "dest_ip": "10.0.0.5", "port": 53, "protocol": "DNS"}
]

# Known suspicious or malicious external C2 indicators
suspicious_indicators = {
    "ips": ["198.51.100.99", "203.0.113.50"],
    "ports": [4444, 1337, 31337] # Common backdoor/meterpreter ports
}

def audit_network_connections(events, indicators):
    print("[*] Auditing active endpoint network connection logs for C2 activity...\n")
    alerts = 0
    
    for event in events:
        process = event["process"]
        dest_ip = event["dest_ip"]
        port = event["port"]
        protocol = event["protocol"]
        
        is_suspicious_ip = dest_ip in indicators["ips"]
        is_suspicious_port = port in indicators["ports"]
        
        if is_suspicious_ip or is_suspicious_port:
            alerts += 1
            print(f"  🚨 [C2 ALERT]: Suspicious network connection detected!")
            print(f"     ├─ Source Process: {process}")
            print(f"     ├─ Destination IP: {dest_ip}")
            print(f"     ├─ Destination Port: {port} ({protocol})")
            print(f"     └─ Reason: {'Matched Known Threat IP' if is_suspicious_ip else 'Matched Suspicious Port'}\n")
        else:
            print(f"  ✅ [NORMAL]: Process '{process}' -> {dest_ip}:{port} ({protocol})")
            
    return alerts

# Run the network connection audit
total_alerts = audit_network_connections(network_events, suspicious_indicators)

print("\n--- ENDPOINT NETWORK AUDIT SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_alerts} suspicious outbound connection(s)!")
    print(f"     └─ Action Required: Isolate host network interface and inspect associated process.")
else:
    print("  ✅ [SECURE]: All active endpoint network connections appear normal.")

print("==========================================")