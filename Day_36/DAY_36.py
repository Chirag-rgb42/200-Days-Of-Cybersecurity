# ==========================================
# Day 36: Failed Login Bruteforce Detector
# Purpose: Practice log analysis and security monitoring event detection
# ==========================================

print("=== FAILED LOGIN BRUTEFORCE DETECTOR ===")

# Simulated authentication server log entries
auth_logs = [
    "2026-08-21 10:01:12 - INFO - Successful login for user 'alice' from 192.168.1.10",
    "2026-08-21 10:05:22 - WARNING - Failed login for user 'admin' from 203.0.113.50",
    "2026-08-21 10:05:30 - WARNING - Failed login for user 'admin' from 203.0.113.50",
    "2026-08-21 10:05:45 - WARNING - Failed login for user 'root' from 203.0.113.50",
    "2026-08-21 10:06:01 - WARNING - Failed login for user 'administrator' from 203.0.113.50",
    "2026-08-21 10:10:00 - INFO - Successful login for user 'bob' from 192.168.1.20"
]

def detect_bruteforce(logs, threshold=3):
    print("[*] Parsing authentication logs for brute-force patterns...\n")
    failed_attempts = {}
    
    for log in logs:
        if "Failed login" in log:
            # Extract IP address from the end of the log line
            ip_address = log.split("from")[-1].strip()
            
            # Count occurrences per IP
            failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1
            
    alerts = []
    for ip, count in failed_attempts.items():
        print(f"[*] IP {ip} recorded {count} failed login attempt(s).")
        if count >= threshold:
            alerts.append((ip, count))
            
    return alerts

# Run the detection analysis
suspicious_ips = detect_bruteforce(auth_logs, threshold=3)

print("\n--- SECURITY INCIDENT SUMMARY ---")
if suspicious_ips:
    for ip, count in suspicious_ips:
        print(f"  🚨 [ALERT]: Potential brute-force attack detected from IP: {ip} ({count} failures)!")
        print(f"     └─ Recommendation: Temporarily block IP address at the firewall.\n")
else:
    print("  ✅ [SECURE]: No brute-force patterns detected.")

print("==========================================")