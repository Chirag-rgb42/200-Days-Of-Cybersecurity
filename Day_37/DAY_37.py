# ==========================================
# Day 37: Web Server Access Log Anomaly Detector
# Purpose: Practice web log analysis and detection of scanning activity via HTTP status codes
# ==========================================

print("=== WEB SERVER ACCESS LOG ANOMALY DETECTOR ===")

# Simulated web server access logs (Common Log Format / custom format)
access_logs = [
    '192.168.1.50 - - [22/Aug/2026:12:00:10] "GET /index.html HTTP/1.1" 200 1024',
    '192.168.1.50 - - [22/Aug/2026:12:00:12] "GET /about.html HTTP/1.1" 200 512',
    '203.0.113.88 - - [22/Aug/2026:12:01:00] "GET /admin HTTP/1.1" 404 196',
    '203.0.113.88 - - [22/Aug/2026:12:01:01] "GET /wp-login.php HTTP/1.1" 404 196',
    '203.0.113.88 - - [22/Aug/2026:12:01:02] "GET /config.bak HTTP/1.1" 403 210',
    '203.0.113.88 - - [22/Aug/2026:12:01:03] "GET /.env HTTP/1.1" 404 196',
    '192.168.1.100 - - [22/Aug/2026:12:02:15] "GET /contact.html HTTP/1.1" 200 800'
]

def detect_scanning_activity(logs, error_threshold=3):
    print("[*] Parsing web access logs for error spikes and scanning patterns...\n")
    error_counts = {}
    
    for log in logs:
        parts = log.split()
        ip = parts[0]
        status_code = parts[-2]
        
        # Track 4xx (Client Error / Not Found / Forbidden) responses
        if status_code.startswith("4"):
            error_counts[ip] = error_counts.get(ip, 0) + 1
            
    alerts = []
    for ip, count in error_counts.items():
        print(f"[*] IP {ip} generated {count} client error response(s) (4xx).")
        if count >= error_threshold:
            alerts.append((ip, count))
            
    return alerts

# Run the anomaly detection analysis
suspicious_scanners = detect_scanning_activity(access_logs, error_threshold=3)

print("\n--- SECURITY INCIDENT SUMMARY ---")
if suspicious_scanners:
    for ip, count in suspicious_scanners:
        print(f"  🚨 [ALERT]: Potential reconnaissance/scanning detected from IP: {ip} ({count} error responses)!")
        print(f"     └─ Recommendation: Review request paths and consider rate-limiting or blocking IP.\n")
else:
    print("  ✅ [SECURE]: No unusual web scanning anomalies detected.")

print("==========================================")