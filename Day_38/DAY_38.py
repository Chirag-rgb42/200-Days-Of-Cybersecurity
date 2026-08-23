# ==========================================
# Day 38: Suspicious User-Agent & Bot Log Analyzer
# Purpose: Practice log analysis and identification of automated scanning tools via User-Agent strings
# ==========================================

import re

print("=== SUSPICIOUS USER-AGENT LOG ANALYZER ===")

# Simulated web access logs including User-Agent strings at the end
access_logs = [
    '192.168.1.10 - - [23/Aug/2026:14:00:01] "GET /index.html HTTP/1.1" 200 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '203.0.113.45 - - [23/Aug/2026:14:01:15] "GET /admin HTTP/1.1" 403 "python-requests/2.28.1"',
    '198.51.100.22 - - [23/Aug/2026:14:02:30] "GET /login.php HTTP/1.1" 200 "Mozilla/5.0 (Macintosh; Intel Mac OS X)"',
    '203.0.113.45 - - [23/Aug/2026:14:02:32] "GET /config.json HTTP/1.1" 404 "sqlmap/1.6.5#stable"',
    '198.51.100.99 - - [23/Aug/2026:14:03:00] "GET /robots.txt HTTP/1.1" 200 "curl/7.68.0"'
]

# Signatures for known automated scanners, scripting libraries, and tools
suspicious_ua_patterns = [
    r"python-requests",
    r"sqlmap",
    r"curl",
    r"nikto",
    r"nmap",
    r"gobuster"
]

def analyze_user_agents(logs):
    print("[*] Parsing web logs for suspicious User-Agent signatures...\n")
    findings = []
    
    for log in logs:
        # Extract IP and User-Agent string from log line
        parts = log.split('"')
        if len(parts) >= 4:
            ip = parts[0].strip().split()[0]
            user_agent = parts[3]
            
            # Check against known tool signatures
            for pattern in suspicious_ua_patterns:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    findings.append((ip, user_agent, pattern))
                    
    return findings

# Run the user-agent analysis
suspicious_traffic = analyze_user_agents(access_logs)

print("\n--- SECURITY INCIDENT SUMMARY ---")
if suspicious_traffic:
    for ip, ua, pattern in suspicious_traffic:
        print(f"  🚨 [ALERT]: Suspicious automated tool signature detected!")
        print(f"     ├─ Source IP: {ip}")
        print(f"     ├─ Matched Tool Pattern: '{pattern}'")
        print(f"     └─ Full User-Agent: '{ua}'\n")
else:
    print("  ✅ [SECURE]: No suspicious user-agent signatures found.")

print("==========================================")