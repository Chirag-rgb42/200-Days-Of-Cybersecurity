# ==========================================
# Day 39: Mini SIEM Log Aggregator & Threat Dashboard
# Purpose: Practice log correlation and unified security monitoring across multiple sources
# ==========================================

import re

print("==================================================")
print("=== MINI SIEM LOG AGGREGATOR & DASHBOARD (DAY 39) ===")
print("==================================================\n")

# Consolidated multi-source log stream
enterprise_logs = [
    '192.168.1.50 - - [24/Aug/2026:08:15:00] "GET /index.html HTTP/1.1" 200 "Mozilla/5.0"',
    '203.0.113.88 - - [24/Aug/2026:08:16:22] "GET /admin HTTP/1.1" 404 "sqlmap/1.6.5#stable"',
    '203.0.113.88 - - [24/Aug/2026:08:16:25] "GET /wp-login.php HTTP/1.1" 404 "sqlmap/1.6.5#stable"',
    '203.0.113.88 - - [24/Aug/2026:08:17:10] "POST /login HTTP/1.1" 401 "python-requests/2.28.1"',
    'AUTH_LOG: Failed login for user "admin" from 203.0.113.88 at 08:17:12',
    'AUTH_LOG: Failed login for user "root" from 203.0.113.88 at 08:17:15',
    'AUTH_LOG: Failed login for user "administrator" from 203.0.113.88 at 08:17:20'
]

def run_siem_analysis(logs):
    print("[*] Ingesting and aggregating multi-source security logs...\n")
    
    total_events = len(logs)
    failed_logins = 0
    scanning_errors = 0
    bad_bots = 0
    
    alert_ips = set()
    
    for log in logs:
        # Check for authentication failures
        if "Failed login" in log or "401" in log:
            failed_logins += 1
            
        # Check for web scanning status codes (404 / 403)
        if '" 404 ' in log or '" 403 ' in log:
            scanning_errors += 1
            
        # Check for automated tool user-agents
        if "sqlmap" in log or "python-requests" in log or "curl" in log:
            bad_bots += 1
            
        # Extract potential attacker IP (IPv4 pattern matching)
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
        if ip_match and ip_match.group() != "192.168.1.50":
            alert_ips.add(ip_match.group())

    return total_events, failed_logins, scanning_errors, bad_bots, alert_ips

# Execute SIEM analysis
events, logins, errors, bots, ips = run_siem_analysis(enterprise_logs)

print("--- CENTRALIZED SECURITY DASHBOARD ---")
print(f"  📊 Total Ingested Events : {events}")
print(f"  ❌ Failed Authentication  : {logins}")
print(f"  🌐 Web Recon/Errors (4xx) : {errors}")
print(f"  🤖 Automated Bot Hits     : {bots}")
print(f"  🚨 Flagged Source IPs     : {list(ips)}")
print("--------------------------------------------------")

if len(ips) > 0:
    print("⚠️ [SIEM STATUS]: Active threat campaign correlated from external IP(s)!")
    print("   Recommendation: Isolate source IP addresses and initiate incident response protocol.")
else:
    print("✅ [SIEM STATUS]: Environment secure. No anomalous correlations found.")

print("==================================================")