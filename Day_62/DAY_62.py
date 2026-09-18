# ==========================================
# Day 62: Windows Security Log Brute-Force Detector
# Purpose: Practice incident response and analysis of failed authentication events (Event ID 4625)
# ==========================================

print("=== WINDOWS SECURITY LOG BRUTE-FORCE DETECTOR ===")

# Simulated Windows Security Event Log entries (Focusing on Event ID 4625 - Failed Logon)
security_event_logs = [
    {"timestamp": "2026-09-18T08:12:01", "event_id": 4625, "target_user": "administrator", "source_ip": "192.168.1.50", "reason": "Bad Password"},
    {"timestamp": "2026-09-18T08:15:30", "event_id": 4625, "target_user": "root", "source_ip": "203.0.113.88", "reason": "Unknown User Name"},
    {"timestamp": "2026-09-18T08:15:32", "event_id": 4625, "target_user": "admin", "source_ip": "203.0.113.88", "reason": "Bad Password"},
    {"timestamp": "2026-09-18T08:15:34", "event_id": 4625, "target_user": "administrator", "source_ip": "203.0.113.88", "reason": "Bad Password"},
    {"timestamp": "2026-09-18T08:15:36", "event_id": 4625, "target_user": "sysadmin", "source_ip": "203.0.113.88", "reason": "Bad Password"},
    {"timestamp": "2026-09-18T09:00:10", "event_id": 4624, "target_user": "alice", "source_ip": "192.168.1.10", "reason": "Successful Logon"}
]

# Brute-force threshold (Number of failed attempts from a single IP to trigger an alert)
BRUTE_FORCE_THRESHOLD = 3

def detect_brute_force_attacks(logs, threshold):
    print("[*] Parsing Windows Security logs for failed authentication patterns (Event ID 4625)...\n")
    
    failed_attempts_by_ip = {}
    
    # Step 1: Aggregate failed logons by source IP
    for log in logs:
        if log.get("event_id") == 4625:
            ip = log["source_ip"]
            user = log["target_user"]
            time = log["timestamp"]
            
            if ip not in failed_attempts_by_ip:
                failed_attempts_by_ip[ip] = {"count": 0, "users_targeted": set(), "timestamps": []}
                
            failed_attempts_by_ip[ip]["count"] += 1
            failed_attempts_by_ip[ip]["users_targeted"].add(user)
            failed_attempts_by_ip[ip]["timestamps"].append(time)
            
    # Step 2: Evaluate aggregated data against the threshold
    alerts_triggered = 0
    for ip, data in failed_attempts_by_ip.items():
        count = data["count"]
        users = list(data["users_targeted"])
        
        if count >= threshold:
            alerts_triggered += 1
            print(f"  🚨 [BRUTE-FORCE ALERT]: Multiple authentication failures detected!")
            print(f"     ├─ Source IP: {ip}")
            print(f"     ├─ Total Failed Attempts: {count}")
            print(f"     ├─ Targeted Accounts: {users}")
            print(f"     └─ Status: Threshold exceeded ({count} >= {threshold}). Possible credential attack.\n")
        else:
            print(f"  ✅ [NORMAL]: IP {ip} recorded {count} failed attempt(s) (Below threshold).")
            
    return alerts_triggered

# Run the brute-force detection analysis
total_alerts = detect_brute_force_attacks(security_event_logs, BRUTE_FORCE_THRESHOLD)

print("--- SECURITY LOG AUDIT SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Flagged {total_alerts} active brute-force campaign(s)!")
    print(f"     └─ Action Required: Implement temporary IP blocking at the firewall and review account lockouts.")
else:
    print("  ✅ [SECURE]: No brute-force patterns identified in current log stream.")

print("==========================================")