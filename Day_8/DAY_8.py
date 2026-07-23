# ==========================================
# Day 8: Log Field Extractor & IP Parser
# Purpose: Practice string splitting and index extraction
# ==========================================

print("=== LOG FIELD PARSER & THREAT ANALYZER ===")

# Simulated authentication log entries
raw_logs = [
    "2026-07-22 14:00:12 SUCCESS user_alice 192.168.1.50",
    "2026-07-22 14:02:45 FAILED user_root 203.0.113.19",
    "2026-07-22 14:03:01 FAILED user_root 203.0.113.19",
    "2026-07-22 14:05:10 SUCCESS user_bob 192.168.1.51",
    "2026-07-22 14:08:22 FAILED user_admin 198.51.100.77"
]

suspicious_ips = []

# Iterate through logs and parse individual fields
for entry in raw_logs:
    # Split the line into a list of words based on whitespace
    fields = entry.split()
    
    timestamp = f"{fields[0]} {fields[1]}"
    status = fields[2]
    username = fields[3]
    ip_address = fields[4]
    
    # Flag failed events and capture offending IP addresses
    if status == "FAILED":
        print(f"⚠️ [ALERT] Failed login detected!")
        print(f"   ├─ Timestamp: {timestamp}")
        print(f"   ├─ Target Account: {username}")
        print(f"   └─ Source IP: {ip_address}\n")
        
        suspicious_ips.append(ip_address)

print("--- PARSING SUMMARY ---")
print(f"Total entries processed: {len(raw_logs)}")
print(f"Flagged suspicious IPs for firewall review: {suspicious_ips}")
print("==========================================")