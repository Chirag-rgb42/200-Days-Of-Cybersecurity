# ==========================================
# Day 9: Automated IP Frequency & Brute-Force Detector
# Purpose: Practice data aggregation using dictionaries
# ==========================================

print("=== BRUTE-FORCE DETECTION ENGINE ===")

# Simulated raw log file data
auth_logs = [
    "2026-07-23 09:00:10 FAILED user_admin 203.0.113.19",
    "2026-07-23 09:00:12 FAILED user_admin 203.0.113.19",
    "2026-07-23 09:00:15 FAILED user_admin 203.0.113.19",
    "2026-07-23 09:00:18 FAILED user_admin 203.0.113.19",
    "2026-07-23 09:01:05 FAILED user_root 198.51.100.4",
    "2026-07-23 09:02:11 SUCCESS user_alice 192.168.1.50",
    "2026-07-23 09:03:00 FAILED user_guest 198.51.100.4"
]

# Dictionary to store IP address failure counts
failed_ip_counts = {}
THRESHOLD = 3  # Set brute-force threshold limit

# 1. Process logs and count failures per IP
for log in auth_logs:
    fields = log.split()
    status = fields[2]
    ip_address = fields[4]
    
    if status == "FAILED":
        # Increment the count for this IP address
        if ip_address in failed_ip_counts:
            failed_ip_counts[ip_address] += 1
        else:
            failed_ip_counts[ip_address] = 1

# 2. Analyze aggregated counts and trigger alerts
print("\n--- FAILED LOGIN FREQUENCY REPORT ---")
for ip, count in failed_ip_counts.items():
    print(f"IP: {ip} | Total Failed Attempts: {count}")
    
    # Check if the IP exceeded our brute-force threshold
    if count >= THRESHOLD:
        print(f"🚨 [CRITICAL ALERT] IP {ip} exceeded threshold ({count}/{THRESHOLD} attempts)!")
        print(f"   Action: Adding {ip} to automatic Firewall Block List.\n")

print("====================================")