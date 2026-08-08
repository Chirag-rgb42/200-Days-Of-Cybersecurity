# ==========================================
# Day 23: Security Log Parser & Brute-Force Detector
# Purpose: Practice log parsing, string matching, and threat detection
# ==========================================

from collections import defaultdict
import os

print("=== SECURITY LOG PARSER & BRUTE-FORCE DETECTOR ===")

# Create a sample log file for demonstration
log_filename = "auth_simulated.log"

def create_sample_log():
    log_data = [
        "2026-08-08 10:01:12 - SUCCESSFUL login for user admin from 192.168.1.10",
        "2026-08-08 10:05:22 - FAILED password for root from 203.0.113.45",
        "2026-08-08 10:05:25 - FAILED password for root from 203.0.113.45",
        "2026-08-08 10:05:28 - FAILED password for root from 203.0.113.45",
        "2026-08-08 10:05:31 - FAILED password for root from 203.0.113.45",
        "2026-08-08 10:10:04 - SUCCESSFUL login for user alice from 192.168.1.22"
    ]
    with open(log_filename, "w") as f:
        for line in log_data:
            f.write(line + "\n")
    print(f"[*] Created sample log file: {log_filename}")

# Function to analyze logs for failed login attempts
def analyze_logs(filepath):
    failed_attempts = defaultdict(int)
    threshold = 3 # Flag if failed attempts exceed this number

    print(f"[*] Parsing log file: {filepath}...\n")
    
    with open(filepath, "r") as f:
        for line in f:
            if "FAILED password" in line:
                # Extract the IP address (assuming it's the last element in the log line)
                parts = line.strip().split()
                ip_address = parts[-1]
                failed_attempts[ip_address] += 1

    print("--- ANALYSIS RESULTS ---")
    for ip, count in failed_attempts.items():
        print(f"  ├─ IP Address: {ip} | Failed Attempts: {count}")
        if count >= threshold:
            print(f"  └─ 🚨 [ALERT]: Brute-force pattern detected from {ip}!")

# --- Run the Script ---
create_sample_log()
analyze_logs(log_filename)

# Cleanup sample log file
if os.path.exists(log_filename):
    os.remove(log_filename)

print("==========================================")