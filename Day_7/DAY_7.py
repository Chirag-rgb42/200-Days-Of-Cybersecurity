# ==========================================
# Day 7: Log File Analyzer & Suspicious Activity Detector
# Purpose: Practice File I/O and text parsing
# ==========================================

print("=== AUTOMATED AUTHENTICATION LOG AUDITOR ===")

log_filename = "/home/chirag-suthar/server_auth.log"
failed_attempts = 0
successful_logins = 0

# 1. Open and read the log file safely
try:
    with open(log_filename, "r") as file:
        logs = file.readlines()

    # 2. Iterate through each line in the log file
    for line in logs:
        clean_line = line.strip()
        
        # Check for keywords inside each log entry
        if "FAILED" in clean_line:
            failed_attempts += 1
            print(f"🚨 Suspicious Entry Detected: {clean_line}")
        elif "SUCCESS" in clean_line:
            successful_logins += 1

    # 3. Output summary report
    print("\n--- AUDIT SUMMARY REPORT ---")
    print(f"Total Log Entries Analyzed: {len(logs)}")
    print(f"✅ Successful Logins: {successful_logins}")
    print(f"⚠️ Failed Login Attempts: {failed_attempts}")

    if failed_attempts >= 3:
        print("\n🚨 ALERT: High volume of failed logins detected! Possible brute-force activity.")

except FileNotFoundError:
    print(f"❌ Error: Could not find the file '{log_filename}'. Please verify file location.")

print("============================================")