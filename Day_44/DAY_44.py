# ==========================================
# Day 44: Suspicious DLL Module Loading Auditor
# Purpose: Practice endpoint security telemetry and detection of unauthorized DLL loads
# ==========================================

print("=== SUSPICIOUS DLL MODULE LOADING AUDITOR ===")

# Simulated process module load events (ImageLoad telemetry)
module_load_events = [
    {"process": "explorer.exe", "dll_name": "ntdll.dll", "path": "C:\\Windows\\System32\\ntdll.dll"},
    {"process": "explorer.exe", "dll_name": "kernel32.dll", "path": "C:\\Windows\\System32\\kernel32.dll"},
    {"process": "svchost.exe", "dll_name": "version.dll", "path": "C:\\Users\\Public\\version.dll"},
    {"process": "notepad.exe", "dll_name": "custom_hook.dll", "path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\custom_hook.dll"}
]

# Trusted system directories for authorized DLL execution
trusted_directories = [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\"
]

def audit_module_loads(events, trusted_dirs):
    print("[*] Auditing endpoint process module load events...\n")
    anomalies = 0
    
    for event in events:
        process = event["process"]
        dll_name = event["dll_name"]
        path = event["path"]
        
        # Check if the DLL path starts with any trusted directory
        is_trusted = any(path.startswith(td) for td in trusted_dirs)
        
        if is_trusted:
            print(f"  ✅ [TRUSTED]: Process '{process}' loaded '{dll_name}' from secure path.")
        else:
            anomalies += 1
            print(f"  🚨 [ANOMALY DETECTED]: Suspicious or untrusted module load!")
            print(f"     ├─ Target Process: {process}")
            print(f"     ├─ Loaded DLL: {dll_name}")
            print(f"     └─ Untrusted Path: {path}\n")
            
    return anomalies

# Run the module load audit
total_anomalies = audit_module_loads(module_load_events, trusted_directories)

print("--- ENDPOINT MODULE AUDIT SUMMARY ---")
if total_anomalies > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_anomalies} untrusted module load event(s)!")
    print(f"     └─ Action Required: Investigate potential DLL injection or sideloading.")
else:
    print("  ✅ [SECURE]: All loaded modules originate from trusted system directories.")

print("==========================================")