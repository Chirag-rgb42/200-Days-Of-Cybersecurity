# ==========================================
# Day 63: Windows Registry Persistence Analyzer
# Purpose: Practice digital forensics and detection of malicious startup persistence via registry run keys
# ==========================================

print("=== WINDOWS REGISTRY PERSISTENCE ANALYZER ===")

# Simulated Windows Registry Run Key entries exported from a compromised system
registry_hive_data = [
    {
        "hive": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "SecurityHealth",
        "binary_path": "C:\\Windows\\System32\\SecurityHealthSystray.exe"
    },
    {
        "hive": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "UpdaterService",
        "binary_path": "C:\\Users\\Public\\AppData\\Local\\Temp\\updater.exe" # Suspicious path!
    },
    {
        "hive": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "value_name": "OneDriveSetup",
        "binary_path": "C:\\Program Files\\Microsoft OneDrive\\OneDriveSetup.exe"
    },
    {
        "hive": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "SysHelper",
        "binary_path": "C:\\Users\\Admin\\Downloads\\payload_backdoor.exe" # Suspicious path!
    }
]

# Indicators of suspicious file paths commonly used by malware for persistence
suspicious_path_indicators = ["\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\"]

def audit_registry_persistence(entries):
    print("[*] Parsing registry run keys and auditing startup binaries for persistence anomalies...\n")
    persistence_alerts = 0
    
    for entry in entries:
        hive = entry["hive"]
        name = entry["value_name"]
        path = entry["binary_path"]
        path_lower = path.lower()
        
        # Check if binary path points to user downloads, temp folders, or public directories
        is_suspicious = any(indicator in path_lower for indicator in suspicious_path_indicators)
        
        if is_suspicious:
            persistence_alerts += 1
            print(f"  🚨 [PERSISTENCE ALERT]: Suspicious startup entry detected!")
            print(f"     ├─ Registry Hive: {hive}")
            print(f"     ├─ Value Name: {name}")
            print(f"     └─ Binary Path: {path} (Flagged: Executing from non-standard location)\n")
        else:
            print(f"  ✅ [LEGITIMATE]: '{name}' -> {path}")
            
    return persistence_alerts

# Run the registry persistence analysis
total_alerts = audit_registry_persistence(registry_hive_data)

print("--- REGISTRY FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Found {total_alerts} malicious registry persistence mechanism(s)!")
    print(f"     └─ Action Required: Remove unauthorized registry keys and isolate associated persistence binaries.")
else:
    print("  ✅ [SECURE]: All registry startup entries conform to standard system paths.")

print("==========================================")