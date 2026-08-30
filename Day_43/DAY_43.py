# ==========================================
# Day 43: Startup Persistence Mechanism Auditor
# Purpose: Practice endpoint security and detection of unauthorized persistence entries
# ==========================================

print("=== STARTUP PERSISTENCE MECHANISM AUDITOR ===")

# Simulated registry and startup persistence entries found on an endpoint
system_persistence_entries = [
    {"location": "Registry Run Key", "name": "WindowsDefenderUpdate", "path": "C:\\Users\\Public\\update.exe"},
    {"location": "Registry Run Key", "name": "OneDrive", "path": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"},
    {"location": "Scheduled Task", "name": "GoogleUpdateTaskMachineUA", "path": "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe"},
    {"location": "Startup Folder", "name": "BackdoorScript", "path": "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\nc.exe"}
]

# Known legitimate applications often found in startup locations
whitelisted_paths = [
    "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe"
]

def audit_persistence(entries, whitelist):
    print("[*] Auditing endpoint startup persistence locations...\n")
    unauthorized_count = 0
    
    for entry in entries:
        location = entry["location"]
        name = entry["name"]
        path = entry["path"]
        
        # Check if the persistence binary is whitelisted
        if path in whitelist:
            print(f"  ✅ [AUTHORIZED]: {location} -> '{name}' ({path})")
        else:
            unauthorized_count += 1
            print(f"  🚨 [SUSPICIOUS PERSISTENCE]: Unauthorized entry found!")
            print(f"     ├─ Vector: {location}")
            print(f"     ├─ Entry Name: {name}")
            print(f"     └─ Target Path: {path}\n")
            
    return unauthorized_count

# Run the persistence audit
total_unauthorized = audit_persistence(system_persistence_entries, whitelisted_paths)

print("--- ENDPOINT AUDIT SUMMARY ---")
if total_unauthorized > 0:
    print(f"  ⚠️ [ALERT]: Found {total_unauthorized} suspicious persistence mechanism(s)!")
    print(f"     └─ Action Required: Investigate unauthorized startup binaries immediately.")
else:
    print("  ✅ [SECURE]: All startup persistence entries are verified and authorized.")

print("==========================================")