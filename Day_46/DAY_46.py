# ==========================================
# Day 46: File Integrity Monitoring (FIM) Baseline Auditor
# Purpose: Practice endpoint security, file hashing, and unauthorized modification detection
# ==========================================

import hashlib

print("=== FILE INTEGRITY MONITORING (FIM) AUDITOR ===")

# Simulated baseline hashes established during system initialization
baseline_registry = {
    "/etc/passwd": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "C:\\Windows\\System32\\drivers\\etc\\hosts": "8f14e45fceea167a5a36dedd4bea2543",
    "/var/www/html/index.php": "5bc32896d3f23c3b012431f4ff86c738"
}

# Simulated current state of files on disk (one has been modified)
current_file_states = {
    "/etc/passwd": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Unchanged
    "C:\\Windows\\System32\\drivers\\etc\\hosts": "9a28b5e2d14c382f819074ba2d12f111", # MODIFIED!
    "/var/www/html/index.php": "5bc32896d3f23c3b012431f4ff86c738"                 # Unchanged
}

def audit_file_integrity(baseline, current_state):
    print("[*] Checking critical file hashes against established security baseline...\n")
    modifications = 0
    
    for filepath, original_hash in baseline.items():
        current_hash = current_state.get(filepath)
        
        if not current_hash:
            modifications += 1
            print(f"  🚨 [DELETION DETECTED]: File '{filepath}' is missing from disk!\n")
        elif current_hash != original_hash:
            modifications += 1
            print(f"  🚨 [TAMPERING ALERT]: File modification detected!")
            print(f"     ├─ Target File: {filepath}")
            print(f"     ├─ Original Baseline Hash: {original_hash}")
            print(f"     └─ Current Discovered Hash: {current_hash}\n")
        else:
            print(f"  ✅ [INTEGRITY VERIFIED]: '{filepath}' matches baseline.")
            
    return modifications

# Run the integrity check
total_modifications = audit_file_integrity(baseline_registry, current_file_states)

print("\n--- FIM AUDIT SUMMARY ---")
if total_modifications > 0:
    print(f"  ⚠️ [ALERT]: Detected {total_modifications} unauthorized file modification(s)!")
    print(f"     └─ Action Required: Quarantine altered files and investigate host integrity.")
else:
    print("  ✅ [SECURE]: All system files match their trusted baseline hashes.")

print("==========================================")