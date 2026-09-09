# ==========================================
# Day 53: Azure Storage Key & Secret Leak Auditor
# Purpose: Practice cloud security and detection of hardcoded cloud access credentials
# ==========================================

import re

print("=== AZURE STORAGE KEY & SECRET LEAK AUDITOR ===")

# Simulated configuration and code files found in a repository
codebase_files = [
    {
        "file_path": "config/production.json",
        "content": '{\n  "StorageAccount": "myproductionstorage",\n  "ContainerName": "uploads"\n}'
    },
    {
        "file_path": "scripts/deploy_app.py",
        "content": 'AZURE_STORAGE_KEY = "DefaultEndpointsProtocol=https;AccountName=myprod;AccountKey=Sp3ci4lK3yH3r3F0rT3st1ng==;EndpointSuffix=core.windows.net"\n'
    },
    {
        "file_path": "app/settings.py",
        "content": 'DATABASE_URL = "sqlite:///app.db"\nDEBUG = False\n'
    }
]

# Regular expression pattern to detect Azure storage connection strings / account keys
azure_key_pattern = r"AccountKey=[A-Za-z0-9+/=]{20,}"

def audit_codebase_for_secrets(files):
    print("[*] Scanning codebase files for exposed cloud credentials...\n")
    leaks_found = 0
    
    for file_obj in files:
        path = file_obj["file_path"]
        content = file_obj["content"]
        
        if re.search(azure_key_pattern, content):
            leaks_found += 1
            print(f"  🚨 [SECRET LEAK]: Exposed Azure credential found!")
            print(f"     ├─ Target File: {path}")
            print(f"     └─ Status: Hardcoded secret detected in source code.\n")
        else:
            print(f"  ✅ [CLEAN]: '{path}' contains no hardcoded cloud secrets.")
            
    return leaks_found

# Run the secret leak audit
total_leaks = audit_codebase_for_secrets(codebase_files)

print("\n--- CLOUD SECRET AUDIT SUMMARY ---")
if total_leaks > 0:
    print(f"  ⚠️ [ALERT]: Found {total_leaks} exposed cloud credential(s) in codebase!")
    print(f"     └─ Action Required: Rotate leaked keys immediately and purge from git history.")
else:
    print("  ✅ [SECURE]: No hardcoded cloud keys discovered.")

print("==========================================")