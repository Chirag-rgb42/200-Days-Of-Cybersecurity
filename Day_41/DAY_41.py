# ==========================================
# Day 41: Malware Signature & String Matcher
# Purpose: Practice endpoint security and simulated YARA-style malware pattern matching
# ==========================================

import re

print("=== MALWARE SIGNATURE & STRING MATCHER ===")

# Simulated malware signatures / rule strings (similar to YARA rule conditions)
malware_rules = {
    "Trojan.Generic.Agent": [r"eval\(base64_decode", r"cmd\.exe\s+/c"],
    "Ransomware.LockBit": [r"Your files have been encrypted", r"\.onion\.to"],
    "Spyware.Keylogger": [r"pynput\.keyboard", r"log_keystrokes"]
}

def scan_file_content(file_path, content):
    print(f"[*] Scanning file '{file_path}' for malware signatures...")
    matches_found = []
    
    for malware_name, signatures in malware_rules.items():
        for sig in signatures:
            if re.search(sig, content, re.IGNORECASE):
                matches_found.append((malware_name, sig))
                
    return matches_found

# Simulated file contents to scan (e.g., suspicious script vs clean file)
suspicious_file_sample = """
import os
import sys
# Simulating a suspicious payload snippet
payload = "eval(base64_decode('aW1wb3J0IG9z...'))"
os.system("cmd.exe /c whoami")
"""

clean_file_sample = """
# Standard application configuration file
app_name = "SecureApp"
version = "1.0.0"
print("Application running smoothly.")
"""

test_files = [
    {"path": "/tmp/suspicious_script.py", "content": suspicious_file_sample},
    {"path": "/var/www/html/config.py", "content": clean_file_sample}
]

print("\n--- RUNNING ENDPOINT SECURITY SCAN ---")
for file_obj in test_files:
    results = scan_file_content(file_obj["path"], file_obj["content"])
    if results:
        print(f"  🚨 [MALWARE ALERT]: File flagged as malicious!")
        for mw_name, sig in results:
            print(f"     ├─ Family: {mw_name}")
            print(f"     └─ Matched Signature: '{sig}'\n")
    else:
        print(f"  ✅ [CLEAN]: '{file_obj['path']}' passed all signature checks.\n")

print("==========================================")