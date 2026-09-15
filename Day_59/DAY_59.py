# ==========================================
# Day 59: File Hash (SHA-256) Malware Threat Hunter
# Purpose: Practice threat intelligence analysis and hunting for malicious file signatures on endpoints
# ==========================================

print("=== FILE HASH MALWARE THREAT HUNTER ===")

# Known malicious SHA-256 file hashes from threat intelligence feeds
threat_intel_hashes = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "47329d4791a8da5e1b4f4c9c670b8fbc394a8f93e9818817a3f4e3c1b67b1b34",
    "b891a271e8478783df82b757b494d6e9f193f2f8274a169b128522f128e461a2"
]

# Simulated endpoint file system inventory (File paths and their computed SHA-256 hashes)
endpoint_file_inventory = [
    {"path": "C:\\Windows\\System32\\notepad.exe", "hash": "5bc32896d3f23c3b012431f4ff86c738"},
    {"path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\update_patch.exe", "hash": "47329d4791a8da5e1b4f4c9c670b8fbc394a8f93e9818817a3f4e3c1b67b1b34"},
    {"path": "C:\\Program Files\\App\\service.dll", "hash": "8f14e45fceea167a5a36dedd4bea2543"},
    {"path": "C:\\Users\\Admin\\Downloads\\document.pdf", "hash": "111222333444555666777888999000aa"}
]

def hunt_malicious_hashes(inventory, malicious_hashes):
    print("[*] Scanning endpoint file system inventory against threat intelligence hash blacklists...\n")
    threats_detected = 0
    
    for file_obj in inventory:
        path = file_obj["path"]
        file_hash = file_obj["hash"]
        
        if file_hash in malicious_hashes:
            threats_detected += 1
            print(f"  🚨 [MALWARE THREAT DETECTED]: Known malicious file hash matched!")
            print(f"     ├─ Target Path: {path}")
            print(f"     └─ SHA-256 Hash: {file_hash}\n")
        else:
            print(f"  ✅ [CLEAN]: '{path}' verified safe.")
            
    return threats_detected

# Run the hash threat hunt
total_threats = hunt_malicious_hashes(endpoint_file_inventory, threat_intel_hashes)

print("\n--- THREAT HUNT SUMMARY ---")
if total_threats > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_threats} malicious file(s) on endpoint inventory!")
    print(f"     └─ Action Required: Immediately quarantine infected files and initiate host containment.")
else:
    print("  ✅ [SECURE]: All endpoint file hashes verified clean against threat feed.")

print("==========================================")