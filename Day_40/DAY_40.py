# ==========================================
# Day 40: IOC Hash & IP Reputation Scanner
# Purpose: Practice threat intelligence matching and Indicator of Compromise (IOC) detection
# ==========================================

print("=== IOC HASH & IP REPUTATION SCANNER ===")

# Simulated Threat Intelligence Feed (Known Malicious IOCs)
threat_intel_feed = {
    "ips": ["198.51.100.99", "203.0.113.50"],
    "file_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "5bc32896d3f23c3b012431f4ff86c738"]
}

# Simulated internal system artifacts to scan (IPs and file hashes observed on network/hosts)
system_artifacts = [
    {"type": "ip", "value": "192.168.1.10", "source": "Internal Workstation"},
    {"type": "ip", "value": "203.0.113.50", "source": "External Gateway Connection"},
    {"type": "hash", "value": "5bc32896d3f23c3b012431f4ff86c738", "source": "Downloaded Binary (/tmp/update.bin)"},
    {"type": "hash", "value": "a1b2c3d4e5f67890123456789abcdef0", "source": "System Application (/bin/ls)"}
]

def scan_artifacts(artifacts, feed):
    print("[*] Scanning system artifacts against active Threat Intelligence feed...\n")
    matches = 0
    
    for item in artifacts:
        artifact_type = item["type"]
        value = item["value"]
        source = item["source"]
        
        if artifact_type == "ip" and value in feed["ips"]:
            matches += 1
            print(f"  🚨 [MALICIOUS IP MATCH]: Found threat IP '{value}'")
            print(f"     └─ Source Context: {source}\n")
        elif artifact_type == "hash" and value in feed["file_hashes"]:
            matches += 1
            print(f"  🚨 [MALICIOUS HASH MATCH]: Found known malware hash '{value}'")
            print(f"     └─ Source Context: {source}\n")
        else:
            print(f"  ✅ [CLEAN]: {artifact_type.upper()} '{value}' ({source}) is clean.\n")
            
    return matches

# Run the threat intelligence scan
total_matches = scan_artifacts(system_artifacts, threat_intel_feed)

print("--- THREAT INTEL SCAN SUMMARY ---")
if total_matches > 0:
    print(f"  ⚠️ [ALERT]: Threat Intelligence engine flagged {total_matches} malicious indicator(s)!")
    print(f"     └─ Action Required: Isolate affected hosts and initiate containment procedures.")
else:
    print("  ✅ [SECURE]: No matching indicators of compromise found.")

print("==========================================")