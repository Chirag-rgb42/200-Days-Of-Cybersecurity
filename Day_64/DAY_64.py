# ==========================================
# Day 64: Browser History & Artifact Forensic Parser
# Purpose: Practice digital forensics by parsing web browser download logs for malicious URLs
# ==========================================

print("=== BROWSER HISTORY ARTIFACT FORENSIC PARSER ===")

# Simulated browser history/download records extracted from a user profile database
browser_downloads = [
    {
        "timestamp": "2026-09-20 10:14:22",
        "user": "admin_alice",
        "url": "https://github.com/downloads/tool.zip",
        "file_name": "tool.zip",
        "danger_type": "SAFE"
    },
    {
        "timestamp": "2026-09-20 11:05:10",
        "user": "contractor_bob",
        "url": "http://malicious-payload-drop.net/payload.exe",
        "file_name": "payload.exe",
        "danger_type": "DANGEROUS"
    },
    {
        "timestamp": "2026-09-20 11:45:00",
        "user": "admin_alice",
        "url": "https://update.microsoft.com/patch",
        "file_name": "patch",
        "danger_type": "SAFE"
    },
    {
        "timestamp": "2026-09-20 12:30:15",
        "user": "contractor_bob",
        "url": "http://evil-command-center.com/backdoor.msi",
        "file_name": "backdoor.msi",
        "danger_type": "DANGEROUS"
    }
]

def parse_browser_artifacts(downloads):
    print("[*] Parsing browser history and download records for forensic indicators...\n")
    forensic_alerts = 0
    
    for record in downloads:
        time = record["timestamp"]
        user = record["user"]
        url = record["url"]
        filename = record["file_name"]
        danger = record["danger_type"]
        
        if danger == "DANGEROUS":
            forensic_alerts += 1
            print(f"  🚨 [FORENSIC ALERT]: Malicious file download identified!")
            print(f"     ├─ Timestamp: {time}")
            print(f"     ├─ User Profile: {user}")
            print(f"     ├─ File Name: {filename}")
            print(f"     └─ Source URL: {url}\n")
        else:
            print(f"  ✅ [CLEAN]: User '{user}' downloaded safe file '{filename}' from {url}")
            
    return forensic_alerts

# Run the browser artifact analysis
total_alerts = parse_browser_artifacts(browser_downloads)

print("--- BROWSER FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Flagged {total_alerts} malicious download artifact(s)!")
    print(f"     └─ Action Required: Trace user activity session and inspect execution logs for downloaded binaries.")
else:
    print("  ✅ [SECURE]: All browser history download records verified safe.")

print("==========================================")