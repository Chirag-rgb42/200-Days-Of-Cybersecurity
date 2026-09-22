# ==========================================
# Day 66: Windows Scheduled Tasks Persistence Analyzer
# Purpose: Practice digital forensics and detection of malicious task scheduler persistence
# ==========================================

print("=== WINDOWS SCHEDULED TASKS PERSISTENCE ANALYZER ===")

# Simulated Windows Scheduled Tasks inventory extracted from a compromised system
scheduled_tasks = [
    {
        "task_name": "MicrosoftEdgeUpdateTaskMachineCore",
        "author": "System",
        "trigger": "Startup",
        "action_path": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"
    },
    {
        "task_name": "SystemHealthCheck",
        "author": "Admin",
        "trigger": "Daily",
        "action_path": "C:\\Users\\Public\\AppData\\Local\\Temp\\update_service.exe" # Suspicious path!
    },
    {
        "task_name": "Adobe Acrobat Update Task",
        "author": "System",
        "trigger": "Weekly",
        "action_path": "C:\\Program Files\\Adobe\\Acrobat\\Acrobat\\AdobeUpdate.exe"
    },
    {
        "task_name": "NetworkSyncHelper",
        "author": "User",
        "trigger": "Logon",
        "action_path": "C:\\Users\\Admin\\Downloads\\backdoor_script.bat" # Suspicious path!
    }
]

# Indicators of suspicious file paths commonly used by malware for task persistence
suspicious_path_indicators = ["\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\"]

def audit_scheduled_tasks(tasks):
    print("[*] Parsing scheduled task definitions and auditing action paths for persistence anomalies...\n")
    persistence_alerts = 0
    
    for task in tasks:
        name = task["task_name"]
        author = task["author"]
        trigger = task["trigger"]
        path = task["action_path"]
        path_lower = path.lower()
        
        # Check if the execution path points to user downloads, temp folders, or public directories
        is_suspicious = any(indicator in path_lower for indicator in suspicious_path_indicators)
        
        if is_suspicious:
            persistence_alerts += 1
            print(f"  🚨 [PERSISTENCE ALERT]: Suspicious scheduled task detected!")
            print(f"     ├─ Task Name: {name}")
            print(f"     ├─ Author/Creator: {author}")
            print(f"     ├─ Trigger Event: {trigger}")
            print(f"     └─ Action Path: {path} (Flagged: Executing from non-standard location)\n")
        else:
            print(f"  ✅ [LEGITIMATE]: Task '{name}' -> {path}")
            
    return persistence_alerts

# Run the scheduled tasks persistence analysis
total_alerts = audit_scheduled_tasks(scheduled_tasks)

print("--- SCHEDULED TASKS FORENSICS SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Found {total_alerts} malicious scheduled task persistence mechanism(s)!")
    print(f"     └─ Action Required: Unregister unauthorized scheduled tasks and quarantine associated binaries.")
else:
    print("  ✅ [SECURE]: All scheduled task action paths conform to standard system baselines.")

print("==========================================")