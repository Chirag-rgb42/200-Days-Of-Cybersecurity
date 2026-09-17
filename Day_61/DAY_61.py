# ==========================================
# Day 61: Rapid Host Triage & Volatile Data Collection Script
# Purpose: Practice incident response (IR) and automated collection of volatile system telemetry
# ==========================================

import datetime

print("=== RAPID HOST TRIAGE & DFIR COLLECTOR ===")

# Simulated live host volatile telemetry (Running processes, network connections, and users)
system_telemetry = {
    "hostname": "workstation-alpha-09",
    "timestamp": str(datetime.datetime.now()),
    "running_processes": [
        {"pid": 412, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
        {"pid": 1337, "name": "suspicious_payload.exe", "path": "C:\\Users\\Public\\suspicious_payload.exe"},
        {"pid": 2048, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"}
    ],
    "active_connections": [
        {"local_ip": "192.168.1.50", "remote_ip": "203.0.113.99", "port": 4444, "state": "ESTABLISHED"},
        {"local_ip": "192.168.1.50", "remote_ip": "10.0.0.1", "port": 443, "state": "ESTABLISHED"}
    ],
    "logged_in_users": ["admin_alice", "service_account"]
}

# Known malicious process names or indicators of compromise for triage
suspicious_indicators = ["suspicious_payload.exe", "mimikatz.exe", "nc.exe"]

def perform_host_triage(telemetry):
    print(f"[*] Initiating rapid host triage on '{telemetry['hostname']}' at {telemetry['timestamp']}...\n")
    
    triage_alerts = 0
    
    print("--- 1. ACTIVE USERS ---")
    for user in telemetry["logged_in_users"]:
        print(f"  👤 Logged-in User: {user}")
        
    print("\n--- 2. RUNNING PROCESSES (Scanning for Anomalies) ---")
    for proc in telemetry["running_processes"]:
        pname = proc["name"]
        pid = proc["pid"]
        path = proc["path"]
        
        if pname in suspicious_indicators:
            triage_alerts += 1
            print(f"  🚨 [TRIAGE ALERT]: Malicious process name detected!")
            print(f"     ├─ PID: {pid}")
            print(f"     ├─ Process Name: {pname}")
            print(f"     └─ Path: {path}")
        else:
            print(f"  ✅ [NORMAL]: Process '{pname}' (PID: {pid})")
            
    print("\n--- 3. ACTIVE NETWORK CONNECTIONS ---")
    for conn in telemetry["active_connections"]:
        rip = conn["remote_ip"]
        port = conn["port"]
        state = conn["state"]
        
        if port == 4444 or rip.startswith("203.0.113"):
            triage_alerts += 1
            print(f"  🚨 [TRIAGE ALERT]: Suspicious outbound network connection!")
            print(f"     ├─ Remote Destination: {rip}:{port}")
            print(f"     └─ Connection State: {state}")
        else:
            print(f"  ✅ [NORMAL CONNECTION]: Connected to {rip}:{port} [{state}]")
            
    return triage_alerts

# Run the host triage collection
total_alerts = perform_host_triage(system_telemetry)

print("\n--- TRIAGE SUMMARY REPORT ---")
if total_alerts > 0:
    print(f"  ⚠️ [INCIDENT DETECTED]: Found {total_alerts} high-risk anomaly indicator(s) during host triage!")
    print(f"     └─ Action Required: Immediately isolate host from network and preserve volatile RAM dump.")
else:
    print("  ✅ [CLEAN]: Host telemetry shows no active indicators of compromise.")

print("==========================================")