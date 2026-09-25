# ==========================================
# Day 69: Automated Incident Response Containment Playbook
# Purpose: Practice automated incident response, host containment, and remediation workflows
# ==========================================

import datetime

print("=== AUTOMATED INCIDENT RESPONSE CONTAINMENT PLAYBOOK ===")

# Simulated active incident context detected by SOC monitoring
active_incident = {
    "incident_id": "INC-2026-8842",
    "detected_at": str(datetime.datetime.now()),
    "compromised_host": "workstation-alpha-09",
    "threat_process": "suspicious_payload.exe",
    "process_pid": 1337,
    "compromised_user": "contractor_bob",
    "malicious_ip": "203.0.113.99"
}

def execute_containment_playbook(incident):
    print(f"[*] INITIATING AUTOMATED CONTAINMENT PLAYBOOK FOR {incident['incident_id']}...\n")
    
    actions_taken = 0
    
    # Step 1: Terminate Malicious Process
    print(f"[-] Action 1: Terminating malicious process '{incident['threat_process']}' (PID: {incident['process_pid']})...")
    print(f"    ✅ SUCCESS: Process PID {incident['process_pid']} terminated successfully.")
    actions_taken += 1
    
    # Step 2: Isolate Host Network Interface
    print(f"\n[-] Action 2: Isolating host '{incident['compromised_host']}' from enterprise network...")
    print(f"    ✅ SUCCESS: Network interface for {incident['compromised_host']} placed in software quarantine (Blocked all traffic except DFIR management).")
    actions_taken += 1
    
    # Step 3: Disable Compromised User Account
    print(f"\n[-] Action 3: Disabling compromised user account '{incident['compromised_user']}' and revoking active sessions...")
    print(f"    ✅ SUCCESS: Account '{incident['compromised_user']}' locked out in Active Directory. All OAuth tokens revoked.")
    actions_taken += 1
    
    # Step 4: Block Malicious C2 IP at Firewall
    print(f"\n[-] Action 4: Adding malicious C2 IP '{incident['malicious_ip']}' to perimeter firewall blocklist...")
    print(f"    ✅ SUCCESS: Rule added to drop all ingress/egress traffic to {incident['malicious_ip']}.")
    actions_taken += 1
    
    return actions_taken

# Execute the containment playbook
total_actions = execute_containment_playbook(active_incident)

print("\n--- CONTAINMENT PLAYBOOK SUMMARY REPORT ---")
print(f"  🛡️ Incident ID       : {active_incident['incident_id']}")
print(f"  🎯 Host Affected     : {active_incident['compromised_host']}")
print(f"  ⚡ Actions Executed  : {total_actions} automated containment steps completed.")
print(f"  🏁 Status            : THREAT CONTAINED. Handing over to forensic analysis team.")
print("==========================================")