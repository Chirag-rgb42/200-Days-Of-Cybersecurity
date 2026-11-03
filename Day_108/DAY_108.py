# ==========================================
# Day 108: Automated Active Directory LAPS Misconfiguration Auditor
# Purpose: Practice enterprise AD security assessment by auditing computer object DACLs for unauthorized LAPS password read access
# ==========================================

print("=== AUTOMATED AD LAPS MISCONFIGURATION AUDITOR ===")

# Simulated Active Directory computer objects and LAPS attribute access rules
laps_audit_data = [
    {
        "computer_name": "WKSTN-FINANCE01",
        "laps_enabled": True,
        "acl_entries": [
            {"principal": "Domain Admins", "can_read_laps": True, "is_authorized": True},
            {"principal": "LAPS-Admin-Group", "can_read_laps": True, "is_authorized": True},
            {"principal": "Domain Users", "can_read_laps": False, "is_authorized": True}
        ]
    },
    {
        "computer_name": "WKSTN-EXEC02",
        "laps_enabled": True,
        "acl_entries": [
            {"principal": "Domain Admins", "can_read_laps": True, "is_authorized": True},
            {"principal": "Contractor-Helpdesk", "can_read_laps": True, "is_authorized": False}, # Vulnerable: Unauthorized group can read LAPS passwords!
            {"principal": "svc_inventory", "can_read_laps": True, "is_authorized": False}        # Vulnerable: Service account has extended read rights!
        ]
    },
    {
        "computer_name": "SRV-DEV01",
        "laps_enabled": False, # Vulnerable: LAPS not enabled on server, risking credential reuse!
        "acl_entries": []
    }
]

def audit_laps_misconfigurations(audit_data):
    print("[*] Initiating Active Directory LAPS deployment and ACL permission audit...\n")
    laps_alerts = 0
    
    for target in audit_data:
        cname = target["computer_name"]
        enabled = target["laps_enabled"]
        acls = target["acl_entries"]
        
        print(f"[-] Auditing Computer Asset: {cname}")
        print(f"    └─ LAPS Deployment Active: {enabled}")
        
        if not enabled:
            laps_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: LAPS Not Enabled!")
            print(f"     └─ Risk: Asset does not utilize automated local admin password rotation, increasing exposure to lateral movement.\n")
            continue
            
        # Check ACL entries for unauthorized LAPS password read access
        for entry in acls:
            principal = entry["principal"]
            can_read = entry["can_read_laps"]
            authorized = entry["is_authorized"]
            
            if can_read and not authorized:
                laps_alerts += 1
                print(f"  🚨 [VULNERABILITY DETECTED]: Unauthorized LAPS Read Permission!")
                print(f"     └─ Risk: Principal '{principal}' has read permissions over LAPS password attributes (`ms-MACS-AdministratorPassword`).")
                
        print()
        
    return laps_alerts

# Run the LAPS audit scan
total_vulnerabilities = audit_laps_misconfigurations(laps_audit_data)

print("--- LAPS ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} LAPS deployment / permission security risk(s)!")
    print(f"     └─ Action Required: Revoke extended read rights on LAPS attributes for unauthorized groups and enforce LAPS policies domain-wide.")
else:
    print("  ✅ [SECURE]: All computer assets passed LAPS deployment and permission checks.")

print("==========================================")