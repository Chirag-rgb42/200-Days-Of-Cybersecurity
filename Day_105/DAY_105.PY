# ==========================================
# Day 105: Automated Active Directory Resource-Based Constrained Delegation (RBCD) Auditor
# Purpose: Practice enterprise AD security assessment by detecting dangerous computer object permissions and RBCD misconfigurations
# ==========================================

print("=== AUTOMATED AD RBCD VULNERABILITY AUDITOR ===")

# Simulated Active Directory computer objects and access control permissions
rbcd_audit_objects = [
    {
        "target_computer": "SQLSRV01.corp.local",
        "owner": "IT-Admins",
        "has_write_permissions": False, # Secure: Standard ACL permissions
        "rbcd_configured": False
    },
    {
        "target_computer": "WORKSTATION-LAB",
        "owner": "Helpdesk-Users",
        "has_write_permissions": True,  # Vulnerable: Low-privileged group has GenericAll/Write over computer object!
        "rbcd_configured": True         # Vulnerable: Attackers can map arbitrary accounts to impersonate users
    },
    {
        "target_computer": "FILESVR01.corp.local",
        "owner": "Domain Admins",
        "has_write_permissions": False,
        "rbcd_configured": False
    }
]

def audit_rbcd_vulnerabilities(objects):
    print("[*] Initiating Active Directory Resource-Based Constrained Delegation (RBCD) audit...\n")
    rbcd_alerts = 0
    
    for obj in objects:
        target = obj["target_computer"]
        owner = obj["owner"]
        write_perms = obj["has_write_permissions"]
        rbcd = obj["rbcd_configured"]
        
        print(f"[-] Auditing Computer Object: {target}")
        print(f"    ├─ Object Owner: {owner}")
        print(f"    ├─ Dangerous Write Permissions (GenericAll/WriteDacl): {write_perms}")
        print(f"    └─ RBCD Attribute (msDS-AllowedToActOnBehalfOfOtherIdentity): {rbcd}")
        
        # Check if computer object is vulnerable to RBCD abuse
        if write_perms or rbcd:
            rbcd_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Resource-Based Constrained Delegation Risk!")
            print(f"     └─ Risk: Object has insecure write permissions or active RBCD configuration, allowing unauthorized service ticket mapping and privilege escalation.\n")
        else:
            print(f"  ✅ [SECURE]: Computer object access controls and delegation settings are hardened.\n")
            
    return rbcd_alerts

# Run the RBCD audit scan
total_vulnerabilities = audit_rbcd_vulnerabilities(rbcd_audit_objects)

print("--- RBCD ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} computer object(s) vulnerable to RBCD abuse!")
    print(f"     └─ Action Required: Restrict object control permissions (remove GenericAll/Write privileges from non-admin users) and audit RBCD attributes.")
else:
    print("  ✅ [SECURE]: All computer objects passed RBCD security verification.")

print("==========================================")