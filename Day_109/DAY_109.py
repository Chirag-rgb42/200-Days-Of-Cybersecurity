# ==========================================
# Day 108: Automated Active Directory GPO Security & DACL Auditor
# Purpose: Practice enterprise AD security assessment by auditing Group Policy Object permissions for unauthorized write access
# ==========================================

print("=== AUTOMATED AD GPO SECURITY AUDITOR ===")

# Simulated Active Directory Group Policy Objects and delegation ACL rules
gpo_audit_data = [
    {
        "gpo_name": "Default Domain Policy",
        "linked_ou": "Domain Root",
        "acl_entries": [
            {"principal": "Domain Admins", "permission": "Edit Settings", "is_authorized": True},
            {"principal": "SYSTEM", "permission": "Full Control", "is_authorized": True},
            {"principal": "Domain Users", "permission": "Read", "is_authorized": True}
        ]
    },
    {
        "gpo_name": "Workstation Hardening Policy",
        "linked_ou": "OU=Workstations,DC=corp,DC=local",
        "acl_entries": [
            {"principal": "Domain Admins", "permission": "Edit Settings", "is_authorized": True},
            {"principal": "Helpdesk-Level1", "permission": "Edit Settings", "is_authorized": False}, # Vulnerable: Low-privilege group can edit GPO!
            {"principal": "svc_deploy", "permission": "WriteDacl", "is_authorized": False}           # Vulnerable: Service account can hijack GPO ACL!
        ]
    },
    {
        "gpo_name": "Domain Controller Audit Policy",
        "linked_ou": "OU=Domain Controllers,DC=corp,DC=local",
        "acl_entries": [
            {"principal": "Domain Admins", "permission": "Full Control", "is_authorized": True},
            {"principal": "Enterprise Admins", "permission": "Full Control", "is_authorized": True}
        ]
    }
]

def audit_gpo_permissions(audit_data):
    print("[*] Initiating Active Directory Group Policy Object (GPO) permission audit...\n")
    gpo_alerts = 0
    
    for gpo in audit_data:
        gname = gpo["gpo_name"]
        ou = gpo["linked_ou"]
        acls = gpo["acl_entries"]
        
        print(f"[-] Auditing Policy: {gname}")
        print(f"    ├─ Linked Organizational Unit: {ou}")
        print(f"    └─ Evaluating ACL Delegations...")
        
        # Check ACL entries for unauthorized edit or write permissions
        for entry in acls:
            principal = entry["principal"]
            perm = entry["permission"]
            authorized = entry["is_authorized"]
            
            if perm in ["Edit Settings", "WriteDacl", "Full Control"] and not authorized:
                gpo_alerts += 1
                print(f"  🚨 [VULNERABILITY DETECTED]: Unauthorized GPO Edit Permission!")
                print(f"     └─ Risk: Principal '{principal}' has '{perm}' on '{gname}'. Compromise allows domain-wide policy tampering and arbitrary code execution.")
                
        print()
        
    return gpo_alerts

# Run the GPO audit scan
total_vulnerabilities = audit_gpo_permissions(gpo_audit_data)

print("--- GPO ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} GPO delegation security risk(s)!")
    print(f"     └─ Action Required: Revoke write and edit permissions on GPOs for non-administrative accounts and enforce strict DACL governance.")
else:
    print("  ✅ [SECURE]: All Group Policy Objects passed permission delegation verification.")

print("==========================================")