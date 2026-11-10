# ==========================================
# Day 115: Automated Active Directory GPO Permissions & Abuse Auditor
# Purpose: Practice enterprise AD security assessment by detecting dangerous write permissions over Group Policy Objects
# ==========================================

print("=== AUTOMATED AD GPO PERMISSIONS AUDITOR ===")

# Simulated Active Directory GPOs, linked OUs, and delegated permissions
gpo_audit_data = [
    {
        "gpo_name": "Default Domain Policy",
        "linked_target": "corp.local (Domain Root)",
        "delegated_principal": "Domain Admins",
        "permission": "Full Control",
        "is_authorized": True
    },
    {
        "gpo_name": "DC Hardening Baseline",
        "linked_target": "OU=Domain Controllers,DC=corp,DC=local",
        "delegated_principal": "svc_helpdesk_automation", # Vulnerable: Service account has write rights on DC GPO!
        "permission": "GenericWrite",
        "is_authorized": False
    },
    {
        "gpo_name": "Workstation Security Settings",
        "linked_target": "OU=Workstations,DC=corp,DC=local",
        "delegated_principal": "Desktop-Support-Team",
        "permission": "WriteProperty",
        "is_authorized": False # Vulnerable: Non-Tier 0 team holds write perms on widespread GPO
    },
    {
        "gpo_name": "Finance App Deployment",
        "linked_target": "OU=Finance,DC=corp,DC=local",
        "delegated_principal": "Domain Admins",
        "permission": "Full Control",
        "is_authorized": True
    }
]

def audit_gpo_permissions(policies):
    print("[*] Initiating Active Directory Group Policy Object (GPO) ACL audit...\n")
    gpo_alerts = 0
    
    for gpo in policies:
        gname = gpo["gpo_name"]
        target = gpo["linked_target"]
        principal = gpo["delegated_principal"]
        perm = gpo["permission"]
        auth = gpo["is_authorized"]
        
        print(f"[-] Auditing GPO: {gname}")
        print(f"    ├─ Linked Scope: {target}")
        print(f"    ├─ Delegated Principal: {principal}")
        print(f"    └─ Granted Permission: {perm}")
        
        # Check if non-authorized accounts hold write rights over GPOs
        if not auth and ("Write" in perm or "Full" in perm):
            gpo_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Insecure GPO Delegation Flagged!")
            print(f"     └─ Risk: Non-authorized principal '{principal}' has '{perm}' rights. Attackers compromising this account can inject malicious scripts/scheduled tasks across '{target}'.\n")
        else:
            print(f"  ✅ [SECURE]: GPO delegation rights are restricted to authorized administrators.\n")
            
    return gpo_alerts

# Run the GPO security audit
total_vulnerabilities = audit_gpo_permissions(gpo_audit_data)

print("--- GPO SECURITY ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} GPO delegation misconfiguration(s)!")
    print(f"     └─ Action Required: Revoke write permissions (GenericAll/WriteDacl/WriteProperty) for non-admin accounts across GPO containers and enforce strict Tiered Administration.")
else:
    print("  ✅ [SECURE]: All GPO permissions passed Active Directory delegation verification.")

print("==========================================")