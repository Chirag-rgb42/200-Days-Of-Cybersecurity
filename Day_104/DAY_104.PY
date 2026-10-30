# ==========================================
# Day 104: Automated Active Directory Constrained Delegation Auditor
# Purpose: Practice enterprise AD security assessment by detecting risky constrained delegation targets and S4U abuse paths
# ==========================================

print("=== AUTOMATED AD CONSTRAINED DELEGATION AUDITOR ===")

# Simulated Active Directory accounts with constrained delegation rules
constrained_delegation_objects = [
    {
        "account_name": "svc_web_app",
        "service_type": "IIS Web Service",
        "allowed_targets": [
            "HTTP/appserver01.corp.local",
            "HTTP/appserver02.corp.local"
        ],
        "is_risky_target": False # Secure: Restricted to standard HTTP services
    },
    {
        "account_name": "svc_print_spooler",
        "service_type": "Print Spooler Service",
        "allowed_targets": [
            "cifs/dc01.corp.local",
            "ldap/dc01.corp.local"
        ],
        "is_risky_target": True # Vulnerable: Allowed to delegate to DC CIFS/LDAP (Domain Escalation Vector!)
    },
    {
        "account_name": "svc_app_sync",
        "service_type": "Database Sync Utility",
        "allowed_targets": [
            "MSSQLSvc/sql01.corp.local:1433"
        ],
        "is_risky_target": False
    }
]

def audit_constrained_delegation(objects):
    print("[*] Initiating Active Directory Constrained Delegation security audit...\n")
    delegation_alerts = 0
    
    for obj in objects:
        name = obj["account_name"]
        stype = obj["service_type"]
        targets = obj["allowed_targets"]
        risky = obj["is_risky_target"]
        
        print(f"[-] Auditing Service Account: {name} ({stype})")
        print(f"    └─ Allowed Delegation Targets (msDS-AllowedToDelegateTo): {targets}")
        
        # Check if targets include high-privilege domain controller services
        if risky or any("dc01.corp.local" in target.lower() for target in targets):
            delegation_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Risky Constrained Delegation Path!")
            print(f"     └─ Risk: Account can delegate user impersonation to high-privilege Domain Controller services, enabling potential S4U abuse and domain escalation.\n")
        else:
            print(f"  ✅ [SECURE]: Constrained delegation targets are restricted to non-critical application services.\n")
            
    return delegation_alerts

# Run the constrained delegation audit scan
total_vulnerabilities = audit_constrained_delegation(constrained_delegation_objects)

print("--- CONSTRAINED DELEGATION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} account(s) with risky constrained delegation targets!")
    print(f"     └─ Action Required: Review `msDS-AllowedToDelegateTo` privileges, remove unnecessary delegation to Domain Controllers, and audit service account hygiene.")
else:
    print("  ✅ [SECURE]: All constrained delegation configurations passed security verification.")

print("==========================================")