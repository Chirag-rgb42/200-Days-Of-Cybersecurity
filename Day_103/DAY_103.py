# ==========================================
# Day 103: Automated Active Directory Unconstrained Delegation Auditor
# Purpose: Practice enterprise AD security assessment by detecting computer and user objects configured with unconstrained delegation
# ==========================================

print("=== AUTOMATED AD UNCONSTRAINED DELEGATION AUDITOR ===")

# Simulated Active Directory domain objects and delegation properties
ad_domain_objects = [
    {
        "object_name": "DC01.corp.local",
        "object_type": "Domain Controller",
        "unconstrained_delegation": True,  # Standard and expected for Domain Controllers
        "is_dc": True
    },
    {
        "object_name": "WEBSRV01.corp.local",
        "object_type": "Computer (Member Server)",
        "unconstrained_delegation": True,  # Vulnerable: Member server with unconstrained delegation!
        "is_dc": False
    },
    {
        "object_name": "FILESRV02.corp.local",
        "object_type": "Computer (Member Server)",
        "unconstrained_delegation": False, # Secure: Uses constrained delegation or none
        "is_dc": False
    },
    {
        "object_name": "sql_service_acct",
        "object_type": "User Account",
        "unconstrained_delegation": True,  # Vulnerable: Service account trusting delegation!
        "is_dc": False
    }
]

def audit_unconstrained_delegation(objects):
    print("[*] Initiating Active Directory Unconstrained Delegation security audit...\n")
    delegation_alerts = 0
    
    for obj in objects:
        name = obj["object_name"]
        otype = obj["object_type"]
        unconstrained = obj["unconstrained_delegation"]
        is_dc = obj["is_dc"]
        
        print(f"[-] Auditing Directory Object: {name} ({otype})")
        print(f"    ├─ Unconstrained Delegation Enabled: {unconstrained}")
        print(f"    └─ Is Domain Controller: {is_dc}")
        
        # Check for risky unconstrained delegation (Allowed on DCs, but critical risk on member servers/accounts)
        if unconstrained and not is_dc:
            delegation_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Unconstrained Delegation Risk!")
            print(f"     └─ Risk: Non-DC object is configured with unconstrained delegation, allowing TGT caching and potential domain takeover if compromised.\n")
        elif unconstrained and is_dc:
            print(f"  ℹ️ [INFO]: Domain Controllers require delegation functionality by design (Ensure hardening controls are active).\n")
        else:
            print(f"  ✅ [SECURE]: Object does not utilize unconstrained delegation.\n")
            
    return delegation_alerts

# Run the delegation vulnerability audit
total_vulnerabilities = audit_unconstrained_delegation(ad_domain_objects)

print("--- UNCONSTRAINED DELEGATION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} high-risk object(s) with unconstrained delegation!")
    print(f"     └─ Action Required: Disable unconstrained delegation on member servers, implement Constrained Delegation or Resource-Based Constrained Delegation (RBCD).")
else:
    print("  ✅ [SECURE]: No unauthorized unconstrained delegation configurations detected.")

print("==========================================")