# ==========================================
# Day 111: Automated Active Directory Protected Users Group Auditor
# Purpose: Practice enterprise AD security assessment by verifying Protected Users group enrollment and LSASS hardening rules
# ==========================================

print("=== AUTOMATED AD PROTECTED USERS GROUP AUDITOR ===")

# Simulated Active Directory administrative and service user accounts
ad_privileged_accounts = [
    {
        "username": "da_admin_sec",
        "role": "Domain Admin",
        "in_protected_users_group": True,
        "ntlm_allowed": False,
        "allow_credential_caching": False
    },
    {
        "username": "da_legacy_admin",
        "role": "Domain Admin",
        "in_protected_users_group": False, # Vulnerable: Domain Admin missing from Protected Users group!
        "ntlm_allowed": True,              # Vulnerable: NTLM authentication still permitted!
        "allow_credential_caching": True  # Vulnerable: Passwords/hashes cached locally for LSASS dumping!
    },
    {
        "username": "ea_global_lead",
        "role": "Enterprise Admin",
        "in_protected_users_group": True,
        "ntlm_allowed": False,
        "allow_credential_caching": False
    },
    {
        "username": "svc_ad_sync",
        "role": "Directory Sync Service",
        "in_protected_users_group": False, # Alert: Sensitive service account not enrolled
        "ntlm_allowed": True,
        "allow_credential_caching": True
    }
]

def audit_protected_users(accounts):
    print("[*] Initiating Active Directory Protected Users Group audit...\n")
    protection_alerts = 0
    
    for account in accounts:
        uname = account["username"]
        role = account["role"]
        is_protected = account["in_protected_users_group"]
        ntlm = account["ntlm_allowed"]
        caching = account["allow_credential_caching"]
        
        print(f"[-] Auditing Account: {uname} ({role})")
        print(f"    ├─ Enrolled in 'Protected Users' Group: {is_protected}")
        print(f"    ├─ NTLM Authentication Allowed: {ntlm}")
        print(f"    └─ Local Credential Caching Allowed: {caching}")
        
        # Check if high-privilege administrative accounts are missing Protected Users safeguards
        if ("Admin" in role) and not is_protected:
            protection_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Tier 0 Account Missing Protected Users Controls!")
            print(f"     └─ Risk: High-privilege account is not enrolled in 'Protected Users', leaving it exposed to NTLM relay attacks and LSASS credential dumping.\n")
        elif not is_protected:
            print(f"  ⚠️ [WARNING]: Non-enrolled privileged account. Verify if service workflow requires NTLM.\n")
        else:
            print(f"  ✅ [SECURE]: Account properly enrolled with NTLM disabled and credential caching suppressed.\n")
            
    return protection_alerts

# Run the audit scan
total_vulnerabilities = audit_protected_users(ad_privileged_accounts)

print("--- PROTECTED USERS ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} privileged account(s) missing from Protected Users group!")
    print(f"     └─ Action Required: Add all Tier 0 administrative accounts to `CN=Protected Users,CN=Users,DC=...`, disable NTLM fallback, and enable LSA Protection (RunAsPPL).")
else:
    print("  ✅ [SECURE]: All administrative accounts verified inside Protected Users group.")

print("==========================================")