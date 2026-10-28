# ==========================================
# Day 102: Automated Active Directory AS-REP Roasting Auditor
# Purpose: Practice enterprise AD security assessment by detecting user accounts with Kerberos pre-authentication disabled
# ==========================================

print("=== AUTOMATED AD AS-REP ROASTING AUDITOR ===")

# Simulated Active Directory domain user accounts and pre-authentication flags
ad_user_accounts = [
    {
        "username": "jdoe",
        "display_name": "John Doe",
        "pre_auth_required": True,
        "account_control_flags": "NORMAL_ACCOUNT"
    },
    {
        "username": "legacy_service_acct",
        "display_name": "Legacy App Service",
        "pre_auth_required": False,  # Vulnerable: Kerberos pre-authentication disabled!
        "account_control_flags": "DONT_REQ_PREAUTH"
    },
    {
        "username": "asmith",
        "display_name": "Alice Smith",
        "pre_auth_required": True,
        "account_control_flags": "NORMAL_ACCOUNT"
    },
    {
        "username": "batch_runner",
        "display_name": "Nightly Batch Job",
        "pre_auth_required": False,  # Vulnerable: Missing pre-auth flag!
        "account_control_flags": "DONT_REQ_PREAUTH"
    }
]

def audit_as_rep_roasting(accounts):
    print("[*] Initiating Active Directory AS-REP Roasting security audit...\n")
    asrep_alerts = 0
    
    for user in accounts:
        uname = user["username"]
        name = user["display_name"]
        pre_auth = user["pre_auth_required"]
        flags = user["account_control_flags"]
        
        print(f"[-] Auditing User Account: {uname} ({name})")
        print(f"    ├─ Pre-Authentication Required: {pre_auth}")
        print(f"    └─ User Account Control Flags: {flags}")
        
        # Check if pre-authentication is disabled
        if not pre_auth:
            asrep_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: AS-REP Roasting Flaw!")
            print(f"     └─ Risk: Account has Kerberos pre-authentication disabled ({flags}), allowing unauthenticated ticket requests and offline cracking.\n")
        else:
            print(f"  ✅ [SECURE]: Kerberos pre-authentication is strictly enforced.\n")
            
    return asrep_alerts

# Run the AS-REP roasting vulnerability audit
total_vulnerabilities = audit_as_rep_roasting(ad_user_accounts)

print("--- AS-REP ROASTING ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} user account(s) vulnerable to AS-REP Roasting!")
    print(f"     └─ Action Required: Enable Kerberos pre-authentication (`DONT_REQ_PREAUTH` removal) on all service and user accounts.")
else:
    print("  ✅ [SECURE]: All user accounts passed Kerberos pre-authentication verification.")

print("==========================================")