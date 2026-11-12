# ==========================================
# Day 117: Automated Active Directory LAPS Compliance Auditor
# Purpose: Practice enterprise AD security assessment by verifying Windows LAPS deployment, password rotation, and attribute read permissions
# ==========================================

print("=== AUTOMATED AD LAPS COMPLIANCE AUDITOR ===")

# Simulated Active Directory computer objects and LAPS configuration status
laps_audit_endpoints = [
    {
        "hostname": "HR-WORKSTATION01",
        "laps_enabled": True,
        "password_age_days": 14,
        "max_allowed_age_days": 30,
        "unauthorized_readers": [] # Secure: Only authorized Tier-1 admins can read LAPS password
    },
    {
        "hostname": "IT-SUPPORT-PC09",
        "laps_enabled": False,     # Vulnerable: LAPS not deployed (shared local admin password risk!)
        "password_age_days": 410,
        "max_allowed_age_days": 30,
        "unauthorized_readers": []
    },
    {
        "hostname": "SALES-LAPTOP12",
        "laps_enabled": True,
        "password_age_days": 85,   # Vulnerable: LAPS password rotation overdue!
        "max_allowed_age_days": 30,
        "unauthorized_readers": ["All-Authenticated-Users"] # Vulnerable: Misconfigured read ACL on LAPS attribute!
    },
    {
        "hostname": "APP-SERVER03",
        "laps_enabled": True,
        "password_age_days": 7,
        "max_allowed_age_days": 30,
        "unauthorized_readers": []
    }
]

def audit_laps_compliance(endpoints):
    print("[*] Initiating Active Directory Windows LAPS compliance audit...\n")
    laps_alerts = 0
    
    for host in endpoints:
        hname = host["hostname"]
        enabled = host["laps_enabled"]
        age = host["password_age_days"]
        max_age = host["max_allowed_age_days"]
        bad_readers = host["unauthorized_readers"]
        
        print(f"[-] Auditing Endpoint: {hname}")
        print(f"    ├─ LAPS Active & Managing Password: {enabled}")
        print(f"    ├─ Current Password Age: {age} days (Max: {max_age} days)")
        print(f"    └─ Unauthorized LAPS Attribute Readers: {bad_readers if bad_readers else 'None'}")
        
        # Check for LAPS gaps, overdue rotation, or excessive read permissions
        is_expired = age > max_age
        has_bad_acl = len(bad_readers) > 0
        
        if not enabled or is_expired or has_bad_acl:
            laps_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: LAPS Compliance Failure!")
            if not enabled:
                print(f"     └─ Risk: LAPS is disabled; endpoint is exposed to shared local admin Pass-the-Hash lateral movement.")
            if is_expired:
                print(f"     └─ Risk: Local admin password rotation is overdue ({age} days > {max_age} days).")
            if has_bad_acl:
                print(f"     └─ Risk: Unauthorized principals ({', '.join(bad_readers)}) can read the LAPS password attribute in AD.")
            print()
        else:
            print(f"  ✅ [SECURE]: LAPS is active, password is fresh, and attribute ACLs are restricted.\n")
            
    return laps_alerts

# Run the LAPS compliance audit
total_vulnerabilities = audit_laps_compliance(laps_audit_endpoints)

print("--- LAPS COMPLIANCE ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) with LAPS deployment or ACL issues!")
    print(f"     └─ Action Required: Enforce Windows LAPS GPO across all OUs, trigger immediate password resets on overdue hosts, and restrict read permissions on `msLAPS-Password`.")
else:
    print("  ✅ [SECURE]: All audited endpoints passed LAPS deployment and ACL compliance checks.")

print("==========================================")