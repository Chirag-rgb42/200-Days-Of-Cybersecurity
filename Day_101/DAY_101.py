# ==========================================
# Day 101: Automated Active Directory Kerberoasting & Service Account Auditor
# Purpose: Practice enterprise AD security assessment by detecting vulnerable SPNs and weak encryption types
# ==========================================

print("=== AUTOMATED AD KERBEROASTING & SERVICE AUDITOR ===")

# Simulated Active Directory service accounts and principal configurations
ad_service_accounts = [
    {
        "account_name": "svc_sql_prod",
        "spn": "MSSQLSvc/sqlserver01.corp.local:1433",
        "encryption_type": "AES256",
        "password_last_changed": "2026-01-15",
        "is_weak_password_suspected": False
    },
    {
        "account_name": "svc_iis_legacy",
        "spn": "HTTP/webportal.corp.local",
        "encryption_type": "RC4_HMAC",       # Vulnerable: Weak legacy encryption!
        "password_last_changed": "2023-04-10", # Vulnerable: Stale password never rotated!
        "is_weak_password_suspected": True   # Vulnerable: Suspected weak human-created password!
    },
    {
        "account_name": "svc_backup_agent",
        "spn": "cifs/backupsrv.corp.local",
        "encryption_type": "AES128",
        "password_last_changed": "2025-11-20",
        "is_weak_password_suspected": False
    }
]

def audit_service_accounts(accounts):
    print("[*] Initiating Active Directory SPN and Kerberoasting vulnerability audit...\n")
    ad_alerts = 0
    
    for svc in accounts:
        name = svc["account_name"]
        spn = svc["spn"]
        enc = svc["encryption_type"]
        changed = svc["password_last_changed"]
        weak_pass = svc["is_weak_password_suspected"]
        
        print(f"[-] Auditing Service Account: {name}")
        print(f"    ├─ SPN: {spn}")
        print(f"    ├─ Encryption Type: {enc}")
        print(f"    ├─ Password Last Changed: {changed}")
        print(f"    └─ Weak Password Risk: {weak_pass}")
        
        # Check for Kerberoasting / AD security vulnerabilities
        is_vulnerable = weak_pass or enc == "RC4_HMAC"
        
        if is_vulnerable:
            ad_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Kerberoasting / Service Account Flaw!")
            if enc == "RC4_HMAC":
                print(f"     └─ Risk: Account relies on legacy RC4 encryption, which is easier to crack.")
            if weak_pass:
                print(f"     └─ Risk: Account is susceptible to offline Kerberoasting brute-force attacks due to weak credentials.\n")
            print()
        else:
            print(f"  ✅ [SECURE]: Service account properly hardened with strong encryption and hygiene.\n")
            
    return ad_alerts

# Run the Active Directory audit scan
total_vulnerabilities = audit_service_accounts(ad_service_accounts)

print("--- AD SECURITY ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} service account(s) vulnerable to Kerberoasting / AD compromise!")
    print(f"     └─ Action Required: Enforce complex passwords (15+ chars), migrate to AES encryption, and use Group Managed Service Accounts (gMSA).")
else:
    print("  ✅ [SECURE]: All Active Directory service accounts passed security verification.")

print("==========================================")