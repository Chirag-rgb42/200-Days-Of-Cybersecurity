# ==========================================
# Day 106: Automated Active Directory DCSync Vulnerability Auditor
# Purpose: Practice enterprise AD security assessment by detecting unauthorized directory replication permissions
# ==========================================

print("=== AUTOMATED AD DCSYNC VULNERABILITY AUDITOR ===")

# Simulated Active Directory accounts and domain ACL replication rights
dcsync_audit_targets = [
    {
        "account_name": "DC01$",
        "account_type": "Domain Controller",
        "has_get_changes": True,
        "has_get_changes_all": True,
        "is_authorized_dc": True
    },
    {
        "account_name": "svc_backup_ad",
        "account_type": "Service Account",
        "has_get_changes": True,
        "has_get_changes_all": True,   # Vulnerable: Non-DC service account holds full DCSync rights!
        "is_authorized_dc": False
    },
    {
        "account_name": "helpdesk_lead",
        "account_type": "User Account",
        "has_get_changes": True,       # Vulnerable: Partial replication right assigned to user!
        "has_get_changes_all": False,
        "is_authorized_dc": False
    },
    {
        "account_name": "svc_sql_prod",
        "account_type": "Service Account",
        "has_get_changes": False,
        "has_get_changes_all": False,  # Secure: Standard privileges only
        "is_authorized_dc": False
    }
]

def audit_dcsync_permissions(targets):
    print("[*] Initiating Active Directory DCSync replication permissions audit...\n")
    dcsync_alerts = 0
    
    for target in targets:
        name = target["account_name"]
        atype = target["account_type"]
        get_changes = target["has_get_changes"]
        get_changes_all = target["has_get_changes_all"]
        is_dc = target["is_authorized_dc"]
        
        print(f"[-] Auditing Principal: {name} ({atype})")
        print(f"    ├─ DS-Replication-Get-Changes: {get_changes}")
        print(f"    ├─ DS-Replication-Get-Changes-All: {get_changes_all}")
        print(f"    └─ Authorized Domain Controller: {is_dc}")
        
        # Check if non-DC accounts hold DCSync permissions
        is_vulnerable = (get_changes or get_changes_all) and not is_dc
        
        if is_vulnerable:
            dcsync_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Unauthorized DCSync Privileges Flagged!")
            print(f"     └─ Risk: Non-DC object holds directory replication rights, allowing remote password hash dump (krbtgt/admin) via MS-DRSR protocol.\n")
        elif is_dc:
            print(f"  ℹ️ [INFO]: Domain Controller holds expected system replication rights.\n")
        else:
            print(f"  ✅ [SECURE]: Object does not possess DCSync replication rights.\n")
            
    return dcsync_alerts

# Run the DCSync vulnerability audit
total_vulnerabilities = audit_dcsync_permissions(dcsync_audit_targets)

print("--- DCSYNC ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} non-DC principal(s) with DCSync replication rights!")
    print(f"     └─ Action Required: Immediately revoke `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights from non-Domain Controller accounts.")
else:
    print("  ✅ [SECURE]: All non-DC accounts passed DCSync permissions verification.")

print("==========================================")