# ==========================================
# Day 107: Automated Active Directory AdminSDHolder & SDProp Auditor
# Purpose: Practice enterprise AD security assessment by auditing AdminSDHolder ACLs and flagging orphaned adminCount accounts
# ==========================================

print("=== AUTOMATED AD ADMINSDHOLDER & SDPROP AUDITOR ===")

# Simulated Active Directory protected accounts and AdminSDHolder ACL rules
adminsdholder_audit_data = {
    "adminsdholder_acl": [
        {"principal": "Domain Admins", "access_right": "Full Control", "is_authorized": True},
        {"principal": "Enterprise Admins", "access_right": "Full Control", "is_authorized": True},
        {"principal": "svc_helpdesk_bot", "access_right": "WriteDacl", "is_authorized": False} # Vulnerable: Unauthorized backdoor ACL on template!
    ],
    "protected_accounts": [
        {
            "username": "da_jdoe",
            "admin_count": 1,
            "is_member_of_admin_group": True,
            "inheritance_disabled": True # Standard for active domain admins
        },
        {
            "username": "former_contractor",
            "admin_count": 1,
            "is_member_of_admin_group": False, # Vulnerable: Orphaned adminCount=1 with disabled inheritance!
            "inheritance_disabled": True
        },
        {
            "username": "m_smith",
            "admin_count": 0,
            "is_member_of_admin_group": False,
            "inheritance_disabled": False # Secure: Standard user account
        }
    ]
}

def audit_adminsdholder_and_sdprop(data):
    print("[*] Initiating AdminSDHolder object ACL and SDProp propagation audit...\n")
    security_alerts = 0
    
    # Task 1: Audit AdminSDHolder Object ACLs
    print("[-] [Phase 1/2] Checking AdminSDHolder Template ACL Permissions...")
    for rule in data["adminsdholder_acl"]:
        pname = rule["principal"]
        right = rule["access_right"]
        auth = rule["is_authorized"]
        
        if not auth:
            security_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Unauthorized AdminSDHolder ACL Entry!")
            print(f"     └─ Risk: Principal '{pname}' has '{right}' on AdminSDHolder. SDProp will propagate this backdoor to all protected domain admins!\n")
        else:
            print(f"  ✅ [SECURE]: Authorized default permission for '{pname}'.")
            
    # Task 2: Audit Orphaned adminCount=1 Accounts
    print("\n[-] [Phase 2/2] Scanning Accounts for Orphaned adminCount=1 Flags...")
    for account in data["protected_accounts"]:
        uname = account["username"]
        acount = account["admin_count"]
        is_admin = account["is_member_of_admin_group"]
        no_inherit = account["inheritance_disabled"]
        
        print(f"[-] Auditing Account: {uname}")
        print(f"    ├─ adminCount: {acount}")
        print(f"    ├─ Active Admin Group Member: {is_admin}")
        print(f"    └─ ACL Inheritance Disabled: {no_inherit}")
        
        # Check for orphan accounts (adminCount=1 but no longer in an admin group)
        if acount == 1 and not is_admin:
            security_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Orphaned adminCount Account Flagged!")
            print(f"     └─ Risk: User is no longer an admin but retains `adminCount=1` and disabled ACL inheritance, blocking standard security policy updates.\n")
        else:
            print(f"  ✅ [SECURE]: Account status aligns with administrative group membership.\n")
            
    return security_alerts

# Run the audit scan
total_vulnerabilities = audit_adminsdholder_and_sdprop(adminsdholder_audit_data)

print("--- ADMINSDHOLDER ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} AdminSDHolder / SDProp security risk(s)!")
    print(f"     └─ Action Required: Clean unauthorized ACEs from `CN=AdminSDHolder,CN=System,DC=...`, reset `adminCount` to 0 on orphan accounts, and re-enable ACL inheritance.")
else:
    print("  ✅ [SECURE]: AdminSDHolder permissions and account flags are fully hardened.")

print("==========================================")