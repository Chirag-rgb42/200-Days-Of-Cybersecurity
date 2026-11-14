# ==========================================
# Day 119: Automated Active Directory Password Policy & FGPP Auditor
# Purpose: Practice enterprise AD security assessment by auditing default password policies and Fine-Grained Password Policies (FGPP)
# ==========================================

print("=== AUTOMATED AD PASSWORD POLICY & FGPP AUDITOR ===")

# Simulated Active Directory Password Settings Objects (PSOs) and Default Domain Policy
ad_password_policies = [
    {
        "policy_name": "Default Domain Policy",
        "applied_to": "All Domain Users",
        "min_password_length": 8,       # Vulnerable: Too short by modern standards (Min recommended: 14+)
        "complexity_enabled": True,
        "lockout_threshold": 0,         # Vulnerable: Account lockout disabled (Enables unthrottled spraying!)
        "precedence": 999
    },
    {
        "policy_name": "Tier0_Admin_PSO",
        "applied_to": "Domain Admins & Enterprise Admins",
        "min_password_length": 16,      # Secure: Strong length requirement for admins
        "complexity_enabled": True,
        "lockout_threshold": 5,         # Secure: Locks out after 5 bad attempts
        "precedence": 10                # High precedence FGPP
    },
    {
        "policy_name": "ServiceAccounts_PSO",
        "applied_to": "Custom Service Accounts Group",
        "min_password_length": 12,
        "complexity_enabled": True,
        "lockout_threshold": 0,         # Intentional for service accounts to prevent service outages
        "precedence": 50
    }
]

def audit_password_policies(policies):
    print("[*] Initiating Active Directory password policy and FGPP audit...\n")
    policy_alerts = 0
    
    for policy in policies:
        pname = policy["policy_name"]
        target = policy["applied_to"]
        min_len = policy["min_password_length"]
        complexity = policy["complexity_enabled"]
        lockout = policy["lockout_threshold"]
        prec = policy["precedence"]
        
        print(f"[-] Auditing Policy: {pname} (Target: {target})")
        print(f"    ├─ Minimum Password Length: {min_len} chars")
        print(f"    ├─ Password Complexity Enabled: {complexity}")
        print(f"    ├─ Account Lockout Threshold: {lockout} attempts")
        print(f"    └─ Precedence Order: {prec}")
        
        # Check for weak password length or disabled account lockout on standard/admin policies
        is_weak_length = min_len < 12
        is_lockout_disabled = (lockout == 0) and ("Admin" in pname or "Default" in pname)
        
        if is_weak_length or is_lockout_disabled:
            policy_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Insecure Password Policy Configuration!")
            if is_weak_length:
                print(f"     └─ Risk: Minimum password length ({min_len}) is below modern enterprise security baselines (recommended 14+).")
            if is_lockout_disabled:
                print(f"     └─ Risk: Account lockout threshold is disabled (0), leaving accounts vulnerable to offline/online brute-forcing and password spraying.")
            print()
        else:
            print(f"  ✅ [SECURE]: Password policy meets enterprise complexity and lockout thresholds.\n")
            
    return policy_alerts

# Run the password policy audit
total_vulnerabilities = audit_password_policies(ad_password_policies)

print("--- PASSWORD POLICY ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} password policy misconfiguration(s)!")
    print(f"     └─ Action Required: Increase minimum password length to 14+ characters, enforce account lockout thresholds, and implement strict Fine-Grained Password Policies for privileged groups.")
else:
    print("  ✅ [SECURE]: All password policies passed security baseline verification.")

print("==========================================")