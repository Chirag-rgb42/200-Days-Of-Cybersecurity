# ==========================================
# Day 113: Automated Active Directory AD CS ESC1 Vulnerability Auditor
# Purpose: Practice enterprise AD security assessment by detecting misconfigured AD CS certificate templates vulnerable to ESC1
# ==========================================

print("=== AUTOMATED AD CS ESC1 VULNERABILITY AUDITOR ===")

# Simulated Active Directory Certificate Services (AD CS) templates
ad_cs_templates = [
    {
        "template_name": "User",
        "display_name": "Default User Template",
        "enrollee_supplies_san": False,
        "allows_client_auth": True,
        "low_privileged_enrollment": True
    },
    {
        "template_name": "VulnerableWebRegistration",
        "display_name": "Custom Web App Enrollment",
        "enrollee_supplies_san": True,   # Vulnerable: Enrollee can supply arbitrary SAN!
        "allows_client_auth": True,     # Vulnerable: Permits Client Authentication EKU!
        "low_privileged_enrollment": True # Vulnerable: Domain Users have enrollment rights!
    },
    {
        "template_name": "Computer",
        "display_name": "Default Computer Template",
        "enrollee_supplies_san": False,
        "allows_client_auth": True,
        "low_privileged_enrollment": False
    }
]

def audit_ad_cs_esc1(templates):
    print("[*] Initiating Active Directory Certificate Services (AD CS) ESC1 audit...\n")
    esc1_alerts = 0
    
    for template in templates:
        tname = template["template_name"]
        dname = template["display_name"]
        san = template["enrollee_supplies_san"]
        client_auth = template["allows_client_auth"]
        low_priv = template["low_privileged_enrollment"]
        
        print(f"[-] Auditing Certificate Template: {tname} ({dname})")
        print(f"    ├─ Enrollee Supplies SAN (ESC1 Flag): {san}")
        print(f"    ├─ Allows Client Authentication EKU: {client_auth}")
        print(f"    └─ Low-Privileged User Enrollment Rights: {low_priv}")
        
        # Check for ESC1 Vulnerability Criteria (All three conditions must be true)
        if san and client_auth and low_priv:
            esc1_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: AD CS ESC1 Misconfiguration!")
            print(f"     └─ Risk: Low-privileged users can request certificates with arbitrary SANs and Client Auth EKUs, enabling domain admin impersonation.\n")
        else:
            print(f"  ✅ [SECURE]: Template configuration is hardened against ESC1 abuse.\n")
            
    return esc1_alerts

# Run the AD CS audit scan
total_vulnerabilities = audit_ad_cs_esc1(ad_cs_templates)

print("--- AD CS ESC1 ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} certificate template(s) vulnerable to ESC1!")
    print(f"     └─ Action Required: Disable `ENROLEE_SUPPLIES_SUBJECT`, restrict low-privileged enrollment permissions, and audit active certificates.")
else:
    print("  ✅ [SECURE]: All certificate templates passed AD CS ESC1 security verification.")

print("==========================================")