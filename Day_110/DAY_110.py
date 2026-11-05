# ==========================================
# Day 110: Automated Active Directory CS ESC1 Vulnerability Auditor
# Purpose: Practice enterprise AD security assessment by detecting misconfigured certificate templates vulnerable to SAN impersonation
# ==========================================

print("=== AUTOMATED AD CS ESC1 VULNERABILITY AUDITOR ===")

# Simulated Active Directory Certificate Services (AD CS) template configurations
certificate_templates = [
    {
        "template_name": "UserAuthentication",
        "allows_client_auth": True,
        "enrollee_supplies_subject": False, # Secure: SAN cannot be supplied by requester
        "enrollment_permissions": ["Domain Users"]
    },
    {
        "template_name": "Web Server Custom",
        "allows_client_auth": True,          # Vulnerable Conditions:
        "enrollee_supplies_subject": True,   # 1. Enrollee supplies subject (SAN)
        "enrollment_permissions": ["Domain Users"] # 2. Low-privilege users can enroll
    },
    {
        "template_name": "DomainControllerAuth",
        "allows_client_auth": True,
        "enrollee_supplies_subject": True,
        "enrollment_permissions": ["Domain Controllers"] # Secure: Restricted to DCs
    }
]

def audit_adcs_esc1(templates):
    print("[*] Initiating AD CS Certificate Template security audit...\n")
    esc1_alerts = 0
    
    for tmpl in templates:
        name = tmpl["template_name"]
        client_auth = tmpl["allows_client_auth"]
        supplies_san = tmpl["enrollee_supplies_subject"]
        perms = tmpl["enrollment_permissions"]
        
        print(f"[-] Auditing Template: {name}")
        print(f"    ├─ Extended Key Usage (Client Auth): {client_auth}")
        print(f"    ├─ Enrollee Supplies Subject (SAN): {supplies_san}")
        print(f"    └─ Enrollment Rights Granted To: {perms}")
        
        # Check for ESC1 vulnerability requirements
        is_esc1_vulnerable = client_auth and supplies_san and ("Domain Users" in perms or "Authenticated Users" in perms)
        
        if is_esc1_vulnerable:
            esc1_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: AD CS ESC1 Misconfiguration Flagged!")
            print(f"     └─ Risk: Low-privileged users can request authentication certificates and supply arbitrary SANs (Domain Admin impersonation).\n")
        else:
            print(f"  ✅ [SECURE]: Certificate template permissions and SAN configuration are hardened.\n")
            
    return esc1_alerts

# Run the AD CS ESC1 audit scan
total_vulnerabilities = audit_adcs_esc1(certificate_templates)

print("--- AD CS ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} AD CS template(s) vulnerable to ESC1 domain escalation!")
    print(f"     └─ Action Required: Uncheck `ENROLLEE_SUPPLIES_SUBJECT` on authentication templates or restrict enrollment permissions to authorized security groups.")
else:
    print("  ✅ [SECURE]: All certificate templates passed AD CS ESC1 security verification.")

print("==========================================")