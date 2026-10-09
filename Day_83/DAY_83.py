# ==========================================
# Day 83: Automated CSRF Protection Auditor
# Purpose: Practice web vulnerability assessment by auditing state-changing endpoints for anti-CSRF controls
# ==========================================

print("=== AUTOMATED CSRF PROTECTION AUDITOR ===")

# Simulated state-changing web endpoints and their security attributes
state_changing_endpoints = [
    {
        "endpoint": "/api/v1/user/update-password",
        "method": "POST",
        "has_csrf_token": True,
        "samesite_cookie": "Strict"
    },
    {
        "endpoint": "/api/v1/account/transfer-funds",
        "method": "POST",
        "has_csrf_token": False, # Vulnerable: Missing anti-CSRF token!
        "samesite_cookie": "None"  # Vulnerable: Insecure cookie attribute!
    },
    {
        "endpoint": "/api/v1/settings/email",
        "method": "POST",
        "has_csrf_token": True,
        "samesite_cookie": "Lax"
    },
    {
        "endpoint": "/admin/create-user",
        "method": "POST",
        "has_csrf_token": False, # Vulnerable: Missing anti-CSRF token!
        "samesite_cookie": "None"
    }
]

def audit_csrf_defenses(endpoints):
    print("[*] Auditing state-changing endpoints for anti-CSRF tokens and SameSite cookie flags...\n")
    csrf_alerts = 0
    
    for item in endpoints:
        ep = item["endpoint"]
        method = item["method"]
        token_present = item["has_csrf_token"]
        samesite = item["samesite_cookie"]
        
        print(f"[-] Auditing Endpoint: [{method}] {ep}")
        print(f"    ├─ Anti-CSRF Token Present: {token_present}")
        print(f"    └─ Cookie SameSite Attribute: {samesite}")
        
        # Check for CSRF vulnerabilities
        if not token_present or samesite.lower() == "none":
            csrf_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Inadequate CSRF Protection!")
            if not token_present:
                print(f"     └─ Risk: State-changing POST endpoint lacks unique anti-CSRF token validation.")
            if samesite.lower() == "none":
                print(f"     └─ Risk: Session cookies configured with SameSite=None without secure cross-site barriers.\n")
            print()
        else:
            print(f"  ✅ [SECURE]: Endpoint implements robust anti-CSRF tokens and secure cookie settings.\n")
            
    return csrf_alerts

# Run the CSRF security audit
total_vulnerabilities = audit_csrf_defenses(state_changing_endpoints)

print("--- CSRF AUDIT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to Cross-Site Request Forgery!")
    print(f"     └─ Action Required: Implement cryptographic anti-CSRF tokens and configure SameSite cookie protections.")
else:
    print("  ✅ [SECURE]: All state-changing endpoints passed CSRF verification.")

print("==========================================")