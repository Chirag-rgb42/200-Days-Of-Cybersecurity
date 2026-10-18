# ==========================================
# Day 92: Automated Security Headers Auditor
# Purpose: Practice web application security assessment by auditing HTTP response headers for missing security controls
# ==========================================

print("=== AUTOMATED SECURITY HEADERS AUDITOR ===")

# Simulated target web endpoints and their HTTP response headers
target_endpoints = [
    {
        "endpoint": "https://secure-portal.acme-corp.local/login",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'"
        }
    },
    {
        "endpoint": "https://legacy-app.acme-corp.local/admin",
        "headers": {
            "Server": "Apache/2.4.41"
            # Missing all essential security headers!
        }
    },
    {
        "endpoint": "https://api.acme-corp.local/v1/status",
        "headers": {
            "Strict-Transport-Security": "max-age=86400",
            # Missing X-Content-Type-Options and CSP
        }
    }
]

# Essential security headers that should be present on hardened web applications
required_headers = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy"
]

def audit_security_headers(endpoints):
    print("[*] Initiating automated security header audit across endpoints...\n")
    header_alerts = 0
    
    for target in endpoints:
        ep = target["endpoint"]
        headers = target["headers"]
        
        print(f"[-] Auditing Endpoint: {ep}")
        missing_headers = [h for h in required_headers if h not in headers]
        
        if missing_headers:
            header_alerts += len(missing_headers)
            print(f"  🚨 [VULNERABILITY DETECTED]: Missing Security Headers!")
            print(f"     ├─ Absent Controls: {missing_headers}")
            print(f"     └─ Risk: Web application lacks vital browser hardening controls.\n")
        else:
            print(f"  ✅ [SECURE]: All essential security headers are properly configured.\n")
            
    return header_alerts

# Run the security header audit
total_vulnerabilities = audit_security_headers(target_endpoints)

print("--- SECURITY HEADERS AUDIT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} missing security header configuration(s)!")
    print(f"     └─ Action Required: Configure web servers to append HSTS, CSP, X-Content-Type-Options, and X-Frame-Options.")
else:
    print("  ✅ [SECURE]: All endpoints passed security header verification.")

print("==========================================")