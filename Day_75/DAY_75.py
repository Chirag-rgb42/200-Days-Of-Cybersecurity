# ==========================================
# Day 75: Automated HTTP Security Headers Audit Scanner
# Purpose: Practice web vulnerability assessment by auditing missing HTTP security headers
# ==========================================

print("=== HTTP SECURITY HEADERS AUDIT SCANNER ===")

# Simulated web server response headers from target endpoints
target_sites = [
    {
        "url": "https://secure-portal.local",
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
    },
    {
        "url": "https://legacy-app.local",
        "headers": {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3"
            # Missing all modern security headers!
        }
    }
]

# Essential security headers that should be present
required_security_headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options"
]

def audit_security_headers(sites):
    print("[*] Auditing target web response headers for missing security controls...\n")
    total_findings = 0
    
    for site in sites:
        url = site["url"]
        headers = site["headers"]
        print(f"[-] Scanning Target: {url}")
        
        missing_headers = []
        for req_header in required_security_headers:
            if req_header not in headers:
                missing_headers.append(req_header)
                
        if missing_headers:
            total_findings += len(missing_headers)
            print(f"  🚨 [SECURITY WARNING]: Missing {len(missing_headers)} recommended security header(s)!")
            for mh in missing_headers:
                print(f"     └─ Missing Header: {mh}")
            print()
        else:
            print(f"  ✅ [SECURE]: All mandatory security headers are properly implemented.\n")
            
    return total_findings

# Run the security headers audit
total_missing = audit_security_headers(target_sites)

print("--- SECURITY HEADERS AUDIT SUMMARY ---")
if total_missing > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_missing} missing security header configuration(s) across targets!")
    print(f"     └─ Action Required: Configure web server to return robust security headers.")
else:
    print("  ✅ [SECURE]: All target sites passed header verification.")

print("==========================================")