# ==========================================
# Day 129: Automated CORS & Session Cookie Security Auditor
# Purpose: Audit web API CORS policies and Set-Cookie attributes for origin reflection, CSRF, and session hijacking risks
# ==========================================

print("=== AUTOMATED CORS & SESSION COOKIE SECURITY AUDITOR ===")

# Trusted corporate frontend origins
TRUSTED_ORIGINS = {
    "https://app.corp.local",
    "https://portal.corp.local"
}

# Simulated API endpoints with CORS headers and Set-Cookie directives
api_endpoint_configs = [
    {
        "endpoint": "https://api.corp.local/v1/account",
        "test_request_origin": "https://evil-attacker.com",
        "cors_headers": {
            "Access-Control-Allow-Origin": "https://app.corp.local",
            "Access-Control-Allow-Credentials": "true"
        },
        "set_cookie": "session_id=9a8b7c6d5e4f; Secure; HttpOnly; SameSite=Strict; Path=/"
    },
    {
        "endpoint": "https://api.corp.local/v1/profile",
        "test_request_origin": "https://evil-attacker.com",
        "cors_headers": {
            "Access-Control-Allow-Origin": "https://evil-attacker.com", # Vulnerable: Reflects untrusted origin!
            "Access-Control-Allow-Credentials": "true"                # Vulnerable: Combined with credentials!
        },
        "set_cookie": "auth_token=xyz123secret; Path=/"                   # Vulnerable: Missing Secure, HttpOnly, SameSite!
    },
    {
        "endpoint": "https://api.corp.local/v1/notifications",
        "test_request_origin": "https://evil-attacker.com",
        "cors_headers": {
            "Access-Control-Allow-Origin": "null",                    # Vulnerable: 'null' origin trust bypass!
            "Access-Control-Allow-Credentials": "true"
        },
        "set_cookie": "sid=abc987def654; Secure; SameSite=None"           # Vulnerable: Missing HttpOnly flag!
    }
]

def audit_cors_and_cookies(endpoints):
    print("[*] Initiating CORS policy and session cookie security audit...\n")
    security_alerts = 0

    for item in endpoints:
        url = item["endpoint"]
        probe_origin = item["test_request_origin"]
        cors = item["cors_headers"]
        cookie_header = item["set_cookie"]
        findings = []

        allow_origin = cors.get("Access-Control-Allow-Origin", "")
        allow_creds = cors.get("Access-Control-Allow-Credentials", "false").lower() == "true"

        # 1. Audit CORS Origin Reflection & Null Origin Trust
        if allow_origin == probe_origin and allow_origin not in TRUSTED_ORIGINS:
            severity = "Critical" if allow_creds else "High"
            findings.append(
                f"{severity} - Arbitrary CORS Origin Reflection ('{allow_origin}' with Credentials={allow_creds}): "
                "Untrusted domains can read authenticated API responses."
            )
        elif allow_origin == "null":
            findings.append("High - Trusted 'null' CORS Origin: Attackers can exploit sandboxed iframes to bypass origin checks.")
        elif allow_origin == "*" and allow_creds:
            findings.append("High - Wildcard CORS ('*') with Credentials Enabled: Overly permissive cross-origin policy.")

        # 2. Audit Set-Cookie Security Flags
        cookie_flags = [flag.strip().lower() for flag in cookie_header.split(";")[1:]]

        if "httponly" not in cookie_flags:
            findings.append("High - Cookie Missing 'HttpOnly': Session identifier is accessible via JavaScript (XSS theft risk).")
        if "secure" not in cookie_flags:
            findings.append("Medium - Cookie Missing 'Secure': Cookie may be transmitted over unencrypted HTTP connections.")
        if not any(flag.startswith("samesite=strict") or flag.startswith("samesite=lax") for flag in cookie_flags):
            findings.append("Medium - Weak or Missing 'SameSite' Attribute: Enforce 'SameSite=Strict' or 'SameSite=Lax' to mitigate CSRF.")

        print(f"[-] Auditing Endpoint: {url}")
        print(f"    ├─ CORS Allow-Origin: {allow_origin} (Credentials: {allow_creds})")
        print(f"    └─ Set-Cookie Policy: {cookie_header}")

        if findings:
            security_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} CORS/Cookie security issue(s)!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: CORS policy restricts origins to trusted domains and session cookies are hardened.\n")

    return security_alerts

# Run the CORS and cookie audit
total_vulnerabilities = audit_cors_and_cookies(api_endpoint_configs)

print("--- CORS & SESSION COOKIE ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) with CORS or session cookie vulnerabilities!")
    print(f"     └─ Action Required: Enforce strict CORS origin allowlists, reject 'null' origins, and set 'Secure; HttpOnly; SameSite=Strict' on all session cookies.")
else:
    print("  ✅ [SECURE]: All audited endpoints passed CORS and session cookie security verification.")

print("==========================================")