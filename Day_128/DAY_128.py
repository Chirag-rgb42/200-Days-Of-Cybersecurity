# ==========================================
# Day 128: Automated HTTP Security Headers & CSP Policy Auditor
# Purpose: Audit web application HTTP response headers for missing protections and weak Content-Security-Policy directives
# ==========================================

print("=== AUTOMATED HTTP SECURITY HEADERS & CSP AUDITOR ===")

# Simulated HTTP response headers captured from web applications
web_app_responses = [
    {
        "app_name": "Customer Banking Portal",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' https://cdn.corp.local; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
    },
    {
        "app_name": "Marketing & Docs Portal",
        "headers": {
            "Strict-Transport-Security": "max-age=3600", # Vulnerable: HSTS max-age far below 1-year baseline!
            "Content-Security-Policy": "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'", # Vulnerable: Unsafe CSP!
            "X-Content-Type-Options": "nosniff"
            # Vulnerable: Missing X-Frame-Options and Referrer-Policy!
        }
    },
    {
        "app_name": "Internal Support Dashboard",
        "headers": {
            "Server": "Apache/2.4.49 (Ubuntu)" # Vulnerable: Exposes server version banner & lacks all security headers!
        }
    }
]

MIN_HSTS_SECONDS = 31536000  # 1 year

def audit_http_headers(applications):
    print("[*] Initiating HTTP security headers and CSP configuration audit...\n")
    header_alerts = 0

    for app in applications:
        name = app["app_name"]
        # Normalize header keys to lowercase for case-insensitive lookup
        headers = {k.lower(): v for k, v in app["headers"].items()}
        findings = []

        # 1. Audit Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append("Missing 'Strict-Transport-Security' (HSTS): Vulnerable to SSL stripping and downgrade attacks.")
        else:
            if "max-age=" in hsts:
                try:
                    age_part = [p.strip() for p in hsts.split(";") if p.strip().startswith("max-age=")][0]
                    max_age = int(age_part.split("=")[1])
                    if max_age < MIN_HSTS_SECONDS:
                        findings.append(f"Weak HSTS 'max-age={max_age}': Increase to at least 31536000 seconds (1 year).")
                except ValueError:
                    findings.append("Malformed HSTS 'max-age' directive.")

        # 2. Audit Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append("Missing 'Content-Security-Policy' (CSP): Lacks browser-level XSS and script injection mitigation.")
        else:
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                findings.append("Weak CSP Directive ('unsafe-inline' or 'unsafe-eval'): Allows inline script execution, weakening XSS protection.")
            if "default-src *" in csp or "script-src *" in csp:
                findings.append("Overly Permissive CSP Wildcard ('*'): Restrict script and resource origins explicitly.")

        # 3. Audit Clickjacking & MIME-Sniffing Headers
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append("Missing or Invalid 'X-Content-Type-Options: nosniff': Browsers may MIME-sniff non-script responses.")

        has_frame_ancestors = csp and "frame-ancestors" in csp
        if "x-frame-options" not in headers and not has_frame_ancestors:
            findings.append("Missing Clickjacking Protection: Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors'.")

        # 4. Check for verbose Server version disclosure
        server_banner = headers.get("server", "")
        if any(char.isdigit() for char in server_banner):
            findings.append(f"Information Disclosure ('Server: {server_banner}'): Strip version numbers from HTTP response headers.")

        print(f"[-] Auditing Web Application: {name}")
        if findings:
            header_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} HTTP header issue(s)!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: All critical HTTP security headers and strict CSP rules are enforced.\n")

    return header_alerts

# Run the HTTP headers audit
total_vulnerabilities = audit_http_headers(web_app_responses)

print("--- HTTP SECURITY HEADERS ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} web application(s) with missing or weak security headers!")
    print(f"     └─ Action Required: Enforce 1-year HSTS, remove 'unsafe-inline'/'unsafe-eval' from CSP, add 'nosniff', and suppress server banners.")
else:
    print("  ✅ [SECURE]: All audited web applications passed HTTP security header verification.")

print("==========================================")