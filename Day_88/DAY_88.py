# ==========================================
# Day 88: Automated Clickjacking (UI Redressing) Vulnerability Scanner
# Purpose: Practice web application security assessment by auditing framing defense headers
# ==========================================

print("=== AUTOMATED CLICKJACKING PROTECTION SCANNER ===")

# Simulated target web endpoints and their security response headers
target_endpoints = [
    {
        "endpoint": "https://secure-portal.local/dashboard",
        "headers": {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'self'"
        }
    },
    {
        "endpoint": "https://legacy-app.local/settings",
        "headers": {
            "Server": "nginx/1.18.0"
            # Missing X-Frame-Options and frame-ancestors CSP!
        }
    },
    {
        "endpoint": "https://partner-portal.local/iframe-view",
        "headers": {
            "X-Frame-Options": "ALLOWALL", # Weak/deprecated header value!
        }
    }
]

def scan_for_clickjacking(endpoints):
    print("[*] Auditing web response headers for clickjacking / framing protections...\n")
    clickjacking_alerts = 0
    
    for item in endpoints:
        ep = item["endpoint"]
        headers = item["headers"]
        
        xfo = headers.get("X-Frame-Options")
        csp = headers.get("Content-Security-Policy", "")
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ X-Frame-Options: {xfo if xfo else 'Not Set'}")
        print(f"    └─ CSP frame-ancestors: {csp if 'frame-ancestors' in csp else 'Not Set'}")
        
        # Check framing protections
        has_xfo_protection = xfo and xfo.upper() in ["DENY", "SAMEORIGIN"]
        has_csp_protection = "frame-ancestors" in csp
        
        if not has_xfo_protection and not has_csp_protection:
            clickjacking_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential Clickjacking (UI Redressing) Flaw!")
            print(f"     └─ Risk: Endpoint lacks framing restrictions, allowing attackers to embed it in malicious iframes.\n")
        elif xfo and xfo.upper() == "ALLOWALL":
            clickjacking_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Insecure Framing Policy!")
            print(f"     └─ Risk: X-Frame-Options explicitly set to ALLOWALL.\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint properly restricts page framing.\n")
            
    return clickjacking_alerts

# Run the clickjacking vulnerability scan
total_vulnerabilities = scan_for_clickjacking(target_endpoints)

print("--- CLICKJACKING ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to Clickjacking!")
    print(f"     └─ Action Required: Configure X-Frame-Options (DENY/SAMEORIGIN) or Content-Security-Policy frame-ancestors.")
else:
    print("  ✅ [SECURE]: All endpoints successfully enforced framing defenses.")

print("==========================================")