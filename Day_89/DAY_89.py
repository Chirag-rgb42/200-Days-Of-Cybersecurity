# ==========================================
# Day 89: Automated Open Redirect Vulnerability Scanner
# Purpose: Practice web application security assessment by detecting unvalidated redirect parameters
# ==========================================

print("=== AUTOMATED OPEN REDIRECT SCANNER ===")

# Simulated web application endpoints and redirect parameters
redirect_tests = [
    {
        "endpoint": "/login",
        "parameter": "next",
        "input_value": "/dashboard/overview",
        "trusted_domain": "secure-portal.local"
    },
    {
        "endpoint": "/auth/redirect",
        "parameter": "url",
        "input_value": "https://evil-attacker.com/login-clone",
        "trusted_domain": "secure-portal.local"
    },
    {
        "endpoint": "/outbound",
        "parameter": "target",
        "input_value": "//malicious-site.net/steal-tokens",
        "trusted_domain": "secure-portal.local"
    },
    {
        "endpoint": "/feedback/thanks",
        "parameter": "return",
        "input_value": "/home",
        "trusted_domain": "secure-portal.local"
    }
]

def scan_for_open_redirects(tests):
    print("[*] Initiating automated Open Redirect scan across navigation parameters...\n")
    redirect_alerts = 0
    
    for test in tests:
        ep = test["endpoint"]
        param = test["parameter"]
        val = test["input_value"]
        domain = test["trusted_domain"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Parameter: {param}")
        print(f"    └─ Payload Tested: {val}")
        
        # Check if input points to an external domain or protocol-relative URI
        is_external = val.startswith("http://") or val.startswith("https://") or val.startswith("//")
        
        if is_external:
            # Check if domain matches trusted internal domain
            if domain not in val and not val.startswith("//"):
                redirect_alerts += 1
                print(f"  🚨 [VULNERABILITY DETECTED]: Open Redirect Flaw!")
                print(f"     └─ Risk: Parameter redirects users to untrusted external domain ({val}).\n")
            elif val.startswith("//"):
                redirect_alerts += 1
                print(f"  🚨 [VULNERABILITY DETECTED]: Protocol-Relative Open Redirect!")
                print(f"     └─ Risk: Parameter allows protocol-relative redirection to external hosts ({val}).\n")
            else:
                print(f"  ✅ [SECURE]: Redirect destination matches trusted domain.\n")
        else:
            print(f"  ✅ [SECURE]: Parameter restricts redirection to safe relative paths.\n")
            
    return redirect_alerts

# Run the open redirect vulnerability scan
total_vulnerabilities = scan_for_open_redirects(redirect_tests)

print("--- OPEN REDIRECT ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to Open Redirect!")
    print(f"     └─ Action Required: Enforce strict relative path redirection or validate destination domains against an explicit whitelist.")
else:
    print("  ✅ [SECURE]: All redirection parameters successfully restricted.")

print("==========================================")