# ==========================================
# Day 95: Automated Server-Side Template Injection (SSTI) Scanner
# Purpose: Practice web application security assessment by detecting unsafe template evaluations
# ==========================================

print("=== AUTOMATED SSTI VULNERABILITY SCANNER ===")

# Simulated web application endpoints and input parameters tested with template probes
ssti_test_payloads = [
    {
        "endpoint": "/api/v1/welcome",
        "parameter": "name",
        "probe_input": "{{7*7}}",
        "expected_evaluation": "49",
        "engine": "Jinja2 / Twig"
    },
    {
        "endpoint": "/api/v1/profile/view",
        "parameter": "user",
        "probe_input": "${7*7}",
        "expected_evaluation": "49",
        "engine": "FreeMarker / Thymeleaf"
    },
    {
        "endpoint": "/api/v1/search",
        "parameter": "q",
        "probe_input": "secure_search_term",
        "expected_evaluation": "secure_search_term", # Secure: Treated as literal string
        "engine": "None"
    }
]

def scan_for_ssti(payloads):
    print("[*] Initiating automated Server-Side Template Injection (SSTI) scan across inputs...\n")
    ssti_alerts = 0
    
    for test in payloads:
        ep = test["endpoint"]
        param = test["parameter"]
        probe = test["probe_input"]
        expected = test["expected_evaluation"]
        engine = test["engine"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Parameter: {param}")
        print(f"    ├─ Template Probe: {probe}")
        
        # Simulate server rendering response based on template evaluation
        # If probe is evaluated (e.g. {{7*7}} turns into 49), a vulnerability exists
        is_evaluated = False
        if "{{7*7}}" in probe and expected == "49":
            is_evaluated = True
        elif "${7*7}" in probe and expected == "49":
            is_evaluated = True
            
        if is_evaluated:
            ssti_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Server-Side Template Injection (SSTI) Flaw!")
            print(f"     └─ Risk: Template engine ({engine}) evaluated user-supplied expression '{probe}' into '{expected}', risking RCE.\n")
        else:
            print(f"  ✅ [SECURE]: Input handled as literal string; no template evaluation detected.\n")
            
    return ssti_alerts

# Run the SSTI vulnerability scan
total_vulnerabilities = scan_for_ssti(ssti_test_payloads)

print("--- SSTI ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to Server-Side Template Injection!")
    print(f"     └─ Action Required: Separate user data from template execution contexts by passing variables safely rather than concatenating strings.")
else:
    print("  ✅ [SECURE]: All endpoints passed template injection verification.")

print("==========================================")