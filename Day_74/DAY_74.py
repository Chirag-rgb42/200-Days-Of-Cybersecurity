# ==========================================
# Day 74: Automated Cross-Site Scripting (XSS) Vulnerability Scanner
# Purpose: Practice web application vulnerability assessment and detection of XSS flaws
# ==========================================

print("=== AUTOMATED XSS VULNERABILITY SCANNER ===")

# Simulated web application form parameters and input endpoints
target_inputs = [
    {"endpoint": "/search", "parameter": "q", "input_value": "standard search term"},
    {"endpoint": "/comment", "parameter": "message", "input_value": "<script>alert('XSS')</script>"},
    {"endpoint": "/profile", "parameter": "bio", "input_value": "<img src=x onerror=alert(1)>"},
    {"endpoint": "/feedback", "parameter": "name", "input_value": "Jane Doe"}
]

# Common XSS test payloads
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]

def simulate_xss_response(param, value):
    # Mocking vulnerable response if payload is reflected unescaped
    if any(payload in value for payload in ["<script>", "onerror=", "javascript:"]):
        return {"status": 200, "reflected": True, "content": f"<div>User input rendered: {value}</div>"}
    else:
        return {"status": 200, "reflected": False, "content": "<div>Input sanitized and escaped successfully.</div>"}

def scan_for_xss(inputs):
    print("[*] Initiating automated Cross-Site Scripting (XSS) vulnerability scan across form parameters...\n")
    xss_alerts = 0
    
    for item in inputs:
        endpoint = item["endpoint"]
        param = item["parameter"]
        val = item["input_value"]
        
        response = simulate_xss_response(param, val)
        
        if response["reflected"]:
            xss_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential Cross-Site Scripting (XSS)!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Parameter: {param}")
            print(f"     ├─ Payload Tested: {val}")
            print(f"     └─ Status: Unsanitized input reflected in response body.\n")
        else:
            print(f"  ✅ [SECURE]: Parameter '{param}' on '{endpoint}' escaped input properly.")
            
    return xss_alerts

# Run the XSS vulnerability scan
total_vulnerabilities = scan_for_xss(target_inputs)

print("--- XSS ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️️ [ALERT]: Flagged {total_vulnerabilities} parameter(s) vulnerable to XSS!")
    print(f"     └─ Action Required: Implement strict output encoding and context-aware escaping.")
else:
    print("  ✅ [SECURE]: All form parameters successfully sanitized user input.")

print("==========================================")