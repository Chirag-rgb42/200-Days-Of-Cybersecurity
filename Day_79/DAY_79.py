# ==========================================
# Day 79: Automated Server-Side Request Forgery (SSRF) Vulnerability Scanner
# Purpose: Practice web vulnerability assessment and detection of SSRF flaws
# ==========================================

print("=== AUTOMATED SSRF VULNERABILITY SCANNER ===")

# Simulated web application endpoints taking URL parameters for fetching resources
target_inputs = [
    {"endpoint": "/fetch-preview", "parameter": "url", "input_value": "https://example.com/image.png"},
    {"endpoint": "/webhook/test", "parameter": "callback", "input_value": "http://127.0.0.1:8080/admin"},
    {"endpoint": "/import", "parameter": "source", "input_value": "http://169.254.169.254/latest/meta-data/"},
    {"endpoint": "/pdf-generator", "parameter": "template_url", "input_value": "https://trusted-cdn.local/template.html"}
]

# Common internal and metadata endpoints targeted by SSRF payloads
ssrf_indicators = ["127.0.0.1", "localhost", "169.254.169.254", "internal.net", "0.0.0.0"]

def simulate_ssrf_response(param, value):
    # Mocking vulnerable response if internal IPs or metadata URLs are requested
    if any(indicator in value for indicator in ssrf_indicators):
        return {"status": 200, "vulnerable": True, "response": "HTTP/1.1 200 OK - Internal metadata / service payload returned!"}
    else:
        return {"status": 200, "vulnerable": False, "response": "HTTP/1.1 200 OK - External resource fetched successfully."}

def scan_for_ssrf(inputs):
    print("[*] Initiating automated Server-Side Request Forgery (SSRF) scan across URL parameters...\n")
    ssrf_alerts = 0
    
    for item in inputs:
        endpoint = item["endpoint"]
        param = item["parameter"]
        val = item["input_value"]
        
        response = simulate_ssrf_response(param, val)
        
        if response["vulnerable"]:
            ssrf_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential Server-Side Request Forgery (SSRF)!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Parameter: {param}")
            print(f"     ├─ Payload Tested: {val}")
            print(f"     └─ Server Behavior: Allowed request to internal resource/metadata endpoint.\n")
        else:
            print(f"  ✅ [SECURE]: Parameter '{param}' on '{endpoint}' blocked internal routing.")
            
    return ssrf_alerts

# Run the SSRF vulnerability scan
total_vulnerabilities = scan_for_ssrf(target_inputs)

print("--- SSRF ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} parameter(s) vulnerable to SSRF!")
    print(f"     └─ Action Required: Implement strict URL parsing, IP whitelisting, and block loopback/metadata ranges.")
else:
    print("  ✅ [SECURE]: All URL parameters successfully restricted outbound requests.")

print("==========================================")