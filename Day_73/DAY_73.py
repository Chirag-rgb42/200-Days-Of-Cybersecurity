# ==========================================
# Day 73: Automated SQL Injection (SQLi) Vulnerability Scanner
# Purpose: Practice web application vulnerability assessment and detection of SQL injection flaws
# ==========================================

print("=== AUTOMATED SQL INJECTION (SQLi) SCANNER ===")

# Simulated web application input fields and target endpoints
target_inputs = [
    {"endpoint": "/login", "parameter": "username", "input_value": "admin"},
    {"endpoint": "/search", "parameter": "q", "input_value": "test' OR '1'='1"},
    {"endpoint": "/profile", "parameter": "id", "input_value": "42 OR 1=1 --"},
    {"endpoint": "/contact", "parameter": "email", "input_value": "user@example.com"}
]

# Common SQL injection test payloads
sqli_payloads = ["' OR '1'='1", "OR 1=1 --", "' UNION SELECT", "'; DROP TABLE users; --"]

# Simulated application response behaviors when vulnerable
def simulate_backend_query(param, value):
    # Mocking vulnerable response indicators
    if any(p in value for p in ["' OR '1'='1", "1=1 --", "UNION SELECT"]):
        return {"status": 200, "content": "Welcome Admin! Multiple records returned.", "vulnerable": True}
    else:
        return {"status": 200, "content": "Standard user profile loaded successfully.", "vulnerable": False}

def scan_for_sqli(inputs):
    print("[*] Initiating automated SQL injection vulnerability scan across form parameters...\n")
    sqli_alerts = 0
    
    for item in inputs:
        endpoint = item["endpoint"]
        param = item["parameter"]
        val = item["input_value"]
        
        # Test input against SQLi characteristics
        response = simulate_backend_query(param, val)
        
        if response["vulnerable"]:
            sqli_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential SQL Injection (SQLi)!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Vulnerable Parameter: {param}")
            print(f"     ├─ Test Payload Used: {val}")
            print(f"     └─ Server Response Behavior: {response['content']}\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint '{endpoint}' parameter '{param}' handled input safely.")
            
    return sqli_alerts

# Run the SQLi vulnerability scan
total_vulnerabilities = scan_for_sqli(target_inputs)

print("--- SQL INJECTION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} vulnerable parameter(s) susceptible to SQLi!")
    print(f"     └─ Action Required: Implement parameterized queries (Prepared Statements) immediately.")
else:
    print("  ✅ [SECURE]: All form parameters successfully sanitized user input.")

print("==========================================")