# ==========================================
# Day 76: Automated Directory Traversal (LFI) Scanner
# Purpose: Practice web vulnerability assessment and detection of Local File Inclusion flaws
# ==========================================

print("=== AUTOMATED DIRECTORY TRAVERSAL (LFI) SCANNER ===")

# Simulated web application endpoints and input parameters
target_inputs = [
    {"endpoint": "/load_page", "parameter": "page", "input_value": "home.html"},
    {"endpoint": "/download", "parameter": "file", "input_value": "../../../../etc/passwd"},
    {"endpoint": "/view", "parameter": "doc", "input_value": "..\\..\\..\\Windows\\win.ini"},
    {"endpoint": "/display", "parameter": "template", "input_value": "contact.php"}
]

# Common LFI / Path Traversal test payloads
lfi_payloads = ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini", "/etc/shadow"]

def simulate_lfi_response(param, value):
    # Mocking vulnerable response if path traversal sequences are processed
    if ".." in value and ("/etc/" in value or "Windows" in value):
        return {"status": 200, "vulnerable": True, "content": "root:x:0:0:root:/root:/bin/bash (System file exposed!)"}
    else:
        return {"status": 200, "vulnerable": False, "content": "Template loaded successfully."}

def scan_for_lfi(inputs):
    print("[*] Initiating automated Directory Traversal (LFI) vulnerability scan...\n")
    lfi_alerts = 0
    
    for item in inputs:
        endpoint = item["endpoint"]
        param = item["parameter"]
        val = item["input_value"]
        
        response = simulate_lfi_response(param, val)
        
        if response["vulnerable"]:
            lfi_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential Local File Inclusion (LFI)!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Parameter: {param}")
            print(f"     ├─ Payload Tested: {val}")
            print(f"     └─ Server Behavior: Returned sensitive system file contents.\n")
        else:
            print(f"  ✅ [SECURE]: Parameter '{param}' on '{endpoint}' safely handled input.")
            
    return lfi_alerts

# Run the LFI vulnerability scan
total_vulnerabilities = scan_for_lfi(target_inputs)

print("--- LFI ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} parameter(s) vulnerable to Directory Traversal!")
    print(f"     └─ Action Required: Implement strict input whitelisting and avoid direct path concatenation.")
else:
    print("  ✅ [SECURE]: All endpoints properly restricted path navigation.")

print("==========================================")