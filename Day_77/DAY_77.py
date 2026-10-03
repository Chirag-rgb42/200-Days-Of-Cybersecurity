# ==========================================
# Day 77: Automated OS Command Injection Vulnerability Scanner
# Purpose: Practice web application vulnerability assessment and detection of OS command execution flaws
# ==========================================

print("=== AUTOMATED OS COMMAND INJECTION SCANNER ===")

# Simulated web application endpoints and input parameters requiring system utilities
target_inputs = [
    {"endpoint": "/ping", "parameter": "host", "input_value": "127.0.0.1"},
    {"endpoint": "/tools/lookup", "parameter": "domain", "input_value": "example.com; whoami"},
    {"endpoint": "/diagnostics", "parameter": "target", "input_value": "8.8.8.8 & id"},
    {"endpoint": "/dns", "parameter": "query", "input_value": "localhost"}
]

# Common OS command injection test payloads
command_payloads = ["; whoami", "& id", "| uname -a", "; cat /etc/passwd"]

def simulate_command_response(param, value):
    # Mocking vulnerable response if shell metacharacters are processed
    if any(char in value for char in [";", "&", "|", "`"]):
        return {"status": 200, "vulnerable": True, "output": "uid=0(root) gid=0(root) groups=0(root) (Command executed successfully!)"}
    else:
        return {"status": 200, "vulnerable": False, "output": "Ping statistics for 127.0.0.1: packets sent = 4"}

def scan_for_command_injection(inputs):
    print("[*] Initiating automated OS Command Injection vulnerability scan...\n")
    injection_alerts = 0
    
    for item in inputs:
        endpoint = item["endpoint"]
        param = item["parameter"]
        val = item["input_value"]
        
        response = simulate_command_response(param, val)
        
        if response["vulnerable"]:
            injection_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential OS Command Injection!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Parameter: {param}")
            print(f"     ├─ Payload Tested: {val}")
            print(f"     └─ Shell Output: {response['output']}\n")
        else:
            print(f"  ✅ [SECURE]: Parameter '{param}' on '{endpoint}' handled input safely.")
            
    return injection_alerts

# Run the command injection vulnerability scan
total_vulnerabilities = scan_for_command_injection(target_inputs)

print("--- COMMAND INJECTION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} parameter(s) vulnerable to OS Command Injection!")
    print(f"     └─ Action Required: Avoid shell execution functions or use safe APIs with strict argument arrays.")
else:
    print("  ✅ [SECURE]: All parameters successfully sanitized shell metacharacters.")

print("==========================================")