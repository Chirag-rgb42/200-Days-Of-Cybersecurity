# ==========================================
# Day 78: Automated CORS Misconfiguration Auditor
# Purpose: Practice web vulnerability assessment by auditing unsafe CORS response headers
# ==========================================

print("=== AUTOMATED CORS MISCONFIGURATION AUDITOR ===")

# Simulated target web endpoints and their CORS response header configurations
target_apis = [
    {
        "endpoint": "https://api.secure-bank.local/user",
        "tested_origin": "https://evil-attacker.com",
        "response_headers": {
            "Access-Control-Allow-Origin": "https://secure-bank.local",
            "Access-Control-Allow-Credentials": "true"
        }
    },
    {
        "endpoint": "https://api.vulnerable-portal.local/data",
        "tested_origin": "https://evil-attacker.com",
        "response_headers": {
            "Access-Control-Allow-Origin": "https://evil-attacker.com", # Dangerous: Reflecting arbitrary origin!
            "Access-Control-Allow-Credentials": "true"                  # Dangerous combination with reflected origin!
        }
    },
    {
        "endpoint": "https://api.wildcard-service.local/public",
        "tested_origin": "https://evil-attacker.com",
        "response_headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "false"
        }
    }
]

def audit_cors_misconfigurations(apis):
    print("[*] Auditing web application CORS response headers for trust misconfigurations...\n")
    cors_alerts = 0
    
    for api in apis:
        endpoint = api["endpoint"]
        origin = api["tested_origin"]
        headers = api["response_headers"]
        
        acao = headers.get("Access-Control-Allow-Origin")
        acac = headers.get("Access-Control-Allow-Credentials", "false")
        
        print(f"[-] Testing Endpoint: {endpoint}")
        print(f"    ├─ Injected Origin Header: {origin}")
        print(f"    ├─ Response ACAO: {acao}")
        print(f"    └─ Response ACAC: {acac}")
        
        # Check for dangerous CORS patterns
        is_reflected = (acao == origin)
        is_wildcard_with_creds = (acao == "*" and acac.lower() == "true")
        
        if is_reflected and acac.lower() == "true":
            cors_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Critical CORS Misconfiguration!")
            print(f"     └─ Risk: Arbitrary origin reflected with credentials enabled! Attackers can steal user data.\n")
        elif is_wildcard_with_creds:
            cors_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Invalid CORS Configuration!")
            print(f"     └─ Risk: Wildcard origin '*' combined with credentials enabled.\n")
        else:
            print(f"  ✅ [SECURE]: CORS policy properly restricts cross-origin access.\n")
            
    return cors_alerts

# Run the CORS audit
total_vulnerabilities = audit_cors_misconfigurations(target_apis)

print("--- CORS AUDIT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} dangerous CORS misconfiguration(s)!")
    print(f"     └─ Action Required: Enforce strict white-listing of trusted domains and avoid dynamic origin reflection.")
else:
    print("  ✅ [SECURE]: All endpoints passed CORS header verification.")

print("==========================================")