# ==========================================
# Day 94: Automated HTTP Parameter Pollution (HPP) Vulnerability Scanner
# Purpose: Practice web application security assessment by detecting duplicate parameter parsing discrepancies
# ==========================================

print("=== AUTOMATED HTTP PARAMETER POLLUTION SCANNER ===")

# Simulated web application query parameters and multi-value request tests
hpp_test_payloads = [
    {
        "endpoint": "/api/v1/user/search",
        "parameter": "query",
        "submitted_values": ["admin", "guest"], # Duplicate parameter injection test
        "backend_behavior": "array"             # Vulnerable: Backend processes array or concatenates values unexpectedly
    },
    {
        "endpoint": "/api/v1/transfer",
        "parameter": "amount",
        "submitted_values": ["100", "5000"],
        "backend_behavior": "last"              # Overrides first parameter value with second!
    },
    {
        "endpoint": "/api/v1/profile/view",
        "parameter": "id",
        "submitted_values": ["1042"],
        "backend_behavior": "strict"            # Secure: Single parameter validated properly
    },
    {
        "endpoint": "/api/v1/report/generate",
        "parameter": "format",
        "submitted_values": ["pdf", "exec"],
        "backend_behavior": "concatenation"     # Vulnerable: Combines parameters into execution string!
    }
]

def scan_for_hpp(payloads):
    print("[*] Initiating automated HTTP Parameter Pollution (HPP) scan across endpoints...\n")
    hpp_alerts = 0
    
    for test in payloads:
        ep = test["endpoint"]
        param = test["parameter"]
        vals = test["submitted_values"]
        behavior = test["backend_behavior"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Parameter: {param}")
        print(f"    └─ Submitted Duplicate Values: {vals}")
        
        # Check if backend exhibits vulnerable HPP parsing behavior when multiple values are sent
        is_vulnerable = len(vals) > 1 and behavior in ["array", "last", "concatenation"]
        
        if is_vulnerable:
            hpp_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: HTTP Parameter Pollution (HPP) Flaw!")
            print(f"     └─ Risk: Backend parser resolves duplicate parameters using '{behavior}' logic, risking filter bypass or logic corruption.\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint handles parameter values securely without duplication risk.\n")
            
    return hpp_alerts

# Run the HPP vulnerability scan
total_vulnerabilities = scan_for_hpp(hpp_test_payloads)

print("--- HPP ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to HTTP Parameter Pollution!")
    print(f"     └─ Action Required: Enforce strict single-value parameter validation and normalize incoming query strings.")
else:
    print("  ✅ [SECURE]: All endpoints passed parameter parsing verification.")

print("==========================================")