# ==========================================
# Day 96: Automated Prototype Pollution Vulnerability Scanner
# Purpose: Practice API vulnerability assessment by detecting unsafe object merging and prototype injection flaws
# ==========================================

print("=== AUTOMATED PROTOTYPE POLLUTION SCANNER ===")

# Simulated API JSON payloads and object merge requests
prototype_test_payloads = [
    {
        "endpoint": "/api/v1/user/settings",
        "payload": {"theme": "dark", "notifications": True},
        "target_keys": ["theme", "notifications"]
    },
    {
        "endpoint": "/api/v1/profile/update",
        "payload": {"__proto__": {"isAdmin": True, "role": "superuser"}}, # Malicious prototype pollution payload!
        "target_keys": ["__proto__", "constructor"]
    },
    {
        "endpoint": "/api/v1/preferences",
        "payload": {"constructor": {"prototype": {"polluted": True}}}, # Alternative gadget payload
        "target_keys": ["__proto__", "constructor"]
    },
    {
        "endpoint": "/api/v1/feedback",
        "payload": {"comment": "Great platform!", "rating": 5},
        "target_keys": ["__proto__", "constructor"]
    }
]

# Sensitive prototype-polluting property keys that should never be processed in user input
pollution_keys = ["__proto__", "constructor", "prototype"]

def scan_for_prototype_pollution(payloads):
    print("[*] Initiating automated Prototype Pollution scan across API payloads...\n")
    pollution_alerts = 0
    
    for test in payloads:
        ep = test["endpoint"]
        payload = test["payload"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    └─ Payload Keys Submitted: {list(payload.keys())}")
        
        # Check if any top-level or nested keys attempt to access prototype chains
        is_polluted = any(key in pollution_keys for key in payload.keys())
        
        # Also check nested dictionaries for __proto__ injection
        for k, v in payload.items():
            if isinstance(v, dict):
                if any(sub_key in pollution_keys for sub_key in v.keys()):
                    is_polluted = True
                    
        if is_polluted:
            pollution_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Prototype Pollution Flaw!")
            print(f"     └─ Risk: Payload attempts to manipulate global JavaScript prototype objects via unsafe keys.\n")
        else:
            print(f"  ✅ [SECURE]: Payload contains standard properties without prototype access vectors.\n")
            
    return pollution_alerts

# Run the prototype pollution vulnerability scan
total_vulnerabilities = scan_for_prototype_pollution(prototype_test_payloads)

print("--- PROTOTYPE POLLUTION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} payload(s) vulnerable to Prototype Pollution!")
    print(f"     └─ Action Required: Freeze object prototypes (Object.freeze), use Map structures, or sanitize recursive merge functions.")
else:
    print("  ✅ [SECURE]: All API payloads passed prototype safety verification.")

print("==========================================")