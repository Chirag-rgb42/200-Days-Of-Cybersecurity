# ==========================================
# Day 84: Automated Mass Assignment Vulnerability Scanner
# Purpose: Practice API vulnerability assessment and detection of unauthorized parameter binding / privilege escalation
# ==========================================

print("=== AUTOMATED MASS ASSIGNMENT VULNERABILITY SCANNER ===")

# Simulated API profile update requests containing standard and sensitive property bindings
api_requests = [
    {
        "endpoint": "/api/v1/profile/update",
        "payload": {"username": "contractor", "email": "bob@example.com"},
        "intended_fields": ["username", "email"]
    },
    {
        "endpoint": "/api/v1/profile/update",
        "payload": {"username": "contractor", "email": "bob@example.com", "is_admin": True},
        "intended_fields": ["username", "email"]
    },
    {
        "endpoint": "/api/v1/settings/preferences",
        "payload": {"theme": "dark", "notifications": True, "role": "superuser"},
        "intended_fields": ["theme", "notifications"]
    },
    {
        "endpoint": "/api/v1/settings/preferences",
        "payload": {"theme": "light", "notifications": False},
        "intended_fields": ["theme", "notifications"]
    }
]

# Sensitive attributes that should never be modifiable via standard user input binding
sensitive_attributes = ["is_admin", "role", "permissions", "account_balance", "verified"]

def scan_for_mass_assignment(requests):
    print("[*] Initiating automated Mass Assignment vulnerability scan across API payloads...\n")
    mass_assignment_alerts = 0
    
    for req in requests:
        endpoint = req["endpoint"]
        payload = req["payload"]
        
        print(f"[-] Testing Endpoint: {endpoint}")
        print(f"    └─ Submitted Payload Keys: {list(payload.keys())}")
        
        # Check if any payload keys match sensitive un-intended attributes
        injected_sensitive_fields = [key for key in payload.keys() if key in sensitive_attributes]
        
        if injected_sensitive_fields:
            mass_assignment_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential Mass Assignment / Over-Binding Flaw!")
            print(f"     └─ Risk: Unrestricted model binding accepted unauthorized sensitive keys: {injected_sensitive_fields}\n")
        else:
            print(f"  ✅ [SECURE]: Payload only contains permitted model properties.\n")
            
    return mass_assignment_alerts

# Run the mass assignment vulnerability scan
total_vulnerabilities = scan_for_mass_assignment(api_requests)

print("--- MASS ASSIGNMENT ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to Mass Assignment!")
    print(f"     └─ Action Required: Enforce strict Data Transfer Object (DTO) schemas and explicit property whitelisting.")
else:
    print("  ✅ [SECURE]: All API update payloads successfully validated.")

print("==========================================")