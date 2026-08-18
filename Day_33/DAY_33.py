# ==========================================
# Day 33: Server Configuration Compliance Auditor
# Purpose: Practice infrastructure hardening and automated security configuration checks
# ==========================================

print("=== SERVER CONFIGURATION COMPLIANCE AUDITOR ===")

# Simulated server configuration settings to audit
server_config = {
    "root_login": "enabled",
    "firewall_status": "inactive",
    "ssh_port": 22,
    "allow_password_auth": "yes",
    "ssl_tls_version": "TLSv1.0"
}

# Security hardening rules / baselines
security_baseline = {
    "root_login": {"expected": "disabled", "risk": "High: Root login should be disabled"},
    "firewall_status": {"expected": "active", "risk": "High: Firewall must be active"},
    "allow_password_auth": {"expected": "no", "risk": "Medium: Use SSH keys instead of passwords"},
    "ssl_tls_version": {"expected": "TLSv1.2", "risk": "High: Outdated TLS version exposes traffic"}
}

def audit_configuration(config, baseline):
    print("[*] Auditing server configuration settings against security baseline...\n")
    violations = 0
    
    for setting, rule in baseline.items():
        current_value = config.get(setting)
        expected_value = rule["expected"]
        
        if current_value != expected_value:
            violations += 1
            print(f"  ❌ [MISCONFIGURATION]: '{setting}' is set to '{current_value}'")
            print(f"     └─ Risk & Fix: {rule['risk']} (Expected: {expected_value})\n")
        else:
            print(f"  ✅ [COMPLIANT]: '{setting}' meets baseline requirements ('{current_value}').\n")
            
    return violations

# Run the compliance audit
total_violations = audit_configuration(server_config, security_baseline)

if total_violations > 0:
    print(f"Audit Summary: Found {total_violations} configuration violation(s) requiring remediation.")
else:
    print("Audit Summary: All configuration settings are compliant.")

print("==========================================")