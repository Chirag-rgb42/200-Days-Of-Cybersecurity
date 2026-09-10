# ==========================================
# Day 54: Cloud Security Group & Firewall Ingress Auditor
# Purpose: Practice cloud security and detection of overly permissive inbound firewall rules
# ==========================================

print("=== CLOUD SECURITY GROUP INGRESS AUDITOR ===")

# Simulated cloud security group rules (JSON format)
security_groups = [
    {
        "group_name": "web-server-sg",
        "rules": [
            {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_ip": "0.0.0.0/0"},
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ip": "0.0.0.0/0"}
        ]
    },
    {
        "group_name": "database-internal-sg",
        "rules": [
            {"protocol": "tcp", "from_port": 3306, "to_port": 3306, "cidr_ip": "10.0.0.0/16"}
        ]
    },
    {
        "group_name": "management-bastion-sg",
        "rules": [
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ip": "0.0.0.0/0"}, # Dangerous! SSH open to world
            {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ip": "0.0.0.0/0"} # Dangerous! RDP open to world
        ]
    }
]

# Sensitive ports that should never be exposed globally to 0.0.0.0/0
sensitive_ports = [22, 3389, 3306, 5432, 27017]

def audit_security_groups(groups, restricted_ports):
    print("[*] Auditing cloud security group firewall rules for ingress exposure...\n")
    violations = 0
    
    for sg in groups:
        group_name = sg["group_name"]
        rules = sg["rules"]
        
        group_has_risk = False
        for rule in rules:
            port = rule["from_port"]
            cidr = rule["cidr_ip"]
            
            # Check if a sensitive port is exposed to the entire internet (0.0.0.0/0)
            if port in restricted_ports and cidr == "0.0.0.0/0":
                violations += 1
                group_has_risk = True
                print(f"  🚨 [EXPOSURE ALERT]: Security Group '{group_name}' has high-risk ingress rule!")
                print(f"     ├─ Sensitive Port: {port}")
                print(f"     └─ Exposed CIDR: {cidr} (Open to the public internet)\n")
                
        if not group_has_risk:
            print(f"  ✅ [SECURE]: Security Group '{group_name}' follows safe network access baselines.")
            
    return violations

# Run the firewall security audit
total_violations = audit_security_groups(security_groups, sensitive_ports)

print("\n--- CLOUD FIREWALL AUDIT SUMMARY ---")
if total_violations > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_violations} risky firewall ingress rule(s)!")
    print(f"     └─ Action Required: Restrict CIDR ranges to trusted IP blocks (e.g., VPN or office IPs).")
else:
    print("  ✅ [SECURE]: All cloud security group ingress rules are properly restricted.")

print("==========================================")