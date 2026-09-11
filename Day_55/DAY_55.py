# ==========================================
# Day 55: Kubernetes RBAC Privilege Escalation Auditor
# Purpose: Practice container and cloud security by detecting dangerous cluster roles
# ==========================================

print("=== KUBERNETES RBAC PRIVILEGE ESCALATION AUDITOR ===")

# Simulated Kubernetes ClusterRole and Role manifests (JSON/Dict format)
rbac_roles = [
    {
        "role_name": "restricted-reader-role",
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}
        ]
    },
    {
        "role_name": "overly-permissive-admin-role",
        "rules": [
            {"apiGroups": [""], "resources": ["secrets", "pods"], "verbs": ["*"]}
        ]
    },
    {
        "role_name": "deployment-manager-role",
        "rules": [
            {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "create", "update"]}
        ]
    }
]

def audit_kubernetes_rbac(roles):
    print("[*] Auditing Kubernetes RBAC policies for privilege escalation risks...\n")
    escalation_risks = 0
    
    for role in roles:
        role_name = role["role_name"]
        rules = role["rules"]
        
        has_dangerous_privilege = False
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            
            # Check if role grants wildcard verbs (*) on sensitive resources like secrets or pods
            if "*" in verbs and ("secrets" in resources or "*" in resources or "pods" in resources):
                escalation_risks += 1
                has_dangerous_privilege = True
                print(f"  🚨 [PRIVILEGE ESCALATION RISK]: Role '{role_name}' is dangerously permissive!")
                print(f"     ├─ Sensitive Resources: {resources}")
                print(f"     └─ Dangerous Verbs: {verbs} (Wildcard access detected)\n")
                
        if not has_dangerous_privilege:
            print(f"  ✅ [SECURE]: Role '{role_name}' follows least-privilege principles.")
            
    return escalation_risks

# Run the Kubernetes RBAC audit
total_risks = audit_kubernetes_rbac(rbac_roles)

print("\n--- KUBERNETES SECURITY AUDIT SUMMARY ---")
if total_risks > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_risks} dangerous RBAC privilege escalation path(s)!")
    print(f"     └─ Action Required: Restrict verbs and resource scopes in cluster role definitions.")
else:
    print("  ✅ [SECURE]: All Kubernetes roles adhere to security baselines.")

print("==========================================")