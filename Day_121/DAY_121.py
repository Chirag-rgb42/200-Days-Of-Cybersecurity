# ==========================================
# Day 121: Automated CI/CD Pipeline & GitHub Actions Security Auditor
# Purpose: Audit CI/CD workflow definitions for supply chain risks (unpinned actions, broad token permissions, unsafe PR triggers)
# ==========================================

print("=== AUTOMATED CI/CD PIPELINE SECURITY AUDITOR ===")

# Simulated CI/CD GitHub Actions workflow configurations
cicd_workflows = [
    {
        "workflow_name": "production-deploy.yml",
        "trigger": "push",
        "token_permissions": "contents: read",
        "actions_used": [
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11", # Secure: Pinned to full SHA
            "aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502"
        ]
    },
    {
        "workflow_name": "community-pr-preview.yml",
        "trigger": "pull_request_target", # Vulnerable: Runs untrusted PR code with write/secret context!
        "token_permissions": "write-all", # Vulnerable: Overly permissive GITHUB_TOKEN!
        "actions_used": [
            "actions/checkout@v4",         # Vulnerable: Mutable version tag instead of commit SHA!
            "thirdparty/deploy-preview@main" # Vulnerable: Tracks mutable 'main' branch!
        ]
    },
    {
        "workflow_name": "unit-tests.yml",
        "trigger": "pull_request",
        "token_permissions": "read-all",
        "actions_used": [
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            "actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d"
        ]
    }
]

def is_pinned_to_sha(action_ref):
    """Checks if a GitHub Action reference is pinned to a 40-character hex commit SHA."""
    if "@" not in action_ref:
        return False
    ref = action_ref.split("@", 1)[1]
    return len(ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in ref)

def audit_cicd_workflows(workflows):
    print("[*] Initiating CI/CD workflow supply chain security audit...\n")
    pipeline_alerts = 0
    
    for wf in workflows:
        wname = wf["workflow_name"]
        trigger = wf["trigger"]
        perms = wf["token_permissions"]
        actions = wf["actions_used"]
        
        unpinned = [act for act in actions if not is_pinned_to_sha(act)]
        unsafe_trigger = (trigger == "pull_request_target")
        broad_perms = ("write-all" in perms)
        
        print(f"[-] Auditing Workflow: {wname}")
        print(f"    ├─ Trigger Event: {trigger}")
        print(f"    ├─ Token Permissions: {perms}")
        print(f"    └─ Unpinned Third-Party Actions: {len(unpinned)}")
        
        if unpinned or unsafe_trigger or broad_perms:
            pipeline_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Supply Chain / CI/CD Misconfiguration!")
            if unsafe_trigger:
                print(f"     └─ Risk: 'pull_request_target' exposes repository secrets and write tokens to untrusted forks.")
            if broad_perms:
                print(f"     └─ Risk: 'write-all' violates Principle of Least Privilege for GITHUB_TOKEN.")
            if unpinned:
                print(f"     └─ Risk: Mutable action tags detected ({', '.join(unpinned)}). Pin to full 40-char commit SHAs.")
            print()
        else:
            print(f"  ✅ [SECURE]: Workflow enforces SHA pinning, safe triggers, and least-privilege token scopes.\n")
            
    return pipeline_alerts

# Run the CI/CD security audit
total_vulnerabilities = audit_cicd_workflows(cicd_workflows)

print("--- CI/CD PIPELINE ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} CI/CD workflow(s) with supply chain security risks!")
    print(f"     └─ Action Required: Pin all third-party actions to immutable commit SHAs, enforce 'permissions: read-all' by default, and isolate untrusted PR workflows.")
else:
    print("  ✅ [SECURE]: All CI/CD workflows passed supply chain security verification.")

print("==========================================")