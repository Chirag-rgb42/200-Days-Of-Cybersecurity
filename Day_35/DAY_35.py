# ==========================================
# Day 35: GitHub Actions CI/CD Workflow Security Auditor
# Purpose: Practice CI/CD pipeline security and automated YAML configuration checks
# ==========================================

print("=== GITHUB ACTIONS CI/CD WORKFLOW SECURITY AUDITOR ===")

# Simulated GitHub Actions YAML workflow configuration content
workflow_content = """
name: CI Pipeline
on:
  pull_request_target:
    branches: [ main ]
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      - name: Run build step
        run: |
          echo "Building application..."
          echo ${{ secrets.PROD_API_KEY }}
"""

def audit_workflow(content):
    print("[*] Auditing CI/CD workflow configurations for security risks...\n")
    risks = 0
    
    # Check for risky pull_request_target trigger
    if "pull_request_target:" in content:
        risks += 1
        print("  🚨 [HIGH RISK]: Workflow uses the 'pull_request_target' trigger.")
        print("     └─ Recommendation: Can lead to remote code execution vulnerabilities if handling untrusted PRs.\n")
        
    # Check for direct secret reference inside run steps
    if "${{ secrets." in content and "run:" in content:
        risks += 1
        print("  ⚠️ [WARNING]: Direct secret expansion inside a shell 'run' command block.")
        print("     └─ Recommendation: Pass secrets as environment variables (`env:`) instead of direct string expansion.\n")
        
    return risks

# Run the workflow security audit
total_risks = audit_workflow(workflow_content)

if total_risks > 0:
    print(f"Audit Summary: Found {total_risks} security risk(s) in the CI/CD pipeline configuration.")
else:
    print("Audit Summary: Workflow configuration meets security best practices.")

print("==========================================")