# ==========================================
# Day 86: Automated Business Logic Flaw & Workflow Bypass Scanner
# Purpose: Practice web application vulnerability assessment by detecting step-bypass and state-manipulation flaws
# ==========================================

print("=== AUTOMATED BUSINESS LOGIC WORKFLOW SCANNER ===")

# Simulated multi-step web application workflows and request sequences
workflow_tests = [
    {
        "workflow_name": "E-Commerce Checkout",
        "target_endpoint": "/api/v1/checkout/complete-order",
        "prerequisites_completed": ["cart_populated", "shipping_selected", "payment_processed"],
        "direct_access_attempt": True
    },
    {
        "workflow_name": "Premium Subscription Upgrade",
        "target_endpoint": "/api/v1/subscription/activate-pro",
        "prerequisites_completed": ["cart_populated"], # Vulnerable: Skipped payment step!
        "direct_access_attempt": True
    },
    {
        "workflow_name": "Password Reset Flow",
        "target_endpoint": "/api/v1/auth/update-new-password",
        "prerequisites_completed": ["email_verified", "otp_confirmed"],
        "direct_access_attempt": True
    }
]

def scan_workflow_bypasses(tests):
    print("[*] Initiating workflow analysis to test for business logic step-bypasses...\n")
    logic_flaw_alerts = 0
    
    for test in tests:
        name = test["workflow_name"]
        endpoint = test["target_endpoint"]
        prereqs = test["prerequisites_completed"]
        
        print(f"[-] Testing Workflow: {name}")
        print(f"    ├─ Target Endpoint: {endpoint}")
        print(f"    └─ Completed Prerequisites: {prereqs}")
        
        # Define mandatory prerequisite requirements per workflow type
        is_flawed = False
        if "Checkout" in name and "payment_processed" not in prereqs:
            is_flawed = True
        elif "Subscription" in name and "payment_processed" not in prereqs:
            is_flawed = True
            
        if is_flawed:
            logic_flaw_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Business Logic Workflow Bypass!")
            print(f"     └─ Risk: Endpoint allowed state progression without completing mandatory payment/validation steps.\n")
        else:
            print(f"  ✅ [SECURE]: Workflow properly enforces all sequential prerequisites.\n")
            
    return logic_flaw_alerts

# Run the business logic workflow scan
total_vulnerabilities = scan_workflow_bypasses(workflow_tests)

print("--- BUSINESS LOGIC ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} workflow(s) vulnerable to business logic bypass!")
    print(f"     └─ Action Required: Enforce strict server-side state machines and session state validation across all steps.")
else:
    print("  ✅ [SECURE]: All multi-step workflows successfully verified.")

print("==========================================")