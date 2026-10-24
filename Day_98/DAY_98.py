# ==========================================
# Day 98: Automated Race Condition & TOCTOU Vulnerability Scanner
# Purpose: Practice web application concurrency assessment by detecting race conditions in transactional endpoints
# ==========================================

import threading
import time

print("=== AUTOMATED RACE CONDITION SCANNER ===")

# Simulated transactional endpoints and concurrent request tests
concurrency_tests = [
    {
        "endpoint": "/api/v1/coupon/redeem",
        "action": "Single-use discount code reuse",
        "concurrent_threads": 10,
        "successful_responses": 10, # Vulnerable: All 10 threads redeemed the single-use coupon!
        "is_atomic": False
    },
    {
        "endpoint": "/api/v1/wallet/withdraw",
        "action": "Balance withdrawal overdraw",
        "concurrent_threads": 5,
        "successful_responses": 5,  # Vulnerable: Allowed multiple withdrawals exceeding balance!
        "is_atomic": False
    },
    {
        "endpoint": "/api/v1/tickets/purchase",
        "action": "Limited inventory checkout",
        "concurrent_threads": 20,
        "successful_responses": 1,  # Secure: Database locking prevented over-selling!
        "is_atomic": True
    }
]

def scan_for_race_conditions(tests):
    print("[*] Initiating multi-threaded concurrency simulation across transactional endpoints...\n")
    race_alerts = 0
    
    for test in tests:
        ep = test["endpoint"]
        action = test["action"]
        threads = test["concurrent_threads"]
        successes = test["successful_responses"]
        atomic = test["is_atomic"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Action Type: {action}")
        print(f"    ├─ Concurrent Threads Fired: {threads}")
        print(f"    └─ Successful Concurrent Responses: {successes}")
        
        # Check if multiple concurrent requests succeeded on single-state resources
        if not atomic and successes > 1:
            race_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Race Condition / TOCTOU Flaw!")
            print(f"     └─ Risk: Endpoint processed {successes} concurrent requests without database locking, allowing state corruption.\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint properly enforces atomic database transactions and locking.\n")
            
    return race_alerts

# Run the race condition vulnerability scan
total_vulnerabilities = scan_for_race_conditions(concurrency_tests)

print("--- RACE CONDITION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} workflow(s) vulnerable to Race Conditions!")
    print(f"     └─ Action Required: Implement database-level row locking (`SELECT ... FOR UPDATE`), ACID transactions, and atomic state checks.")
else:
    print("  ✅ [SECURE]: All concurrent transaction workflows passed safety verification.")

print("==========================================")