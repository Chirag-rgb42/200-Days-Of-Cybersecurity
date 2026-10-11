# ==========================================
# Day 85: Automated Rate Limiting & Brute-Force Vulnerability Scanner
# Purpose: Practice API security assessment by detecting lack of rate limiting on sensitive auth endpoints
# ==========================================

print("=== AUTOMATED RATE LIMITING & BRUTE-FORCE SCANNER ===")

# Simulated authentication endpoints and burst request traffic test results
endpoint_tests = [
    {
        "endpoint": "/api/v1/auth/login",
        "request_count": 100,
        "time_window_seconds": 5,
        "response_status_codes": [200, 200, 200, 200, 200] # Vulnerable: No 429 encountered!
    },
    {
        "endpoint": "/api/v1/auth/password-reset",
        "request_count": 50,
        "time_window_seconds": 2,
        "response_status_codes": [200, 429, 429, 429, 429] # Secure: Rate-limited after initial attempts
    },
    {
        "endpoint": "/api/v1/mfa/verify",
        "request_count": 200,
        "time_window_seconds": 10,
        "response_status_codes": [200, 200, 200, 200, 200] # Vulnerable: Allows unlimited brute-forcing of PINs/OTPs!
    }
]

def scan_for_rate_limiting(tests):
    print("[*] Initiating rapid-fire burst request simulation to test rate-limiting controls...\n")
    vulnerability_alerts = 0
    
    for test in tests:
        ep = test["endpoint"]
        count = test["request_count"]
        statuses = test["response_status_codes"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Burst Traffic Sent: {count} requests in {test['time_window_seconds']}s")
        
        # Check if 429 Too Many Requests or equivalent blocking status appears
        rate_limited = any(status == 429 for status in statuses)
        
        if not rate_limited:
            vulnerability_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Missing Rate Limiting / Brute-Force Protection!")
            print(f"     └─ Risk: Server accepted {count} rapid requests without issuing HTTP 429 or locking out.\n")
        else:
            print(f"  ✅ [SECURE]: Rate limiting enforced successfully (HTTP 429 received).\n")
            
    return vulnerability_alerts

# Run the rate limiting scan
total_vulnerabilities = scan_for_rate_limiting(endpoint_tests)

print("--- RATE LIMITING ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to high-speed brute-force attacks!")
    print(f"     └─ Action Required: Implement IP/account-based rate limiting, throttling, and CAPTCHA mechanisms.")
else:
    print("  ✅ [SECURE]: All auth endpoints protected against brute-force flooding.")

print("==========================================")