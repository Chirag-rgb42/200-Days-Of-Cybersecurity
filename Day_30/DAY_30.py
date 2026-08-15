# ==========================================
# Day 30: Mini All-in-One Web Security Auditor
# Purpose: Milestone project combining SQLi and XSS pattern detection into a unified script
# ==========================================

import re

print("==========================================")
print("=== MINI WEB SECURITY AUDITOR (DAY 30) ===")
print("==========================================\n")

# Module 1: SQL Injection Pattern Detector
def check_sqli(payload):
    sql_patterns = [
        r"(\%27)|(\')",             # Single quote
        r"(\%2D\%2D)|(--)",         # SQL comments
        r"(\bOR\b.*=)",             # Boolean bypass
        r"(\bUNION\b.*\bSELECT\b)"  # Data union extraction
    ]
    for pattern in sql_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

# Module 2: Cross-Site Scripting (XSS) Pattern Detector
def check_xss(payload):
    xss_patterns = [
        r"<script.*?>.*?</script.*?>", # Script tags
        r"javascript:",                # URI scheme
        r"onerror\s*=",                # Event handler
        r"onload\s*="                  # Event handler
    ]
    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

# Simulated application input data stream to audit
test_payloads = [
    "normal_username_01",
    "admin' OR '1'='1",
    "<script>document.location='http://attacker.com'</script>",
    "product_search_laptop",
    "javascript:alert('XSS')"
]

print("[*] Initializing multi-vector security scan...\n")

for index, payload in enumerate(test_payloads, 1):
    print(f"[Scan #{index}] Analyzing input: '{payload}'")
    
    sqli_detected = check_sqli(payload)
    xss_detected = check_xss(payload)
    
    if sqli_detected:
        print("  🚨 [ALERT]: SQL Injection vulnerability pattern identified!")
    elif xss_detected:
        print("  🚨 [ALERT]: Cross-Site Scripting (XSS) vector identified!")
    else:
        print("  ✅ [SECURE]: Input passed all security validation checks.")
    print("-" * 50)

print("\n=== MILESTONE AUDIT COMPLETE ===")