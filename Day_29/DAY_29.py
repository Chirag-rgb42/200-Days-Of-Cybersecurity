# ==========================================
# Day 29: Cross-Site Scripting (XSS) Pattern Detector
# Purpose: Practice input sanitization and XSS vulnerability detection concepts
# ==========================================

import re

print("=== CROSS-SITE SCRIPTING (XSS) PATTERN DETECTOR ===")

# Common XSS patterns / signatures used in malicious input payloads
xss_patterns = [
    r"<script.*?>.*?</script.*?>", # Basic script tags
    r"javascript:",                # JavaScript URI scheme
    r"onerror\s*=",                # Event handler injection
    r"onload\s*=",                 # Event handler injection
    r"<img.*?src.*?=.*?>",         # Suspicious image execution vectors
]

def scan_for_xss(user_input):
    print(f"[*] Analyzing user input for XSS: '{user_input}'")
    
    for pattern in xss_patterns:
        # Search for pattern match case-insensitively
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
            
    return False

# Simulated form inputs to test against our security filter
test_inputs = [
    "Hello, welcome to my website!",
    "<script>alert('XSS Attack!')</script>",
    "Check out this link: javascript:alert(1)",
    "<img src=x onerror=alert('XSS')>"
]

print("\n--- RUNNING INPUT SECURITY AUDIT ---")
for text in test_inputs:
    is_malicious = scan_for_xss(text)
    if is_malicious:
        print(f"  🚨 [ALERT]: Potential Cross-Site Scripting (XSS) pattern detected!\n")
    else:
        print(f"  ✅ [SAFE]: Input passed validation checks.\n")

print("==========================================")