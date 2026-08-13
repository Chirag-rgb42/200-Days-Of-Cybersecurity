# ==========================================
# Day 28: Simple SQL Injection (SQLi) Pattern Detector
# Purpose: Practice input validation and web vulnerability detection concepts
# ==========================================

import re

print("=== SQL INJECTION (SQLi) PATTERN DETECTOR ===")

# Common SQL Injection patterns / signatures used in malicious inputs
sql_patterns = [
    r"(\%27)|(\')",             # Single quote manipulation
    r"(\%2D\%2D)|(--)",         # SQL comment indicators
    r"(\bOR\b.*=)",             # Classic boolean bypass pattern (e.g., OR 1=1)
    r"(\bUNION\b.*\bSELECT\b)", # Data extraction via UNION SELECT
    r"(\bDROP\b.*\bTABLE\b)"    # Destructive commands (DROP TABLE)
]

def scan_for_sql_injection(user_input):
    print(f"[*] Analyzing user input: '{user_input}'")
    
    for pattern in sql_patterns:
        # Search for pattern match case-insensitively
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
            
    return False

# Simulated form inputs to test against our security filter
test_inputs = [
    "john_doe123",
    "admin' OR '1'='1",
    "search_term_laptop",
    "admin'; DROP TABLE users;--"
]

print("\n--- RUNNING INPUT SECURITY AUDIT ---")
for text in test_inputs:
    is_malicious = scan_for_sql_injection(text)
    if is_malicious:
        print(f"  🚨 [ALERT]: Potential SQL Injection pattern detected!\n")
    else:
        print(f"  ✅ [SAFE]: Input passed validation checks.\n")

print("==========================================")