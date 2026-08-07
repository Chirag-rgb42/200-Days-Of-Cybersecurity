# ==========================================
# Day 22: Password Strength & Hashing Auditor
# Purpose: Practice input validation, complexity checks, and secure hashing
# ==========================================

import hashlib
import re

print("=== PASSWORD STRENGTH & HASHING AUDITOR ===")

def evaluate_password_strength(password):
    score = 0
    feedback = []

    # Check length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Consider making the password at least 12 characters long.")
    else:
        feedback.append("Password is too short (less than 8 characters).")

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Check for numbers
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Check for special characters
    if re.search(r"[r~`!@#$int^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
    else:
        feedback.append("Add special symbols (e.g., @, #, $, !).")

    return score, feedback

def secure_hash_password(password):
    # Simulate secure hashing using SHA-256 (In production, use bcrypt or Argon2)
    hash_object = hashlib.sha256(password.encode('utf-8'))
    return hash_object.hexdigest()

# --- Test the Auditor ---
test_password = "SecurePassword123!"

print(f"[*] Testing sample password: '{test_password}'")
score, issues = evaluate_password_strength(test_password)

print(f"\n[+] Complexity Score: {score}/6")

if score >= 5:
    print("✅ [STRONG]: Password meets security requirements.")
else:
    print("⚠️ [WEAK]: Password needs improvement.")
    for issue in issues:
        print(f"   -> {issue}")

hashed_value = secure_hash_password(test_password)
print(f"\n[+] Secure Hash Representation (SHA-256):\n    {hashed_value}")
print("==========================================")