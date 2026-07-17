# ==========================================
# Day 3: Password Strength Checker
# Purpose: Practice conditional logic (if/elif/else) and len()
# ==========================================

print("=== PASSWORD SECURITY EVALUATOR ===")

user_password = input("Enter a password to test: ")

password_length = len(user_password)

if password_length < 8:
    print("\n❌ Security Status: WEAK")
    print("⚠️ Critical Warning: Passwords must be at least 8 characters long to prevent brute-force attacks.")

elif password_length >= 8 and password_length < 14:
    print("\n⚠️ Security Status: MEDIUM")
    print("💡 Advice: Good start, but adding more characters or special symbols makes it much safer.")

else:
    print("\n✅ Security Status: STRONG")
    print("🔒 Excellent! Long passwords are exponentially harder for hackers to crack.")

print(f"\n[Debug Info: Your password contains {password_length} characters]")
print("====================================")