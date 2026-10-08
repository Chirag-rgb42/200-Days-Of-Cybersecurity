# ==========================================
# Day 82: Automated JWT Vulnerability & Weak Secret Auditor
# Purpose: Practice API vulnerability assessment and detection of weak JWT signing keys & algorithm flaws
# ==========================================

print("=== AUTOMATED JWT VULNERABILITY AUDITOR ===")

# Simulated JWT tokens captured from different API endpoints
jwt_samples = [
    {
        "endpoint": "/api/v1/login",
        "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4if.,",
        "algorithm": "none",
        "secret_used": None
    },
    {
        "endpoint": "/api/v1/dashboard",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY29udHJhY3RvciIsImlkIjo0Mn0.signature_abc123",
        "algorithm": "HS256",
        "secret_used": "secret"  # Weak default secret!
    },
    {
        "endpoint": "/api/v1/settings",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpZCI6MX0.signature_xyz987",
        "algorithm": "HS256",
        "secret_used": "SuperSecureComplexCryptographicKey2026!" # Strong secret
    }
]

# Common weak secrets wordlist used in brute-force checks
weak_secrets_wordlist = ["secret", "password123", "admin", "123456", "jwt_secret"]

def audit_jwt_security(samples):
    print("[*] Initiating automated JWT structure and signature security audit...\n")
    jwt_alerts = 0
    
    for sample in samples:
        endpoint = sample["endpoint"]
        algo = sample["algorithm"]
        secret = sample["secret_used"]
        
        print(f"[-] Auditing Endpoint: {endpoint}")
        print(f"    ├─ Algorithm Header: {algo}")
        
        # Check 1: Unsecured 'none' algorithm check
        if algo.lower() == "none":
            jwt_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Insecure JWT Algorithm!")
            print(f"     └─ Risk: Algorithm is set to 'none'. Signature verification is bypassed entirely.\n")
            continue
            
        # Check 2: Weak symmetric secret check
        if algo.upper() == "HS256" and secret in weak_secrets_wordlist:
            jwt_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Weak JWT Signing Secret!")
            print(f"     └─ Risk: Token signed with easily guessable secret '{secret}'. Attackers can forge tokens.\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint uses robust algorithm and strong secret key.\n")
            
    return jwt_alerts

# Run the JWT security audit
total_vulnerabilities = audit_jwt_security(jwt_samples)

print("--- JWT AUDIT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} insecure JWT configuration(s)!")
    print(f"     └─ Action Required: Enforce strict algorithm whitelisting (disable 'none') and use high-entropy secrets.")
else:
    print("  ✅ [SECURE]: All JWT tokens passed cryptographic verification.")

print("==========================================")