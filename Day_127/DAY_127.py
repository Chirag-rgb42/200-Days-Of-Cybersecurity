# ==========================================
# Day 127: Automated JWT (JSON Web Token) Security & Configuration Auditor
# Purpose: Decode and audit JWT structures and API verification policies for 'alg: none', weak secrets, and missing claims
# ==========================================

import base64
import json
import time

print("=== AUTOMATED JWT SECURITY & CONFIGURATION AUDITOR ===")

def base64url_encode(data_dict):
    raw = json.dumps(data_dict, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")

def base64url_decode(segment):
    padding = "=" * ((4 - len(segment) % 4) % 4)
    decoded = base64.urlsafe_b64decode(segment + padding)
    return json.loads(decoded.decode("utf-8"))

# Construct sample JWTs representing different API service configurations
current_ts = int(time.time())

token_secure = (
    f"{base64url_encode({'alg': 'RS256', 'typ': 'JWT'})}."
    f"{base64url_encode({'sub': 'usr_8841', 'role': 'analyst', 'iss': 'auth.corp.local', 'aud': 'billing-api', 'exp': current_ts + 900})}."
    "ValidAsymmetricSignatureBytesHere"
)

token_alg_none = (
    f"{base64url_encode({'alg': 'none', 'typ': 'JWT'})}."
    f"{base64url_encode({'sub': 'admin', 'role': 'superadmin'})}."
)

token_weak_hs256 = (
    f"{base64url_encode({'alg': 'HS256', 'typ': 'JWT'})}."
    f"{base64url_encode({'sub': 'usr_1022', 'role': 'user', 'exp': current_ts + 86400 * 365})}."
    "WeakHmacSignatureBytes"
)

api_jwt_samples = [
    {
        "service_name": "Billing Microservice",
        "token": token_secure,
        "enforced_algorithms": ["RS256"],
        "signing_secret_bits": 2048
    },
    {
        "service_name": "Legacy Admin Portal",
        "token": token_alg_none,
        "enforced_algorithms": ["RS256", "none"], # Vulnerable: Permits 'none' algorithm!
        "signing_secret_bits": 0
    },
    {
        "service_name": "Partner Webhook API",
        "token": token_weak_hs256,
        "enforced_algorithms": ["HS256"],
        "signing_secret_bits": 64               # Vulnerable: Short HMAC secret susceptible to brute-force!
    }
]

def audit_jwt_security(samples):
    print("[*] Initiating JWT cryptographic and claim policy audit...\n")
    jwt_alerts = 0

    for item in samples:
        svc = item["service_name"]
        token = item["token"]
        allowed_algs = item["enforced_algorithms"]
        key_bits = item["signing_secret_bits"]

        parts = token.split(".")
        header = base64url_decode(parts[0])
        payload = base64url_decode(parts[1])
        signature = parts[2] if len(parts) > 2 else ""

        alg = header.get("alg", "MISSING")
        findings = []

        # 1. Check for 'alg: none' or empty signature
        if str(alg).lower() == "none" or "none" in [a.lower() for a in allowed_algs] or not signature:
            findings.append("Critical - Unsigned Token ('alg: none'): Attackers can forge arbitrary claims without a signing key.")

        # 2. Check for weak symmetric HMAC secret length
        if alg.startswith("HS") and key_bits < 256:
            findings.append(f"High - Weak HMAC Secret ({key_bits} bits): Symmetric HS256 keys require >= 256 bits to prevent offline cracking.")

        # 3. Check for missing expiration ('exp') or excessive lifetime
        if "exp" not in payload:
            findings.append("High - Missing Expiration ('exp') Claim: Token never expires if intercepted.")
        elif (payload["exp"] - current_ts) > 86400:
            findings.append("Medium - Excessive Token Lifetime: Expiration exceeds 24 hours; enforce short-lived access tokens.")

        # 4. Check for missing issuer ('iss') and audience ('aud') scoping
        if "iss" not in payload or "aud" not in payload:
            findings.append("Medium - Missing 'iss' or 'aud' Claims: Token can be replayed across unintended microservices.")

        print(f"[-] Auditing Service: {svc}")
        print(f"    ├─ Header Algorithm: {alg} (Allowed: {allowed_algs})")
        print(f"    └─ Claims Present: {list(payload.keys())}")

        if findings:
            jwt_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} JWT security issue(s)!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: JWT enforces asymmetric signing, strict expiration, and issuer/audience claims.\n")

    return jwt_alerts

# Run the JWT audit
total_vulnerabilities = audit_jwt_security(api_jwt_samples)

print("--- JWT SECURITY ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} service(s) with vulnerable JWT configurations!")
    print(f"     └─ Action Required: Explicitly reject 'alg: none', enforce strong >=256-bit keys or RS256/ES256, and validate 'exp', 'iss', and 'aud' claims.")
else:
    print("  ✅ [SECURE]: All audited JWT configurations passed cryptographic and claim verification.")

print("==========================================")