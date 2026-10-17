# ==========================================
# Day 91: Automated SSL/TLS Certificate & Cipher Auditor
# Purpose: Practice web infrastructure security assessment by auditing TLS versions and certificate validity
# ==========================================

print("=== AUTOMATED SSL/TLS SECURITY AUDITOR ===")

# Simulated target HTTPS endpoints and their TLS configuration properties
target_endpoints = [
    {
        "endpoint": "https://secure.acme-corp.local",
        "tls_version": "TLSv1.3",
        "certificate_expired": False,
        "is_self_signed": False
    },
    {
        "endpoint": "https://legacy-portal.acme-corp.local",
        "tls_version": "TLSv1.0", # Vulnerable: Legacy insecure protocol!
        "certificate_expired": True,  # Vulnerable: Expired certificate!
        "is_self_signed": False
    },
    {
        "endpoint": "https://dev-internal.acme-corp.local",
        "tls_version": "TLSv1.2",
        "certificate_expired": False,
        "is_self_signed": True   # Vulnerable: Self-signed cert in use!
    }
]

def audit_tls_configurations(endpoints):
    print("[*] Initiating automated SSL/TLS security and certificate audit...\n")
    tls_alerts = 0
    
    for target in endpoints:
        ep = target["endpoint"]
        tls = target["tls_version"]
        expired = target["certificate_expired"]
        self_signed = target["is_self_signed"]
        
        print(f"[-] Auditing Endpoint: {ep}")
        print(f"    ├─ Negotiated TLS Version: {tls}")
        print(f"    ├─ Certificate Expired: {expired}")
        print(f"    └─ Self-Signed: {self_signed}")
        
        # Check for TLS vulnerabilities
        is_legacy_tls = tls in ["TLSv1.0", "TLSv1.1"]
        
        if is_legacy_tls or expired or self_signed:
            tls_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: TLS / Certificate Security Flaw!")
            if is_legacy_tls:
                print(f"     └─ Risk: Uses legacy/deprecated protocol ({tls}) vulnerable to downgrade attacks.")
            if expired:
                print(f"     └─ Risk: SSL certificate has expired, triggering browser security warnings.")
            if self_signed:
                print(f"     └─ Risk: Certificate is self-signed rather than issued by a trusted CA.\n")
            print()
        else:
            print(f"  ✅ [SECURE]: Endpoint uses strong TLS configuration and valid certificate.\n")
            
    return tls_alerts

# Run the TLS security audit
total_vulnerabilities = audit_tls_configurations(target_endpoints)

print("--- TLS AUDIT ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) with SSL/TLS security issues!")
    print(f"     └─ Action Required: Upgrade to TLS 1.2/1.3, renew expired certificates, and install trusted CA certificates.")
else:
    print("  ✅ [SECURE]: All endpoints passed cryptographic transport verification.")

print("==========================================")