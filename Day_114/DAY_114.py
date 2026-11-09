# ==========================================
# Day 114: Automated Active Directory AD CS ESC8 Vulnerability Auditor
# Purpose: Practice enterprise AD security assessment by detecting unencrypted AD CS Web Enrollment endpoints vulnerable to NTLM relay (ESC8)
# ==========================================

print("=== AUTOMATED AD CS ESC8 VULNERABILITY AUDITOR ===")

# Simulated AD CS web enrollment endpoints across domain servers
ad_cs_web_endpoints = [
    {
        "server_name": "PKI-CA01.corp.local",
        "service_path": "/certsrv/",
        "http_enabled": True,             # Vulnerable: Plaintext HTTP allows NTLM interception!
        "https_enforced": False,          # Vulnerable: HTTPS not strictly required
        "extended_protection_active": False # Vulnerable: EPA disabled
    },
    {
        "server_name": "PKI-CA02.corp.local",
        "service_path": "/certsrv/",
        "http_enabled": False,            # Secure: HTTP disabled, HTTPS only
        "https_enforced": True,           # Secure: HTTPS strictly enforced
        "extended_protection_active": True  # Secure: EPA active against NTLM relay
    },
    {
        "server_name": "ENROLLSRV01.corp.local",
        "service_path": "/certservices/",
        "http_enabled": True,
        "https_enforced": False,
        "extended_protection_active": False
    }
]

def audit_ad_cs_esc8(endpoints):
    print("[*] Initiating AD CS Web Enrollment ESC8 vulnerability audit...\n")
    esc8_alerts = 0
    
    for endpoint in endpoints:
        sname = endpoint["server_name"]
        path = endpoint["service_path"]
        http = endpoint["http_enabled"]
        https = endpoint["https_enforced"]
        epa = endpoint["extended_protection_active"]
        
        print(f"[-] Auditing Enrollment Server: {sname} ({path})")
        print(f"    ├─ HTTP Enabled (Unencrypted Port 80): {http}")
        print(f"    ├─ HTTPS Enforced: {https}")
        print(f"    └─ Extended Protection for Auth (EPA): {epa}")
        
        # Check for ESC8 Vulnerability Criteria (HTTP enabled or missing EPA)
        if http or not epa:
            esc8_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: AD CS ESC8 NTLM Relay Risk!")
            print(f"     └─ Risk: Web enrollment accepts unencrypted HTTP or lacks EPA, allowing attackers to coerce machine authentication and relay NTLM for certificate generation.\n")
        else:
            print(f"  ✅ [SECURE]: Web enrollment endpoint is hardened with HTTPS and EPA enforcement.\n")
            
    return esc8_alerts

# Run the ESC8 audit scan
total_vulnerabilities = audit_ad_cs_esc8(ad_cs_web_endpoints)

print("--- AD CS ESC8 ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} AD CS web endpoint(s) vulnerable to ESC8 NTLM relay!")
    print(f"     └─ Action Required: Disable HTTP bindings on IIS Web Enrollment, enforce HTTPS with TLS, and enable Extended Protection for Authentication (EPA).")
else:
    print("  ✅ [SECURE]: All AD CS web enrollment endpoints passed ESC8 security verification.")

print("==========================================")