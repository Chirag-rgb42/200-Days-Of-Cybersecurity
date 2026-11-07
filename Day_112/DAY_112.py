# ==========================================
# Day 112: Automated Active Directory LSA Protection & Credential Guard Auditor
# Purpose: Practice enterprise AD security assessment by verifying host-level LSASS memory protections and Credential Guard status
# ==========================================

print("=== AUTOMATED AD LSA PROTECTION & CREDENTIAL GUARD AUDITOR ===")

# Simulated Windows domain endpoints and host security configurations
domain_endpoints = [
    {
        "hostname": "DC01.corp.local",
        "device_type": "Domain Controller",
        "lsa_protection_enabled": True,  # Protected Process Light (RunAsPPL) enabled
        "credential_guard_active": True, # VBS Credential Guard active
        "vbs_enabled": True
    },
    {
        "hostname": "FINANCE-PC04",
        "device_type": "Workstation",
        "lsa_protection_enabled": False, # Vulnerable: LSA Protection disabled (LSASS memory readable!)
        "credential_guard_active": False, # Vulnerable: Credential Guard inactive
        "vbs_enabled": True
    },
    {
        "hostname": "EXEC-LAPTOP01",
        "device_type": "Workstation",
        "lsa_protection_enabled": True,
        "credential_guard_active": True,
        "vbs_enabled": True
    },
    {
        "hostname": "LEGACY-SRV02",
        "device_type": "Member Server",
        "lsa_protection_enabled": False, # Vulnerable: Missing LSASS protection
        "credential_guard_active": False,
        "vbs_enabled": False             # Legacy hardware lacking VBS support
    }
]

def audit_host_credential_protections(endpoints):
    print("[*] Initiating domain host credential isolation audit...\n")
    host_alerts = 0
    
    for host in endpoints:
        hname = host["hostname"]
        htype = host["device_type"]
        lsa_ppl = host["lsa_protection_enabled"]
        cred_guard = host["credential_guard_active"]
        vbs = host["vbs_enabled"]
        
        print(f"[-] Auditing Endpoint: {hname} ({htype})")
        print(f"    ├─ Virtualization-Based Security (VBS): {vbs}")
        print(f"    ├─ LSA Protection (RunAsPPL): {lsa_ppl}")
        print(f"    └─ Windows Defender Credential Guard: {cred_guard}")
        
        # Check for missing LSASS defenses
        if not lsa_ppl or not cred_guard:
            host_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Inadequate Credential Isolation!")
            print(f"     └─ Risk: Endpoint lacks LSA Protection or Credential Guard, leaving LSASS memory exposed to dumping attacks (Mimikatz/ProcDump).\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint has active LSASS protection and Credential Guard enabled.\n")
            
    return host_alerts

# Run the host security audit
total_vulnerabilities = audit_host_credential_protections(domain_endpoints)

print("--- CREDENTIAL ISOLATION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) missing host credential protections!")
    print(f"     └─ Action Required: Enable `RunAsPPL=1` via GPO/Intune, enforce Virtualization-Based Security (VBS), and enable Credential Guard domain-wide.")
else:
    print("  ✅ [SECURE]: All audited endpoints passed LSA Protection and Credential Guard compliance.")

print("==========================================")