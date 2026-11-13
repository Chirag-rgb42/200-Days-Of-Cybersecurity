# ==========================================
# Day 118: Automated Active Directory SMB Signing & NTLM Relay Posture Auditor
# Purpose: Practice enterprise AD security assessment by verifying mandatory SMB signing and legacy SMBv1 status across domain hosts
# ==========================================

print("=== AUTOMATED AD SMB SIGNING & NTLM RELAY AUDITOR ===")

# Simulated Windows domain hosts and SMB security configurations
smb_audit_hosts = [
    {
        "hostname": "DC01.corp.local",
        "role": "Domain Controller",
        "smb_signing_required": True,  # Default on DCs: Enforced
        "smbv1_enabled": False
    },
    {
        "hostname": "FILESVR-FINANCE01",
        "role": "Member File Server",
        "smb_signing_required": False, # Vulnerable: Optional SMB signing allows NTLM relay attacks!
        "smbv1_enabled": False
    },
    {
        "hostname": "HR-DESKTOP08",
        "role": "Workstation",
        "smb_signing_required": False, # Vulnerable: Targetable for SMB relay
        "smbv1_enabled": True          # Vulnerable: Legacy SMBv1 protocol active!
    },
    {
        "hostname": "SEC-JUMPBOX01",
        "role": "Hardened Admin Workstation",
        "smb_signing_required": True,
        "smbv1_enabled": False
    }
]

def audit_smb_posture(hosts):
    print("[*] Initiating domain SMB signing and protocol security audit...\n")
    smb_alerts = 0
    
    for host in hosts:
        hname = host["hostname"]
        role = host["role"]
        signing = host["smb_signing_required"]
        smbv1 = host["smbv1_enabled"]
        
        print(f"[-] Auditing Host: {hname} ({role})")
        print(f"    ├─ SMB Signing Required (Enforced): {signing}")
        print(f"    └─ Legacy SMBv1 Enabled: {smbv1}")
        
        # Check for missing mandatory SMB signing or active SMBv1
        if not signing or smbv1:
            smb_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Insecure SMB Configuration!")
            if not signing:
                print(f"     └─ Risk: SMB signing is not required; host is vulnerable to NTLM relay attacks.")
            if smbv1:
                print(f"     └─ Risk: Legacy SMBv1 protocol is enabled, exposing the host to downgrade and remote execution exploits.")
            print()
        else:
            print(f"  ✅ [SECURE]: Mandatory SMB signing is enforced and SMBv1 is disabled.\n")
            
    return smb_alerts

# Run the SMB security audit
total_vulnerabilities = audit_smb_posture(smb_audit_hosts)

print("--- SMB SECURITY ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} domain host(s) with insecure SMB configurations!")
    print(f"     └─ Action Required: Enable 'Microsoft network server: Digitally sign communications (always)' via GPO and disable SMBv1 domain-wide.")
else:
    print("  ✅ [SECURE]: All audited domain hosts enforce SMB signing and disable SMBv1.")

print("==========================================")