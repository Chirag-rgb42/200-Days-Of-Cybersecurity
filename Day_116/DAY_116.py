# ==========================================
# Day 116: Automated Active Directory Domain Trust Auditor
# Purpose: Practice enterprise AD security assessment by auditing domain trusts and detecting missing SID filtering protections
# ==========================================

print("=== AUTOMATED AD DOMAIN TRUST AUDITOR ===")

# Simulated Active Directory domain trust relationships
domain_trusts = [
    {
        "target_domain": "subsidiary.corp.local",
        "trust_type": "Parent-Child (Transitive)",
        "trust_direction": "Bidirectional",
        "sid_filtering_enabled": True,  # Secure: SID filtering blocks cross-domain SID injection
        "selective_authentication": False
    },
    {
        "target_domain": "partner-external.com",
        "trust_type": "External Trust (Non-Transitive)",
        "trust_direction": "Bidirectional",
        "sid_filtering_enabled": False, # Vulnerable: SID filtering disabled on external trust!
        "selective_authentication": False # Vulnerable: Full access allowed across trust boundary
    },
    {
        "target_domain": "acquiredforest.net",
        "trust_type": "Forest Trust (Transitive)",
        "trust_direction": "Inbound",
        "sid_filtering_enabled": True,
        "selective_authentication": True   # Secure: Explicit selective authentication enforced
    }
]

def audit_domain_trusts(trusts):
    print("[*] Initiating Active Directory domain trust configuration audit...\n")
    trust_alerts = 0
    
    for trust in trusts:
        tdomain = trust["target_domain"]
        ttype = trust["trust_type"]
        tdirection = trust["trust_direction"]
        sid_filter = trust["sid_filtering_enabled"]
        selective_auth = trust["selective_authentication"]
        
        print(f"[-] Auditing Trust Relationship: {tdomain}")
        print(f"    ├─ Trust Type: {ttype}")
        print(f"    ├─ Trust Direction: {tdirection}")
        print(f"    ├─ SID Filtering Enabled: {sid_filter}")
        print(f"    └─ Selective Authentication: {selective_auth}")
        
        # Check for Trust Misconfigurations (Bidirectional/External trust without SID filtering)
        if not sid_filter and tdirection == "Bidirectional":
            trust_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Dangerous Domain Trust Configuration!")
            print(f"     └─ Risk: Trust lacks SID filtering on a bidirectional link, allowing foreign users to perform SID history injection and traverse forest boundaries.\n")
        else:
            print(f"  ✅ [SECURE]: Trust relationship is configured with proper security boundaries.\n")
            
    return trust_alerts

# Run the trust security audit
total_vulnerabilities = audit_domain_trusts(domain_trusts)

print("--- DOMAIN TRUST ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} domain trust misconfiguration(s)!")
    print(f"     └─ Action Required: Enable SID filtering (`netdom trust ... /enablesidfiltering:yes`), restrict transitive forest traversal, and enforce selective authentication where necessary.")
else:
    print("  ✅ [SECURE]: All domain trusts passed security boundary verification.")

print("==========================================")