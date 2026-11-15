# ==========================================
# Day 120: Unified Active Directory Security Posture & Risk Scoring Suite (Milestone)
# Purpose: Consolidate enterprise AD auditing checks (Kerberos, AD CS, ACLs, LAPS, SMB) into a unified risk report
# ==========================================

print("==========================================================")
print("   DAY 120 MILESTONE: UNIFIED AD SECURITY POSTURE SUITE   ")
print("==========================================================\n")

# Consolidated enterprise Active Directory telemetry snapshot
enterprise_ad_snapshot = {
    "domain_name": "corp.local",
    "checks": [
        {
            "category": "Identity & Kerberos",
            "control": "Kerberoastable Tier-0 Accounts",
            "compliant": True,
            "severity_weight": 25,
            "remediation": "Remove SPNs from privileged accounts or enforce 25+ char gMSA passwords."
        },
        {
            "category": "Privilege & ACLs",
            "control": "AdminSDHolder & Tier-0 Group Nesting",
            "compliant": False,
            "severity_weight": 25,
            "remediation": "Strip unauthorized ACEs on AdminSDHolder and flatten nested non-admin groups in Domain Admins."
        },
        {
            "category": "PKI / AD CS",
            "control": "AD CS Template & Web Enrollment Hardening (ESC1/ESC8)",
            "compliant": False,
            "severity_weight": 25,
            "remediation": "Disable ENROLEE_SUPPLIES_SUBJECT on templates and enforce HTTPS + EPA on /certsrv/."
        },
        {
            "category": "Lateral Movement",
            "control": "Windows LAPS & Mandatory SMB Signing",
            "compliant": True,
            "severity_weight": 15,
            "remediation": "Deploy LAPS across all OUs and require SMB signing via GPO."
        },
        {
            "category": "Credential Isolation",
            "control": "Protected Users Group & LSA Protection (RunAsPPL)",
            "compliant": True,
            "severity_weight": 10,
            "remediation": "Enroll all Tier-0 admins in Protected Users and enable RunAsPPL domain-wide."
        }
    ]
}

def run_unified_ad_assessment(snapshot):
    domain = snapshot["domain_name"]
    checks = snapshot["checks"]
    
    print(f"[*] Target Active Directory Forest/Domain: {domain}")
    print(f"[*] Evaluating {len(checks)} core enterprise security domains...\n")
    
    total_possible_score = sum(item["severity_weight"] for item in checks)
    earned_score = 0
    failed_controls = []
    
    for item in checks:
        cat = item["category"]
        ctrl = item["control"]
        passed = item["compliant"]
        weight = item["severity_weight"]
        
        if passed:
            earned_score += weight
            print(f"  ✅ [PASS] ({weight}/{weight} pts) | {cat}: {ctrl}")
        else:
            failed_controls.append(item)
            print(f"  🚨 [FAIL] (0/{weight} pts) | {cat}: {ctrl}")
            print(f"     └─ Recommended Fix: {item['remediation']}")
            
    return earned_score, total_possible_score, failed_controls

# Execute the Day 120 Milestone Suite
score, max_score, failures = run_unified_ad_assessment(enterprise_ad_snapshot)
compliance_pct = (score / max_score) * 100

print("\n==========================================================")
print("            EXECUTIVE AD POSTURE SUMMARY                  ")
print("==========================================================")
print(f"  📊 Overall Security Posture Score : {score} / {max_score} ({compliance_pct:.1f}%)")
print(f"  ⚠️ Critical Gaps Identified       : {len(failures)}")

if compliance_pct >= 85:
    print("  🛡️ Posture Rating                 : STRONG (Hardened Baseline)")
elif compliance_pct >= 60:
    print("  🟠 Posture Rating                 : MODERATE (Immediate Tier-0 Remediation Needed)")
else:
    print("  🔴 Posture Rating                 : CRITICAL (High Risk of Domain Compromise)")

print("==========================================================")