# ==========================================
# Day 57: Multi-Cloud Security Posture & Compliance Auditor (Cloud Capstone)
# Purpose: Consolidate S3 public exposure, firewall ingress risks, and IMDSv1 audits into a unified tool
# ==========================================

print("==================================================")
print("=== MULTI-CLOUD SECURITY POSTURE AUDITOR (DAY 57) ===")
print("==================================================\n")

# Simulated multi-cloud inventory data (S3 Buckets, Security Groups, EC2 Metadata options)
cloud_infrastructure = {
    "s3_buckets": [
        {"name": "company-internal-backups", "public_access": True},
        {"name": "customer-avatars", "public_access": False}
    ],
    "security_groups": [
        {"name": "bastion-sg", "port": 22, "cidr": "0.0.0.0/0"},
        {"name": "app-sg", "port": 443, "cidr": "0.0.0.0/0"}
    ],
    "ec2_instances": [
        {"id": "i-0abc1234", "name": "legacy-app", "imds_v1_enabled": True},
        {"id": "i-0xyz5678", "name": "modern-api", "imds_v1_enabled": False}
    ]
}

def audit_cloud_posture(infra):
    print("[*] Ingesting cloud inventory telemetry and executing compliance checks...\n")
    
    s3_risks = 0
    firewall_risks = 0
    imds_risks = 0
    
    # 1. Audit S3 Buckets
    for bucket in infra["s3_buckets"]:
        if bucket["public_access"]:
            s3_risks += 1
            print(f"  🚨 [S3 RISK]: Bucket '{bucket['name']}' is publicly exposed!")
            
    # 2. Audit Security Groups
    for sg in infra["security_groups"]:
        if sg["port"] == 22 and sg["cidr"] == "0.0.0.0/0":
            firewall_risks += 1
            print(f"  🚨 [FIREWALL RISK]: Security Group '{sg['name']}' exposes SSH (port 22) to the world!")
            
    # 3. Audit EC2 Metadata Service
    for inst in infra["ec2_instances"]:
        if inst["imds_v1_enabled"]:
            imds_risks += 1
            print(f"  🚨 [IMDS RISK]: Instance '{inst['name']}' ({inst['id']}) permits insecure IMDSv1 access!")

    return s3_risks, firewall_risks, imds_risks

# Execute the posture audit
s3_total, firewall_total, imds_total = audit_cloud_posture(cloud_infrastructure)
total_findings = s3_total + firewall_total + imds_total

print("\n--- CLOUD SECURITY POSTURE SUMMARY ---")
print(f"  📦 Public S3 Bucket Findings     : {s3_total}")
print(f"  🔥 Risky Firewall Ingress Rules  : {firewall_total}")
print(f"  🔐 Insecure IMDSv1 Instances     : {imds_total}")
print("--------------------------------------------------")

if total_findings > 0:
    print(f"⚠️ [AUDIT RESULT]: Found {total_findings} cloud security misconfiguration(s)!")
    print(f"   Recommendation: Remediate public storage, restrict firewall CIDRs, and enforce IMDSv2.")
else:
    print("✅ [AUDIT RESULT]: Cloud environment posture is fully secure and compliant.")

print("==================================================")