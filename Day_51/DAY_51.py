# ==========================================
# Day 51: AWS S3 Bucket & IAM Misconfiguration Auditor
# Purpose: Practice cloud security auditing and detection of public storage permissions
# ==========================================

import json

print("=== CLOUD S3 & IAM MISCONFIGURATION AUDITOR ===")

# Simulated cloud resource policies (JSON format representing AWS S3 bucket access policies)
cloud_policies = [
    {
        "bucket_name": "company-internal-backups",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::company-internal-backups/*"
                }
            ]
        }
    },
    {
        "bucket_name": "customer-profile-avatars",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::customer-profile-avatars/*"
                }
            ]
        }
    }
]

def audit_cloud_policies(policies):
    print("[*] Auditing cloud storage policies for public exposure risks...\n")
    risk_count = 0
    
    for item in policies:
        bucket = item["bucket_name"]
        statements = item["policy"].get("Statement", [])
        
        is_public = False
        for stmt in statements:
            principal = stmt.get("Principal")
            # Check if principal is wildcard '*' or allows anonymous/public access
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                is_public = True
                
        if is_public:
            risk_count += 1
            print(f"  🚨 [CRITICAL RISK]: S3 Bucket '{bucket}' is publicly exposed!")
            print(f"     └─ Reason: Policy allows wildcard Principal ('*') access.\n")
        else:
            print(f"  ✅ [SECURE]: S3 Bucket '{bucket}' has restricted access controls.")
            
    return risk_count

# Run the cloud policy audit
total_risks = audit_cloud_policies(cloud_policies)

print("\n--- CLOUD SECURITY AUDIT SUMMARY ---")
if total_risks > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_risks} insecure cloud storage policy(ies)!")
    print(f"     └─ Action Required: Revoke public principal access and enforce least-privilege IAM rules.")
else:
    print("  ✅ [SECURE]: All audited cloud policies adhere to security baselines.")

print("==========================================")