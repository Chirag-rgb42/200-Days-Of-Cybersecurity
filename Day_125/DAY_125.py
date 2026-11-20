# ==========================================
# Day 125: Automated Infrastructure-as-Code (IaC) Terraform Security Auditor
# Purpose: Statically audit Terraform resource definitions for public storage, open security groups, and unencrypted databases
# ==========================================

print("=== AUTOMATED IAC TERRAFORM SECURITY AUDITOR ===")

# Simulated parsed Terraform resource blocks from an infrastructure repository
terraform_resources = [
    {
        "file": "storage.tf",
        "resource_type": "aws_s3_bucket",
        "resource_name": "customer_backups",
        "config": {
            "acl": "public-read",          # Vulnerable: Publicly readable S3 bucket!
            "versioning_enabled": True,
            "server_side_encryption": False # Vulnerable: Encryption at rest disabled!
        }
    },
    {
        "file": "network.tf",
        "resource_type": "aws_security_group",
        "resource_name": "web_app_sg",
        "config": {
            "ingress_cidr": "0.0.0.0/0",   # Vulnerable: Open to the entire internet!
            "ingress_port": 22,            # Vulnerable: Administrative SSH port exposed!
            "protocol": "tcp"
        }
    },
    {
        "file": "database.tf",
        "resource_type": "aws_db_instance",
        "resource_name": "prod_postgres",
        "config": {
            "publicly_accessible": False,
            "storage_encrypted": True,     # Secure: Encryption at rest enabled
            "backup_retention_period": 14
        }
    },
    {
        "file": "storage_secure.tf",
        "resource_type": "aws_s3_bucket",
        "resource_name": "internal_audit_logs",
        "config": {
            "acl": "private",              # Secure: Private bucket ACL
            "versioning_enabled": True,
            "server_side_encryption": True # Secure: AES256/KMS encryption enabled
        }
    }
]

ADMIN_PORTS = {22, 3389, 5432, 3306}

def audit_terraform_iac(resources):
    print("[*] Initiating static Infrastructure-as-Code (Terraform) security audit...\n")
    iac_alerts = 0
    
    for res in resources:
        fname = res["file"]
        rtype = res["resource_type"]
        rname = res["resource_name"]
        cfg = res["config"]
        findings = []
        
        # 1. Audit AWS S3 Bucket configurations
        if rtype == "aws_s3_bucket":
            if cfg.get("acl") in ("public-read", "public-read-write"):
                findings.append(f"Public S3 ACL ('{cfg.get('acl')}'): Restrict bucket access to 'private' and block public ACLs.")
            if not cfg.get("server_side_encryption", False):
                findings.append("Missing Server-Side Encryption: Enable KMS or AES256 encryption at rest.")
                
        # 2. Audit AWS Security Group ingress rules
        elif rtype == "aws_security_group":
            cidr = cfg.get("ingress_cidr")
            port = cfg.get("ingress_port")
            if cidr == "0.0.0.0/0" and port in ADMIN_PORTS:
                findings.append(f"Unrestricted Ingress ('0.0.0.0/0' on port {port}): Administrative/database ports must never be exposed globally.")
                
        # 3. Audit AWS RDS Database instances
        elif rtype == "aws_db_instance":
            if cfg.get("publicly_accessible", False):
                findings.append("Publicly Accessible Database: Set 'publicly_accessible = false' to isolate RDS inside private subnets.")
            if not cfg.get("storage_encrypted", False):
                findings.append("Unencrypted RDS Storage: Enforce 'storage_encrypted = true' for sensitive database volumes.")
                
        print(f"[-] Auditing Resource: {rtype}.{rname} (File: {fname})")
        if findings:
            iac_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} IaC policy violation(s)!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: Resource complies with cloud hardening and encryption baselines.\n")
            
    return iac_alerts

# Run the IaC security audit
total_violations = audit_terraform_iac(terraform_resources)

print("--- IAC SECURITY ASSESSMENT SUMMARY ---")
if total_violations > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_violations} Terraform resource(s) violating cloud security policies!")
    print(f"     └─ Action Required: Remediate public S3 ACLs, restrict 0.0.0.0/0 admin ingress rules, and enforce encryption at rest before 'terraform apply'.")
else:
    print("  ✅ [SECURE]: All audited Terraform resources passed IaC security verification.")

print("==========================================")