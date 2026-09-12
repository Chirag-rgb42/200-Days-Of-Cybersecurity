# ==========================================
# Day 56: AWS EC2 Instance Metadata (IMDS) Security Auditor
# Purpose: Practice cloud security and detection of insecure IMDSv1 configurations susceptible to SSRF
# ==========================================

print("=== AWS IMDS SECURITY & SSRF RISK AUDITOR ===")

# Simulated EC2 instance configuration profiles (JSON/Dict format)
ec2_instances = [
    {
        "instance_id": "i-0123456789abcdef0",
        "instance_name": "web-frontend-prod",
        "metadata_options": {
            "http_endpoint": "enabled",
            "http_tokens": "required", # IMDSv2 enforced (Secure)
            "http_put_response_hop_limit": 1
        }
    },
    {
        "instance_id": "i-0fedcba9876543210",
        "instance_name": "legacy-app-server",
        "metadata_options": {
            "http_endpoint": "enabled",
            "http_tokens": "optional",  # IMDSv1 enabled (Insecure / Vulnerable to SSRF)
            "http_put_response_hop_limit": 2
        }
    },
    {
        "instance_id": "i-01122334455667788",
        "instance_name": "internal-worker-node",
        "metadata_options": {
            "http_endpoint": "disabled", # Disabled completely (Most Secure)
            "http_tokens": "required",
            "http_put_response_hop_limit": 1
        }
    }
]

def audit_imds_configurations(instances):
    print("[*] Auditing EC2 instance metadata service (IMDS) configurations...\n")
    vulnerabilities = 0
    
    for inst in instances:
        inst_id = inst["instance_id"]
        name = inst["instance_name"]
        options = inst["metadata_options"]
        
        endpoint = options.get("http_endpoint")
        tokens = options.get("http_tokens")
        
        if endpoint == "enabled" and tokens == "optional":
            vulnerabilities += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Instance '{name}' ({inst_id}) uses insecure IMDSv1!")
            print(f"     ├─ Risk: Vulnerable to Server-Side Request Forgery (SSRF) credential theft.")
            print(f"     └─ Status: Tokens are optional. Recommend enforcing IMDSv2.\n")
        elif endpoint == "disabled":
            print(f"  ✅ [SECURE]: Instance '{name}' ({inst_id}) has metadata service completely disabled.")
        else:
            print(f"  ✅ [SECURE]: Instance '{name}' ({inst_id}) correctly enforces IMDSv2 tokens.")
            
    return vulnerabilities

# Run the IMDS security audit
total_vulns = audit_imds_configurations(ec2_instances)

print("\n--- CLOUD METADATA AUDIT SUMMARY ---")
if total_vulns > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulns} instance(s) with insecure IMDSv1 configurations!")
    print(f"     └─ Action Required: Update launch templates to require IMDSv2 tokens (`http_tokens = required`).")
else:
    print("  ✅ [SECURE]: All audited EC2 instances enforce robust metadata security standards.")

print("==========================================")