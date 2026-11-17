# ==========================================
# Day 122: Automated Dockerfile & Container Build Security Auditor
# Purpose: Statically analyze Dockerfile definitions for root execution, mutable tags, and hardcoded build secrets
# ==========================================

import re

print("=== AUTOMATED DOCKERFILE & CONTAINER SECURITY AUDITOR ===")

# Simulated Dockerfile definitions from application repositories
dockerfiles_to_audit = {
    "payment-service/Dockerfile": [
        "FROM python:3.12.7-slim-bookworm",
        "WORKDIR /app",
        "COPY requirements.txt .",
        "RUN pip install --no-cache-dir -r requirements.txt",
        "COPY . .",
        "RUN adduser --disabled-password --gecos '' appuser",
        "USER appuser",
        "EXPOSE 8080",
        "CMD [\"gunicorn\", \"app:server\"]"
    ],
    "legacy-api/Dockerfile": [
        "FROM ubuntu:latest",                        # Vulnerable: Mutable ':latest' base tag!
        "ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", # Vulnerable: Hardcoded secret in ENV!
        "ARG DB_PASSWORD=SuperSecretProdPass123",     # Vulnerable: Secret passed via build ARG!
        "WORKDIR /srv/api",
        "COPY . .",
        "RUN apt-get update && apt-get install -y python3 curl netcat",
        "EXPOSE 22 5000",                             # Vulnerable: Exposing SSH port 22 inside a container!
        "CMD [\"python3\", \"run.py\"]"
        # Vulnerable: Missing 'USER' instruction (defaults to root)!
    ]
}

SECRET_PATTERNS = re.compile(r"(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\s*=", re.IGNORECASE)

def audit_dockerfiles(files_dict):
    print("[*] Initiating static Dockerfile security audit...\n")
    total_flagged_files = 0
    
    for filepath, lines in files_dict.items():
        findings = []
        has_non_root_user = False
        
        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
                
            # 1. Check for mutable ':latest' or untagged base image
            if line.upper().startswith("FROM "):
                image = line.split()[1]
                if image.endswith(":latest") or (":" not in image and "@" not in image):
                    findings.append(f"Line {line_num}: Base image '{image}' uses a mutable tag. Pin a specific version or SHA256 digest.")
            
            # 2. Check for hardcoded secrets in ENV or ARG
            if line.upper().startswith(("ENV ", "ARG ")) and SECRET_PATTERNS.search(line):
                findings.append(f"Line {line_num}: Potential secret detected in build instruction ('{line.split()[0]}'). Secrets persist in image layers.")
                
            # 3. Check for non-root USER instruction
            if line.upper().startswith("USER "):
                user_val = line.split()[1].lower()
                if user_val not in ("root", "0"):
                    has_non_root_user = True
                    
            # 4. Check for risky exposed ports (e.g., SSH port 22)
            if line.upper().startswith("EXPOSE "):
                ports = line.split()[1:]
                if "22" in ports or "22/tcp" in ports:
                    findings.append(f"Line {line_num}: SSH port 22 exposed. Containers should not run SSH daemons.")

        if not has_non_root_user:
            findings.append("Missing non-root 'USER' instruction: Container will execute as 'root' (UID 0) by default.")
            
        print(f"[-] Auditing Build File: {filepath}")
        if findings:
            total_flagged_files += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} security issue(s) found!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: Dockerfile enforces pinned base images, non-root execution, and clean build layers.\n")
            
    return total_flagged_files

# Run the Dockerfile security audit
vulnerable_count = audit_dockerfiles(dockerfiles_to_audit)

print("--- CONTAINER BUILD ASSESSMENT SUMMARY ---")
if vulnerable_count > 0:
    print(f"  ⚠️ [ALERT]: Flagged {vulnerable_count} Dockerfile(s) failing container hardening baselines!")
    print(f"     └─ Action Required: Enforce non-root USER directives, pin immutable image tags, and inject runtime secrets via secret managers rather than ENV/ARG.")
else:
    print("  ✅ [SECURE]: All audited Dockerfiles passed container security checks.")

print("==========================================")