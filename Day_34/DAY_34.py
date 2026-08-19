# ==========================================
# Day 34: Dockerfile Security Misconfiguration Auditor
# Purpose: Practice container security and DevSecOps compliance scanning
# ==========================================

print("=== DOCKERFILE SECURITY MISCONFIGURATION AUDITOR ===")

# Simulated Dockerfile lines to audit
dockerfile_lines = [
    "FROM python:latest",
    "WORKDIR /app",
    "COPY . /app",
    "RUN pip install -r requirements.txt",
    "EXPOSE 22",
    "EXPOSE 80",
    "USER root"
]

def audit_dockerfile(lines):
    print("[*] Auditing Dockerfile lines for security anti-patterns...\n")
    warnings = 0
    
    for line_num, line in enumerate(lines, 1):
        line_str = line.strip()
        
        # Check for latest tag anti-pattern
        if "FROM" in line_str and ":latest" in line_str:
            warnings += 1
            print(f"  ⚠️ [WARNING] Line {line_num}: Uses ':latest' tag.")
            print(f"     └─ Recommendation: Specify a fixed version tag for secure reproducibility.\n")
        
        # Check for root user execution
        elif "USER root" in line_str:
            warnings += 1
            print(f"  🚨 [HIGH RISK] Line {line_num}: Container explicitly runs as 'root'.")
            print(f"     └─ Recommendation: Switch to a dedicated non-root user account.\n")
            
        # Check for risky exposed ports (e.g., SSH port 22)
        elif "EXPOSE 22" in line_str:
            warnings += 1
            print(f"  🚨 [MEDIUM RISK] Line {line_num}: Exposes port 22 (SSH).")
            print(f"     └─ Recommendation: Avoid running SSH inside containers; manage via orchestrator logs.\n")

    return warnings

# Run the Dockerfile audit
total_warnings = audit_dockerfile(dockerfile_lines)

if total_warnings > 0:
    print(f"Audit Summary: Found {total_warnings} security warning(s) requiring remediation.")
else:
    print("Audit Summary: Dockerfile meets basic security guidelines.")

print("==========================================")