# ==========================================
# Day 32: Insecure Dependency / SCA Auditor
# Purpose: Practice software composition analysis and vulnerable package detection
# ==========================================

print("=== INSECURE DEPENDENCY / SCA AUDITOR ===")

# Simulated database of known vulnerable packages and affected versions
# (In production, tools like Snyk, Dependabot, or safety check against live CVE databases)
vulnerability_database = {
    "requests": {"vulnerable_version": "2.25.1", "cve": "CVE-2021-33503"},
    "flask": {"vulnerable_version": "1.0.2", "cve": "CVE-2019-1010083"},
    "paramiko": {"vulnerable_version": "2.7.1", "cve": "CVE-2022-24302"}
}

# Simulated project dependencies list (extracted from requirements.txt)
project_dependencies = [
    {"name": "requests", "version": "2.25.1"},
    {"name": "flask", "version": "2.1.2"},
    {"name": "paramiko", "version": "2.7.1"}
]

def audit_dependencies(dependencies):
    print("[*] Auditing project dependencies against known vulnerability database...\n")
    alerts = 0
    
    for dep in dependencies:
        name = dep["name"]
        version = dep["version"]
        
        if name in vulnerability_database:
            vuln_info = vulnerability_database[name]
            if vuln_info["vulnerable_version"] == version:
                alerts += 1
                print(f"  🚨 [ALERT]: Vulnerable package found!")
                print(f"     ├─ Package: {name} (v{version})")
                print(f"     └─ Associated CVE: {vuln_info['cve']} - Action required: Update package!\n")
            else:
                print(f"  ✅ [SECURE]: {name} (v{version}) is using a safe version.\n")
        else:
            print(f"  ℹ️ [INFO]: {name} (v{version}) has no reported vulnerabilities in database.\n")
            
    return alerts

# Run the dependency audit
total_alerts = audit_dependencies(project_dependencies)

if total_alerts > 0:
    print(f"Summary: Found {total_alerts} security vulnerability alert(s) requiring remediation.")
else:
    print("Summary: All dependencies are secure.")

print("==========================================")