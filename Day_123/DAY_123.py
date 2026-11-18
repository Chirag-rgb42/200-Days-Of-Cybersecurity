# ==========================================
# Day 123: Automated Dependency Confusion & SBOM Package Auditor
# Purpose: Audit application dependencies for dependency confusion risks, unpinned version specifiers, and known CVEs
# ==========================================

print("=== AUTOMATED DEPENDENCY CONFUSION & SBOM AUDITOR ===")

# Simulated internal private package names registered on corporate Artifactory/Nexus
INTERNAL_PRIVATE_PACKAGES = {
    "corp-auth-middleware",
    "corp-billing-core",
    "internal-telemetry-sdk"
}

# Simulated known vulnerable package versions (CVE feed)
KNOWN_VULNERABLE_VERSIONS = {
    "requests": ["2.19.0", "2.20.0"],
    "pyyaml": ["5.1", "5.3.1"],
    "urllib3": ["1.24.1", "1.25.7"]
}

# Simulated application dependency manifest / SBOM entries
project_dependencies = [
    {
        "package": "requests",
        "version_spec": "==2.32.3",
        "registry_source": "pypi-public",
        "hash_verified": True
    },
    {
        "package": "corp-auth-middleware",
        "version_spec": ">=1.4.0",      # Vulnerable: Internal package without pinned registry or exact version!
        "registry_source": "auto-resolve", # Vulnerable: Allows fallback to public PyPI (Dependency Confusion!)
        "hash_verified": False
    },
    {
        "package": "pyyaml",
        "version_spec": "==5.3.1",      # Vulnerable: Known CVE (Arbitrary Code Execution via yaml.load)!
        "registry_source": "pypi-public",
        "hash_verified": True
    },
    {
        "package": "corp-billing-core",
        "version_spec": "==2.1.0",
        "registry_source": "private-artifactory-only", # Secure: Explicitly bound to private registry
        "hash_verified": True
    }
]

def audit_dependencies(deps):
    print("[*] Initiating software supply chain & SBOM dependency audit...\n")
    supply_chain_alerts = 0
    
    for dep in deps:
        pkg = dep["package"]
        spec = dep["version_spec"]
        source = dep["registry_source"]
        hashed = dep["hash_verified"]
        
        findings = []
        
        # 1. Check for Dependency Confusion exposure on internal packages
        if pkg in INTERNAL_PRIVATE_PACKAGES and source != "private-artifactory-only":
            findings.append(f"Dependency Confusion Risk: Internal package '{pkg}' uses '{source}' instead of strict private registry pinning.")
            
        # 2. Check for unpinned version specifiers
        if not spec.startswith("=="):
            findings.append(f"Unpinned Version Specifier ('{spec}'): Use exact '==' pinning to prevent unexpected upstream updates.")
            
        # 3. Check against known vulnerable package versions
        clean_version = spec.lstrip("=<>~!")
        if pkg in KNOWN_VULNERABLE_VERSIONS and clean_version in KNOWN_VULNERABLE_VERSIONS[pkg]:
            findings.append(f"Known Vulnerable Version ({pkg} {clean_version}): Flagged in CVE advisory feed.")
            
        # 4. Check for missing cryptographic hash verification
        if not hashed:
            findings.append("Missing Integrity Hash: Package lacks SHA256 hash verification in lockfile.")
            
        print(f"[-] Auditing Package: {pkg} ({spec})")
        print(f"    ├─ Registry Resolution: {source}")
        print(f"    └─ Integrity Hash Verified: {hashed}")
        
        if findings:
            supply_chain_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} supply chain risk(s) found!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: Dependency is strictly pinned, hash-verified, and free of known CVEs.\n")
            
    return supply_chain_alerts

# Run the dependency audit
total_vulnerabilities = audit_dependencies(project_dependencies)

print("--- SUPPLY CHAIN & SBOM ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} package(s) with dependency confusion, pinning, or CVE risks!")
    print(f"     └─ Action Required: Lock internal packages to private registries, enforce exact '==' version + SHA256 hash pinning, and upgrade vulnerable libraries.")
else:
    print("  ✅ [SECURE]: All project dependencies passed SBOM and supply chain security verification.")

print("==========================================")