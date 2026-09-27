# ==========================================
# Day 71: Automated CVE Banner Matcher & Vulnerability Assessor
# Purpose: Practice vulnerability management by mapping service banners to known CVEs
# ==========================================

print("=== CVE BANNER MATCHER & VULNERABILITY ASSESSOR ===")

# Simulated service banners discovered during port enumeration / banner grabbing
discovered_services = [
    {"port": 21, "service": "FTP", "banner": "vsftpd 2.3.4"},
    {"port": 22, "service": "SSH", "banner": "OpenSSH 7.2p2"},
    {"port": 80, "service": "HTTP", "banner": "Apache httpd 2.4.49"},
    {"port": 443, "service": "HTTPS", "banner": "nginx 1.18.0"}
]

# Simulated CVE database mapping vulnerable software signatures to CVE IDs and severity
cve_database = {
    "vsftpd 2.3.4": {"cve": "CVE-2011-2523", "severity": "CRITICAL", "desc": "Backdoor Command Execution Vulnerability"},
    "openssh 7.2p2": {"cve": "CVE-2016-6210", "severity": "MEDIUM", "desc": "Username Enumeration Vulnerability"},
    "apache httpd 2.4.49": {"cve": "CVE-2021-42013", "severity": "HIGH", "desc": "Path Traversal and Remote Code Execution"}
}

def assess_vulnerabilities(services, vuln_db):
    print("[*] Cross-referencing discovered service banners against CVE vulnerability database...\n")
    vulnerabilities_found = 0
    
    for item in services:
        port = item["port"]
        service = item["service"]
        banner = item["banner"]
        
        if banner in vuln_db:
            vulnerabilities_found += 1
            cve_info = vuln_db[banner]
            print(f"  🚨 [VULNERABILITY DETECTED]: Port {port} ({service})")
            print(f"     ├─ Discovered Banner: {banner}")
            print(f"     ├─ Associated CVE: {cve_info['cve']}")
            print(f"     ├─ Severity Level: {cve_info['severity']}")
            print(f"     └─ Description: {cve_info['desc']}\n")
        else:
            print(f"  ✅ [SECURE / UNKNOWN]: Port {port} ({service}) -> '{banner}' has no known CVE match.")
            
    return vulnerabilities_found

# Run the vulnerability assessment analysis
total_vulns = assess_vulnerabilities(discovered_services, cve_database)

print("--- VULNERABILITY ASSESSMENT SUMMARY ---")
if total_vulns > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulns} vulnerable service version(s) requiring immediate patching!")
    print(f"     └─ Action Required: Prioritize remediation based on CVSS severity scores.")
else:
    print("  ✅ [SECURE]: All service banners verified clean against vulnerability feed.")

print("==========================================")