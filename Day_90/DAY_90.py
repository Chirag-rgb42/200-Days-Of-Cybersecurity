# ==========================================
# Day 90: Automated Subdomain Enumeration Scanner
# Purpose: Practice penetration testing reconnaissance by discovering active subdomains using a wordlist
# ==========================================

print("=== AUTOMATED SUBDOMAIN ENUMERATION SCANNER ===")

# Target root domain for reconnaissance
target_domain = "acme-corp.local"

# Common subdomain prefix wordlist
subdomain_wordlist = [
    "www",
    "mail",
    "portal",
    "admin",
    "dev",
    "staging",
    "api",
    "vpn",
    "test",
    "billing"
]

# Simulated active/resolved subdomains on the target infrastructure
active_subdomains_mock = [
    "www.acme-corp.local",
    "portal.acme-corp.local",
    "admin.acme-corp.local", # High-risk discovery!
    "api.acme-corp.local",
    "staging.acme-corp.local" # Forgotten staging server!
]

def enumerate_subdomains(domain, wordlist):
    print(f"[*] Initiating subdomain enumeration for target: {domain}")
    print(f"[*] Loaded {len(wordlist)} prefixes from wordlist. Scanning...\n")
    
    discovered_hosts = []
    
    for prefix in wordlist:
        hostname = f"{prefix}.{domain}"
        
        # Simulate checking if the subdomain resolves / is active
        if hostname in active_subdomains_mock:
            discovered_hosts.append(hostname)
            print(f"  🟢 [DISCOVERED]: Active Host Found -> {hostname}")
        else:
            # Silent or verbose miss
            pass
            
    return discovered_hosts

# Run the subdomain enumeration scan
found_hosts = enumerate_subdomains(target_domain, subdomain_wordlist)

print("\n--- SUBDOMAIN RECONNAISSANCE SUMMARY ---")
print(f"  📊 Target Root Domain: {target_domain}")
print(f"  🔍 Total Prefixes Tested: {len(subdomain_wordlist)}")
print(f"  🚨 Active Subdomains Discovered: {len(found_hosts)}")

for host in found_hosts:
    if "admin" in host or "staging" in host or "dev" in host:
        print(f"     └─ ⚠️ [HIGH-VALUE TARGET]: {host} (Review access controls immediately!)")
    else:
        print(f"     └─ 📁 [STANDARD HOST]: {host}")

print("==========================================")