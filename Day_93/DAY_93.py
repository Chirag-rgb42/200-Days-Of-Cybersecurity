# ==========================================
# Day 93: Automated Web Directory & Endpoint Fuzzer
# Purpose: Practice web penetration testing content discovery by brute-forcing hidden paths using a wordlist
# ==========================================

print("=== AUTOMATED WEB DIRECTORY & ENDPOINT FUZZER ===")

# Target web base URL
target_url = "https://portal.acme-corp.local"

# Directory and endpoint wordlist
directory_wordlist = [
    "admin",
    "login",
    "dashboard",
    "api",
    "backup.zip",
    "config.json",
    "test",
    "uploads",
    "server-status",
    "secret-notes.txt"
]

# Simulated active web resources on the target server
active_endpoints_mock = {
    "/login": 200,
    "/api": 200,
    "/admin": 403,         # Forbidden: High-value target!
    "/backup.zip": 200,    # Critical: Sensitive file exposed!
    "/uploads": 301
}

def fuzz_web_directories(base_url, wordlist):
    print(f"[*] Initiating web content discovery fuzzing against: {base_url}")
    print(f"[*] Loaded {len(wordlist)} paths from wordlist. Scanning...\n")
    
    discovered_paths = []
    
    for path in wordlist:
        full_path = f"/{path}"
        
        # Simulate checking if endpoint exists on the server
        if full_path in active_endpoints_mock:
            status_code = active_endpoints_mock[full_path]
            discovered_paths.append((full_path, status_code))
            print(f"  🟢 [FOUND]: {base_url}{full_path} -> HTTP {status_code}")
        else:
            # Simulated 404 Not Found (hidden/non-existent)
            pass
            
    return discovered_paths

# Run the directory fuzzer scan
found_endpoints = fuzz_web_directories(target_url, directory_wordlist)

print("\n--- CONTENT DISCOVERY SUMMARY ---")
print(f"  📊 Target Base URL: {target_url}")
print(f"  🔍 Total Paths Fuzzed: {len(directory_wordlist)}")
print(f"  🚨 Active Endpoints Discovered: {len(found_endpoints)}")

for path, status in found_endpoints:
    if path in ["/admin", "/backup.zip", "/config.json"]:
        print(f"     └─ ⚠️ [HIGH-VALUE FINDING]: {path} (HTTP {status}) - Immediate security review required!")
    else:
        print(f"     └─ 📁 [STANDARD PATH]: {path} (HTTP {status})")

print("==========================================")