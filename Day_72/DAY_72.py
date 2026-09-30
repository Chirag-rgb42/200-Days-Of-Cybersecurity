# ==========================================
# Day 72: Automated Web Directory & Content Discovery Fuzzer
# Purpose: Practice web application reconnaissance and discovery of hidden administrative endpoints
# ==========================================

print("=== WEB DIRECTORY & CONTENT DISCOVERY FUZZER ===")

# Target web application base URL
target_base_url = "http://localhost:8080"

# Common wordlist of directories and files to fuzz
directory_wordlist = [
    "/index.html",
    "/login",
    "/admin",
    "/dashboard",
    "/config.json",
    "/backup.zip",
    "/secret-api",
    "/robots.txt"
]

# Simulated server responses mapping paths to mock HTTP status codes
simulated_server_responses = {
    "/index.html": 200,
    "/login": 200,
    "/admin": 403,         # Forbidden (Interesting target!)
    "/dashboard": 401,     # Unauthorized
    "/config.json": 200,   # Sensitive configuration file exposed!
    "/backup.zip": 200,    # Sensitive archive exposed!
    "/secret-api": 200,    # Undocumented API endpoint!
    "/robots.txt": 200
}

def fuzz_web_directories(base_url, wordlist, responses):
    print(f"[*] Initiating content discovery fuzzing against: {base_url}\n")
    discovered_endpoints = 0
    
    for path in wordlist:
        full_url = base_url + path
        status_code = responses.get(path, 404)
        
        if status_code == 200:
            discovered_endpoints += 1
            print(f"  🟢 [FOUND - 200 OK]: {full_url} (Accessible resource)")
        elif status_code == 403:
            discovered_endpoints += 1
            print(f"  🟡 [RESTRICTED - 403 Forbidden]: {full_url} (Protected administrative path)")
        elif status_code == 401:
            discovered_endpoints += 1
            print(f"  🟠 [UNAUTHORIZED - 401]: {full_url} (Authentication required)")
        else:
            print(f"  🔴 [NOT FOUND - 404]: {full_url}")
            
    return discovered_endpoints

# Run the web fuzzer
total_found = fuzz_web_directories(target_base_url, directory_wordlist, simulated_server_responses)

print("\n--- WEB RECONNAISSANCE SUMMARY ---")
print(f"  📊 Scan Completed on {target_base_url}")
print(f"  🔍 Discovered Endpoints: {total_found}")
print(f"     └─ Action Required: Review exposed files (like backup.zip or config.json) and restrict admin access.")
print("==========================================")