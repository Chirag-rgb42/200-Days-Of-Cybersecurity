# ==========================================
# Day 27: Simple Web Directory Brute-Forcer
# Purpose: Practice content discovery and web reconnaissance automation
# ==========================================

import urllib.request
import urllib.error

print("=== SIMPLE WEB DIRECTORY BRUTE-FORCER ===")

# Target URL (Using httpbin.org as a safe testing sandbox)
target_url = "http://httpbin.org"

# Common directories/files wordlist to test
wordlist = ["admin", "login", "dashboard", "secret", "config.json", "robots.txt"]

def discover_directories(url, paths):
    print(f"[*] Starting directory discovery on: {url}\n")
    
    for path in paths:
        full_url = f"{url}/{path}"
        try:
            # Send HTTP GET request with a custom user-agent
            req = urllib.request.Request(full_url, headers={'User-Agent': 'SecurityAuditBot/1.0'})
            with urllib.request.urlopen(req) as response:
                status = response.getcode()
                if status == 200:
                    print(f"  ✅ [FOUND - 200 OK]: {full_url}")
        except urllib.error.HTTPError as e:
            # Handle standard HTTP response error codes
            if e.code == 404:
                print(f"  ❌ [NOT FOUND - 404]: {full_url}")
            elif e.code == 403:
                print(f"  🔒 [FORBIDDEN - 403]: {full_url} (Protected directory exists!)")
            else:
                print(f"  ⚠️ [HTTP {e.code}]: {full_url}")
        except urllib.error.URLError as e:
            print(f"  🚨 [ERROR]: Could not connect to {full_url}")

discover_directories(target_url, wordlist)
print("\n==========================================")