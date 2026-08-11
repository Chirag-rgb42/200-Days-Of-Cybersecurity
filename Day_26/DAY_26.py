# ==========================================
# Day 26: HTTP Security Header Analyzer
# Purpose: Practice web application security auditing and header inspection
# ==========================================

import urllib.request
import urllib.error

print("=== HTTP SECURITY HEADER ANALYZER ===")

def check_security_headers(url):
    try:
        print(f"[*] Analyzing security headers for: {url}")
        
        # Create request with a custom user-agent
        req = urllib.request.Request(url, headers={'User-Agent': 'SecurityAuditBot/1.0'})
        
        with urllib.request.urlopen(req) as response:
            headers = response.headers
            
            # List of vital security headers to inspect
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            
            print("\n--- SECURITY HEADER AUDIT REPORT ---")
            for header in security_headers:
                if header in headers:
                    print(f"  ✅ [PRESENT] {header}")
                    print(f"     -> Value: {headers.get(header)}")
                else:
                    print(f"  ❌ [MISSING] {header} is not set.")
                    
    except urllib.error.URLError as e:
        print(f"🚨 [ERROR]: Failed to connect to URL: {e.reason}")
    except Exception as e:
        print(f"🚨 [ERROR]: An unexpected error occurred: {e}")

# Target configuration (Testing a secure public site)
target_url = "https://github.com"

check_security_headers(target_url)
print("==========================================")