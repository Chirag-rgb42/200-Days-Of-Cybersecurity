# ==========================================
# Day 31: Hardcoded Secrets & API Key Detector
# Purpose: Practice source code auditing and DevSecOps security scanning
# ==========================================

import re

print("=== HARDCODED SECRETS & API KEY DETECTOR ===")

# Regex patterns for common sensitive credentials / secrets
secret_patterns = [
    r"password\s*=\s*['\"].*?['\"]",       # Hardcoded passwords
    r"api_key\s*=\s*['\"].*?['\"]",       # Generic API keys
    r"AKIA[0-9A-Z]{16}",                  # AWS Access Key ID pattern
    r"bearer\s+[a-zA-Z0-9_\-\.]{20,}"     # Bearer tokens
]

def scan_code_for_secrets(file_content):
    print("[*] Scanning source code content for hardcoded credentials...")
    findings = []
    
    # Split content line by line to track line numbers
    lines = file_content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append((line_num, line.strip()))
                
    return findings

# Simulated source code file content to audit
sample_source_code = """
# Configuration file for application
database_host = "localhost"
database_port = 5432
app_environment = "production"

# --- Potential Risk Areas ---
password = "SuperSecretPassword123"
api_key = "sk_live_9988776655443321"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
"""

print("\n--- RUNNING SOURCE CODE AUDIT ---")
leaks = scan_code_for_secrets(sample_source_code)

if leaks:
    print(f"🚨 [ALERT]: Found {len(leaks)} potential hardcoded secret(s)!\n")
    for line_num, content in leaks:
        print(f"  ├─ Line {line_num}: {content}")
    print("  └─ Action Required: Move credentials to environment variables!")
else:
    print("✅ [SECURE]: No hardcoded credentials found.")

print("\n==========================================")