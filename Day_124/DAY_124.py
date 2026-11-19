# ==========================================
# Day 124: Automated Pre-Commit Secret & High-Entropy Token Scanner
# Purpose: Detect hardcoded API keys, cloud credentials, and high-entropy secrets in staged code before commit
# ==========================================

import math
import re

print("=== AUTOMATED PRE-COMMIT SECRET & ENTROPY SCANNER ===")

# Known vendor secret regex signatures
SECRET_SIGNATURES = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Personal Access Token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "Stripe Live Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Private Key Header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
}

# Regex to extract quoted string assignments for entropy analysis
ASSIGNMENT_PATTERN = re.compile(r"""(?:api_key|secret|token|password|auth)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,})["']""", re.IGNORECASE)

# Simulated staged source files awaiting 'git commit'
staged_files = {
    "config/settings.py": [
        "DEBUG = False",
        "ALLOWED_HOSTS = ['api.corp.local']",
        "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'", # Vulnerable: Known AWS key prefix!
        "INTERNAL_WEBHOOK_SECRET = '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1908'" # Vulnerable: High-entropy secret!
    ],
    "services/github_client.py": [
        "import os",
        "GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')", # Secure: Loaded cleanly from environment variable
        "API_TIMEOUT = 30"
    ],
    "scripts/deploy_helper.sh": [
        "#!/bin/bash",
        "TOKEN='ghp_1234567890abcdef1234567890abcdef1234'", # Vulnerable: Hardcoded GitHub PAT!
        "echo 'Deployment initialized'"
    ]
}

def calculate_shannon_entropy(data):
    """Calculates Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        prob = data.count(char) / length
        entropy -= prob * math.log2(prob)
    return entropy

def scan_staged_files(files_dict, entropy_threshold=3.8):
    print("[*] Scanning staged files for hardcoded secrets and high-entropy tokens...\n")
    total_secrets_found = 0
    
    for filepath, lines in files_dict.items():
        file_findings = []
        
        for line_num, line in enumerate(lines, start=1):
            matched_signature = False
            
            # 1. Check against known vendor regex signatures
            for sig_name, pattern in SECRET_SIGNATURES.items():
                if pattern.search(line):
                    file_findings.append(f"Line {line_num} [Signature Match - {sig_name}]: Hardcoded credential detected.")
                    matched_signature = True
                    
            # 2. Check quoted sensitive assignments using Shannon entropy
            if not matched_signature:
                match = ASSIGNMENT_PATTERN.search(line)
                if match:
                    candidate_secret = match.group(1)
                    entropy = calculate_shannon_entropy(candidate_secret)
                    if entropy >= entropy_threshold:
                        file_findings.append(
                            f"Line {line_num} [High-Entropy Secret - {entropy:.2f} bits]: Potential hardcoded token detected."
                        )
                        
        print(f"[-] Scanning File: {filepath}")
        if file_findings:
            total_secrets_found += len(file_findings)
            print(f"  🚨 [COMMIT BLOCKED]: {len(file_findings)} secret(s) detected!")
            for finding in file_findings:
                print(f"     └─ {finding}")
            print()
        else:
            print(f"  ✅ [CLEAN]: No hardcoded secrets or high-entropy tokens found.\n")
            
    return total_secrets_found

# Execute the pre-commit scan
secrets_detected = scan_staged_files(staged_files)

print("--- PRE-COMMIT SECRET SCAN SUMMARY ---")
if secrets_detected > 0:
    print(f"  ⛔ [REJECTED]: Commit aborted! Found {secrets_detected} exposed secret(s) across staged files.")
    print(f"     └─ Action Required: Remove hardcoded credentials, load secrets via environment variables or a secret manager, and rotate any exposed keys.")
else:
    print("  ✅ [APPROVED]: All staged files are clean. Safe to proceed with git commit.")

print("==========================================")