# ==========================================
# Day 126: Automated SAST (Static Application Security Testing) AST Code Scanner
# Purpose: Parse Python source code via AST to detect command injection, unsafe deserialization, and weak cryptography
# ==========================================

import ast

print("=== AUTOMATED AST-BASED SAST CODE VULNERABILITY SCANNER ===")

# Simulated Python source files from an application codebase
application_files = {
    "api/diagnostics.py": """
import os
import subprocess

def ping_host(target_ip):
    # Vulnerable: Command injection sink via os.system
    os.system("ping -c 1 " + target_ip)

def run_healthcheck(service_name):
    # Vulnerable: subprocess with shell=True enabled
    subprocess.run(f"systemctl status {service_name}", shell=True)
""",
    "utils/session_loader.py": """
import pickle
import hashlib

def restore_session(raw_bytes):
    # Vulnerable: Arbitrary code execution via pickle.loads
    return pickle.loads(raw_bytes)

def legacy_token_hash(token):
    # Vulnerable: Broken MD5 hash algorithm
    return hashlib.md5(token.encode()).hexdigest()
""",
    "services/secure_auth.py": """
import hashlib
import subprocess

def hash_api_key(api_key):
    # Secure: Strong SHA-256 cryptographic digest
    return hashlib.sha256(api_key.encode()).hexdigest()

def safe_status_check(service_name):
    # Secure: Argument list passed without shell=True
    subprocess.run(["systemctl", "status", service_name], shell=False)
"""
}

class SecurityASTVisitor(ast.NodeVisitor):
    """AST Visitor that inspects function calls for dangerous security sinks."""
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        func_name = self._get_call_name(node.func)

        # 1. Detect dynamic execution sinks (eval / exec)
        if func_name in ("eval", "exec"):
            self.findings.append((node.lineno, f"Critical - Dynamic Code Execution ('{func_name}'): Avoid evaluating untrusted strings."))

        # 2. Detect OS command injection sinks
        elif func_name == "os.system":
            self.findings.append((node.lineno, "High - Command Injection Sink ('os.system'): Replace with subprocess.run([...], shell=False)."))

        elif func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append((node.lineno, f"High - Shell Injection Risk ('{func_name}' with shell=True): Disable shell=True and pass argument lists."))

        # 3. Detect insecure deserialization
        elif func_name in ("pickle.loads", "pickle.load"):
            self.findings.append((node.lineno, f"Critical - Insecure Deserialization ('{func_name}'): Use JSON or cryptographic signing instead of pickle."))

        # 4. Detect weak cryptographic hash functions
        elif func_name in ("hashlib.md5", "hashlib.sha1"):
            self.findings.append((node.lineno, f"Medium - Weak Cryptography ('{func_name}'): Upgrade to SHA-256 or a modern password hashing KDF."))

        self.generic_visit(node)

    def _get_call_name(self, func_node):
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            return f"{func_node.value.id}.{func_node.attr}"
        return ""

def run_sast_scan(files_dict):
    print("[*] Parsing application source files with Python AST engine...\n")
    vulnerable_files = 0

    for filepath, source_code in files_dict.items():
        tree = ast.parse(source_code, filename=filepath)
        visitor = SecurityASTVisitor()
        visitor.visit(tree)

        print(f"[-] Scanning Source File: {filepath}")
        if visitor.findings:
            vulnerable_files += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(visitor.findings)} SAST finding(s)!")
            for line_no, message in visitor.findings:
                print(f"     └─ Line {line_no}: {message}")
            print()
        else:
            print(f"  ✅ [SECURE]: No dangerous sinks or weak cryptographic calls detected.\n")

    return vulnerable_files

# Execute the SAST scan
total_vulnerable = run_sast_scan(application_files)

print("--- SAST CODE AUDIT SUMMARY ---")
if total_vulnerable > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerable} source file(s) containing high-risk code patterns!")
    print(f"     └─ Action Required: Eliminate shell=True command execution, replace pickle deserialization, and upgrade legacy MD5/SHA1 digests.")
else:
    print("  ✅ [SECURE]: All scanned source files passed AST static security analysis.")

print("==========================================")