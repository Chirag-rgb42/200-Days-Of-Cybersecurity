# ==========================================
# Day 132: Automated Path Traversal & Safe File-Access Validator
# Purpose: Defensively validate user-supplied filenames against directory traversal, null-byte injection, and unsafe extensions
# ==========================================

from pathlib import Path
from urllib.parse import unquote

print("=== AUTOMATED PATH TRAVERSAL & FILE SANDBOX VALIDATOR ===")

# Base directory authorized for user report downloads
BASE_STORAGE_DIR = Path("/var/app/exports/reports").resolve()

# Approved file extensions for download
ALLOWED_EXTENSIONS = {".pdf", ".csv", ".txt"}

# Simulated user-supplied filename parameters from an API download endpoint
requested_filenames = [
    "q4_security_summary.pdf",                  # Safe: Clean filename inside base directory
    "../../etc/passwd",                         # Unsafe: Classic dot-dot-slash traversal!
    "%2e%2e%2f%2e%2e%2fapp%2f.env",             # Unsafe: URL-encoded traversal targeting .env secrets!
    "invoices/2026/../../secret_keys.pem",      # Unsafe: Nested traversal escaping base directory!
    "report_2026.pdf\x00.exe",                  # Unsafe: Null-byte injection!
    "backup_dump.sql"                           # Unsafe: Disallowed file extension (.sql)!
]

def validate_safe_file_access(base_dir, user_filename):
    """Validates that a user-supplied filename resolves strictly inside base_dir with an approved extension."""
    # 1. Decode URL-encoded characters to catch %2e%2e%2f bypasses
    decoded_name = unquote(user_filename)

    # 2. Block null-byte injection attempts
    if "\x00" in decoded_name:
        return False, "Blocked Null-Byte Injection: Filename contains illegal null character (\\x00)."

    # 3. Canonicalize target path relative to the base directory
    candidate_path = (base_dir / decoded_name).resolve()

    # 4. Enforce strict directory sandbox confinement
    if not candidate_path.is_relative_to(base_dir):
        return False, f"Blocked Directory Traversal: Resolved path '{candidate_path}' escapes sandbox '{base_dir}'."

    # 5. Block hidden dotfiles (e.g., .env, .ssh)
    if any(part.startswith(".") for part in candidate_path.relative_to(base_dir).parts):
        return False, f"Blocked Hidden Dotfile Access: '{candidate_path.name}' is restricted."

    # 6. Enforce strict file extension allowlist
    if candidate_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return False, f"Blocked Disallowed Extension ('{candidate_path.suffix}'): Only {sorted(ALLOWED_EXTENSIONS)} are permitted."

    return True, f"Verified safe sandboxed file path: '{candidate_path}'"

def run_path_traversal_audit(filenames):
    print(f"[*] Enforcing File Sandbox Root: {BASE_STORAGE_DIR}\n")
    blocked_count = 0

    for fname in filenames:
        is_safe, reason = validate_safe_file_access(BASE_STORAGE_DIR, fname)
        print(f"[-] Inspecting Filename Parameter: {repr(fname)}")
        if is_safe:
            print(f"  ✅ [ALLOWED]: {reason}\n")
        else:
            blocked_count += 1
            print(f"  🚨 [TRAVERSAL BLOCKED]: {reason}\n")

    return blocked_count

# Execute the Path Traversal validation audit
total_blocked = run_path_traversal_audit(requested_filenames)

print("--- PATH TRAVERSAL VALIDATION SUMMARY ---")
print(f"  🛡️ Total Requests Evaluated : {len(requested_filenames)}")
print(f"  ⛔ Malicious Paths Blocked  : {total_blocked}")
print("  ✅ Defense Mechanism        : Canonical path resolution (Path.resolve), sandbox confinement, and extension allowlisting active.")
print("==========================================")