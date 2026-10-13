# ==========================================
# Day 87: Automated Unrestricted File Upload Vulnerability Scanner
# Purpose: Practice web application vulnerability assessment and detection of dangerous file upload flaws
# ==========================================

print("=== AUTOMATED FILE UPLOAD VULNERABILITY SCANNER ===")

# Simulated file upload endpoints and test upload payloads
upload_tests = [
    {
        "endpoint": "/api/v1/profile/avatar",
        "filename": "avatar.png",
        "content_type": "image/png",
        "file_bytes": b"\x89PNG\r\n\x1a\n...valid image data..."
    },
    {
        "endpoint": "/api/v1/documents/upload",
        "filename": "shell.php",
        "content_type": "application/x-httpd-php",
        "file_bytes": b"<?php system($_GET['cmd']); ?>" # Dangerous web shell payload!
    },
    {
        "endpoint": "/api/v1/forum/attachment",
        "filename": "payload.php.jpg",
        "content_type": "image/jpeg",
        "file_bytes": b"<?php echo 'Bypassed extension filter!'; ?>" # Double extension bypass attempt
    },
    {
        "endpoint": "/api/v1/resume/submit",
        "filename": "resume.pdf",
        "content_type": "application/pdf",
        "file_bytes": b"%PDF-1.4 ...valid resume content..."
    }
]

# Dangerous executable extensions that should never be permitted in upload directories
dangerous_extensions = [".php", ".php5", ".phtml", ".exe", ".sh", ".jsp", ".asp"]

def scan_for_file_upload_flaws(tests):
    print("[*] Initiating automated file upload scan across ingestion endpoints...\n")
    upload_alerts = 0
    
    for test in tests:
        endpoint = test["endpoint"]
        filename = test["filename"]
        content_type = test["content_type"]
        
        print(f"[-] Testing Endpoint: {endpoint}")
        print(f"    ├─ Upload Filename: {filename}")
        print(f"    └─ Content-Type: {content_type}")
        
        # Check if filename contains dangerous extensions or double extensions
        is_dangerous = any(filename.lower().endswith(ext) or (ext in filename.lower() and "." in filename.split(ext)[0]) for ext in dangerous_extensions)
        
        if is_dangerous:
            upload_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Unrestricted File Upload Flaw!")
            print(f"     └─ Risk: Endpoint accepted executable file extension, risking remote code execution (RCE).\n")
        else:
            print(f"  ✅ [SECURE]: File type and extension successfully validated and restricted.\n")
            
    return upload_alerts

# Run the file upload vulnerability scan
total_vulnerabilities = scan_for_file_upload_flaws(upload_tests)

print("--- FILE UPLOAD ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} upload endpoint(s) vulnerable to malicious file execution!")
    print(f"     └─ Action Required: Enforce strict whitelisting of file extensions, validate magic bytes, and store uploads outside the web root.")
else:
    print("  ✅ [SECURE]: All upload endpoints properly filtered executable formats.")

print("==========================================")