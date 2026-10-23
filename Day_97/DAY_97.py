# ==========================================
# Day 97: Automated Insecure Deserialization Vulnerability Scanner
# Purpose: Practice API security assessment by detecting unsafe deserialization streams and pickle tokens
# ==========================================

print("=== AUTOMATED INSECURE DESERIALIZATION SCANNER ===")

# Simulated API requests and session tokens containing serialized data streams  
deserialization_payloads = [
    {
        "endpoint": "/api/v1/user/session",
        "parameter": "session_token",
        "token_format": "JSON",
        "payload_sample": "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9" # Safe JSON base64 string
    },
    {
        "endpoint": "/api/v1/profile/restore",
        "parameter": "state_blob",
        "token_format": "Python Pickle",
        "payload_sample": "gASVHgAAAAAAAAB9lCiMAHVzZXlMAHRlc3SFlFKUaA==" # Dangerous Python pickle serialization!
    },
    {
        "endpoint": "/api/v1/export/report",
        "parameter": "config_object",
        "token_format": "Java ObjectStream",
        "payload_sample": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvcklJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdw==" # Dangerous Java stream!
    },
    {
        "endpoint": "/api/v1/settings/load",
        "parameter": "prefs",
        "token_format": "JSON",
        "payload_sample": "eyJ0aGVtZSI6ImRhcmsifQ=="
    }
]

# Unsafe serialization formats that should never be processed directly from untrusted user input
unsafe_formats = ["Python Pickle", "Java ObjectStream", "PHP Unserialize"]

def scan_for_insecure_deserialization(payloads):
    print("[*] Initiating automated Insecure Deserialization scan across API endpoints...\n")
    deserialization_alerts = 0
    
    for test in payloads:
        ep = test["endpoint"]
        param = test["parameter"]
        fmt = test["token_format"]
        sample = test["payload_sample"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Parameter: {param}")
        print(f"    └─ Detected Serialization Format: {fmt}")
        
        # Check if endpoint processes unsafe serialization formats
        is_vulnerable = fmt in unsafe_formats
        
        if is_vulnerable:
            deserialization_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Insecure Deserialization Flaw!")
            print(f"     └─ Risk: Endpoint processes untrusted binary/serialized objects ({fmt}), risking Remote Code Execution (RCE).\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint utilizes safe data interchange formats (e.g., standard JSON).\n")
            
    return deserialization_alerts

# Run the deserialization vulnerability scan
total_vulnerabilities = scan_for_insecure_deserialization(deserialization_payloads)

print("--- DESERIALIZATION ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to Insecure Deserialization!")
    print(f"     └─ Action Required: Avoid native binary serialization formats (pickle, Java streams); use safe parsers like JSON or Protocol Buffers.")
else:
    print("  ✅ [SECURE]: All API endpoints passed serialization safety verification.")

print("==========================================")