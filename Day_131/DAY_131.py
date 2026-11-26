# ==========================================
# Day 131: Automated XXE (XML External Entity) & Unsafe Parser Security Auditor
# Purpose: Audit incoming XML payloads for external entity injection (XXE) and verify parser hardening configurations
# ==========================================

import re

print("=== AUTOMATED XXE & XML PARSER SECURITY AUDITOR ===")

# Regex patterns to detect DTDs, External Entities, and Billion Laughs expansion in XML payloads
DOCTYPE_PATTERN = re.compile(r"<!DOCTYPE\s+", re.IGNORECASE)
EXTERNAL_ENTITY_PATTERN = re.compile(r"<!ENTITY\s+\S+\s+(SYSTEM|PUBLIC)\s+", re.IGNORECASE)
GENERAL_ENTITY_PATTERN = re.compile(r"<!ENTITY\s+", re.IGNORECASE)

# Simulated XML payloads and microservice parser configurations
xml_endpoints_audit = [
    {
        "service": "Order Fulfillment API",
        "parser_library": "defusedxml.ElementTree",
        "dtd_processing_disabled": True,
        "sample_payload": """<?xml version="1.0" encoding="UTF-8"?>
<order>
    <order_id>ORD-90421</order_id>
    <item>Hardware Security Key</item>
    <quantity>2</quantity>
</order>"""
    },
    {
        "service": "Legacy SAML SSO Endpoint",
        "parser_library": "xml.etree.ElementTree",  # Vulnerable: Standard library parser without defusedxml!
        "dtd_processing_disabled": False,
        "sample_payload": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<samlResponse><user>&xxe;</user></samlResponse>"""  # Vulnerable: External SYSTEM file entity!
    },
    {
        "service": "Partner Invoice Importer",
        "parser_library": "lxml.etree.XMLParser",
        "dtd_processing_disabled": False,          # Vulnerable: DTDs still permitted (Billion Laughs risk)!
        "sample_payload": """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<invoice><note>&lol2;</note></invoice>"""        # Vulnerable: Nested entity expansion payload!
    }
]

def audit_xml_security(endpoints):
    print("[*] Initiating XML External Entity (XXE) and parser configuration audit...\n")
    xxe_alerts = 0

    for item in endpoints:
        svc = item["service"]
        parser = item["parser_library"]
        dtd_disabled = item["dtd_processing_disabled"]
        payload = item["sample_payload"]
        findings = []

        # 1. Audit parser library hardening
        if parser.startswith("xml.") or not dtd_disabled:
            findings.append(
                f"High - Unsafe XML Parser Configuration ('{parser}', dtd_disabled={dtd_disabled}): "
                "Migrate to 'defusedxml' or explicitly set resolve_entities=False and no_network=True."
            )

        # 2. Inspect XML payload for External Entities (SYSTEM / PUBLIC)
        if EXTERNAL_ENTITY_PATTERN.search(payload):
            findings.append(
                "Critical - XXE External Entity Detected ('<!ENTITY ... SYSTEM/PUBLIC>'): "
                "Blocks attempt to read local files or trigger internal SSRF requests."
            )
        elif GENERAL_ENTITY_PATTERN.search(payload):
            findings.append(
                "High - Internal Entity Expansion Detected ('<!ENTITY>'): "
                "Potential Billion Laughs XML bomb denial-of-service payload."
            )

        # 3. Check for DOCTYPE declarations
        if DOCTYPE_PATTERN.search(payload):
            findings.append(
                "Medium - DTD Declaration ('<!DOCTYPE>') Present: Reject payloads containing inline Document Type Definitions."
            )

        print(f"[-] Auditing XML Service: {svc}")
        print(f"    ├─ Parser Library : {parser}")
        print(f"    └─ DTDs Disabled  : {dtd_disabled}")

        if findings:
            xxe_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: {len(findings)} XXE/Parser security issue(s)!")
            for issue in findings:
                print(f"     └─ {issue}")
            print()
        else:
            print(f"  ✅ [SECURE]: Hardened XML parser active and payload is free of DTD/entity declarations.\n")

    return xxe_alerts

# Execute the XXE security audit
total_vulnerabilities = audit_xml_security(xml_endpoints_audit)

print("--- XXE & XML PARSER ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} XML service(s) vulnerable to XXE or entity expansion!")
    print(f"     └─ Action Required: Replace standard 'xml.*' parsers with 'defusedxml', disable DTD processing, and reject incoming '<!DOCTYPE>' declarations.")
else:
    print("  ✅ [SECURE]: All audited XML endpoints passed XXE and parser security verification.")

print("==========================================")