# ==========================================
# Day 5: Network Protocol Database Lookup
# Purpose: Practice Python dictionaries and lookups
# ==========================================

print("=== NETWORK PROTOCOL DATABASE ===")

protocol_ports = {
    "FTP": 21,
    "SSH": 22,
    "Telnet": 23,
    "HTTP": 80,
    "HTTPS": 443
}

protocol_security = {
    "FTP": "❌ INSECURE (Plaintext credentials)",
    "SSH": "✅ SECURE (Encrypted traffic)",
    "Telnet": "❌ INSECURE (Cleartext communication)",
    "HTTP": "❌ INSECURE (Unencrypted web traffic)",
    "HTTPS": "✅ SECURE (Encrypted web traffic)"
}

query = input("Enter protocol name to look up (e.g., SSH, HTTP, FTP): ")

if query in protocol_ports:
    port = protocol_ports[query]
    status = protocol_security[query]
    
    print(f"\n🔍 Protocol Profile: {query}")
    print(f"📡 Standard Port: {port}")
    print(f"🛡️ Security Status: {status}")
else:
    print("\n❌ Protocol not found in the baseline database.")

print("=================================")