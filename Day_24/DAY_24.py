# ==========================================
# Day 24: Threat Intelligence IP Reputation Checker
# Purpose: Practice API integration concepts and threat intelligence lookups
# ==========================================

import json

print("=== THREAT INTELLIGENCE IP REPUTATION CHECKER ===")

# Simulated threat intelligence database / API response mock
# (In production, this would query APIs like AbuseIPDB or VirusTotal using the 'requests' library)
mock_threat_intel_db = {
    "192.168.1.50": {"status": "Malicious", "reports": 45, "category": "Brute-Force"},
    "203.0.113.45": {"status": "Malicious", "reports": 120, "category": "SSH Scanner"},
    "10.0.0.15": {"status": "Clean", "reports": 0, "category": "None"}
}

def check_ip_reputation(ip_address):
    print(f"[*] Querying Threat Intelligence feed for IP: {ip_address}...")
    
    # Real-world API integration pattern:
    # response = requests.get(f"https://api.example-threat-intel.com/v2/check?ip={ip_address}", headers=api_headers)
    
    intel_data = mock_threat_intel_db.get(ip_address, {"status": "Unknown", "reports": 0, "category": "Unlisted"})
    return intel_data

# Test the lookup with sample source IPs
test_ips = ["192.168.1.50", "10.0.0.15", "203.0.113.45"]

print("--- RUNNING REPUTATION AUDIT ---")
for ip in test_ips:
    result = check_ip_reputation(ip)
    print(f"  ├─ Target IP: {ip}")
    print(f"  ├─ Reputation Status: {result['status']}")
    print(f"  ├─ Community Reports: {result['reports']}")
    print(f"  └─ Attack Category:   {result['category']}\n")

print("==========================================")