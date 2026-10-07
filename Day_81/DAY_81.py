# ==========================================
# Day 81: Automated IDOR (Insecure Direct Object Reference) Vulnerability Scanner
# Purpose: Practice API vulnerability assessment and detection of missing object-level authorization controls
# ==========================================

print("=== AUTOMATED IDOR / BOLA VULNERABILITY SCANNER ===")

# Simulated API endpoints and user requests targeting resource identifiers
api_requests = [
    {
        "endpoint": "/api/v1/user/profile",
        "parameter": "id",
        "requested_id": "1001",
        "session_user": "user_alice",
        "owner_user": "user_alice"
    },
    {
        "endpoint": "/api/v1/user/profile",
        "parameter": "id",
        "requested_id": "1002",
        "session_user": "user_alice",
        "owner_user": "user_bob"     # Alice trying to access Bob's ID!
    },
    {
        "endpoint": "/api/v1/documents",
        "parameter": "doc_id",
        "requested_id": "504",
        "session_user": "user_alice",
        "owner_user": "user_charlie" # Alice trying to access Charlie's document!
    },
    {
        "endpoint": "/api/v1/settings",
        "parameter": "account_no",
        "requested_id": "9981",
        "session_user": "user_alice",
        "owner_user": "user_alice"
    }
]

def simulate_api_response(req):
    # Mocking authorization enforcement behavior
    session = req["session_user"]
    owner = req["owner_user"]
    
    # Vulnerable behavior: Server returns data if requested ID is valid, without checking session ownership
    if session != owner:
        return {
            "status_code": 200, 
            "vulnerable": True, 
            "body": f"SUCCESS: Retrieved confidential data belonging to {owner} using session {session}."
        }
    else:
        return {
            "status_code": 200, 
            "vulnerable": False, 
            "body": "SUCCESS: Authorized resource access."
        }

def scan_for_idor(requests):
    print("[*] Initiating automated IDOR / BOLA scan across object identifiers...\n")
    idor_alerts = 0
    
    for req in requests:
        endpoint = req["endpoint"]
        param = req["parameter"]
        req_id = req["requested_id"]
        session = req["session_user"]
        owner = req["owner_user"]
        
        response = simulate_api_response(req)
        
        if response["vulnerable"]:
            idor_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: Potential IDOR / BOLA Flaw!")
            print(f"     ├─ Target Endpoint: {endpoint}")
            print(f"     ├─ Parameter & Value: {param}={req_id}")
            print(f"     ├─ Session Context: {session}")
            print(f"     ├─ Resource Owner: {owner}")
            print(f"     └─ Server Response: {response['body']}\n")
        else:
            print(f"  ✅ [SECURE]: Endpoint '{endpoint}' enforced object ownership for {param}={req_id}.")
            
    return idor_alerts

# Run the IDOR vulnerability scan
total_vulnerabilities = scan_for_idor(api_requests)

print("--- IDOR ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} endpoint(s) vulnerable to IDOR / BOLA!")
    print(f"     └─ Action Required: Implement robust server-side authorization checks verifying user ownership of requested objects.")
else:
    print("  ✅ [SECURE]: All object-level requests successfully validated authorization.")

print("==========================================")