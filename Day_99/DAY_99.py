# ==========================================
# Day 99: Automated GraphQL Vulnerability & Introspection Scanner
# Purpose: Practice API security assessment by detecting exposed GraphQL introspection and missing batching controls
# ==========================================

print("=== AUTOMATED GRAPHQL VULNERABILITY SCANNER ===")

# Simulated GraphQL endpoints and inspection test responses
graphql_endpoints = [
    {
        "endpoint": "/api/graphql",
        "introspection_enabled": True,  # Vulnerable: Exposes entire database schema!
        "batching_allowed": True,       # Vulnerable: Allows query batching DoS!
        "max_query_depth": 15           # Too deep / unconstrained
    },
    {
        "endpoint": "/graphql/v1/query",
        "introspection_enabled": False, # Secure: Disabled in production
        "batching_allowed": False,      # Secure: Batching restricted
        "max_query_depth": 3            # Secure: Strict depth limit enforced
    },
    {
        "endpoint": "/internal/gql",
        "introspection_enabled": True,  # Vulnerable: Internal debug endpoint exposed
        "batching_allowed": True,
        "max_query_depth": 10
    }
]

def scan_graphql_endpoints(endpoints):
    print("[*] Initiating automated GraphQL security and introspection audit...\n")
    graphql_alerts = 0
    
    for target in endpoints:
        ep = target["endpoint"]
        introspection = target["introspection_enabled"]
        batching = target["batching_allowed"]
        depth = target["max_query_depth"]
        
        print(f"[-] Testing Endpoint: {ep}")
        print(f"    ├─ Introspection Enabled: {introspection}")
        print(f"    ├─ Query Batching Allowed: {batching}")
        print(f"    └─ Max Query Depth Limit: {depth}")
        
        # Evaluate GraphQL security risks
        if introspection or batching or depth > 5:
            graphql_alerts += 1
            print(f"  🚨 [VULNERABILITY DETECTED]: GraphQL Security Flaw!")
            if introspection:
                print(f"     └─ Risk: Introspection is active, allowing complete schema mapping.")
            if batching:
                print(f"     └─ Risk: Unrestricted query batching risks Denial-of-Service (DoS).")
            if depth > 5:
                print(f"     └─ Risk: Query depth limit ({depth}) is too high, risking nested resource exhaustion.\n")
            print()
        else:
            print(f"  ✅ [SECURE]: GraphQL endpoint properly hardened with introspection disabled and depth limits enforced.\n")
            
    return graphql_alerts

# Run the GraphQL vulnerability scan
total_vulnerabilities = scan_graphql_endpoints(graphql_endpoints)

print("--- GRAPHQL ASSESSMENT SUMMARY ---")
if total_vulnerabilities > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_vulnerabilities} GraphQL endpoint(s) with security configuration flaws!")
    print(f"     └─ Action Required: Disable introspection in production, enforce query depth/complexity limits, and restrict batching.")
else:
    print("  ✅ [SECURE]: All GraphQL endpoints passed security configuration verification.")

print("==========================================")