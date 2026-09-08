# ==========================================
# Day 52: AWS CloudTrail Suspicious API Auditor
# Purpose: Practice cloud log analysis and detection of high-risk administrative actions
# ==========================================

import json

print("=== AWS CLOUDTRAIL SUSPICIOUS API AUDITOR ===")

# Simulated AWS CloudTrail log entries (JSON format representing management events)
cloudtrail_logs = [
    {
        "eventTime": "2026-09-08T10:15:22Z",
        "eventName": "DescribeInstances",
        "sourceIPAddress": "192.168.1.50",
        "userIdentity": {"userName": "developer_alice"},
        "readOnly": True
    },
    {
        "eventTime": "2026-09-08T10:22:05Z",
        "eventName": "CreateAccessKey",
        "sourceIPAddress": "203.0.113.88",
        "userIdentity": {"userName": "contractor_bob"},
        "readOnly": False
    },
    {
        "eventTime": "2026-09-08T11:05:12Z",
        "eventName": "AuthorizeSecurityGroupIngress",
        "sourceIPAddress": "198.51.100.45",
        "userIdentity": {"userName": "admin_service_role"},
        "readOnly": False
    },
    {
        "eventTime": "2026-09-08T11:30:00Z",
        "eventName": "StopLogging",
        "sourceIPAddress": "203.0.113.88",
        "userIdentity": {"userName": "compromised_user"},
        "readOnly": False
    }
]

# High-risk CloudTrail event names indicating potential compromise or persistence
high_risk_events = [
    "CreateAccessKey",              # Creating long-term programmatic credentials
    "AuthorizeSecurityGroupIngress", # Opening firewall ports to the world
    "StopLogging",                  # Attempting to blind security monitoring
    "CreateUser",                   # Adding unauthorized IAM accounts
    "AttachUserPolicy"              # Escalating privileges
]

def audit_cloudtrail_logs(logs, sensitive_events):
    print("[*] Parsing CloudTrail management event logs for high-risk API activity...\n")
    alerts = 0
    
    for log in logs:
        event_name = log.get("eventName")
        source_ip = log.get("sourceIPAddress")
        username = log.get("userIdentity", {}).get("userName", "Unknown")
        timestamp = log.get("eventTime")
        
        if event_name in sensitive_events:
            alerts += 1
            print(f"  🚨 [HIGH-RISK CLOUD EVENT]: Unauthorized or sensitive action detected!")
            print(f"     ├─ Timestamp: {timestamp}")
            print(f"     ├─ Event Name: {event_name}")
            print(f"     ├─ User Identity: {username}")
            print(f"     └─ Source IP: {source_ip}\n")
        else:
            print(f"  ✅ [NORMAL]: User '{username}' performed '{event_name}' from {source_ip}")
            
    return alerts

# Run the CloudTrail audit
total_alerts = audit_cloudtrail_logs(cloudtrail_logs, high_risk_events)

print("--- CLOUDTAIL AUDIT SUMMARY ---")
if total_alerts > 0:
    print(f"  ⚠️ [ALERT]: Flagged {total_alerts} high-risk cloud API event(s)!")
    print(f"     └─ Action Required: Investigate user sessions and revoke compromised credentials.")
else:
    print("  ✅ [SECURE]: All CloudTrail events conform to standard operational baselines.")

print("==========================================")