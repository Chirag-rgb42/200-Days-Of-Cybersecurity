# ==========================================
# Day 11: Security Alert Object Modeling (OOP)
# Purpose: Practice Python Classes and Objects
# ==========================================

print("=== INCIDENT RESPONSE OBJECT ENGINE ===")

# 1. Define a Class for Security Alerts
class SecurityAlert:
    # Constructor method to initialize the alert object
    def __init__(self, alert_id, severity, source_ip, description):
        self.alert_id = alert_id
        self.severity = severity
        self.source_ip = source_ip
        self.description = description
        self.status = "OPEN"  # Default status for new alerts

    # Method to display the alert details
    def display_alert(self):
        print(f"\n[Alert #{self.alert_id}] Severity: {self.severity.upper()}")
        print(f"  ├─ Source IP: {self.source_ip}")
        print(f"  ├─ Description: {self.description}")
        print(f"  └─ Current Status: {self.status}")

    # Method to update the alert status
    def resolve_alert(self):
        self.status = "RESOLVED"
        print(f"✅ Alert #{self.alert_id} has been marked as RESOLVED.")


# 2. Instantiate (create) individual Alert objects from our class
alert1 = SecurityAlert("ALT-501", "High", "203.0.113.45", "Brute-force SSH attack detected")
alert2 = SecurityAlert("ALT-502", "Medium", "192.168.1.100", "Unauthorized port scan initiated")

# 3. Interact with our objects
alert1.display_alert()
alert2.display_alert()

print("\n--- Performing Incident Response Action ---")
alert1.resolve_alert()

# Check status update on alert1
alert1.display_alert()

print("========================================")