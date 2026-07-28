# ==========================================
# Day 12: Threat Intelligence Inheritance (OOP)
# Purpose: Practice OOP Inheritance and Method Overriding
# ==========================================

print("=== THREAT INTELLIGENCE CLASSIFIER ===")

# 1. Define the Parent (Base) Class
class Threat:
    def __init__(self, threat_name, severity, target_ip):
        self.threat_name = threat_name
        self.severity = severity
        self.target_ip = target_ip

    def get_details(self):
        return f"Threat: {self.threat_name} | Severity: {self.severity} | Target: {self.target_ip}"


# 2. Define a Child Class for Brute-Force Attacks (inherits from Threat)
class BruteForceThreat(Threat):
    def __init__(self, target_ip, failed_attempts):
        # Use super() to inherit properties from the parent Threat class
        super().__init__("Brute-Force Attack", "High", target_ip)
        self.failed_attempts = failed_attempts

    # Specialized method specific to brute-force threats
    def calculate_risk(self):
        if self.failed_attempts > 10:
            return "🔴 CRITICAL RISK: Immediate firewall block required."
        return "🟡 MODERATE RISK: Monitor traffic closely."


# 3. Define another Child Class for Malware Infections (inherits from Threat)
class MalwareThreat(Threat):
    def __init__(self, target_ip, malware_family):
        super().__init__("Malware Payload", "Critical", target_ip)
        self.malware_family = malware_family

    # Specialized method for malware analysis
    def quarantine_action(self):
        return f"🚨 ISOLATION ENGAGED: Quarantining host {self.target_ip} due to {self.malware_family} infection."


# --- INSTANTIATING AND TESTING OBJECTS ---

print("\n--- Analyzing Brute-Force Event ---")
bf_incident = BruteForceThreat("192.168.1.55", 14)
print(bf_incident.get_details())
print(bf_incident.calculate_risk())

print("\n--- Analyzing Malware Event ---")
malware_incident = MalwareThreat("10.0.0.42", "Ransomware.LockBit")
print(malware_incident.get_details())
print(malware_incident.quarantine_action())

print("\n========================================")