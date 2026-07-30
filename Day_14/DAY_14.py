# ==========================================
# Day 14: Unified Threat Scanner (Polymorphism)
# Purpose: Practice method overriding and polymorphic execution
# ==========================================

print("=== UNIFIED THREAT MONITORING ENGINE ===")

# 1. Define distinct threat classes with the same method name: analyze()
class BruteForceLog:
    def __init__(self, ip):
        self.ip = ip

    def analyze(self):
        return f"🔍 [Brute-Force] Checking login failures for target IP: {self.ip}"


class MalwareLog:
    def __init__(self, filename):
        self.filename = filename

    def analyze(self):
        return f"🦠 [Malware] Scanning file hash and signature for: {self.filename}"


class PhishingLog:
    def __init__(self, sender_email):
        self.sender_email = sender_email

    def analyze(self):
        return f"🎣 [Phishing] Inspecting email header and links from: {self.sender_email}"


# --- IMPLEMENTING POLYMORPHISM ---

# 2. Create a mixed list of different threat objects
security_queue = [
    BruteForceLog("203.0.113.45"),
    MalwareLog("payload.exe"),
    PhishingLog("suspicious-support@fake-bank.com"),
    BruteForceLog("198.51.100.99")
]

print("\n--- Executing Batch Security Scan ---")

# 3. Loop through the list and call .analyze() on each object uniformly
# Notice how Python automatically knows which class's analyze() method to run!
for threat in security_queue:
    print(threat.analyze())

print("========================================")