# ==========================================
# Day 13: Encapsulation & Secure Firewall Rules (OOP)
# Purpose: Practice private attributes and controlled data modification
# ==========================================

print("=== SECURE FIREWALL RULE MANAGER ===")

class FirewallRule:
    def __init__(self, rule_id, ip_address, action):
        self.rule_id = rule_id
        self.__ip_address = ip_address  # Private attribute (hidden)
        self.__action = action          # Private attribute (hidden)

    # Getter method to safely view the private IP address
    def get_ip_address(self):
        return self.__ip_address

    # Getter method to view the action
    def get_action(self):
        return self.__action

    # Setter method to safely update the action with validation
    def set_action(self, new_action):
        allowed_actions = ["ALLOW", "BLOCK", "LOG"]
        
        if new_action.upper() in allowed_actions:
            self.__action = new_action.upper()
            print(f"✅ Firewall rule {self.rule_id} updated successfully to: {self.__action}")
        else:
            print(f"❌ [SECURITY ERROR]: '{new_action}' is not a valid firewall action. Update rejected.")

    # Method to display rule summary
    def display_rule(self):
        print(f"Rule ID: {self.rule_id} | IP: {self.__ip_address} | Action: {self.__action}")


# --- TESTING ENCAPSULATION ---

print("\n--- Initializing Firewall Rule ---")
rule1 = FirewallRule("RULE-001", "192.168.1.150", "BLOCK")
rule1.display_rule()

# Attempting to access private attributes directly (This would fail or bypass controls)
# print(rule1.__action) # Uncommenting this line would throw an AttributeError!

print("\n--- Testing Safe Updates via Setter ---")
# Valid update
rule1.set_action("LOG")
rule1.display_rule()

# Invalid update attempt
rule1.set_action("DELETE_EVERYTHING")
rule1.display_rule()

print("\n========================================")