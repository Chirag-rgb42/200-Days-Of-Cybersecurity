'''
==========================================
Day 2: Security Analyst Greeting Script
Purpose: Practice variables, inputs, and f-strings
========================================== 
'''

print("=== SECURE TERMINAL INITIALIZED ===")


analyst_name = input("Enter your Analyst Name: ")

clearance_level = int(input("Enter Security Clearance Level (1-5): "))

print("\n--- ACCESS GRANTED ---")
print(f"Welcome back, Analyst " + analyst_name + "!")
print(f"Your clearance level" ,[int(clearance_level)], "has been verified.")
print("System Status: All firewalls operational. No active breaches detected.")
print("====================================")