# ==========================================
# Day 4: Automated Port Scanner Simulator
# Purpose: Practice 'for' loops and range automation
# ==========================================

print("=== AUTOMATED NETWORK PORT SCANNER ===")
print("Target IP: 192.168.1.1\n")

# range(1, 31) will loop from number 1 up to number 30
for port in range(1, 31):
    
    if port == 13:
        print(f"📡 Port {port}: [OPEN] <-- ⚠️ WARNING: Insecure FTP detected!")
    elif port == 20:
        print(f"📡 Port {port}: [OPEN] <-- ✅ Secure SSH Access available.")
    elif port == 27:
        print(f"📡 Port {port}: [OPEN] <-- 🚨 CRITICAL: Vulnerable Telnet protocol active!")
    else:
        # 3. For all other ports, show they are closed
        print(f"📡 Port {port}: [CLOSED]")

print("\n=== SCAN COMPLETE: 3 Open Ports Found ===")