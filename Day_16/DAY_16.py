# ==========================================
# Day 16: Automated TCP Port Scanner
# Purpose: Practice network looping, sockets, and error handling
# ==========================================

import socket
import time

print("=== AUTOMATED TCP PORT SCANNER ===")

# Target host (Using local loopback for safe testing)
target_host = "127.0.0.1"

# Define a list of common ports to scan (e.g., FTP, SSH, HTTP, HTTPS)
ports_to_scan = [21, 22, 23, 80, 443, 8080]

print(f"[*] Scanning target: {target_host}")
print(f"[*] Total ports queued for scan: {len(ports_to_scan)}")
print("-" * 40)

start_time = time.time()

# Loop through each port in our target list
for port in ports_to_scan:
    try:
        # Create a fresh socket for each port check
        scanner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scanner_socket.settimeout(1.0) # Short timeout for speed
        
        # Attempt connection
        result = scanner_socket.connect_ex((target_host, port))
        
        # connect_ex returns 0 if the connection was successful (Port is OPEN)
        if result == 0:
            print(f"🟢 [OPEN] Port {port} is active and listening.")
        else:
            print(f"🔴 [CLOSED] Port {port}")
            
        # Close socket before moving to the next port
        scanner_socket.close()

    except socket.error:
        print(f"❌ [ERROR] Could not connect to port {port}.")

end_time = time.time()
print("-" * 40)
print(f"[*] Scan completed in {end_time - start_time:.2f} seconds.")
print("==========================================")