# ==========================================
# Day 17: Multi-Threaded High-Speed Port Scanner
# Purpose: Practice concurrency and multithreading for speed optimization
# ==========================================

import socket
import threading
import time

print("=== HIGH-SPEED MULTI-THREADED PORT SCANNER ===")

target_host = "127.0.0.1"

# Function to scan a single port
def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_host, port))
        
        if result == 0:
            print(f"🟢 [OPEN] Port {port} is active.")
        
        sock.close()
    except socket.error:
        pass


# Range of ports to scan (e.g., ports 1 to 100)
ports_to_scan = range(1, 101)

print(f"[*] Scanning target {target_host} across ports 1-100 using threads...")
start_time = time.time()

threads = []

# Create a thread for every single port scan
for port in ports_to_scan:
    # Initialize a thread targeting our scan_port function
    t = threading.Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()  # Start the thread execution

# Wait for all threads to complete before ending the program
for t in threads:
    t.join()

end_time = time.time()
print("-" * 40)
print(f"[*] Multi-threaded scan completed in {end_time - start_time:.4f} seconds.")
print("==============================================")