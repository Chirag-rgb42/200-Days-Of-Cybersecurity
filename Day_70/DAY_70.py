# ==========================================
# Day 70: Automated Port Scanner & Service Banner Grabbing Tool
# Purpose: Practice vulnerability assessment, asset discovery, and service identification
# ==========================================

import socket

print("=== AUTOMATED PORT SCANNER & BANNER GRABBER ===")

# Target host configuration (Using localhost / loopback for safe practice)
target_host = "127.0.0.1"
ports_to_scan = [21, 22, 80, 443, 3306, 8080]

def grab_banner(s):
    try:
        s.settimeout(2.0)
        banner = s.recv(1024).decode().strip()
        return banner if banner else "No banner returned"
    except Exception:
        return "Banner retrieval failed or timeout"

def scan_ports(host, ports):
    print(f"[*] Initiating vulnerability assessment scan on target: {host}\n")
    open_ports_found = 0
    
    for port in ports:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        
        result = sock.connect_ex((host, port))
        
        if result == 0:
            open_ports_found += 1
            print(f"  🚨 [PORT OPEN]: Port {port} is active.")
            
            # Attempt to grab service banner
            banner = grab_banner(sock)
            print(f"     └─ Service Banner: {banner}\n")
        else:
            print(f"  ✅ [CLOSED]: Port {port}")
            
        sock.close()
        
    return open_ports_found

# Run the port scan and banner grabber
total_open = scan_ports(target_host, ports_to_scan)

print("--- VULNERABILITY ASSESSMENT SUMMARY ---")
print(f"  📊 Scan Completed on {target_host}")
print(f"  🔍 Open Ports Discovered: {total_open}")
print(f"     └─ Next Step: Cross-reference discovered service banners against CVE databases.")
print("==========================================")