# ==========================================
# Day 25: Basic Service Banner Grabber
# Purpose: Practice service fingerprinting and network reconnaissance
# ==========================================

import socket

print("=== BASIC SERVICE BANNER GRABBER ===")

def grab_banner(ip, port):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        # Connect to target IP and port
        sock.connect((ip, port))
        
        # Attempt to receive the welcome banner sent by the service
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if banner:
            print(f"[+] Banner successfully grabbed from {ip}:{port}:")
            print(f"    \"{banner}\"")
        else:
            print(f"[-] Connected, but no banner text received from {ip}:{port}.")
            
        sock.close()
    except socket.timeout:
        print(f"⏱️ [TIMEOUT]: Connection to {ip}:{port} timed out.")
    except ConnectionRefusedError:
        print(f"❌ [REFUSED]: Port {port} is closed or refusing connections.")
    except Exception as e:
        print(f"🚨 [ERROR]: An unexpected error occurred: {e}")

# Target configuration (using local loopback for safe testing)
target_ip = "127.0.0.1"
target_port = 22 # Standard SSH port (change if testing another local service)

print(f"[*] Scanning target {target_ip} on port {target_port}...")
grab_banner(target_ip, target_port)
print("==========================================")