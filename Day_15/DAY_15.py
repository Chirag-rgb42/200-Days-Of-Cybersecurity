# ==========================================
# Day 15: Introduction to Network Sockets & TCP Client
# Purpose: Practice basic socket creation and connection handling
# ==========================================

import socket

print("=== BASIC TCP SOCKET CLIENT ===")

# Target host and port (Using a local loopback address for safe testing)
# In real penetration testing or auditing, this would be your target IP.
target_host = "127.0.0.1"
target_port = 9999  # Mock port

try:
    print(f"[*] Attempting to connect to {target_host} on port {target_port}...")
    
    # 1. Create a socket object
    # AF_INET specifies IPv4, SOCK_STREAM specifies TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set a timeout so the script doesn't hang indefinitely if the port is closed
    client_socket.settimeout(50.0)
    
    # 2. Attempt to connect to the target (Will fail safely if no server is listening)
    client_socket.connect((target_host, target_port))
    
    print("[+] Connection established successfully!")
    
    # 3. Send custom data/payload across the socket
    message = "GET / HTTP/1.1\r\nHost: local-target\r\n\r\n"
    client_socket.sendall(message.encode())
    
    # 4. Receive the response from the server
    response = client_socket.recv(4096)
    print(f"[*] Received response:\n{response.decode()}")

except socket.timeout:
    print("❌ [TIMEOUT]: Connection timed out. Target port may be filtered or closed.")

except ConnectionRefusedError:
    print("❌ [CONNECTION REFUSED]: No service is actively listening on this port.")

except Exception as e:
    print(f"🚨 [ERROR]: An unexpected socket error occurred: {e}")

finally:
    # Always ensure the socket is closed properly
    print("[*] Closing socket connection.")
    client_socket.close()
    print("========================================")