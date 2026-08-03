# ==========================================
# Day 18: Basic Network Packet Sniffer
# Purpose: Understand raw sockets and passive traffic capture concepts
# ==========================================

import socket
import os
import sys

print("=== BASIC RAW SOCKET PACKET SNIFFER ===")

def start_sniffer():
    # Determine host IP based on operating system
    host = "127.0.0.1" # Using loopback for safe local demonstration

    try:
        # Create a raw socket to capture IP packets (AF_INET for IPv4, SOCK_RAW for raw packets)
        # Note: IPPROTO_IP captures all IP traffic. Root privileges required (sudo on Linux/macOS).
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        sniffer.bind((host, 0))
        
        # Include IP headers in the captured data
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print(f"[*] Sniffer active on host: {host}")
        print("[*] Listening for incoming network packets... (Press Ctrl+C to stop)")

        # Capture a single packet for demonstration
        # In a real tool, this would be wrapped in an infinite while loop.
        raw_buffer = sniffer.recvfrom(65565)[0]
        print(f"[+] Captured packet of length: {len(raw_buffer)} bytes")
        print(f"[+] First 50 bytes of raw data: {raw_buffer[:50]}")

    except PermissionError:
        print("❌ [PERMISSION ERROR]: Raw sockets require Administrator or Root privileges.")
        print("   -> Try running your terminal as Administrator (Windows) or use 'sudo python3 day18.py' (Linux/Mac).")
    except Exception as e:
        print(f"🚨 [ERROR]: An unexpected error occurred: {e}")

if __name__ == "__main__":
    start_sniffer()
    print("========================================")