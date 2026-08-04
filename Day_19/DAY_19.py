# ==========================================
# Day 19: IP Header Packet Parser
# Purpose: Practice binary unpacking and network protocol decoding
# ==========================================

import socket
import struct

print("=== IP HEADER PACKET PARSER ===")

# Let's simulate a raw IPv4 header byte string for demonstration safely
# (In a live sniffer, this data comes directly from socket.recvfrom())
# Breakdown of a simulated minimal IPv4 header:
# Version/IHL (0x45), Type of Service (0x00), Total Length (0x0014), etc.
simulated_ip_header = b'\x45\x00\x00\x14\xab\xcd\x00\x00\x40\x06\x3c\xaf\xc0\xa8\x01\x0a\x08\x08\x08\x08'

def parse_ip_header(packet_bytes):
    print("[*] Parsing raw packet bytes...")
    
    # Unpack the first 20 bytes of the IP header
    # ! = Network byte order (Big Endian)
    # BBH = Unsigned Char (1 byte), Unsigned Char (1 byte), Unsigned Short (2 bytes)
    # HH = Two Unsigned Shorts
    # BBH = Char, Char, Short
    # 4s4s = 4-byte source IP, 4-byte destination IP
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', packet_bytes[:20])
    
    version_ihl = unpacked_data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    
    ttl = unpacked_data[5]
    protocol = unpacked_data[6]
    
    # Convert packed 4-byte IPs into human-readable dotted-decimal strings
    src_ip = socket.inet_ntoa(unpacked_data[8])
    dst_ip = socket.inet_ntoa(unpacked_data[9])
    
    print("\n--- DECODED PACKET METADATA ---")
    print(f"  ├─ IP Version: {version}")
    print(f"  ├─ Header Length: {iph_length} bytes")
    print(f"  ├─ Time to Live (TTL): {ttl}")
    print(f"  ├─ Protocol ID: {protocol}")
    print(f"  ├─ Source IP: {src_ip}")
    print(f"  └─ Destination IP: {dst_ip}")

# Run the parser on our simulated header
parse_ip_header(simulated_ip_header)
print("========================================")