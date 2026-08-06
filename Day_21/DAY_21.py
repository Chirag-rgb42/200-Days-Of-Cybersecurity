# ==========================================
# Day 21: Basic File Integrity Monitor (FIM)
# Purpose: Practice cryptographic hashing and system change detection
# ==========================================

import hashlib
import os

print("=== BASIC FILE INTEGRITY MONITOR (FIM) ===")

# Create a dummy sensitive configuration file for testing
target_filename = "critical_config.txt"

def create_dummy_file():
    with open(target_filename, "w") as f:
        f.write("admin_user=root\n")
        f.write("allow_remote_login=true\n")
    print(f"[*] Created baseline target file: {target_filename}")

# Function to calculate SHA-256 hash of a file
def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

# --- Main FIM Workflow ---
create_dummy_file()

# Step 1: Establish the baseline hash
baseline_hash = calculate_file_hash(target_filename)
print(f"[+] Baseline SHA-256 Hash established:\n    {baseline_hash}\n")

print("[*] Monitoring file integrity... (Simulating an external change)")

# Step 2: Simulate an unauthorized modification to the file
with open(target_filename, "a") as f:
    f.write("backdoor_account=active\n") # Unauthorized tampering!
print(f"⚠️ [SIMULATION]: Unauthorized modification appended to {target_filename}\n")

# Step 3: Check current hash against baseline
current_hash = calculate_file_hash(target_filename)
print(f"[+] Current SHA-256 Hash checked:\n    {current_hash}\n")

if baseline_hash == current_hash:
    print("✅ [SECURE]: File integrity intact. No changes detected.")
else:
    print("🚨 [ALERT]: File tampering or unauthorized modification detected!")

# Cleanup test file
if os.path.exists(target_filename):
    os.remove(target_filename)

print("==========================================")