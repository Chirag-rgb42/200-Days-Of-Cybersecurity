# ==========================================
# Day 6: File Integrity Hash Checker Simulator
# Purpose: Practice defining and calling functions
# ==========================================

# 1. Define a function to compare file hashes
def check_file_integrity(original_hash, current_hash):
    """Compares two hash strings to detect file modification."""
    if original_hash == current_hash:
        return "✅ INTEGRITY VERIFIED: File has not been modified."
    else:
        return "🚨 ALERT: File hash mismatch! Possible unauthorized modification."

# 2. Define a function to print formatted security headers
def print_header(title):
    print("\n" + "=" * 40)
    print(f" 🛡️  {title.upper()}")
    print("=" * 40)

# --- MAIN PROGRAM EXECUTION ---

print_header("File Integrity Checker")

# Baseline hash (known good file)
baseline_hash = "e99a18c428cb38d5f260853678922e03"

# Case 1: Testing an unaltered file
test_hash_1 = "e99a18c428cb38d5f260853678922e03"
print("[Test 1] Checking uncorrupted system file...")
result1 = check_file_integrity(baseline_hash, test_hash_1)
print(f"Status: {result1}")

# Case 2: Testing a altered file
test_hash_2 = "a11b22c334dd55ee66ff77gg88hh99ii"
print("\n[Test 2] Checking modified system file...")
result2 = check_file_integrity(baseline_hash, test_hash_2)
print(f"Status: {result2}")

print_header("Check Complete")