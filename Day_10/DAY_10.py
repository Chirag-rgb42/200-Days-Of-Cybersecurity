# ==========================================
# Day 10: Bulletproof Log Reader with Error Handling
# Purpose: Practice try/except blocks to prevent script crashes
# ==========================================

print("=== SECURE LOG PARSER INITIALIZED ===")

# Intentionally targeting a log file that might not exist yet
target_log = "missing_security_audit.log"

try:
    print(f"\n[Attempting to open '{target_log}'...]")
    
    # This will trigger a FileNotFoundError because the file hasn't been created
    with open(target_log, "r") as log_file:
        content = log_file.read()
        print(content)

except FileNotFoundError:
    print("❌ [ERROR CAUGHT]: The specified log file could not be found.")
    print("🛡️ [SAFE RECOVERY]: Defaulting to backup system logs or alerting the admin instead of crashing.")

except Exception as e:
    # A catch-all safety net for any other unexpected errors
    print(f"🚨 [UNEXPECTED ERROR]: {e}")

finally:
    print("\n[Execution completed safely. System resources cleaned up.]")
    print("======================================")