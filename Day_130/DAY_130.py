# ==========================================
# Day 130: Automated SSRF (Server-Side Request Forgery) & URL Allowlist Validator
# Purpose: Defensively validate outbound webhook/fetch URLs against private IPs, cloud metadata endpoints, and unsafe schemes
# ==========================================

import ipaddress
from urllib.parse import urlparse

print("=== AUTOMATED SSRF & OUTBOUND URL SECURITY VALIDATOR ===")

# Explicit allowlist of approved external webhook/integration domains
APPROVED_EXTERNAL_DOMAINS = {
    "api.stripe.com",
    "webhooks.partner-trusted.com",
    "events.corp-integrations.com"
}

# Simulated user-supplied URLs submitted to a webhook or URL-preview endpoint
submitted_urls = [
    "https://webhooks.partner-trusted.com/events/notify",                # Safe: Approved HTTPS domain
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", # Unsafe: Cloud metadata endpoint (Link-Local)!
    "http://127.0.0.1:8080/admin/shutdown",                              # Unsafe: Loopback internal service!
    "http://10.24.15.8:9200/_cat/indices",                               # Unsafe: RFC 1918 private internal network!
    "file:///etc/passwd",                                                # Unsafe: Local file scheme!
    "https://untrusted-external-site.org/callback"                       # Unsafe: Domain not in allowlist!
]

def validate_outbound_url(raw_url):
    """Validates a URL against scheme, IP range, and domain allowlist rules to prevent SSRF."""
    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    # 1. Enforce strict HTTP/HTTPS scheme allowlist
    if scheme not in ("http", "https"):
        return False, f"Blocked Scheme ('{scheme}://'): Only 'http' and 'https' protocols are permitted."

    if not hostname:
        return False, "Malformed URL: Missing target hostname."

    # 2. Block explicit localhost aliases
    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return False, f"Blocked Loopback Hostname ('{hostname}'): Internal host access denied."

    # 3. Check if hostname is a direct IP literal and validate against non-public ranges
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.is_loopback:
            return False, f"Blocked Loopback IP ('{ip_obj}'): Access to 127.0.0.0/8 or ::1 is prohibited."
        if ip_obj.is_link_local:
            return False, f"Blocked Link-Local / Cloud Metadata IP ('{ip_obj}'): Access to 169.254.0.0/16 is prohibited."
        if ip_obj.is_private:
            return False, f"Blocked Private RFC 1918 IP ('{ip_obj}'): Internal network traversal denied."
        if ip_obj.is_reserved or ip_obj.is_multicast:
            return False, f"Blocked Reserved/Multicast IP ('{ip_obj}'): Non-routable address denied."
        return False, f"Blocked Direct IP Access ('{ip_obj}'): Outbound requests must use allowlisted domain names."
    except ValueError:
        # Hostname is a domain name rather than a raw IP literal
        pass

    # 4. Enforce strict external domain allowlist
    if hostname.lower() not in APPROVED_EXTERNAL_DOMAINS:
        return False, f"Unapproved Domain ('{hostname}'): Domain is not present in the outbound allowlist."

    return True, f"Verified safe outbound destination ('{hostname}')."

def run_ssrf_audit(urls):
    print("[*] Evaluating submitted outbound URLs against SSRF defense rules...\n")
    blocked_count = 0

    for url in urls:
        is_safe, reason = validate_outbound_url(url)
        print(f"[-] Inspecting URL: {url}")
        if is_safe:
            print(f"  ✅ [ALLOWED]: {reason}\n")
        else:
            blocked_count += 1
            print(f"  🚨 [SSRF BLOCKED]: {reason}\n")

    return blocked_count

# Execute the SSRF URL validation audit
total_blocked = run_ssrf_audit(submitted_urls)

print("--- SSRF URL VALIDATION SUMMARY ---")
print(f"  🛡️ Total URLs Inspected : {len(submitted_urls)}")
print(f"  ⛔ Unsafe URLs Blocked  : {total_blocked}")
print("  ✅ Policy Enforcement   : Strict scheme allowlist, RFC 1918/link-local IP filtering, and domain allowlisting active.")
print("==========================================")