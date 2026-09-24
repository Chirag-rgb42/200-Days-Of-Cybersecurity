# ==========================================
# Day 68: DFIR Incident Timeline Chronological Correlator
# Purpose: Practice digital forensics by merging multi-artifact logs into a unified timeline
# ==========================================

print("=== DFIR INCIDENT TIMELINE CORRELATOR ===")

# Simulated multi-artifact forensic logs from various sources
forensic_evidence = [
    {
        "timestamp": "2026-09-24T09:12:05",
        "source": "Browser History",
        "artifact": "Downloaded payload.exe from http://malicious-drop.net",
        "risk_level": "HIGH"
    },
    {
        "timestamp": "2026-09-24T09:12:40",
        "source": "Endpoint Process Log",
        "artifact": "Executed C:\\Users\\Public\\payload.exe (PID: 2048)",
        "risk_level": "HIGH"
    },
    {
        "timestamp": "2026-09-24T09:15:00",
        "source": "Registry Run Key",
        "artifact": "Added persistence entry: UpdaterService -> payload.exe",
        "risk_level": "HIGH"
    },
    {
        "timestamp": "2026-09-24T09:20:15",
        "source": "Firewall Telemetry",
        "artifact": "Outbound connection to C2 IP 203.0.113.99 on port 4444",
        "risk_level": "HIGH"
    }
]

def reconstruct_attack_timeline(evidence):
    print("[*] Ingesting multi-source forensic logs and building chronological timeline...\n")
    
    # Sort evidence items chronologically based on their timestamp string
    sorted_timeline = sorted(evidence, key=lambda x: x["timestamp"])
    
    incident_steps = 0
    for event in sorted_timeline:
        incident_steps += 1
        time = event["timestamp"]
        source = event["source"]
        artifact = event["artifact"]
        risk = event["risk_level"]
        
        print(f"  [Step {incident_steps}] 🕒 {time}")
        print(f"     ├─ Evidence Source: {source}")
        print(f"     ├─ Forensic Artifact: {artifact}")
        print(f"     └─ Risk Indicator: 🚨 {risk}\n")
        
    return incident_steps

# Run the timeline reconstruction
total_events = reconstruct_attack_timeline(forensic_evidence)

print("--- INCIDENT RECONSTRUCTION SUMMARY ---")
print(f"  📊 Successfully correlated {total_events} forensic artifacts into a unified attack narrative.")
print(f"     └─ Conclusion: Full lifecycle intrusion detected (Download $\rightarrow$ Execution $\rightarrow$ Persistence $\rightarrow$ C2).")
print("==========================================")