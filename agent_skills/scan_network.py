#!/usr/bin/env python3
import sys
import json
import psutil

def run_ndr_scan():
    """
    Agentic Wrapper Skill: Performs a single-shot execution of Watchtower NDR.
    Outputs strict JSON for LLM ingestion.
    """
    try:
        try:
            connections = psutil.net_connections(kind='tcp')
        except psutil.AccessDenied:
            print(json.dumps({
                "skill": "watchtower_scan_network",
                "error": "Root/Administrator privileges (sudo) required natively on macOS/Linux to map global socket arrays.",
                "ai_verdict": "UNVERIFIED: PERMISSION DENIED"
            }, indent=2))
            sys.exit(1)
            
        external = [c for c in connections if c.raddr and not str(c.raddr.ip).startswith(("127.", "100."))]
        
        # Determine Verdict
        verdict = "SAFE"
        if len(external) > 150:
            verdict = "CRITICAL: MASS EXFILTRATION C2 BURST DETECTED"
        elif len(external) > 50:
            verdict = "WARNING: HIGH EXTERNAL PORT USAGE"

        # Unique external IPs
        ip_set = set([c.raddr.ip for c in external])

        payload = {
            "skill": "watchtower_scan_network",
            "total_local_sockets": len(connections),
            "total_external_sockets": len(external),
            "unique_external_targets": len(ip_set),
            "ai_verdict": verdict,
            "connected_ips": list(ip_set)
        }
        
        print(json.dumps(payload, indent=2))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e), "skill": "watchtower_scan_network"}))
        sys.exit(1)

if __name__ == "__main__":
    run_ndr_scan()
