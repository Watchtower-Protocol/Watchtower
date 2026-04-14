import os
import sys
import time
import json
import psutil
import urllib.request
from collections import defaultdict

API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040")
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"

# Known suspicious ports typically mapped to Metasploit, Cobalt Strike, or Cryptominers
SUSPICIOUS_PORTS = [4444, 4445, 1337, 31337, 6667, 3333, 9999, 4440]
egress_tracker = defaultdict(int)

def emit_ndr_threat(proc_name, pid, remote_ip, remote_port, details):
    payload = {
        "source": HOSTNAME,
        "event_type": "NDR_EGRESS_ANOMALY",
        "file_path": f"PID://{pid}",
        "description": details,
        "severity": "high",
        "ai_verdict": "MALICIOUS",
        "ai_reason": f"Network anomaly. Process {proc_name} communicating over atypical structures to {remote_ip}:{remote_port}."
    }
    try:
        req = urllib.request.Request(f"{API_URL}/api/v2/ingest/threat", json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req, timeout=5)
    except: pass

def run_ndr_sweep():
    # Sweep current network states natively mimicking packet flow inspection
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                r_ip, r_port = conn.raddr
                
                # Exclude localhost tunneling
                if r_ip in ['127.0.0.1', '0.0.0.0', '::1'] or r_ip.startswith("169.254"): continue
                
                try:
                    proc = psutil.Process(conn.pid)
                    p_name = proc.name()
                except:
                    p_name = "Unknown"

                # 1. Port Heuristics
                if r_port in SUSPICIOUS_PORTS:
                    print(f"[!] NDR ALERT: Process {p_name} bound to blacklisted Port {r_port} ({r_ip})")
                    emit_ndr_threat(p_name, conn.pid, r_ip, r_port, f"Detected C2 beacon port mapping: {r_port}")
                    
                # 2. Burst / Micro-Exfiltration Tracking
                egress_tracker[conn.pid] += 1
                if egress_tracker[conn.pid] > 200: # Over 200 simultaneous connection states indicates an Exfil burst or C2 blast
                    print(f"[!] NDR BURST ALERT: Process {p_name} is bursting massive parallel connections ({egress_tracker[conn.pid]})")
                    emit_ndr_threat(p_name, conn.pid, r_ip, r_port, f"Massive parallel egress burst detected: {egress_tracker[conn.pid]} sockets.")
                    egress_tracker[conn.pid] = 0 # Reset to prevent spam
                    
    except psutil.AccessDenied:
        pass # Expected on strict OS configurations without sudo
    
    # Degrade tracker map progressively
    for pid in list(egress_tracker.keys()):
        egress_tracker[pid] = max(0, egress_tracker[pid] - 10)

if __name__ == "__main__":
    print("[watchtower_ndr.py] Pure-Python Autonomous Network Detection & Response Engine active.")
    while True:
        try:
            run_ndr_sweep()
            time.sleep(10) # Sweep 10s intervals
        except KeyboardInterrupt:
            sys.exit(0)
