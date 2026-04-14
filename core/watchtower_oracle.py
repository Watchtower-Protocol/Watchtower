import psutil
import time
import json
import urllib.request
import os
import hashlib
from collections import defaultdict

# Watchtower Oracle - Deep Process & Network Telemetry
API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040") + "/api/v2/ingest/threat"
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"

# Stateful baseline: { "process_name": { "ports": set(), "connections": 0 } }
PROCESS_BASELINE = defaultdict(lambda: {"ports": set(), "connections": 0})
LEARNING_MODE_CONNECTIONS = 20 # Number of connections before we consider a process "baselined"
PROCESS_HASH_CACHE = {}

def get_process_hash(path):
    if not path or not os.path.exists(path): return "UNKNOWN"
    if path in PROCESS_HASH_CACHE: return PROCESS_HASH_CACHE[path]
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        res = sha256.hexdigest()
        PROCESS_HASH_CACHE[path] = res
        return res
    except:
        return "ACCESS_DENIED"

def is_suspicious_ip(ip):
    # Ignore localhost & Tailscale
    if (ip.startswith("127.") or ip.startswith("192.168.") or 
        ip.startswith("10.") or ip.startswith("100.") or 
        ip.startswith("172.") or ip == "::1"):
        return False
    return True

def scan_network():
    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("[-] Oracle: Access Denied to net_connections. Run script as root (sudo) for full telemetry.")
        return

    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.raddr:
            try:
                p = psutil.Process(conn.pid)
                name = p.name()
                cmd = " ".join(p.cmdline()[:3])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "UNKNOWN_PROCESS"
                cmd = "ACCESS_DENIED"

            # Skip standard noise locally
            if name.lower() in ["arc", "chrome", "safari", "firefox", "brave"]:
                continue

            resp_p = conn.raddr.port
            profile = PROCESS_BASELINE[name]
            profile["connections"] += 1

            # Phase 1: Threat Intel / Suspicious IP hard check (Legacy Oracle)
            is_anomalous = False
            reason = ""
            if is_suspicious_ip(conn.raddr.ip):
                # Phase 2: Anomaly Baselining (NDR Replacement)
                if profile["connections"] < LEARNING_MODE_CONNECTIONS:
                    profile["ports"].add(resp_p)
                    # Don't alert yet, just learning
                else:
                    if resp_p not in profile["ports"]:
                        # Exclude standard web ports from anomalous tagging
                        if resp_p not in [80, 443, 53, 123]:
                            is_anomalous = True
                            reason = f"Process {name} established connection to irregular new destination port ({conn.raddr.ip}:{resp_p}). Cmd: {cmd}"
                            profile["ports"].add(resp_p)
            
            if is_anomalous:
                payload = {
                    "source": HOSTNAME,
                    "event_type": "NETWORK_ANOMALY",
                    "title": f"Process Anomaly: {name}",
                    "file_path": str(conn.pid), # Storing PID here so UI 'KILL' button works natively
                    "ai_verdict": "SUSPICIOUS",
                    "ai_reason": reason,
                    "severity": "high"
                }
                
                req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), headers={
                    'Content-Type': 'application/json', 'x-api-key': API_KEY
                })
                try: 
                    urllib.request.urlopen(req)
                    print(f"[*] Deep Oracle triggered on PID {conn.pid} ({name}) -> {conn.raddr.ip}:{resp_p}")
                except Exception as e: 
                    pass

def scan_inventory():
    inventory_payload = []
    
    # Process scraping
    for p in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'username']):
        try:
            name = p.info['name']
            exe = p.info['exe']
            create_time = p.info['create_time']
            username = p.info['username']
            
            # Filter intense macOS/Linux noise and background services to save API bandwith
            if not exe or not name or name.startswith("mds") or name.startswith("sysmond"): continue
            
            uptime_seconds = int(time.time() - create_time)
            # Only track apps alive longer than 30s to avoid transient subprocess noise
            if uptime_seconds < 30: continue
            
            phash = get_process_hash(exe)
            
            inventory_payload.append({
                "pid": p.info['pid'],
                "name": name,
                "path": exe,
                "hash": phash,
                "uptime": uptime_seconds,
                "user": username
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    API_INV_URL = API_URL.replace("/ingest/threat", "/ingest/inventory")
    payload = {
        "source": HOSTNAME,
        "inventory": inventory_payload
    }
    try:
        req = urllib.request.Request(API_INV_URL, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req, timeout=5)
    except:
        pass

if __name__ == "__main__":
    print(f"[Watchtower Oracle] Initializing Deep Process Profiling & Network Telemetry on {HOSTNAME}...")
    while True:
        scan_network()
        scan_inventory()
        time.sleep(15)