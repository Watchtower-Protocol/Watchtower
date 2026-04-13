import json
import time
import os
import threading
try:
    import paramiko
except ImportError:
    paramiko = None
import watchtower_topology

DATA_DIR = os.environ.get("WATCHTOWER_DATA_DIR", "../data")
INFRASTRUCTURE_FILE = os.path.join(DATA_DIR, "infrastructure.json")
DUMPS_DIR = os.path.join(DATA_DIR, "raw_mac_dumps")

def load_infrastructure():
    if not os.path.exists(INFRASTRUCTURE_FILE):
        return []
    try:
        with open(INFRASTRUCTURE_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def scrape_switch(host, username, password):
    if not paramiko:
        print("[Scraper] Paramiko missing. Skipping SSH.")
        return None
        
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password, timeout=10)
        # Compatible with Cisco, Aruba, etc.
        stdin, stdout, stderr = client.exec_command('show mac address-table')
        output = stdout.read().decode('utf-8')
        
        os.makedirs(DUMPS_DIR, exist_ok=True)
        out_path = os.path.join(DUMPS_DIR, f"{host}_macs.txt")
        with open(out_path, 'w') as f:
            f.write(output)
            
        client.close()
        return out_path
    except Exception as e:
        print(f"[!] SSH Scraper failed on {host}: {e}")
        return None

def run_scraper_cycle():
    infra = load_infrastructure()
    file_paths = {}
    
    for device in infra:
        if device.get('type') == 'switch' and device.get('protocol') == 'ssh':
            host = device.get('ip')
            usr = device.get('username')
            pwd = device.get('password')
            path = scrape_switch(host, usr, pwd)
            if path:
                file_paths[host] = path
                
    if file_paths:
        print(f"[*] Autonomous Topology Scraper extracted tables from {len(file_paths)} switches. Re-Mapping Layer 2...")
        watchtower_topology.ingest_raw_dumps(file_paths)

def background_loop():
    print("[Watchtower Topography] Autonomous SSH Network Mapping Engine active.")
    while True:
        try:
            run_scraper_cycle()
        except Exception as e:
            print(f"[!] Scraper cycle error: {e}")
        time.sleep(300) # Every 5 minutes heartbeat

def start_scraper():
    threading.Thread(target=background_loop, daemon=True).start()

if __name__ == "__main__":
    background_loop()
