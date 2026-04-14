import json
import re
import csv
from collections import defaultdict
import os
import urllib.request
import time
import watchtower_ndr

"""
Watchtower Topology Mapper
Author: Vertex
Purpose: Parses MAC address tables from Cisco/Legacy network switches to build a physical topology map.
Integrates with Watchtower NDR to detect rogue devices and map wireless bridge (PtP) endpoints.
"""

OUI_MAP = {
    "9c:8e:cd": "Amcrest / Dahua (Camera)",
    "38:ca:84": "Amcrest / Dahua (Camera)",
    "e8:d8:d1": "Amcrest / Dahua (Camera)",
    "4c:cf:7c": "Amcrest / Dahua (Camera)",
    "14:cb:19": "Amcrest / Dahua (Camera)",
    "bc:16:f5": "Amcrest / Dahua (Camera)",
    "9c:76:0e": "Amcrest / Dahua (Camera)",
    "74:83:c2": "Ubiquiti (Bridge/AP)",
    "b4:fb:e4": "Ubiquiti (Bridge/AP)",
    "fc:ec:da": "Ubiquiti (Bridge/AP)",
    "f0:9f:c2": "Ubiquiti (Bridge/AP)",
    "68:d7:9a": "Ubiquiti (Bridge/AP)",
    "24:5a:4c": "Ubiquiti (Bridge/AP)",
    "18:e8:29": "Ubiquiti (Bridge/AP)",
    "1c:98:ec": "Apple Device",
    "f8:b4:6a": "Apple Device",
    "a8:b1:3b": "Apple Device",
    "64:4e:d7": "Cisco Switch",
    "bc:f1:f2": "Cisco Switch",
    "34:bd:c8": "Cisco Switch",
    "e4:38:83": "Cisco Switch",
    "00:15:5d": "Microsoft (Hyper-V)",
}

def get_vendor(mac):
    prefix = mac[:8].lower()
    if prefix in OUI_MAP:
        return OUI_MAP[prefix]
        
    cache_path = os.path.join(os.environ.get("WATCHTOWER_DATA_DIR", "../data"), "mac_vendor_cache.json")
    cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                cache = json.load(f)
        except: pass
        
    if prefix in cache:
        return cache[prefix]
        
    # Autonomous Fallback
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{mac}", headers={'User-Agent': 'Watchtower-NDR-Subsystem'})
        res = urllib.request.urlopen(req, timeout=3)
        vendor = res.read().decode('utf-8').strip()
        cache[prefix] = vendor
        with open(cache_path, 'w') as f:
            json.dump(cache, f)
        time.sleep(1.2) # Strictly respect free API boundaries
        return vendor
    except:
        cache[prefix] = "Unknown / Workstation"
        with open(cache_path, 'w') as f:
            json.dump(cache, f)
        return "Unknown / Workstation"

def parse_switch_files(file_paths):
    data = []
    for ip, path in file_paths.items():
        if not os.path.exists(path):
            continue
        with open(path, 'r') as f:
            for line in f:
                match = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+([A-Za-z0-9]+)', line, re.IGNORECASE)
                if match:
                    mac, port = match.groups()
                    if port == "0": continue
                    data.append({"switch": ip, "mac": mac.lower(), "port": port})
    return data

def build_topology(data):
    port_macs = defaultdict(lambda: defaultdict(list))
    for row in data:
        port_macs[row['switch']][row['port']].append(row['mac'])

    output = []
    for sw, ports in port_macs.items():
        for pt, macs in ports.items():
            vendors = [get_vendor(m) for m in macs]
            
            mac_count = len(macs)
            has_ubiquiti = any("Ubiquiti" in v for v in vendors)
            has_camera = any("Camera" in v for v in vendors)
            has_cisco = any("Cisco" in v for v in vendors)
            
            topology = "Direct Connection"
            if mac_count > 3:
                if has_ubiquiti and has_camera:
                    topology = "PtP Wireless Bridge (Cameras)"
                elif has_ubiquiti:
                    topology = "Wireless AP / Bridge"
                elif has_cisco:
                    topology = "Switch-to-Switch Trunk"
                else:
                    topology = "General Uplink / Trunk"
            elif mac_count > 1:
                topology = "Small Hub / Splitter"
                if has_ubiquiti: topology = "Wireless AP / Bridge"
                if has_ubiquiti and has_camera: topology = "PtP Wireless Bridge (Cameras)"

            for m in macs:
                output.append({
                    "Switch_IP": sw,
                    "Port": pt,
                    "Port_Topology": topology,
                    "Device_Category": get_vendor(m),
                    "MAC_Address": m
                })
    return output

def ingest_raw_dumps(file_paths):
    parsed_data = parse_switch_files(file_paths)
    topology = build_topology(parsed_data)
    
    csv_path = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + '/detailed_network_topology.csv'
    json_path = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + '/historical_topology.json'
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    
    # --- ROGUE HARDWARE DIFF ENGINE ---
    old_state = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                old_state = json.load(f)
        except: pass
        
    new_state = {}
    for r in topology:
        key = f"{r['Switch_IP']}::{r['Port']}"
        new_state[key] = r['Port_Topology']
        
    for key, new_topo in new_state.items():
        if key in old_state:
            old_topo = old_state[key]
            if old_topo == "Direct Connection" and new_topo in ["Small Hub / Splitter", "Wireless AP / Bridge", "PtP Wireless Bridge (Cameras)"]:
                sw_ip, pt = key.split("::")
                watchtower_ndr.emit_ndr_threat(
                    proc_name="L2_TOPOLOGY_MONITOR",
                    pid=777,
                    remote_ip=sw_ip,
                    remote_port=pt,
                    details=f"ROGUE HARDWARE DETECTED: Physical Port {pt} on Switch {sw_ip} mutated from a Direct Connection to a '{new_topo}'. Unauthorized infrastructure attached!"
                )
                print(f"[!] ROGUE TOPOLOGY ALERT: Port {pt} on {sw_ip} breached density thresholds.")
                
    with open(json_path, 'w') as f:
        json.dump(new_state, f)
    # ----------------------------------
    
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["Switch_IP", "Port", "Port_Topology", "Device_Category", "MAC_Address"])
        writer.writeheader()
        for row in sorted(topology, key=lambda x: (x['Switch_IP'], x['Port_Topology'], x['Port'], x['Device_Category'])):
            writer.writerow(row)
            
    print(f"[Watchtower Topology Layer] Mapping built with {len(topology)} live MAC paths.")
    return topology
