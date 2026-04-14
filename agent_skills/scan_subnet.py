#!/usr/bin/env python3
import os, sys, json, socket, platform, subprocess, argparse, concurrent.futures

def get_arp_cache():
    hosts = []
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
        for line in output.splitlines():
            parts = line.split()
            if platform.system().lower() == "windows":
                if "dynamic" in line.lower() or "static" in line.lower():
                    if len(parts) >= 2: hosts.append({"ip": parts[0], "mac": parts[1]})
            else:
                if "(" in line and ")" in line:
                    ip = line.split("(")[1].split(")")[0]
                    mac = line.split("at ")[1].split()[0] if "at " in line else "unknown"
                    if mac != "<incomplete>": hosts.append({"ip": ip, "mac": mac})
    except Exception: pass
    return hosts

def scan_host(host_info):
    target_ip = host_info["ip"]
    open_ports = []
    for port in [22, 445, 3389, 5985]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((target_ip, port))
            open_ports.append(port)
        except: pass
        finally: s.close()
    host_info["open_ports"] = open_ports
    try: host_info["hostname"] = socket.gethostbyaddr(target_ip)[0]
    except: host_info["hostname"] = "Unknown"
    return host_info

if __name__ == "__main__":
    arp_hosts = get_arp_cache()
    targets = list({h["ip"]: h for h in arp_hosts}.values())
    enriched_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for res in executor.map(scan_host, targets): enriched_hosts.append(res)
    print(json.dumps({"status": "success", "discovered_hosts": len(enriched_hosts), "hosts": enriched_hosts}, indent=2))
