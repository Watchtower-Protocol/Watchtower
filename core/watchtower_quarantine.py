import os
import sys
import shutil
import argparse
import psutil
import platform
import subprocess
from urllib.parse import urlparse

QUARANTINE_DIR = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + "/security/quarantine"

def quarantine_file(filepath):
    if not os.path.exists(filepath): 
        return f"[-] File not found: {filepath}"
    
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        # Cross-platform permission strip
        os.chmod(filepath, 0o000)
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(filepath) + ".quarantine")
        shutil.move(filepath, dest)
        return f"[+] SUCCESS: Quarantined to {dest}"
    except Exception as e:
        return f"[-] Failed to quarantine {filepath}: {e}"

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=3)
        return f"[+] SUCCESS: Terminated PID {pid} ({p.name()})"
    except psutil.NoSuchProcess:
        return f"[-] PID {pid} no longer exists."
    except Exception as e:
        return f"[-] Failed to terminate PID {pid}: {e}"

def lock_directory(filepath):
    if not os.path.exists(filepath): return f"[-] Path not found: {filepath}"
    try:
        target_dir = os.path.dirname(filepath) if os.path.isfile(filepath) else filepath
        # Read & Execute only, prevents file dropping or encryption
        os.chmod(target_dir, 0o555) 
        return f"[+] SUCCESS: Directory {target_dir} locked to Read-Only mode."
    except Exception as e:
        return f"[-] Failed to lock directory: {e}"

def isolate_network(hub_url):
    try:
        parsed_url = urlparse(hub_url)
        hub_ip = parsed_url.hostname or hub_url
        os_sys = platform.system()
        
        if os_sys == "Darwin":
            # macOS: pfctl
            rules = f"block drop all\npass in proto tcp from {hub_ip} to any\npass out proto tcp from any to {hub_ip}\n"
            p = subprocess.Popen(["sudo", "pfctl", "-f", "-", "-e"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = p.communicate(rules)
            if p.returncode != 0:
                # If sudo requires password, this will fail in background, but assumes passwordless sudo for enterprise EDR
                return f"[-] Failed macOS pf isolation: {err}"
            return f"[+] SUCCESS: Network Isolated (macOS). Hub {hub_ip} Allowed."
            
        elif os_sys == "Linux":
            # Linux: iptables
            commands = [
                ["sudo", "iptables", "-A", "INPUT", "-s", hub_ip, "-j", "ACCEPT"],
                ["sudo", "iptables", "-A", "OUTPUT", "-d", hub_ip, "-j", "ACCEPT"],
                ["sudo", "iptables", "-P", "INPUT", "DROP"],
                ["sudo", "iptables", "-P", "OUTPUT", "DROP"],
                ["sudo", "iptables", "-P", "FORWARD", "DROP"]
            ]
            for cmd in commands:
                subprocess.run(cmd, check=True, capture_output=True)
            return f"[+] SUCCESS: Network Isolated (Linux). Hub {hub_ip} Allowed."
            
        elif os_sys == "Windows":
            # Windows: netsh
            commands = [
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=Allow Hub In", "dir=in", "action=allow", f"remoteip={hub_ip}"],
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=Allow Hub Out", "dir=out", "action=allow", f"remoteip={hub_ip}"],
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"]
            ]
            for cmd in commands:
                subprocess.run(cmd, check=True, capture_output=True)
            return f"[+] SUCCESS: Network Isolated (Windows). Hub {hub_ip} Allowed."
            
        else:
            return f"[-] Unsupported OS for network isolation: {os_sys}"
    except Exception as e:
        return f"[-] Failed to isolate network: {e}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["quarantine", "kill", "lock_dir", "isolate_network"], required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    
    if args.action == "quarantine":
        print(quarantine_file(args.target))
    elif args.action == "kill":
        try:
            print(kill_process(int(args.target)))
        except ValueError:
            print("[-] Target must be an integer PID for kill action.")
    elif args.action == "lock_dir":
        print(lock_directory(args.target))
    elif args.action == "isolate_network":
        print(isolate_network(args.target))