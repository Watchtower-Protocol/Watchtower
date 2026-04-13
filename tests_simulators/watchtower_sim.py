import os
import sys
import time
import socket
import base64
import argparse
import subprocess
import threading

def trigger_fim():
    print("[*] Triggering FIM High-Entropy Obfuscation Engine...")
    target_dir = "/tmp/watchtower_monitor"
    os.makedirs(target_dir, exist_ok=True)
    target_file = os.path.join(target_dir, "simulate_ransom.enc")
    
    # Generate massive random high-entropy payload to trick Shannon math logic
    payload = os.urandom(8192)
    b64_payload = base64.b64encode(payload).decode('utf-8')
    
    with open(target_file, 'w') as f:
        f.write("# Suspicious payload wrapper\n")
        f.write(f"import ctypes\n")
        f.write(f"exe_val = '{b64_payload[:200]}'\n")
        for i in range(250):
            f.write(f"var_{i} = '{base64.b64encode(os.urandom(50)).decode()}'\n")

    print(f"[+] Dropped highly obfuscated codebase to {target_file}.")
    print("[+] WATCHTOWER EFFECT: The FIM Engine will intercept the file write, assess the mathematical Entropy, and immediately push it into the Gemma-4 local LLM context to determine if it is a ransomware dropper.")

def trigger_ndr():
    print("[*] Triggering NDR Exfiltration Burst Engine...")
    print("[!] Generating 210 simultaneous parallel TCP sockets. Watchtower should classify this as C2 exfiltration.")
    
    sockets = []
    # Using Cloudflare 1.1.1.1 as a safe external point so we create valid ESTABLISHED network states
    target_ip = "1.1.1.1" 
    target_port = 443
    
    def open_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            sockets.append(s)
            time.sleep(15) # Hold state open for Watchtower sweeping window
            s.close()
        except: pass

    threads = []
    for _ in range(215):
        t = threading.Thread(target=open_socket)
        threads.append(t)
        t.start()
        
    time.sleep(5) # Let connections fully establish
    print(f"[+] Successfully opened {len(sockets)} outbound ports in parallel. Sweepers activate every 10s.")
    print("[+] WATCHTOWER EFFECT: 'watchtower_ndr.py' will sweep `psutil` mapping. It will see an anomaly > 200 sockets, and immediately issue a CRITICAL [NDR BURST ALERT] to the Threat Matrix.")
    time.sleep(12) # Wait for sweeping decay

def trigger_behavioral():
    print("[*] Triggering Cognitive Behavioral Engine (LotL Attack)...")
    # Execute a typical Living-off-the-Land (LotL) payload argument structure.
    # The Behavioral Engine monitors commands for encoded loops or obfuscated calls like this:
    cmd = "python3 -c \"import base64; exec(base64.b64decode('cHJpbnQoIlNtdWxhdGVkIExvdEwgRXhlY3V0aW9uIik='))\""
    print(f"[!] Firing process: {cmd}")
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.wait(timeout=10)
        print("[+] Living-off-the-Land sequence isolated.")
        print("[+] WATCHTOWER EFFECT: 'watchtower_behavioral.py' continually scans terminal lines. It will parse `base64` coupled with `python3 -c`, identify it as suspicious Fileless Execution, and sever the process instantly while logging a Threat.")
    except Exception as e:
        print(f"[-] Execution trap: {e}")

def trigger_decoy():
    print("[*] Triggering physical Decoy (USB/DLP) Subsystem...")
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    decoy_file = os.path.join(parent, "data", "decoy_passwords.txt")
    
    # Pre-create just in case watchdog hasn't started natively yet
    if not os.path.exists(decoy_file):
        os.makedirs(os.path.dirname(decoy_file), exist_ok=True)
        with open(decoy_file, 'w') as f:
            f.write("admin:hunter2")
            
    print(f"[!] Executing simulated unauthorized data exfiltration on {decoy_file}...")
    try:
        with open(decoy_file, 'r') as f:
            secret = f.read()
        print("[+] Unauthorized read executed. Local system handlers breached.")
        print("[+] WATCHTOWER EFFECT: 'watchtower_decoy.py' has an absolute file handle lock on this document. By issuing a standard `open(read)`, Watchtower's OS lock triggers, throwing an instant DLP Honeytoken alert to the user Matrix.")
    except Exception as e:
        print(f"[-] Read trap: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Watchtower EDR Threat Simulator Matrix")
    parser.add_argument('--fim', action='store_true', help="Simulates obfuscated crypto payload drops (Shannon Entropy)")
    parser.add_argument('--ndr', action='store_true', help="Simulates massive C2 Data loss / Exfiltration burst sockets")
    parser.add_argument('--lotl', action='store_true', help="Simulates Behavioral Living-off-the-Land memory attacks")
    parser.add_argument('--decoy', action='store_true', help="Simulates Insider-Threat traversing unauthorized files")
    parser.add_argument('--all', action='store_true', help="Trigger all local simulated attacks violently")
    
    args = parser.parse_args()
    
    print("====================================================")
    print(" WATCHTOWER v1.6 - ISOLATED TESTING SUITE ")
    print(" NOTE: Keep the Command Center Dashboard open on ")
    print("       localhost:8080 to watch telemetry stream live.")
    print("====================================================\n")
    
    executed = False
    if args.fim or args.all:
        trigger_fim()
        executed = True
        print()
    if args.ndr or args.all:
        trigger_ndr()
        executed = True
        print()
    if args.lotl or args.all:
        trigger_behavioral()
        executed = True
        print()
    if args.decoy or args.all:
        trigger_decoy()
        executed = True
        print()
        
    if not executed:
        parser.print_help()
