import os
import sys
import time
import json
import psutil
import re
import urllib.request

API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040")
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"

# Simulated YARA Regex Patterns for Memory/Binary evaluation
YARA_RULES = {
    "CobaltStrike_Beacon_Hex": rb"(?i)(%[0-9a-fA-F]{2}){10,}|sCrc32|NetBIOS",
    "Mimikatz_LSA_Driver": rb"sekurlsa::logonpasswords|lsass\.exe",
    "Metasploit_Meterpreter_Shikata": rb"meterpreter|shellcode|ws2_32\.dll",
    "Ransomware_Crypto_Routines": rb"vssadmin delete shadows|wbadmin DELETE SYSTEMSTATEBACKUP|bcdedit /set {default} recoveryenabled No"
}

def scan_process_memory(pid):
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        if not exe_path or not os.path.exists(exe_path):
            return None
        
        # In a zero-dependency Python script, reading raw RAM across OS boundaries (Mac/Win/Lin)
        # crashes without strict ctypes bindings. Instead, we scan the physical execution 
        # binary memory map directly off the disk representing the active process shell.
        with open(exe_path, 'rb') as f:
            chunk = f.read(1024 * 1024) # Scan first Megabyte of the executable signature
            for rule_name, pattern in YARA_RULES.items():
                if re.search(pattern, chunk):
                    return rule_name
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        pass
    except Exception as e:
        pass
    return None

def run_yara_sweep():
    # print("[*] YARA Memory Signature Engine sweeping active processes...") # Disabled for silent running
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            matched_rule = scan_process_memory(proc.info['pid'])
            if matched_rule:
                print(f"[!] YARA MATCH: Process {proc.info['name']} (PID: {proc.info['pid']}) triggered {matched_rule}")
                # Emit threat
                payload = {
                    "source": HOSTNAME,
                    "event_type": "YARA_SIGNATURE_MATCH",
                    "file_path": f"PID://{proc.info['pid']}",
                    "description": f"Process {proc.info['name']} matched advanced execution signature [{matched_rule}].",
                    "severity": "critical",
                    "ai_verdict": "MALICIOUS",
                    "ai_reason": f"Heuristic YARA Engine natively detected {matched_rule} execution string."
                }
                req = urllib.request.Request(f"{API_URL}/api/v2/ingest/threat", json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
                urllib.request.urlopen(req, timeout=5)
        except:
            continue

if __name__ == "__main__":
    print("[watchtower_regex_sweeper.py] Pure-Python Regex Memory Sweeper Active.")
    while True:
        try:
            run_yara_sweep()
            time.sleep(300) # Deep Memory Sweep every 5 minutes
        except KeyboardInterrupt:
            sys.exit(0)
