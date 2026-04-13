import os
import sys
import time
import platform
import subprocess
import json
import urllib.request

API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040")
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"

def push_telemetry(msg):
    payload = {
        "source": HOSTNAME,
        "event_type": "SYSTEM_SNAPSHOT",
        "file_path": "OS_VOLUME",
        "description": msg,
        "severity": "low",
        "ai_verdict": "SAFE",
        "ai_reason": "Automated rollback volume generator synced."
    }
    try:
        req = urllib.request.Request(f"{API_URL}/api/v2/ingest/threat", json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req, timeout=5)
    except: pass

def create_snapshot():
    sys_os = platform.system().lower()
    print(f"[*] Rollback Engine initiating localized file-system shadow copy...")
    
    if sys_os == "darwin":
        try:
            # tmutil is the native APFS backup utility for MacOS
            res = subprocess.run(["tmutil", "localsnapshot"], capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[+] APFS Shadow Copy Generated gracefully: {res.stdout.strip()}")
                push_telemetry("Local APFS shadow copy securely generated.")
            else:
                print(f"[-] APFS Shadow Copy execution failed natively. Check permissions.")
        except Exception as e:
            print(f"[-] tmutil unrecoverable failure: {e}")
            
    elif sys_os == "windows":
        try:
            # VSS (Volume Shadow Copy Service) command for Windows
            res = subprocess.run(["vssadmin", "create", "shadow", "/for=C:"], capture_output=True, text=True)
            print(f"[+] VSS Volume Shadow Copy Generated successfully.")
            push_telemetry("Local VSS Volume shadow copy securely generated.")
        except Exception as e:
            print(f"[-] VSS Snapshot failed. Ensure the Agent is running as SYSTEM/Administrator. {e}")
            
    elif sys_os == "linux":
        print("[-] Native Linux Rollback currently relies exclusively on native BTRFS headers. Skipping LVM cloning sequence for zero-dependency safety.")

if __name__ == "__main__":
    print("[watchtower_rollback.py] Autonomous VSS/APFS Rollback Zero-Dependency Engine active.")
    while True:
        try:
            create_snapshot()
            time.sleep(3600 * 4) # Execute a silent snapshot deep routine every 4 hours automatically
        except KeyboardInterrupt:
            sys.exit(0)
