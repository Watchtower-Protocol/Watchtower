import psutil
import time
import json
import urllib.request
import os

API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040") + "/api/v2/ingest/threat"
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"
AUDIT_MODE = os.environ.get("WATCHTOWER_AUDIT_MODE", "false").lower() == "true"

# Living off the Land (LotL) Indicators of Attack (IOA)
IOA_RULES = {
    "encoded_shell": ["-enc", "-encodedcommand", "base64 -d"],
    "suspicious_paths": ["/tmp/wt_", "C:\\PerfLogs\\", "C:\\Users\\Public\\"]
}

def analyze_process_behavior():
    for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
        try:
            cmdline_raw = p.info['cmdline'] or []
            cmd = " ".join(cmdline_raw).lower()
            exe = p.info['exe'] or ""
            name = p.info['name'] or ""
            if not cmd and not exe: continue

            matched_rule = None
            
            # Rule 1: Encoded shells
            if "powershell" in name.lower() or "pwsh" in name.lower() or "bash" in name.lower() or "sh" in name.lower():
                if any(x in cmd for x in IOA_RULES["encoded_shell"]):
                    matched_rule = "Encoded Shell Pipeline (Possible Memory Injection / C2)"
                    
            # Rule 2: Web downloading to execution
            if any(x in cmd for x in ["curl ", "wget "]) and ("| bash" in cmd or "| sh" in cmd):
                matched_rule = "Web-To-Execution Pipeline (LotL)"
                
            # Rule 3: Execution from highly suspicious temp paths
            if any(exe.startswith(x) for x in IOA_RULES["suspicious_paths"]):
                matched_rule = "Execution from Unbacked Temp Directory"

            if matched_rule:
                print(f"[!] BEHAVIORAL IOA TRIGGERED: PID {p.info['pid']} ({name}) -> {matched_rule}")
                
                payload = {
                    "source": HOSTNAME,
                    "event_type": "BEHAVIORAL_ANOMALY",
                    "title": f"LotL Behavior Blocked: {name}",
                    "file_path": exe or cmd, 
                    "ai_verdict": "MALICIOUS",
                    "ai_reason": f"Heuristic Rule Match: {matched_rule}. Command: {cmd}",
                    "severity": "high"
                }
                
                try:
                    req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
                    urllib.request.urlopen(req, timeout=5)
                except Exception as e:
                    pass
                
                if not AUDIT_MODE:
                    print(f"[*] Terminating anomalous process {p.info['pid']}...")
                    p.terminate()
                else:
                    print(f"[*] [AUDIT MODE] Skipped Termination.")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

if __name__ == "__main__":
    print(f"[Watchtower Behavioral Engine] IOA Tracking Initialized on {HOSTNAME} (Audit Mode: {AUDIT_MODE})")
    while True:
        analyze_process_behavior()
        time.sleep(5)
