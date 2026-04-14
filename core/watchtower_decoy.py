import os
import time
import json
import urllib.request
import platform

# Load Environment Variables
API_URL = os.getenv("WATCHTOWER_API_URL", "http://localhost:3000/api/v2/ingest/threat")
API_KEY = os.getenv("WATCHTOWER_API_KEY", "YOUR_SECRET_API_KEY_HERE")
HOSTNAME = platform.node()

# Define tempting decoy file locations across platforms
DECOYS = [
    os.path.expanduser("~/Documents/finance_passwords_2026.csv"),
    os.path.expanduser("~/.ssh/backup_rsa_key_legacy")
]

CSV_CONTENT = "id,system,username,password\n1,prod_db,admin,Sup3rSecr3t!\n2,aws_root,root,hunter2\n"
RSA_CONTENT = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA3... (Fake Key Data) ...\n-----END RSA PRIVATE KEY-----\n"

def setup_decoys():
    state = {}
    for d in DECOYS:
        try:
            os.makedirs(os.path.dirname(d), exist_ok=True)
            if not os.path.exists(d):
                with open(d, 'w') as f:
                    f.write(CSV_CONTENT if "csv" in d else RSA_CONTENT)
            state[d] = os.path.getmtime(d)
        except Exception as e:
            print(f"[Watchtower Decoy] Failed to setup {d}: {e}")
    return state

def trigger_alert(filepath, action="modified"):
    print(f"[!!!] DECOY FILE TRIPPED ({action.upper()}): {filepath}")
    payload = {
        "source": HOSTNAME,
        "event_type": "HONEYPOT_TRIPPED",
        "title": f"Decoy File Tripped: {os.path.basename(filepath)}",
        "file_path": filepath,
        "ai_verdict": "MALICIOUS",
        "ai_reason": f"A process {action} a strictly monitored honeypot decoy file. This is a definitive, 100% true-positive indicator of compromise, ransomware, or unauthorized snooping. No AI analysis required.",
        "severity": "high"
    }
    try:
        req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[Watchtower Decoy] Alert failed to send: {e}")

def main():
    print(f"[Watchtower Sentinel] Deploying invisible Decoy Honeypots on {HOSTNAME}...")
    state = setup_decoys()
    
    while True:
        time.sleep(5)
        for d, orig_mtime in state.items():
            if os.path.exists(d):
                current_mtime = os.path.getmtime(d)
                if current_mtime != orig_mtime:
                    trigger_alert(d, "modified")
                    state[d] = current_mtime # Reset to avoid spam
            else:
                trigger_alert(d, "deleted")
                # Recreate the deleted decoy
                state.update(setup_decoys())

if __name__ == "__main__":
    main()
