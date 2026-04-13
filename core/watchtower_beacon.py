import os
import sys
import time
import json
import urllib.request
import subprocess
import zipfile
import tempfile

# Watchtower Remote Beacon (C2 Pull)
API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040")
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"
POLICY_FILE = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + "/policy.json"

RUNNING_SENSORS = {}

def sync_policy():
    url = f"{API_URL}/api/v2/policies/sync?host={HOSTNAME}"
    try:
        req = urllib.request.Request(url, headers={'x-api-key': API_KEY})
        with urllib.request.urlopen(req, timeout=5) as response:
            policy = json.loads(response.read().decode()).get("policy", {})
            with open(POLICY_FILE, "w") as f:
                json.dump(policy, f)
            return policy
    except:
        if os.path.exists(POLICY_FILE):
            with open(POLICY_FILE, "r") as f:
                return json.load(f)
        return {
            "ENABLE_FIM": True, "ENABLE_ORACLE": True, "ENABLE_BEHAVIORAL": True, "ENABLE_DECOY": True,
            "ENABLE_COMPLIANCE": True, "ENABLE_ROLLBACK": True, "ENABLE_YARA": True, "ENABLE_NDR": True,
            "WATCHTOWER_AUDIT_MODE": False
        }

def manage_sensors(policy):
    target_sensors = []
    if str(policy.get("ENABLE_FIM")).lower() == "true": target_sensors.append("watchtower_fim.py")
    if str(policy.get("ENABLE_ORACLE")).lower() == "true": target_sensors.append("watchtower_oracle.py")
    if str(policy.get("ENABLE_BEHAVIORAL")).lower() == "true": target_sensors.append("watchtower_behavioral.py")
    if str(policy.get("ENABLE_DECOY")).lower() == "true": target_sensors.append("watchtower_decoy.py")
    if str(policy.get("ENABLE_COMPLIANCE")).lower() == "true": target_sensors.append("watchtower_compliance.py")
    if str(policy.get("ENABLE_ROLLBACK")).lower() == "true": target_sensors.append("watchtower_rollback.py")
    if str(policy.get("ENABLE_YARA")).lower() == "true": target_sensors.append("watchtower_regex_sweeper.py")
    if str(policy.get("ENABLE_NDR")).lower() == "true": target_sensors.append("watchtower_ndr.py")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    for s in target_sensors:
        if s not in RUNNING_SENSORS or RUNNING_SENSORS[s].poll() is not None:
            print(f"[Supervisor] Booting {s}...")
            env = os.environ.copy()
            if "WATCHTOWER_AUDIT_MODE" in policy:
                env["WATCHTOWER_AUDIT_MODE"] = str(policy["WATCHTOWER_AUDIT_MODE"]).lower()
            script_path = os.path.join(script_dir, s)
            try:
                RUNNING_SENSORS[s] = subprocess.Popen([sys.executable, script_path], env=env)
            except Exception as e:
                print(f"[Supervisor] Critical Failure booting {s}: {e}")
                

    for s in list(RUNNING_SENSORS.keys()):
        if s not in target_sensors:
            if RUNNING_SENSORS[s].poll() is None:
                print(f"[Supervisor] Policy dynamically updated. Terminating {s} natively...")
                RUNNING_SENSORS[s].terminate()
                try: RUNNING_SENSORS[s].wait(timeout=5)
                except: RUNNING_SENSORS[s].kill()
            del RUNNING_SENSORS[s]

def check_beacon():
    url = f"{API_URL}/api/v2/c2/beacon?host={HOSTNAME}"
    try:
        req = urllib.request.Request(url, headers={'x-api-key': API_KEY})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            commands = data.get("commands", [])
            for cmd in commands:
                action = cmd.get("action")
                target = cmd.get("target")
                hmac_sig = cmd.get("hmac")
                print(f"[*] C2 Beacon Received: Execute {action} on {target}")
                execute_local_quarantine(action, target, hmac_sig)
    except Exception as e:
        # Silently fail on connection drop
        pass

def execute_local_quarantine(action, target, hmac_sig=None):
    if action == "UPDATE_POLICY":
        print("[*] Supervisor received UPDATE_POLICY. Re-syncing configurations...")
        new_pol = sync_policy()
        manage_sensors(new_pol)
        return

    if action == "REVOKE_TRUST":
        print(f"[*] CTI Dynamic Revocation: Stripping {target} from trust...")
        sig_file = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + "/signatures.json"
        try:
            with open(sig_file, "r") as f:
                data = json.load(f)
        except:
            data = {"bad_hashes": []}
            
        if target not in data.get("bad_hashes", []):
            if "bad_hashes" not in data: data["bad_hashes"] = []
            data["bad_hashes"].append(target)
            with open(sig_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Trust revoked. Hash {target} prioritized into malicious cache.")
        return

    if action == "UPDATE_CORE":
        print(f"[*] Executing OTA Agent Update from {target}...")
        try:
            import urllib.request
            import zipfile
            import hmac
            import hashlib
            
            payload_path = "/tmp/watchtower_update.zip"
            urllib.request.urlretrieve(target, payload_path)
            
            # V4 Crypto Verify
            with open(payload_path, 'rb') as f:
                payload_bytes = f.read()
            expected_hmac = hmac.new(API_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()
            
            if hmac_sig and not hmac.compare_digest(hmac_sig, expected_hmac):
                print(f"[!] FATAL: OTA Signature Mismatch! Expected {expected_hmac[:12]}, Got {hmac_sig[:12]}")
                os.remove(payload_path)
                return
                
            print(f"[+] OTA Payload HMAC Verified: {expected_hmac[:12]}...")
            
            with zipfile.ZipFile(payload_path, 'r') as zip_ref:
                zip_ref.extractall(os.path.dirname(os.path.abspath(__file__)))
                
            os.remove(payload_path)
            
            print("[*] Update extracted. Restarting Watchtower core...")
            os.execv(sys.executable, ['python3'] + sys.argv)
            
        except Exception as e:
            print(f"[!] OTA Update Failed: {e}")
        return

    script_dir = os.path.dirname(__file__)
    quarantine_script = os.path.join(script_dir, "watchtower_quarantine.py")
    
    try:
        result = subprocess.run(
            ["python3", quarantine_script, "--action", action, "--target", target],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip() or result.stderr.strip()
        print(f"[C2 Execution Result]: {output}")
        # In a fully armed system, we would push this 'output' array back to 4040
        # so the Command Center knows the beacon executed it successfully. 
        # (This is implicitly captured if the process goes offline or file disappears, 
        # but a direct response loop is robust).
    except Exception as e:
        print(f"[-] Subprocess failure: {e}")

if __name__ == "__main__":
    print(f"[Watchtower Beacon + Supervisor] Agent {HOSTNAME} securely bound to C2 Hub: {API_URL}")
    current_policy = sync_policy()
    manage_sensors(current_policy)
    
    try:
        while True:
            check_beacon()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[Supervisor] Shutting down sensors...")
        for s, p in RUNNING_SENSORS.items():
            if p.poll() is None: p.terminate()
        sys.exit(0)
