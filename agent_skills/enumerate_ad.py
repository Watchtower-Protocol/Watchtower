#!/usr/bin/env python3
import os, sys, json, subprocess, platform

def run_ad_sensor():
    if platform.system().lower() != "windows":
        return {"status": "skipped", "message": "Host is not Windows. AD enumeration bypassed."}
    
    script_path = os.path.join(os.path.dirname(__file__), "..", "core", "watchtower_ad_sensor.ps1")
    if not os.path.exists(script_path):
        return {"status": "error", "message": f"AD sensor script missing at {script_path}"}
    
    try:
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        try: return json.loads(result.stdout)
        except: return {"status": "success", "raw_output": result.stdout.strip()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    print(json.dumps(run_ad_sensor(), indent=2))
