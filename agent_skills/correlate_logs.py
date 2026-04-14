#!/usr/bin/env python3
import subprocess, platform, json

def parse_logs():
    sys_os = platform.system().lower()
    logs = []
    try:
        if sys_os == "windows":
            cmd = 'wevtutil qe Security /c:5 /f:text /rd:true /q:"*[System[(EventID=4625)]]"'
            out = subprocess.check_output(cmd, shell=True, text=True)
            logs = [line.strip() for line in out.split('\n') if line.strip() and "Account Name" in line]
        elif sys_os == "linux":
            cmd = "grep 'Failed password' /var/log/auth.log | tail -n 5"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            logs = [line.strip() for line in out.split('\n') if line.strip()]
        elif sys_os == "darwin":
            cmd = "log show --predicate 'eventMessage contains \"Authentication failed\"' --last 24h | tail -n 5"
            out = subprocess.check_output(cmd, shell=True, text=True)
            logs = [line.strip() for line in out.split('\n') if line.strip()]
    except Exception as e:
        logs = [f"Could not read logs: {str(e)}"]
        
    return {"status": "success", "os": sys_os, "recent_failed_logins": logs}

if __name__ == "__main__":
    print(json.dumps(parse_logs(), indent=2))
