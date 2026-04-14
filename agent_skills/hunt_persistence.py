#!/usr/bin/env python3
import os, sys, json, platform, subprocess

def hunt_persistence():
    os_sys = platform.system().lower()
    findings = []
    try:
        if os_sys == "windows":
            try:
                out = subprocess.check_output(["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"], text=True)
                findings.append({"location": "HKCU Run Key", "data": out.strip().split("\n")})
            except: pass
            try:
                out = subprocess.check_output(["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"], text=True)
                findings.append({"location": "HKLM Run Key", "data": out.strip().split("\n")})
            except: pass
            
        elif os_sys == "darwin":
            la_path = os.path.expanduser("~/Library/LaunchAgents")
            if os.path.exists(la_path): findings.append({"location": "User LaunchAgents", "files": os.listdir(la_path)})
            ld_path = "/Library/LaunchDaemons"
            if os.path.exists(ld_path): findings.append({"location": "System LaunchDaemons", "files": os.listdir(ld_path)})
                
        elif os_sys == "linux":
            try:
                out = subprocess.check_output(["crontab", "-l"], text=True, stderr=subprocess.DEVNULL)
                findings.append({"location": "User Crontab", "data": out.strip().split("\n")})
            except: pass
            if os.path.exists("/etc/crontab"):
                with open("/etc/crontab", "r") as f: findings.append({"location": "/etc/crontab", "data": f.readlines()})
                    
    except Exception as e:
        return {"status": "error", "message": str(e)}
        
    return {"status": "success", "os": os_sys, "persistence_hooks": findings}

if __name__ == "__main__":
    print(json.dumps(hunt_persistence(), indent=2))
