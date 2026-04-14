#!/usr/bin/env python3
import sys, json, subprocess

def audit_docker():
    try:
        out = subprocess.check_output(["docker", "ps", "-q"], text=True)
        containers = out.strip().split("\n")
        if not containers or containers == [""]:
            return {"status": "clean", "message": "No active Docker containers found on this host."}
            
        findings = []
        for c_id in containers:
            inspect_out = subprocess.check_output(["docker", "inspect", c_id], text=True)
            data = json.loads(inspect_out)[0]
            
            name = data.get("Name", "Unknown")
            privileged = data["HostConfig"].get("Privileged", False)
            network_mode = data["HostConfig"].get("NetworkMode", "")
            
            issues = []
            if privileged: issues.append("CRITICAL: Container running in highly volatile --privileged mode (Escape Vector).")
            if network_mode == "host": issues.append("WARNING: Container bound to Host Network.")
            
            if issues: findings.append({"container_id": c_id, "name": name, "issues": issues})
            
        return {"status": "success", "audited_count": len(containers), "vulnerable_containers": findings}
    except Exception as e:
        return {"status": "error", "message": f"Docker audit failed (Is Docker installed?): {str(e)}"}

if __name__ == "__main__":
    print(json.dumps(audit_docker(), indent=2))
