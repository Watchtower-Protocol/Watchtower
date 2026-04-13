import os
import sys
import time
import json
import urllib.request
import platform
import subprocess

API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040")
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"

def send_alert(title, details, severity="low"):
    payload = {
        "source": HOSTNAME,
        "event_type": "COMPLIANCE_AUDIT",
        "file_path": "OS_CONFIGURATION",
        "description": details,
        "severity": severity,
        "ai_verdict": "VULNERABILITY",
        "ai_reason": title
    }
    try:
        req = urllib.request.Request(f"{API_URL}/api/v2/ingest/threat", json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[-] Failed to send compliance alert: {e}")

def audit_mac():
    findings = []
    try:
        res = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True)
        if "disabled" in res.stdout.lower():
            findings.append("macOS Application Firewall is DISABLED.")
    except: pass
    
    try:
        res = subprocess.run(["fdesetup", "status"], capture_output=True, text=True)
        if "FileVault is Off" in res.stdout:
            findings.append("FileVault Full Disk Encryption is DISABLED.")
    except: pass
    return findings

def audit_linux():
    findings = []
    if os.path.exists("/etc/ssh/sshd_config"):
        with open("/etc/ssh/sshd_config", "r") as f:
            content = f.read()
            if "PermitRootLogin yes" in content and not "#PermitRootLogin" in content:
                findings.append("SSH PermitRootLogin is ENABLED. Highly Vulnerable.")
    return findings

def run_audit():
    print("[*] Initiating CIS Compliance Sweep...")
    findings = []
    sys_os = platform.system().lower()
    
    if sys_os == "darwin":
        findings = audit_mac()
    elif sys_os == "linux":
        findings = audit_linux()
        
    if findings:
        report = " | ".join(findings)
        send_alert("Compliance Posture Failure", f"CIS Audit identified baseline policy violations: {report}", "medium")
        print(f"[!] Compliance Flaws Found: {report}")
    else:
        print("[+] Host Posture completely conforms to Baseline Security Standards.")

if __name__ == "__main__":
    print("[watchtower_compliance.py] Host Node CIS Auditor bound and actively running sweeps.")
    while True:
        try:
            run_audit()
            time.sleep(3600) # Audit deeply once per hour
        except KeyboardInterrupt:
            sys.exit(0)
