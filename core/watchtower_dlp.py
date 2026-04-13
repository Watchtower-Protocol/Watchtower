import os
import time
import json
import urllib.request
import subprocess
import psutil

# Watchtower DLP - Device Control & Data Loss Prevention
API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040") + "/api/v2/ingest/threat"
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"
BLOCK_USB = os.environ.get("WATCHTOWER_BLOCK_USB", "true").lower() == "true"

def get_external_drives():
    drives = []
    # On macOS external drives mount to /Volumes. On Linux, /media or /mnt.
    # psutil identifies them typically with 'removable' or mounted in these paths.
    for partition in psutil.disk_partitions(all=False):
        if 'cdrom' in partition.opts or partition.fstype == '': continue
        
        # Identify typical external mount paths
        if partition.mountpoint.startswith('/Volumes/') or \
           partition.mountpoint.startswith('/media/') or \
           partition.mountpoint.startswith('/run/media/'):
            # Ignore standard recovery disks or VM mounts
            if "Recovery" in partition.mountpoint or "VMware" in partition.mountpoint: continue
            drives.append(partition.mountpoint)
    return set(drives)

def eject_drive(mountpoint):
    if os.name == 'posix':
        if 'darwin' in os.uname().sysname.lower():
            cmd = ["diskutil", "unmount", mountpoint]
        else:
            cmd = ["umount", mountpoint]
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return True
        except Exception as e:
            pass
    return False

def push_dlp_alert(mountpoint, action_taken):
    payload = {
        "source": HOSTNAME,
        "event_type": "DLP_VIOLATION",
        "title": f"Unauthorized USB Device Attempt",
        "file_path": mountpoint,
        "ai_verdict": "SUSPICIOUS",
        "ai_reason": f"DLP Sensor detected a mass storage insertion at {mountpoint}. Policy Action: {action_taken}.",
        "severity": "high"
    }
    try:
        req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req)
        print(f"[*] DLP Triggered: Alert dispatched for {mountpoint}")
    except Exception as e:
        print(f"[-] Failed to push DLP alert: {e}")

def monitor_devices():
    known_drives = get_external_drives()
    print(f"[Watchtower DLP] Initialized. USB Write Protection: {'ON' if BLOCK_USB else 'OFF'}. Known partitions: {len(known_drives)}")
    
    while True:
        current_drives = get_external_drives()
        new_drives = current_drives - known_drives
        
        for drive in new_drives:
            print(f"[!] DLP: New external drive detected -> {drive}")
            action_taken = "Logged Only"
            
            if BLOCK_USB:
                print(f"[*] DLP Policy Enforcing... Ejecting {drive}")
                success = eject_drive(drive)
                if success:
                    action_taken = "Drive Forcibly Ejected (Zero-Trust)"
                else:
                    action_taken = "Ejection Failed. Admin Intervention Required."
            
            push_dlp_alert(drive, action_taken)
            # Add to known to prevent spamming
            known_drives.add(drive)
            
        # Handle removed drives naturally
        known_drives.intersection_update(current_drives)
        time.sleep(2)

if __name__ == "__main__":
    monitor_devices()
