#!/usr/bin/env python3
import time, subprocess, sys, os

def monitor_core_loop():
    print("[*] Watchtower Resurrection Daemon operational. Shielding core processes.")
    while True:
        try:
            # Use ps aux and verify watchtower_beacon.py is active
            out = subprocess.check_output("ps aux | grep watchtower_beacon.py | grep -v grep || true", shell=True, text=True)
            if "watchtower_beacon.py" not in out:
                print("[!] CRITICAL ALERT: watchtower_beacon.py has been terminated!")
                print("[*] Resurrection Daemon automatically reviving telemetry framework...")
                # Re-launch
                subprocess.Popen(["python3", "watchtower_beacon.py"])
        except Exception as e:
            pass
        time.sleep(30)

if __name__ == "__main__":
    monitor_core_loop()
