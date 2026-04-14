#!/usr/bin/env python3
import socket, sys, json, argparse, time

def deploy_honeypot(port, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.settimeout(timeout)
        
        conn, addr = s.accept()
        data = conn.recv(1024)
        conn.close()
        s.close()
        
        return {"status": "breach_detected", "port": port, "attacker_ip": addr[0], "payload_preview": str(data)[:100]}
    except socket.timeout:
        s.close()
        return {"status": "clean", "port": port}
    except Exception as e:
        return {"status": "error", "message": f"Could not bind port {port}. Error: {str(e)}"}

def run_daemon(port):
    print(f"[*] Watchtower Honeypot listening indefinitely on port {port}...")
    while True:
        res = deploy_honeypot(port, timeout=86400)
        if res["status"] == "breach_detected":
            print(f"[!] HONEYPOT TRIPPED! Port: {port} | Attacker IP: {res['attacker_ip']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()
    
    if args.monitor: run_daemon(args.port)
    else: print(json.dumps(deploy_honeypot(args.port, args.timeout), indent=2))
