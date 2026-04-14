#!/usr/bin/env python3
import sys, json, subprocess, platform, time, argparse

def capture_traffic(port, duration=10):
    os_sys = platform.system().lower()
    results = {"port": port, "duration": duration, "flows": []}
    
    try:
        if os_sys in ["linux", "darwin"]:
            cmd = ["tcpdump", "-i", "any", "-nn", "-c", "100", f"port {port}"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(duration)
            proc.terminate()
            out, err = proc.communicate()
            
            for line in out.splitlines():
                if ">" in line: results["flows"].append(line.strip())
                
        elif os_sys == "windows":
            cmd = ["netstat", "-ano", "-p", "TCP"]
            out = subprocess.check_output(cmd, text=True)
            for line in out.splitlines():
                if str(port) in line: results["flows"].append(line.strip())
                
        results["total_packets_captured"] = len(results["flows"])
        results["flows"] = results["flows"][:20] 
        return {"status": "success", "data": results}
        
    except Exception as e:
        return {"status": "error", "message": f"Packet capture failed (requires elevation?): {str(e)}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--duration", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(capture_traffic(args.port, args.duration), indent=2))
