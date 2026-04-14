#!/usr/bin/env python3
import sys, json, subprocess, platform, time, argparse, math

def calc_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def sniff_dns(duration=10):
    os_sys = platform.system().lower()
    high_entropy_domains = []
    
    if os_sys in ["linux", "darwin"]:
        try:
            cmd = ["tcpdump", "-i", "any", "-nn", "-c", "50", "udp port 53"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(duration)
            proc.terminate()
            out, err = proc.communicate()
            
            for line in out.splitlines():
                if "A?" in line:
                    domain = line.split("A? ")[1].split(" ")[0].strip()
                    ent = calc_entropy(domain)
                    if ent > 4.0: 
                        high_entropy_domains.append({"domain": domain, "entropy": round(ent, 2)})
                        
            return {"status": "success", "duration": duration, "suspect_dns_tunnels": high_entropy_domains[:10]}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    else:
        return {"status": "unsupported", "message": "DNS Entropy capture natively requires Linux/Mac tcpdump."}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(sniff_dns(args.duration), indent=2))
