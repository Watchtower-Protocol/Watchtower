import urllib.request
import json
import time

def send_mock_data():
    try:
        # Load API Key
        with open(".env") as f:
            lines = f.readlines()
            key = [line.split('=')[1].strip() for line in lines if line.startswith('WATCHTOWER_API_KEY')][0]
        
        # Threat Intel Payload
        payload1 = {
            "source": "Sentinel-Node-Alpha",
            "event_type": "THREAT_INTEL",
            "title": "Outbound Cobalt Strike Beacon",
            "file_path": "PID 41183 (/usr/libexec/periodic)",
            "ai_verdict": "MALICIOUS",
            "ai_reason": "Process is establishing a repeating 60-second jitter connection to a known malicious C2 IP. Execution pattern matches Cobalt Strike memory footprint. Network signature and memory footprint identified via Oracle trace.",
            "severity": "high"
        }

        req1 = urllib.request.Request(
            "http://127.0.0.1:4040/api/v2/ingest/threat", 
            data=json.dumps(payload1).encode(), 
            headers={'Content-Type': 'application/json', 'x-api-key': key}
        )
        urllib.request.urlopen(req1)
        print("[-] High-severity intel injected.")
        time.sleep(1)

        # FIM Payload
        payload2 = {
            "source": "FIM-Agent",
            "event_type": "FILE_MODIFIED",
            "title": "sshd_config overridden",
            "file_path": "/etc/ssh/sshd_config",
            "ai_verdict": "SUSPICIOUS",
            "ai_reason": "User gravity modified global sshd protocol settings outside of normal patch windows.",
            "severity": "medium"
        }
        
        req2 = urllib.request.Request(
            "http://127.0.0.1:4040/api/v2/ingest/fim", 
            data=json.dumps(payload2).encode(), 
            headers={'Content-Type': 'application/json', 'x-api-key': key}
        )
        urllib.request.urlopen(req2)
        print("[-] Medium-severity FIM alert injected.")
        
        print("\nSUCCESS: All mock data streamed to localhost:4040. Open your dashboard!")
        
    except Exception as e:
        print(f"[!] Engine Error -> Failed to inject: {e}")

if __name__ == "__main__":
    send_mock_data()

