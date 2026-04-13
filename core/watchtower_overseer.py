import os
import time
import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta

WATCHTOWER_API = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:3000") + "/api/alerts"
WATCHTOWER_INGEST = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:3000") + "/api/v2/ingest/fim"  # We can push updates here, or add a dedicated update endpoint
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
STALL_TIMEOUT_SECONDS = 15

# We use the Micro model for fallback consistency checks
LM_STUDIO_URL = os.environ.get("AI_INFERENCE_URL", "http://127.0.0.1:1234/v1/chat/completions")

def fetch_alerts():
    req = urllib.request.Request(WATCHTOWER_API, headers={'x-api-key': API_KEY})
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"[-] Overseer failed to fetch alerts: {e}")
        return []

def fallback_analysis(filepath):
    # Quick heuristic / micro-model fallback
    system_prompt = "You are the Overseer AI. The main AI failed to analyze this file in time. Provide a rapid fallback verdict. Output ONLY valid JSON: {\"verdict\": \"SAFE\"|\"SUSPICIOUS\", \"reason\": \"<brief>\"}"
    payload = {
        "model": "local-micro", # Using whatever is default on 1234 or heuristic
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"File: {filepath}\nProvide rapid verdict."}
        ],
        "temperature": 0.1,
        "max_tokens": 100
    }
    
    try:
        req = urllib.request.Request(LM_STUDIO_URL, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
        response = urllib.request.urlopen(req, timeout=10)
        result = json.loads(response.read().decode('utf-8'))
        ai_text = result['choices'][0]['message']['content'].strip()
        
        # Simple extraction
        if "SUSPICIOUS" in ai_text: return "SUSPICIOUS", "Overseer Fallback: File marked suspicious due to main AI timeout."
        return "SAFE", "Overseer Fallback: Defaulted to SAFE due to main AI timeout."
    except:
        return "UNKNOWN", "Overseer Fallback: Local Micro-AI also failed/offline."

def update_stalled_alert(alert):
    filepath = alert.get("file_path", "unknown")
    print(f"[*] Overseer intervening on stalled alert for: {filepath}")
    
    verdict, reason = fallback_analysis(filepath)
    severity = "medium" if verdict == "SUSPICIOUS" else "low"
    
    # Push the resolution back to the V2 ingest endpoint
    # (In a true DB we'd PUT/PATCH, but pushing a new corrected event works for the UI log)
    data = json.dumps({
        "source": "overseer-agent",
        "file_path": filepath,
        "event_type": alert.get("event_type", "TIMEOUT_RESOLUTION"),
        "severity": severity,
        "ai_verdict": verdict,
        "ai_reason": reason
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(WATCHTOWER_INGEST, data=data, headers={
            'Content-Type': 'application/json',
            'x-api-key': API_KEY
        })
        urllib.request.urlopen(req)
        print(f"[+] Overseer resolved stalled state: {verdict}")
    except Exception as e:
        print(f"[-] Overseer update failed: {e}")

def main():
    print("[Watchtower Overseer] Starting consistency & stall-check daemon...")
    while True:
        alerts = fetch_alerts()
        now = datetime.utcnow()
        
        for alert in alerts:
            if alert.get("ai_verdict") == "ANALYZING...":
                # Parse timestamp safely
                time_str = alert.get("ingested_at") or alert.get("received_at")
                if time_str:
                    try:
                        # Handle Z ending
                        if time_str.endswith('Z'): time_str = time_str[:-1]
                        alert_time = datetime.fromisoformat(time_str)
                        if (now - alert_time).total_seconds() > STALL_TIMEOUT_SECONDS:
                            update_stalled_alert(alert)
                    except Exception as e:
                        print(f"Time parse error: {e}")
        
        time.sleep(5) # Poll every 5 seconds

if __name__ == "__main__":
    main()