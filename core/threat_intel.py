#!/usr/bin/env python3
import urllib.request
import urllib.error
import json
import os

STATE_FILE = os.path.expanduser("~/.openclaw/workspace/data/security/threat_intel_state.json")

TELEGRAM_BOT_TOKEN = "8556410041:AAET648uDyrBWk7UJdol-w1ZQcytX_ySAGI"
CHAT_ID = "-1003752847454"
TOPIC_ID = 202

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

WATCHTOWER_API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:3000") + "/api/v2/ingest/threat"
WATCHTOWER_API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except: pass
    return {"seen_cves": []}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def send_telegram_alert(cve_id, product, name, desc, remediation):
    message = f"🚨 CISA KEV ZERO-DAY ALERT 🚨\n\nID: {cve_id}\nTactical Target: {product}\nVulnerability: {name}\n\nThreat Synopsis:\n{desc}\n\nRequired Remediation:\n{remediation}\n\n🔗 Source: CISA Known Exploited Vulnerabilities Catalog"
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "message_thread_id": TOPIC_ID,
        "text": message,
        "disable_web_page_preview": True
    }
    
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")

def send_watchtower_alert(cve_id, product, name, desc):
    payload = {
        "source": "CISA KEV Catalog",
        "event_type": "THREAT_INTEL",
        "title": f"[{cve_id}] {name}",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "keywords": [cve_id, product, "zero-day", "KEV", "CISA"],
        "ai_summary": desc,
        "severity": "high"
    }
    try:
        req = urllib.request.Request(WATCHTOWER_API_URL, data=json.dumps(payload).encode('utf-8'), headers={
            'Content-Type': 'application/json',
            'x-api-key': WATCHTOWER_API_KEY
        })
        urllib.request.urlopen(req, timeout=10)
        print(f"[ALERT SENT] CISA Threat Intel routed to Watchtower V2: {cve_id}")
    except Exception as e:
        print(f"Failed to send Watchtower alert: {e}")

def poll_cisa_kev():
    state = load_state()
    seen_cves = set(state.get("seen_cves", []))

    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0 (Watchtower EDR)'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Read backwards to get most recent first
            for vuln in reversed(vulnerabilities):
                cve_id = vuln.get("cveID", "")
                if not cve_id or cve_id in seen_cves: continue
                
                print(f"Processing Active CISA Threat: {cve_id}")
                product = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}"
                name = vuln.get("vulnerabilityName", "Unknown Vulnerability")
                desc = vuln.get("shortDescription", "No description provided.")
                action = vuln.get("requiredAction", "Patch immediately.")
                
                send_telegram_alert(cve_id, product, name, desc, action)
                send_watchtower_alert(cve_id, product, name, desc)
                
                seen_cves.add(cve_id)
                
            state["seen_cves"] = list(seen_cves)[-500:] # Keep list from growing infinitely
            save_state(state)
            
    except Exception as e:
        print(f"Error polling CISA KEV JSON endpoint: {str(e)}")

if __name__ == "__main__":
    poll_cisa_kev()
