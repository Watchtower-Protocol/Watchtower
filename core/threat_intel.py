import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import json
import os
import re

STATE_FILE = os.path.expanduser("~/.openclaw/workspace/data/security/threat_intel_state.json")
KEYWORDS = ["npm", "node.js", "python", "macos", "tailscale", "supply chain", "zero-day", "zero day", "axios", "rce", "remote code execution", "backdoor"]

TELEGRAM_BOT_TOKEN = "8556410041:AAET648uDyrBWk7UJdol-w1ZQcytX_ySAGI"
CHAT_ID = "-1003752847454"
TOPIC_ID = 202

QWEN_URL = os.environ.get("AI_INFERENCE_URL", "http://127.0.0.1:1234/v1/chat/completions")

FEEDS = [
    {"name": "GitHub Security Advisories", "url": "https://github.blog/security/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"}
]

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except: pass
    return {"seen_urls": []}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def get_article_text(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8', errors='ignore')
            text = re.sub('<script.*?>.*?</script>', '', html, flags=re.DOTALL|re.IGNORECASE)
            text = re.sub('<style.*?>.*?</style>', '', text, flags=re.DOTALL|re.IGNORECASE)
            text = re.sub('<[^<]+>', ' ', text)
            text = re.sub('\\s+', ' ', text)
            return text[:4000]
    except Exception as e:
        return "Could not fetch article content."

def summarize_with_qwen(title, text):
    prompt = f"Title: {title}\n\nContent: {text}\n\nSummarize this cybersecurity threat in exactly 3 concise, highly analytical bullet points focusing on the impact and attack vector. Do not use conversational filler. Do not use bold formatting in the bullet marks."
    payload = {
        "model": "qwen/qwen3.5-35b-a3b",
        "messages": [
            {"role": "system", "content": "You are a Watchtower Security Threat Analyst. [ONE ACTION PER TURN]"},
            {"role": "user", "content": prompt}
        ],
        "stop": ["\nuser:", "\nTool [", "\nObservation:"],
        "temperature": 0.2
    }
    try:
        req = urllib.request.Request(QWEN_URL, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=60) as response:
            res = json.loads(response.read().decode('utf-8'))
            return res['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"- Error generating summary from local AI: {str(e)}"

def send_telegram_alert(title, source, link, summary, keywords):
    message = f"🚨 THREAT INTEL ALERT 🚨\n\nTitle: {title}\nSource: {source}\nKeywords: {', '.join(keywords)}\n\nAI Threat Summary:\n{summary}\n\n🔗 Read Full Disclosure: {link}"
    
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

WATCHTOWER_API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:3000") + "/api/v2/ingest/threat"
WATCHTOWER_API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")

def send_watchtower_alert(title, source, link, summary, keywords):
    payload = {
        "source": source,
        "event_type": "THREAT_INTEL",
        "title": title,
        "url": link,
        "keywords": keywords,
        "ai_summary": summary,
        "severity": "high" if "zero-day" in keywords or "rce" in keywords else "medium"
    }
    try:
        req = urllib.request.Request(WATCHTOWER_API_URL, data=json.dumps(payload).encode('utf-8'), headers={
            'Content-Type': 'application/json',
            'x-api-key': WATCHTOWER_API_KEY
        })
        urllib.request.urlopen(req, timeout=10)
        print(f"[ALERT SENT] Threat Intel routed to Watchtower V2: {title}")
    except Exception as e:
        print(f"Failed to send Watchtower alert: {e}")

def main():
    state = load_state()
    new_seen = set(state.get("seen_urls", []))

    for feed in FEEDS:
        try:
            req = urllib.request.Request(feed["url"], headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                root = ET.fromstring(response.read())
                for element in root.iter():
                    if element.tag.endswith('item') or element.tag.endswith('entry'):
                        title, link = "", ""
                        for child in element:
                            if child.tag.endswith('title'): title = child.text
                            elif child.tag.endswith('link'):
                                if child.text: link = child.text
                                elif 'href' in child.attrib: link = child.attrib['href']
                        if title and link:
                            if link in state.get("seen_urls", []): continue
                            new_seen.add(link)
                            
                            title_lower = title.lower()
                            matches = [kw for kw in KEYWORDS if kw in title_lower]
                            if matches:
                                print(f"Processing threat: {title}")
                                article_text = get_article_text(link)
                                summary = summarize_with_qwen(title, article_text)
                                send_telegram_alert(title, feed["name"], link, summary, matches)
                                send_watchtower_alert(title, feed["name"], link, summary, matches)
        except Exception as e:
            print(f"Error processing feed {feed['url']}: {e}")

    state["seen_urls"] = list(new_seen)[-500:]
    save_state(state)

if __name__ == "__main__":
    main()
