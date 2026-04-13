import os
import json
import time
import urllib.request
import urllib.error
import threading
import queue
import hashlib
import math
import fnmatch
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import watchtower_ai_bridge
import watchtower_quarantine

# Watchtower File Integrity Monitor (FIM) - Native High-Speed Queue
API_URL = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:4040") + "/api/v2/ingest/fim"
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else "Local-Node"
SIGNATURES_FILE = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + "/signatures.json"
WHITELIST_FILE = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + "/whitelist.json"
AUDIT_MODE = os.environ.get("WATCHTOWER_AUDIT_MODE", "false").lower() == "true"

SIGNATURE_CACHE = set()
WHITELIST_CACHE = {"paths": [], "hashes": []}

def reload_caches():
    global SIGNATURE_CACHE, WHITELIST_CACHE
    try:
        with open(SIGNATURES_FILE, 'r') as f:
            SIGNATURE_CACHE = set(json.load(f).get("bad_hashes", []))
    except: pass
    try:
        with open(WHITELIST_FILE, 'r') as f:
            WHITELIST_CACHE = json.load(f)
    except: pass

reload_caches()

def get_file_hash(filepath):
    """Calculates SHA256 of file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def check_deterministic_signature(filepath, file_hash=None):
    if not file_hash: file_hash = get_file_hash(filepath)
    if not file_hash: return False
    return file_hash in SIGNATURE_CACHE

def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(8192) # sample 8KB
        if not data: return 0.0
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0: entropy += - p_x * math.log2(p_x)
        return round(entropy, 2)
    except:
        return 0.0

def is_whitelisted(filepath, file_hash=None):
    if not file_hash: file_hash = get_file_hash(filepath)
    if file_hash in WHITELIST_CACHE.get("hashes", []): return True
    for p in WHITELIST_CACHE.get("paths", []):
        if fnmatch.fnmatch(filepath, p): return True
    return False

# High-Value Target (HVT) Directories to Monitor
HVT_PATHS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.environ.get("WATCHTOWER_TARGET_DIR", "./data"),  # Sandbox tests
    "/etc", 
    "/usr/local/bin"
]

# Strict Noise Filters (Exts & Dirs) to prevent CPU and Queue burn
IGNORED_DIRS = ["__pycache__", ".venv", "node_modules", ".git", "Library", ".cache", ".next", "dist", "build", "turbopack", ".vscode"]
IGNORED_EXTS = [".log", ".tmp", ".cache", ".DS_Store", ".swp", ".sqlite", "-wal", "-journal", ".pack", ".map", ".json", ".lock", ".idx"]

# AI Temporal Throttling (Debouncer)
throttle_lock = threading.Lock()
debounce_log = {}
DEBOUNCE_WINDOW_SEC = 5
MAX_HITS_BEFORE_THROTTLE = 3

# The AI Throttling Queue
alert_queue = queue.Queue()

def queue_worker():
    """Background processor that feeds alerts to AI sequentially preventing DDoS."""
    while True:
        event_type, filepath, phash = alert_queue.get()
        try:
            _process_and_alert(event_type, filepath, phash)
        except Exception as e:
            print(f"[!] FIM AI Processing Error: {e}")
        finally:
            alert_queue.task_done()

# Start worker immediately
threading.Thread(target=queue_worker, daemon=True).start()

RISK_EXTS = [".sh", ".bash", ".exe", ".py", ".js", ".plist", ".dylib", ".so", ".app", ".dmg", ".pkg", ".deb", ".php", ".rb", ".pl", ".bat", ".ps1"]

def is_noisy(filepath):
    """Filters out mass system background noise relying heavily on High Risk Whitelisting."""
    filename = os.path.basename(filepath).lower()
    if filename.startswith('.'): return True
    
    for idir in IGNORED_DIRS:
        if f"/{idir}/" in filepath or filepath.endswith(f"/{idir}"): return True

    for ext in IGNORED_EXTS:
        if filename.endswith(ext): return True
        
    # Throttle: Only scan files with no extension (Linux/Mac binaries) or explicit risk extensions
    _, ext = os.path.splitext(filename)
    if not ext:
        return False # No extension, might be an ELF or Mach-O executable
        
    if ext in RISK_EXTS:
        return False
        
    # Ignore all other generic document/media/settings files to save AI compute
    return True

def push_to_queue(event_type, filepath):
    if filepath.endswith("signatures.json") or filepath.endswith("whitelist.json"):
        reload_caches()
        return
        
    if is_noisy(filepath): return
    
    # --- TEMPORAL RATE LIMITER (DOS Debouncer) ---
    with throttle_lock:
        now = time.time()
        last_time, counter = debounce_log.get(filepath, (0, 0))
        
        if now - last_time < DEBOUNCE_WINDOW_SEC:
            counter += 1
            debounce_log[filepath] = (now, counter)
            if counter > MAX_HITS_BEFORE_THROTTLE:
                return # Hard-Drop redundant hits natively to securely protect LM Studio
        else:
            debounce_log[filepath] = (now, 1)
    
    phash = get_file_hash(filepath)
    if is_whitelisted(filepath, phash): return
    
    alert_queue.put((event_type, filepath, phash))

def _process_and_alert(event_type, filepath, phash):
    print(f"[*] FSEvent Triggered: {event_type} on {filepath}")
    
    # 1. Immediate Initial Alert (Status: Pending Analysis)
    data_pending = json.dumps({
        "source": HOSTNAME,
        "file_path": filepath,
        "event_type": event_type,
        "severity": "medium", 
        "ai_verdict": "ANALYZING...",
        "ai_reason": "Sent to Sovereign Cognitive Queue..."
    }).encode('utf-8')
    
    try:
        req_pending = urllib.request.Request(API_URL, data=data_pending, headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req_pending)
    except Exception as e:
        print(f"[Warning] Failed to send pending alert: {e}")

    # 2. Local AI & Signature Analysis Call
    is_known_bad = check_deterministic_signature(filepath, phash) if event_type != "FILE_DELETED" else False
    
    if is_known_bad:
        verdict = "MALICIOUS"
        reason = "Match against deterministic threat signature."
        print(f"[!] DETERMINISTIC MATCH: {filepath}. Auto-Quarantining.")
        if not AUDIT_MODE:
            watchtower_quarantine.quarantine_file(filepath)
        else:
            print(f"[AUDIT MODE] Skipped Quarantine Actions.")
    elif event_type == "FILE_DELETED":
        verdict = "SAFE"
        reason = "File deleted. No content to analyze."
    else:
        ent = calculate_entropy(filepath)
        ai_res = watchtower_ai_bridge.analyze_file(event_type, filepath, entropy=ent)
        verdict = ai_res.get("verdict", "UNKNOWN")
        reason = ai_res.get("reason", "No reason provided")
        
    severity = "high" if verdict in ["MALICIOUS", "SUSPICIOUS"] else "low"
    
    # 3. Final Enriched Alert
    data_final = json.dumps({
        "source": HOSTNAME,
        "file_path": filepath,
        "event_type": event_type,
        "severity": severity,
        "ai_verdict": verdict,
        "ai_reason": reason
    }).encode('utf-8')
    
    try:
        req_final = urllib.request.Request(API_URL, data=data_final, headers={'Content-Type': 'application/json', 'x-api-key': API_KEY})
        urllib.request.urlopen(req_final)
        print(f"[ALERT SECURED] {event_type} | AI: {verdict}")
    except Exception as e:
        print(f"[ERROR] Failed to send final alert: {e}")


class WatchtowerEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory: push_to_queue("FILE_CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory: push_to_queue("FILE_MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory: push_to_queue("FILE_DELETED", event.src_path)

def main():
    observer = Observer()
    event_handler = WatchtowerEventHandler()
    
    # Attach watchdogs to all existing critical OS paths
    active_monitors = 0
    for path in HVT_PATHS:
        if os.path.exists(path):
            try:
                observer.schedule(event_handler, path, recursive=True)
                print(f"[Watchtower FIM] Native tracking attached to: {path}")
                active_monitors += 1
            except Exception as e:
                print(f"[!] Warning: Cannot monitor {path} - {e}")
    
    if active_monitors == 0:
        print("[!] Fatal: No valid High-Value Targets (HVT) found to monitor. Exiting.")
        return

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Watchtower FIM] Halting monitor...")
        observer.stop()
    observer.join()

if __name__ == '__main__':
    main()