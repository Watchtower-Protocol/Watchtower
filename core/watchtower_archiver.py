import lancedb
import json
import os
import time
import urllib.request
from datetime import datetime

# Watchtower LanceDB Archiver
WATCHTOWER_API = os.environ.get("WATCHTOWER_API_URL", "http://127.0.0.1:3000") + "/api/alerts"
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
LANCEDB_PATH = os.environ.get("WATCHTOWER_DATA_DIR", "../data") + "/security/watchtower.lancedb"

# We use the SentenceTransformer from the RAG system to generate embeddings
try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("Dependencies missing. Ensure sentence-transformers is installed.")
    exit(1)

MODEL_NAME = "all-MiniLM-L6-v2"

def main():
    print(f"[Watchtower Archiver] Connecting to LanceDB at {LANCEDB_PATH}...")
    db = lancedb.connect(LANCEDB_PATH)
    
    # Load embedding model
    print(f"[Watchtower Archiver] Loading embedding model: {MODEL_NAME}")
    model = SentenceTransformer(MODEL_NAME)
    
    # Check if table exists, else create it
    if "security_events" not in db.table_names():
        # Define schema implicitly via a dummy insert or explicit pyarrow schema
        print("[Watchtower Archiver] Creating 'security_events' table...")
        dummy_vector = model.encode("dummy").tolist()
        db.create_table("security_events", data=[{
            "id": "dummy", 
            "vector": dummy_vector, 
            "event_type": "INIT", 
            "severity": "low", 
            "content": "init", 
            "timestamp": datetime.utcnow().isoformat()
        }])
        db.table("security_events").delete('id = "dummy"')
    
    table = db.table("security_events")
    
    # Simple poll to archive completed alerts
    archived_ids = set()
    try:
        # Load previously archived IDs if possible (simplified for MVP)
        existing = table.search().limit(1000).to_list()
        archived_ids = set([r["id"] for r in existing])
    except Exception as e:
        print(f"Warning: could not load existing IDs: {e}")

    print("[Watchtower Archiver] Monitoring API for completed alerts...")
    while True:
        try:
            req = urllib.request.Request(WATCHTOWER_API, headers={'x-api-key': API_KEY})
            with urllib.request.urlopen(req) as response:
                alerts = json.loads(response.read().decode())
                
                new_records = []
                for alert in alerts:
                    aid = alert.get("id")
                    verdict = alert.get("ai_verdict", "")
                    
                    # Only archive resolved alerts
                    if aid and aid not in archived_ids and verdict != "ANALYZING...":
                        # Create semantic content for embedding
                        title = alert.get("file_path") or alert.get("title") or "Unknown Event"
                        reason = alert.get("ai_reason") or alert.get("ai_summary") or ""
                        content = f"Event: {alert.get('event_type')} | Target: {title} | Verdict: {verdict} | Reason: {reason}"
                        
                        vector = model.encode(content).tolist()
                        
                        time_str = alert.get("ingested_at") or alert.get("received_at") or datetime.utcnow().isoformat()
                        
                        new_records.append({
                            "id": aid,
                            "vector": vector,
                            "event_type": alert.get("event_type", "UNKNOWN"),
                            "severity": alert.get("severity", "low"),
                            "content": content,
                            "timestamp": time_str
                        })
                        archived_ids.add(aid)
                
                if new_records:
                    print(f"[Watchtower Archiver] Committing {len(new_records)} new alerts to LanceDB Vector Memory.")
                    table.add(new_records)
                    
        except Exception as e:
            print(f"[-] Archiver error: {e}")
            
        time.sleep(10)

if __name__ == "__main__":
    main()