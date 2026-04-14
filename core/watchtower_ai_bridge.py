import json
import urllib.request
import urllib.error
import os
import threading

LM_STUDIO_URL = os.environ.get("AI_INFERENCE_URL", "http://127.0.0.1:1234/v1/chat/completions")
MODEL_ID = "qwen/qwen3.5-35b-a3b"

# Global Hardware Enforcement Semaphore
hardware_limit_lock = threading.Semaphore(2)

def analyze_file(event_type, filepath, entropy=None):
    if not hardware_limit_lock.acquire(blocking=False):
        return {"verdict": "UNKNOWN", "reason": "Hardware AI Inference Throttled (Denial of Service Prevention natively invoked)."}
    try:
        return _analyze_file(event_type, filepath, entropy)
    finally:
        hardware_limit_lock.release()

def _analyze_file(event_type, filepath, entropy=None):
    if not os.path.exists(filepath):
        return {"verdict": "UNKNOWN", "reason": "File already deleted or inaccessible."}
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read(4096) # Read first 4KB to save context/bandwidth
    except Exception as e:
        return {"verdict": "UNKNOWN", "reason": f"Could not read file: {e}"}

    # System Sentinel: Prompt Injection Defense
    jailbreak_heuristics = ["ignore previous", "system override", "forget all", "disregard", "new persona", "you are now"]
    content_lower = content.lower()
    for heuristic in jailbreak_heuristics:
        if heuristic in content_lower:
            return {"verdict": "MALICIOUS", "reason": f"Prompt Injection / Jailbreak Detected (Heuristic: '{heuristic}')"}

    system_prompt = (
        "You are Watchtower, an elite cybersecurity EDR AI. "
        "Analyze this file event and its content snippet. "
        "Respond ONLY with a valid JSON object. No explanation. "
        "Schema: {\"verdict\": \"SAFE\", \"reason\": \"<1 sentence explanation>\"} "
        "(Choose SAFE, SUSPICIOUS, or MALICIOUS for the verdict)."
    )
    
    entropy_str = f"\nFile Entropy (Shannon): {entropy} / 8.0 (High entropy > 7.0 indicates packing, obfuscation, or encryption)" if entropy else ""
    user_prompt = f"Event: {event_type}\nFile: {filepath}{entropy_str}\nContent snippet:\n{content}\n\nOutput strictly valid JSON now:"

    # Dynamically fetch the currently loaded model from LM Studio
    model_id = "qwen-coder" # Replace with your preferred local or cloud model
    try:
        models_url = LM_STUDIO_URL.replace("/chat/completions", "/models")
        req_models = urllib.request.Request(models_url)
        resp_models = urllib.request.urlopen(req_models, timeout=5)
        loaded_models = json.loads(resp_models.read().decode('utf-8'))
        if 'data' in loaded_models and len(loaded_models['data']) > 0:
            model_id = loaded_models['data'][0]['id']
    except Exception as e:
        print(f"[AI Bridge] Could not retrieve active model list from LM Studio, defaulting to {model_id}.")

    payload = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system_prompt + " [ONE ACTION PER TURN]"},
            {"role": "user", "content": user_prompt}
        ],
        "stop": ["\nuser:", "\nTool [", "\nObservation:"],
        "temperature": 0.1,
        "max_tokens": 400
    }

    req = urllib.request.Request(LM_STUDIO_URL, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
    
    try:
        
        response = urllib.request.urlopen(req, timeout=120) # Extended timeout to allow deep thinking
        result = json.loads(response.read().decode('utf-8'))
        ai_text = result['choices'][0]['message']['content'].strip()
        
        # 1. Strip the <think> blocks cleanly (handles multi-line and greedy matches)
        import re
        ai_text = re.sub(r'<think>.*?</think>', '', ai_text, flags=re.DOTALL).strip()
        
        # 2. Extract JSON payload strictly
        json_match = re.search(r'(\{.*?\})', ai_text, re.DOTALL)
        if json_match:
            ai_text = json_match.group(1).strip()

        
        # Strip markdown if the model disobeys the prompt
        if ai_text.startswith("```json"): ai_text = ai_text[7:]
        if ai_text.startswith("```"): ai_text = ai_text[3:]
        if ai_text.endswith("```"): ai_text = ai_text[:-3]
        
        return json.loads(ai_text.strip())
    except Exception as e:
        return {"verdict": "ERROR", "reason": f"AI Bridge failure: {e}. Raw Text: {ai_text}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        print(json.dumps(analyze_file(sys.argv[1], sys.argv[2]), indent=2))
