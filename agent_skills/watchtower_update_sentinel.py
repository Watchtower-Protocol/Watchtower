#!/usr/bin/env python3
import sys, json, os, argparse

def update_sentinel(new_heuristic, force_consent):
    if not force_consent:
        return {"status": "dry_run", "message": f"Consent flag skipped. You must converse with the human user and secure permission to add '{new_heuristic}' to the global Sentinel Firewall blocklist."}
    
    rules_path = os.path.join(os.path.dirname(__file__), "..", "core", "prompt_sentinel_rules.json")
    
    try:
        if os.path.exists(rules_path):
            with open(rules_path, "r") as f:
                data = json.load(f)
        else:
            data = {"jailbreak_heuristics": []}
            
        if new_heuristic.lower() not in data["jailbreak_heuristics"]:
            data["jailbreak_heuristics"].append(new_heuristic.lower())
            
        with open(rules_path, "w") as f:
            json.dump(data, f, indent=2)
            
        return {"status": "success", "message": f"Successfully updated global AI Semantic Firewall with '{new_heuristic}'"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--heuristic", required=True, help="New jailbreak string to block")
    parser.add_argument("--force-consent", type=lambda x: (str(x).lower() == 'true'), default=False)
    args = parser.parse_args()
    
    print(json.dumps(update_sentinel(args.heuristic, args.force_consent), indent=2))
