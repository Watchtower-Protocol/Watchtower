#!/usr/bin/env python3
import sys, json, os, platform, subprocess, argparse

def execute_yara(rules_path, target_dir):
    try:
        import yara
    except ImportError:
        return {
            "status": "error",
            "message": "Commercial YARA compiler missing to preserve zero-dependency footprint.",
            "remediation_command": "pip install yara-python"
        }
    
    try:
        rules = yara.compile(filepath=rules_path)
    except Exception as e:
        return {"status": "error", "message": f"Syntax error in YARA rule: {str(e)}"}
        
    findings = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            file_path = os.path.join(root, f)
            try:
                matches = rules.match(file_path)
                if matches:
                    findings.append({"file": file_path, "rules_matched": [m.rule for m in matches]})
            except: pass
            
    return {"status": "success", "target": target_dir, "yara_matches": findings}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True, help="Path to .yar rules file")
    parser.add_argument("--target", required=True, help="Directory to scan")
    args = parser.parse_args()
    print(json.dumps(execute_yara(args.rules, args.target), indent=2))
