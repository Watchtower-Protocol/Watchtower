#!/usr/bin/env python3
import os
import sys
import math
import json
import argparse

def calculate_shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def run_fim_scan(file_path):
    """
    Agentic Wrapper Skill: Single-shot Shannon Entropy validation natively.
    """
    if not os.path.exists(file_path):
        print(json.dumps({"error": f"File {file_path} not found.", "skill": "watchtower_scan_file_entropy"}))
        sys.exit(1)

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        
        entropy = calculate_shannon_entropy(data)
        size_kb = len(data) / 1024.0
        
        verdict = "SAFE"
        # Highly obfuscated/encrypted files (like ransomware droppers) skew closer to 8.0
        if entropy > 7.5 and size_kb > 5:
            verdict = "CRITICAL: FILE HIGHLY OBFUSCATED OR ENCRYPTED (Ransomware Signatures)"
        elif entropy > 7.0:
            verdict = "WARNING: ELEVATED OBFUSCATION DETECTED"

        payload = {
            "skill": "watchtower_scan_file_entropy",
            "file_path": file_path,
            "file_size_kb": round(size_kb, 2),
            "shannon_entropy_score": round(entropy, 4),
            "ai_verdict": verdict
        }
        
        print(json.dumps(payload, indent=2))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e), "skill": "watchtower_scan_file_entropy"}))
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Watchtower Agent Skill: File Entropy Checker")
    parser.add_argument("filepath", type=str, help="Absolute path to the suspect file natively.")
    args = parser.parse_args()
    run_fim_scan(args.filepath)
