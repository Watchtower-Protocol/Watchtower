# Watchtower V3 Architecture: Antigravity Handoff Brief

## Overview
This document serves as the formal handover to Antigravity. I (Vertex) have begun the transition of Watchtower from a V2 API Gateway to a V3 Enterprise Sovereign EDR by injecting four critical new components.

Phase 1 is officially complete and active in this repository. Phases 2, 3, and 4 require deep system-level auditing and cross-platform (macOS/Linux/Windows) testing. 

## The V3 Blueprint

### [✅] Phase 1: The Honeypot (Decoy Sensors)
**Status:** Implemented in `core/watchtower_decoy.py` and wired into `start.sh`, `start-agent.sh`, and `.env`.
**Function:** It deploys invisible, tempting dummy files (`~/Documents/finance_passwords_2026.csv` and `~/.ssh/backup_rsa_key_legacy`). If any rogue script or ransomware touches them, it fires a definitive `MALICIOUS` alert to the Hub API, bypassing AI analysis entirely for a guaranteed true positive.

### [PENDING] Phase 2: The Fast-Path (Deterministic Signatures)
**Action Required by Antigravity:** 
We need to implement a hash-checker in `watchtower_fim.py`. Before it passes a created/modified file to the AI Bridge (`watchtower_ai_bridge.py`), it must calculate the SHA256 hash. If it matches a list of known bad hashes (e.g., from a local `data/signatures.json` file), it must trigger an instant quarantine. This will save massive compute latency on known threats.

### [PENDING] Phase 3: The Network Kill Switch (Cross-Platform Isolation)
**Action Required by Antigravity:** 
Modify `core/watchtower_quarantine.py` to handle a `NETWORK_ISOLATION` command from the Hub. 
You must implement a Python `subprocess` logic block that detects the OS (`platform.system()`) and executes the correct firewall isolation command:
- **macOS:** Inject an explicit deny rule into `pfctl`.
- **Linux:** Inject a `DROP` rule into `iptables`.
- **Windows:** Inject a block-all rule into `netsh advfirewall`.
*Crucial Constraint:* You must leave the Tailscale/Hub IP Open so the agent can still receive the "Un-isolate" command.

### [PENDING] Phase 4: Fleet Auto-Updating (C2 OTA Payload)
**Action Required by Antigravity:** 
Upgrade `watchtower_beacon.py` to accept an `UPDATE_CORE` command. It should download a `.zip` payload, extract it over the `core/` directory, and restart its own process. This allows us to push updates to 50 remote Linux/Windows nodes simultaneously from the Hub UI without SSH.

---

*Antigravity: Read this file. Acknowledge the architecture. Execute the pending phases one-by-one and update this document as you clear them.*