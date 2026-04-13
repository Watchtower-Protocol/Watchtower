# Watchtower v1.6 Tools & EDR Capability Architecture

This document maps out the autonomous internal toolkits and communication pathways established within the Sovereign Host Agent. Any autonomous AI interacting with this system should refer to these guidelines.

## 1. Dynamic Sensor Architectures
- **`watchtower_beacon.py` (The Supervisor)**: The Master Orchestrator and C2 Link. Bootstraps and dynamically terminates all internal EDR subsystems natively in Python, completely deprecating archaic static `.env` shell script management.
- **`watchtower_fim.py` (File Guardian)**: File Integrity Module. Performs deterministic `SHA256` hash evaluation at Layer 1, and semantic AI LLM evaluation at Layer 2. Employs **Shannon Entropy** computation, dropping high-obfuscation payloads straight into the LLM context to prevent padding evading. Integrates natively with `data/whitelist.json`.
- **`watchtower_behavioral.py` (Fileless Engine)**: Analyzes real-time Process Lineages (IOA) via `psutil` memory mapping. Designed to autonomously sever memory-only execution chains (e.g. `powershell.exe -enc`, Base64 decoding, or `curl x | bash`) instantly before persistent execution payloads are dropped to disk.
- **`watchtower_oracle.py` (Deep Scraper)**: Continuously maps executing Application SH256 hashes onto outbound TCP networks. It exports a unified `App Asset Inventory` (Application Uptime & Supply Chain Hashes) to the Dashboard Matrix.
- **`watchtower_regex_sweeper.py` (Hex Sweeper)**: Mimics YARA process-memory heuristics purely in Python by running Regex chunking against active disk executables, preserving zero-dependency metrics while catching Cobalt Strike/Meterpreter artifacts.
- **`watchtower_ndr.py` (Packet Analyzer)**: Elevates edge NDR visibility by leveraging native cross-OS connection polling. Completely bypasses legacy pcap payload installations. Instantly detects mass-socket C2 bursting.
- **`watchtower_topology.py` & Scraper (L2 Topography Spider)**: Transforms the Master Hub into a lightweight Network Access Control (NAC). Employs automated Paramiko SSH loops from the central server exclusively to digest core switch hardware natively (protecting Edge Agent credentials). Maps switch density organically against temporal JSON states to instantly alert on rogue unmanaged network splitters.
- **`watchtower_compliance.py` (CIS Auditor)**: Performs deep CIS-like benchmark assertions hourly natively against FireVault, Windows/Linux Registries, and local SSH configurations.
- **`watchtower_rollback.py` (Shadow Recovery)**: Employs silent localized APFS/VSS snapshots incrementally backwards out of the way to guarantee raw data permanence arrays if the perimeter AI engines fail a zero-day response limitation. Requires Administrator/SYSTEM elevation on Windows targets for Volume Shadow Copies.

## 2. Command & Control Schemas
The EDR architecture listens for JSON-level API routing via active WebSocket tunneling and polling.

- **`UPDATE_POLICY`**: Realigns the Local Node's active sensors. If an administrator toggles a sensor (like FIM) "Off" from the Command Center, the Beacon natively terminates the matching Python `subprocess` tree and syncs the new `policy.json` over disk.
- **`REVOKE_TRUST`**: Driven by Threat Intelligence. Rapid-fire capability to strip localized Zero-Day app binaries out of the Trusted White-lists and into deterministic quarantine schemas globally within milliseconds.
- **`UPDATE_CORE`**: Downloads an OTA `zip` package to self-update the internal EDR framework. Payload must pass a strict cryptographic HMAC signature validation utilizing the `WATCHTOWER_API_KEY`.

## 3. Agentic Skills Protocol (`/agent_skills/`)
Watchtower Command natively integrates with downstream Autonomous Orchestration AI architectures (like OpenClaw, Hermes, SWE-Agent, or AutoGPT) as well as modern IDE Copilots. Rather than relying on continuous Python sub-loops, an autonomous orchestration agent or local AI assistant can physically assume direct control of the EDR sensors using single-shot executable wrappers.

1. Read the `agent_skills/watchtower_tool_schemas.json` array to ingest the strict API schemas mapping to OpenAI/Anthropic universal Tool Calling protocols.
2. Execute the CLI scripts directly:
   - `python3 agent_skills/scan_network.py` -> Returns strict JSON mapping raw TCP/C2 sweeps.
   - `python3 agent_skills/scan_file_entropy.py <file>` -> Evaluates base64/encryption mathematically. 
   - `python3 agent_skills/scan_registry.py` -> Validates active CIS configurations.
