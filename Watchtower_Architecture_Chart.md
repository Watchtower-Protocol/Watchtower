# Watchtower v1.6.9: Complete System Topology

This document illustrates the precise pipeline workflows and internal dependencies of the Watchtower Sovereign Security platform through a top-down architecture schematic.

```mermaid
graph TD
    %% Central Hub Section
    subgraph Hub [Command Center Matrix - Node.js]
        UI(Dashboards / Threat Stream / Asset Matrix)
        API{Express REST / Socket.IO Core}
        DB[(Local Offline State DB)]
        OTA[Over-The-Air Fleet Management]
        GPO(Host Group Policy Configuration)
        
        UI <--> API
        API <--> DB
        UI --> OTA
        UI <--> GPO
    end

    %% The Remote Host Endpoints
    subgraph Edge [Deployed Host Endpoints - Python Supervisor]
        Supervisor((watchtower_beacon.py))
        
        %% Tier 1: Real-time Intel Hooks
        subgraph Detectors [Tier 1: Intelligent Sensing]
            FIM[watchtower_fim.py : Hash & Entropy]
            YARA[watchtower_regex_sweeper.py : Regex Process Memory]
            BEHAVIOR[watchtower_behavioral.py : Fileless Tracking]
            NDR[watchtower_ndr.py : Burst Egress Telemetry]
            ORACLE[watchtower_oracle.py : App Lifecycle Inventory]
        end
        
        %% Tier 2: Corrective Auto-Action Hooks
        subgraph Effectors [Tier 2: Enforcement & Remediation]
            ROLLBACK[watchtower_rollback.py : APFS/VSS File Recovery]
            COMPLY[watchtower_compliance.py : CIS Posture Verification]
            QUARANTINE[watchtower_quarantine.py : Process Mute/Ban]
        end
        
        %% C2 Orchestration Logic
        Supervisor -.->|Dynamically toggles processes| Detectors
        Supervisor -.->|Periodically triggers| Effectors
    end

    %% Network Tunnels
    Detectors == "API: Port 4040 JSON Payloads" ==> API
    GPO -. "Sync: policy.json" .-> Supervisor
    QUARANTINE <.. "Polling" .. API
    OTA == "Push: HMAC-Verified core.zip" ==> Supervisor
    API -. "Threat Intel WebSockets" .-> UI
```

### Flow Breakdown

1. **Detection (Bottom-Up):** The Active Intel Sensors dynamically scan the internal OS state natively via Python representations. When a malicious state is detected, a JSON artifact is pushed directly up port `4040` into the `Express.js REST Core`.
2. **Analysis (Hub):** The Node API evaluates the telemetry. Based on configuration (and the *AI Bridge* logic models), it can categorize the payload into alerts.
3. **Execution (Top-Down):** If autonomous thresholds are breached (e.g. ransomware encryption bursts detected via `watchtower_regex_sweeper.py`), the Hub pushes a `QUARANTINE` schema down into the C2 queue. The `watchtower_beacon.py` Supervisor polls this instantaneously, triggers `watchtower_quarantine.py`, isolates the offender, and the local `watchtower_rollback.py` daemon can retroactively restore files.
4. **Operations (OTA):** Developers push modifications directly using `core.zip` files embedded through the `OTA Fleet Management` portal without shutting down the mesh.
