# Watchtower Threat Simulation Suite

> [!WARNING]
> **INTERNAL USE ONLY**. These scripts are meticulously designed to test the efficacy of Watchtower's native sensors by recreating attacker behaviors natively. DO NOT deploy this directory to production agents. DO NOT include it in `core.zip` OTA updates.

## Overview
This standalone toolkit provides completely harmless, synthetic replicas of malicious zero-day vectors. It is used strictly to validate that the Watchtower EDR subsystems are functioning perfectly out-of-the-box. Each function authentically mimics real-world attacker footprints on disk or in memory without generating any actual persistent malicious code.

## Local Execution Instructions

1. **Boot Watchtower**: Ensure the central Hub components are running, and boot an edge node utilizing `./start-agent.sh`. Ensure all subsystem policies (Behavioral, NDR, Decoy, FIM) are enabled dynamically via the UI Policy manager.
2. **Open Dashboard**: Keep `http://localhost:8080` open on your screen to visualize the telemetry streaming live.
3. In a separate native terminal window, navigate into this safe directory: `cd tests_simulators/`.
4. Execute the simulation architectures:

```bash
# Display help and available attack vectors
python3 watchtower_sim.py --help

# 1. Trigger File Integrity & Shannon Entropy Math Drop
python3 watchtower_sim.py --fim

# 2. Trigger Burst Packet Micro-Exfiltration (NDR Sweep)
python3 watchtower_sim.py --ndr

# 3. Trigger Fileless Living-off-the-Land (Behavioral LotL)
python3 watchtower_sim.py --lotl

# 4. Trigger USB/Insider-Threat Honeytoken Access (DLP)
python3 watchtower_sim.py --decoy

# 5. Full Chaos Validation (Execute all 4 parallel)
python3 watchtower_sim.py --all
```

## Matrix Validation
When the Python tests sequentially sequence out, switch immediately back natively to your **Command Center Dashboard**. 

You should definitively confirm that the Telemetry Threat Matrix captures and registers each burst exactly as they occur (e.g. `[NDR BURST ALERT]`, `[SYSTEM_SNAPSHOT]`, `[MALICIOUS ENTROPY]`). If the Sentinel Quarantine is armed properly (Audit Mode OFF), you will seamlessly observe the offending test processes violently terminate milliseconds after spawn.

## Security Clarification: Is this safe?
> [!TIP]
> **Yes, it is 100% completely safe.** 

If every single Watchtower AI engine was momentarily disabled and these tests executed directly on a bare-metal machine, absolutely nothing malicious would occur natively. The simulation suite purely utilizes programmatic "smoke and mirrors" to trick Watchtower's AI sensors into *perceiving* an attack is happening by replicating the *shape and contour* of an attack without containing any underlying payload ammo.

Here is exactly what executes under the hood if it bypasses the sensors:

1. **The Entropy Test (`--fim`)**
   * **What it mimics:** A heavily obfuscated ransomware script dynamically dropping.
   * **What it actually executes:** It purely writes standard `python3` strings containing completely randomized alphanumeric gibberish (e.g., `var_1 = 'ahHhL...'`). The pseudo-payload fundamentally never actually executes; if forced to, it merely allocates arbitrary dictionary texts to temporary memory and gracefully exits.

2. **The NDR Exfiltration Test (`--ndr`)**
   * **What it mimics:** A massive exfiltration pipe flushing your encrypted files to a C2 server.
   * **What it actually executes:** The script binds `socket()` commands against `1.1.1.1` (Cloudflare's public, safe DNS service) directly on Port 443. It forces open 200+ empty TCP connections, effectively resolving to send absolutely **zero** data fragments, holds the connection states natively alive for 15 seconds, and then collapses them safely.

3. **The Fileless Behavioral Test (`--lotl`)**
   * **What it mimics:** A dangerous encoded remote-access shell dropped natively in physical memory.
   * **What it actually executes:** It runs a Base64 encoded structure (`import base64; exec...`). If you decode the specific Base64 string hardcoded within the simulator, it translates literally into: `print("Simulated LotL Execution")`. It successfully triggers Behavioral heuristics natively by simply printing a word.

4. **The Insider Access Test (`--decoy`)**
   * **What it mimics:** An unauthorized user recursively copying your deep data vaults.
   * **What it actually executes:** It safely locates the local `decoy_passwords.txt` mock file instantiated by Watchtower, initiates a standard `open(Read)` query natively, and closes the buffer immediately natively against the file system.

Every mechanism was meticulously engineered exclusively for localized, isolated diagnostic benchmarking natively. There are zero external payload calls, zero unverified internal downloads, and zero destructive actions executed. You are completely secure to test!
