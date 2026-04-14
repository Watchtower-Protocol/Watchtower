# Watchtower Installation Guide

Welcome to the definitive deployment guide for Watchtower. Because the system is engineered as a Sovereign Architecture, there are no binary installers (`.exe` or `.pkg`). You are in complete control of the source code.

## Path A: Standalone Deployment (Manual User Setup)

If you are a system administrator or power user looking to install Watchtower on your personal machine or server without using an Autonomous AI Agent, follow these native OS instructions.

### Windows Users
1. Clone or download this repository.
2. Ensure you have **Python 3.10+** installed on your system.
3. Double-click `setup.bat`. This will bypass execution policies locally and launch the setup loop natively in PowerShell.
4. Select `1` for Hub or `2` for Edge Sensor.
5. If you configured a Master Hub, ensure you run `npm install` inside `/backend` and `/frontend`.
6. Double-click `start.bat` (for Hubs) or `start-agent.bat` (for Edge nodes). 

### Mac & Linux Users
1. Open a terminal and navigate to this repository.
2. Ensure `python3`, `npm`, and `node` are installed recursively.
3. Execute the setup engine:
```bash
chmod +x setup.sh
./setup.sh
```
4. Follow the interactive CLI to generate your cryptographic `.env` topology.
5. To boot the system, execute `./start.sh` (Hubs) or `./start-agent.sh` (Edge nodes).

---

## Path B: Agentic Deployment (Autonomous AI Orchestration)

Watchtower is built identically for AI consumption. If you are using OpenClaw, SWE-Agent, Hermes, or AutoGPT, you can simply point your Agent to this repository directory.

**Sample Prompt to your AI:**
> "Please navigate into the Watchtower directory. I need you to securely initialize the environment as a Master Hub node. Do not install Node dependencies yet, just configure the python virtual environment and ensure the cryptography secrets are successfully vaulted in the .env file. Use the native setup scripts provided in the dir."

Because the Agent has native bash execution capabilities, it will autonomously invoke `setup.sh`, negotiate the CLI parameters dynamically, and architect your system for you.
