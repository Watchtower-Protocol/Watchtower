# Contributing to Watchtower EDR
First off, thank you for considering contributing to Watchtower! This is an entirely Sovereign, Zero-Dependency project sustained by our architecture testing community natively.

## The Zero-Dependency Golden Rule
The definitive premise of Watchtower is that **Edge Python Agents execute autonomously without PIP installs**. 
If you build a new `watchtower_XXX.py` sensor and submit a PR:
- **DO NOT** `import requests`, `import paramiko` (on the Edge layer), `import pandas`, etc.
- You must strictly utilize the Python natively-bound OS libraries (`urllib.request`, `subprocess`, `os`, `sys`, `json`).
- If you rely on external logic (like AI APIs or specialized networking like Scapy), that pipeline must occur strictly within the Node.js **Master Hub backend** or via native Hub daemons (like `watchtower_net_scraper.py` running exclusively inside `start.sh`).

## How to Submit A Change
1. Fork the framework branch!
2. Validate your Python code against MacOS, Linux, and Windows locally using the `watchtower_sim.py` environment.
3. Submit a Pull Request documenting exactly what OS environment you ran tests against natively.

