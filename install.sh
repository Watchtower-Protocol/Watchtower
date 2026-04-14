#!/bin/bash
echo "[Watchtower] Running Pre-Flight Checks..."

for cmd in node npm python3 openssl curl; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "\033[1;31m[!] CRITICAL ERROR: '$cmd' is not installed or not in PATH.\033[0m"
        echo "Please install $cmd and run ./install.sh again."
        exit 1
    fi
done

echo "[+] All base dependencies found."

echo "[Watchtower] Initializing Sovereign EDR Suite..."
python3 -m venv .venv
source .venv/bin/activate
if [ ! -f requirements.txt ]; then
    cat << REQ > requirements.txt
watchdog==6.0.0
psutil==7.2.2
sentence-transformers==3.4.1
lancedb==0.17.0
numpy==1.26.4
pyarrow==19.0.0
REQ
else
    echo "[Watchtower] Existing requirements.txt detected. Supplementing dependencies safely..."
    grep -q "psutil" requirements.txt || echo "psutil==7.2.2" >> requirements.txt
fi
pip install -r requirements.txt --no-deps

if [ "$1" == "--hub" ] || [ -z "$1" ]; then
    echo "[Watchtower] Installing Node.js C2 Hub Components..."
    cd backend && npm ci --ignore-scripts && cd ..
    cd frontend && npm ci --ignore-scripts && cd ..
fi

mkdir -p data/quarantine
echo "[Watchtower] Dependency Installation Complete."

