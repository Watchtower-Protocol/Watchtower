#!/bin/bash
echo "[Watchtower] Booting Command Center & Core Sensors..."

# Load environment variables
set -a
source .env 2>/dev/null
set +a

# Activate Python environment
source .venv/bin/activate
cd core
PIDS=""

if [ "$NODE_TYPE" == "HUB" ]; then
    echo "[Watchtower] Initiating Master Hub Boot Sequence..."
    
    # Start Backend API
    (cd ../backend && node app.js) &
    API_PID=$!
    
    # Start Frontend UI
    (cd ../frontend && node serve_ui.js) &
    UI_PID=$!
    
    sleep 2
    
    echo "[Watchtower] Starting C2 Beacon Listener & Hub Services..."
    python3 watchtower_beacon.py &
    PIDS="$PIDS $!"
elif [ "$NODE_TYPE" == "EDGE" ]; then
    echo "[Watchtower Sentinel] Initiating Edge Node Sequence..."
    echo "[Watchtower Sentinel] Starting Python Supervisor (Dynamic Node Orchestrator)..."
    python3 watchtower_beacon.py &
    PIDS="$PIDS $!"
else
    echo "[!] CRITICAL SEVERE: Internal Configuration missing NODE_TYPE."
    echo "[!] Re-run ./setup.sh to rebuild the .env correctly."
    exit 1
fi

echo "[Watchtower] Engaging Kernel-Level Resurrection Watchdog..."
python3 watchtower_resurrection.py &
PIDS="$PIDS $!"

echo "[Watchtower] Booting Master Topography Scraper Engine natively..."
python3 watchtower_net_scraper.py &
PIDS="$PIDS $!"

echo "[Watchtower] Starting Crypto Guard DLP Monitor..."
python3 ../agent_skills/crypto_guard.py --monitor &
PIDS="$PIDS $!"

echo "[Watchtower] Deploying Local Network Honeypot on port 3306 (MySQL decoy)..."
python3 ../agent_skills/honeypot_spawner.py --port 3306 --monitor &
PIDS="$PIDS $!"

echo "[Watchtower] All systems operational. Press Ctrl+C to shutdown."
if [ "$NODE_TYPE" == "HUB" ]; then
    trap "kill $API_PID $UI_PID $PIDS; exit" INT TERM
else
    trap "kill $PIDS; exit" INT TERM
fi
wait
