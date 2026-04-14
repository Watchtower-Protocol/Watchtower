#!/bin/bash
echo "[Watchtower] Booting Command Center & Core Sensors..."

# Load environment variables
set -a
source .env
set +a

# Start Backend API
(cd backend && node app.js) &
API_PID=$!

# Start Frontend UI
(cd frontend && node serve_ui.js) &
UI_PID=$!

# Wait a second for API to boot
sleep 2

# Activate Python environment
source .venv/bin/activate
cd core

PIDS=""

echo "[Watchtower] Starting C2 Beacon Listener & Hub Services..."
python3 watchtower_beacon.py &
PIDS="$PIDS $!"

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

echo "[Watchtower] All enabled systems operational. Press Ctrl+C to shutdown."
trap "kill $API_PID $UI_PID $PIDS; exit" INT TERM
wait
