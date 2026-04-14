#!/bin/bash
echo "[Watchtower Sentinel] Booting Silent Analytics Sensors..."

# Load environment variables
set -a
source .env
set +a

# Activate Python environment
source .venv/bin/activate
cd core

PIDS=""

echo "[Watchtower Sentinel] Starting Python Supervisor (Dynamic Node Orchestrator)..."
python3 watchtower_beacon.py &
PIDS="$PIDS $!"

echo "[Watchtower Sentinel] Headless supervisor operational. Press Ctrl+C to shutdown."
trap "kill $PIDS; exit" INT TERM
wait

