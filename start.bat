@echo off
echo [Watchtower] Booting Command Center ^& Core Sensors...

for /f "delims=" %%A in (.env) do set %%A

start /b cmd /c "cd backend && node app.js"
start /b cmd /c "cd frontend && node serve_ui.js"

timeout /t 2 /nobreak >nul

call .venv\Scripts\activate.bat
cd core

echo [Watchtower] Starting C2 Beacon Listener ^& Hub Services...
start /b python watchtower_beacon.py

echo [Watchtower] Engaging Kernel-Level Resurrection Watchdog...
start /b python watchtower_resurrection.py

echo [Watchtower] Booting Master Topography Scraper Engine natively...
start /b python watchtower_net_scraper.py

echo [Watchtower] Starting Crypto Guard DLP Monitor...
start /b python ../agent_skills/crypto_guard.py --monitor

echo [Watchtower] Deploying Local Network Honeypot on port 3306 (MySQL decoy)...
start /b python ../agent_skills/honeypot_spawner.py --port 3306 --monitor

echo [Watchtower] All enabled systems operational. Close this terminal to shutdown.
pause
