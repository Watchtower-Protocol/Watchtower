@echo off
echo Starting Watchtower Agent (Edge Mode)...
if not exist .venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment not found. Please run setup.bat first.
    pause
    exit /b
)
call .venv\Scripts\activate.bat
python core/watchtower_ai_bridge.py
pause
