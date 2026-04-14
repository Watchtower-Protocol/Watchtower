@echo off
echo ============================================
echo       WATCHTOWER SOVEREIGN ONBOARDING       
echo ============================================
echo Starting PowerShell Configuration Engine...
echo Running execution bypass for local session...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0setup.ps1'"
pause
