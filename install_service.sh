#!/bin/bash
# Generates a LaunchDaemon (macOS) or Systemd (Linux) service for Watchtower
DIR=$(pwd)
USER=$(whoami)

TARGET_SCRIPT="start.sh"
SERVICE_NAME="watchtower"
DESC="Watchtower Sovereign EDR Hub"

if [ "$1" == "--agent" ]; then
    TARGET_SCRIPT="start-agent.sh"
    SERVICE_NAME="watchtower-agent"
    DESC="Watchtower Sentinel Edge Node"
fi

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[*] Generating macOS LaunchDaemon for $SERVICE_NAME..."
    mkdir -p "$HOME/Library/LaunchAgents"
    PLIST="$HOME/Library/LaunchAgents/com.vertex.$SERVICE_NAME.plist"
    cat << EOF2 > "$PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vertex.$SERVICE_NAME</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DIR/$TARGET_SCRIPT</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$DIR/data/${SERVICE_NAME}.log</string>
    <key>StandardErrorPath</key>
    <string>$DIR/data/${SERVICE_NAME}_error.log</string>
</dict>
</plist>
EOF2
    launchctl load "$PLIST" 2>/dev/null || echo "Run 'launchctl load $PLIST' to start."
    echo -e "\033[1;32m[+] macOS $SERVICE_NAME Service Installed.\033[0m"

elif grep -q "Ubuntu\|Debian" /etc/os-release > /dev/null 2>&1 || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[*] Generating Linux Systemd Service for $SERVICE_NAME..."
    SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
    sudo bash -c "cat << EOF2 > $SERVICE
[Unit]
Description=$DESC
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$DIR
ExecStart=$DIR/$TARGET_SCRIPT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF2"
    sudo systemctl daemon-reload
    sudo systemctl enable $SERVICE_NAME
    sudo systemctl start $SERVICE_NAME
    echo -e "\033[1;32m[+] Linux Systemd $SERVICE_NAME Service Installed.\033[0m"
else
    echo "Unsupported OS for auto-service generation."
fi
