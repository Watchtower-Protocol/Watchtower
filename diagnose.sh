#!/bin/bash
echo -e "\033[1;36m============================================\033[0m"
echo -e "\033[1;36m      WATCHTOWER DIAGNOSTIC ENGINE          \033[0m"
echo -e "\033[1;36m============================================\033[0m"
echo ""

if [ ! -f ".env" ]; then
    echo -e "\033[1;31m[FAIL]\033[0m .env file is missing. Run ./setup.sh"
    exit 1
else
    echo -e "\033[1;32m[PASS]\033[0m .env file found."
    source .env
fi

if lsof -i:$WATCHTOWER_API_PORT -t >/dev/null 2>&1; then
    echo -e "\033[1;32m[PASS]\033[0m API Gateway is running on port $WATCHTOWER_API_PORT"
else
    echo -e "\033[1;31m[FAIL]\033[0m API Gateway is OFFLINE (Port $WATCHTOWER_API_PORT is closed)"
fi

if lsof -i:$WATCHTOWER_UI_PORT -t >/dev/null 2>&1; then
    echo -e "\033[1;32m[PASS]\033[0m UI Dashboard is running on port $WATCHTOWER_UI_PORT"
else
    echo -e "\033[1;31m[FAIL]\033[0m UI Dashboard is OFFLINE (Port $WATCHTOWER_UI_PORT is closed)"
fi

echo "[*] Pinging Sovereign AI Engine at $AI_INFERENCE_URL..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$AI_INFERENCE_URL" --max-time 3)
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "405" || "$HTTP_CODE" == "200" ]]; then
    echo -e "\033[1;32m[PASS]\033[0m Local AI Engine is reachable."
else
    echo -e "\033[1;31m[FAIL]\033[0m Local AI Engine is UNREACHABLE (HTTP $HTTP_CODE). Check LM Studio/Ollama."
fi

if [ -f "data/watchtower_db.json" ]; then
    echo -e "\033[1;32m[PASS]\033[0m Local Asset & Threat Database exists."
else
    echo -e "\033[1;33m[WARN]\033[0m Local Database not found. (Normal if first boot)."
fi
echo ""
echo "Diagnostic complete."

