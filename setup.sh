#!/bin/bash
clear
echo -e "\033[1;36m============================================\033[0m"
echo -e "\033[1;36m      WATCHTOWER SOVEREIGN ONBOARDING       \033[0m"
echo -e "\033[1;36m============================================\033[0m"
echo ""

cp .env.example .env 2>/dev/null || true

echo -e "\033[1;33mAre you configuring a Master Hub or an Edge Sensor?\033[0m"
echo "1) Master Hub (Command Center & Dashboard)"
echo "2) Edge Sensor (Lightweight Client Endpoint)"
echo ""
read -p "Selection [1/2]: " NODE_TYPE

if [ "$NODE_TYPE" == "1" ]; then
    echo ""
    echo -e "\033[1;32m[+] Initializing Master Hub Architecture...\033[0m"
    KEY=$(openssl rand -hex 24)
    LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    
    sed -i.bak "s/generate_a_secure_random_key_here/$KEY/g" .env
    if [ "$LOCAL_IP" != "127.0.0.1" ] && [ -n "$LOCAL_IP" ]; then
        sed -i.bak "s|http://127.0.0.1:4040|http://$LOCAL_IP:4040|g" .env
    fi
    rm -f .env.bak
    
    echo -e "\033[1;32m[+] Cryptographic Hub Keys Vaulted natively.\033[0m"
    echo -e "\033[1;33mExecuting Dependency Installation Phase...\033[0m"
    chmod +x install.sh
    ./install.sh --hub
    
    echo ""
    echo -e "\033[1;32m============================================\033[0m"
    echo -e "Hub Setup Complete! Run \033[1;36m./start.sh\033[0m and visit localhost:8080."
    echo -e "\033[1;32m============================================\033[0m"

elif [ "$NODE_TYPE" == "2" ]; then
    echo ""
    echo -e "\033[1;33m[+] Initializing Edge Sensor Deployment...\033[0m"
    read -p "Enter Target Hub IP (e.g. http://10.1.1.50:4040): " HUB_IP
    read -p "Enter Hub API Key (Found in Hub's .env file): " HUB_KEY
    
    sed -i.bak "s|http://127.0.0.1:4040|$HUB_IP|g" .env
    sed -i.bak "s/generate_a_secure_random_key_here/$HUB_KEY/g" .env
    rm -f .env.bak
    
    echo -e "\033[1;33mExecuting Python Sensor Engine dependencies...\033[0m"
    chmod +x install.sh
    ./install.sh --edge
    
    echo ""
    echo -e "\033[1;32m============================================\033[0m"
    echo -e "Edge Setup Complete! Run \033[1;36m./start-agent.sh\033[0m"
    echo -e "\033[1;32m============================================\033[0m"
else
    echo -e "\033[1;31mInvalid Selection. Exiting Setup.\033[0m"
    exit 1
fi

