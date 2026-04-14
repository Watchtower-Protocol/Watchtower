Write-Host "============================================" -ForegroundColor Cyan
Write-Host "      WATCHTOWER SOVEREIGN ONBOARDING       " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (Test-Path ".env.example") {
    Copy-Item ".env.example" -Destination ".env" -ErrorAction SilentlyContinue
}

Write-Host "Are you configuring a Master Hub or an Edge Sensor?" -ForegroundColor Yellow
Write-Host "1) Master Hub (Command Center & Dashboard)"
Write-Host "2) Edge Sensor (Lightweight Client Endpoint)"
Write-Host ""

$NodeType = Read-Host "Selection [1/2]"

if ($NodeType -eq "1") {
    Write-Host "`n[+] Initializing Master Hub Architecture..." -ForegroundColor Green
    
    # Generate random hex key (24 bytes)
    $Bytes = New-Object Byte[] 24
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Bytes)
    $Key = -join ($Bytes | ForEach-Object { $_.ToString("x2") })
    
    # Get Local IP
    $LocalIp = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
    if ([string]::IsNullOrWhiteSpace($LocalIp)) { $LocalIp = "127.0.0.1" }
    
    $EnvContent = Get-Content ".env"
    $EnvContent = $EnvContent -replace "generate_a_secure_random_key_here", $Key
    if ($LocalIp -ne "127.0.0.1") {
        $EnvContent = $EnvContent -replace "http://127.0.0.1:4040", "http://$LocalIp:4040"
    }
    $EnvContent | Set-Content ".env"
    
    Write-Host "[+] Cryptographic Hub Keys Vaulted natively." -ForegroundColor Green
    Write-Host "Executing Dependency Installation Phase (Python venv)..." -ForegroundColor Yellow
    
    if (-not (Test-Path ".venv")) {
        python -m venv .venv
    }
    & ".\.venv\Scripts\Activate.ps1"
    pip install -r requirements.txt --no-deps
    
    Write-Host "Installing Node.js C2 Hub Components..." -ForegroundColor Yellow
    Set-Location backend
    npm ci --ignore-scripts
    Set-Location ..
    Set-Location frontend
    npm ci --ignore-scripts
    Set-Location ..
    
    New-Item -ItemType Directory -Force -Path "data/quarantine" | Out-Null
    
    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "Hub Setup Complete!"
    Write-Host "============================================" -ForegroundColor Green
}
elseif ($NodeType -eq "2") {
    Write-Host "`n[+] Initializing Edge Sensor Deployment..." -ForegroundColor Yellow
    $HubIp = Read-Host "Enter Target Hub IP (e.g. http://10.1.1.50:4040)"
    $HubKey = Read-Host "Enter Hub API Key (Found in Hub's .env file)"
    
    $EnvContent = Get-Content ".env"
    $EnvContent = $EnvContent -replace "http://127.0.0.1:4040", $HubIp
    $EnvContent = $EnvContent -replace "generate_a_secure_random_key_here", $HubKey
    $EnvContent | Set-Content ".env"
    
    Write-Host "Executing Python Sensor Engine dependencies..." -ForegroundColor Yellow
    if (-not (Test-Path ".venv")) {
        python -m venv .venv
    }
    & ".\.venv\Scripts\Activate.ps1"
    pip install -r requirements.txt --no-deps
    
    New-Item -ItemType Directory -Force -Path "data/quarantine" | Out-Null
    
    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "Edge Setup Complete! Run .\start-agent.bat to start the Watchtower Node."
    Write-Host "============================================" -ForegroundColor Green
}
else {
    Write-Host "Invalid Selection. Exiting Setup." -ForegroundColor Red
    Exit
}
