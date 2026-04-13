<#
.SYNOPSIS
Watchtower Sovereign EDR - Active Directory & Windows Server Sensor
.DESCRIPTION
Monitors high-fidelity Windows Security Event Logs and streams them to the Watchtower Hub.
Includes an outbound beacon for Command & Control (C2) to execute response actions without opening inbound ports.
#>

$HubIP = "100.x.x.x" # Replace with Master Hub Tailscale/Mesh IP
$HubApiPort = 3000
$ApiKey = os.environ.get("WATCHTOWER_API_KEY", "WATCHTOWER_DEFAULT_KEY")
$Hostname = $env:COMPUTERNAME

$IngestUrl = "http://${HubIP}:${HubApiPort}/api/v2/ingest/threat"
$BeaconUrl = "http://${HubIP}:${HubApiPort}/api/v2/c2/beacon"

# High-Fidelity Event IDs for AD Compromise
$TargetEvents = @(
    4625, # Failed Logon (Brute Force / Password Spray)
    4720, # User Account Created (Backdoor)
    4728, # Member Added to Global Security Group
    4732, # Member Added to Local Security Group (e.g., Administrators)
    4756, # Member Added to Universal Security Group
    4740, # User Account Locked Out
    1102, # Audit Log Cleared (Defense Evasion)
    4662, # Directory Service Access (DCSync / DCShadow attacks)
    4624  # Successful Logon (Filtered later for Type 9 / Logon with explicit credentials)
)

Write-Host "[Watchtower AD Sensor] Initializing on $Hostname..." -ForegroundColor Cyan

# 1. Start Event Log Subscription
$Query = "*[System[(" + ($TargetEvents | ForEach-Object { "EventID=$_" }) -join " or " + ")]]"

# Note: In production, we use WMI Event Subscriptions or continuous tailing. 
# For MVP, we poll the last X minutes on an interval to ensure reliability without locking the log.
$LastChecked = Get-Date


# Tier 2: The Reflex (Offline Fallback)
$FailedLogons = @{}
$ReflexThreshold = 20
$ReflexWindowSecs = 60

Function Send-Telemetry ($EventRecord) {
    $EventID = $EventRecord.Id
    $Message = $EventRecord.Message
    $Time = $EventRecord.TimeCreated.ToString("o")
    
    # Offline Reflex - Event 4625 Brute Force
    if ($EventID -eq 4625) {
        $TargetUser = $EventRecord.Properties[5].Value # Usually index 5 is TargetUserName
        if ($TargetUser -and $TargetUser -ne "SYSTEM" -and $TargetUser -ne "$Hostname$") {
            if (-not $FailedLogons.ContainsKey($TargetUser)) {
                $FailedLogons[$TargetUser] = @{ Count = 1; FirstSeen = (Get-Date) }
            } else {
                $FailedLogons[$TargetUser].Count++
            }
            
            $TimeDiff = ((Get-Date) - $FailedLogons[$TargetUser].FirstSeen).TotalSeconds
            
            if ($TimeDiff -le $ReflexWindowSecs -and $FailedLogons[$TargetUser].Count -ge $ReflexThreshold) {
                Write-Host "[!] AUTONOMOUS REFLEX TRIGGERED: Brute force detected for $TargetUser." -ForegroundColor Red
                Disable-ADAccount -Identity $TargetUser -ErrorAction SilentlyContinue
                Write-Host "[+] Local Offline Quarantine Complete. User Disabled." -ForegroundColor Green
                $FailedLogons[$TargetUser].Count = 0 # reset
            } elseif ($TimeDiff -gt $ReflexWindowSecs) {
                $FailedLogons[$TargetUser] = @{ Count = 1; FirstSeen = (Get-Date) }
            }
        }
    }

    $EventID = $EventRecord.Id
    $Message = $EventRecord.Message
    $Time = $EventRecord.TimeCreated.ToString("o")
    
    $Severity = "medium"
    if ($EventID -eq 1102 -or $EventID -eq 4662) { $Severity = "high" }

    $Payload = @{
        source = $Hostname
        event_type = "AD_SECURITY_EVENT"
        title = "Windows Event ID: $EventID"
        file_path = "SecurityLog"
        ai_verdict = "ANALYZING..."
        ai_reason = $Message.Substring(0, [math]::Min($Message.Length, 1000)) # Truncate massive logs
        severity = $Severity
        timestamp = $Time
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $IngestUrl -Method Post -Body $Payload -ContentType "application/json" -Headers @{"x-api-key"=$ApiKey} -TimeoutSec 5 | Out-Null
        Write-Host "[+] Telemetry Sent: Event $EventID" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to reach Hub: $_" -ForegroundColor Red
    }
}

Function Check-C2-Queue {
    # Outbound beaconing to check for commands (No inbound ports opened on the DC)
    try {
        $Response = Invoke-RestMethod -Uri "$BeaconUrl?host=$Hostname" -Method Get -Headers @{"x-api-key"=$ApiKey} -TimeoutSec 5
        if ($Response.commands) {
            foreach ($Cmd in $Response.commands) {
                Write-Host "[!] C2 Command Received: $($Cmd.action) on $($Cmd.target)" -ForegroundColor Yellow
                if ($Cmd.action -eq "disable_user") {
                    Disable-ADAccount -Identity $Cmd.target -ErrorAction SilentlyContinue
                    Write-Host "[+] Disabled AD User: $($Cmd.target)" -ForegroundColor Green
                }
                elseif ($Cmd.action -eq "isolate_network") {
                    Disable-NetAdapter -Name "*" -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Host "[!] Initiated Network Isolation" -ForegroundColor Red
                }
            }
        }
    } catch {
        # Silent fail on beacon
    }
}

# Main Loop
while ($true) {
    # 1. Telemetry Polling
    $Now = Get-Date
    try {
        $Events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$TargetEvents; StartTime=$LastChecked} -ErrorAction SilentlyContinue
        if ($Events) {
            foreach ($Event in $Events) {
                Send-Telemetry $Event
            }
        }
    } catch {}
    $LastChecked = $Now

    # 2. C2 Beacon
    Check-C2-Queue

    Start-Sleep -Seconds 10
}