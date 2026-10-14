<#
.SYNOPSIS
    LabTrace SOC - Authorized Windows Hotspot Endpoint Telemetry Agent
.DESCRIPTION
    Lightweight PowerShell agent for Windows client devices connected to the
    LabTrace SOC host's Wi-Fi hotspot.
    Enforces explicit consent, withdrawal, and strict privacy boundaries.
    Collects only observable network metadata (IP, port, protocol, byte count).
#>

[CmdletBinding()]
param (
    [string]$ServerUrl = "http://192.168.137.1:3000",
    [switch]$Consent,
    [switch]$Withdraw,
    [string]$DeviceId,
    [string]$Name,
    [int]$IntervalSeconds = 10,
    [switch]$TestBurst,
    [switch]$TestScan
)

$ConfigFile = Join-Path $PSScriptRoot ".hotspot-agent-config.json"

Write-Host @"
========================================================================
🛡️  LabTrace SOC — Authorized Windows Hotspot Endpoint Agent
========================================================================
PURPOSE:
  Provides authorized, privacy-preserving network telemetry to the central
  LabTrace SOC server when connected to the host's Wi-Fi hotspot.

PRIVACY BOUNDARIES (Strictly Enforced):
  ✅ Collects: Timestamp, Destination IP, Destination Port, Protocol, Byte Counts.
  ❌ NEVER Collects: Passwords, Keystrokes, Personal Messages, Auth Tokens.
  ❌ NEVER Decrypts: TLS/HTTPS payloads or encrypted browser contents.
  ❌ NEVER Bypasses: Windows system security or administrative boundaries.

CONTROL:
  You may withdraw consent at any time:
    .\hotspot-agent.ps1 -Withdraw
========================================================================
"@ -ForegroundColor Cyan

# Handle Consent Withdrawal
if ($Withdraw) {
    $devId = $DeviceId
    if (-not $devId -and (Test-Path $ConfigFile)) {
        try {
            $savedCfg = Get-Content $ConfigFile | ConvertFrom-Json
            $devId = $savedCfg.deviceId
        } catch {}
    }
    if (-not $devId) {
        Write-Host "[!] No active enrolled device ID found to withdraw." -ForegroundColor Red
        exit 1
    }

    Write-Host "[*] Contacting server to withdraw monitoring consent for $devId..." -ForegroundColor Yellow
    $body = @{
        deviceId = $devId
        status   = "Not Monitored"
        notes    = "Withdrawn via PowerShell endpoint agent"
        reviewer = "Client User"
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri "$ServerUrl/api/network/consent" -Method POST -Body $body -ContentType "application/json" | Out-Null
        Write-Host "[+] Consent successfully WITHDRAWN on server." -ForegroundColor Green
        if (Test-Path $ConfigFile) { Remove-Item $ConfigFile -Force }
    } catch {
        Write-Host "[!] Failed to withdraw consent: $_" -ForegroundColor Red
    }
    exit 0
}

# Require Consent
if (-not $Consent) {
    $choice = Read-Host "Do you explicitly consent to authorized network metadata monitoring? [y/N]"
    if ($choice -notmatch "^(y|yes)$") {
        Write-Host "[*] Monitoring aborted by user. No data collected." -ForegroundColor Yellow
        exit 0
    }
}

# Detect local IP
$localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "192.168.137.*" } | Select-Object -First 1).IPAddress
if (-not $localIp) {
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress
}
if (-not $localIp) { $localIp = "192.168.137.2" }

$hostname = if ($Name) { $Name } else { $env:COMPUTERNAME }
$osInfo = (Get-CimInstance Win32_OperatingSystem).Caption

Write-Host "[*] Local Hotspot IP:   $localIp" -ForegroundColor Cyan
Write-Host "[*] Hostname / Device:  $hostname" -ForegroundColor Cyan
Write-Host "[*] Operating System:   $osInfo" -ForegroundColor Cyan
Write-Host "[*] Central SOC Server: $ServerUrl" -ForegroundColor Cyan

# Check existing enrollment
$apiKey = $null
$activeDevId = $null
if (Test-Path $ConfigFile) {
    try {
        $saved = Get-Content $ConfigFile | ConvertFrom-Json
        if ($saved.server -eq $ServerUrl) {
            $apiKey = $saved.apiKey
            $activeDevId = $saved.deviceId
        }
    } catch {}
}

if (-not $apiKey) {
    Write-Host "[*] Enrolling device with central SOC server..." -ForegroundColor Yellow
    $enrollBody = @{
        ip             = $localIp
        hostname       = $hostname
        deviceType     = $osInfo
        consentGranted = $true
    } | ConvertTo-Json

    try {
        $enrollRes = Invoke-RestMethod -Uri "$ServerUrl/api/network/agent/enroll" -Method POST -Body $enrollBody -ContentType "application/json"
        $apiKey = $enrollRes.apiKey
        $activeDevId = $enrollRes.deviceId
        @{
            server     = $ServerUrl
            deviceId   = $activeDevId
            apiKey     = $apiKey
            enrolledAt = (Get-Date).ToString("o")
        } | ConvertTo-Json | Set-Content $ConfigFile
        Write-Host "[+] Enrolled successfully as $activeDevId" -ForegroundColor Green
    } catch {
        Write-Host "[!] Enrollment failed: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[+] Loaded existing enrollment token for $activeDevId" -ForegroundColor Green
}

# Test Burst Injection
if ($TestBurst) {
    Write-Host "[*] Sending test connection burst for lab verification..." -ForegroundColor Yellow
    $burstEvents = @()
    $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    for ($i = 0; $i -lt 18; $i++) {
        $burstEvents += @{
            source_ip         = $localIp
            dest_ip           = "192.168.137.1"
            dest_port         = 8000 + $i
            protocol          = "TCP"
            bytes_transferred = 256
            timestamp         = $nowIso
        }
    }
    Invoke-RestMethod -Uri "$ServerUrl/api/network/agent/events" -Method POST -Body ($burstEvents | ConvertTo-Json) -Headers @{ "x-agent-key" = $apiKey } -ContentType "application/json" | Out-Null
    Write-Host "[+] Test burst transmitted." -ForegroundColor Green
}

# Periodic telemetry loop
Write-Host "[+] Starting telemetry transmission loop ($IntervalSeconds s interval). Press Ctrl+C to stop.`n" -ForegroundColor Green
$tick = 0
try {
    while ($true) {
        $tick++
        $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $sample = @(@{
            source_ip         = $localIp
            dest_ip           = "192.168.137.1"
            dest_port         = 3000
            protocol          = "TCP"
            bytes_transferred = 512
            domain            = "labtrace.local"
            timestamp         = $nowIso
        })
        try {
            $resp = Invoke-RestMethod -Uri "$ServerUrl/api/network/agent/events" -Method POST -Body ($sample | ConvertTo-Json) -Headers @{ "x-agent-key" = $apiKey } -ContentType "application/json"
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Tick $tick`: Telemetry heartbeat transmitted (512 B) -> Accepted" -ForegroundColor Gray
        } catch {
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Tick $tick`: Telemetry transmission failed: $_" -ForegroundColor Red
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
} finally {
    Write-Host "`n[*] Agent stopped." -ForegroundColor Yellow
    Write-Host "[*] To withdraw consent on the server, run: .\hotspot-agent.ps1 -Withdraw" -ForegroundColor Cyan
}
