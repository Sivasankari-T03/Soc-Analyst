<#
.SYNOPSIS
    LabTrace SOC Authorized Windows Endpoint Agent
.DESCRIPTION
    Lightweight, opt-in endpoint agent for authorized Windows devices in a cybersecurity lab.
    Continuously monitors Windows Security Event Log for logon metadata (Event IDs 4624 & 4625)
    and delivers events securely to the central LabTrace SOC server with local buffering,
    automatic retry, deduplication keys, and explicit privacy guardrails.

.PRIVACY GUARANTEE:
    This agent strictly collects logon metadata: timestamp, account alias, computer name, IP, and logon type.
    It NEVER collects passwords, keystrokes, personal files, messages, or browser history.
    Authorized for lab monitoring only.

.PARAMETER ServerUrl
    LabTrace central server ingest endpoint (default: http://localhost:3000/api/ingest)
.PARAMETER ApiKey
    API Key for authentication with the central server
.PARAMETER PollIntervalSeconds
    Interval in seconds between event checks (default: 5)
.PARAMETER Mode
    'Live' to monitor actual Windows Security Log (requires Admin/Event Log Readers),
    or 'Test' to run safe simulated authorized logon events.
.PARAMETER BufferFile
    Path to local queue file for persistent buffering during network disconnects
.PARAMETER AcceptConsent
    Suppresses the interactive consent confirmation prompt
#>

param(
    [string]$ServerUrl = "http://localhost:3000/api/ingest",
    [string]$ApiKey = "labtrace-secret-key",
    [int]$PollIntervalSeconds = 5,
    [ValidateSet("Live", "Test")]
    [string]$Mode = "Live",
    [string]$BufferFile = "$PSScriptRoot\.labtrace-buffer.json",
    [switch]$AcceptConsent
)

$HostName = [System.Net.Dns]::GetHostName()
$DeviceId = "WIN-$HostName"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  LabTrace SOC Authorized Windows Endpoint Agent                    " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  Host Device:       $HostName ($DeviceId)                          " -ForegroundColor Gray
Write-Host "  Target Server:     $ServerUrl                                     " -ForegroundColor Yellow
Write-Host "  Collection Mode:   $Mode                                          " -ForegroundColor Green
Write-Host "  Buffer Location:   $BufferFile                                    " -ForegroundColor Gray
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[PRIVACY BOUNDARIES]" -ForegroundColor White
Write-Host "  - Only Event IDs 4624 (Success) and 4625 (Failure) logon metadata collected." -ForegroundColor Gray
Write-Host "  - Never monitors passwords, keystrokes, browsing contents, or private files." -ForegroundColor Gray
Write-Host "  - Machine accounts (*$) and OS background services filtered locally." -ForegroundColor Gray
Write-Host ""

# Explicit Consent Verification
if (-not $AcceptConsent) {
    Write-Host "AUTHORIZATION REQUIRED:" -ForegroundColor Yellow
    Write-Host "Do you have explicit permission to monitor this device for the LabTrace SOC lab?" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'YES' to proceed with endpoint monitoring"
    if ($confirm.Trim().ToUpper() -ne "YES") {
        Write-Host "Operation cancelled. Agent exiting without collecting data." -ForegroundColor Red
        exit 0
    }
}

# Auto-Enrollment Heartbeat: Registers device with central server
function Send-EnrollmentHeartbeat {
    $enrollUrl = $ServerUrl.Replace("/api/ingest", "/api/agents/enroll").Replace("/ingest", "/api/agents/enroll")
    try {
        $enrollBody = @{
            device_name = $HostName
            hostname    = $HostName
            api_key     = $ApiKey
            os_info     = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Caption)
        } | ConvertTo-Json
        
        $null = Invoke-RestMethod -Uri $enrollUrl -Method Post -Body $enrollBody -ContentType "application/json" -TimeoutSec 3 -ErrorAction SilentlyContinue
        Write-Host "[OK] Enrolled with Central SOC Server as: $DeviceId" -ForegroundColor Green
    } catch {
        # Server might use pre-configured key, proceed gracefully
    }
}

Send-EnrollmentHeartbeat

# Privilege check if Live mode
if ($Mode -eq "Live") {
    try {
        $testCheck = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop
        Write-Host "[OK] Windows Security Log access verified." -ForegroundColor Green
    } catch {
        Write-Host ""
        Write-Host "[!] Administrative Privileges Required for Live Windows Event Log Access:" -ForegroundColor Yellow
        Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "    -> Open PowerShell as Administrator to collect real Security events." -ForegroundColor Cyan
        Write-Host "    -> Switching to 'Test' mode for safe local simulation." -ForegroundColor Magenta
        Write-Host ""
        $Mode = "Test"
    }
}

# Load buffered events from disk if any exist from previous disconnects
$bufferQueue = [System.Collections.Generic.List[PSCustomObject]]::new()
if (Test-Path $BufferFile) {
    try {
        $cachedJson = Get-Content -Path $BufferFile -Raw -ErrorAction SilentlyContinue
        if ($cachedJson) {
            $cachedItems = $cachedJson | ConvertFrom-Json
            if ($cachedItems) {
                foreach ($ci in $cachedItems) { $bufferQueue.Add($ci) }
                Write-Host "[Buffer] Restored $($bufferQueue.Count) queued event(s) from local buffer file." -ForegroundColor DarkCyan
            }
        }
    } catch {}
}

# Save buffer to disk on failures
function Save-BufferQueue {
    try {
        if ($bufferQueue.Count -gt 0) {
            $bufferQueue | ConvertTo-Json -Depth 4 | Set-Content -Path $BufferFile -Force -ErrorAction SilentlyContinue
        } else {
            if (Test-Path $BufferFile) { Remove-Item -Path $BufferFile -Force -ErrorAction SilentlyContinue }
        }
    } catch {}
}

# Transmission Function with Retry
function Send-EventsWithRetry {
    param([array]$EventsToSend)

    if (-not $EventsToSend -or $EventsToSend.Count -eq 0) { return }

    # Add new events to queue
    foreach ($ev in $EventsToSend) {
        $bufferQueue.Add($ev)
    }

    $headers = @{
        "Content-Type" = "application/json"
        "x-api-key"    = $ApiKey
        "x-agent-id"   = $DeviceId
    }

    try {
        $batch = @($bufferQueue)
        $jsonPayload = $batch | ConvertTo-Json -Depth 4
        
        $response = Invoke-RestMethod -Uri $ServerUrl -Method Post -Body $jsonPayload -Headers $headers -TimeoutSec 6 -ErrorAction Stop

        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Dispatched $($batch.Count) event(s) to Central Server (Accepted: $($response.accepted), Duplicates: $($response.duplicates))" -ForegroundColor Green
        
        # Successfully sent: clear in-memory and disk buffer
        $bufferQueue.Clear()
        Save-BufferQueue
    } catch {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Server unreachable at $ServerUrl : $($_.Exception.Message)" -ForegroundColor DarkYellow
        Write-Host "    --> Safely buffered $($bufferQueue.Count) events locally in $BufferFile (will retry on next tick)." -ForegroundColor Gray
        Save-BufferQueue
    }
}

$lastTime = (Get-Date).AddMinutes(-5)
$testCounter = 1000

Write-Host "`n[Agent Active] Monitoring authorized authentication activity every $PollIntervalSeconds seconds... (Ctrl+C to stop)`n" -ForegroundColor Cyan

while ($true) {
    $rows = @()

    if ($Mode -eq "Live") {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4624, 4625
                StartTime = $lastTime
            } -ErrorAction SilentlyContinue

            $lastTime = Get-Date

            if ($events) {
                $rows = $events | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $data = @{}
                    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                    
                    $username = $data.TargetUserName
                    # Privacy & Noise Filter: ignore system services & machine accounts
                    if ($username -and ($username -notlike '*$') -and ($username -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+)$')) {
                        $ip = $data.IpAddress
                        if (-not $ip -or $ip -eq "-" -or $ip -eq "::1") { $ip = "127.0.0.1" }
                        
                        # Generate deterministic deduplication ID
                        $dedupKey = "WIN-$HostName-$($_.RecordId)-$($_.TimeCreated.Ticks)"

                        [PSCustomObject]@{
                            event_id        = $dedupKey
                            timestamp       = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
                            account         = $username
                            computer        = $HostName
                            ip              = $ip
                            event           = if ($_.Id -eq 4625) { 'FAILED' } else { 'SUCCESS' }
                            logon_type      = $data.LogonType
                            department_case = "LIVE-ENDPOINT"
                            agent_id        = $DeviceId
                            data_source     = "live"
                        }
                    }
                }
            }
        } catch {
            Write-Host "[!] Event poll exception: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        # Test Mode generator: Generates Windows logon attempts with deterministic IDs
        $testCounter++
        $rand = Get-Random -Minimum 1 -Maximum 100
        $accounts = @("a.kumar", "r.priya", "guest_lab", "m.arun", "t.nisha", "svc.backup", "admin.lab")
        $selectedUser = $accounts | Get-Random
        
        $isFail = ($rand -lt 30)
        $ip = if ($rand -lt 15) { "185.220.101.4" } else { "10.20.1.$((Get-Random -Minimum 10 -Maximum 250))" }
        $nowStr = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $dedupKey = "WIN-TEST-$HostName-$testCounter"

        $rows = @(
            [PSCustomObject]@{
                event_id        = $dedupKey
                timestamp       = $nowStr
                account         = $selectedUser
                computer        = $HostName
                ip              = $ip
                event           = if ($isFail) { 'FAILED' } else { 'SUCCESS' }
                logon_type      = if ($rand -lt 20) { "10" } else { "2" }
                department_case = "SIMULATED-AGENT"
                agent_id        = $DeviceId
                data_source     = "simulated"
            }
        )
    }

    if ($rows -and $rows.Count -gt 0) {
        Send-EventsWithRetry -EventsToSend $rows
    } elseif ($bufferQueue.Count -gt 0) {
        # Retry sending buffered events if previously failed
        Send-EventsWithRetry -EventsToSend @()
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
