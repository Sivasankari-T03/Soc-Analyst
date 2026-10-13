<#
.SYNOPSIS
    LabTrace Windows Event Collector (Event IDs 4624 / 4625)
.DESCRIPTION
    Continuously monitors the local Windows Security log or Lab Domain Controller
    for logon events and forwards them to the LabTrace Ingest Server.
.PARAMETER ServerUrl
    LabTrace server ingest endpoint (default: http://localhost:3000/api/ingest)
.PARAMETER ApiKey
    API Key header for authentication
.PARAMETER PollIntervalSeconds
    Seconds to sleep between event polls (default: 5)
.PARAMETER Mode
    'Live' to query real Windows Security log, or 'Test' to generate simulated Windows logons
#>

param(
    [string]$ServerUrl = "http://localhost:3000/api/ingest",
    [string]$ApiKey = "labtrace-secret-key",
    [int]$PollIntervalSeconds = 5,
    [ValidateSet("Live", "Test")]
    [string]$Mode = "Live"
)

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  LabTrace SOC - Windows Event Log Collector           " -ForegroundColor Cyan
Write-Host "  Target Ingest Server: $ServerUrl                     " -ForegroundColor Gray
Write-Host "  Mode:                 $Mode                          " -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Cyan

# Test Security log access if in Live mode
if ($Mode -eq "Live") {
    try {
        $testCheck = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop
        Write-Host "[OK] Security log access verified (Administrator / Event Log Readers)." -ForegroundColor Green
    } catch {
        Write-Host ""
        Write-Host "[!] Note: Reading the Windows Security log requires either Administrator privileges" -ForegroundColor Yellow
        Write-Host "    or membership in the 'Event Log Readers' local group." -ForegroundColor Yellow
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "--> To run live collection: Open PowerShell as Administrator." -ForegroundColor Cyan
        Write-Host "--> Switching automatically to Test Mode so you can see live events immediately!" -ForegroundColor Magenta
        Write-Host ""
        $Mode = "Test"
    }
}

$lastTime = (Get-Date).AddMinutes(-5)
$testCounter = 1000

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
                    if ($username -and ($username -notlike '*$') -and ($username -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON)$')) {
                        $ip = $data.IpAddress
                        if (-not $ip -or $ip -eq "-" -or $ip -eq "::1") { $ip = "127.0.0.1" }
                        
                        [PSCustomObject]@{
                            event_id        = "WIN-$($_.RecordId)"
                            timestamp       = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
                            account         = $username
                            computer        = $_.MachineName
                            ip              = $ip
                            event           = if ($_.Id -eq 4625) { 'FAILED' } else { 'SUCCESS' }
                            logon_type      = $data.LogonType
                            department_case = "LIVE-WIN"
                        }
                    }
                }
            }
        } catch {
            Write-Host "[!] Poll error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        # Test Mode generator: Generates Windows-structured logon attempts
        $testCounter++
        $rand = Get-Random -Minimum 1 -Maximum 100
        $pcs = @("PC-01", "PC-02", "PC-03", "PC-04", "PC-05", "PC-08", "PC-12")
        $accounts = @("a.kumar", "r.priya", "guest_lab", "m.arun", "t.nisha", "svc.backup", "admin.lab")
        $selectedPc = $pcs | Get-Random
        $selectedUser = $accounts | Get-Random
        
        $isFail = ($rand -lt 35)
        $ip = if ($rand -lt 15) { "185.220.101.4" } elseif ($rand -lt 30) { "45.155.205.9" } else { "10.20.4.$((Get-Random -Minimum 10 -Maximum 250))" }
        
        $nowStr = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $rows = @(
            [PSCustomObject]@{
                event_id        = "WIN-$testCounter"
                timestamp       = $nowStr
                account         = $selectedUser
                computer        = $selectedPc
                ip              = $ip
                event           = if ($isFail) { 'FAILED' } else { 'SUCCESS' }
                logon_type      = if ($rand -lt 20) { "10" } else { "2" }
                department_case = "TEST-STREAM"
            }
        )
    }

    if ($rows -and $rows.Count -gt 0) {
        try {
            $jsonBody = $rows | ConvertTo-Json -Depth 3
            $headers = @{
                "Content-Type" = "application/json"
                "x-api-key"    = $ApiKey
            }
            $response = Invoke-RestMethod -Uri $ServerUrl -Method Post -Body $jsonBody -Headers $headers -TimeoutSec 5
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Forwarded $($rows.Count) event(s) to Ingest Server (Accepted: $($response.accepted))" -ForegroundColor Green
        } catch {
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Ingest server unreachable at $ServerUrl : $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
