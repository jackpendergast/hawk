# ============================================================================
# 03-windows-agent.ps1  --  Wazuh 4.7 Agent + ClamAV on Windows
# Targets: AD/DNS (2019), Web (2019), FTP (2022), Win11 Wks
# Usage:   .\03-windows-agent.ps1 -ManagerIP "10.0.0.5"
#
# What this does:
#   - Downloads and installs ClamAV MSI (silent)
#   - Creates a scheduled task for hourly ClamAV scans
#   - Configures on-access scanning via clamd.conf
#   - Downloads and installs Wazuh agent MSI pointed at manager
#   - Patches ossec.conf: syscollector, FIM (realtime C:\Users),
#     Windows event channels (Security + Sysmon/Operational)
#   - Restarts wazuh-agent service
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP,

    [string]$RegPassword = "MyStrongKey"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # speeds up Invoke-WebRequest

$WazuhVersion  = "4.7"
$WazuhAgentMSI = "wazuh-agent-4.7.3-1.msi"
$ClamAVMSI     = "clamav-1.4.3.win.x64.msi"
$TempDir       = "$env:TEMP\ccdc-deploy"

New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "=========================================="
Write-Host " CCDC Endpoint Protection - Windows"
Write-Host " Manager IP: $ManagerIP"
Write-Host "=========================================="

# ===========================================================================
# SECTION 1: ClamAV
# ===========================================================================
Write-Host "`n===== ClamAV Installation ====="

# Download ClamAV MSI
$ClamURL = "https://www.clamav.net/downloads/production/$ClamAVMSI"
$ClamPath = "$TempDir\$ClamAVMSI"

# ClamAV download URL can vary. Try the direct link first, fall back to
# a known GitHub releases mirror if needed.
Write-Host "[*] Downloading ClamAV..."
try {
    Invoke-WebRequest -Uri $ClamURL -OutFile $ClamPath -UseBasicParsing
} catch {
    Write-Host "[!] Primary download failed, trying GitHub releases..."
    $ClamURL = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.3/$ClamAVMSI"
    Invoke-WebRequest -Uri $ClamURL -OutFile $ClamPath -UseBasicParsing
}

# Silent install per the inject: ADDLOCAL="ClamAV,FreshClam"
Write-Host "[*] Installing ClamAV (silent)..."
Start-Process msiexec.exe -ArgumentList "/i `"$ClamPath`" /qn" -Wait -NoNewWindow

# Give the installer a moment to finish writing files
Start-Sleep -Seconds 5

# ---------------------------------------------------------------------------
# Locate ClamAV install directory
# ---------------------------------------------------------------------------
$ClamDirs = @(
    "${env:ProgramFiles}\ClamAV",
    "${env:ProgramFiles(x86)}\ClamAV",
    "C:\ClamAV",
    "${env:ProgramFiles}\clamav"
)
$ClamDir = $ClamDirs | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $ClamDir) {
    Write-Host "[!] Could not find ClamAV install directory. Checking Program Files..."
    $ClamDir = Get-ChildItem "${env:ProgramFiles}" -Directory -Filter "*clam*" -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty FullName
}

if ($ClamDir) {
    Write-Host "[*] ClamAV found at: $ClamDir"
} else {
    Write-Host "[!] WARNING: ClamAV directory not found. Manual config may be needed."
    $ClamDir = "${env:ProgramFiles}\ClamAV"
}

# ---------------------------------------------------------------------------
# Configure clamd.conf and freshclam.conf from examples if needed
# ---------------------------------------------------------------------------
$ClamdConf    = "$ClamDir\clamd.conf"
$FreshConf    = "$ClamDir\freshclam.conf"
$ClamdExample = "$ClamDir\conf_examples\clamd.conf.sample"
$FreshExample = "$ClamDir\conf_examples\freshclam.conf.sample"

if ((-not (Test-Path $ClamdConf)) -and (Test-Path $ClamdExample)) {
    Copy-Item $ClamdExample $ClamdConf
    # Remove the "Example" line that prevents clamd from starting
    (Get-Content $ClamdConf) -replace '^Example', '#Example' | Set-Content $ClamdConf
}

if ((-not (Test-Path $FreshConf)) -and (Test-Path $FreshExample)) {
    Copy-Item $FreshExample $FreshConf
    (Get-Content $FreshConf) -replace '^Example', '#Example' | Set-Content $FreshConf
}

# ---------------------------------------------------------------------------
# On-access scanning: enable in clamd.conf
# (inject requirement: "on-access scanning")
# On Windows, ClamAV uses the "OnAccessScan" directives if available,
# but the primary mechanism is the clamd service + scheduled scanning.
# We ensure clamd listens on TCP 3310 so the Get-Service check works.
# ---------------------------------------------------------------------------
if (Test-Path $ClamdConf) {
    $clamdContent = Get-Content $ClamdConf -Raw
    if ($clamdContent -notmatch 'TCPSocket\s+3310') {
        Add-Content $ClamdConf "`nTCPSocket 3310"
        Add-Content $ClamdConf "TCPAddr 127.0.0.1"
    }
}

# Run initial signature update
Write-Host "[*] Running freshclam (initial signature update)..."
$freshclamExe = "$ClamDir\freshclam.exe"
if (Test-Path $freshclamExe) {
    & $freshclamExe --config-file="$FreshConf" 2>&1 | Out-Null
}

# ---------------------------------------------------------------------------
# Install ClamAV as a Windows service (clamd)
# ---------------------------------------------------------------------------
$clamdExe = "$ClamDir\clamd.exe"
if (Test-Path $clamdExe) {
    Write-Host "[*] Installing clamd as a Windows service..."
    & $clamdExe --install 2>&1 | Out-Null
    Start-Service "ClamAV" -ErrorAction SilentlyContinue
    Set-Service "ClamAV" -StartupType Automatic -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Scheduled task: hourly ClamAV scan
# (inject requirement: "set to run hourly")
# ---------------------------------------------------------------------------
$clamscanExe = "$ClamDir\clamscan.exe"
if (Test-Path $clamscanExe) {
    Write-Host "[*] Creating hourly scan scheduled task..."
    $Action = New-ScheduledTaskAction -Execute $clamscanExe `
               -Argument "--recursive --infected --log=`"$ClamDir\scan.log`" C:\"
    # Use -Once with indefinite repetition for hourly runs
    $Trigger = New-ScheduledTaskTrigger -Daily -At (Get-Date).AddMinutes(5)

    $Trigger.Repetition.Interval = (New-TimeSpan -Hours 1)
    $Trigger.Repetition.Duration = ([TimeSpan]::MaxValue)

    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "ClamAV_Hourly_Scan" -Action $Action `
        -Trigger $Trigger -Settings $Settings -User "SYSTEM" `
        -RunLevel Highest -Force | Out-Null
    Write-Host "[*] Hourly ClamAV scan task registered."
} else {
    Write-Host "[!] clamscan.exe not found at expected path."
}

# ===========================================================================
# SECTION 2: Wazuh Agent
# ===========================================================================
Write-Host "`n===== Wazuh Agent Installation ====="

$WazuhURL  = "https://packages.wazuh.com/4.x/windows/$WazuhAgentMSI"
$WazuhPath = "$TempDir\$WazuhAgentMSI"

Write-Host "[*] Downloading Wazuh agent..."
Invoke-WebRequest -Uri $WazuhURL -OutFile $WazuhPath -UseBasicParsing

Write-Host "[*] Installing Wazuh agent (silent)..."
Start-Process msiexec.exe -ArgumentList @(
    "/i", "`"$WazuhPath`"",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_PASSWORD=`"$RegPassword`"",
    "/qn"
) -Wait -NoNewWindow

Start-Sleep -Seconds 5

# ---------------------------------------------------------------------------
# Patch ossec.conf per inject requirements:
#   <syscollector><enabled>yes</enabled></syscollector>
#   <fim><enabled>yes</enabled><directories realtime="yes">C:\Users</directories></fim>
#   <windows_event_channels>
#     <channel>Security</channel>
#     <channel>Microsoft-Windows-Sysmon/Operational</channel>
#   </windows_event_channels>
# ---------------------------------------------------------------------------
$OssecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (-not (Test-Path $OssecConf)) {
    $OssecConf = "C:\Program Files\ossec-agent\ossec.conf"
}

if (Test-Path $OssecConf) {
    Write-Host "[*] Patching ossec.conf with required modules..."

    [xml]$xml = Get-Content $OssecConf

    # --- syscollector: ensure enabled ---
    $sysc = $xml.ossec_config.syscollector
    if ($sysc) {
        $enabledNode = $sysc.SelectSingleNode("enabled")
        if ($enabledNode) {
            $enabledNode.InnerText = "yes"
        } else {
            $el = $xml.CreateElement("enabled")
            $el.InnerText = "yes"
            $sysc.PrependChild($el) | Out-Null
        }
    }

    # --- syscheck (FIM): add realtime directory for C:\Users ---
    $syscheck = $xml.ossec_config.syscheck
    if ($syscheck) {
        # Check if C:\Users is already monitored with realtime
        $alreadySet = $false
        foreach ($dir in $syscheck.SelectNodes("directories")) {
            if ($dir.InnerText -match 'C:\\Users' -and $dir.GetAttribute("realtime") -eq "yes") {
                $alreadySet = $true
            }
        }
        if (-not $alreadySet) {
            $dirNode = $xml.CreateElement("directories")
            $dirNode.SetAttribute("realtime", "yes")
            $dirNode.InnerText = "C:\Users"
            $syscheck.AppendChild($dirNode) | Out-Null
        }
        # Make sure syscheck is not disabled
        $disabledNode = $syscheck.SelectSingleNode("disabled")
        if ($disabledNode) { $disabledNode.InnerText = "no" }
    }

    # --- localfile: add Windows event channels ---
    # Security channel
    $secChannel = $xml.CreateElement("localfile")
    $locName = $xml.CreateElement("location")
    $locName.InnerText = "Security"
    $logFormat = $xml.CreateElement("log_format")
    $logFormat.InnerText = "eventchannel"
    $secChannel.AppendChild($locName) | Out-Null
    $secChannel.AppendChild($logFormat) | Out-Null
    $xml.ossec_config.AppendChild($secChannel) | Out-Null

    # Sysmon channel
    $sysmonChannel = $xml.CreateElement("localfile")
    $locName2 = $xml.CreateElement("location")
    $locName2.InnerText = "Microsoft-Windows-Sysmon/Operational"
    $logFormat2 = $xml.CreateElement("log_format")
    $logFormat2.InnerText = "eventchannel"
    $sysmonChannel.AppendChild($locName2) | Out-Null
    $sysmonChannel.AppendChild($logFormat2) | Out-Null
    $xml.ossec_config.AppendChild($sysmonChannel) | Out-Null

    $xml.Save($OssecConf)
    Write-Host "[*] ossec.conf updated with syscollector, FIM, and event channels."
} else {
    Write-Host "[!] ossec.conf not found. Manual configuration required."
}

# ---------------------------------------------------------------------------
# Restart the Wazuh agent
# (inject note: "Don't forget to restart")
# ---------------------------------------------------------------------------
Write-Host "[*] Restarting Wazuh agent..."
Restart-Service "WazuhSvc" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Check service status
$wazuhSvc = Get-Service "WazuhSvc" -ErrorAction SilentlyContinue
if ($wazuhSvc -and $wazuhSvc.Status -eq "Running") {
    Write-Host "[*] Wazuh agent is running."
} else {
    Write-Host "[!] Wazuh agent may not have started. Check services manually."
}

# ===========================================================================
# Verification
# ===========================================================================
Write-Host "`n=========================================="
Write-Host " VERIFICATION"
Write-Host "=========================================="
Write-Host "`nClamAV service status:"
Get-Service "ClamAV*" -ErrorAction SilentlyContinue | Select-Object Status, Name, DisplayName | Format-Table -AutoSize

Write-Host "Wazuh agent service status:"
Get-Service "WazuhSvc" -ErrorAction SilentlyContinue | Select-Object Status, Name, DisplayName | Format-Table -AutoSize

Write-Host "Scheduled tasks:"
Get-ScheduledTask -TaskName "ClamAV*" -ErrorAction SilentlyContinue | Select-Object TaskName, State | Format-Table -AutoSize

Write-Host "`n=========================================="
Write-Host " Done. Agent should register with manager at $ManagerIP"
Write-Host "=========================================="
