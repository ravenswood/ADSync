<#
.SYNOPSIS
    One-time system preparation script for the AD Sync Engine.
.DESCRIPTION
    1. Creates the C:\ADSync directory structure.
    2. Registers OpenBao as a Windows Service using sc.exe.
    3. Configures necessary firewall rules.
.NOTES
    Must be run as Administrator.
    v4.4 - Added aggressive process termination to handle uncooperative service stops.
#>

$LogName = "ADSync"
$Source = "ADSyncScript"
$ParentDir = "C:\ADSync"
$SyncDirectory = "$ParentDir\Sync"
$ExportDir = "$ParentDir\Export"
$ImportDir = "$ParentDir\Import"
$BaoDataDir = "$ParentDir\OpenBao"
$BaoStorageDir = "$BaoDataDir\data"
$BaoConfigPath = "$BaoDataDir\config.hcl"
$BaoExecutable = "$BaoDataDir\bao.exe"
$OpenBaoPort = 8200
$ADPorts = @(389, 636, 3268, 3269, 445, 88)

Write-Host "--- Starting Server Initialization (v4.4) ---" -ForegroundColor Cyan

# --- 1. Event Log Setup ---
if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    try { New-EventLog -LogName $LogName -Source $Source } catch { }
}

# --- 2. Directory Creation ---
$Dirs = @($ParentDir, $SyncDirectory, $ExportDir, $ImportDir, $BaoDataDir, $BaoStorageDir)
foreach ($Dir in $Dirs) {
    if (-not (Test-Path $Dir)) {
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
    }
}

# --- 3. OpenBao Service Provisioning ---
Write-Host "Configuring OpenBao Service..." -ForegroundColor Cyan

$HclStoragePath = $BaoStorageDir.Replace('\', '/')

# Config lines (UTF8 No-BOM)
$ConfigLines = @(
    'storage "file" {',
    "  path = `"$HclStoragePath`"",
    '}',
    '',
    'listener "tcp" {',
    "  address = `"127.0.0.1:$OpenBaoPort`"",
    '  tls_disable = 1',
    '}',
    '',
    "api_addr = `"http://127.0.0.1:$OpenBaoPort`""
)

try {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($BaoConfigPath, $ConfigLines, $Utf8NoBom)
    Write-Host "[OK] Configuration file generated." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to write config file: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# Service Management Logic
if (Test-Path $BaoExecutable) {
    $ServiceName = "OpenBao"
    
    # AGGRESSIVE CLEANUP: 
    # Windows Service "Stop" often fails to kill the underlying native process if it's hung.
    Write-Host "Forcing termination of any existing bao.exe instances..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Get-Process "bao" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Wait for file handles to release
    Start-Sleep -Seconds 2

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Re-registering service for clean configuration..." -ForegroundColor Gray
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }

    # Register service
    $BinaryPath = "`"$BaoExecutable`" server -config=`"$BaoConfigPath`""
    & sc.exe create $ServiceName binpath= $BinaryPath DisplayName= "OpenBao Security Vault" start= auto | Out-Null
    
    # Optimization: Set recovery options so Windows kills the process if it fails
    & sc.exe failure $ServiceName reset= 0 actions= restart/60000 | Out-Null
    
    Write-Host "Starting OpenBao service..." -ForegroundColor Yellow
    try {
        Start-Service $ServiceName -ErrorAction Stop
        
        if ((Get-Service $ServiceName).Status -eq 'Running') {
            Write-Host "[OK] OpenBao service is running." -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[ADVICE] If it still won't start, run: Get-Process bao | Stop-Process -Force" -ForegroundColor White
    }
}

# --- 4. Network Configuration ---
foreach ($port in $ADPorts) {
    $name = "AD Sync Outbound $port"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Outbound -RemotePort $port -Protocol TCP -Action Allow | Out-Null
    }
}

Write-Host "--- Initialization Complete ---" -ForegroundColor Cyan