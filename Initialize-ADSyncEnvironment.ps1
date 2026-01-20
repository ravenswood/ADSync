<#
.SYNOPSIS
    Unified System Preparation & Vault Initialization Script.
    Name: Initialize-ADSyncEnvironment.ps1
    Version: 5.2
.DESCRIPTION
    A master script to prepare the AD Sync environment from scratch:
    1. Creates the C:\ADSync directory structure.
    2. Provisions the OpenBao config.hcl and registers the Windows Service.
    3. Configures all required Firewall rules (AD, Vault, SSH).
    4. Performs first-time cryptographic initialization (Generating vault_keys.json).
.NOTES
    v5.2 Update: Added SSH Port 22 firewall rule and enhanced force-kill logic for bao.exe.
#>

$LogName = "ADSync"
$Source = "ADSyncScript"
$ParentDir = "C:\ADSync"
$Paths = @(
    "$ParentDir\OpenBao",
    "$ParentDir\OpenBao\data",
    "$ParentDir\Sync",
    "$ParentDir\Export",
    "$ParentDir\Import",
    "$ParentDir\Logs",
    "$ParentDir\Users",
    "$ParentDir\Bin"
)

$BaoExe        = "$ParentDir\OpenBao\bao.exe"
$BaoConfigPath = "$ParentDir\OpenBao\config.hcl"
$KeysFile      = "$ParentDir\OpenBao\vault_keys.json"
$VaultAddr     = "http://127.0.0.1:8200"

Write-Host "--- Starting Master Initialization (v5.2) ---" -ForegroundColor Cyan

# --- 1. Event Log Setup ---
if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    try { New-EventLog -LogName $LogName -Source $Source } catch { }
}

# --- 2. Directory Creation ---
foreach ($Dir in $Paths) {
    if (-not (Test-Path $Dir)) {
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Created directory: $Dir" -ForegroundColor Gray
    }
}

# --- 3. OpenBao Configuration & Service Management ---
$HclStoragePath = ("$ParentDir\OpenBao\data").Replace('\', '/')
$ConfigLines = @(
    'storage "file" {',
    "  path = `"$HclStoragePath`"",
    '}',
    '',
    'listener "tcp" {',
    '  address = "127.0.0.1:8200"',
    '  tls_disable = 1',
    '}',
    '',
    'api_addr = "http://127.0.0.1:8200"'
)

try {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($BaoConfigPath, $ConfigLines, $Utf8NoBom)
} catch {
    Write-Host "[ERROR] Failed to write config.hcl" -ForegroundColor Red
    return
}

if (Test-Path $BaoExe) {
    $ServiceName = "OpenBao"
    Write-Host ">>> Managing OpenBao Service Lifecycle..." -ForegroundColor Gray
    
    # Forceful Termination Logic
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    
    # Aggressive process cleanup for any lingering bao instances
    $BaoProcs = Get-Process "bao" -ErrorAction SilentlyContinue
    if ($BaoProcs) {
        Write-Host ">>> Force-killing all lingering bao.exe processes..." -ForegroundColor Yellow
        $BaoProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Remove existing service definition to ensure binary path updates
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Register Service
    $BinaryPath = "`"$BaoExe`" server -config=`"$BaoConfigPath`""
    & sc.exe create $ServiceName binpath= $BinaryPath DisplayName= "OpenBao Security Vault" start= auto | Out-Null
    & sc.exe failure $ServiceName reset= 0 actions= restart/60000 | Out-Null
    
    try { 
        Start-Service $ServiceName -ErrorAction Stop 
        Write-Host "[OK] OpenBao service registered and started." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to start OpenBao service. Check Event Viewer for details." -ForegroundColor Red
    }
} else {
    Write-Warning "bao.exe not found in $ParentDir\OpenBao. Please place the binary and rerun."
    return
}

# --- 4. Network Configuration ---
Write-Host ">>> Configuring Firewalls..." -ForegroundColor Gray

# Active Directory Outbound Ports
$ADPorts = @(389, 636, 3268, 3269, 445, 88)
foreach ($port in $ADPorts) {
    $name = "AD Sync Outbound $port"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Outbound -RemotePort $port -Protocol TCP -Action Allow | Out-Null
    }
}

# OpenBao API Inbound (Loopback focus)
if (!(Get-NetFirewallRule -DisplayName "OpenBao-API-8200" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "OpenBao-API-8200" -Direction Inbound -LocalPort 8200 -Protocol TCP -Action Allow | Out-Null
}

# SSH Inbound (Required for SFTP Transport)
if (!(Get-NetFirewallRule -DisplayName "ADSync-SSH-Inbound" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "ADSync-SSH-Inbound" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow -Description "Allows inbound SSH/SFTP for AD Sync transport." | Out-Null
    Write-Host "[OK] SSH Inbound rule (Port 22) configured." -ForegroundColor Gray
}

# --- 5. VAULT CRYPTOGRAPHIC INITIALIZATION ---
Write-Host ">>> Checking Vault Initialization Status..." -ForegroundColor Cyan
$env:BAO_ADDR = $VaultAddr
Start-Sleep -Seconds 5 # Increased wait for service to fully initialize API

try {
    $InitStatus = & $BaoExe operator init -status -format=json | ConvertFrom-Json
    
    if ($InitStatus.initialized -eq $false) {
        Write-Host ">>> Initializing Vault (Generating Master Keys)..." -ForegroundColor Yellow
        $InitResults = & $BaoExe operator init -key-shares=1 -key-threshold=1 -format=json
        
        if ($null -ne $InitResults) {
            $InitResults | Out-File $KeysFile -Force
            Write-Host "[SUCCESS] vault_keys.json created at $KeysFile" -ForegroundColor Green
            
            # Perform initial unseal
            $Keys = $InitResults | ConvertFrom-Json
            $UnsealKey = $Keys.unseal_keys_b64[0]
            & $BaoExe operator unseal $UnsealKey | Out-Null
            Write-Host "[OK] Vault unsealed." -ForegroundColor Green
        }
    } else {
        Write-Host "[INFO] Vault is already initialized." -ForegroundColor Gray
        if (!(Test-Path $KeysFile)) {
            Write-Warning "Vault is initialized but vault_keys.json is missing! Manual recovery required."
        }
    }
} catch {
    Write-Host "[ERROR] Could not communicate with Vault API. Try running the script again in 30 seconds." -ForegroundColor Red
}

Write-Host "--- Initialization Complete ---" -ForegroundColor Cyan