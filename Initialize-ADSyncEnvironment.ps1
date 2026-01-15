<#
.SYNOPSIS
    Environment Initialization and Hardening Script for AD Sync.
    Name: Initialize-SyncServer.ps1
    Version: 2.2
.DESCRIPTION
    This script prepares a Windows Server to act as either a Source or Target 
    sync node. It performs the following critical infrastructure tasks:
    1. Directory Creation: Establishes the standard C:\ADSync hierarchy.
    2. NTFS Hardening: Restricts access to sensitive directories to Administrators and SYSTEM.
    3. Service Registration: Configures OpenBao (bao.exe) as a managed Windows Service.
    4. Firewall Provisioning: Opens necessary ports for OpenBao (8200) and AD communication.
    5. Event Logging: Creates the 'ADSync' custom event log for script auditing.
.NOTES
    Run this script as an Administrator. 
    Ensure 'bao.exe' is placed in C:\ADSync\OpenBao before execution.
#>

# --- 1. CONFIGURATION ---
$ParentDir = "C:\ADSync"
$Paths = @(
    "$ParentDir\OpenBao",    # Storage for Vault binaries and encrypted data
    "$ParentDir\Sync",       # Work area for credential ingestion
    "$ParentDir\Export",     # Outbox for transport payloads (Source server)
    "$ParentDir\Import",     # Inbox for incoming payloads (Target server)
    "$ParentDir\Logs",       # Backup text logs
    "$ParentDir\Users"       # Storage for generated user password files
)
$BaoExe = "$ParentDir\OpenBao\bao.exe"
$BaoData = "$ParentDir\OpenBao\data"

# --- 2. DIRECTORY STRUCTURE & NTFS PERMISSIONS ---
Write-Host ">>> Establishing Directory Structure..." -ForegroundColor Cyan
foreach ($Path in $Paths) {
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Created: $Path" -ForegroundColor Gray
    }
}

# Create the internal Vault data storage folder
if (!(Test-Path $BaoData)) { New-Item -ItemType Directory -Path $BaoData -Force | Out-Null }

# Hardening: We remove inherited permissions and grant Full Control only to 
# the SYSTEM account and the local Administrators group. This protects 
# the encryption keys and secrets from standard users.
Write-Host ">>> Hardening NTFS Permissions..." -ForegroundColor Cyan
$Acl = Get-Acl $ParentDir
$Acl.SetAccessRuleProtection($true, $false) # Protect against inheritance

# UPDATED: Using explicit .new() syntax to avoid New-Object positional parameter errors
$Rules = @(
    [System.Security.AccessControl.FileSystemAccessRule]::new("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
    [System.Security.AccessControl.FileSystemAccessRule]::new("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
)

foreach ($Rule in $Rules) { 
    $Acl.AddAccessRule($Rule) 
}
Set-Acl $ParentDir $Acl

# --- 3. EVENT LOG PROVISIONING ---
if (![System.Diagnostics.EventLog]::SourceExists("ADSyncScript")) {
    Write-Host ">>> Registering Custom Event Log: ADSync..." -ForegroundColor Cyan
    New-EventLog -LogName "ADSync" -Source "ADSyncScript"
}

# --- 4. OPENBAO SERVICE REGISTRATION ---
Write-Host ">>> Configuring OpenBao Windows Service..." -ForegroundColor Cyan
if (!(Test-Path $BaoExe)) {
    Write-Warning "CRITICAL: bao.exe NOT FOUND at $BaoExe."
} else {
    $SvcName = "OpenBao"
    $ExistingSvc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    
    if ($null -eq $ExistingSvc) {
        $BinaryPath = "$BaoExe server -dev -dev-listen-address=127.0.0.1:8200"
        sc.exe create $SvcName binPath= $BinaryPath start= auto DisplayName= "OpenBao Security Vault"
        sc.exe description $SvcName "Provides cryptographic services and secret storage for ADSync."
        Start-Service $SvcName
        Write-Host "SUCCESS: OpenBao service registered and started." -ForegroundColor Green
    } else {
        Write-Host "OpenBao service already exists." -ForegroundColor Gray
    }
}

# --- 5. FIREWALL CONFIGURATION ---
Write-Host ">>> Provisioning Local Firewall Rules..." -ForegroundColor Cyan

$VaultRule = "OpenBao-API-8200"
if (!(Get-NetFirewallRule -DisplayName $VaultRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $VaultRule -Direction Inbound -LocalPort 8200 -Protocol TCP -Action Allow -Description "Allow local API communication with OpenBao."
}

$ADRule = "ADSync-Transport-Out"
if (!(Get-NetFirewallRule -DisplayName $ADRule -ErrorAction SilentlyContinue)) {
    $ADPorts = @("389", "636", "3268", "3269", "445", "88")
    New-NetFirewallRule -DisplayName $ADRule -Direction Outbound -LocalPort $ADPorts -Protocol TCP -Action Allow -Description "Allow outbound AD Sync traffic."
}

Write-Host ">>> Infrastructure Setup Complete." -ForegroundColor Cyan