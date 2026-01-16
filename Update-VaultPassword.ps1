<#
.SYNOPSIS
    Manual User Password Update Utility for OpenBao.
    Name: Update-VaultPassword.ps1
    Version: 1.1
    
.DESCRIPTION
    This utility allows an administrator to manually update or rotate a user's 
    password within the OpenBao KV-V2 vault. Changes are logged to the 
    'ADSync' Windows Event Log for auditing.

.NOTES
    This script is part of the AD Sync Project toolkit.
    Version 1.1: Added logic to write updated password to the Users directory.
#>

# --- 1. CONFIGURATION ---
$ParentDir = "C:\ADSync"
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json"
$UserSecretsPath = "secret/data/users" # KV-V2 path for user passwords
$PasswordLogDir  = "$ParentDir\Users"  # Local log for password reference

# --- 2. PREREQUISITE CHECKS ---
if (Test-Path $KeysFile) {
    $BaoToken = (Get-Content $KeysFile | ConvertFrom-Json).root_token
} else {
    Write-Error "CRITICAL: vault_keys.json not found. Vault must be initialized first."
    exit
}

# Ensure Password Log Directory exists
if (!(Test-Path $PasswordLogDir)) { 
    New-Item -ItemType Directory -Path $PasswordLogDir -Force | Out-Null 
}

# --- 3. UTILITY FUNCTIONS ---

function Invoke-Bao {
    <# Standard wrapper for OpenBao API calls #>
    param(
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$Path,
        [object]$Body = $null
    )
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    $params = @{ 
        Uri = "http://127.0.0.1:8200/v1/$Path"; 
        Headers = $headers; 
        Method = $Method;
        ErrorAction = "Stop"
    }
    if ($Body) { $params.Body = ($Body | ConvertTo-Json) }
    try { 
        return Invoke-RestMethod @params
    } catch { 
        return $null 
    }
}

function Write-SyncLog {
    <# Log changes to Console and Windows Event Log #>
    param($Msg, $Type = "Information")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Type] $Msg"
    try {
        # Note: Event Log 'ADSync' and Source 'ADSyncScript' must be pre-registered
        Write-EventLog -LogName "ADSync" -Source "ADSyncScript" -EntryType $Type -EventId 2000 -Message $Msg
    } catch {
        Write-Warning "Could not write to Windows Event Log. Ensure 'ADSync' log source is registered."
    }
}

# --- 4. INTERACTIVE LOGIC ---

Write-Host "--- OpenBao Password Update Utility ---" -ForegroundColor Cyan

# Prompt for UserID
$TargetUserID = Read-Host "Enter the UserID (sAMAccountName) to update"
if ([string]::IsNullOrWhiteSpace($TargetUserID)) {
    Write-Error "UserID cannot be empty."
    exit
}

# Prompt for Password (masked)
$NewPassword = Read-Host "Enter the new password for [$TargetUserID]" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword)
$PlainTextPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

if ([string]::IsNullOrWhiteSpace($PlainTextPass)) {
    Write-Error "Password cannot be empty."
    exit
}

# Check if user already exists in Vault (optional metadata check)
$VaultPath = "$UserSecretsPath/$TargetUserID"
$Existing = Invoke-Bao -Method Get -Path $VaultPath

# Prepare the update payload for KV-V2
$Payload = @{
    data = @{
        password = $PlainTextPass
        updatedBy = $env:USERNAME
        updatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# Execute Update in Vault
$Result = Invoke-Bao -Method Post -Path $VaultPath -Body $Payload

if ($null -ne $Result) {
    # LOGIC: Write password to users directory (Matching Sync Script Logic)
    $PassFilePath = "$PasswordLogDir\$TargetUserID.txt"
    "User: $TargetUserID`r`nUpdated Password: $PlainTextPass`r`nDate: $(Get-Date)`r`nUpdated By: $env:USERNAME" | Out-File $PassFilePath -Force
    
    $ActionType = if ($null -eq $Existing) { "Created" } else { "Updated" }
    $LogMsg = "SUCCESS: Manual password $ActionType for user [$TargetUserID] by administrator [$env:USERNAME]. File updated: $PassFilePath"
    
    Write-SyncLog -Msg $LogMsg -Type "Information"
    Write-Host "`nPassword successfully saved to Vault and logged to $PassFilePath." -ForegroundColor Green
} else {
    $ErrorMsg = "FAILURE: Could not update password for user [$TargetUserID] in Vault."
    Write-SyncLog -Msg $ErrorMsg -Type "Error"
    Write-Error $ErrorMsg
}

# Clean up sensitive pointer from memory
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)