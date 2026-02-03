<#
.SYNOPSIS
    Manual User Password Update Utility for OpenBao.
    Name: Update-VaultPassword.ps1
    Version: 1.2
    
.DESCRIPTION
    This utility allows an administrator to manually rotate a user's password 
    within the OpenBao KV-V2 vault. Changes are logged to the 'ADSync' 
    Windows Event Log for auditing.

.NOTES
    This script is part of the AD Sync Project toolkit.
    Version 1.2: Replaced manual password entry with automated generation matching 
                 the main Sync script logic.
#>

. "$PSScriptRoot\ADSyncLibrary.ps1"


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
        Uri = "$VaultAddr/v1/$Path"; 
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

# --- 4. EXECUTION LOGIC ---

Write-Host "--- OpenBao Automated Password Rotation Utility ---" -ForegroundColor Cyan

# Prompt for UserID
$TargetUserID = Read-Host "Enter the UserID (sAMAccountName) to rotate"
if ([string]::IsNullOrWhiteSpace($TargetUserID)) {
    Write-Error "UserID cannot be empty."
    exit
}


Write-Host "Generating new secure password for [$TargetUserID]..." -ForegroundColor Gray

$PlainTextPass = Get-StrongPassword

# Check if user already exists in Vault (optional metadata check)
$VaultPath = "$UserSecretsPath/$TargetUserID"
$Existing = Invoke-Bao -Method Get -Path $VaultPath

# Prepare the update payload for KV-V2
$Payload = @{
    data = @{
        password  = $PlainTextPass
        updatedBy = $env:USERNAME
        updatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        method    = "Manual-Rotation-Utility"
    }
}

# Execute Update in Vault
$Result = Invoke-Bao -Method Post -Path $VaultPath -Body $Payload

if ($null -ne $Result) {
    # LOGIC: Write password to users directory (Matching Sync Script Logic)
    $PassFilePath = "$PasswordLogDir\$TargetUserID.txt"
    "User: $TargetUserID`r`nGenerated Password: $PlainTextPass`r`nDate: $(Get-Date)`r`nRotated By: $env:USERNAME" | Out-File $PassFilePath -Force
    
    $ActionType = if ($null -eq $Existing) { "Generated/Created" } else { "Rotated" }
    $LogMsg = "SUCCESS: Manual password $ActionType for user [$TargetUserID] by administrator [$env:USERNAME]. File updated: $PassFilePath"
    
    Write-SyncLog -Msg $LogMsg -Type "Information"
    
    Write-Host "`nRotation Successful!" -ForegroundColor Green
    #Write-Host "New Password: " -NoNewline
    #Write-Host $PlainTextPass -ForegroundColor Yellow
    Write-Host "Password logged to: $PassFilePath"
} else {
    $ErrorMsg = "FAILURE: Could not update password for user [$TargetUserID] in Vault."
    Write-SyncLog -Msg $ErrorMsg -Type "Error"
    Write-Error $ErrorMsg
}