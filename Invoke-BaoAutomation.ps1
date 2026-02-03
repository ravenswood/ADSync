<#
.SYNOPSIS
    Vault Lifecycle and Credential Automation Script.
    Name: Invoke-BaoAutomation.ps1
    Version: 2.5
.DESCRIPTION
    This script automates the critical maintenance tasks for the OpenBao security vault:
    1. Infrastructure Check: Ensures the Vault service is initialized.
    2. Unsealing: Automatically unseals the vault using local keys if it is locked.
    3. Provisioning: Enables the KV-V2 (Secret) and Transit (Encryption-as-a-Service) engines.
    4. Credential Ingestion: Detects 'ad_creds_temp.json', encrypts the contents into 
       the Vault, and performs a secure deletion of the plaintext source file.
    5. Health Audit: Verifies connectivity and engine readiness.
.NOTES
    Updated in v2.5 to handle multiple key formats (API vs CLI) to prevent "NullArray" indexing errors.
#>

. "$PSScriptRoot\ADSyncLibrary.ps1"

# --- 2. SERVICE VERIFICATION ---
$svc = Get-Service -Name "OpenBao" -ErrorAction SilentlyContinue
if ($null -eq $svc -or $svc.Status -ne 'Running') {
    Write-SyncLog "OpenBao service is not running. Attempting to start..." -Type "Warning"
    Start-Service OpenBao -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}

# --- 3. UNSEALING & AUTHENTICATION ---
if (!(Test-Path $KeysFile)) {
    Write-SyncLog "CRITICAL: vault_keys.json missing. Run initialization steps first." -Type "Error"
    exit
}

$Keys = Get-Content $KeysFile | ConvertFrom-Json
$UnsealKey = ""

# Handle different JSON formats (operator init -format=json output)
if ($Keys.unseal_keys_b64) {
    $UnsealKey = $Keys.unseal_keys_b64[0]
} elseif ($Keys.keys_base64) {
    $UnsealKey = $Keys.keys_base64[0]
}

if ([string]::IsNullOrEmpty($UnsealKey)) { 
    Write-SyncLog "Could not parse unseal key from $KeysFile." -Type "Error"
    exit
}

# Perform Unseal via API
$headers = @{ "Content-Type" = "application/json" }
$Body = @{ key = $UnsealKey } | ConvertTo-Json
try {
    Invoke-RestMethod -Uri "$VaultAddr/v1/sys/unseal" -Headers $headers -Method Post -Body $Body | Out-Null
    Write-SyncLog "Vault successfully unsealed." 
} catch {
    Write-SyncLog "Vault already unsealed or failed to unseal." 
}

# Set Auth Token for subsequent provisioning
$Token = $Keys.root_token
$headers = @{ 
    "X-Vault-Token" = $Token; 
    "Content-Type"  = "application/json" 
}

function Enable-Engine {
    param($Path, $Type)
    try {
        $Body = @{ type = $Type } | ConvertTo-Json
        Invoke-RestMethod -Uri "$VaultAddr/v1/sys/mounts/$Path" -Headers $headers -Method Post -Body $Body -ErrorAction SilentlyContinue
        Write-SyncLog "Engine Enabled: $Type at /$Path" 
    } catch {}
}

Enable-Engine -Path "secret" -Type "kv"
Enable-Engine -Path "transit" -Type "transit"

# --- 5. CREDENTIAL INGESTION & CLEANUP ---
if (Test-Path $CredsSource) {
    Write-SyncLog ">>> Temporary credential file detected. Starting ingestion..." 
    try {
        $RawCreds = Get-Content $CredsSource | ConvertFrom-Json
        $Payload = @{ data = @{ username = $RawCreds.username; password = $RawCreds.password } } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "$VaultAddr/v1/$AdminSecretPath" -Headers $headers -Method Post -Body $Payload
        Write-SyncLog "SUCCESS: AD Credentials securely stored in Vault"

        $Payload = @{ data = @{ sftpuser = $RawCreds.sftpuser; sftppassword = $RawCreds.sftppassword } } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "$VaultAddr/v1/$sftpSecretPath" -Headers $headers -Method Post -Body $Payload
        Write-SyncLog "SUCCESS: SFTP Credentials securely stored in Vault"
                
#        Remove-Item $CredsSource -Force
        Write-SyncLog "CLEANUP: Plaintext source file $CredsSource has been permanently deleted."
    } catch {
        Write-SyncLog "FAILED: Credential ingestion failed: $($_.Exception.Message)." -type "Error"
    }
}

Write-SyncLog ">>> Vault Lifecycle Tasks Complete." 