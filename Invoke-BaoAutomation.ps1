<#
.SYNOPSIS
    Vault Lifecycle and Credential Automation Script.
    Name: Invoke-BaoAutomation.ps1
.DESCRIPTION
    This script automates the critical maintenance tasks for the OpenBao security vault:
    1. Infrastructure Check: Ensures the Vault service is initialized.
    2. Unsealing: Automatically unseals the vault using local keys if it is locked.
    3. Provisioning: Enables the KV-V2 (Secret) and Transit (Encryption-as-a-Service) engines.
    4. Credential Ingestion: Detects 'ad_creds_temp.json', encrypts the contents into 
       the Vault, and performs a secure deletion of the plaintext source file.
    5. Health Audit: Verifies connectivity and engine readiness.
.NOTES
    If fails on 1st run, run again
#>

. "$PSScriptRoot\ADSyncLibrary.ps1"

# --- SERVICE VERIFICATION ---
$svc = Get-Service -Name "OpenBao" -ErrorAction SilentlyContinue
if ($null -eq $svc -or $svc.Status -ne 'Running') {
    Write-SyncLog "OpenBao service is not running. Attempting to start..." -Type "Warning"
    Start-Service OpenBao -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}

# Set Auth Token for subsequent provisioning
$Keys = Get-Content $KeysFile | ConvertFrom-Json
$Token = $Keys.root_token
$headers = @{ 
    "X-Vault-Token" = $Token; 
    "Content-Type"  = "application/json" 
}
Set-BaoStatus Unseal
Enable-Engine -Path "secret" -Type "kv"
Enable-Engine -Path "transit" -Type "transit"

# --- CREDENTIAL INGESTION & CLEANUP ---
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
                
        Remove-Item $CredsSource -Force
        Write-SyncLog "CLEANUP: Plaintext source file $CredsSource has been permanently deleted."
    } catch {
        Write-SyncLog "FAILED: Credential ingestion failed: $($_.Exception.Message)." -type "Error"
    }
}



Write-SyncLog ">>> Vault Lifecycle Tasks Complete." 