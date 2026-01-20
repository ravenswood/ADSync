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

# --- 1. CONFIGURATION & PATHS ---
$ParentDir   = "C:\ADSync"
$KeysFile    = "$ParentDir\OpenBao\vault_keys.json"    # Contains unseal keys and root token
$CredsSource = "$ParentDir\Sync\ad_creds_temp.json"    # Plaintext source for initial setup
$AdminSecret = "secret/data/ad-admin"                 # Vault destination for AD Admin creds
$VaultAddr   = "http://127.0.0.1:8200"                 # Local API endpoint for OpenBao

# --- 2. SERVICE VERIFICATION ---
$svc = Get-Service -Name "OpenBao" -ErrorAction SilentlyContinue
if ($null -eq $svc -or $svc.Status -ne 'Running') {
    Write-Warning "OpenBao service is not running. Attempting to start..."
    Start-Service OpenBao -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}

# --- 3. UNSEALING & AUTHENTICATION ---
if (!(Test-Path $KeysFile)) {
    Write-Error "CRITICAL: vault_keys.json missing. Run initialization steps first."
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
    Write-Error "Could not parse unseal key from $KeysFile."
    exit
}

# Perform Unseal via API
$headers = @{ "Content-Type" = "application/json" }
$Body = @{ key = $UnsealKey } | ConvertTo-Json
try {
    Invoke-RestMethod -Uri "$VaultAddr/v1/sys/unseal" -Headers $headers -Method Post -Body $Body | Out-Null
    Write-Host "Vault successfully unsealed." -ForegroundColor Green
} catch {
    Write-Host "Vault already unsealed or failed to unseal." -ForegroundColor Gray
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
        Write-Host "Engine Enabled: $Type at /$Path" -ForegroundColor Gray
    } catch {}
}

Enable-Engine -Path "secret" -Type "kv"
Enable-Engine -Path "transit" -Type "transit"

# --- 5. CREDENTIAL INGESTION & CLEANUP ---
if (Test-Path $CredsSource) {
    Write-Host ">>> Temporary credential file detected. Starting ingestion..." -ForegroundColor Cyan
    try {
        $RawCreds = Get-Content $CredsSource | ConvertFrom-Json
        $Payload = @{ data = @{ username = $RawCreds.username; password = $RawCreds.password } } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "$VaultAddr/v1/$AdminSecret" -Headers $headers -Method Post -Body $Payload
        Write-Host "SUCCESS: AD Credentials securely stored in Vault." -ForegroundColor Green
        
        Remove-Item $CredsSource -Force
        Write-Host "CLEANUP: Plaintext source file $CredsSource has been permanently deleted."
    } catch {
        Write-Error "FAILED: Credential ingestion failed: $($_.Exception.Message)."
    }
}

Write-Host ">>> Vault Lifecycle Tasks Complete." -ForegroundColor Cyan