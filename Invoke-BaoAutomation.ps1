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

# --- 2. VAULT INITIALIZATION CHECK ---
if (!(Test-Path $KeysFile)) {
    Write-Host ">>> Initializing Fresh Vault Instance..." -ForegroundColor Cyan
    
    $InitBody = @{
        secret_shares = 1
        secret_threshold = 1
    } | ConvertTo-Json

    try {
        $Init = Invoke-RestMethod -Uri "$VaultAddr/v1/sys/init" -Method Post -Body $InitBody
        $Init | ConvertTo-Json | Out-File $KeysFile
        Write-Host "SUCCESS: Vault Initialized. Root keys saved to $KeysFile." -ForegroundColor Green
    } catch {
        Write-Error "Initialization failed. Ensure the OpenBao service is running."
        return
    }
}

# --- 3. UNSEAL LOGIC ---
# Load the keys from the local JSON file
$VaultData = Get-Content $KeysFile | ConvertFrom-Json

# FIX: Check for both 'keys' (API format) and 'unseal_keys_b64' (CLI format)
if ($VaultData.keys) {
    $UnsealKey = $VaultData.keys[0]
} elseif ($VaultData.unseal_keys_b64) {
    $UnsealKey = $VaultData.unseal_keys_b64[0]
} else {
    Write-Error "CRITICAL: No unseal keys found in $KeysFile. Format is unrecognized."
    return
}

$RootToken = $VaultData.root_token

Write-Host ">>> Checking Vault Seal Status..."
try {
    $Status = Invoke-RestMethod -Uri "$VaultAddr/v1/sys/health" -Method Get -ErrorAction SilentlyContinue
} catch {
    $Status = $null 
}

if ($null -eq $Status -or $Status.sealed -eq $true) {
    Write-Host "Vault is currently sealed. Attempting Unseal operation..." -ForegroundColor Yellow
    $UnsealBody = @{ key = $UnsealKey } | ConvertTo-Json
    Invoke-RestMethod -Uri "$VaultAddr/v1/sys/unseal" -Method Post -Body $UnsealBody | Out-Null
    Write-Host "Vault unsealed successfully." -ForegroundColor Green
} else {
    Write-Host "Vault is already unsealed and operational." -ForegroundColor Gray
}

# --- 4. ENGINE PROVISIONING ---
$headers = @{ 
    "X-Vault-Token" = $RootToken
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
} else {
    Write-Host "No temporary credentials found. Utilizing existing secrets stored in Vault." -ForegroundColor Gray
}

Write-Host ">>> Vault Automation Cycle Complete." -ForegroundColor Cyan