<#
.SYNOPSIS
    Automated initialization, unsealing, and secret provisioning for OpenBao.
.DESCRIPTION
    1. Initializes Vault if brand new.
    2. Unseals the Vault using saved keys.
    3. Enables KV-V2 and Transit engines.
    4. Ingests AD credentials from a temporary file and deletes it after storage.
#>

$ParentDir = "C:\ADSync"
$BaoDataDir = "$ParentDir\OpenBao"
$KeysFile = "$BaoDataDir\vault_keys.json"
$BaoExecutable = "$BaoDataDir\bao.exe"
$TempCredsFile = "$ParentDir\Sync\ad_creds_temp.json"
$env:BAO_ADDR = "http://127.0.0.1:8200"

Write-Host "--- Starting OpenBao Automation ---" -ForegroundColor Cyan

# 1. Initialize Vault if no keys exist
if (-not (Test-Path $KeysFile)) {
    Write-Host "[INIT] Initializing new Vault instance..." -ForegroundColor Yellow
    $InitJson = & $BaoExecutable operator init -key-shares=1 -key-threshold=1 -format=json
    if ($InitJson) {
        $InitJson | Out-File -FilePath $KeysFile -Encoding utf8 -Force
        Write-Host "[OK] Vault initialized. Keys saved to $KeysFile" -ForegroundColor Green
    }
}

# 2. Unseal the Vault
$Keys = Get-Content $KeysFile | ConvertFrom-Json
$Status = & $BaoExecutable status -format=json | ConvertFrom-Json

if ($Status.sealed -eq $true) {
    Write-Host "[UNSEAL] Unsealing Vault..." -ForegroundColor Yellow
    & $BaoExecutable operator unseal $Keys.unseal_keys_b64[0] | Out-Null
    Write-Host "[OK] Vault is now unsealed." -ForegroundColor Green
}

# 3. Provision Secret Engines
$env:BAO_TOKEN = $Keys.root_token

# Enable KV-V2 for AD Admin Secrets
$SecretsList = & $BaoExecutable secrets list -format=json | ConvertFrom-Json
if (-not $SecretsList."secret/") {
    Write-Host "[CONFIG] Enabling KV-V2 Secret Engine..." -ForegroundColor Yellow
    & $BaoExecutable secrets enable -path=secret kv-v2 | Out-Null
}

# Enable Transit Engine for Encryption
if (-not $SecretsList."transit/") {
    Write-Host "[CONFIG] Enabling Transit Engine..." -ForegroundColor Yellow
    & $BaoExecutable secrets enable transit | Out-Null
}

# 4. Ingest AD Credentials from Temporary File
if (Test-Path $TempCredsFile) {
    Write-Host "[SECURITY] Found temporary credential file. Ingesting..." -ForegroundColor Cyan
    try {
        $Creds = Get-Content $TempCredsFile | ConvertFrom-Json
        
        # Verify JSON structure
        if ($Creds.username -and $Creds.password) {
            # Store in Vault
            $Payload = @{ data = @{ username = $Creds.username; password = $Creds.password } } | ConvertTo-Json
            $headers = @{ "X-Vault-Token" = $Keys.root_token; "Content-Type" = "application/json" }
            
            Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/secret/data/ad-admin" -Headers $headers -Method Post -Body $Payload | Out-Null
            
            Write-Host "[OK] AD Admin credentials successfully stored in Vault." -ForegroundColor Green
            
            # Securely Delete the File
            Write-Host "[CLEANUP] Removing temporary credential file..." -ForegroundColor Yellow
            Remove-Item $TempCredsFile -Force
            Write-Host "[OK] Temporary file deleted." -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Invalid JSON format in ${TempCredsFile}. Expected 'username' and 'password'." -ForegroundColor Red
        }
    } catch {
        # Fixed the variable reference error by using a simple variable or delimiting with {}
        $errorMessage = $_.Exception.Message
        Write-Host "[ERROR] Failed to process ${TempCredsFile}: ${errorMessage}" -ForegroundColor Red
    }
} else {
    Write-Host "[INFO] No temporary credential file found. Skipping ingest." -ForegroundColor Gray
}

Write-Host "--- Automation Sequence Complete ---" -ForegroundColor Cyan
& $BaoExecutable status