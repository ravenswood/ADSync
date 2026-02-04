<#
.SYNOPSIS
    Shared Library for AD Sync & OpenBao Operations.
.DESCRIPTION
    Contains global variables, logging logic, and OpenBao API wrappers 
    used by the synchronization suite.
#>

# Customise this depending on where depoyed
$TargetOU       = "OU=RBAC,DC=jml,DC=local"   # The OU to be queried or updated

# Remote Source Connection Details
$SftpHost       = "192.168.1.181"      # Remote SFTP server
$SftpPort       = 22                   # Default SFTP port
#"sftpuser": "xxxxxxxxxxxx",           # These should be defined in Sync/ad_creds_temp.json
#"sftppassword": "xxxxxxxxxx",         # Read once into the vault then file will be deleted

########## No Changes should be needed below this line ###############

# --- OU EXCLUSION FILTERS ---
$OUExcludeFilters = @(
    "OU=Balfour*",
    "OU=Siemens*",
    "OU=GE*",
    "OU=GSS*",    
    "OU=Hitachi*", 
    "*Staging*",
    "*Testing*"
)

# --- GLOBAL CONFIGURATION ---
$ParentDir       = "C:\ADSync"
$LogName         = "ADSync"
$Source          = "ADSyncScript"
$KeysFile        = "$ParentDir\OpenBao\vault_keys.json"
$VaultAddr       = "http://127.0.0.1:8200"
$PasswordLogDir  = "$ParentDir\Users"
$CredsSource     = "$ParentDir\Sync\ad_creds_temp.json" 
$ExportDir       = "$ParentDir\Export"           
$ImportDir       = "$ParentDir\Import" 
$BackupDir       = "$ParentDir\OpenBao" 
$UserSecretsPath = "secret/data/users"
$AdminSecretPath = "secret/data/ad-admin"
$sftpSecretPath  = "secret/data/sftpuser"

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

# --- OpenBao Configuration & Service Management ---
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

# OU Filtering
# Check if a filter was provided
if (![string]::IsNullOrWhiteSpace($FilterName)) {
    Write-Synclog "Filter applied: Removing entries containing '*$FilterName*'" -Category "FILTER"
    # Filter the array using wildcards before and after the input
    $OUExcludeFilters = $OUExcludeFilters | Where-Object { $_ -notlike "*$FilterName*" }
    $ExportDir = "$ParentDir\Export\$FilterName"   
} 

# --- SHARED FUNCTIONS ---

function Get-StrongPassword {
    <# Generates a strong 3-word password using the BIP-39 wordlist. #>
    $filePath = "$ParentDir\bip39_english.txt"
    if (-not (Test-Path $filePath)) { 
        return -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) 
    }
    $wordlist = Get-Content $filePath | Where-Object { $_.Trim() }
    $selectedWords = $wordlist | Get-Random -Count 3 | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($_) }
    $number = Get-Random -Minimum 10 -Maximum 99
    $symbol = "!","@","#","$","%","&" | Get-Random
    return ($selectedWords -join "_") + "_$number-$symbol"
}

function Invoke-Bao {
    <# Standardized wrapper for OpenBao REST API calls #>
    param(
        [Parameter(Mandatory=$true)][string]$Method, 
        [Parameter(Mandatory=$true)][string]$Path, 
        [object]$Body = $null, 
        [string]$Token = $null
    )
    
    # Resolve Token: Use provided token, or try to load from keys file
    $InternalToken = if ($Token) { $Token } elseif (Test-Path $KeysFile) { 
        (Get-Content $KeysFile | ConvertFrom-Json).root_token 
    }
    
    $headers = @{ "X-Vault-Token" = $InternalToken; "Content-Type" = "application/json" }
    $params = @{ Uri = "$VaultAddr/v1/$Path"; Headers = $headers; Method = $Method; ErrorAction = "Stop" }
    
    if ($Body) { $params.Body = ($Body | ConvertTo-Json) }
    try { 
        $result = Invoke-RestMethod @params
        if ($result.data.data) { return $result.data.data }
        return $result.data
    } catch { return $null }
}

function Write-SyncLog {
    <# Writes formatted log entries to Console and Windows Event Log #>
    param(
        [Parameter(Mandatory=$true)][string]$Msg, 
        [ValidateSet("Information", "Warning", "Error")][string]$Type = "Information", 
        [string]$Category = "GENERAL", 
        [int]$EventID = 1000
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $EntryType = [System.Diagnostics.EventLogEntryType]::$Type
    $FormattedMsg = "[$Category] $Msg"
    
    $Color = switch ($Type) { "Warning" { "Yellow" } "Error" { "Red" } Default { "Gray" } }
    Write-Host "[$Timestamp] [$Type] $FormattedMsg" -ForegroundColor $Color
    
    try {
        if (![System.Diagnostics.EventLog]::SourceExists($Source)) { 
            New-EventLog -LogName $LogName -Source $Source 
        }
        Write-EventLog -LogName $LogName -Source $Source -EntryType $EntryType -EventId $EventID -Message $FormattedMsg
    } catch { }
}

function Enable-Engine {
    param($Path, $Type)
    try {
        $Body = @{ type = $Type } | ConvertTo-Json
        Invoke-RestMethod -Uri "$VaultAddr/v1/sys/mounts/$Path" -Headers $headers -Method Post -Body $Body -ErrorAction SilentlyContinue
        Write-SyncLog "Engine Enabled: $Type at /$Path" 
    } catch {}
}

# --- UNSEALING & AUTHENTICATION ---

function Set-BaoStatus {
    param($Action)
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
        Write-SyncLog "Could not parse $Action key from $KeysFile." -Type "Error"
        exit
    }

    # Perform Unseal via API
    $headers = @{ "Content-Type" = "application/json" }
    $Body = @{ key = $UnsealKey } | ConvertTo-Json

    try {
        if ($Action -eq "Seal") {
            $headers = @{ "X-Vault-Token" = $Keys.root_token }
            Invoke-RestMethod -Uri "$VaultAddr/v1/sys/seal" -Method Put -Headers $headers | Out-Null
            Write-SyncLog "Vault Sealed" 
        }
        else {
            if (-not $UnsealKey) { throw "An UnsealKey is required to unseal the vault." }
            $body = @{ key = $UnsealKey } | ConvertTo-Json
            Invoke-RestMethod -Uri "$VaultAddr/v1/sys/unseal" -Method Put -Headers $headers -Body $body | Out-Null
            Write-SyncLog "Vault Unsealed" 
        }

        # Verify final status
        $status = Invoke-RestMethod -Uri "$VaultAddr/v1/sys/seal-status" -Method Get | Out-Null
        return $status | Select-Object sealed, progress, threshold
      }
      catch {
        Write-SyncLog "Operation failed: $_"
    }

    # Set Auth Token for subsequent provisioning
    $Token = $Keys.root_token
    $headers = @{ 
        "X-Vault-Token" = $Token; 
        "Content-Type"  = "application/json" 
    }
}