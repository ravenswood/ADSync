<#
.SYNOPSIS
    Shared Library for AD Sync & OpenBao Operations.
.DESCRIPTION
    Contains global variables, logging logic, and OpenBao API wrappers 
    used by the synchronization suite.
#>


# --- OU EXCLUSION FILTERS ---
$OUExcludeFilters = @(
    "*Staging*",
    "*Testing*",
    "OU=xBalfour*"
)
          
$TargetOU = "OU=RBAC,DC=jml,DC=local"

# Remote Source Connection Details
$SftpHost        = "192.168.1.181" 
$SftpPort        = 22 


# --- GLOBAL CONFIGURATION ---
$ParentDir       = "C:\ADSync"
$LogName         = "ADSync"
$Source          = "ADSyncScript"
$KeysFile        = "$ParentDir\OpenBao\vault_keys.json"
$VaultAddr       = "http://127.0.0.1:8200"
$PasswordLogDir      = "$ParentDir\Users"
$CredsSource = "$ParentDir\Sync\ad_creds_temp.json" 
$ExportDir = "$ParentDir\Export"           
$ImportDir = "$ParentDir\Import" 


$UserSecretsPath = "secret/data/users"
$AdminSecretPath = "secret/data/ad-admin"
$sftpSecretPath = "secret/data/sftpuser"

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

# 1. Check if the config file was provided
if (-not [string]::IsNullOrWhiteSpace($LibraryPath)) {

    $LibPath = "$LibraryPath.ps1"
    # 2. Verify the file actually exists on disk
    if (Test-Path -Path "$PSScriptRoot\$LibPath") {
        Write-SyncLog "Dot-sourcing: $PSScriptRoot\$LibPath" 
        
        # 3. Dot-source the file
        . "$PSScriptRoot\$LibPath"
    }
    else {
        Write-SyncLog "The file '$PSScriptRoot\$LibPath' was specified but could not be found." -Type "Error"
    }
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
    return ($selectedWords -join "_") + "_$number$symbol"
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