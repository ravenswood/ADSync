<#
.SYNOPSIS
    Primary AD Synchronization and Secure Transport Script.
.DESCRIPTION
    v3.1 - Implements Asymmetric Encryption (RSA-4096) for the export payload.
    The Export side uses the Public Key to encrypt, and the Import side uses 
    the Private Key (stored securely in OpenBao) to decrypt.

.NOTES
    Author: AD Sync Project
    Version: 3.1
#>

# --- CONFIGURATION & PATHS ---
$ParentDir = "C:\ADSync"
$ExportDir = "$ParentDir\Export"
$ImportDir = "$ParentDir\Import"
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json"

# State and API Paths
$UserSecretsPath = "secret/data/users"                 
$AdminSecretPath = "secret/data/ad-admin"              
$TargetOU        = "OU=Supplier,DC=ng,DC=local"              
$PasswordLogDir  = "$ParentDir\Users"                

# Define filenames
$StateFileName = "AD_State_Export.json"
$SignatureFileName = "AD_State_Export.hmac"
$BackupKeyFileName = "transport-key.backup"

# LDAP Attribute Mapping
$AttrMap = @{
    "DisplayName"     = "displayName"
    "EmailAddress"    = "mail"
    "GivenName"       = "givenName"
    "Surname"         = "sn"
    "Description"     = "description"
    "Title"           = "title"
    "Department"      = "department"
    "Company"         = "company"
    "StreetAddress"   = "streetAddress"
    "City"            = "l"
    "State"           = "st"
    "PostalCode"      = "postalCode"
    "Country"         = "c"
    "TelephoneNumber" = "telephoneNumber"
    "MobilePhone"     = "mobile"
    "Manager"         = "manager"
}

# Ensure local environment is ready
if (Test-Path $KeysFile) {
    $BaoToken = (Get-Content $KeysFile | ConvertFrom-Json).root_token
} else {
    Write-Error "CRITICAL: vault_keys.json not found. Run Invoke-BaoAutomation.ps1 first."
    exit
}

# --- CORE UTILITY FUNCTIONS ---

function Invoke-Bao {
    param($Method, $Path, $Body = $null)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    $params = @{ 
        Uri = "http://127.0.0.1:8200/v1/$Path"; 
        Headers = $headers; 
        Method = $Method;
        ErrorAction = "Stop"
    }
    if ($Body) { $params.Body = ($Body | ConvertTo-Json) }
    try { 
        $result = Invoke-RestMethod @params
        if ($result.data.data) { return $result.data.data }
        if ($result.data) { return $result.data }
        return $result
    } catch { return $null }
}

function Write-SyncLog {
    param($Msg, $Type = "Information")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Type] $Msg"
    Write-Host $LogMessage
    try {
        $EventEntryType = if ($Type -eq "Error") { "Error" } elseif ($Type -eq "Warning") { "Warning" } else { "Information" }
        Write-EventLog -LogName "ADSync" -Source "ADSyncScript" -EntryType $EventEntryType -EventId 1000 -Message $Msg
    } catch {}
}

function Initialize-TransitEngine {
    param($KeyBackupPath)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    
    # Ensure Transit is enabled
    try { Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/sys/mounts/transit" -Headers $headers -Method Post -Body (@{ type = "transit" } | ConvertTo-Json) -ErrorAction SilentlyContinue } catch {}

    # Restore key if moving to Import server
    if (Test-Path $KeyBackupPath) {
        if ($null -eq (Invoke-Bao -Method Get -Path "transit/keys/transport-key")) {
            $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
            Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json)
            Write-SyncLog "Asymmetric Transport Key Restored."
        }
    }
    
    # Initialize Asymmetric Key (RSA-4096) if missing
    if ($null -eq (Invoke-Bao -Method Get -Path "transit/keys/transport-key")) {
        # type="rsa-4096" enables asymmetric encryption/decryption
        Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/keys/transport-key" -Headers $headers -Method Post -Body (@{ 
            type = "rsa-4096"; 
            exportable = $true; 
            allow_plaintext_backup = $true 
        } | ConvertTo-Json)
        Write-SyncLog "Initialized RSA-4096 Asymmetric Key."
    }

    # Backup the key during Export so the Import server can use the Private half
    if ($Global:Mode -eq "Export") {
        $backup = Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/backup/transport-key" -Headers $headers -Method Get
        if ($backup.data.backup) { $backup.data.backup | Out-File $KeyBackupPath -Encoding ascii -Force }
    }
}

function Protect-Data {
    param([string]$Plaintext)
    $Base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plaintext))
    # Transit automatically uses the Public Key for encryption when key type is RSA
    $Result = Invoke-Bao -Method Post -Path "transit/encrypt/transport-key" -Body @{ plaintext = $Base64 }
    return $Result.ciphertext
}

function Unprotect-Data {
    param([string]$Ciphertext)
    # Transit automatically uses the Private Key for decryption
    $Result = Invoke-Bao -Method Post -Path "transit/decrypt/transport-key" -Body @{ ciphertext = $Ciphertext }
    $Bytes = [Convert]::FromBase64String($Result.plaintext)
    return [System.Text.Encoding]::UTF8.GetString($Bytes)
}

# --- MAIN WORKFLOWS ---

function Export-ADState {
    Write-SyncLog "Starting Asymmetric Export Mode -> $ExportDir"
    if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }
    if (!(Test-Path $PasswordLogDir)) { New-Item -ItemType Directory -Path $PasswordLogDir -Force | Out-Null }
    
    Initialize-TransitEngine -KeyBackupPath "$ExportDir\$BackupKeyFileName"

    $Users = Get-ADUser -Filter * -SearchBase $TargetOU -Properties ($AttrMap.Keys + "MemberOf")
    $ExportUsers = @()

    foreach ($U in $Users) {
        $Secret = Invoke-Bao -Method Get -Path "$UserSecretsPath/$($U.SamAccountName)"
        if (!$Secret) {
            $Pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
            Invoke-Bao -Method Post -Path "$UserSecretsPath/$($U.SamAccountName)" -Body @{password=$Pass}
            $Secret = @{ password = $Pass }
        }
        
        $UserPasswordFile = Join-Path $PasswordLogDir "$($U.SamAccountName).txt"
        $Secret.password | Out-File -FilePath $UserPasswordFile -Encoding utf8 -Force
        
        # Asymmetrically Encrypt user password
        $EncPass = Protect-Data -Plaintext $Secret.password
        
        $GroupNames = New-Object System.Collections.Generic.List[string]
        if ($U.MemberOf) {
            foreach ($gDn in $U.MemberOf) {
                try {
                    $gName = (Get-ADGroup -Identity $gDn).SamAccountName
                    if ($gName) { $GroupNames.Add($gName) }
                } catch { }
            }
        }

        $UserMap = @{ 
            SamAccountName = $U.SamAccountName; 
            DisplayName    = $U.DisplayName;
            ProtectedPass  = $EncPass; 
            Groups         = $GroupNames.ToArray(); 
            Attributes     = @{} 
        }
        foreach ($Key in $AttrMap.Keys) { if ($U.$Key) { $UserMap.Attributes[$Key] = $U.$Key.ToString() } }
        $ExportUsers += $UserMap
    }
    
    $Export = @{ Users = $ExportUsers }
    $StatePath = "$ExportDir\$StateFileName"
    $SigPath = "$ExportDir\$SignatureFileName"
    
    $Export | ConvertTo-Json -Depth 10 | Out-File $StatePath
    $Bytes = [System.IO.File]::ReadAllBytes($StatePath)
    
    # Sign using the RSA key
    $Sig = Invoke-Bao -Method Post -Path "transit/hmac/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes) }
    $Sig.hmac | Out-File $SigPath -Encoding ascii
    Write-SyncLog "Asymmetric Export Complete."
}

function Import-ADState {
    Write-SyncLog "Starting Asymmetric Import Mode <- $ImportDir"
    
    $StatePath = "$ImportDir\$StateFileName"
    $SigPath = "$ImportDir\$SignatureFileName"
    $KeyBackupPath = "$ImportDir\$BackupKeyFileName"

    if (!(Test-Path $StatePath)) { Write-SyncLog "No state file found at $StatePath" -Type Warning; return }
    Initialize-TransitEngine -KeyBackupPath $KeyBackupPath
    
    $Bytes = [System.IO.File]::ReadAllBytes($StatePath)
    $HMAC = (Get-Content $SigPath).Trim()
    
    # Verify HMAC using the asymmetric key
    if ((Invoke-Bao -Method Post -Path "transit/verify/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes); hmac = $HMAC }).valid -ne $true) {
        Write-SyncLog "CRITICAL: Signature mismatch!" -Type Error; return
    }

    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))
    $Data = Get-Content $StatePath | ConvertFrom-Json
    
    foreach ($SU in $Data.Users) {
        try {
            # Asymmetrically Decrypt user password
            $PlainPass = Unprotect-Data -Ciphertext $SU.ProtectedPass
            $SP = $PlainPass | ConvertTo-SecureString -AsPlainText -Force
            
            $AttrParams = @{}
            foreach ($P in $SU.Attributes.PSObject.Properties) {
                if ($AttrMap[$P.Name]) { $AttrParams[$AttrMap[$P.Name]] = $P.Value }
            }

            $ObjName = if ($SU.DisplayName) { $SU.DisplayName } else { $SU.SamAccountName }

            $TU = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -ErrorAction SilentlyContinue
            if (!$TU) {
                New-ADUser -Name $ObjName -SamAccountName $SU.SamAccountName -Path $TargetOU `
                           -AccountPassword $SP -Enabled $true -Credential $Creds `
                           -PasswordNeverExpires $true -CannotChangePassword $true `
                           -OtherAttributes $AttrParams
                Write-SyncLog "Created User: $($SU.SamAccountName)"
                $TU = Get-ADUser -Identity $SU.SamAccountName
            } else {
                Set-ADUser -Identity $TU.DistinguishedName -Replace $AttrParams `
                           -PasswordNeverExpires $true -CannotChangePassword $true -Credential $Creds
                Set-ADAccountPassword -Identity $TU.DistinguishedName -NewPassword $SP -Reset -Credential $Creds
                Write-SyncLog "Updated User: $($SU.SamAccountName)"
            }

            if ($SU.Groups) {
                foreach ($GroupName in $SU.Groups) {
                    $TargetGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction SilentlyContinue
                    if (!$TargetGroup) {
                        New-ADGroup -Name $GroupName -SamAccountName $GroupName -Path $TargetOU -GroupScope Global -Credential $Creds
                        $TargetGroup = Get-ADGroup -Identity $GroupName
                    }
                    
                    $IsMember = Get-ADGroupMember -Identity $TargetGroup.DistinguishedName | Where-Object { $_.SamAccountName -eq $SU.SamAccountName }
                    if (-not $IsMember) {
                        Add-ADGroupMember -Identity $TargetGroup.DistinguishedName -Members $TU.DistinguishedName -Credential $Creds
                        Write-SyncLog "Added $($SU.SamAccountName) to group $GroupName"
                    }
                }
            }
        } catch { Write-SyncLog "Error processing $($SU.SamAccountName): $($_.Exception.Message)" -Type Warning }
    }
}

# --- EXECUTION LOGIC ---
if (Test-Path "$ImportDir\$StateFileName") { 
    $Global:Mode = "Import"
    Import-ADState 
} else { 
    $Global:Mode = "Export"
    Export-ADState 
}