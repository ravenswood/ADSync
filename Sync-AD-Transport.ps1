<#
.SYNOPSIS
    Primary Active Directory Synchronization and Secure Transport Script.
    Name: Sync-AD-Transport.ps1
    Version: 3.8
    
.DESCRIPTION
    This script facilitates the secure transfer of AD user objects and group memberships 
    between disconnected (air-gapped) environments. 
    
    Security Features:
    - RSA-4096 Asymmetric Encryption for user passwords.
    - HMAC-SHA256 Payload Signing to prevent data tampering.
    - OpenBao Transit Engine integration.
    
    Reconciliation & CRUD Logging:
    - [CREATE] Logs new user and group creation.
    - [UPDATE] Logs specific attribute drift and resolution.
    - [GROUP SYNC] Logs additions and removals from security groups.
    - [PASSWORDS] Logs generation of new credentials for new users.

.NOTES
    Requires: ActiveDirectory PowerShell Module, OpenBao running on localhost:8200.
#>

# --- 1. GLOBAL CONFIGURATION & FILE PATHS ---

$ParentDir = "C:\ADSync"
$ExportDir = "$ParentDir\Export"  
$ImportDir = "$ParentDir\Import"  
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json" 

$UserSecretsPath = "secret/data/users"                 
$AdminSecretPath = "secret/data/ad-admin"              
$TargetOU        = "OU=Supplier,DC=ng,DC=local"        
$PasswordLogDir  = "$ParentDir\Users"                  

$StateFileName = "AD_State_Export.json"                
$SignatureFileName = "AD_State_Export.hmac"            
$BackupKeyFileName = "transport-key.backup"            

# --- 2. LDAP ATTRIBUTE MAPPING ---
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

# --- 3. PREREQUISITE CHECKS ---
if (Test-Path $KeysFile) {
    $BaoToken = (Get-Content $KeysFile | ConvertFrom-Json).root_token
} else {
    Write-Error "CRITICAL: vault_keys.json not found. Run Invoke-BaoAutomation.ps1 first."
    exit
}

# --- 4. CORE UTILITY FUNCTIONS ---

function Invoke-Bao {
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
        $result = Invoke-RestMethod @params
        if ($result.data.data) { return $result.data.data }
        if ($result.data) { return $result.data }
        return $result
    } catch { return $null }
}

function Write-SyncLog {
    param($Msg, $Type = "Information", $Category = "GENERAL")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FormattedMsg = "[$Category] $Msg"
    Write-Host "[$Timestamp] [$Type] $FormattedMsg"
    try {
        $EventEntryType = if ($Type -eq "Error") { "Error" } elseif ($Type -eq "Warning") { "Warning" } else { "Information" }
        Write-EventLog -LogName "ADSync" -Source "ADSyncScript" -EntryType $EventEntryType -EventId 1000 -Message $FormattedMsg
    } catch {}
}

function Initialize-TransitEngine {
    param($KeyBackupPath)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    
    try { Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/sys/mounts/transit" -Headers $headers -Method Post -Body (@{ type = "transit" } | ConvertTo-Json) -ErrorAction SilentlyContinue } catch {}

    if (Test-Path $KeyBackupPath) {
        if ($null -eq (Invoke-Bao -Method Get -Path "transit/keys/transport-key")) {
            $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
            Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json)
            Write-SyncLog "Asymmetric Transport Key Restored from backup." -Category "SECURITY"
        }
    }
    
    if ($null -eq (Invoke-Bao -Method Get -Path "transit/keys/transport-key")) {
        Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/keys/transport-key" -Headers $headers -Method Post -Body (@{ 
            type = "rsa-4096"; 
            exportable = $true; 
            allow_plaintext_backup = $true 
        } | ConvertTo-Json)
        Write-SyncLog "Initialized new RSA-4096 Asymmetric Key." -Category "SECURITY"
    }

    if ($Global:Mode -eq "Export") {
        $backup = Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/backup/transport-key" -Headers $headers -Method Get
        if ($backup.data.backup) { $backup.data.backup | Out-File $KeyBackupPath -Encoding ascii -Force }
    }
}

function Protect-Data {
    param([string]$Plaintext)
    $Base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plaintext))
    $Result = Invoke-Bao -Method Post -Path "transit/encrypt/transport-key" -Body @{ plaintext = $Base64 }
    return $Result.ciphertext
}

function Unprotect-Data {
    param([string]$Ciphertext)
    $Result = Invoke-Bao -Method Post -Path "transit/decrypt/transport-key" -Body @{ ciphertext = $Ciphertext }
    $Bytes = [Convert]::FromBase64String($Result.plaintext)
    return [System.Text.Encoding]::UTF8.GetString($Bytes)
}

# --- 5. EXPORT WORKFLOW (Source Server) ---

function Export-ADState {
    Write-SyncLog "Starting Asymmetric Export Mode -> Scope: $TargetOU" -Category "EXPORT"
    if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }
    if (!(Test-Path $PasswordLogDir)) { New-Item -ItemType Directory -Path $PasswordLogDir -Force | Out-Null }
    
    Initialize-TransitEngine -KeyBackupPath "$ExportDir\$BackupKeyFileName"

    $Users = Get-ADUser -Filter * -SearchBase $TargetOU -Properties ($AttrMap.Keys + @("MemberOf", "SamAccountName"))
    $ExportUsers = @()

    foreach ($U in $Users) {
        $Secret = Invoke-Bao -Method Get -Path "$UserSecretsPath/$($U.SamAccountName)"
        
        if ($null -eq $Secret) {
            $Pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
            Invoke-Bao -Method Post -Path "$UserSecretsPath/$($U.SamAccountName)" -Body @{ data = @{ password = $Pass } }
            $Secret = @{ password = $Pass }
            
            $PassFilePath = "$PasswordLogDir\$($U.SamAccountName).txt"
            "User: $($U.SamAccountName)`r`nGenerated Password: $Pass`r`nDate: $(Get-Date)" | Out-File $PassFilePath -Force
            Write-SyncLog "Generated new password for $($U.SamAccountName). File: $PassFilePath" -Category "CRUD-CREATE"
        }
        
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
        Write-SyncLog "Staged user for export: $($U.SamAccountName)" -Category "EXPORT-READ"
    }
    
    $Export = @{ Users = $ExportUsers }
    $StatePath = "$ExportDir\$StateFileName"
    $SigPath = "$ExportDir\$SignatureFileName"
    
    $Export | ConvertTo-Json -Depth 10 | Out-File $StatePath
    
    $Bytes = [System.IO.File]::ReadAllBytes($StatePath)
    $Sig = Invoke-Bao -Method Post -Path "transit/hmac/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes) }
    $Sig.hmac | Out-File $SigPath -Encoding ascii
    
    Write-SyncLog "Export Complete. Payload and Signature generated." -Category "EXPORT"
}

# --- 6. IMPORT WORKFLOW (Target Server) ---

function Import-ADState {
    Write-SyncLog "Starting Enforced Import Mode -> Target OU: $TargetOU" -Category "IMPORT"
    
    $StatePath = "$ImportDir\$StateFileName"
    $SigPath = "$ImportDir\$SignatureFileName"
    $KeyBackupPath = "$ImportDir\$BackupKeyFileName"

    if (!(Test-Path $StatePath)) { Write-SyncLog "No state file found at $StatePath" -Type Warning -Category "IMPORT"; return }
    Initialize-TransitEngine -KeyBackupPath $KeyBackupPath
    
    $Bytes = [System.IO.File]::ReadAllBytes($StatePath)
    $HMAC = (Get-Content $SigPath).Trim()
    
    if ((Invoke-Bao -Method Post -Path "transit/verify/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes); hmac = $HMAC }).valid -ne $true) {
        Write-SyncLog "CRITICAL: Signature mismatch! Payload rejected." -Type Error -Category "SECURITY"
        return
    }

    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))
    $Data = Get-Content $StatePath | ConvertFrom-Json
    
    foreach ($SU in $Data.Users) {
        try {
            $PlainPass = Unprotect-Data -Ciphertext $SU.ProtectedPass
            $SP = $PlainPass | ConvertTo-SecureString -AsPlainText -Force
            
            $ReconcileMap = @{}
            foreach ($P in $SU.Attributes.PSObject.Properties) {
                if ($AttrMap[$P.Name]) { 
                    $ReconcileMap[$AttrMap[$P.Name]] = $P.Value 
                }
            }

            $ObjName = if ($SU.DisplayName) { $SU.DisplayName } else { $SU.SamAccountName }
            $TU = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -Properties ($AttrMap.Values + "MemberOf") -ErrorAction SilentlyContinue
            
            if (!$TU) {
                # [CREATE] User
                New-ADUser -Name $ObjName -SamAccountName $SU.SamAccountName -Path $TargetOU `
                           -AccountPassword $SP -Enabled $true -Credential $Creds `
                           -PasswordNeverExpires $true -CannotChangePassword $true `
                           -OtherAttributes $ReconcileMap
                Write-SyncLog "CREATE SUCCESS: Created new user account '$($SU.SamAccountName)'" -Category "CRUD-CREATE"
                $TU = Get-ADUser -Identity $SU.SamAccountName -Properties ($AttrMap.Values + "MemberOf")
            } else {
                # [UPDATE] User Attributes
                $Updates = @{}
                foreach ($LdapAttr in $ReconcileMap.Keys) {
                    $SourceVal = $ReconcileMap[$LdapAttr]
                    $TargetVal = $TU.$LdapAttr
                    if ($SourceVal -ne $TargetVal) {
                        $Updates[$LdapAttr] = $SourceVal
                        Write-SyncLog "DRIFT DETECTED: User '$($SU.SamAccountName)' property '$LdapAttr' mismatched. Overwriting with source data." -Category "CRUD-UPDATE"
                    }
                }

                if ($Updates.Count -gt 0) {
                    Set-ADUser -Identity $TU.DistinguishedName -Replace $Updates -Credential $Creds
                    Write-SyncLog "UPDATE SUCCESS: Synchronized $($Updates.Count) attributes for '$($SU.SamAccountName)'" -Category "CRUD-UPDATE"
                }

                Set-ADAccountPassword -Identity $TU.DistinguishedName -NewPassword $SP -Reset -Credential $Creds
                Set-ADUser -Identity $TU.DistinguishedName -PasswordNeverExpires $true -CannotChangePassword $true -Credential $Creds
                Write-SyncLog "PASSWORD SYNC: Reset password for '$($SU.SamAccountName)' to match source." -Category "CRUD-UPDATE"
            }

            # [RECONCILE] Groups (Create & Membership)
            $SourceGroups = if ($SU.Groups) { $SU.Groups } else { @() }
            $CurrentGroups = @()
            if ($TU.MemberOf) {
                foreach ($gDn in $TU.MemberOf) {
                    $g = Get-ADGroup -Identity $gDn -ErrorAction SilentlyContinue
                    if ($g) { $CurrentGroups += $g.SamAccountName }
                }
            }

            foreach ($GroupName in $SourceGroups) {
                $TargetGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction SilentlyContinue
                if (!$TargetGroup) {
                    # [CREATE] Group
                    New-ADGroup -Name $GroupName -SamAccountName $GroupName -Path $TargetOU -GroupScope Global -Credential $Creds
                    $TargetGroup = Get-ADGroup -Identity $GroupName
                    Write-SyncLog "CREATE SUCCESS: Created missing security group '$GroupName'" -Category "CRUD-CREATE"
                }
                if ($CurrentGroups -notcontains $GroupName) {
                    # [UPDATE] Add to Group
                    Add-ADGroupMember -Identity $TargetGroup.DistinguishedName -Members $TU.DistinguishedName -Credential $Creds
                    Write-SyncLog "GROUP ADD: User '$($SU.SamAccountName)' added to group '$GroupName'" -Category "CRUD-UPDATE"
                }
            }

            foreach ($GroupName in $CurrentGroups) {
                if ($SourceGroups -notcontains $GroupName) {
                    # [DELETE] Membership
                    $TargetGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction SilentlyContinue
                    if ($TargetGroup) {
                        Remove-ADGroupMember -Identity $TargetGroup.DistinguishedName -Members $TU.DistinguishedName -Confirm:$false -Credential $Creds
                        Write-SyncLog "GROUP REMOVE: User '$($SU.SamAccountName)' removed from group '$GroupName' (Source Removal)" -Category "CRUD-DELETE"
                    }
                }
            }
        } catch { 
            Write-SyncLog "RECONCILE ERROR: Failed processing '$($SU.SamAccountName)': $($_.Exception.Message)" -Type Warning -Category "IMPORT"
        }
    }
}

# --- 7. EXECUTION LOGIC ---
if (Test-Path "$ImportDir\$StateFileName") { 
    $Global:Mode = "Import"
    Import-ADState 
} else { 
    $Global:Mode = "Export"
    Export-ADState 
}