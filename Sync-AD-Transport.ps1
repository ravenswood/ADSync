<#
.SYNOPSIS
    Primary Active Directory Synchronization and Secure Transport Script.
    Name: Sync-AD-Transport.ps1
    Version: 5.2
    
.DESCRIPTION
    Facilitates secure AD sync between air-gapped environments using OpenBao.
    v5.2: Modified logging logic to only write password reference files 
    when a NEW password is created for a user.

.NOTES
    Target OU: "OU=Supplier,DC=jml,DC=local"
    Audit Dir: "C:\ADSync\Users"
#>

# --- 1. GLOBAL CONFIGURATION & FILE PATHS ---
$ParentDir = "C:\ADSync"
$ExportDir = "$ParentDir\Export"  
$ImportDir = "$ParentDir\Import"  
$UserLogDir = "$ParentDir\Users" # Path for plaintext password reference files
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json" 

# Active Directory Scopes
$TargetOU = "OU=Supplier,DC=jml,DC=local"

# Vault Paths
$UserSecretsPath = "secret/data/users"                 
$AdminSecretPath = "secret/data/ad-admin"              

# File naming conventions for transport
$StateFileName     = "AD_State_Export.json"                
$SignatureFileName = "AD_State_Export.hmac"            
$BackupKeyFileName = "transport-key.backup"            

# --- 2. LDAP ATTRIBUTE MAPPING (EXPANDED) ---
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
    "EmployeeID"      = "employeeID"
    "EmployeeNumber"  = "employeeNumber"
    "FacsimileTelephoneNumber" = "facsimileTelephoneNumber"
}

# --- 3. PREREQUISITE CHECKS ---
if (Test-Path $KeysFile) {
    $BaoToken = (Get-Content $KeysFile | ConvertFrom-Json).root_token
} else {
    Write-Error "CRITICAL: vault_keys.json not found."
    exit
}

if (!(Test-Path $UserLogDir)) { New-Item -ItemType Directory -Path $UserLogDir -Force | Out-Null }

# Define Mode Early
if (Test-Path "$ImportDir\$StateFileName") { $Global:Mode = "Import" } else { $Global:Mode = "Export" }

# --- 4. CORE UTILITY FUNCTIONS ---

function Invoke-Bao {
    param([string]$Method, [string]$Path, [object]$Body = $null)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    $params = @{ Uri = "http://127.0.0.1:8200/v1/$Path"; Headers = $headers; Method = $Method; ErrorAction = "Stop" }
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
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:ss"
    $FormattedMsg = "[$Category] $Msg"
    Write-Host "[$Timestamp] [$Type] $FormattedMsg"
    try {
        $EntryType = if ($Type -eq "Error") { "Error" } elseif ($Type -eq "Warning") { "Warning" } else { "Information" }
        Write-EventLog -LogName "ADSync" -Source "ADSyncScript" -EntryType $EntryType -EventId 1000 -Message $FormattedMsg
    } catch {}
}

function Initialize-TransitEngine {
    param($KeyBackupPath)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    try { 
        Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/sys/mounts/transit" -Headers $headers -Method Post -Body (@{ type = "transit" } | ConvertTo-Json) -ErrorAction SilentlyContinue 
    } catch {}

    $keyFound = $false
    try {
        $check = Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/keys/transport-key" -Headers $headers -Method Get -ErrorAction Stop
        if ($check.data.name -eq "transport-key") { $keyFound = $true }
    } catch { $keyFound = $false }

    if (-not $keyFound) {
        if ($Global:Mode -eq "Import") {
            if (Test-Path $KeyBackupPath) {
                Write-SyncLog "Key not found. Restoring transport-key from payload backup..." -Category "SECURITY"
                $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
                try {
                    Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json) -ErrorAction Stop
                } catch {
                    Write-SyncLog "Failed to restore key: $($_.Exception.Message)" -Type Error -Category "SECURITY"; exit
                }
            } else {
                Write-SyncLog "CRITICAL: transport-key.backup is missing!" -Type Error; exit
            }
        } else {
            Write-SyncLog "Key not found. Generating new RSA-4096 transport-key..." -Category "SECURITY"
            Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/keys/transport-key" -Headers $headers -Method Post -Body (@{ type = "rsa-4096"; exportable = $true; allow_plaintext_backup = $true } | ConvertTo-Json)
        }
    }

    if ($Global:Mode -eq "Export") {
        $backup = Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/backup/transport-key" -Headers $headers -Method Get
        if ($backup.data.backup) { $backup.data.backup | Out-File $KeyBackupPath -Encoding ascii -Force }
    }
}

function Protect-Data { param([string]$Plaintext)
    $Base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plaintext))
    return (Invoke-Bao -Method Post -Path "transit/encrypt/transport-key" -Body @{ plaintext = $Base64 }).ciphertext
}

function Unprotect-Data { param([string]$Ciphertext)
    $Result = Invoke-Bao -Method Post -Path "transit/decrypt/transport-key" -Body @{ ciphertext = $Ciphertext }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.plaintext))
}

# --- 5. EXPORT WORKFLOW ---

function Export-ADState {
    Write-SyncLog "Starting AD Export..." -Category "EXPORT"
    if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }
    Initialize-TransitEngine -KeyBackupPath "$ExportDir\$BackupKeyFileName"
    
    $Users = Get-ADUser -Filter * -SearchBase $TargetOU -Properties ($AttrMap.Keys + @("MemberOf"))
    $ExportUsers = @()
    $FoundGroups = @{} 

    foreach ($U in $Users) {
        $Secret = Invoke-Bao -Method Get -Path "$UserSecretsPath/$($U.SamAccountName)"
        
        # LOGIC CHANGE: Only generate and write to file if the secret doesn't exist
        if ($null -eq $Secret) {
            # Generate complex password if not in Vault
            $Pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
            Invoke-Bao -Method Post -Path "$UserSecretsPath/$($U.SamAccountName)" -Body @{ data = @{ password = $Pass } }
            $Secret = @{ password = $Pass }
            
            # LOGGING: Write password to users directory for admin reference ONLY on creation
            $PassFilePath = "$UserLogDir\$($U.SamAccountName).txt"
            "User: $($U.SamAccountName)`r`nPassword: $($Secret.password)`r`nExport Date: $(Get-Date)`r`nNote: Initial password generation." | Out-File $PassFilePath -Force
            Write-SyncLog "NEW USER DETECTED: Generated password and log file for $($U.SamAccountName)" -Category "SECURITY"
        }
        
        $EncPass = Protect-Data -Plaintext $Secret.password
        $GroupNames = @()
        if ($U.MemberOf) {
            foreach ($gDn in $U.MemberOf) {
                $gName = ($gDn -split ',')[0].Replace("CN=","")
                $GroupNames += $gName; $FoundGroups[$gName] = $true
            }
        }
        $UserMap = @{ SamAccountName = $U.SamAccountName; DisplayName = $U.DisplayName; ProtectedPass = $EncPass; Groups = $GroupNames; Attributes = @{} }
        foreach ($Key in $AttrMap.Keys) { if ($U.$Key) { $UserMap.Attributes[$Key] = $U.$Key.ToString() } }
        $ExportUsers += $UserMap
    }
    $Export = @{ Users = $ExportUsers; ValidGroups = $FoundGroups.Keys }
    $Export | ConvertTo-Json -Depth 10 | Out-File "$ExportDir\$StateFileName"
    
    $Bytes = [System.IO.File]::ReadAllBytes("$ExportDir\$StateFileName")
    $Sig = Invoke-Bao -Method Post -Path "transit/hmac/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes) }
    $Sig.hmac | Out-File "$ExportDir\$SignatureFileName" -Encoding ascii
    Write-SyncLog "Export Complete. Count: $($ExportUsers.Count)" -Category "EXPORT"
}

# --- 6. IMPORT WORKFLOW ---

function Import-ADState {
    Write-SyncLog "Starting Import Reconciliation..." -Category "IMPORT"
    $StatePath = "$ImportDir\$StateFileName"; $SigPath = "$ImportDir\$SignatureFileName"; $KeyPath = "$ImportDir\$BackupKeyFileName"
    if (!(Test-Path $StatePath)) { return }
    
    Initialize-TransitEngine -KeyBackupPath $KeyPath
    
    $Bytes = [System.IO.File]::ReadAllBytes($StatePath); $HMAC = (Get-Content $SigPath).Trim()
    if ((Invoke-Bao -Method Post -Path "transit/verify/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes); hmac = $HMAC }).valid -ne $true) {
        Write-SyncLog "Signature Invalid!" -Type Error -Category "SECURITY"; return
    }
    
    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    if ($null -eq $Admin) { Write-SyncLog "CRITICAL: AD Admin credentials missing!" -Type Error; return }
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))
    
    $Data = Get-Content $StatePath | ConvertFrom-Json
    $SourceUserList = @(); $ActualGroupsInPayload = @()
    if ($Data.ValidGroups) { $ActualGroupsInPayload = @($Data.ValidGroups) }

    # --- Phase 1: Group Provisioning ---
    foreach ($GroupName in $ActualGroupsInPayload) {
        $TargetGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction SilentlyContinue
        if (!$TargetGroup) {
            New-ADGroup -Name $GroupName -SamAccountName $GroupName -Path $TargetOU -GroupScope Global -Credential $Creds
            Write-SyncLog "CREATE GROUP: '$GroupName' provisioned." -Category "CRUD-CREATE"
        }
    }

    # --- Phase 2: User Reconciliation & Membership ---
    foreach ($SU in $Data.Users) {
        $SourceUserList += $SU.SamAccountName
        try {
            $PlainPass = Unprotect-Data -Ciphertext $SU.ProtectedPass
            $SP = $PlainPass | ConvertTo-SecureString -AsPlainText -Force
            $ReconcileMap = @{}
            foreach ($P in $SU.Attributes.PSObject.Properties) { if ($AttrMap[$P.Name]) { $ReconcileMap[$AttrMap[$P.Name]] = $P.Value } }
            
            $TU = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -Properties ($AttrMap.Values + @("MemberOf")) -ErrorAction SilentlyContinue
            
            if (!$TU) {
                $ObjName = if ($SU.DisplayName) { $SU.DisplayName } else { $SU.SamAccountName }
                New-ADUser -Name $ObjName -SamAccountName $SU.SamAccountName -Path $TargetOU -AccountPassword $SP -Enabled $true -Credential $Creds -PasswordNeverExpires $true -CannotChangePassword $true -OtherAttributes $ReconcileMap
                Write-SyncLog "CREATE USER: '$($SU.SamAccountName)' created." -Category "CRUD-CREATE"
                $TU = Get-ADUser -Identity $SU.SamAccountName -Properties ($AttrMap.Values + @("MemberOf"))
            } else {
                $Updates = @{}
                foreach ($LdapAttr in $ReconcileMap.Keys) {
                    if ($ReconcileMap[$LdapAttr] -ne $TU.$LdapAttr) { $Updates[$LdapAttr] = $ReconcileMap[$LdapAttr] }
                }
                if ($Updates.Count -gt 0) { Set-ADUser -Identity $TU.DistinguishedName -Replace $Updates -Credential $Creds }
                Set-ADAccountPassword -Identity $TU.DistinguishedName -NewPassword $SP -Reset -Credential $Creds
                Write-SyncLog "UPDATE USER: '$($SU.SamAccountName)' attributes/password synced." -Category "CRUD-UPDATE"
            }

            # MEMBERSHIP LOGIC
            $SourceGroups = @()
            if ($SU.Groups) { $SourceGroups = @($SU.Groups) }
            
            $CurrentGroups = @()
            if ($TU.MemberOf) {
                foreach ($gDn in $TU.MemberOf) { $CurrentGroups += (Get-ADGroup -Identity $gDn).SamAccountName }
            }

            foreach ($gName in $SourceGroups) {
                if ($CurrentGroups -notcontains $gName) {
                    Add-ADGroupMember -Identity $gName -Members $TU.DistinguishedName -Credential $Creds
                    Write-SyncLog "JOIN: User '$($SU.SamAccountName)' -> '$gName'." -Category "CRUD-UPDATE"
                }
            }
            foreach ($gName in $CurrentGroups) {
                if ($SourceGroups -notcontains $gName) {
                    Remove-ADGroupMember -Identity $gName -Members $TU.DistinguishedName -Confirm:$false -Credential $Creds
                    Write-SyncLog "LEAVE: User '$($SU.SamAccountName)' <- '$gName'." -Category "CRUD-UPDATE"
                }
            }
        } catch { Write-SyncLog "Error on $($SU.SamAccountName): $($_.Exception.Message)" -Type Warning }
    }

    # --- Phase 3: Cleanup (AD Objects) ---
    Get-ADUser -Filter * -SearchBase $TargetOU | ForEach-Object {
        if ($SourceUserList -notcontains $_.SamAccountName) {
            Write-SyncLog "DELETE USER: '$($_.SamAccountName)' (Stale)." -Category "CRUD-DELETE"
            Remove-ADUser -Identity $_.DistinguishedName -Confirm:$false -Credential $Creds
            Invoke-Bao -Method Delete -Path "$UserSecretsPath/$($_.SamAccountName)"
        }
    }
    Get-ADGroup -Filter * -SearchBase $TargetOU | ForEach-Object {
        if ($ActualGroupsInPayload -notcontains $_.SamAccountName) {
            Write-SyncLog "DELETE GROUP: '$($_.SamAccountName)' (Stale)." -Category "CRUD-DELETE"
            Remove-ADGroup -Identity $_.DistinguishedName -Confirm:$false -Credential $Creds
        }
    }

    # --- Phase 4: Import Folder Cleanup ---
    Write-SyncLog "Finalizing: Purging import artifacts from $ImportDir..." -Category "IMPORT"
    $FilesToPurge = @($StatePath, $SigPath, $KeyPath)
    foreach ($File in $FilesToPurge) {
        if (Test-Path $File) {
            Remove-Item $File -Force
            Write-SyncLog "Purged artifact: $(Split-Path $File -Leaf)" -Category "CLEANUP"
        }
    }
}

# START EXECUTION
if ($Global:Mode -eq "Import") { Import-ADState } else { Export-ADState }