<#
.SYNOPSIS
    Primary Active Directory Synchronization and Secure Transport Script.
    Name: Sync-AD-Transport.ps1
    Version: 7.5
    
.DESCRIPTION
    v7.5: 
    - Forced 'PasswordNeverExpires' and 'CannotChangePassword' to $true on user creation.
    - Maintains v7.4 [PSCredential] type enforcement for Initialize-OUPath.
    - Maintains v7.2 property casting fix for Get-ADUser.

.NOTES
    Target OU: "OU=Supplier,DC=jml,DC=local"
#>

# --- 1. GLOBAL CONFIGURATION & FILE PATHS ---
$ParentDir = "C:\ADSync"
$ExportDir = "$ParentDir\Export"  
$ImportDir = "$ParentDir\Import"  
$UserLogDir = "$ParentDir\Users" 
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json" 

# Define the scope of the sync
$TargetOU = "OU=Supplier,DC=jml,DC=local"

# Vault API paths for identity and admin credentials
$UserSecretsPath = "secret/data/users"                 
$AdminSecretPath = "secret/data/ad-admin"              

# Transport artifact filenames
$StateFileName     = "AD_State_Export.json"                
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
}

[string[]]$LdapProperties = $AttrMap.Values | ForEach-Object { $_ }

# --- 3. PREREQUISITE CHECKS ---
if (Test-Path $KeysFile) {
    $BaoToken = (Get-Content $KeysFile | ConvertFrom-Json).root_token
} else {
    Write-Error "CRITICAL: vault_keys.json not found. API access is impossible."
    exit
}

if (!(Test-Path $UserLogDir)) { New-Item -ItemType Directory -Path $UserLogDir -Force | Out-Null }

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
        return $result.data
    } catch { return $null }
}

function Write-SyncLog {
    param($Msg, $Type = "Information", $Category = "GENERAL")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
    Write-Host "[$Timestamp] [$Type] [$Category] $Msg"
    try {
        Write-EventLog -LogName "ADSync" -Source "ADSyncScript" -EntryType ([System.Diagnostics.EventLogEntryType]::$Type) -EventId 1000 -Message "[$Category] $Msg"
    } catch { }
}

function Initialize-TransitEngine {
    param($KeyBackupPath)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    
    try { 
        Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/sys/mounts/transit" -Headers $headers -Method Post -Body (@{ type = "transit" } | ConvertTo-Json) -ErrorAction SilentlyContinue 
    } catch { }

    $keyCheck = Invoke-Bao -Method Get -Path "transit/keys/transport-key"

    if ($Global:Mode -eq "Import") {
        if ($null -eq $keyCheck) {
            if (Test-Path $KeyBackupPath) {
                Write-SyncLog "Key 'transport-key' missing. Restoring from backup..." -Category "SECURITY"
                $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
                Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json)
            } else {
                Write-Error "CRITICAL: Backup file missing at $KeyBackupPath. Cannot decrypt payload."
                exit
            }
        }
    } else {
        if ($null -eq $keyCheck) {
            Write-SyncLog "Creating new RSA-4096 transport key..." -Category "SECURITY"
            Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/keys/transport-key" -Headers $headers -Method Post -Body (@{ type = "rsa-4096"; exportable = $true; allow_plaintext_backup = $true } | ConvertTo-Json)
        }
        $backup = Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/backup/transport-key" -Headers $headers -Method Get
        if ($backup.data.backup) { $backup.data.backup | Out-File $KeyBackupPath -Encoding ascii -Force }
    }
}

function Protect-Data { 
    param([string]$Plaintext)
    $Base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plaintext))
    return (Invoke-Bao -Method Post -Path "transit/encrypt/transport-key" -Body @{ plaintext = $Base64 }).ciphertext
}

function Unprotect-Data { 
    param([string]$Ciphertext)
    $Result = Invoke-Bao -Method Post -Path "transit/decrypt/transport-key" -Body @{ ciphertext = $Ciphertext }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.plaintext))
}

# --- 5. EXPORT WORKFLOW ---

function Export-ADState {
    Write-SyncLog "Starting AD Export..." -Category "EXPORT"
    if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }
    Initialize-TransitEngine -KeyBackupPath "$ExportDir\$BackupKeyFileName"
    
    $OUs = Get-ADOrganizationalUnit -Filter * -SearchBase $TargetOU -SearchScope Subtree
    $ExportOUs = @()
    foreach ($OU in $OUs) {
        if ($OU.DistinguishedName -ieq $TargetOU) { continue }
        $RelativePath = $OU.DistinguishedName.Replace(",$TargetOU", "")
        $ExportOUs += @{ RelativePath = $RelativePath; Name = $OU.Name }
    }

    $Users = Get-ADUser -Filter * -SearchBase $TargetOU -Properties ($AttrMap.Keys + @("MemberOf"))
    $ExportUsers = @()
    foreach ($U in $Users) {
        $Secret = Invoke-Bao -Method Get -Path "$UserSecretsPath/$($U.SamAccountName)"
        if ($null -eq $Secret) {
            $Pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
            Invoke-Bao -Method Post -Path "$UserSecretsPath/$($U.SamAccountName)" -Body @{ data = @{ password = $Pass } }
            $Secret = @{ password = $Pass }
            "$($U.SamAccountName): $Pass" | Out-File "$UserLogDir\$($U.SamAccountName).txt"
        }
        
        $RelOU = $U.DistinguishedName -replace "^CN=[^,]+,",""
        $RelOU = $RelOU.Replace(",$TargetOU", "")
        if ($RelOU -eq $U.DistinguishedName) { $RelOU = "" } 

        $UserMap = @{ 
            SamAccountName = $U.SamAccountName; 
            RelativeOU = $RelOU; 
            ProtectedPass = Protect-Data -Plaintext $Secret.password; 
            Groups = @();
            Attributes = @{} 
        }
        
        foreach ($Key in $AttrMap.Keys) { if ($U.$Key) { $UserMap.Attributes[$Key] = $U.$Key.ToString() } }
        if ($U.MemberOf) { foreach ($g in $U.MemberOf) { $UserMap.Groups += ($g -split ',')[0].Replace("CN=","") } }
        $ExportUsers += $UserMap
    }

    $Groups = Get-ADGroup -Filter * -SearchBase $TargetOU
    $ExportGroups = @()
    foreach ($G in $Groups) {
        $RelOU = $G.DistinguishedName -replace "^CN=[^,]+,",""
        $RelOU = $RelOU.Replace(",$TargetOU", "")
        if ($RelOU -eq $G.DistinguishedName) { $RelOU = "" }
        $ExportGroups += @{ Name = $G.Name; SamAccountName = $G.SamAccountName; RelativeOU = $RelOU }
    }

    $Export = @{ OUs = $ExportOUs; Users = $ExportUsers; Groups = $ExportGroups }
    $Export | ConvertTo-Json -Depth 10 | Out-File "$ExportDir\$StateFileName"
    
    $Bytes = [System.IO.File]::ReadAllBytes("$ExportDir\$StateFileName")
    $Sig = Invoke-Bao -Method Post -Path "transit/hmac/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes) }
    $Sig.hmac | Out-File "$ExportDir\$SignatureFileName" -Encoding ascii
    Write-SyncLog "Export complete." -Category "EXPORT"
}

# --- 6. IMPORT WORKFLOW ---

function Import-ADState {
    Write-SyncLog "Starting AD Import..." -Category "IMPORT"
    $Data = Get-Content "$ImportDir\$StateFileName" | ConvertFrom-Json
    Initialize-TransitEngine -KeyBackupPath "$ImportDir\$BackupKeyFileName"

    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))

    function Initialize-OUPath {
        param(
            [string]$RelativePath, 
            [System.Management.Automation.PSCredential]$Credential
        )
        if ([string]::IsNullOrWhiteSpace($RelativePath)) { return }
        $CleanedPath = ($RelativePath -split "," | Where-Object { $_ -match "^OU=" }) -join ","
        if ([string]::IsNullOrWhiteSpace($CleanedPath)) { return }

        $FullDN = "$CleanedPath,$TargetOU"
        $ExistingOU = Get-ADObject -Filter "DistinguishedName -eq '$FullDN' -and ObjectClass -eq 'organizationalUnit'" -ErrorAction SilentlyContinue
        
        if (!$ExistingOU) {
            $Parts = $CleanedPath -split ","
            if ($Parts.Count -gt 1) {
                $ParentRel = ($Parts[1..($Parts.Count-1)]) -join ","
                Initialize-OUPath -RelativePath $ParentRel -Credential $Credential
            } else {
                $ParentRel = ""
            }
            $ParentDN = if ([string]::IsNullOrEmpty($ParentRel)) { $TargetOU } else { "$ParentRel,$TargetOU" }
            $OUName = ($Parts[0] -replace "OU=","")
            if (!(Get-ADObject -Filter "DistinguishedName -eq '$FullDN'" -ErrorAction SilentlyContinue)) {
                Write-SyncLog "Creating missing OU Container: $FullDN" -Category "RECONCILE"
                New-ADOrganizationalUnit -Name $OUName -Path $ParentDN -ProtectedFromAccidentalDeletion $false -Credential $Credential
            }
        }
    }

    foreach ($OU in $Data.OUs) { Initialize-OUPath -RelativePath $OU.RelativePath -Credential $Creds }

    foreach ($G in $Data.Groups) {
        Initialize-OUPath -RelativePath $G.RelativeOU -Credential $Creds
        $CleanedRelOU = ($G.RelativeOU -split "," | Where-Object { $_ -match "^OU=" }) -join ","
        $ParentPath = if ([string]::IsNullOrEmpty($CleanedRelOU)) { $TargetOU } else { "$CleanedRelOU,$TargetOU" }
        if (!(Get-ADGroup -Filter "SamAccountName -eq '$($G.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            Write-SyncLog "Creating Group: $($G.SamAccountName) in $ParentPath" -Category "RECONCILE"
            New-ADGroup -Name $G.Name -SamAccountName $G.SamAccountName -Path $ParentPath -GroupScope Global -Credential $Creds
        }
    }

    foreach ($SU in $Data.Users) {
        Initialize-OUPath -RelativePath $SU.RelativeOU -Credential $Creds
        $CleanedRelOU = ($SU.RelativeOU -split "," | Where-Object { $_ -match "^OU=" }) -join ","
        $ParentPath = if ([string]::IsNullOrEmpty($CleanedRelOU)) { $TargetOU } else { "$CleanedRelOU,$TargetOU" }
        
        $Pass = Unprotect-Data -Ciphertext $SU.ProtectedPass
        $SP = $Pass | ConvertTo-SecureString -AsPlainText -Force
        
        $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -Properties $LdapProperties -ErrorAction SilentlyContinue
        
        $LdapChanges = @{}
        foreach ($Prop in $SU.Attributes.PSObject.Properties) {
            $LdapName = $AttrMap[$Prop.Name]
            if ($LdapName) {
                $ExistingVal = if ($ExistingUser) { $ExistingUser.$LdapName } else { $null }
                if ($Prop.Value -ne $ExistingVal) { $LdapChanges[$LdapName] = $Prop.Value }
            }
        }

        if (!$ExistingUser) {
            $UserParams = @{
                Name = $SU.SamAccountName
                SamAccountName = $SU.SamAccountName
                Path = $ParentPath
                AccountPassword = $SP
                Enabled = $true
                Credential = $Creds
                PasswordNeverExpires = $true
                ChangePasswordAtLogon = $false
                CannotChangePassword = $true
                OtherAttributes = $LdapChanges
            }
            Write-SyncLog "CREATED USER: $($SU.SamAccountName)" -Category "RECONCILE"
            New-ADUser @UserParams
        } elseif ($LdapChanges.Count -gt 0) {
            Write-SyncLog "UPDATING USER: $($SU.SamAccountName)" -Category "RECONCILE"
            Set-ADUser -Identity $SU.SamAccountName -Replace $LdapChanges -Credential $Creds
        }

        $CurrentGroups = (Get-ADPrincipalGroupMembership -Identity $SU.SamAccountName -Credential $Creds | Select-Object -ExpandProperty Name)
        foreach ($grp in $SU.Groups) { 
            if ($grp -notin $CurrentGroups) {
                Add-ADGroupMember -Identity $grp -Members $SU.SamAccountName -Credential $Creds -ErrorAction SilentlyContinue 
            }
        }
    }
    Remove-Item "$ImportDir\*" -Force
}

if ($Global:Mode -eq "Import") { Import-ADState } else { Export-ADState }