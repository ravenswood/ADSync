<#
.SYNOPSIS
    Primary Active Directory Synchronization and Secure Transport Script.
    Name: Sync-AD-Transport.ps1
    Version: 12.0
    
.DESCRIPTION
    v12.0: 
    - Implemented $OUExcludeFilters variable array for easy configuration.
    - Added logic to strip filtered OUs/Users/Groups from the import payload.
    - Automated purge of objects in AD that fall under excluded filters.

.NOTES
    Target OU: "OU=RBAC,DC=jml,DC=local"
#>

# --- 1. GLOBAL CONFIGURATION & FILE PATHS ---
$ParentDir = "C:\ADSync"
$ExportDir = "$ParentDir\Export"           
$ImportDir = "$ParentDir\Import"           
$UserLogDir = "$ParentDir\Users"           
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json" 

$TargetOU = "OU=RBAC,DC=jml,DC=local"

# --- OU EXCLUSION FILTERS ---
# Any OU path matching these wildcard patterns will be ignored during import.
# Objects existing in these OUs in the Target AD will be DELETED.
$OUExcludeFilters = @(
    "*Disabled Users*",
    "*Staging*",
    "*Testing*",
    "OU=Temporary*"
)

$UserSecretsPath = "secret/data/users"                 
$AdminSecretPath = "secret/data/ad-admin"              

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
    Write-Error "CRITICAL: vault_keys.json not found."
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
                $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
                Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json)
            } else { Write-Error "CRITICAL: Backup file missing."; exit }
        }
    } else {
        if ($null -eq $keyCheck) {
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
        $RelativePath = $OU.DistinguishedName.Replace(",$TargetOU", "").Trim(',')
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
        }
        
        $RelOU = ($U.DistinguishedName -replace "^CN=[^,]+,","").Replace(",$TargetOU", "").Trim(',')
        if ($RelOU -eq $U.DistinguishedName) { $RelOU = "" } 

        $UserMap = @{ SamAccountName = $U.SamAccountName; RelativeOU = $RelOU; ProtectedPass = Protect-Data -Plaintext $Secret.password; Groups = @(); Attributes = @{} }
        foreach ($Key in $AttrMap.Keys) { if ($U.$Key) { $UserMap.Attributes[$Key] = $U.$Key.ToString() } }
        if ($U.MemberOf) { foreach ($g in $U.MemberOf) { $UserMap.Groups += ($g -split ',')[0].Replace("CN=","") } }
        $ExportUsers += $UserMap
    }

    $Groups = Get-ADGroup -Filter * -SearchBase $TargetOU
    $ExportGroups = @()
    foreach ($G in $Groups) {
        $RelOU = ($G.DistinguishedName -replace "^CN=[^,]+,","").Replace(",$TargetOU", "").Trim(',')
        if ($RelOU -eq $G.DistinguishedName) { $RelOU = "" }
        $ExportGroups += @{ Name = $G.Name; SamAccountName = $G.SamAccountName; RelativeOU = $RelOU }
    }

    @{ OUs = $ExportOUs; Users = $ExportUsers; Groups = $ExportGroups } | ConvertTo-Json -Depth 10 | Out-File "$ExportDir\$StateFileName"
    Write-SyncLog "Export complete." -Category "EXPORT"
}

# --- 6. IMPORT WORKFLOW ---

function Import-ADState {
    Write-SyncLog "Starting AD Import..." -Category "IMPORT"
    $Data = Get-Content "$ImportDir\$StateFileName" | ConvertFrom-Json
    Initialize-TransitEngine -KeyBackupPath "$ImportDir\$BackupKeyFileName"

    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))

    # --- 6a. FILTER PAYLOAD BASED ON $OUExcludeFilters ---
    if ($OUExcludeFilters -and $OUExcludeFilters.Count -gt 0) {
        Write-SyncLog "Applying exclusion filters to import payload..." -Category "IMPORT"
        
        # Identify OUs to exclude
        $OUsToRemove = $Data.OUs | Where-Object {
            $path = $_.RelativePath
            $isMatch = $false
            foreach ($filter in $OUExcludeFilters) { if ($path -like $filter) { $isMatch = $true; break } }
            $isMatch
        } | ForEach-Object { $_.RelativePath }

        if ($OUsToRemove.Count -gt 0) {
            # 1. Filter the OU list
            $Data.OUs = $Data.OUs | Where-Object { $_.RelativePath -notin $OUsToRemove }
            
            # 2. Filter Users belonging to those OUs
            $OriginalUserCount = $Data.Users.Count
            $Data.Users = $Data.Users | Where-Object { $_.RelativeOU -notin $OUsToRemove }
            
            # 3. Filter Groups belonging to those OUs
            $OriginalGroupCount = $Data.Groups.Count
            $Data.Groups = $Data.Groups | Where-Object { $_.RelativeOU -notin $OUsToRemove }

            Write-SyncLog "Exclusion Summary: $($OUsToRemove.Count) OUs, $($OriginalUserCount - $Data.Users.Count) Users, and $($OriginalGroupCount - $Data.Groups.Count) Groups stripped from import." -Category "IMPORT" -Type Warning
        }
    }

    function Initialize-OUPath {
        param([string]$RelativePath, [System.Management.Automation.PSCredential]$Credential)
        if ([string]::IsNullOrWhiteSpace($RelativePath)) { return }
        $FullDN = "$RelativePath,$TargetOU"
        if (!(Get-ADObject -Filter "DistinguishedName -eq '$FullDN'" -ErrorAction SilentlyContinue)) {
            $Parts = $RelativePath -split ","
            if ($Parts.Count -gt 1) { Initialize-OUPath -RelativePath (($Parts[1..($Parts.Count-1)]) -join ",") -Credential $Credential }
            $ParentDN = if ($Parts.Count -gt 1) { (($Parts[1..($Parts.Count-1)]) -join ",") + ",$TargetOU" } else { $TargetOU }
            New-ADOrganizationalUnit -Name ($Parts[0] -replace "OU=","") -Path $ParentDN -ProtectedFromAccidentalDeletion $false -Credential $Credential
        }
    }

    # 1. Create/Ensure OUs
    foreach ($OU in $Data.OUs) { Initialize-OUPath -RelativePath $OU.RelativePath -Credential $Creds }

    # 2. Reconcile Groups (Includes Purge)
    $SourceGroupSams = $Data.Groups | ForEach-Object { $_.SamAccountName }
    Get-ADGroup -Filter * -SearchBase $TargetOU -Credential $Creds | ForEach-Object {
        if ($_.SamAccountName -notin $SourceGroupSams) {
            Write-SyncLog "PURGING GROUP (Not in source/filtered): $($_.SamAccountName)" -Category "RECONCILE" -Type Warning
            Remove-ADGroup -Identity $_.DistinguishedName -Confirm:$false -Credential $Creds
        }
    }
    foreach ($G in $Data.Groups) {
        if (!(Get-ADGroup -Filter "SamAccountName -eq '$($G.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $G.Name -SamAccountName $G.SamAccountName -Path ("$($G.RelativeOU),$TargetOU".Trim(',')) -GroupScope Global -Credential $Creds
        }
    }

    # 3. Reconcile Users (Includes Purge)
    $SourceUserSams = $Data.Users | ForEach-Object { $_.SamAccountName }
    Get-ADUser -Filter * -SearchBase $TargetOU -Credential $Creds | ForEach-Object {
        if ($_.SamAccountName -notin $SourceUserSams) {
            Write-SyncLog "PURGING USER (Not in source/filtered): $($_.SamAccountName)" -Category "RECONCILE" -Type Warning
            Remove-ADUser -Identity $_.DistinguishedName -Confirm:$false -Credential $Creds
        }
    }
    foreach ($SU in $Data.Users) {
        $Pass = Unprotect-Data -Ciphertext $SU.ProtectedPass
        $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -Properties $LdapProperties -ErrorAction SilentlyContinue
        
        $LdapChanges = @{}
        foreach ($Prop in $SU.Attributes.PSObject.Properties) {
            if ($AttrMap[$Prop.Name] -and $Prop.Value -ne $ExistingUser.$($AttrMap[$Prop.Name])) { $LdapChanges[$AttrMap[$Prop.Name]] = $Prop.Value }
        }

        if (!$ExistingUser) {
            $UP = @{ Name=$SU.SamAccountName; SamAccountName=$SU.SamAccountName; Path=("$($SU.RelativeOU),$TargetOU".Trim(',')); AccountPassword=($Pass | ConvertTo-SecureString -AsPlainText -Force); Enabled=$true; Credential=$Creds; PasswordNeverExpires=$true; ChangePasswordAtLogon=$false; CannotChangePassword=$true; OtherAttributes=$LdapChanges }
            New-ADUser @UP
        } elseif ($LdapChanges.Count -gt 0) { Set-ADUser -Identity $SU.SamAccountName -Replace $LdapChanges -Credential $Creds }

        $CurrentGroups = (Get-ADPrincipalGroupMembership -Identity $SU.SamAccountName -Credential $Creds | Select-Object -ExpandProperty Name)
        foreach ($grp in $SU.Groups) { if ($grp -notin $CurrentGroups) { Add-ADGroupMember -Identity $grp -Members $SU.SamAccountName -Credential $Creds -ErrorAction SilentlyContinue } }
    }

    # 4. Final Cleanup: Delete empty/obsolete OUs
    $ValidOUDNs = $Data.OUs | ForEach-Object { "$($_.RelativePath),$TargetOU".Trim(',') }
    Get-ADOrganizationalUnit -Filter * -SearchBase $TargetOU -SearchScope Subtree -Credential $Creds | 
        Where-Object { $_.DistinguishedName -ne $TargetOU -and $_.DistinguishedName -notin $ValidOUDNs } |
        Sort-Object { $_.DistinguishedName.Length } -Descending | ForEach-Object {
            Write-SyncLog "PURGING OBSOLETE OU: $($_.DistinguishedName)" -Category "RECONCILE" -Type Warning
            Remove-ADOrganizationalUnit -Identity $_.DistinguishedName -Recursive -Confirm:$false -Credential $Creds
        }

    Remove-Item "$ImportDir\*" -Force
}

if ($Global:Mode -eq "Import") { Import-ADState } else { Export-ADState }