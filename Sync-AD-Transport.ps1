<#
.SYNOPSIS
    Primary Active Directory Synchronization and Secure Transport Script.
    Name: Sync-AD-Transport.ps1
    Version: 13.9
    
.DESCRIPTION
    v13.9: 
    - Included deletion of group memberships: Users are now removed from groups
      that are not specified in the input JSON file.
    - Forced password reset on import: Existing users now have their passwords 
      overwritten with the value from the JSON payload.
    - Maintains Event ID 1000 logging and secure transport logic.

.NOTES
    Target OU: "OU=RBAC,DC=jml,DC=local"
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$LibraryPath
)

. "$PSScriptRoot\ADSyncLibrary.ps1"


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

if (!(Test-Path $PasswordLogDir)) { New-Item -ItemType Directory -Path $PasswordLogDir -Force | Out-Null }

if (Test-Path "$ImportDir\$StateFileName") { $Global:Mode = "Import" } else { $Global:Mode = "Export" }

# --- 4. CORE UTILITY FUNCTIONS ---


function Initialize-TransitEngine {
    <#
    .DESCRIPTION
        Ensures the OpenBao Transit Secret Engine is mounted and keys are ready.
    #>
    param($KeyBackupPath)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    try { 
        Invoke-RestMethod -Uri "$VaultAddr/v1/sys/mounts/transit" -Headers $headers -Method Post -Body (@{ type = "transit" } | ConvertTo-Json) -ErrorAction SilentlyContinue 
    } catch { }

    $keyCheck = Invoke-Bao -Method Get -Path "transit/keys/transport-key"

    if ($Global:Mode -eq "Import") {
        if ($null -eq $keyCheck) {
            if (Test-Path $KeyBackupPath) {
                Write-SyncLog "Restoring Transport Key from backup..." -Category "TRANSIT"
                $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
                Invoke-RestMethod -Uri "$VaultAddr/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json)
            } else { Write-Error "CRITICAL: Asymmetric key backup missing for Import."; exit }
        }
    } else {
        if ($null -eq $keyCheck) {
            Write-SyncLog "Generating new RSA-4096 Asymmetric Transport Key..." -Category "TRANSIT"
            Invoke-RestMethod -Uri "$VaultAddr/v1/transit/keys/transport-key" -Headers $headers -Method Post -Body (@{ type = "rsa-4096"; exportable = $true; allow_plaintext_backup = $true } | ConvertTo-Json)
        }
        $backup = Invoke-RestMethod -Uri "$VaultAddr/v1/transit/backup/transport-key" -Headers $headers -Method Get
        if ($backup.data.backup) { $backup.data.backup | Out-File $KeyBackupPath -Encoding ascii -Force }
    }
}

function Get-HMACSignature {
    <#
    .DESCRIPTION
        Generates SHA2-256 HMAC for state integrity.
    #>
    param([string]$DataString)
    $Base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($DataString))
    $Result = Invoke-Bao -Method Post -Path "transit/hmac/transport-key" -Body @{ input = $Base64Data; algorithm = "sha2-256" }
    return $Result.hmac
}

function Test-HMACSignature {
    <#
    .DESCRIPTION
        Verifies HMAC integrity.
    #>
    param([string]$DataString, [string]$Hmac)
    $Base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($DataString))
    $Result = Invoke-Bao -Method Post -Path "transit/verify/transport-key/sha2-256" -Body @{ input = $Base64Data; hmac = $Hmac }
    return $Result.valid
}

function Protect-ADData { 
    <#
    .DESCRIPTION
        Encrypts data with RSA-4096.
    #>
    param([string]$Plaintext)
    $Base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plaintext))
    return (Invoke-Bao -Method Post -Path "transit/encrypt/transport-key" -Body @{ plaintext = $Base64 }).ciphertext
}

function Unprotect-ADData { 
    <#
    .DESCRIPTION
        Decrypts data with RSA-4096.
    #>
    param([string]$Ciphertext)
    $Result = Invoke-Bao -Method Post -Path "transit/decrypt/transport-key" -Body @{ ciphertext = $Ciphertext }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.plaintext))
}

# --- 5. EXPORT WORKFLOW ---

function Export-ADState {
    <#
    .DESCRIPTION
        Exports AD state to signed JSON.
    #>
    Write-SyncLog "Starting AD Export (Read)..." -Category "EXPORT"
    if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }
    Initialize-TransitEngine -KeyBackupPath "$ExportDir\$BackupKeyFileName"
    
    $OUs = Get-ADOrganizationalUnit -Filter * -SearchBase $TargetOU -SearchScope Subtree
    $ExportOUs = @()
    foreach ($OU in $OUs) {
        if ($OU.DistinguishedName -ieq $TargetOU) { continue }
        $RelativePath = $OU.DistinguishedName.Replace(",$TargetOU", "").Trim(',')
        $ExportOUs += @{ RelativePath = $RelativePath; Name = $OU.Name }
    }
    Write-SyncLog "Collected $($ExportOUs.Count) OUs." -Category "EXPORT"

    $Users = Get-ADUser -Filter * -SearchBase $TargetOU -Properties ($AttrMap.Keys + @("MemberOf"))
    $ExportUsers = @()
    foreach ($U in $Users) {
        $Secret = Invoke-Bao -Method Get -Path "$UserSecretsPath/$($U.SamAccountName)"
        if ($null -eq $Secret) {
            Write-SyncLog "Generating new password for user: $($U.SamAccountName)" -Category "EXPORT"
            #$Pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
            $Pass = Get-StrongPassword
            Invoke-Bao -Method Post -Path "$UserSecretsPath/$($U.SamAccountName)" -Body @{ data = @{ password = $Pass } }
            $Secret = @{ password = $Pass }
            
            # Save the plain-text password to the user directory for manual reference
            $UserFilePath = Join-Path $UserLogDir "$($U.SamAccountName).txt"
            "User: $TargetUserID`r`nGenerated Password: $Pass`r`nDate: $(Get-Date)`r`n" | Out-File -FilePath $UserFilePath -Force
        }
        $RelOU = ($U.DistinguishedName -replace "^CN=[^,]+,","").Replace(",$TargetOU", "").Trim(',')
        if ($RelOU -eq $U.DistinguishedName) { $RelOU = "" } 
        $UserMap = @{ SamAccountName = $U.SamAccountName; RelativeOU = $RelOU; ProtectedPass = Protect-ADData -Plaintext $Secret.password; Groups = @(); Attributes = @{} }
        foreach ($Key in $AttrMap.Keys) { if ($U.$Key) { $UserMap.Attributes[$Key] = $U.$Key.ToString() } }
        if ($U.MemberOf) { foreach ($g in $U.MemberOf) { $UserMap.Groups += ($g -split ',')[0].Replace("CN=","") } }
        $ExportUsers += $UserMap
    }
    Write-SyncLog "Collected $($ExportUsers.Count) Users." -Category "EXPORT"

    $Groups = Get-ADGroup -Filter * -SearchBase $TargetOU
    $ExportGroups = @()
    foreach ($G in $Groups) {
        $RelOU = ($G.DistinguishedName -replace "^CN=[^,]+,","").Replace(",$TargetOU", "").Trim(',')
        if ($RelOU -eq $G.DistinguishedName) { $RelOU = "" }
        $ExportGroups += @{ Name = $G.Name; SamAccountName = $G.SamAccountName; RelativeOU = $RelOU }
    }
    Write-SyncLog "Collected $($ExportGroups.Count) Groups." -Category "EXPORT"

    if ($OUExcludeFilters -and $OUExcludeFilters.Count -gt 0) {
        $OUsToRemove = $ExportOUS + $ExportGroups + $ExportUsers | Where-Object {
            $path = $_.RelativePath
            $isMatch = $false
            foreach ($filter in $OUExcludeFilters) { if ($path -like $filter) { $isMatch = $true; break } }
            $isMatch
        } | ForEach-Object { $_.RelativePath }

        if ($OUsToRemove.Count -gt 0) {
            Write-SyncLog "Stripping $($OUsToRemove.Count) excluded OUs from payload." -Category "FILTER"
            $ExportOUs = $ExportOUs | Where-Object { $_.RelativePath -notin $OUsToRemove }
            $ExportUsers = $ExportUsers | Where-Object { $_.RelativeOU -notin $OUsToRemove }
            $ExportGroups = $ExportGroups | Where-Object { $_.RelativeOU -notin $OUsToRemove }
        }
    }

    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $JsonPayload = @{ OUs = $ExportOUs; Users = $ExportUsers; Groups = $ExportGroups } | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText("$ExportDir\$StateFileName", $JsonPayload, $Utf8NoBom)
    
    $Signature = Get-HMACSignature -DataString $JsonPayload
    [System.IO.File]::WriteAllText("$ExportDir\$SignatureFileName", $Signature, [System.Text.Encoding]::ASCII)

    Write-SyncLog "Export complete. State file signed and written." -Category "EXPORT"
}

# --- 6. IMPORT WORKFLOW ---

function Import-ADState {
    <#
    .DESCRIPTION
        Reconciles target AD with source JSON state.
    #>
    Write-SyncLog "Starting AD Import/Reconciliation..." -Category "IMPORT"
    
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    if (!(Test-Path "$ImportDir\$StateFileName")) { Write-Error "State file missing."; return }
    
    $RawJson = [System.IO.File]::ReadAllText("$ImportDir\$StateFileName", $Utf8NoBom)
    $Signature = ([System.IO.File]::ReadAllText("$ImportDir\$SignatureFileName")).Trim()
    
    Initialize-TransitEngine -KeyBackupPath "$ImportDir\$BackupKeyFileName"

    if (!(Test-HMACSignature -DataString $RawJson -Hmac $Signature)) {
        Write-Error "CRITICAL: HMAC Signature verification failed."
        exit
    }
    Write-SyncLog "Integrity Check Passed: HMAC Signature is valid." -Category "IMPORT"

    $Data = $RawJson | ConvertFrom-Json
    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))

    if ($OUExcludeFilters -and $OUExcludeFilters.Count -gt 0) {
        $OUsToRemove = $Data.OUs | Where-Object {
            $path = $_.RelativePath
            $isMatch = $false
            foreach ($filter in $OUExcludeFilters) { if ($path -like $filter) { $isMatch = $true; break } }
            $isMatch
        } | ForEach-Object { $_.RelativePath }

        if ($OUsToRemove.Count -gt 0) {
            Write-SyncLog "Stripping $($OUsToRemove.Count) excluded OUs from payload." -Category "FILTER"
            $Data.OUs = $Data.OUs | Where-Object { $_.RelativePath -notin $OUsToRemove }
            $Data.Users = $Data.Users | Where-Object { $_.RelativeOU -notin $OUsToRemove }
            $Data.Groups = $Data.Groups | Where-Object { $_.RelativeOU -notin $OUsToRemove }
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
            
            Write-SyncLog "CREATE OU: $FullDN" -Category "CRUD"
            New-ADOrganizationalUnit -Name ($Parts[0] -replace "OU=","") -Path $ParentDN -ProtectedFromAccidentalDeletion $false -Credential $Credential
        }
    }

    Write-SyncLog "Syncing Organizational Units..." -Category "SYNC"
    foreach ($OU in $Data.OUs) { Initialize-OUPath -RelativePath $OU.RelativePath -Credential $Creds }

    Write-SyncLog "Syncing Groups..." -Category "SYNC"
    $SourceGroupSams = $Data.Groups | ForEach-Object { $_.SamAccountName }
    Get-ADGroup -Filter * -SearchBase $TargetOU -Credential $Creds | ForEach-Object {
        if ($_.SamAccountName -notin $SourceGroupSams) {
            Write-SyncLog "DELETE GROUP: $($_.SamAccountName) (Not in source or excluded)" -Category "CRUD" -Type Warning
            Remove-ADGroup -Identity $_.DistinguishedName -Confirm:$false -Credential $Creds
        }
    }
    foreach ($G in $Data.Groups) {
        if (!(Get-ADGroup -Filter "SamAccountName -eq '$($G.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            Write-SyncLog "CREATE GROUP: $($G.SamAccountName)" -Category "CRUD"
            New-ADGroup -Name $G.Name -SamAccountName $G.SamAccountName -Path ("$($G.RelativeOU),$TargetOU".Trim(',')) -GroupScope Global -Credential $Creds
        }
    }

    Write-SyncLog "Syncing Users..." -Category "SYNC"
    $SourceUserSams = $Data.Users | ForEach-Object { $_.SamAccountName }
    Get-ADUser -Filter * -SearchBase $TargetOU -Credential $Creds | ForEach-Object {
        if ($_.SamAccountName -notin $SourceUserSams) {
            Write-SyncLog "DELETE USER: $($_.SamAccountName) (Not in source or excluded)" -Category "CRUD" -Type Warning
            Remove-ADUser -Identity $_.DistinguishedName -Confirm:$false -Credential $Creds
        }
    }
    foreach ($SU in $Data.Users) {
        $Pass = Unprotect-ADData -Ciphertext $SU.ProtectedPass
        $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -Properties $LdapProperties -ErrorAction SilentlyContinue
        
        $LdapChanges = @{}
        foreach ($Prop in $SU.Attributes.PSObject.Properties) {
            $currentVal = $ExistingUser.$($AttrMap[$Prop.Name])
            if ($AttrMap[$Prop.Name] -and $Prop.Value -ne $currentVal) { 
                $LdapChanges[$AttrMap[$Prop.Name]] = $Prop.Value 
                Write-SyncLog "UPDATE USER ($($SU.SamAccountName)): Attribute '$($AttrMap[$Prop.Name])' changed from '$currentVal' to '$($Prop.Value)'" -Category "CRUD"
            }
        }

        if (!$ExistingUser) {
            Write-SyncLog "CREATE USER: $($SU.SamAccountName)" -Category "CRUD"
            $UP = @{ Name=$SU.SamAccountName; SamAccountName=$SU.SamAccountName; Path=("$($SU.RelativeOU),$TargetOU".Trim(',')); AccountPassword=($Pass | ConvertTo-SecureString -AsPlainText -Force); Enabled=$true; Credential=$Creds; PasswordNeverExpires=$true; ChangePasswordAtLogon=$false; CannotChangePassword=$true; OtherAttributes=$LdapChanges }
            New-ADUser @UP
        } else {
            # --- FORCE PASSWORD RESET ON IMPORT ---
            Write-SyncLog "RESET PASSWORD ($($SU.SamAccountName)): Overwriting existing password with value from state file." -Category "CRUD"
            Set-ADAccountPassword -Identity $SU.SamAccountName -NewPassword ($Pass | ConvertTo-SecureString -AsPlainText -Force) -Reset -Credential $Creds
            
            if ($LdapChanges.Count -gt 0) { 
                Set-ADUser -Identity $SU.SamAccountName -Replace $LdapChanges -Credential $Creds 
            }
        }

        # --- GROUP MEMBERSHIP RECONCILIATION ---
        $CurrentGroups = (Get-ADPrincipalGroupMembership -Identity $SU.SamAccountName -Credential $Creds | Select-Object -ExpandProperty Name)
        
        # 1. Deletion: Remove user from groups NOT in the input file
        foreach ($curGrp in $CurrentGroups) {
            # Skip primary group (usually "Domain Users")
            if ($curGrp -eq "Domain Users") { continue }
            
            if ($curGrp -notin $SU.Groups) {
                Write-SyncLog "UPDATE USER ($($SU.SamAccountName)): Removing from group '$curGrp' (Not in source)" -Category "CRUD" -Type Warning
                Remove-ADGroupMember -Identity $curGrp -Members $SU.SamAccountName -Confirm:$false -Credential $Creds -ErrorAction SilentlyContinue
            }
        }

        # 2. Addition: Add user to groups IN the input file but not in AD
        foreach ($grp in $SU.Groups) { 
            if ($grp -notin $CurrentGroups) { 
                Write-SyncLog "UPDATE USER ($($SU.SamAccountName)): Adding to group '$grp'" -Category "CRUD"
                Add-ADGroupMember -Identity $grp -Members $SU.SamAccountName -Credential $Creds -ErrorAction SilentlyContinue 
            } 
        }
    }

    $ValidOUDNs = $Data.OUs | ForEach-Object { "$($_.RelativePath),$TargetOU".Trim(',') }
    Get-ADOrganizationalUnit -Filter * -SearchBase $TargetOU -SearchScope Subtree -Credential $Creds | 
        Where-Object { $_.DistinguishedName -ne $TargetOU -and $_.DistinguishedName -notin $ValidOUDNs } |
        Sort-Object { $_.DistinguishedName.Length } -Descending | ForEach-Object {
            Write-SyncLog "DELETE OU: $($_.DistinguishedName) (Obsolete)" -Category "CRUD" -Type Warning
            Remove-ADOrganizationalUnit -Identity $_.DistinguishedName -Recursive -Confirm:$false -Credential $Creds
        }

    Remove-Item "$ImportDir\*" -Force
    Write-SyncLog "Import and Reconciliation complete." -Category "IMPORT"
}

if ($Global:Mode -eq "Import") { Import-ADState } else { Export-ADState }