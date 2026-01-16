<#
.SYNOPSIS
    Primary Active Directory Synchronization and Secure Transport Script.
    Name: Sync-AD-Transport.ps1
    Version: 4.3
    
.DESCRIPTION
    This script facilitates the secure transfer of AD user objects and group memberships 
    between disconnected (air-gapped) environments. It uses OpenBao for asymmetric 
    encryption of passwords and HMAC signing for payload integrity.

.LOGIC_FLOW
    1. Initial Configuration: Define paths, LDAP mappings, and Bao tokens.
    2. Utility Functions: Wrapper for Bao API, Event Logging, and Transit encryption.
    3. Export Workflow: 
        - Reads Source OU users.
        - Fetches/Generates passwords in Vault.
        - Asymmetrically encrypts passwords.
        - Packages data into JSON and signs with HMAC.
    4. Import Workflow:
        - Verifies HMAC signature.
        - Restores Transit keys from backup.
        - Phase A: Reconciles Users/Attributes and Group Memberships.
        - Phase B: Deletes stale Users/Groups on Target not found in Source.

.NOTES
    v4.3 Update: Replaced '%' alias with 'ForEach-Object' for PSScriptAnalyzer compliance.
#>

# --- 1. GLOBAL CONFIGURATION & FILE PATHS ---

$ParentDir = "C:\ADSync"
$ExportDir = "$ParentDir\Export"  
$ImportDir = "$ParentDir\Import"  
$KeysFile  = "$ParentDir\OpenBao\vault_keys.json" 

# Vault Paths
$UserSecretsPath = "secret/data/users"                 # KV-V2 path for individual user passwords
$AdminSecretPath = "secret/data/ad-admin"              # KV-V2 path for Target AD admin creds
$TargetOU        = "OU=Supplier,DC=ng,DC=local"        # The scope of synchronization
$PasswordLogDir  = "$ParentDir\Users"                  # Local log for initial password generation

# File naming conventions for transport
$StateFileName = "AD_State_Export.json"                # The data payload
$SignatureFileName = "AD_State_Export.hmac"            # Integrity signature
$BackupKeyFileName = "transport-key.backup"            # Encrypted backup of the Transit key

# --- 2. LDAP ATTRIBUTE MAPPING ---
# Maps PowerShell AD Property Names to LDAP attribute names
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
# Load the Root Token required to communicate with OpenBao
if (Test-Path $KeysFile) {
    $BaoToken = (Get-Content $KeysFile | ConvertFrom-Json).root_token
} else {
    Write-Error "CRITICAL: vault_keys.json not found. Run Invoke-BaoAutomation.ps1 first."
    exit
}

# --- 4. CORE UTILITY FUNCTIONS ---

function Invoke-Bao {
    <# Helper to interact with OpenBao REST API #>
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
        if ($result.data.data) { return $result.data.data } # Handle KV-V2 nested data
        if ($result.data) { return $result.data }           # Handle Transit engine responses
        return $result
    } catch { return $null }
}

function Write-SyncLog {
    <# Standardized logging to Console and Windows Event Log #>
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
    <# Sets up the Transit engine and restores/backs up the RSA keys #>
    param($KeyBackupPath)
    $headers = @{ "X-Vault-Token" = $BaoToken; "Content-Type" = "application/json" }
    
    # Enable Transit engine if not already active
    try { Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/sys/mounts/transit" -Headers $headers -Method Post -Body (@{ type = "transit" } | ConvertTo-Json) -ErrorAction SilentlyContinue } catch {}

    # IMPORT MODE: Restore key if backup exists and key is missing
    if (Test-Path $KeyBackupPath) {
        if ($null -eq (Invoke-Bao -Method Get -Path "transit/keys/transport-key")) {
            $BackupBlob = (Get-Content $KeyBackupPath -Raw).Trim()
            Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/restore/transport-key" -Headers $headers -Method Post -Body (@{ backup = $BackupBlob } | ConvertTo-Json)
            Write-SyncLog "Asymmetric Transport Key Restored from backup." -Category "SECURITY"
        }
    }
    
    # EXPORT MODE: Create new key if it doesn't exist
    if ($null -eq (Invoke-Bao -Method Get -Path "transit/keys/transport-key")) {
        Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/keys/transport-key" -Headers $headers -Method Post -Body (@{ 
            type = "rsa-4096"; 
            exportable = $true; 
            allow_plaintext_backup = $true 
        } | ConvertTo-Json)
        Write-SyncLog "Initialized new RSA-4096 Asymmetric Key." -Category "SECURITY"
    }

    # Backup the key to disk for transport to the target
    if ($Global:Mode -eq "Export") {
        $backup = Invoke-RestMethod -Uri "http://127.0.0.1:8200/v1/transit/backup/transport-key" -Headers $headers -Method Get
        if ($backup.data.backup) { $backup.data.backup | Out-File $KeyBackupPath -Encoding ascii -Force }
    }
}

function Protect-Data {
    <# Encrypts plaintext using the Transit engine (Asymmetric RSA-4096) #>
    param([string]$Plaintext)
    $Base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plaintext))
    $Result = Invoke-Bao -Method Post -Path "transit/encrypt/transport-key" -Body @{ plaintext = $Base64 }
    return $Result.ciphertext
}

function Unprotect-Data {
    <# Decrypts ciphertext using the Transit engine #>
    param([string]$Ciphertext)
    $Result = Invoke-Bao -Method Post -Path "transit/decrypt/transport-key" -Body @{ ciphertext = $Ciphertext }
    $Bytes = [Convert]::FromBase64String($Result.plaintext)
    return [System.Text.Encoding]::UTF8.GetString($Bytes)
}

# --- 5. EXPORT WORKFLOW (Source Server) ---

function Export-ADState {
    Write-SyncLog "Starting Asymmetric Export Mode -> Scope: $TargetOU" -Category "EXPORT"
    
    # Ensure export directories exist
    if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }
    if (!(Test-Path $PasswordLogDir)) { New-Item -ItemType Directory -Path $PasswordLogDir -Force | Out-Null }
    
    Initialize-TransitEngine -KeyBackupPath "$ExportDir\$BackupKeyFileName"

    # Query all users in scope
    $Users = Get-ADUser -Filter * -SearchBase $TargetOU -Properties ($AttrMap.Keys + @("MemberOf", "SamAccountName"))
    $ExportUsers = @()
    $FoundGroups = @{} # Track which groups exist in the Source environment

    foreach ($U in $Users) {
        # Check Vault for existing password
        $Secret = Invoke-Bao -Method Get -Path "$UserSecretsPath/$($U.SamAccountName)"
        
        # If no password in Vault, generate one and log it locally (one-time generation)
        if ($null -eq $Secret) {
            # MODIFIED: Replaced '%' with 'ForEach-Object' for PSScriptAnalyzer compliance
            $Pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
            Invoke-Bao -Method Post -Path "$UserSecretsPath/$($U.SamAccountName)" -Body @{ data = @{ password = $Pass } }
            $Secret = @{ password = $Pass }
            
            $PassFilePath = "$PasswordLogDir\$($U.SamAccountName).txt"
            "User: $($U.SamAccountName)`r`nGenerated Password: $Pass`r`nDate: $(Get-Date)" | Out-File $PassFilePath -Force
            Write-SyncLog "Generated new password for $($U.SamAccountName). File: $PassFilePath" -Category "CRUD-CREATE"
        }
        
        # Asymmetrically encrypt the password for secure transport
        $EncPass = Protect-Data -Plaintext $Secret.password
        
        # Handle Group Memberships
        $GroupNames = New-Object System.Collections.Generic.List[string]
        $UserMemberOf = @($U.MemberOf) # Force array to handle single-item results
        
        if ($UserMemberOf.Count -gt 0) {
            foreach ($gDn in $UserMemberOf) {
                if ($null -ne $gDn) {
                    try {
                        $g = Get-ADGroup -Identity $gDn
                        $gName = $g.SamAccountName
                        if ($gName) { 
                            $GroupNames.Add($gName) 
                            $FoundGroups[$gName] = $true # Mark group as "Active/Valid"
                        }
                    } catch { }
                }
            }
        }

        # Build user object for the JSON payload
        $UserMap = @{ 
            SamAccountName = $U.SamAccountName; 
            DisplayName    = $U.DisplayName;
            ProtectedPass  = $EncPass; 
            Groups         = $GroupNames.ToArray(); 
            Attributes     = @{} 
        }
        # Populate attributes based on mapping table
        foreach ($Key in $AttrMap.Keys) { if ($U.$Key) { $UserMap.Attributes[$Key] = $U.$Key.ToString() } }
        $ExportUsers += $UserMap
        Write-SyncLog "Staged user for export: $($U.SamAccountName)" -Category "EXPORT-READ"
    }
    
    # Final Payload construction
    $Export = @{ 
        Users = $ExportUsers;
        ValidGroups = $FoundGroups.Keys # Metadata for cleanup at Target
    }
    $StatePath = "$ExportDir\$StateFileName"
    $SigPath = "$ExportDir\$SignatureFileName"
    
    $Export | ConvertTo-Json -Depth 10 | Out-File $StatePath
    
    # Sign payload with HMAC to prevent tampering during transfer
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
    
    # Initialize crypto engine and restore the transport key
    Initialize-TransitEngine -KeyBackupPath $KeyBackupPath
    
    # VERIFY SIGNATURE: Ensure the payload hasn't been modified
    $Bytes = [System.IO.File]::ReadAllBytes($StatePath)
    $HMAC = (Get-Content $SigPath).Trim()
    
    if ((Invoke-Bao -Method Post -Path "transit/verify/transport-key" -Body @{ input = [Convert]::ToBase64String($Bytes); hmac = $HMAC }).valid -ne $true) {
        Write-SyncLog "CRITICAL: Signature mismatch! Payload rejected." -Type Error -Category "SECURITY"
        return
    }

    # Fetch AD Admin credentials from Vault to perform AD operations
    $Admin = Invoke-Bao -Method Get -Path $AdminSecretPath
    $Creds = New-Object System.Management.Automation.PSCredential($Admin.username, ($Admin.password | ConvertTo-SecureString -AsPlainText -Force))
    $Data = Get-Content $StatePath | ConvertFrom-Json
    
    # Tracking variables for cleanup phase
    $SourceUserList = @()
    $ActualGroupsInPayload = New-Object System.Collections.Generic.HashSet[string]
    
    # Load valid groups from metadata
    if ($Data.ValidGroups) { foreach ($vg in @($Data.ValidGroups)) { $ActualGroupsInPayload.Add($vg) | Out-Null } }

    # --- Phase A: Create / Update Users & Manage Group Memberships ---
    foreach ($SU in $Data.Users) {
        $SourceUserList += $SU.SamAccountName
        try {
            # Decrypt the incoming password
            $PlainPass = Unprotect-Data -Ciphertext $SU.ProtectedPass
            $SP = $PlainPass | ConvertTo-SecureString -AsPlainText -Force
            
            # Map incoming attributes
            $ReconcileMap = @{}
            foreach ($P in $SU.Attributes.PSObject.Properties) {
                if ($AttrMap[$P.Name]) { $ReconcileMap[$AttrMap[$P.Name]] = $P.Value }
            }

            $ObjName = if ($SU.DisplayName) { $SU.DisplayName } else { $SU.SamAccountName }
            $TU = Get-ADUser -Filter "SamAccountName -eq '$($SU.SamAccountName)'" -Properties ($AttrMap.Values + "MemberOf") -ErrorAction SilentlyContinue
            
            if (!$TU) {
                # [CREATE] Logic: New user found in Source
                New-ADUser -Name $ObjName -SamAccountName $SU.SamAccountName -Path $TargetOU `
                           -AccountPassword $SP -Enabled $true -Credential $Creds `
                           -PasswordNeverExpires $true -CannotChangePassword $true `
                           -OtherAttributes $ReconcileMap
                Write-SyncLog "CREATE SUCCESS: Created new user account '$($SU.SamAccountName)'" -Category "CRUD-CREATE"
                $TU = Get-ADUser -Identity $SU.SamAccountName -Properties ($AttrMap.Values + "MemberOf")
            } else {
                # [UPDATE] Logic: Check for attribute drift
                $Updates = @{}
                foreach ($LdapAttr in $ReconcileMap.Keys) {
                    $SourceVal = $ReconcileMap[$LdapAttr]
                    $TargetVal = $TU.$LdapAttr
                    if ($SourceVal -ne $TargetVal) { $Updates[$LdapAttr] = $SourceVal }
                }
                if ($Updates.Count -gt 0) {
                    Set-ADUser -Identity $TU.DistinguishedName -Replace $Updates -Credential $Creds
                    Write-SyncLog "UPDATE SUCCESS: Synchronized attributes for '$($SU.SamAccountName)'" -Category "CRUD-UPDATE"
                }
                # Always sync password and flags to ensure parity
                Set-ADAccountPassword -Identity $TU.DistinguishedName -NewPassword $SP -Reset -Credential $Creds
                Set-ADUser -Identity $TU.DistinguishedName -PasswordNeverExpires $true -CannotChangePassword $true -Credential $Creds
            }

            # [GROUP RECONCILIATION] Logic: Manage memberships for this user
            $SourceGroups = if ($SU.Groups) { @($SU.Groups) } else { @() }
            $CurrentGroups = @()
            $TargetMemberOf = @($TU.MemberOf) # Handle single-string vs array
            
            if ($TargetMemberOf.Count -gt 0) {
                foreach ($gDn in $TargetMemberOf) {
                    if ($null -ne $gDn) {
                        $g = Get-ADGroup -Identity $gDn -ErrorAction SilentlyContinue
                        if ($g) { $CurrentGroups += $g.SamAccountName }
                    }
                }
            }

            foreach ($GroupName in $SourceGroups) {
                # Ensure group is in our "Keep List" for Phase B
                $ActualGroupsInPayload.Add($GroupName) | Out-Null
                
                # Check if group exists on Target
                $TargetGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction SilentlyContinue
                if (!$TargetGroup) {
                    New-ADGroup -Name $GroupName -SamAccountName $GroupName -Path $TargetOU -GroupScope Global -Credential $Creds
                    $TargetGroup = Get-ADGroup -Identity $GroupName
                    Write-SyncLog "CREATE SUCCESS: Created missing security group '$GroupName'" -Category "CRUD-CREATE"
                }
                # Add user to group if missing
                if ($CurrentGroups -notcontains $GroupName) {
                    Add-ADGroupMember -Identity $TargetGroup.DistinguishedName -Members $TU.DistinguishedName -Credential $Creds
                    Write-SyncLog "GROUP ADD: User '$($SU.SamAccountName)' added to group '$GroupName'" -Category "CRUD-UPDATE"
                }
            }

            # Remove user from groups they are no longer part of in Source
            foreach ($GroupName in $CurrentGroups) {
                if ($SourceGroups -notcontains $GroupName) {
                    $TargetGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction SilentlyContinue
                    if ($TargetGroup) {
                        Remove-ADGroupMember -Identity $TargetGroup.DistinguishedName -Members $TU.DistinguishedName -Confirm:$false -Credential $Creds
                        Write-SyncLog "GROUP REMOVE: User '$($SU.SamAccountName)' removed from group '$GroupName'" -Category "CRUD-DELETE"
                    }
                }
            }
        } catch { 
            Write-SyncLog "RECONCILE ERROR: Failed processing '$($SU.SamAccountName)': $($_.Exception.Message)" -Type Warning -Category "IMPORT"
        }
    }

    # --- Phase B: Deletion / Cleanup (Mirror Source State) ---
    
    # 1. DELETE Users not in Source payload
    $TargetUsers = Get-ADUser -Filter * -SearchBase $TargetOU
    foreach ($TU in $TargetUsers) {
        if ($SourceUserList -notcontains $TU.SamAccountName) {
            Write-SyncLog "STALE USER: User '$($TU.SamAccountName)' no longer exists in Source. Deleting from Target." -Category "CRUD-DELETE"
            Remove-ADUser -Identity $TU.DistinguishedName -Confirm:$false -Credential $Creds
            # Remove associated password record in local Vault
            Invoke-Bao -Method Delete -Path "$UserSecretsPath/$($TU.SamAccountName)"
        }
    }

    # 2. DELETE Groups not found in any user membership or metadata payload
    $TargetGroups = Get-ADGroup -Filter * -SearchBase $TargetOU
    foreach ($TG in $TargetGroups) {
        if (!($ActualGroupsInPayload.Contains($TG.SamAccountName))) {
            Write-SyncLog "STALE GROUP: Group '$($TG.SamAccountName)' no longer exists in Source. Deleting from Target." -Category "CRUD-DELETE"
            Remove-ADGroup -Identity $TG.DistinguishedName -Confirm:$false -Credential $Creds
        }
    }
}

# --- 7. EXECUTION LOGIC ---
# Determine mode based on presence of transport files
if (Test-Path "$ImportDir\$StateFileName") { 
    $Global:Mode = "Import"
    Import-ADState 
} else { 
    $Global:Mode = "Export"
    Export-ADState 
}