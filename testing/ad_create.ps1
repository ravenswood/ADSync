Import-Module ActiveDirectory

# --- CONFIGURATION ---
$JsonPath = ".\ad_structure.json"
$LogFile  = ".\AD_Build_Log.txt"
$TempPass = "TempPass123!" # Users must change this at first logon

# --- LOGGING FUNCTION ---
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Stamp] $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message -ForegroundColor $Color
}

# --- RECURSIVE PROCESSING FUNCTION ---
function Process-ADStructure {
    param (
        [Object]$OUData,
        [String]$ParentPath
    )

    # 1. Construct Distinguished Name
    $CurrentOUPath = "OU=$($OUData.Name),$ParentPath"

    # 2. Create OU (ProtectedFromAccidentalDeletion = $false)
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$CurrentOUPath'" -ErrorAction SilentlyContinue)) {
        try {
            New-ADOrganizationalUnit -Name $OUData.Name `
                                     -Path $ParentPath `
                                     -ProtectedFromAccidentalDeletion $false `
                                     -ErrorAction Stop
            Write-Log "Created OU: $($OUData.Name)" "Cyan"
        } catch {
            Write-Log "FAILED to create OU $($OUData.Name): $($_.Exception.Message)" "Red"
            return # Stop processing this branch if OU creation fails
        }
    } else {
        Write-Log "OU Exists: $($OUData.Name)" "DarkCyan"
    }

    # 3. Create Groups
    foreach ($GroupName in $OUData.Groups) {
        if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $GroupName `
                        -Path $CurrentOUPath `
                        -GroupScope Global `
                        -GroupCategory Security
            Write-Log "  Created Group: $GroupName" "Yellow"
        }
    }

    # 4. Create Users (Disabled & Mapping Names Correctly)
    foreach ($User in $OUData.Users) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($User.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            
            $SecurePass = ConvertTo-SecureString $TempPass -AsPlainText -Force
            
            $UserParams = @{
                SamAccountName        = $User.SamAccountName
                Name                  = "$($User.FirstName) $($User.LastName)"
                DisplayName           = "$($User.FirstName) $($User.LastName)"
                GivenName             = $User.FirstName # Maps to "First Name"
                Surname               = $User.LastName  # Maps to "Last Name"
                Path                  = $CurrentOUPath
                AccountPassword       = $SecurePass
                Enabled               = $false # Created as Disabled
                ChangePasswordAtLogon = $true
            }

            try {
                New-ADUser @UserParams -ErrorAction Stop
                Write-Log "    Created User (Disabled): $($User.SamAccountName)" "Green"

                # Add User to Groups
                foreach ($Group in $User.MemberOf) {
                    try {
                        Add-ADGroupMember -Identity $Group -Members $User.SamAccountName -ErrorAction Stop
                        Write-Log "      Added to Group: $Group" "DarkGray"
                    } catch {
                        Write-Log "      ERROR: Could not add to group $Group" "Red"
                    }
                }
            } catch {
                Write-Log "    FAILED to create user $($User.SamAccountName): $($_.Exception.Message)" "Red"
            }
        } else {
            Write-Log "    User Exists: $($User.SamAccountName)" "DarkGray"
        }
    }

    # 5. RECURSION: Process Sub-OUs if they exist
    if ($OUData.SubOUs) {
        foreach ($SubOU in $OUData.SubOUs) {
            Process-ADStructure -OUData $SubOU -ParentPath $CurrentOUPath
        }
    }
}

# --- SCRIPT EXECUTION ---
if (Test-Path $JsonPath) {
    Write-Log "--- Starting AD Build ---" "Green"
    $Data = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json
    
    foreach ($RootOU in $Data.OUs) {
        Process-ADStructure -OUData $RootOU -ParentPath $RootOU.Path
    }
    Write-Log "--- Build Complete ---" "Green"
} else {
    Write-Error "JSON file not found at $JsonPath"
}