$DomainRoot = "DC=domain,DC=com"
$JsonPath = "C:\path\to\ad_structure.json"
$Config = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

# Global list to store memberships for Pass 2
$GlobalMembershipQueue = @()

function New-ADStructure {
    param ($OUObject, [string]$ParentPath)

    $OUName = $OUObject.Name
    $CurrentOUPath = "OU=$OUName,$ParentPath"

    # Pass 1a: Create OU
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$CurrentOUPath'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $OUName -Path $ParentPath
    }

    # Pass 1b: Create Users
    foreach ($User in $OUObject.users) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($User.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -SamAccountName $User.SamAccountName -GivenName $User.FirstName -Surname $User.LastName `
                       -Name "$($User.FirstName) $($User.LastName)" -Path $CurrentOUPath -Enabled $true
        }
    }

    # Pass 1c: Create Groups and Queue Memberships
    foreach ($Group in $OUObject.groups) {
        if (-not (Get-ADGroup -Filter "Name -eq '$($Group.Name)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $Group.Name -GroupCategory $Group.Category -GroupScope $Group.Scope -Path $CurrentOUPath
        }
        # Store for Pass 2
        if ($Group.members) {
            $script:GlobalMembershipQueue += [PSCustomObject]@{
                GroupName = $Group.Name
                Members   = $Group.members
            }
        }
    }

    # Recursion
    foreach ($SubOU in $OUObject.sub_ous) {
        New=ADStructure -OUObject $SubOU -ParentPath $CurrentOUPath
    }
}

# START PROCESS
Write-Host "--- Pass 1: Creating Hierarchy ---" -ForegroundColor Cyan
foreach ($TopLevelOU in $Config) { New=ADStructure -OUObject $TopLevelOU -ParentPath $DomainRoot }

Write-Host "--- Pass 2: Applying Cross-OU Memberships ---" -ForegroundColor Cyan
foreach ($Item in $GlobalMembershipQueue) {
    foreach ($Member in $Item.Members) {
        try {
            # Add-ADGroupMember supports cross-OU lookup by SamAccountName automatically
            Add-ADGroupMember -Identity $Item.GroupName -Members $Member -ErrorAction Stop
            Write-Host "Linked $Member to $($Item.GroupName)" -ForegroundColor Green
        } catch {
            Write-Warning "Could not link $Member to $($Item.GroupName): $($_.Exception.Message)"
        }
    }
}
