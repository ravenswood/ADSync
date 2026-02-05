<#
.SYNOPSIS
    Wrapper script to run AD export for each suplier and create a unique, supplier specific
    set of files
    
#>
# Define your array of filters
$Suppliers = @(
    "Balfour",
    "Siemens",
    "GE",
    "GSS",    
    "Hitachi"
)

# Define the path to the script you want to run
$ScriptPath = "$PSScriptRoot\Sync-AD-Transport.ps1"

# Loop through each entry in the array
foreach ($supplier in $Suppliers) {
    Write-Host "Processing supplier: $supplier" -ForegroundColor Cyan
    
    # Run the external script and pass the current array value as a parameter
    & $ScriptPath $supplier
}