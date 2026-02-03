$OUExcludeFilters = @(
    "*Staging*",
    "*Testing*",
    "OU=Siemens*"
)
          
$TargetOU = "OU=RBAC,DC=jml,DC=local"

# Remote Source Connection Details
$SftpHost        = "192.168.1.181" 
$SftpPort        = 22 

$ExportDir = "$ParentDir\Export\$LibraryPath"   