<#
.SYNOPSIS
    Secure SFTP Pull Utility for AD Sync Payloads with Auto-Execution.
    Name: Receive-ADSyncPayload.ps1
    
.DESCRIPTION
    This script is designed for the TARGET server in an air-gapped or disconnected 
    AD Sync environment. It performs a "Pull" operation to retrieve encrypted 
    synchronization payloads from a remote Source server via SFTP.
    
    Key Features:
    1. Automated SFTP transfer using WinSCP .NET Assembly.
    2. Security bypass for SSH fingerprints (for dynamic environments).
    3. Re-entrancy protection via lock files to prevent double-execution.
    4. Automatic foreground trigger of the secondary AD Sync Engine.

.PARAMETER SftpHost
    The IP or FQDN of the Source server (Default: 192.168.1.213).
    
.PARAMETER LibraryPath
    The config for a specific site

.NOTES
    - Requires WinSCPnet.dll to be present in C:\ADSync\Bin\.
    - The script must be run with sufficient permissions to write to C:\ADSync 
      and execute the secondary Sync-AD-Transport.ps1 script.
    - ad_creds_temp.json file must contain sftp userid and password for accessing remote
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$LibraryPath
)

. "$PSScriptRoot\ADSyncLibrary.ps1"

# --- GLOBAL CONFIGURATION & PATHING ---

$SyncScriptPath  = "$ParentDir\Sync-AD-Transport.ps1" # The engine to trigger after pull
$WinSCPPath      = "$ParentDir\Bin\WinSCPnet.dll"   # WinSCP .NET Library path
$LockFile        = "$ParentDir\Logs\sftp_pull.lock" # Semaphore file to prevent double runs

# Remote path on the Source server where Exported payloads are staged
$RemoteSourcePath = "/$ExportDir/*" # "/C:/ADSync/Export/*"

# --- SAFETY CHECKS & RE-ENTRANCY PROTECTION ---
# Check if a lock file exists. This prevents two instances from running if a 
# previous task is still hung or if the script was triggered manually while scheduled.
if (Test-Path $LockFile) {
    $LockAge = (Get-Date) - (Get-Item $LockFile).LastWriteTime
    # If the lock is older than 5 minutes, we assume a previous crash and clear it.
    if ($LockAge.TotalMinutes -lt 5) {
        Write-Host "CRITICAL: Script is already running (Lock found at $LockFile). Exiting." -ForegroundColor Yellow
        exit
    } else {
        Remove-Item $LockFile -Force
    }
}

# Create a fresh lock file for the current session
New-Item -Path $LockFile -ItemType File -Force | Out-Null

# Verify the WinSCP library is available before proceeding
if (!(Test-Path $WinSCPPath)) {
    Write-SyncLog "CRITICAL: WinSCP .NET Assembly not found at $WinSCPPath." -Type Error
    Remove-Item $LockFile -Force
    exit
}

# Ensure the Import directory is ready to receive files
if (!(Test-Path $ImportDir)) {
    New-Item -ItemType Directory -Path $ImportDir -Force | Out-Null
}

Set-BaoStatus Unseal
$Sftp = Invoke-Bao -Method Get -Path $sftpSecretPath
$SftpPass = $Sftp.sftppassword 
$SftpUser = $Sftp.sftpUser 
Set-BaoStatus Seal

# --- 4. CORE EXECUTION BLOCK ---
try {
    # Load the WinSCP assembly into the current PowerShell session
    Add-Type -Path $WinSCPPath

    # Configure session parameters
    $sessionOptions = New-Object WinSCP.SessionOptions
    $sessionOptions.Protocol = [WinSCP.Protocol]::Sftp
    $sessionOptions.HostName = $SftpHost
    $sessionOptions.PortNumber = $SftpPort
    $sessionOptions.UserName = $SftpUser
    $sessionOptions.Password = $SftpPass
    
    # SECURITY POLICY: Bypassing strict fingerprint validation.
    # This is set to $true to ignore SSH Host Key changes on the remote end.
    $sessionOptions.GiveUpSecurityAndAcceptAnySshHostKey = $true 

    # Initialize the SFTP session object
    $session = New-Object WinSCP.Session

    try {
        Write-SyncLog "Connecting to Source Server $SftpHost (SSH Check: Disabled)..."
        $session.Open($sessionOptions)

        # Audit the remote key for security tracking, even though we aren't validating it
        $ActualKey = $session.Info.SshHostKeyFingerprint
        Write-SyncLog "Session Established. Remote Host Fingerprint: $ActualKey"

        # Define Transfer Logic (Binary mode ensures no corruption of JSON/HMAC data)
        $transferOptions = New-Object WinSCP.TransferOptions
        $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
        $transferOptions.FileMask = "| */"

        # Perform the "PULL": Get files from Source and place in local Import folder
        $transferResult = $session.GetFiles($RemoteSourcePath, "$ImportDir\", $false, $transferOptions)
        
        # Check for errors in the transfer results
        $transferResult.Check()

        if ($transferResult.Transfers.Count -gt 0) {
            foreach ($transfer in $transferResult.Transfers) {
                Write-SyncLog "Successfully pulled payload component: $($transfer.FileName)"
            }
            Write-SyncLog "Pull Operation Complete. $($transferResult.Transfers.Count) files received."
            
            # --- 5. AUTOMATED SYNC ENGINE TRIGGER ---
            # Now that the files are in 'C:\ADSync\Import', we trigger the main sync engine.
            if (Test-Path $SyncScriptPath) {
                Write-SyncLog "Payload detected. Launching Sync-AD-Transport in FOREGROUND..."
                
                # Using the call operator (&) ensures the sync engine runs in this console
                # allowing administrators to see progress and real-time logs.
                & $SyncScriptPath
                
                Write-SyncLog "Synchronization engine process completed successfully."
            } else {
                Write-SyncLog "WARNING: Sync engine script not found at $SyncScriptPath. Payload remains in Import folder." -Type Warning
            }
        } else {
            Write-SyncLog "No new export files found on the remote Source server."
        }
    }
    finally {
        # Clean up the session memory and close the connection
        if ($null -ne $session) { $session.Dispose() }
    }
}
catch {
    # Log any fatal errors during the SFTP or execution process
    Write-SyncLog "SFTP PULL ERROR: $($_.Exception.Message)" -Type Error
    exit 1
}
finally {
    # CRITICAL: Always release the lock file so the next scheduled task can run.
    Remove-Item $LockFile -ErrorAction SilentlyContinue
}