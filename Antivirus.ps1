# Set your VirusTotal public API key here
$VirusTotalApiKey = "0393b0784dba04ea0c6f5c1e45cac1c35ba83b1fc09e1d792d270dcc159d53d8"

# Configurable parameters
$MonitoringInterval = 600 # Time in seconds to wait before checking the scan results again

# Function to check a file on VirusTotal
function Get-VirusTotalScan {
    param (
        [string]$FilePath
    )

    $VirusTotalUrl = "https://www.virustotal.com/api/v3/files"

    $Headers = @{
        "x-apikey" = $VirusTotalApiKey
    }

    try {
        # Get the file hash
        $fileHash = (Get-FileHash -Algorithm SHA256 $FilePath).Hash
        $VirusTotalUrl += "/$fileHash"
        # Query VirusTotal for the file scan results
        $response = Invoke-RestMethod -Uri $VirusTotalUrl -Headers $Headers -Method Get
    } catch {
        Write-Error "Error accessing VirusTotal API: $_"
        return $null
    }

    # Wait for the scan to complete if the initial query returns no results
    while ($response.data.attributes.last_analysis_stats.malicious -eq $null) {
        Start-Sleep -Seconds $MonitoringInterval
        try {
            # Retry the query to check if the scan results are available
            $response = Invoke-RestMethod -Uri $VirusTotalUrl -Headers $Headers -Method Get
        } catch {
            Write-Error "Error accessing VirusTotal API: $_"
            return $null
        }
    }

    $reportUrl = "https://www.virustotal.com/gui/file/$($response.data.id)/detection"
    Write-Host "Scan results available at: $reportUrl"

    return $response
}

# Function to block execution
function Block-Execution {
    param (
        [string]$FilePath,
        [string]$Reason
    )

    Write-Host "Blocked Execution: $Reason"
    # Log the blocked file
    Write-Log "Blocked file: $FilePath - Reason: $Reason"

    # Revoke all permissions from the infected file using icacls
    icacls $FilePath /deny Everyone:(DE)

    # Add your additional blocking logic here, such as killing the process or quarantining the file.
}

# Function to unblock execution
function Unblock-Execution {
    param (
        [string]$FilePath
    )

    Write-Host "Unblocking file: $FilePath"
    # Log the unblocked file
    Write-Log "Unblocked file: $FilePath"

    # Grant permissions to the file
    icacls $FilePath /grant Everyone:(F)
}

# Function to add the script to Windows startup folder
function AddToStartup {
    $scriptPath = $MyInvocation.MyCommand.Definition
    $startupFolderPath = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolderPath "SimpleAntivirus.lnk"

    if (-Not (Test-Path $shortcutPath)) {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $scriptPath
        $Shortcut.Save()
        Write-Host "Script added to startup."
    }
}

# Function to monitor file changes (creations and modifications) on a given path
function Monitor-Path {
    param (
        [string]$Path
    )

    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = $Path
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true

    # Monitor file creations
    Register-ObjectEvent $fileWatcher "Created" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Host "New file created: $filePath"

        $scanResults = Get-VirusTotalScan -FilePath $filePath

        # Check if the file is detected as malware on VirusTotal
        if ($scanResults -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
            Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
            Send-Notification -Message "Blocked malicious file: $filePath"
        }
    } | Out-Null

    # Monitor file modifications
    Register-ObjectEvent $fileWatcher "Changed" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Host "File modified: $filePath"

        $scanResults = Get-VirusTotalScan -FilePath $filePath

        # Check if the file is detected as malware on VirusTotal
        if ($scanResults -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
            Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
            Send-Notification -Message "Blocked malicious file: $filePath"
        }
    } | Out-Null
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message
    )

    $documentsPath = [Environment]::GetFolderPath("MyDocuments")
    $logFilePath = Join-Path $documentsPath "SimpleAntivirusLog.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFilePath -Value $logMessage
}

# Function to send notifications
function Send-Notification {
    param (
        [string]$Message
    )

    # Example: Send notification via email
    # Note: Replace the following parameters with your actual email settings
    $smtpServer = "smtp.your-email-provider.com"
    $smtpFrom = "your-email@your-domain.com"
    $smtpTo = "recipient-email@domain.com"
    $subject = "SimpleAntivirus Notification"
    $body = $Message

    Send-MailMessage -SmtpServer $smtpServer -From $smtpFrom -To $smtpTo -Subject $subject -Body $body
}

# Function to monitor all local drives
function Monitor-LocalDrives {
    $localDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match "^[A-Z]:" }
    foreach ($drive in $localDrives) {
        Monitor-Path -Path $drive.Root
    }
}

# Function to monitor all network shares
function Monitor-NetworkShares {
    $networkShares = Get-WmiObject Win32_Share | Where-Object { $_.Type -eq 0 } | Select-Object -ExpandProperty Path
    foreach ($share in $networkShares) {
        Monitor-Path -Path $share
    }
}

# Check if the script is already added to startup
function IsInStartup {
    $scriptPath = $MyInvocation.MyCommand.Definition
    $startupFolderPath = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolderPath "SimpleAntivirus.lnk"

    return (Test-Path $shortcutPath)
}

# Check if the script is already added to startup
if (-Not (IsInStartup)) {
    AddToStartup
}

# Start monitoring all local drives and network shares
Monitor-LocalDrives
Monitor-NetworkShares
