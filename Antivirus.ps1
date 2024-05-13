# Set your VirusTotal public API key here
$VirusTotalApiKey = "0393b0784dba04ea0c6f5c1e45cac1c35ba83b1fc09e1d792d270dcc159d53d8"

# Function to check a file on VirusTotal
function Get-VirusTotalScan {
    param (
        [string]$FilePath
    )

    $VirusTotalUrl = "https://www.virustotal.com/api/v3/files"

    $Headers = @{
        "x-apikey" = $VirusTotalApiKey
    }

    $fileHash = (Get-FileHash -Algorithm SHA256 $FilePath).Hash
    $VirusTotalUrl += "/$fileHash"

    $response = Invoke-RestMethod -Uri $VirusTotalUrl -Headers $Headers -Method Get

    # Wait for the scan to complete
    while ($response.data.attributes.last_analysis_stats.malicious -eq $null) {
        Start-Sleep -Seconds 10
        $response = Invoke-RestMethod -Uri $VirusTotalUrl -Headers $Headers -Method Get
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
    
    # Revoke all permissions from the infected file using icacls
    icacls $FilePath /deny Everyone:(DE)

    # Add your additional blocking logic here, such as killing the process or quarantining the file.
}

function Monitor-FileSystem {
    # Get all local drives
    $drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID

    # Monitor local drives
    foreach ($drive in $drives) {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $drive + "\"
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true

        Register-ObjectEvent $fileWatcher "Created" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Write-Host "File created: $filePath"

            # Add your file scanning logic here
        } | Out-Null
    }

    # Monitor network shares
    $networkShares = Get-WmiObject Win32_Share | Where-Object { $_.Type -eq 0 } | Select-Object -ExpandProperty Path
    foreach ($share in $networkShares) {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $share
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true

        Register-ObjectEvent $fileWatcher "Created" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Write-Host "File created on network share: $filePath"

            # Add your file scanning logic here
        } | Out-Null
    }
}


# Function to monitor running processes
function Monitor-Processes {
    $processWatcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher "Security", [System.Diagnostics.Eventing.Reader.PathType]::LogName
    $processWatcher.EventRecordWritten += {
        $processEvent = $_.EventRecord

        # Extract process information from the event
        $processName = $processEvent.Properties[5].Value
        $processId = $processEvent.Properties[0].Value

        Write-Host "Process started: $processName (ID: $processId)"

        # Add your process monitoring logic here, such as checking against a list of known malicious processes.
    }

    $processWatcher.Start()
}


# Check if the script is already added to startup
if (-Not (Test-Path $MyInvocation.MyCommand.Path -PathType Leaf)) {
    # Add the script to the startup folder
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

# Start monitoring
Monitor-FileSystem
Monitor-Processes
