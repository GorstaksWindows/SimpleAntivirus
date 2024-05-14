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

# Function to monitor file creations
function Monitor-FileCreations {
    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = "C:\Users"  # Specify the path to monitor here
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true

    Register-ObjectEvent $fileWatcher "Created" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Host "New file created: $filePath"

        $scanResults = Get-VirusTotalScan -FilePath $filePath

        # Check if the file is detected as malware on VirusTotal
        if ($scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
            Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
        }
    } | Out-Null
}

# Function to monitor file creations in network shares
function Monitor-NetworkFileCreations {
    $networkShares = Get-WmiObject Win32_Share | Where-Object { $_.Type -eq 0 } | Select-Object -ExpandProperty Path
    foreach ($share in $networkShares) {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $share
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true

        Register-ObjectEvent $fileWatcher "Created" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Write-Host "File created on network share: $filePath"

            $scanResults = Get-VirusTotalScan -FilePath $filePath

            # Check if the file is detected as malware on VirusTotal
            if ($scanResults -ne $null -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
                Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
            }
        } | Out-Null
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

# Start monitoring file creations
Monitor-FileCreations
Monitor-NetworkFileCreations
