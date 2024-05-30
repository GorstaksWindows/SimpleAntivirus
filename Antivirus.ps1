# Hide the console window
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("User32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)  # 0 hides the window

# Set your VirusTotal public API key here
$VirusTotalApiKey = "0393b0784dba04ea0c6f5c1e45cac1c35ba83b1fc09e1d792d270dcc159d53d8"

# Configurable parameters
$MonitoringInterval = 60 # Time in seconds to wait before checking the scan results again

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

# Load necessary .NET assemblies for system tray icon
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Function to create the installation directory
function Create-InstallationDirectory {
    $installDir = Join-Path $env:ProgramFiles "SimpleAntivirus"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir | Out-Null
    }

    return $installDir
}

# Function to move the script to the installation directory
function Move-ToInstallationDirectory {
    $installDir = Create-InstallationDirectory
    $scriptPath = $MyInvocation.MyCommand.Definition
    $destination = Join-Path $installDir (Split-Path $scriptPath -Leaf)

    # Move the script to the installation directory
    Move-Item $scriptPath $destination -Force
    return $destination
}

# Function to initialize logging
function Initialize-Logging {
    $installDir = Create-InstallationDirectory
    $logFilePath = Join-Path $installDir "SimpleAntivirusLog.log"
    # Create or truncate the log file
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
    return $logFilePath
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFilePath -Value $logMessage
}

# Function to create the system tray icon
function Create-TrayIcon {
    # Use the executable's own icon
    $iconPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $trayIcon = New-Object System.Windows.Forms.NotifyIcon
    $trayIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
    $trayIcon.Text = "Simple Antivirus"
    $trayIcon.Visible = $true

    # Create a context menu for the tray icon
    $contextMenu = New-Object System.Windows.Forms.ContextMenu
    $viewLogItem = New-Object System.Windows.Forms.MenuItem "View Log"
    $exitItem = New-Object System.Windows.Forms.MenuItem "Exit"

    $contextMenu.MenuItems.Add($viewLogItem)
    $contextMenu.MenuItems.Add($exitItem)
    $trayIcon.ContextMenu = $contextMenu

    # Add event handler for View Log
    $viewLogItem.add_Click({
        $installDir = Create-InstallationDirectory
        $logFilePath = Join-Path $installDir "SimpleAntivirusLog.log"
        if (Test-Path $logFilePath) {
            Invoke-Item $logFilePath
        } else {
            [System.Windows.Forms.MessageBox]::Show("Log file not found.", "Simple Antivirus")
        }
    })

    # Add event handler for Exit
    $exitItem.add_Click({
        $trayIcon.Visible = $false
        [System.Windows.Forms.Application]::Exit()
        Stop-Process -Id $PID
    })

    # Prevent the script from exiting
    [System.Windows.Forms.Application]::Run()
}

# Function to add the executable to Windows startup folder
function AddToStartup {
    $installDir = Create-InstallationDirectory
    $executablePath = Join-Path $installDir "Antivirus.exe"
    $startupFolderPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Startup"), "SimpleAntivirus.lnk")

    if (-not (Test-Path $startupFolderPath)) {
        Move-Item -Path $executablePath -Destination $startupFolderPath -Force
        Write-Log "Executable moved to startup folder."
    }
}

# Initialize logging
$logFilePath = Initialize-Logging
Write-Log "Script installed to $($installDir)."

function Write-Log {
    param (
        [string]$Message
    )

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp - $Message"
        Add-Content -Path $logFilePath -Value $logMessage -ErrorAction Stop
    } catch {
        Write-Error "Failed to write to log file: $_"
    }
}

# Create and show the system tray icon
Create-TrayIcon

# Add script to startup
AddToStartup
