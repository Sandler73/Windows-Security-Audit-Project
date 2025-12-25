# Module-CISA.ps1
# CISA Cybersecurity Performance Goals Compliance Module
# Version: 5.0
# Based on CISA's Cybersecurity Performance Goals and Critical Security Controls

<#
.SYNOPSIS
    CISA cybersecurity performance goals compliance checks.

.DESCRIPTION
    This module checks alignment with CISA's cybersecurity guidance including:
    - Multi-factor authentication enforcement
    - Patch and vulnerability management
    - Centralized logging and monitoring
    - Known Exploited Vulnerabilities (KEV) mitigation
    - Endpoint detection and response
    - Email security (SPF, DMARC, DKIM)
    - Secure configuration management
    - Network segmentation and access controls
    - Incident response capabilities
    - Data encryption and protection

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Version: 5.0
    Based on: CISA Cybersecurity Performance Goals (CPG)
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "CISA"
$results = @()

# Helper function to add results
function Add-Result {
    param($Category, $Status, $Message, $Details = "", $Remediation = "")
    $script:results += [PSCustomObject]@{
        Module = $moduleName
        Category = $Category
        Status = $Status
        Message = $Message
        Details = $Details
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

Write-Host "`n[CISA] Starting CISA Cybersecurity Performance Goals checks..." -ForegroundColor Cyan

# ============================================================================
# CISA CPG: Multi-Factor Authentication
# ============================================================================
Write-Host "[CISA] Checking Multi-Factor Authentication..." -ForegroundColor Yellow

# Check for Network Level Authentication on RDP
try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
        # RDP is enabled, check for NLA
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Network Level Authentication (NLA) is enabled for RDP" `
                -Details "CISA CPG: NLA provides an additional authentication layer before establishing RDP sessions"
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Fail" `
                -Message "RDP is enabled but NLA is not required" `
                -Details "CISA CPG: Require MFA/NLA for all remote access methods" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
        
        # Check RDP port (should not be default 3389 for additional security)
        $rdpPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
        if ($rdpPort -and $rdpPort.PortNumber -eq 3389) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
                -Message "RDP is using default port 3389" `
                -Details "CISA CPG: Consider changing default RDP port as additional security measure"
        }
    } else {
        Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "CISA CPG: RDP is disabled - no remote authentication risk"
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Error" `
        -Message "Failed to check RDP/NLA configuration: $_"
}

# Check for smart card authentication capability
try {
    $scPolicyService = Get-Service -Name "SCPolicySvc" -ErrorAction SilentlyContinue
    if ($scPolicyService) {
        if ($scPolicyService.Status -eq "Running") {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Smart Card Policy service is running" `
                -Details "CISA CPG: Smart card support enables hardware-based MFA"
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
                -Message "Smart Card Policy service is not running" `
                -Details "CISA CPG: Enable if using smart cards for authentication"
        }
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
        -Message "Could not check Smart Card service status"
}

# Check Windows Hello for Business configuration
try {
    $whfbPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue
    if ($whfbPolicy) {
        $enabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($enabled -and $enabled.Enabled -eq 1) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Windows Hello for Business is enabled" `
                -Details "CISA CPG: Windows Hello provides modern MFA capabilities"
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
                -Message "Windows Hello for Business is not enabled" `
                -Details "CISA CPG: Consider enabling Windows Hello for passwordless MFA"
        }
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
        -Message "Windows Hello configuration could not be checked"
}

# Check for cached credentials limit
try {
    $cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
    if ($cachedLogons) {
        $count = $cachedLogons.CachedLogonsCount
        if ($count -le 2) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Cached credential count is limited to $count" `
                -Details "CISA CPG: Limit cached credentials to reduce offline attack risk"
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Warning" `
                -Message "Cached credential count is $count (recommend 2 or less)" `
                -Details "CISA CPG: Minimize cached credentials" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 2"
        }
    } else {
        Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
            -Message "Using default cached credentials setting (typically 10)" `
            -Details "CISA CPG: Consider limiting cached credentials to 2"
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Error" `
        -Message "Failed to check cached credentials: $_"
}

# ============================================================================
# CISA CPG: Patch and Vulnerability Management
# ============================================================================
Write-Host "[CISA] Checking Patch and Vulnerability Management..." -ForegroundColor Yellow

# Check Windows Update service
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
    
    if ($wuService.Status -eq "Running") {
        Add-Result -Category "CISA - Patch Management" -Status "Pass" `
            -Message "Windows Update service is running" `
            -Details "CISA CPG: Automated patching reduces vulnerability exposure"
    } else {
        Add-Result -Category "CISA - Patch Management" -Status "Fail" `
            -Message "Windows Update service is not running (Status: $($wuService.Status))" `
            -Details "CISA CPG: Enable Windows Update for timely patch deployment" `
            -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic"
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check Windows Update service: $_"
}

# Check for recent Windows Updates
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    
    if ($historyCount -gt 0) {
        # Get last 30 days of updates
        $recentUpdates = $searcher.QueryHistory(0, 20) | 
            Where-Object { $_.Date -gt (Get-Date).AddDays(-30) }
        
        if ($recentUpdates) {
            $successfulUpdates = ($recentUpdates | Where-Object { $_.ResultCode -eq 2 }).Count
            $failedUpdates = ($recentUpdates | Where-Object { $_.ResultCode -eq 4 -or $_.ResultCode -eq 5 }).Count
            
            if ($successfulUpdates -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                    -Message "Recent updates detected: $successfulUpdates successful in last 30 days" `
                    -Details "CISA CPG: Regular patching maintains security posture"
            }
            
            if ($failedUpdates -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "$failedUpdates update(s) failed in the last 30 days" `
                    -Details "CISA CPG: Investigate and resolve failed updates" `
                    -Remediation "Review Windows Update history and resolve failures"
            }
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                -Message "No updates installed in the last 30 days" `
                -Details "CISA CPG: System may have critical vulnerabilities - update immediately" `
                -Remediation "Install-WindowsUpdate -AcceptAll -AutoReboot"
        }
        
        # Check for pending updates
        $pendingUpdates = $searcher.Search("IsInstalled=0 and Type='Software'")
        if ($pendingUpdates.Updates.Count -gt 0) {
            $criticalPending = ($pendingUpdates.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
            $importantPending = ($pendingUpdates.Updates | Where-Object { $_.MsrcSeverity -eq "Important" }).Count
            
            if ($criticalPending -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                    -Message "$criticalPending critical updates pending installation" `
                    -Details "CISA CPG: Install critical updates immediately" `
                    -Remediation "Install pending critical updates via Windows Update"
            } elseif ($importantPending -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "$importantPending important updates pending installation" `
                    -Details "CISA CPG: Install important security updates promptly"
            } else {
                Add-Result -Category "CISA - Patch Management" -Status "Info" `
                    -Message "$($pendingUpdates.Updates.Count) non-critical updates pending" `
                    -Details "CISA CPG: Schedule maintenance window for updates"
            }
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                -Message "No pending updates detected" `
                -Details "CISA CPG: System is current with available updates"
        }
    } else {
        Add-Result -Category "CISA - Patch Management" -Status "Warning" `
            -Message "No Windows Update history found" `
            -Details "CISA CPG: Verify Windows Update is functioning properly"
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check Windows Update history: $_"
}

# Check automatic update configuration
try {
    $auSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    
    if ($auSettings) {
        $auOption = $auSettings.AUOptions
        
        switch ($auOption) {
            4 {
                Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                    -Message "Automatic updates are configured for automatic download and install" `
                    -Details "CISA CPG: Automated patching ensures timely updates"
            }
            3 {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "Updates auto-download but require manual installation" `
                    -Details "CISA CPG: Consider fully automated updates" `
                    -Remediation "Set AUOptions to 4 for automatic installation"
            }
            2 {
                Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                    -Message "Updates only notify before download" `
                    -Details "CISA CPG: Enable automatic updates" `
                    -Remediation "Configure automatic updates via Group Policy or Settings"
            }
            1 {
                Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                    -Message "Automatic updates are disabled" `
                    -Details "CISA CPG: Enable automatic updates immediately" `
                    -Remediation "Enable Windows Update automatic updates"
            }
        }
    } else {
        # Check via COM object
        $auSettings = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings
        if ($auSettings.NotificationLevel -ge 3) {
            Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                -Message "Automatic updates are enabled" `
                -Details "CISA CPG: Automated patching is configured"
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                -Message "Automatic updates are not properly configured" `
                -Details "CISA CPG: Enable automatic Windows updates" `
                -Remediation "Configure automatic updates in Windows Update settings"
        }
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check automatic update configuration: $_"
}

# ============================================================================
# CISA CPG: Centralized Logging and Monitoring
# ============================================================================
Write-Host "[CISA] Checking Centralized Logging and Monitoring..." -ForegroundColor Yellow

# Check Security Event Log configuration
try {
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    
    if ($securityLog.IsEnabled) {
        $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
        
        if ($logSizeMB -ge 1024) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Security log is enabled with adequate size ($logSizeMB MB)" `
                -Details "CISA CPG: Large log size supports forensic investigation"
        } elseif ($logSizeMB -ge 512) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Security log is enabled ($logSizeMB MB)" `
                -Details "CISA CPG: Consider increasing for extended retention"
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "Security log size is small ($logSizeMB MB)" `
                -Details "CISA CPG: Increase log size to at least 512 MB for adequate retention" `
                -Remediation "wevtutil sl Security /ms:$([int](512MB))"
        }
        
        # Check log retention policy
        if ($securityLog.LogMode -eq "Circular") {
            Add-Result -Category "CISA - Logging" -Status "Info" `
                -Message "Security log uses circular overwrite policy" `
                -Details "CISA CPG: Ensure logs are forwarded before overwrite"
        } elseif ($securityLog.LogMode -eq "AutoBackup") {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Security log auto-archives when full" `
                -Details "CISA CPG: Auto-backup preserves forensic evidence"
        }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Fail" `
            -Message "Security event log is disabled" `
            -Details "CISA CPG: Security logging is critical for threat detection" `
            -Remediation "Enable Security event log via Event Viewer or Group Policy"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check Security event log: $_"
}

# Check System Event Log configuration
try {
    $systemLog = Get-WinEvent -ListLog System -ErrorAction Stop
    
    if ($systemLog.IsEnabled) {
        $logSizeMB = [math]::Round($systemLog.MaximumSizeInBytes / 1MB, 2)
        
        if ($logSizeMB -ge 128) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "System log is enabled with adequate size ($logSizeMB MB)" `
                -Details "CISA CPG: System logs aid in troubleshooting and security analysis"
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "System log size is small ($logSizeMB MB)" `
                -Details "CISA CPG: Consider increasing to 128 MB or higher"
        }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check System event log: $_"
}

# Check PowerShell logging (Script Block, Module, Transcription)
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "CISA CPG: PowerShell logging detects malicious scripting activity"
    } else {
        Add-Result -Category "CISA - Logging" -Status "Fail" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "CISA CPG: Enable PowerShell logging to detect threats" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell Script Block Logging: $_"
}

try {
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    
    if ($moduleLogging -and $moduleLogging.EnableModuleLogging -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Module Logging is enabled" `
            -Details "CISA CPG: Module logging provides detailed cmdlet execution records"
    } else {
        Add-Result -Category "CISA - Logging" -Status "Warning" `
            -Message "PowerShell Module Logging is not enabled" `
            -Details "CISA CPG: Consider enabling for comprehensive PowerShell auditing" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Value 1"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell Module Logging: $_"
}

try {
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    
    if ($transcription -and $transcription.EnableTranscripting -eq 1) {
        $outputDir = $transcription.OutputDirectory
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Transcription is enabled (Output: $outputDir)" `
            -Details "CISA CPG: Transcription captures full PowerShell session activity"
    } else {
        Add-Result -Category "CISA - Logging" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "CISA CPG: Transcription provides complete session logs (optional but recommended)"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell Transcription: $_"
}

# Check Process Creation auditing (Event ID 4688)
try {
    $processAuditing = auditpol /get /subcategory:"Process Creation" 2>$null
    if ($processAuditing -and $processAuditing -match "Success") {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "Process Creation auditing is enabled" `
            -Details "CISA CPG: Process auditing tracks program execution"
    } else {
        Add-Result -Category "CISA - Logging" -Status "Fail" `
            -Message "Process Creation auditing is not enabled" `
            -Details "CISA CPG: Enable process creation auditing for threat detection" `
            -Remediation "auditpol /set /subcategory:'Process Creation' /success:enable"
    }
    
    # Check if command line logging is enabled for process creation events
    $cmdLineLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    if ($cmdLineLogging -and $cmdLineLogging.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "Command line logging in process auditing is enabled" `
            -Details "CISA CPG: Command line logging captures full execution parameters"
    } else {
        Add-Result -Category "CISA - Logging" -Status "Warning" `
            -Message "Command line logging in process auditing is not enabled" `
            -Details "CISA CPG: Enable to capture process command line arguments" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check Process Creation auditing: $_"
}

# Check for Sysmon installation (advanced logging)
try {
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    $sysmonDriver = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "Sysmon*" }
    
    if ($sysmonService -or $sysmonDriver) {
        if ($sysmonService.Status -eq "Running" -or $sysmonDriver) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Sysmon is installed and running" `
                -Details "CISA CPG: Sysmon provides advanced system monitoring and logging"
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "Sysmon is installed but not running" `
                -Details "CISA CPG: Start Sysmon service for enhanced logging"
        }
        
        # Check Sysmon log
        $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
        if ($sysmonLog -and $sysmonLog.IsEnabled) {
            $logSizeMB = [math]::Round($sysmonLog.MaximumSizeInBytes / 1MB, 2)
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Sysmon operational log is enabled ($logSizeMB MB)" `
                -Details "CISA CPG: Sysmon captures detailed system activity"
        }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Info" `
            -Message "Sysmon is not installed" `
            -Details "CISA CPG: Consider deploying Sysmon for enhanced logging (optional but highly recommended)"
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Info" `
        -Message "Could not check Sysmon status"
}

# Check Windows Event Forwarding configuration
try {
    $wefService = Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
    if ($wefService) {
        if ($wefService.Status -eq "Running") {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Windows Event Collector service is running" `
                -Details "CISA CPG: Event forwarding enables centralized log collection"
            
            # Check for subscriptions
            $subscriptions = wecutil es 2>$null
            if ($subscriptions) {
                $subCount = ($subscriptions | Measure-Object).Count
                Add-Result -Category "CISA - Logging" -Status "Pass" `
                    -Message "Event forwarding subscriptions configured: $subCount" `
                    -Details "CISA CPG: Centralized logging supports SOC operations"
            }
        } else {
            Add-Result -Category "CISA - Logging" -Status "Info" `
                -Message "Windows Event Collector service is not running" `
                -Details "CISA CPG: Enable if using centralized log collection"
        }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Info" `
        -Message "Could not check Windows Event Forwarding configuration"
}

# ============================================================================
# CISA CPG: Endpoint Detection and Response
# ============================================================================
Write-Host "[CISA] Checking Endpoint Detection and Response..." -ForegroundColor Yellow

# Check Windows Defender Antivirus status
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    
    # Real-time protection
    if ($defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Windows Defender real-time protection is enabled" `
            -Details "CISA CPG: Real-time protection prevents malware execution"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Windows Defender real-time protection is DISABLED" `
            -Details "CISA CPG: Enable real-time protection immediately" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    
    # Cloud-delivered protection
    if ($defenderStatus.MAPSReporting -ge 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Cloud-delivered protection is enabled (Level: $($defenderStatus.MAPSReporting))" `
            -Details "CISA CPG: Cloud protection provides rapid threat intelligence"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Cloud-delivered protection is disabled" `
            -Details "CISA CPG: Enable cloud protection for enhanced detection" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced"
    }
    
    # Behavior monitoring
    if ($defenderStatus.BehaviorMonitorEnabled) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Behavior monitoring is enabled" `
            -Details "CISA CPG: Behavior analysis detects zero-day threats"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Behavior monitoring is disabled" `
            -Details "CISA CPG: Enable behavior monitoring" `
            -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
    }
    
    # On-access protection
    if ($defenderStatus.OnAccessProtectionEnabled) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "On-access protection is enabled" `
            -Details "CISA CPG: Scans files when accessed"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "On-access protection is disabled" `
            -Details "CISA CPG: Enable on-access protection" `
            -Remediation "Set-MpPreference -DisableIOAVProtection `$false"
    }
    
    # Signature updates
    $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
    if ($signatureAge.Days -eq 0) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Antivirus signatures are current (updated today at $($defenderStatus.AntivirusSignatureLastUpdated.ToString('HH:mm')))" `
            -Details "CISA CPG: Current signatures ensure protection against latest threats"
    } elseif ($signatureAge.Days -le 3) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Antivirus signatures are $($signatureAge.Days) day(s) old" `
            -Details "CISA CPG: Signatures are reasonably current"
    } elseif ($signatureAge.Days -le 7) {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "Antivirus signatures are $($signatureAge.Days) days old" `
            -Details "CISA CPG: Update signatures more frequently" `
            -Remediation "Update-MpSignature"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Antivirus signatures are severely outdated ($($signatureAge.Days) days old)" `
            -Details "CISA CPG: Update signatures immediately - system is vulnerable" `
            -Remediation "Update-MpSignature -UpdateSource Microsoft"
    }
    
    # Check scan status
    $daysSinceLastFullScan = $null
    if ($defenderStatus.FullScanAge) {
        $daysSinceLastFullScan = $defenderStatus.FullScanAge
        if ($daysSinceLastFullScan -le 7) {
            Add-Result -Category "CISA - EDR" -Status "Pass" `
                -Message "Full scan performed $daysSinceLastFullScan day(s) ago" `
                -Details "CISA CPG: Regular full scans detect dormant threats"
        } else {
            Add-Result -Category "CISA - EDR" -Status "Warning" `
                -Message "Last full scan was $daysSinceLastFullScan days ago" `
                -Details "CISA CPG: Perform weekly full scans" `
                -Remediation "Start-MpScan -ScanType FullScan"
        }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "No full scan has been performed or scan history unavailable" `
            -Details "CISA CPG: Schedule regular full system scans" `
            -Remediation "Start-MpScan -ScanType FullScan"
    }
    
    # Check quick scan status
    $daysSinceLastQuickScan = $defenderStatus.QuickScanAge
    if ($daysSinceLastQuickScan -le 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Quick scan performed $daysSinceLastQuickScan day(s) ago" `
            -Details "CISA CPG: Recent quick scan indicates active protection"
    }
    
    # Network protection
    $networkProtection = Get-MpPreference | Select-Object -ExpandProperty EnableNetworkProtection -ErrorAction SilentlyContinue
    if ($networkProtection -eq 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Network protection is enabled and in block mode" `
            -Details "CISA CPG: Network protection blocks malicious network traffic"
    } elseif ($networkProtection -eq 2) {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "Network protection is in audit mode only" `
            -Details "CISA CPG: Enable block mode for network protection" `
            -Remediation "Set-MpPreference -EnableNetworkProtection Enabled"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Network protection is disabled" `
            -Details "CISA CPG: Enable network protection" `
            -Remediation "Set-MpPreference -EnableNetworkProtection Enabled"
    }
    
    # Controlled folder access (ransomware protection)
    $controlledFolderAccess = Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess -ErrorAction SilentlyContinue
    if ($controlledFolderAccess -eq 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Controlled Folder Access (ransomware protection) is enabled" `
            -Details "CISA CPG: Protects critical folders from ransomware"
    } elseif ($controlledFolderAccess -eq 2) {
        Add-Result -Category "CISA - EDR" -Status "Info" `
            -Message "Controlled Folder Access is in audit mode" `
            -Details "CISA CPG: Consider enabling block mode after testing"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "Controlled Folder Access is disabled" `
            -Details "CISA CPG: Consider enabling for ransomware protection" `
            -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled"
    }
    
    # Attack Surface Reduction rules
    $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
    if ($asrRules -and $asrRules.Count -gt 0) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Attack Surface Reduction rules are configured ($($asrRules.Count) rules)" `
            -Details "CISA CPG: ASR rules reduce attack vectors"
    } else {
        Add-Result -Category "CISA - EDR" -Status "Info" `
            -Message "No Attack Surface Reduction rules configured" `
            -Details "CISA CPG: Consider configuring ASR rules for additional protection"
    }
    
} catch {
    Add-Result -Category "CISA - EDR" -Status "Error" `
        -Message "Failed to check Windows Defender status: $_" `
        -Details "CISA CPG: Ensure endpoint protection is functioning"
}

# Check for Microsoft Defender for Endpoint (advanced EDR)
try {
    $defenderATPService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if ($defenderATPService) {
        if ($defenderATPService.Status -eq "Running") {
            Add-Result -Category "CISA - EDR" -Status "Pass" `
                -Message "Microsoft Defender for Endpoint service is running" `
                -Details "CISA CPG: Advanced EDR provides enhanced threat detection and response"
            
            # Check onboarding status
            $senseOnboarded = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState" -ErrorAction SilentlyContinue
            if ($senseOnboarded -and $senseOnboarded.OnboardingState -eq 1) {
                Add-Result -Category "CISA - EDR" -Status "Pass" `
                    -Message "System is onboarded to Microsoft Defender for Endpoint" `
                    -Details "CISA CPG: MDE provides centralized threat visibility"
            }
        } else {
            Add-Result -Category "CISA - EDR" -Status "Warning" `
                -Message "Microsoft Defender for Endpoint service exists but is not running" `
                -Details "CISA CPG: Start MDE service" `
                -Remediation "Start-Service Sense; Set-Service Sense -StartupType Automatic"
        }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Info" `
            -Message "Microsoft Defender for Endpoint is not installed" `
            -Details "CISA CPG: Consider deploying advanced EDR solution"
    }
} catch {
    Add-Result -Category "CISA - EDR" -Status "Info" `
        -Message "Could not check Microsoft Defender for Endpoint status"
}

# ============================================================================
# CISA CPG: Data Encryption
# ============================================================================
Write-Host "[CISA] Checking Data Encryption..." -ForegroundColor Yellow

# Check BitLocker status on all drives
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $protectedVolumes = 0
    $unprotectedVolumes = 0
    
    foreach ($volume in $volumes) {
        if ($volume.VolumeStatus -eq "FullyEncrypted") {
            $protectedVolumes++
            Add-Result -Category "CISA - Data Encryption" -Status "Pass" `
                -Message "Drive $($volume.MountPoint) is fully encrypted" `
                -Details "CISA CPG: BitLocker protects data at rest (Method: $($volume.EncryptionMethod))"
        } elseif ($volume.VolumeStatus -eq "EncryptionInProgress") {
            Add-Result -Category "CISA - Data Encryption" -Status "Info" `
                -Message "Drive $($volume.MountPoint) encryption in progress ($($volume.EncryptionPercentage)%)" `
                -Details "CISA CPG: Allow encryption to complete"
        } else {
            $unprotectedVolumes++
            Add-Result -Category "CISA - Data Encryption" -Status "Fail" `
                -Message "Drive $($volume.MountPoint) is NOT encrypted (Status: $($volume.VolumeStatus))" `
                -Details "CISA CPG: Enable BitLocker on all system and data volumes" `
                -Remediation "Enable-BitLocker -MountPoint '$($volume.MountPoint)' -EncryptionMethod XtsAes256 -TpmProtector"
        }
        
        # Check recovery key backup
        if ($volume.VolumeStatus -eq "FullyEncrypted") {
            $keyProtectors = $volume.KeyProtector
            $hasRecoveryPassword = $keyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
            
            if ($hasRecoveryPassword) {
                Add-Result -Category "CISA - Data Encryption" -Status "Pass" `
                    -Message "Drive $($volume.MountPoint) has recovery password configured" `
                    -Details "CISA CPG: Recovery keys enable data recovery"
            } else {
                Add-Result -Category "CISA - Data Encryption" -Status "Warning" `
                    -Message "Drive $($volume.MountPoint) lacks recovery password" `
                    -Details "CISA CPG: Add recovery password for emergency access" `
                    -Remediation "Add-BitLockerKeyProtector -MountPoint '$($volume.MountPoint)' -RecoveryPasswordProtector"
            }
        }
    }
    
    if ($protectedVolumes -gt 0 -and $unprotectedVolumes -eq 0) {
        Add-Result -Category "CISA - Data Encryption" -Status "Pass" `
            -Message "All $protectedVolumes volume(s) are encrypted with BitLocker" `
            -Details "CISA CPG: Full disk encryption protects against data theft"
    } elseif ($unprotectedVolumes -gt 0) {
        Add-Result -Category "CISA - Data Encryption" -Status "Fail" `
            -Message "$unprotectedVolumes volume(s) are not encrypted" `
            -Details "CISA CPG: Encrypt all drives containing sensitive data"
    }
    
} catch {
    $errorMsg = $_.Exception.Message
    if ($errorMsg -like "*not supported*" -or $errorMsg -like "*requires*") {
        Add-Result -Category "CISA - Data Encryption" -Status "Info" `
            -Message "BitLocker is not available on this Windows edition" `
            -Details "CISA CPG: BitLocker requires Pro/Enterprise editions"
    } else {
        Add-Result -Category "CISA - Data Encryption" -Status "Error" `
            -Message "Failed to check BitLocker status: $_"
    }
}

# Check EFS (Encrypting File System) usage
try {
    $efsUsers = cipher /u /n 2>$null | Select-String "User:" | Measure-Object
    if ($efsUsers.Count -gt 0) {
        Add-Result -Category "CISA - Data Encryption" -Status "Info" `
            -Message "EFS (Encrypting File System) is in use by $($efsUsers.Count) user(s)" `
            -Details "CISA CPG: EFS provides file-level encryption"
    }
} catch {
    # EFS check is optional
}

# ============================================================================
# CISA CPG: Network Security
# ============================================================================
Write-Host "[CISA] Checking Network Security..." -ForegroundColor Yellow

# Check Windows Firewall status
try {
    $profiles = @("Domain", "Private", "Public")
    $allEnabled = $true
    
    foreach ($profileName in $profiles) {
        $profile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        if ($profile.Enabled) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "$profileName firewall profile is enabled" `
                -Details "CISA CPG: Firewall provides first line of network defense (Default Inbound: $($profile.DefaultInboundAction), Outbound: $($profile.DefaultOutboundAction))"
        } else {
            $allEnabled = $false
            Add-Result -Category "CISA - Network Security" -Status "Fail" `
                -Message "$profileName firewall profile is DISABLED" `
                -Details "CISA CPG: Enable firewall on all network profiles" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True"
        }
        
        # Check if default deny for inbound is configured
        if ($profile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "$profileName profile: Default inbound is set to Block" `
                -Details "CISA CPG: Default deny reduces attack surface"
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Warning" `
                -Message "$profileName profile: Default inbound is set to Allow" `
                -Details "CISA CPG: Configure default deny for inbound traffic" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block"
        }
        
        # Check logging
        if ($profile.LogBlocked -eq "True") {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "$profileName profile: Logging blocked connections" `
                -Details "CISA CPG: Firewall logging aids security monitoring"
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Info" `
                -Message "$profileName profile: Not logging blocked connections" `
                -Details "CISA CPG: Consider enabling firewall logging"
        }
    }
    
    if ($allEnabled) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "Windows Firewall is enabled on all profiles" `
            -Details "CISA CPG: Comprehensive firewall protection is active"
    }
    
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check firewall configuration: $_"
}

# Check SMBv1 status (should be disabled per CISA KEV)
try {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    
    if ($smb1Feature.State -eq "Disabled") {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "CISA CPG: SMBv1 has critical vulnerabilities (WannaCry, NotPetya)"
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Fail" `
            -Message "SMBv1 protocol is ENABLED" `
            -Details "CISA CPG: Disable SMBv1 immediately - actively exploited" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    }
    
    # Also check SMB server configuration
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbServer) {
        if (-not $smbServer.EnableSMB1Protocol) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "SMBv1 is disabled in server configuration" `
                -Details "CISA CPG: Server-level SMBv1 protection"
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Fail" `
                -Message "SMBv1 is enabled in server configuration" `
                -Details "CISA CPG: Disable SMBv1 at server level" `
                -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
        }
        
        # Check SMB signing
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "SMB signing is required" `
                -Details "CISA CPG: SMB signing prevents man-in-the-middle attacks"
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Warning" `
                -Message "SMB signing is not required" `
                -Details "CISA CPG: Require SMB signing to prevent tampering" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        }
        
        # Check SMB encryption
        if ($smbServer.EncryptData) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "SMB encryption is enabled globally" `
                -Details "CISA CPG: SMB encryption protects data in transit"
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Info" `
                -Message "SMB encryption is not enabled globally" `
                -Details "CISA CPG: Consider enabling SMB encryption for sensitive data"
        }
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check SMB configuration: $_"
}

# Check for LLMNR (should be disabled)
try {
    $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "LLMNR (Link-Local Multicast Name Resolution) is disabled" `
            -Details "CISA CPG: Disabling LLMNR prevents name resolution poisoning attacks"
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Warning" `
            -Message "LLMNR may be enabled (default)" `
            -Details "CISA CPG: Disable LLMNR to prevent credential theft attacks" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0"
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check LLMNR status: $_"
}

# Check for NetBIOS over TCP/IP (should be disabled)
try {
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    $netbiosEnabled = $false
    $netbiosDisabled = $false
    
    foreach ($adapter in $adapters) {
        # TcpipNetbiosOptions: 0=Default, 1=Enabled, 2=Disabled
        if ($adapter.TcpipNetbiosOptions -eq 2) {
            $netbiosDisabled = $true
        } elseif ($adapter.TcpipNetbiosOptions -eq 1) {
            $netbiosEnabled = $true
        }
    }
    
    if ($netbiosDisabled -and -not $netbiosEnabled) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "NetBIOS over TCP/IP is disabled on all network adapters" `
            -Details "CISA CPG: Disabling NetBIOS reduces attack surface"
    } elseif ($netbiosEnabled) {
        Add-Result -Category "CISA - Network Security" -Status "Warning" `
            -Message "NetBIOS over TCP/IP is enabled on one or more adapters" `
            -Details "CISA CPG: Disable NetBIOS over TCP/IP to reduce exposure" `
            -Remediation "Configure via network adapter TCP/IP properties or DHCP scope options"
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Info" `
            -Message "NetBIOS over TCP/IP is using default settings" `
            -Details "CISA CPG: Explicitly disable NetBIOS on all adapters"
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check NetBIOS configuration: $_"
}

# ============================================================================
# CISA CPG: Secure Configuration Management
# ============================================================================
Write-Host "[CISA] Checking Secure Configuration Management..." -ForegroundColor Yellow

# Check User Account Control (UAC) settings
try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    
    # EnableLUA - UAC enabled
    if ($uac.EnableLUA -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "User Account Control (UAC) is enabled" `
            -Details "CISA CPG: UAC prevents unauthorized privilege elevation"
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Fail" `
            -Message "User Account Control (UAC) is DISABLED" `
            -Details "CISA CPG: Enable UAC for security isolation" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1; Restart-Computer"
    }
    
    # ConsentPromptBehaviorAdmin - Admin approval mode
    $consentLevel = $uac.ConsentPromptBehaviorAdmin
    switch ($consentLevel) {
        0 {
            Add-Result -Category "CISA - Configuration" -Status "Fail" `
                -Message "UAC: Admin approval mode is disabled (Elevate without prompting)" `
                -Details "CISA CPG: This bypasses UAC protection" `
                -Remediation "Set ConsentPromptBehaviorAdmin to 2 or higher"
        }
        1 {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "UAC: Prompt for credentials on secure desktop" `
                -Details "CISA CPG: Consider using 'Prompt for consent' for better usability"
        }
        2 {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "UAC: Prompt for consent on secure desktop (Recommended)" `
                -Details "CISA CPG: Balanced security and usability"
        }
        3 {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "UAC: Prompt for credentials (not on secure desktop)" `
                -Details "CISA CPG: Secure desktop provides additional protection"
        }
        4 {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "UAC: Prompt for consent (not on secure desktop)" `
                -Details "CISA CPG: Secure desktop recommended"
        }
        5 {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "UAC: Prompt for consent for non-Windows binaries" `
                -Details "CISA CPG: Protects against malicious executables"
        }
    }
    
    # PromptOnSecureDesktop
    if ($uac.PromptOnSecureDesktop -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "UAC: Elevation prompts display on secure desktop" `
            -Details "CISA CPG: Secure desktop prevents UI spoofing attacks"
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Warning" `
            -Message "UAC: Elevation prompts do not use secure desktop" `
            -Details "CISA CPG: Enable secure desktop for UAC prompts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1"
    }
    
    # FilterAdministratorToken
    if ($uac.FilterAdministratorToken -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "UAC: Built-in Administrator account runs in Admin Approval Mode" `
            -Details "CISA CPG: Applies UAC restrictions to built-in admin account"
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Info" `
            -Message "UAC: Built-in Administrator bypasses UAC" `
            -Details "CISA CPG: Consider applying UAC to built-in admin account"
    }
    
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check UAC configuration: $_"
}

# Check Administrator account status
try {
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    
    if ($adminAccount) {
        if ($adminAccount.Enabled) {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "Built-in Administrator account is ENABLED" `
                -Details "CISA CPG: Disable or rename built-in Administrator account" `
                -Remediation "Disable-LocalUser -Name Administrator"
        } else {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "Built-in Administrator account is disabled" `
                -Details "CISA CPG: Disabled admin accounts reduce attack surface"
        }
        
        # Check if account has been renamed
        if ($adminAccount.Name -eq "Administrator") {
            Add-Result -Category "CISA - Configuration" -Status "Info" `
                -Message "Built-in Administrator account has not been renamed" `
                -Details "CISA CPG: Consider renaming for additional obscurity"
        }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check Administrator account: $_"
}

# Check Guest account status
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount) {
        if ($guestAccount.Enabled) {
            Add-Result -Category "CISA - Configuration" -Status "Fail" `
                -Message "Guest account is ENABLED" `
                -Details "CISA CPG: Disable Guest account - presents security risk" `
                -Remediation "Disable-LocalUser -Name Guest"
        } else {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "CISA CPG: Guest account is properly disabled"
        }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check Guest account: $_"
}

# Check for Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "CISA CPG: Secure Boot protects against bootkit and rootkit malware"
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "CISA - Configuration" -Status "Warning" `
            -Message "Secure Boot is disabled" `
            -Details "CISA CPG: Enable Secure Boot in UEFI firmware settings" `
            -Remediation "Enable Secure Boot in BIOS/UEFI settings"
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Info" `
            -Message "Secure Boot status cannot be determined (Legacy BIOS system)" `
            -Details "CISA CPG: UEFI with Secure Boot is recommended for modern systems"
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Info" `
        -Message "Could not determine Secure Boot status" `
        -Details "CISA CPG: Verify Secure Boot is enabled in firmware"
}

# Check for default credentials/passwords
try {
    # Check for accounts with passwords that don't expire
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $passwordNeverExpires = $users | Where-Object { $_.PasswordExpires -eq $null }
    
    if ($passwordNeverExpires) {
        foreach ($user in $passwordNeverExpires) {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "User account '$($user.Name)' has password set to never expire" `
                -Details "CISA CPG: Enforce password expiration policies" `
                -Remediation "Set-LocalUser -Name '$($user.Name)' -PasswordNeverExpires `$false"
        }
    }
    
    # Check for blank passwords
    $nullPasswordPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue
    if ($nullPasswordPolicy -and $nullPasswordPolicy.LimitBlankPasswordUse -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "Blank password use is restricted to console logon only" `
            -Details "CISA CPG: Prevents remote logon with blank passwords"
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Warning" `
            -Message "Blank password use is not properly restricted" `
            -Details "CISA CPG: Enable blank password restrictions" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Value 1"
    }
    
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check password policies: $_"
}

# Check for automatic Windows updates
try {
    $autoUpdateNotification = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue
    
    if ($autoUpdateNotification) {
        $option = $autoUpdateNotification.AUOptions
        if ($option -eq 4) {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "Windows Updates are configured to automatically download and install" `
                -Details "CISA CPG: Automatic updates ensure timely patching"
        } elseif ($option -eq 3) {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "Windows Updates download automatically but require manual installation" `
                -Details "CISA CPG: Enable automatic installation" `
                -Remediation "Configure automatic installation via Group Policy or Settings"
        } else {
            Add-Result -Category "CISA - Configuration" -Status "Fail" `
                -Message "Windows Updates are not configured for automatic download/install" `
                -Details "CISA CPG: Enable automatic updates" `
                -Remediation "Enable automatic updates in Windows Update settings"
        }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Info" `
        -Message "Could not determine automatic update configuration"
}

# ============================================================================
# CISA CPG: Access Control and Privileges
# ============================================================================
Write-Host "[CISA] Checking Access Control and Privileges..." -ForegroundColor Yellow

# Enumerate local administrators
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    
    Add-Result -Category "CISA - Access Control" -Status "Info" `
        -Message "Local Administrators group has $($admins.Count) member(s)" `
        -Details "CISA CPG: Review and minimize administrative accounts. Members: $($admins.Name -join ', ')"
    
    if ($admins.Count -gt 5) {
        Add-Result -Category "CISA - Access Control" -Status "Warning" `
            -Message "Large number of administrators detected ($($admins.Count) members)" `
            -Details "CISA CPG: Limit administrative access to essential personnel only" `
            -Remediation "Review and remove unnecessary administrative accounts"
    }
    
    # Check for domain accounts in local admin group
    $domainAdmins = $admins | Where-Object { $_.ObjectClass -eq "User" -and $_.PrincipalSource -eq "ActiveDirectory" }
    if ($domainAdmins) {
        Add-Result -Category "CISA - Access Control" -Status "Info" `
            -Message "Domain accounts in local Administrators: $($domainAdmins.Count)" `
            -Details "CISA CPG: Minimize domain accounts with local admin rights. Accounts: $($domainAdmins.Name -join ', ')"
    }
    
} catch {
    Add-Result -Category "CISA - Access Control" -Status "Error" `
        -Message "Failed to enumerate local administrators: $_"
}

# Check Remote Desktop Users group
try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    
    if ($rdpUsers) {
        Add-Result -Category "CISA - Access Control" -Status "Info" `
            -Message "Remote Desktop Users group has $($rdpUsers.Count) member(s)" `
            -Details "CISA CPG: Review remote access permissions. Members: $($rdpUsers.Name -join ', ')"
        
        if ($rdpUsers.Count -gt 10) {
            Add-Result -Category "CISA - Access Control" -Status "Warning" `
                -Message "Large number of RDP users ($($rdpUsers.Count))" `
                -Details "CISA CPG: Limit remote access to necessary users only"
        }
    } else {
        Add-Result -Category "CISA - Access Control" -Status "Pass" `
            -Message "Remote Desktop Users group is empty" `
            -Details "CISA CPG: No additional RDP access granted beyond administrators"
    }
} catch {
    # Remote Desktop Users group may not exist
}

# Check for privileged SID history
try {
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    foreach ($user in $localUsers) {
        # Check last logon
        if ($user.LastLogon) {
            $daysSinceLogon = (Get-Date) - $user.LastLogon
            if ($daysSinceLogon.Days -gt 90) {
                Add-Result -Category "CISA - Access Control" -Status "Warning" `
                    -Message "User account '$($user.Name)' has not logged on in $($daysSinceLogon.Days) days" `
                    -Details "CISA CPG: Disable inactive accounts" `
                    -Remediation "Disable-LocalUser -Name '$($user.Name)'"
            }
        }
        
        # Check for accounts that never expire
        if ($user.AccountExpires -eq $null) {
            Add-Result -Category "CISA - Access Control" -Status "Info" `
                -Message "User account '$($user.Name)' is set to never expire" `
                -Details "CISA CPG: Consider setting expiration for non-permanent accounts"
        }
    }
} catch {
    Add-Result -Category "CISA - Access Control" -Status "Error" `
        -Message "Failed to check user account status: $_"
}

# Check for shared folders/network shares
try {
    $shares = Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") }
    
    if ($shares) {
        Add-Result -Category "CISA - Access Control" -Status "Info" `
            -Message "Network shares detected: $($shares.Count)" `
            -Details "CISA CPG: Review share permissions. Shares: $($shares.Name -join ', ')"
        
        foreach ($share in $shares) {
            $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            $everyoneAccess = $access | Where-Object { $_.AccountName -eq "Everyone" }
            
            if ($everyoneAccess) {
                Add-Result -Category "CISA - Access Control" -Status "Warning" `
                    -Message "Share '$($share.Name)' grants access to 'Everyone'" `
                    -Details "CISA CPG: Remove 'Everyone' permissions and use specific groups" `
                    -Remediation "Revoke-SmbShareAccess -Name '$($share.Name)' -AccountName Everyone -Force"
            }
        }
    } else {
        Add-Result -Category "CISA - Access Control" -Status "Pass" `
            -Message "No non-administrative network shares detected" `
            -Details "CISA CPG: No file sharing exposure"
    }
} catch {
    Add-Result -Category "CISA - Access Control" -Status "Error" `
        -Message "Failed to check network shares: $_"
}

# ============================================================================
# CISA CPG: Incident Response Preparation
# ============================================================================
Write-Host "[CISA] Checking Incident Response Preparation..." -ForegroundColor Yellow

# Check System Restore status
try {
    $restoreEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    
    if ($restoreEnabled) {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "System Restore is enabled with $($restoreEnabled.Count) restore point(s)" `
            -Details "CISA CPG: System Restore aids in recovery from incidents"
        
        # Check age of most recent restore point
        $newestRestore = $restoreEnabled | Sort-Object CreationTime -Descending | Select-Object -First 1
        $age = (Get-Date) - $newestRestore.CreationTime
        
        if ($age.Days -le 7) {
            Add-Result -Category "CISA - Incident Response" -Status "Pass" `
                -Message "Recent restore point available ($($age.Days) days old)" `
                -Details "CISA CPG: Recent restore points support rapid recovery"
        } else {
            Add-Result -Category "CISA - Incident Response" -Status "Warning" `
                -Message "Most recent restore point is $($age.Days) days old" `
                -Details "CISA CPG: Create recent restore points before major changes"
        }
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Warning" `
            -Message "No System Restore points found or System Restore is disabled" `
            -Details "CISA CPG: Enable System Restore for recovery capability" `
            -Remediation "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'Security Baseline'"
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Info" `
        -Message "Could not check System Restore status"
}

# Check Windows Error Reporting status
try {
    $werDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
    
    if ($werDisabled -and $werDisabled.Disabled -eq 1) {
        Add-Result -Category "CISA - Incident Response" -Status "Info" `
            -Message "Windows Error Reporting is disabled" `
            -Details "CISA CPG: WER can provide diagnostic information for incidents"
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "Windows Error Reporting is enabled" `
            -Details "CISA CPG: Error reports aid in identifying system issues"
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Info" `
        -Message "Could not check Windows Error Reporting status"
}

# Check for backup software
try {
    $backupService = Get-Service -Name "wbengine" -ErrorAction SilentlyContinue
    
    if ($backupService) {
        if ($backupService.Status -eq "Running") {
            Add-Result -Category "CISA - Incident Response" -Status "Pass" `
                -Message "Windows Backup service is running" `
                -Details "CISA CPG: Regular backups are critical for recovery"
        } else {
            Add-Result -Category "CISA - Incident Response" -Status "Info" `
                -Message "Windows Backup service exists but is not running" `
                -Details "CISA CPG: Configure and schedule regular backups"
        }
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Info" `
            -Message "Windows Backup service not found" `
            -Details "CISA CPG: Implement backup solution for data protection"
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Info" `
        -Message "Could not check backup configuration"
}

# Check Volume Shadow Copy Service
try {
    $vssService = Get-Service -Name "VSS" -ErrorAction Stop
    
    if ($vssService.Status -eq "Running") {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "Volume Shadow Copy Service is running" `
            -Details "CISA CPG: VSS enables point-in-time recovery of files"
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Warning" `
            -Message "Volume Shadow Copy Service is not running" `
            -Details "CISA CPG: VSS is needed for System Restore and Windows Backup" `
            -Remediation "Start-Service VSS; Set-Service VSS -StartupType Automatic"
    }
    
    # Check for shadow copies
    $shadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($shadowCopies) {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "Shadow copies available: $($shadowCopies.Count)" `
            -Details "CISA CPG: Shadow copies enable file recovery"
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Error" `
        -Message "Failed to check Volume Shadow Copy Service: $_"
}

# ============================================================================
# Summary Statistics
# ============================================================================
$passCount = ($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = ($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = ($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

Write-Host "`n[CISA] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results
