# Module-CISA.ps1
# CISA Cybersecurity Performance Goals Compliance Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against CISA Cybersecurity Performance Goals (CPG),
# Binding Operational Directives (BOD), and Zero Trust guidance across 12 domains.

<#
.SYNOPSIS
    CISA cybersecurity performance goals compliance checks for Windows systems.

.DESCRIPTION
    This module checks alignment with CISA cybersecurity guidance including:
    - Multi-factor authentication enforcement (CPG 1.1-1.3)
    - Patch and vulnerability management (CPG 2.1-2.3, BOD 22-01)
    - Centralized logging and monitoring (CPG 3.1-3.4)
    - Endpoint detection and response (CPG 4.1-4.3)
    - Data encryption and protection (CPG 5.1-5.3)
    - Network security and segmentation (CPG 6.1-6.4)
    - Secure configuration management (CPG 7.1-7.5)
    - Access control and privilege management (CPG 8.1-8.4)
    - Incident response preparedness (CPG 9.1-9.3)
    - Supply chain risk management
    - Zero Trust architecture alignment
    - BOD 22-01/23-01 compliance (KEV, asset visibility)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to NIST SP 800-53, CIS Benchmarks, DISA STIGs,
    and NSA guidance.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: CISA Cybersecurity Performance Goals v1.0.1,
                CISA BOD 22-01 (KEV), BOD 23-01 (Asset Visibility),
                CISA Zero Trust Maturity Model v2.0
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-cisa.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "CISA"
$moduleVersion = "6.0"
$results = @()

# ---------------------------------------------------------------------------
# Enhanced result helper with Severity and CrossReferences
# ---------------------------------------------------------------------------
function Add-Result {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Message,
        [string]$Details     = "",
        [string]$Remediation = "",
        [string]$Severity    = "Medium",
        [hashtable]$CrossReferences = @{}
    )
    $script:results += [PSCustomObject]@{
        Module          = $moduleName
        Category        = $Category
        Status          = $Status
        Severity        = $Severity
        Message         = $Message
        Details         = $Details
        Remediation     = $Remediation
        CrossReferences = $CrossReferences
        Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# ---------------------------------------------------------------------------
# Cache-aware registry helper
# ---------------------------------------------------------------------------
$useCache = ($null -ne $SharedData.Cache)
function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    if ($useCache -and (Get-Command 'Get-CachedRegistryValue' -ErrorAction SilentlyContinue)) {
        return Get-CachedRegistryValue -Cache $SharedData.Cache -Path $Path -Name $Name -Default $Default
    }
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($item) { return $item.$Name }
    } catch { }
    return $Default
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
                -Details "CISA CPG: NLA provides an additional authentication layer before establishing RDP sessions" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Fail" `
                -Message "RDP is enabled but NLA is not required" `
                -Details "CISA CPG: Require MFA/NLA for all remote access methods" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        }
        
        # Check RDP port (should not be default 3389 for additional security)
        $rdpPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
        if ($rdpPort -and $rdpPort.PortNumber -eq 3389) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
                -Message "RDP is using default port 3389" `
                -Details "CISA CPG: Consider changing default RDP port as additional security measure" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        }
    } else {
        Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "CISA CPG: RDP is disabled - no remote authentication risk" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Error" `
        -Message "Failed to check RDP/NLA configuration: $_" `
        -Severity "Medium"
}

# Check for smart card authentication capability
try {
    $scPolicyService = Get-Service -Name "SCPolicySvc" -ErrorAction SilentlyContinue
    if ($scPolicyService) {
        if ($scPolicyService.Status -eq "Running") {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Smart Card Policy service is running" `
                -Details "CISA CPG: Smart card support enables hardware-based MFA" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
                -Message "Smart Card Policy service is not running" `
                -Details "CISA CPG: Enable if using smart cards for authentication" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
        -Message "Could not check Smart Card service status" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
}

# Check Windows Hello for Business configuration
try {
    $whfbPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue
    if ($whfbPolicy) {
        $enabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($enabled -and $enabled.Enabled -eq 1) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Windows Hello for Business is enabled" `
                -Details "CISA CPG: Windows Hello provides modern MFA capabilities" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
                -Message "Windows Hello for Business is not enabled" `
                -Details "CISA CPG: Consider enabling Windows Hello for passwordless MFA" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
        -Message "Windows Hello configuration could not be checked" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
}

# Check for cached credentials limit
try {
    $cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
    if ($cachedLogons) {
        $count = $cachedLogons.CachedLogonsCount
        if ($count -le 2) {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Pass" `
                -Message "Cached credential count is limited to $count" `
                -Details "CISA CPG: Limit cached credentials to reduce offline attack risk" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        } else {
            Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Warning" `
                -Message "Cached credential count is $count (recommend 2 or less)" `
                -Details "CISA CPG: Minimize cached credentials" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 2" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
        }
    } else {
        Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Info" `
            -Message "Using default cached credentials setting (typically 10)" `
            -Details "CISA CPG: Consider limiting cached credentials to 2" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 1.2'; NIST='IA-2'; CIS='1.1' }
    }
} catch {
    Add-Result -Category "CISA - Multi-Factor Authentication" -Status "Error" `
        -Message "Failed to check cached credentials: $_" `
        -Severity "Medium"
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
            -Details "CISA CPG: Automated patching reduces vulnerability exposure" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
    } else {
        Add-Result -Category "CISA - Patch Management" -Status "Fail" `
            -Message "Windows Update service is not running (Status: $($wuService.Status))" `
            -Details "CISA CPG: Enable Windows Update for timely patch deployment" `
            -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check Windows Update service: $_" `
        -Severity "Medium"
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
                    -Details "CISA CPG: Regular patching maintains security posture" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
            
            if ($failedUpdates -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "$failedUpdates update(s) failed in the last 30 days" `
                    -Details "CISA CPG: Investigate and resolve failed updates" `
                    -Remediation "Review Windows Update history and resolve failures" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                -Message "No updates installed in the last 30 days" `
                -Details "CISA CPG: System may have critical vulnerabilities - update immediately" `
                -Remediation "Install-WindowsUpdate -AcceptAll -AutoReboot" `
                -Severity "High" `
                -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
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
                    -Remediation "Install pending critical updates via Windows Update" `
                    -Severity "High" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            } elseif ($importantPending -gt 0) {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "$importantPending important updates pending installation" `
                    -Details "CISA CPG: Install important security updates promptly" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            } else {
                Add-Result -Category "CISA - Patch Management" -Status "Info" `
                    -Message "$($pendingUpdates.Updates.Count) non-critical updates pending" `
                    -Details "CISA CPG: Schedule maintenance window for updates" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                -Message "No pending updates detected" `
                -Details "CISA CPG: System is current with available updates" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
        }
    } else {
        Add-Result -Category "CISA - Patch Management" -Status "Warning" `
            -Message "No Windows Update history found" `
            -Details "CISA CPG: Verify Windows Update is functioning properly" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check Windows Update history: $_" `
        -Severity "Medium"
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
                    -Details "CISA CPG: Automated patching ensures timely updates" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
            3 {
                Add-Result -Category "CISA - Patch Management" -Status "Warning" `
                    -Message "Updates auto-download but require manual installation" `
                    -Details "CISA CPG: Consider fully automated updates" `
                    -Remediation "Set AUOptions to 4 for automatic installation" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
            2 {
                Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                    -Message "Updates only notify before download" `
                    -Details "CISA CPG: Enable automatic updates" `
                    -Remediation "Configure automatic updates via Group Policy or Settings" `
                    -Severity "High" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
            1 {
                Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                    -Message "Automatic updates are disabled" `
                    -Details "CISA CPG: Enable automatic updates immediately" `
                    -Remediation "Enable Windows Update automatic updates" `
                    -Severity "High" `
                    -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
            }
        }
    } else {
        # Check via COM object
        $auSettings = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings
        if ($auSettings.NotificationLevel -ge 3) {
            Add-Result -Category "CISA - Patch Management" -Status "Pass" `
                -Message "Automatic updates are enabled" `
                -Details "CISA CPG: Automated patching is configured" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
        } else {
            Add-Result -Category "CISA - Patch Management" -Status "Fail" `
                -Message "Automatic updates are not properly configured" `
                -Details "CISA CPG: Enable automatic Windows updates" `
                -Remediation "Configure automatic updates in Windows Update settings" `
                -Severity "High" `
                -CrossReferences @{ CISA='CPG 2.1'; NIST='SI-2'; CIS='3.4' }
        }
    }
} catch {
    Add-Result -Category "CISA - Patch Management" -Status "Error" `
        -Message "Failed to check automatic update configuration: $_" `
        -Severity "Medium"
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
                -Details "CISA CPG: Large log size supports forensic investigation" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        } elseif ($logSizeMB -ge 512) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Security log is enabled ($logSizeMB MB)" `
                -Details "CISA CPG: Consider increasing for extended retention" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "Security log size is small ($logSizeMB MB)" `
                -Details "CISA CPG: Increase log size to at least 512 MB for adequate retention" `
                -Remediation "wevtutil sl Security /ms:$([int](512MB))" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        }
        
        # Check log retention policy
        if ($securityLog.LogMode -eq "Circular") {
            Add-Result -Category "CISA - Logging" -Status "Info" `
                -Message "Security log uses circular overwrite policy" `
                -Details "CISA CPG: Ensure logs are forwarded before overwrite" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        } elseif ($securityLog.LogMode -eq "AutoBackup") {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Security log auto-archives when full" `
                -Details "CISA CPG: Auto-backup preserves forensic evidence" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Fail" `
            -Message "Security event log is disabled" `
            -Details "CISA CPG: Security logging is critical for threat detection" `
            -Remediation "Enable Security event log via Event Viewer or Group Policy" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check Security event log: $_" `
        -Severity "Medium"
}

# Check System Event Log configuration
try {
    $systemLog = Get-WinEvent -ListLog System -ErrorAction Stop
    
    if ($systemLog.IsEnabled) {
        $logSizeMB = [math]::Round($systemLog.MaximumSizeInBytes / 1MB, 2)
        
        if ($logSizeMB -ge 128) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "System log is enabled with adequate size ($logSizeMB MB)" `
                -Details "CISA CPG: System logs aid in troubleshooting and security analysis" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "System log size is small ($logSizeMB MB)" `
                -Details "CISA CPG: Consider increasing to 128 MB or higher" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check System event log: $_" `
        -Severity "Medium"
}

# Check PowerShell logging (Script Block, Module, Transcription)
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "CISA CPG: PowerShell logging detects malicious scripting activity" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Fail" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "CISA CPG: Enable PowerShell logging to detect threats" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell Script Block Logging: $_" `
        -Severity "Medium"
}

try {
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    
    if ($moduleLogging -and $moduleLogging.EnableModuleLogging -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Module Logging is enabled" `
            -Details "CISA CPG: Module logging provides detailed cmdlet execution records" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Warning" `
            -Message "PowerShell Module Logging is not enabled" `
            -Details "CISA CPG: Consider enabling for comprehensive PowerShell auditing" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell Module Logging: $_" `
        -Severity "Medium"
}

try {
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    
    if ($transcription -and $transcription.EnableTranscripting -eq 1) {
        $outputDir = $transcription.OutputDirectory
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "PowerShell Transcription is enabled (Output: $outputDir)" `
            -Details "CISA CPG: Transcription captures full PowerShell session activity" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "CISA CPG: Transcription provides complete session logs (optional but recommended)" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check PowerShell Transcription: $_" `
        -Severity "Medium"
}

# Check Process Creation auditing (Event ID 4688)
try {
    $processAuditing = auditpol /get /subcategory:"Process Creation" 2>$null
    if ($processAuditing -and $processAuditing -match "Success") {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "Process Creation auditing is enabled" `
            -Details "CISA CPG: Process auditing tracks program execution" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Fail" `
            -Message "Process Creation auditing is not enabled" `
            -Details "CISA CPG: Enable process creation auditing for threat detection" `
            -Remediation "auditpol /set /subcategory:'Process Creation' /success:enable" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
    
    # Check if command line logging is enabled for process creation events
    $cmdLineLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    if ($cmdLineLogging -and $cmdLineLogging.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Add-Result -Category "CISA - Logging" -Status "Pass" `
            -Message "Command line logging in process auditing is enabled" `
            -Details "CISA CPG: Command line logging captures full execution parameters" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Warning" `
            -Message "Command line logging in process auditing is not enabled" `
            -Details "CISA CPG: Enable to capture process command line arguments" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Error" `
        -Message "Failed to check Process Creation auditing: $_" `
        -Severity "Medium"
}

# Check for Sysmon installation (advanced logging)
try {
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    $sysmonDriver = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "Sysmon*" }
    
    if ($sysmonService -or $sysmonDriver) {
        if ($sysmonService.Status -eq "Running" -or $sysmonDriver) {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Sysmon is installed and running" `
                -Details "CISA CPG: Sysmon provides advanced system monitoring and logging" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        } else {
            Add-Result -Category "CISA - Logging" -Status "Warning" `
                -Message "Sysmon is installed but not running" `
                -Details "CISA CPG: Start Sysmon service for enhanced logging" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        }
        
        # Check Sysmon log
        $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
        if ($sysmonLog -and $sysmonLog.IsEnabled) {
            $logSizeMB = [math]::Round($sysmonLog.MaximumSizeInBytes / 1MB, 2)
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Sysmon operational log is enabled ($logSizeMB MB)" `
                -Details "CISA CPG: Sysmon captures detailed system activity" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        }
    } else {
        Add-Result -Category "CISA - Logging" -Status "Info" `
            -Message "Sysmon is not installed" `
            -Details "CISA CPG: Consider deploying Sysmon for enhanced logging (optional but highly recommended)" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Info" `
        -Message "Could not check Sysmon status" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
}

# Check Windows Event Forwarding configuration
try {
    $wefService = Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
    if ($wefService) {
        if ($wefService.Status -eq "Running") {
            Add-Result -Category "CISA - Logging" -Status "Pass" `
                -Message "Windows Event Collector service is running" `
                -Details "CISA CPG: Event forwarding enables centralized log collection" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
            
            # Check for subscriptions
            $subscriptions = wecutil es 2>$null
            if ($subscriptions) {
                $subCount = ($subscriptions | Measure-Object).Count
                Add-Result -Category "CISA - Logging" -Status "Pass" `
                    -Message "Event forwarding subscriptions configured: $subCount" `
                    -Details "CISA CPG: Centralized logging supports SOC operations" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
            }
        } else {
            Add-Result -Category "CISA - Logging" -Status "Info" `
                -Message "Windows Event Collector service is not running" `
                -Details "CISA CPG: Enable if using centralized log collection" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Logging" -Status "Info" `
        -Message "Could not check Windows Event Forwarding configuration" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 3.1'; NIST='AU-2'; CIS='17.1' }
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
            -Details "CISA CPG: Real-time protection prevents malware execution" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Windows Defender real-time protection is DISABLED" `
            -Details "CISA CPG: Enable real-time protection immediately" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Cloud-delivered protection
    if ($defenderStatus.MAPSReporting -ge 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Cloud-delivered protection is enabled (Level: $($defenderStatus.MAPSReporting))" `
            -Details "CISA CPG: Cloud protection provides rapid threat intelligence" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Cloud-delivered protection is disabled" `
            -Details "CISA CPG: Enable cloud protection for enhanced detection" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Behavior monitoring
    if ($defenderStatus.BehaviorMonitorEnabled) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Behavior monitoring is enabled" `
            -Details "CISA CPG: Behavior analysis detects zero-day threats" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Behavior monitoring is disabled" `
            -Details "CISA CPG: Enable behavior monitoring" `
            -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # On-access protection
    if ($defenderStatus.OnAccessProtectionEnabled) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "On-access protection is enabled" `
            -Details "CISA CPG: Scans files when accessed" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "On-access protection is disabled" `
            -Details "CISA CPG: Enable on-access protection" `
            -Remediation "Set-MpPreference -DisableIOAVProtection `$false" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Signature updates
    $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
    if ($signatureAge.Days -eq 0) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Antivirus signatures are current (updated today at $($defenderStatus.AntivirusSignatureLastUpdated.ToString('HH:mm')))" `
            -Details "CISA CPG: Current signatures ensure protection against latest threats" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } elseif ($signatureAge.Days -le 3) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Antivirus signatures are $($signatureAge.Days) day(s) old" `
            -Details "CISA CPG: Signatures are reasonably current" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } elseif ($signatureAge.Days -le 7) {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "Antivirus signatures are $($signatureAge.Days) days old" `
            -Details "CISA CPG: Update signatures more frequently" `
            -Remediation "Update-MpSignature" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Antivirus signatures are severely outdated ($($signatureAge.Days) days old)" `
            -Details "CISA CPG: Update signatures immediately - system is vulnerable" `
            -Remediation "Update-MpSignature -UpdateSource Microsoft" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Check scan status
    $daysSinceLastFullScan = $null
    if ($defenderStatus.FullScanAge) {
        $daysSinceLastFullScan = $defenderStatus.FullScanAge
        if ($daysSinceLastFullScan -le 7) {
            Add-Result -Category "CISA - EDR" -Status "Pass" `
                -Message "Full scan performed $daysSinceLastFullScan day(s) ago" `
                -Details "CISA CPG: Regular full scans detect dormant threats" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
        } else {
            Add-Result -Category "CISA - EDR" -Status "Warning" `
                -Message "Last full scan was $daysSinceLastFullScan days ago" `
                -Details "CISA CPG: Perform weekly full scans" `
                -Remediation "Start-MpScan -ScanType FullScan" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
        }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "No full scan has been performed or scan history unavailable" `
            -Details "CISA CPG: Schedule regular full system scans" `
            -Remediation "Start-MpScan -ScanType FullScan" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Check quick scan status
    $daysSinceLastQuickScan = $defenderStatus.QuickScanAge
    if ($daysSinceLastQuickScan -le 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Quick scan performed $daysSinceLastQuickScan day(s) ago" `
            -Details "CISA CPG: Recent quick scan indicates active protection" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Network protection
    $networkProtection = Get-MpPreference | Select-Object -ExpandProperty EnableNetworkProtection -ErrorAction SilentlyContinue
    if ($networkProtection -eq 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Network protection is enabled and in block mode" `
            -Details "CISA CPG: Network protection blocks malicious network traffic" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } elseif ($networkProtection -eq 2) {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "Network protection is in audit mode only" `
            -Details "CISA CPG: Enable block mode for network protection" `
            -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Fail" `
            -Message "Network protection is disabled" `
            -Details "CISA CPG: Enable network protection" `
            -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Controlled folder access (ransomware protection)
    $controlledFolderAccess = Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess -ErrorAction SilentlyContinue
    if ($controlledFolderAccess -eq 1) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Controlled Folder Access (ransomware protection) is enabled" `
            -Details "CISA CPG: Protects critical folders from ransomware" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } elseif ($controlledFolderAccess -eq 2) {
        Add-Result -Category "CISA - EDR" -Status "Info" `
            -Message "Controlled Folder Access is in audit mode" `
            -Details "CISA CPG: Consider enabling block mode after testing" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Warning" `
            -Message "Controlled Folder Access is disabled" `
            -Details "CISA CPG: Consider enabling for ransomware protection" `
            -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
    # Attack Surface Reduction rules
    $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
    if ($asrRules -and $asrRules.Count -gt 0) {
        Add-Result -Category "CISA - EDR" -Status "Pass" `
            -Message "Attack Surface Reduction rules are configured ($($asrRules.Count) rules)" `
            -Details "CISA CPG: ASR rules reduce attack vectors" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Info" `
            -Message "No Attack Surface Reduction rules configured" `
            -Details "CISA CPG: Consider configuring ASR rules for additional protection" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
    
} catch {
    Add-Result -Category "CISA - EDR" -Status "Error" `
        -Message "Failed to check Windows Defender status: $_" `
        -Details "CISA CPG: Ensure endpoint protection is functioning" `
        -Severity "Medium"
}

# Check for Microsoft Defender for Endpoint (advanced EDR)
try {
    $defenderATPService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if ($defenderATPService) {
        if ($defenderATPService.Status -eq "Running") {
            Add-Result -Category "CISA - EDR" -Status "Pass" `
                -Message "Microsoft Defender for Endpoint service is running" `
                -Details "CISA CPG: Advanced EDR provides enhanced threat detection and response" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
            
            # Check onboarding status
            $senseOnboarded = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState" -ErrorAction SilentlyContinue
            if ($senseOnboarded -and $senseOnboarded.OnboardingState -eq 1) {
                Add-Result -Category "CISA - EDR" -Status "Pass" `
                    -Message "System is onboarded to Microsoft Defender for Endpoint" `
                    -Details "CISA CPG: MDE provides centralized threat visibility" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
            }
        } else {
            Add-Result -Category "CISA - EDR" -Status "Warning" `
                -Message "Microsoft Defender for Endpoint service exists but is not running" `
                -Details "CISA CPG: Start MDE service" `
                -Remediation "Start-Service Sense; Set-Service Sense -StartupType Automatic" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
        }
    } else {
        Add-Result -Category "CISA - EDR" -Status "Info" `
            -Message "Microsoft Defender for Endpoint is not installed" `
            -Details "CISA CPG: Consider deploying advanced EDR solution" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
    }
} catch {
    Add-Result -Category "CISA - EDR" -Status "Info" `
        -Message "Could not check Microsoft Defender for Endpoint status" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 4.2'; NIST='SI-4' }
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
                -Details "CISA CPG: BitLocker protects data at rest (Method: $($volume.EncryptionMethod))" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
        } elseif ($volume.VolumeStatus -eq "EncryptionInProgress") {
            Add-Result -Category "CISA - Data Encryption" -Status "Info" `
                -Message "Drive $($volume.MountPoint) encryption in progress ($($volume.EncryptionPercentage)%)" `
                -Details "CISA CPG: Allow encryption to complete" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
        } else {
            $unprotectedVolumes++
            Add-Result -Category "CISA - Data Encryption" -Status "Fail" `
                -Message "Drive $($volume.MountPoint) is NOT encrypted (Status: $($volume.VolumeStatus))" `
                -Details "CISA CPG: Enable BitLocker on all system and data volumes" `
                -Remediation "Enable-BitLocker -MountPoint '$($volume.MountPoint)' -EncryptionMethod XtsAes256 -TpmProtector" `
                -Severity "High" `
                -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
        }
        
        # Check recovery key backup
        if ($volume.VolumeStatus -eq "FullyEncrypted") {
            $keyProtectors = $volume.KeyProtector
            $hasRecoveryPassword = $keyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
            
            if ($hasRecoveryPassword) {
                Add-Result -Category "CISA - Data Encryption" -Status "Pass" `
                    -Message "Drive $($volume.MountPoint) has recovery password configured" `
                    -Details "CISA CPG: Recovery keys enable data recovery" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
            } else {
                Add-Result -Category "CISA - Data Encryption" -Status "Warning" `
                    -Message "Drive $($volume.MountPoint) lacks recovery password" `
                    -Details "CISA CPG: Add recovery password for emergency access" `
                    -Remediation "Add-BitLockerKeyProtector -MountPoint '$($volume.MountPoint)' -RecoveryPasswordProtector" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
            }
        }
    }
    
    if ($protectedVolumes -gt 0 -and $unprotectedVolumes -eq 0) {
        Add-Result -Category "CISA - Data Encryption" -Status "Pass" `
            -Message "All $protectedVolumes volume(s) are encrypted with BitLocker" `
            -Details "CISA CPG: Full disk encryption protects against data theft" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
    } elseif ($unprotectedVolumes -gt 0) {
        Add-Result -Category "CISA - Data Encryption" -Status "Fail" `
            -Message "$unprotectedVolumes volume(s) are not encrypted" `
            -Details "CISA CPG: Encrypt all drives containing sensitive data" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
    }
    
} catch {
    $errorMsg = $_.Exception.Message
    if ($errorMsg -like "*not supported*" -or $errorMsg -like "*requires*") {
        Add-Result -Category "CISA - Data Encryption" -Status "Info" `
            -Message "BitLocker is not available on this Windows edition" `
            -Details "CISA CPG: BitLocker requires Pro/Enterprise editions" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
    } else {
        Add-Result -Category "CISA - Data Encryption" -Status "Error" `
            -Message "Failed to check BitLocker status: $_" `
            -Severity "Medium"
    }
}

# Check EFS (Encrypting File System) usage
try {
    $efsUsers = cipher /u /n 2>$null | Select-String "User:" | Measure-Object
    if ($efsUsers.Count -gt 0) {
        Add-Result -Category "CISA - Data Encryption" -Status "Info" `
            -Message "EFS (Encrypting File System) is in use by $($efsUsers.Count) user(s)" `
            -Details "CISA CPG: EFS provides file-level encryption" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 5.1'; NIST='SC-28'; CIS='3.11' }
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
    $CISAprofiles = @("Domain", "Private", "Public")
    $allEnabled = $true
    
    foreach ($profileName in $CISAprofiles) {
        $CISAprofile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        if ($CISAprofile.Enabled) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "$profileName firewall profile is enabled" `
                -Details "CISA CPG: Firewall provides first line of network defense (Default Inbound: $($CISAprofile.DefaultInboundAction), Outbound: $($CISAprofile.DefaultOutboundAction))" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        } else {
            $allEnabled = $false
            Add-Result -Category "CISA - Network Security" -Status "Fail" `
                -Message "$profileName firewall profile is DISABLED" `
                -Details "CISA CPG: Enable firewall on all network profiles" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        }
        
        # Check if default deny for inbound is configured
        if ($CISAprofile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "$profileName profile: Default inbound is set to Block" `
                -Details "CISA CPG: Default deny reduces attack surface" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Warning" `
                -Message "$profileName profile: Default inbound is set to Allow" `
                -Details "CISA CPG: Configure default deny for inbound traffic" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        }
        
        # Check logging
        if ($CISAprofile.LogBlocked -eq "True") {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "$profileName profile: Logging blocked connections" `
                -Details "CISA CPG: Firewall logging aids security monitoring" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Info" `
                -Message "$profileName profile: Not logging blocked connections" `
                -Details "CISA CPG: Consider enabling firewall logging" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        }
    }
    
    if ($allEnabled) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "Windows Firewall is enabled on all profiles" `
            -Details "CISA CPG: Comprehensive firewall protection is active" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    }
    
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check firewall configuration: $_" `
        -Severity "Medium"
}

# Check SMBv1 status (should be disabled per CISA KEV)
try {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    
    if ($smb1Feature.State -eq "Disabled") {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "CISA CPG: SMBv1 has critical vulnerabilities (WannaCry, NotPetya)" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Fail" `
            -Message "SMBv1 protocol is ENABLED" `
            -Details "CISA CPG: Disable SMBv1 immediately - actively exploited" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -Severity "High" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    }
    
    # Also check SMB server configuration
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbServer) {
        if (-not $smbServer.EnableSMB1Protocol) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "SMBv1 is disabled in server configuration" `
                -Details "CISA CPG: Server-level SMBv1 protection" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Fail" `
                -Message "SMBv1 is enabled in server configuration" `
                -Details "CISA CPG: Disable SMBv1 at server level" `
                -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" `
                -Severity "High" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        }
        
        # Check SMB signing
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "SMB signing is required" `
                -Details "CISA CPG: SMB signing prevents man-in-the-middle attacks" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Warning" `
                -Message "SMB signing is not required" `
                -Details "CISA CPG: Require SMB signing to prevent tampering" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        }
        
        # Check SMB encryption
        if ($smbServer.EncryptData) {
            Add-Result -Category "CISA - Network Security" -Status "Pass" `
                -Message "SMB encryption is enabled globally" `
                -Details "CISA CPG: SMB encryption protects data in transit" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        } else {
            Add-Result -Category "CISA - Network Security" -Status "Info" `
                -Message "SMB encryption is not enabled globally" `
                -Details "CISA CPG: Consider enabling SMB encryption for sensitive data" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check SMB configuration: $_" `
        -Severity "Medium"
}

# Check for LLMNR (should be disabled)
try {
    $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
        Add-Result -Category "CISA - Network Security" -Status "Pass" `
            -Message "LLMNR (Link-Local Multicast Name Resolution) is disabled" `
            -Details "CISA CPG: Disabling LLMNR prevents name resolution poisoning attacks" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Warning" `
            -Message "LLMNR may be enabled (default)" `
            -Details "CISA CPG: Disable LLMNR to prevent credential theft attacks" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check LLMNR status: $_" `
        -Severity "Medium"
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
            -Details "CISA CPG: Disabling NetBIOS reduces attack surface" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    } elseif ($netbiosEnabled) {
        Add-Result -Category "CISA - Network Security" -Status "Warning" `
            -Message "NetBIOS over TCP/IP is enabled on one or more adapters" `
            -Details "CISA CPG: Disable NetBIOS over TCP/IP to reduce exposure" `
            -Remediation "Configure via network adapter TCP/IP properties or DHCP scope options" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    } else {
        Add-Result -Category "CISA - Network Security" -Status "Info" `
            -Message "NetBIOS over TCP/IP is using default settings" `
            -Details "CISA CPG: Explicitly disable NetBIOS on all adapters" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 6.1'; NIST='SC-7'; CIS='9.1' }
    }
} catch {
    Add-Result -Category "CISA - Network Security" -Status "Error" `
        -Message "Failed to check NetBIOS configuration: $_" `
        -Severity "Medium"
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
            -Details "CISA CPG: UAC prevents unauthorized privilege elevation" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Fail" `
            -Message "User Account Control (UAC) is DISABLED" `
            -Details "CISA CPG: Enable UAC for security isolation" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1; Restart-Computer" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    }
    
    # ConsentPromptBehaviorAdmin - Admin approval mode
    $consentLevel = $uac.ConsentPromptBehaviorAdmin
    switch ($consentLevel) {
        0 {
            Add-Result -Category "CISA - Configuration" -Status "Fail" `
                -Message "UAC: Admin approval mode is disabled (Elevate without prompting)" `
                -Details "CISA CPG: This bypasses UAC protection" `
                -Remediation "Set ConsentPromptBehaviorAdmin to 2 or higher" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
        1 {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "UAC: Prompt for credentials on secure desktop" `
                -Details "CISA CPG: Consider using 'Prompt for consent' for better usability" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
        2 {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "UAC: Prompt for consent on secure desktop (Recommended)" `
                -Details "CISA CPG: Balanced security and usability" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
        3 {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "UAC: Prompt for credentials (not on secure desktop)" `
                -Details "CISA CPG: Secure desktop provides additional protection" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
        4 {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "UAC: Prompt for consent (not on secure desktop)" `
                -Details "CISA CPG: Secure desktop recommended" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
        5 {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "UAC: Prompt for consent for non-Windows binaries" `
                -Details "CISA CPG: Protects against malicious executables" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
    }
    
    # PromptOnSecureDesktop
    if ($uac.PromptOnSecureDesktop -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "UAC: Elevation prompts display on secure desktop" `
            -Details "CISA CPG: Secure desktop prevents UI spoofing attacks" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Warning" `
            -Message "UAC: Elevation prompts do not use secure desktop" `
            -Details "CISA CPG: Enable secure desktop for UAC prompts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    }
    
    # FilterAdministratorToken
    if ($uac.FilterAdministratorToken -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "UAC: Built-in Administrator account runs in Admin Approval Mode" `
            -Details "CISA CPG: Applies UAC restrictions to built-in admin account" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Info" `
            -Message "UAC: Built-in Administrator bypasses UAC" `
            -Details "CISA CPG: Consider applying UAC to built-in admin account" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    }
    
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check UAC configuration: $_" `
        -Severity "Medium"
}

# Check Administrator account status
try {
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    
    if ($adminAccount) {
        if ($adminAccount.Enabled) {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "Built-in Administrator account is ENABLED" `
                -Details "CISA CPG: Disable or rename built-in Administrator account" `
                -Remediation "Disable-LocalUser -Name Administrator" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        } else {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "Built-in Administrator account is disabled" `
                -Details "CISA CPG: Disabled admin accounts reduce attack surface" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
        
        # Check if account has been renamed
        if ($adminAccount.Name -eq "Administrator") {
            Add-Result -Category "CISA - Configuration" -Status "Info" `
                -Message "Built-in Administrator account has not been renamed" `
                -Details "CISA CPG: Consider renaming for additional obscurity" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check Administrator account: $_" `
        -Severity "Medium"
}

# Check Guest account status
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount) {
        if ($guestAccount.Enabled) {
            Add-Result -Category "CISA - Configuration" -Status "Fail" `
                -Message "Guest account is ENABLED" `
                -Details "CISA CPG: Disable Guest account - presents security risk" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        } else {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "CISA CPG: Guest account is properly disabled" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check Guest account: $_" `
        -Severity "Medium"
}

# Check for Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "CISA CPG: Secure Boot protects against bootkit and rootkit malware" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "CISA - Configuration" -Status "Warning" `
            -Message "Secure Boot is disabled" `
            -Details "CISA CPG: Enable Secure Boot in UEFI firmware settings" `
            -Remediation "Enable Secure Boot in BIOS/UEFI settings" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Info" `
            -Message "Secure Boot status cannot be determined (Legacy BIOS system)" `
            -Details "CISA CPG: UEFI with Secure Boot is recommended for modern systems" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Info" `
        -Message "Could not determine Secure Boot status" `
        -Details "CISA CPG: Verify Secure Boot is enabled in firmware" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
}

# Check for default credentials/passwords
try {
    # Check for accounts with passwords that don't expire
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $passwordNeverExpires = $users | Where-Object { $null -eq $_.PasswordExpires }
    
    if ($passwordNeverExpires) {
        foreach ($user in $passwordNeverExpires) {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "User account '$($user.Name)' has password set to never expire" `
                -Details "CISA CPG: Enforce password expiration policies" `
                -Remediation "Set-LocalUser -Name '$($user.Name)' -PasswordNeverExpires `$false" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
    }
    
    # Check for blank passwords
    $nullPasswordPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue
    if ($nullPasswordPolicy -and $nullPasswordPolicy.LimitBlankPasswordUse -eq 1) {
        Add-Result -Category "CISA - Configuration" -Status "Pass" `
            -Message "Blank password use is restricted to console logon only" `
            -Details "CISA CPG: Prevents remote logon with blank passwords" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    } else {
        Add-Result -Category "CISA - Configuration" -Status "Warning" `
            -Message "Blank password use is not properly restricted" `
            -Details "CISA CPG: Enable blank password restrictions" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
    }
    
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Error" `
        -Message "Failed to check password policies: $_" `
        -Severity "Medium"
}

# Check for automatic Windows updates
try {
    $autoUpdateNotification = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue
    
    if ($autoUpdateNotification) {
        $option = $autoUpdateNotification.AUOptions
        if ($option -eq 4) {
            Add-Result -Category "CISA - Configuration" -Status "Pass" `
                -Message "Windows Updates are configured to automatically download and install" `
                -Details "CISA CPG: Automatic updates ensure timely patching" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        } elseif ($option -eq 3) {
            Add-Result -Category "CISA - Configuration" -Status "Warning" `
                -Message "Windows Updates download automatically but require manual installation" `
                -Details "CISA CPG: Enable automatic installation" `
                -Remediation "Configure automatic installation via Group Policy or Settings" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        } else {
            Add-Result -Category "CISA - Configuration" -Status "Fail" `
                -Message "Windows Updates are not configured for automatic download/install" `
                -Details "CISA CPG: Enable automatic updates" `
                -Remediation "Enable automatic updates in Windows Update settings" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Configuration" -Status "Info" `
        -Message "Could not determine automatic update configuration" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 7.1'; NIST='CM-6'; CIS='18.1' }
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
        -Details "CISA CPG: Review and minimize administrative accounts. Members: $($admins.Name -join ', ')" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
    
    if ($admins.Count -gt 5) {
        Add-Result -Category "CISA - Access Control" -Status "Warning" `
            -Message "Large number of administrators detected ($($admins.Count) members)" `
            -Details "CISA CPG: Limit administrative access to essential personnel only" `
            -Remediation "Review and remove unnecessary administrative accounts" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
    }
    
    # Check for domain accounts in local admin group
    $domainAdmins = $admins | Where-Object { $_.ObjectClass -eq "User" -and $_.PrincipalSource -eq "ActiveDirectory" }
    if ($domainAdmins) {
        Add-Result -Category "CISA - Access Control" -Status "Info" `
            -Message "Domain accounts in local Administrators: $($domainAdmins.Count)" `
            -Details "CISA CPG: Minimize domain accounts with local admin rights. Accounts: $($domainAdmins.Name -join ', ')" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
    }
    
} catch {
    Add-Result -Category "CISA - Access Control" -Status "Error" `
        -Message "Failed to enumerate local administrators: $_" `
        -Severity "Medium"
}

# Check Remote Desktop Users group
try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    
    if ($rdpUsers) {
        Add-Result -Category "CISA - Access Control" -Status "Info" `
            -Message "Remote Desktop Users group has $($rdpUsers.Count) member(s)" `
            -Details "CISA CPG: Review remote access permissions. Members: $($rdpUsers.Name -join ', ')" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
        
        if ($rdpUsers.Count -gt 10) {
            Add-Result -Category "CISA - Access Control" -Status "Warning" `
                -Message "Large number of RDP users ($($rdpUsers.Count))" `
                -Details "CISA CPG: Limit remote access to necessary users only" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
        }
    } else {
        Add-Result -Category "CISA - Access Control" -Status "Pass" `
            -Message "Remote Desktop Users group is empty" `
            -Details "CISA CPG: No additional RDP access granted beyond administrators" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
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
                    -Remediation "Disable-LocalUser -Name '$($user.Name)'" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
            }
        }
        
        # Check for accounts that never expire
        if ($null -eq $user.AccountExpires) {
            Add-Result -Category "CISA - Access Control" -Status "Info" `
                -Message "User account '$($user.Name)' is set to never expire" `
                -Details "CISA CPG: Consider setting expiration for non-permanent accounts" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
        }
    }
} catch {
    Add-Result -Category "CISA - Access Control" -Status "Error" `
        -Message "Failed to check user account status: $_" `
        -Severity "Medium"
}

# Check for shared folders/network shares
try {
    $shares = Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") }
    
    if ($shares) {
        Add-Result -Category "CISA - Access Control" -Status "Info" `
            -Message "Network shares detected: $($shares.Count)" `
            -Details "CISA CPG: Review share permissions. Shares: $($shares.Name -join ', ')" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
        
        foreach ($share in $shares) {
            $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            $everyoneAccess = $access | Where-Object { $_.AccountName -eq "Everyone" }
            
            if ($everyoneAccess) {
                Add-Result -Category "CISA - Access Control" -Status "Warning" `
                    -Message "Share '$($share.Name)' grants access to 'Everyone'" `
                    -Details "CISA CPG: Remove 'Everyone' permissions and use specific groups" `
                    -Remediation "Revoke-SmbShareAccess -Name '$($share.Name)' -AccountName Everyone -Force" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
            }
        }
    } else {
        Add-Result -Category "CISA - Access Control" -Status "Pass" `
            -Message "No non-administrative network shares detected" `
            -Details "CISA CPG: No file sharing exposure" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 8.1'; NIST='AC-6'; CIS='1.1' }
    }
} catch {
    Add-Result -Category "CISA - Access Control" -Status "Error" `
        -Message "Failed to check network shares: $_" `
        -Severity "Medium"
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
            -Details "CISA CPG: System Restore aids in recovery from incidents" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
        
        # Check age of most recent restore point
        $newestRestore = $restoreEnabled | Sort-Object CreationTime -Descending | Select-Object -First 1
        $age = (Get-Date) - $newestRestore.CreationTime
        
        if ($age.Days -le 7) {
            Add-Result -Category "CISA - Incident Response" -Status "Pass" `
                -Message "Recent restore point available ($($age.Days) days old)" `
                -Details "CISA CPG: Recent restore points support rapid recovery" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
        } else {
            Add-Result -Category "CISA - Incident Response" -Status "Warning" `
                -Message "Most recent restore point is $($age.Days) days old" `
                -Details "CISA CPG: Create recent restore points before major changes" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
        }
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Warning" `
            -Message "No System Restore points found or System Restore is disabled" `
            -Details "CISA CPG: Enable System Restore for recovery capability" `
            -Remediation "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'Security Baseline'" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Info" `
        -Message "Could not check System Restore status" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
}

# Check Windows Error Reporting status
try {
    $werDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
    
    if ($werDisabled -and $werDisabled.Disabled -eq 1) {
        Add-Result -Category "CISA - Incident Response" -Status "Info" `
            -Message "Windows Error Reporting is disabled" `
            -Details "CISA CPG: WER can provide diagnostic information for incidents" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "Windows Error Reporting is enabled" `
            -Details "CISA CPG: Error reports aid in identifying system issues" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Info" `
        -Message "Could not check Windows Error Reporting status" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
}

# Check for backup software
try {
    $backupService = Get-Service -Name "wbengine" -ErrorAction SilentlyContinue
    
    if ($backupService) {
        if ($backupService.Status -eq "Running") {
            Add-Result -Category "CISA - Incident Response" -Status "Pass" `
                -Message "Windows Backup service is running" `
                -Details "CISA CPG: Regular backups are critical for recovery" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
        } else {
            Add-Result -Category "CISA - Incident Response" -Status "Info" `
                -Message "Windows Backup service exists but is not running" `
                -Details "CISA CPG: Configure and schedule regular backups" `
                -Severity "Medium" `
                -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
        }
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Info" `
            -Message "Windows Backup service not found" `
            -Details "CISA CPG: Implement backup solution for data protection" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Info" `
        -Message "Could not check backup configuration" `
        -Severity "Medium" `
        -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
}

# Check Volume Shadow Copy Service
try {
    $vssService = Get-Service -Name "VSS" -ErrorAction Stop
    
    if ($vssService.Status -eq "Running") {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "Volume Shadow Copy Service is running" `
            -Details "CISA CPG: VSS enables point-in-time recovery of files" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    } else {
        Add-Result -Category "CISA - Incident Response" -Status "Warning" `
            -Message "Volume Shadow Copy Service is not running" `
            -Details "CISA CPG: VSS is needed for System Restore and Windows Backup" `
            -Remediation "Start-Service VSS; Set-Service VSS -StartupType Automatic" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    }
    
    # Check for shadow copies
    $shadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($shadowCopies) {
        Add-Result -Category "CISA - Incident Response" -Status "Pass" `
            -Message "Shadow copies available: $($shadowCopies.Count)" `
            -Details "CISA CPG: Shadow copies enable file recovery" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='CPG 9.1'; NIST='IR-4' }
    }
} catch {
    Add-Result -Category "CISA - Incident Response" -Status "Error" `
        -Message "Failed to check Volume Shadow Copy Service: $_" `
        -Severity "Medium"
}

# ============================================================================
# CISA CPG: Supply Chain Risk Management
# ============================================================================
Write-Host "[CISA] Checking supply chain security controls..." -ForegroundColor Yellow

try {
    # PowerShell Gallery repository trust
    try {
        $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($psGallery) {
            if ($psGallery.InstallationPolicy -eq "Untrusted") {
                Add-Result -Category "CISA - Supply Chain" -Status "Pass" `
                    -Message "PSGallery repository is set to Untrusted (manual approval required)" `
                    -Details "CISA: Untrusted policy prevents automatic installation of unverified modules" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='Supply Chain'; NIST='SA-12'; NSA='Supply Chain Guidance' }
            } else {
                Add-Result -Category "CISA - Supply Chain" -Status "Warning" `
                    -Message "PSGallery repository is Trusted — modules install without manual approval" `
                    -Details "CISA: Trusted repositories allow automatic installation of potentially malicious code" `
                    -Remediation "Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted" `
                    -Severity "Medium" `
                    -CrossReferences @{ CISA='Supply Chain'; NIST='SA-12'; NSA='Supply Chain Guidance' }
            }
        }
    } catch { }

    # Code signing enforcement for drivers
    $driverSigning = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Driver Signing" -Name "Policy" -Default 0
    if ($driverSigning -ge 2) {
        Add-Result -Category "CISA - Supply Chain" -Status "Pass" `
            -Message "Driver signing enforcement is enabled (Policy=$driverSigning)" `
            -Details "CISA: Only digitally signed drivers can be installed" `
            -Severity "High" `
            -CrossReferences @{ CISA='Supply Chain'; NIST='SI-7'; STIG='V-220957' }
    } else {
        Add-Result -Category "CISA - Supply Chain" -Status "Warning" `
            -Message "Driver signing enforcement is not set to block unsigned drivers (Policy=$driverSigning)" `
            -Details "CISA: Unsigned drivers may contain malicious code or vulnerable components" `
            -Remediation "Configure driver signing policy via Group Policy: Computer Config > Windows Settings > Security > Local Policies > Security Options" `
            -Severity "High" `
            -CrossReferences @{ CISA='Supply Chain'; NIST='SI-7'; STIG='V-220957' }
    }

    # WDAC/AppLocker as software supply chain control
    $wdacPolicy = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Default 0
    $appLockerSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    if ($wdacPolicy -eq 1) {
        Add-Result -Category "CISA - Supply Chain" -Status "Pass" `
            -Message "WDAC / Device Guard is enabled for application control" `
            -Details "CISA: Virtualization-based application control restricts software execution to approved applications" `
            -Severity "High" `
            -CrossReferences @{ CISA='Supply Chain'; NIST='CM-7(5)'; NSA='Application Control' }
    } elseif ($appLockerSvc -and $appLockerSvc.Status -eq "Running") {
        Add-Result -Category "CISA - Supply Chain" -Status "Pass" `
            -Message "AppLocker service is running for application control" `
            -Details "CISA: AppLocker restricts which applications can execute" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='Supply Chain'; NIST='CM-7(5)'; CIS='2.2' }
    } else {
        Add-Result -Category "CISA - Supply Chain" -Status "Warning" `
            -Message "No application control mechanism detected (WDAC/AppLocker)" `
            -Details "CISA: Application control is critical for preventing unauthorized software execution" `
            -Remediation "Enable AppLocker via Group Policy or deploy WDAC policies" `
            -Severity "High" `
            -CrossReferences @{ CISA='Supply Chain'; NIST='CM-7(5)'; NSA='Application Control' }
    }

    # Third-party software update mechanism
    $wsus = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Default ""
    if ($wsus) {
        Add-Result -Category "CISA - Supply Chain" -Status "Info" `
            -Message "Centralized update management detected (WSUS: $wsus)" `
            -Details "CISA: Centralized patching helps manage supply chain risk for software components" `
            -Severity "Informational" `
            -CrossReferences @{ CISA='Supply Chain'; NIST='SI-2' }
    }

} catch {
    Add-Result -Category "CISA - Supply Chain" -Status "Error" `
        -Message "Failed to check supply chain controls: $_" `
        -Severity "Medium"
}

# ============================================================================
# CISA CPG: Zero Trust Architecture Alignment
# ============================================================================
Write-Host "[CISA] Checking Zero Trust alignment..." -ForegroundColor Yellow

try {
    # Identity pillar: Credential Guard (VBS-based identity protection)
    $credGuard = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Default 0
    if ($credGuard -ge 1) {
        Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
            -Message "Credential Guard is enabled (LsaCfgFlags=$credGuard)" `
            -Details "CISA ZT Identity: Hardware-isolated credential storage prevents credential theft" `
            -Severity "High" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='IA-5(13)'; NSA='Credential Protection' }
    } else {
        Add-Result -Category "CISA - Zero Trust" -Status "Fail" `
            -Message "Credential Guard is not enabled" `
            -Details "CISA ZT Identity: Credentials stored in memory without hardware isolation (Pass-the-Hash risk)" `
            -Remediation "Enable Credential Guard via Group Policy: Computer Config > Admin Templates > System > Device Guard" `
            -Severity "High" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='IA-5(13)'; NSA='Credential Protection' }
    }

    # Device pillar: Device health attestation
    $healthAttest = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" -Name "EnableDeviceHealthAttestationService" -Default 0
    if ($healthAttest -eq 1) {
        Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
            -Message "Device Health Attestation is enabled" `
            -Details "CISA ZT Device: Device health validated before granting access" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='AC-17(2)' }
    } else {
        Add-Result -Category "CISA - Zero Trust" -Status "Info" `
            -Message "Device Health Attestation is not configured" `
            -Details "CISA ZT Device: Consider enabling for conditional access based on device health" `
            -Severity "Low" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='AC-17(2)' }
    }

    # Network pillar: Host-based firewall enabled on all profiles
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $allEnabled = $true
        foreach ($fwProfile in $fwProfiles) {
            if (-not $fwProfile.Enabled) { $allEnabled = $false }
        }
        if ($allEnabled) {
            Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
                -Message "Windows Firewall is enabled on all network profiles" `
                -Details "CISA ZT Network: Micro-segmentation via host-based firewall is active" `
                -Severity "High" `
                -CrossReferences @{ CISA='Zero Trust'; NIST='SC-7'; CIS='9.1.1' }
        } else {
            Add-Result -Category "CISA - Zero Trust" -Status "Fail" `
                -Message "Windows Firewall is NOT enabled on all network profiles" `
                -Details "CISA ZT Network: All firewall profiles must be enabled for micro-segmentation" `
                -Remediation "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ CISA='Zero Trust'; NIST='SC-7'; CIS='9.1.1' }
        }
    } catch { }

    # Network pillar: SMB signing required (verify-then-trust)
    $smbSigning = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default 0
    if ($smbSigning -eq 1) {
        Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
            -Message "SMB signing is required on server" `
            -Details "CISA ZT Network: All SMB traffic is authenticated preventing relay attacks" `
            -Severity "High" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='SC-8'; NSA='SMB Security' }
    } else {
        Add-Result -Category "CISA - Zero Trust" -Status "Fail" `
            -Message "SMB signing is NOT required on server" `
            -Details "CISA ZT Network: Unsigned SMB allows man-in-the-middle and relay attacks" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='SC-8'; NSA='SMB Security' }
    }

    # Data pillar: BitLocker encryption for data-at-rest
    try {
        $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($bitlockerStatus -and $bitlockerStatus.ProtectionStatus -eq "On") {
            Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
                -Message "BitLocker is enabled on system drive (C:)" `
                -Details "CISA ZT Data: Data-at-rest encryption protects against physical theft" `
                -Severity "High" `
                -CrossReferences @{ CISA='Zero Trust'; NIST='SC-28'; CIS='3.11' }
        } else {
            Add-Result -Category "CISA - Zero Trust" -Status "Warning" `
                -Message "BitLocker is not active on system drive" `
                -Details "CISA ZT Data: Encrypt all data at rest to protect against unauthorized access" `
                -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly" `
                -Severity "High" `
                -CrossReferences @{ CISA='Zero Trust'; NIST='SC-28'; CIS='3.11' }
        }
    } catch { }

    # Visibility/Analytics pillar: Comprehensive audit logging
    $cmdLineAudit = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Default 0
    if ($cmdLineAudit -eq 1) {
        Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
            -Message "Process command-line auditing is enabled" `
            -Details "CISA ZT Analytics: Full visibility into process execution for threat detection" `
            -Severity "High" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='AU-3'; STIG='V-220864' }
    } else {
        Add-Result -Category "CISA - Zero Trust" -Status "Fail" `
            -Message "Process command-line auditing is NOT enabled" `
            -Details "CISA ZT Analytics: Without command-line capture, malicious activity is invisible" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='AU-3'; STIG='V-220864' }
    }

    # Automation/Orchestration pillar: PowerShell logging for SOAR integration
    $scriptBlockLog = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default 0
    if ($scriptBlockLog -eq 1) {
        Add-Result -Category "CISA - Zero Trust" -Status "Pass" `
            -Message "PowerShell Script Block Logging enables SOAR integration" `
            -Details "CISA ZT Automation: Script execution data available for automated threat response" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='AU-3'; NSA='PowerShell Security' }
    } else {
        Add-Result -Category "CISA - Zero Trust" -Status "Warning" `
            -Message "PowerShell Script Block Logging not enabled — limits SOAR capabilities" `
            -Details "CISA ZT Automation: Enable to feed script execution data to security orchestration" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty ... -Name EnableScriptBlockLogging -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='Zero Trust'; NIST='AU-3'; NSA='PowerShell Security' }
    }

} catch {
    Add-Result -Category "CISA - Zero Trust" -Status "Error" `
        -Message "Failed to check Zero Trust alignment: $_" `
        -Severity "Medium"
}

# ============================================================================
# CISA BOD 22-01/23-01: Binding Operational Directives
# ============================================================================
Write-Host "[CISA] Checking BOD 22-01/23-01 compliance..." -ForegroundColor Yellow

try {
    # BOD 22-01: Known Exploited Vulnerabilities — patch currency
    $lastHotfix = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($lastHotfix -and $lastHotfix.InstalledOn) {
        $daysSinceUpdate = ((Get-Date) - $lastHotfix.InstalledOn).Days
        if ($daysSinceUpdate -le 14) {
            Add-Result -Category "CISA - BOD 22-01" -Status "Pass" `
                -Message "BOD 22-01: System patched within 14 days ($daysSinceUpdate days since last update)" `
                -Details "BOD 22-01 requires KEV remediation within 14 days for internet-facing or 25 days for all others" `
                -Severity "High" `
                -CrossReferences @{ CISA='BOD 22-01'; NIST='SI-2(2)'; NSA='Patch Management' }
        } elseif ($daysSinceUpdate -le 25) {
            Add-Result -Category "CISA - BOD 22-01" -Status "Warning" `
                -Message "BOD 22-01: Last update $daysSinceUpdate days ago — within 25-day internal deadline" `
                -Details "Verify no KEV entries remain unpatched beyond their specific due dates" `
                -Severity "High" `
                -Remediation "Run Windows Update immediately and verify KEV catalog compliance" `
                -CrossReferences @{ CISA='BOD 22-01'; NIST='SI-2(2)'; NSA='Patch Management' }
        } else {
            Add-Result -Category "CISA - BOD 22-01" -Status "Fail" `
                -Message "BOD 22-01: System is $daysSinceUpdate days since last update — exceeds KEV deadline" `
                -Details "BOD 22-01 mandates timely remediation of Known Exploited Vulnerabilities" `
                -Remediation "Immediately apply all pending updates and audit against CISA KEV catalog" `
                -Severity "Critical" `
                -CrossReferences @{ CISA='BOD 22-01'; NIST='SI-2(2)'; NSA='Patch Management' }
        }
    } else {
        Add-Result -Category "CISA - BOD 22-01" -Status "Warning" `
            -Message "BOD 22-01: Unable to determine last patch installation date" `
            -Details "Cannot verify KEV compliance without patch history" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='BOD 22-01'; NIST='SI-2' }
    }

    # BOD 22-01: Automatic update mechanism
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    $noAutoUpdate = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Default 0
    if ($wuService -and $wuService.Status -eq "Running" -and $noAutoUpdate -eq 0) {
        Add-Result -Category "CISA - BOD 22-01" -Status "Pass" `
            -Message "BOD 22-01: Windows Update service is running with auto-updates enabled" `
            -Details "Automatic patching mechanism supports timely KEV remediation" `
            -Severity "High" `
            -CrossReferences @{ CISA='BOD 22-01'; NIST='SI-2' }
    } else {
        Add-Result -Category "CISA - BOD 22-01" -Status "Warning" `
            -Message "BOD 22-01: Automatic update mechanism may not be fully active" `
            -Details "WU service: $($wuService.Status), AutoUpdate disabled: $($noAutoUpdate -eq 1)" `
            -Remediation "Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv" `
            -Severity "High" `
            -CrossReferences @{ CISA='BOD 22-01'; NIST='SI-2' }
    }

    # BOD 23-01: Asset Visibility — system identification
    $computerInfo = @{
        Name = $env:COMPUTERNAME
        Domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
        OS = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    }
    if ($computerInfo.Domain -and $computerInfo.Domain -ne "WORKGROUP") {
        Add-Result -Category "CISA - BOD 23-01" -Status "Pass" `
            -Message "BOD 23-01: System is domain-joined ($($computerInfo.Domain)) — centrally managed asset" `
            -Details "Domain-joined systems support centralized inventory, policy enforcement, and vulnerability scanning" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='BOD 23-01'; NIST='CM-8' }
    } else {
        Add-Result -Category "CISA - BOD 23-01" -Status "Warning" `
            -Message "BOD 23-01: System is in WORKGROUP — may lack centralized management" `
            -Details "BOD 23-01 requires full asset inventory and vulnerability enumeration" `
            -Remediation "Join system to domain or enroll in cloud management (Azure AD/Intune)" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='BOD 23-01'; NIST='CM-8' }
    }

    # BOD 23-01: Network discovery protocols (asset enumeration exposure)
    $ssdp = Get-Service -Name SSDPSRV -ErrorAction SilentlyContinue
    $upnp = Get-Service -Name upnphost -ErrorAction SilentlyContinue
    $discoveryDisabled = ((-not $ssdp -or $ssdp.StartType -eq "Disabled") -and (-not $upnp -or $upnp.StartType -eq "Disabled"))
    if ($discoveryDisabled) {
        Add-Result -Category "CISA - BOD 23-01" -Status "Pass" `
            -Message "BOD 23-01: Network discovery services (SSDP/UPnP) are disabled" `
            -Details "System does not advertise itself via automatic discovery protocols" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='BOD 23-01'; NIST='CM-7'; CIS='5.33' }
    } else {
        Add-Result -Category "CISA - BOD 23-01" -Status "Warning" `
            -Message "BOD 23-01: Network discovery services are active" `
            -Details "SSDP/UPnP services expose system to network enumeration" `
            -Remediation "Set-Service -Name SSDPSRV -StartupType Disabled; Set-Service -Name upnphost -StartupType Disabled" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='BOD 23-01'; NIST='CM-7'; CIS='5.33' }
    }

    # BOD 23-01: Vulnerability scanning capability
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($defenderService -and $defenderService.Status -eq "Running") {
        Add-Result -Category "CISA - BOD 23-01" -Status "Pass" `
            -Message "BOD 23-01: Windows Defender provides vulnerability detection capability" `
            -Details "Active endpoint protection supports continuous vulnerability assessment" `
            -Severity "Medium" `
            -CrossReferences @{ CISA='BOD 23-01'; NIST='RA-5'; CIS='8.1' }
    } else {
        Add-Result -Category "CISA - BOD 23-01" -Status "Warning" `
            -Message "BOD 23-01: Windows Defender is not running — limited vulnerability visibility" `
            -Details "BOD 23-01 requires automated vulnerability enumeration within 14 days of discovery" `
            -Severity "High" `
            -CrossReferences @{ CISA='BOD 23-01'; NIST='RA-5' }
    }

} catch {
    Add-Result -Category "CISA - BOD" -Status "Error" `
        -Message "Failed to check BOD compliance: $_" `
        -Severity "Medium"
}

# ============================================================================
# Summary Statistics
# ============================================================================
$passCount  = @($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount  = @($results | Where-Object { $_.Status -eq "Fail" }).Count
$warnCount  = @($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount  = @($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = @($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

# Category breakdown
$categoryStats = @{}
foreach ($r in $results) {
    if (-not $categoryStats.ContainsKey($r.Category)) { $categoryStats[$r.Category] = 0 }
    $categoryStats[$r.Category]++
}

# Severity breakdown (failed checks only)
$severityStats = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
foreach ($r in ($results | Where-Object { $_.Status -eq "Fail" })) {
    $sev = if ($r.PSObject.Properties['Severity']) { $r.Severity } else { 'Medium' }
    if ($severityStats.ContainsKey($sev)) { $severityStats[$sev]++ }
}

Write-Host "`n[CISA] ======================================================================" -ForegroundColor Cyan
Write-Host "[CISA] MODULE COMPLETED — v$moduleVersion" -ForegroundColor Cyan
Write-Host "[CISA] ======================================================================" -ForegroundColor Cyan
Write-Host "[CISA] Total Checks Executed: $totalChecks" -ForegroundColor White
Write-Host "[CISA]" -ForegroundColor Cyan
Write-Host "[CISA] Results Summary:" -ForegroundColor Cyan
$pctPass = if ($totalChecks -gt 0) { [Math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }
Write-Host "[CISA]   Passed:   $($passCount.ToString().PadLeft(3)) ($pctPass%)" -ForegroundColor Green
Write-Host "[CISA]   Failed:   $($failCount.ToString().PadLeft(3))" -ForegroundColor Red
Write-Host "[CISA]   Warnings: $($warnCount.ToString().PadLeft(3))" -ForegroundColor Yellow
Write-Host "[CISA]   Info:     $($infoCount.ToString().PadLeft(3))" -ForegroundColor Cyan
Write-Host "[CISA]   Errors:   $($errorCount.ToString().PadLeft(3))" -ForegroundColor Magenta
Write-Host "[CISA]" -ForegroundColor Cyan
Write-Host "[CISA] Check Categories:" -ForegroundColor Cyan
foreach ($cat in ($categoryStats.Keys | Sort-Object)) {
    Write-Host "[CISA]   $($cat.PadRight(45)): $($categoryStats[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
}
if ($failCount -gt 0) {
    Write-Host "[CISA]" -ForegroundColor Cyan
    Write-Host "[CISA] Failed Check Severity:" -ForegroundColor Cyan
    foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
        if ($severityStats[$sev] -gt 0) {
            $sevColor = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; 'Low' { 'Cyan' }; default { 'Gray' } }
            Write-Host "[CISA]   $($sev.PadRight(15)): $($severityStats[$sev])" -ForegroundColor $sevColor
        }
    }
}
Write-Host "[CISA] ======================================================================`n" -ForegroundColor Cyan

return $results

# ============================================================================
# Standalone Execution Support
# ============================================================================
# When invoked directly (not dot-sourced), run in standalone test mode
# with automatic SharedData initialization, cache warmup, and detailed analysis.
# Usage: .\modules\module-cisa.ps1
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host "  CISA Cybersecurity Performance Goals — Standalone Test Mode v$moduleVersion" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host ""

    # Build standalone SharedData with system detection
    $standaloneData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion    = ''
        IPAddresses  = @()
        ScanDate     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        IsAdmin      = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath   = $PSScriptRoot
        Cache        = $null
    }

    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $standaloneData.OSVersion = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
    } catch {
        $standaloneData.OSVersion = "Windows (version detection failed)"
    }

    try {
        $standaloneData.IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress)
    } catch {
        $standaloneData.IPAddresses = @("N/A")
    }

    # Initialize cache if shared library is available
    $commonLibPath = Join-Path (Split-Path $PSScriptRoot -Parent) "shared_components\audit-common.ps1"
    if (Test-Path $commonLibPath) {
        try {
            . $commonLibPath
            $osInfoObj = Get-OSInfo
            $standaloneCache = New-SharedDataCache -OSInfo $osInfoObj
            Invoke-CacheWarmUp -Cache $standaloneCache
            $standaloneData.Cache = $standaloneCache
            $summary = Get-CacheSummary -Cache $standaloneCache
            Write-Host "  Cache: Enabled ($($summary.ServicesCount) services, $($summary.RegistryCacheCount) registry keys)" -ForegroundColor Green
        } catch {
            Write-Host "  Cache: Not available ($_)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Cache: Shared library not found (running without cache)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  Test Environment:" -ForegroundColor White
    Write-Host "    Hostname:  $($standaloneData.ComputerName)" -ForegroundColor Gray
    Write-Host "    OS:        $($standaloneData.OSVersion)" -ForegroundColor Gray
    Write-Host "    IP(s):     $($standaloneData.IPAddresses -join ', ')" -ForegroundColor Gray
    Write-Host "    Admin:     $($standaloneData.IsAdmin)" -ForegroundColor Gray
    Write-Host "    Scan Time: $($standaloneData.ScanDate)" -ForegroundColor Gray
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host ""

    # Display detailed results
    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  DETAILED STANDALONE RESULTS" -ForegroundColor Cyan
    Write-Host "$("=" * 80)" -ForegroundColor White
    Write-Host "  Generated $($results.Count) audit results`n" -ForegroundColor White

    # Status distribution with visual bars
    Write-Host "  Status Distribution:" -ForegroundColor White
    foreach ($statusType in @("Pass", "Fail", "Warning", "Info", "Error")) {
        $count = @($results | Where-Object { $_.Status -eq $statusType }).Count
        if ($count -gt 0 -and $results.Count -gt 0) {
            $pct = [Math]::Round(($count / $results.Count) * 100, 1)
            $barLen = [Math]::Floor($pct / 2)
            $bar = "#" * $barLen
            $color = switch ($statusType) { "Pass" { "Green" }; "Fail" { "Red" }; "Warning" { "Yellow" }; "Info" { "Cyan" }; default { "Magenta" } }
            Write-Host "    $($statusType.PadRight(8)): $($count.ToString().PadLeft(3)) ($($pct.ToString().PadLeft(5))%) $bar" -ForegroundColor $color
        }
    }

    # Category coverage
    Write-Host "`n  Check Area Coverage:" -ForegroundColor White
    $catCounts = @{}
    foreach ($r in $results) {
        if (-not $catCounts.ContainsKey($r.Category)) { $catCounts[$r.Category] = 0 }
        $catCounts[$r.Category]++
    }
    foreach ($cat in ($catCounts.Keys | Sort-Object)) {
        Write-Host "    $($cat.PadRight(45)): $($catCounts[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
    }

    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  CISA module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
# ============================================================================
# End of CISA Cybersecurity Performance Goals Module (Module-CISA.ps1)
# ============================================================================
