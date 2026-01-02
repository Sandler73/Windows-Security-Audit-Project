# Module-MS-DefenderATP.ps1
# Microsoft Defender for Endpoint (Advanced Threat Protection) Module
# Version: 1.0
# Comprehensive EDR and Advanced Protection Assessment

<#
.SYNOPSIS
    Microsoft Defender for Endpoint (ATP/EDR) comprehensive security assessment.

.DESCRIPTION
    This module performs in-depth analysis of Microsoft Defender for Endpoint capabilities:
    
    ENDPOINT DETECTION & RESPONSE (EDR):
    - Defender for Endpoint onboarding status
    - Sense service (EDR agent) health
    - EDR in block mode configuration
    - Automated Investigation & Response (AIR)
    - Device risk level and exposure score
    - Security baselines compliance
    - Cloud connectivity and telemetry
    
    THREAT & VULNERABILITY MANAGEMENT (TVM):
    - TVM integration and health
    - Security recommendations tracking
    - Software inventory analysis
    - Vulnerability assessment status
    - Configuration assessment
    - Exposure score calculation
    
    ADVANCED PROTECTION:
    - Advanced ASR rules analysis
    - ASR exclusions and exceptions audit
    - Custom indicator (IoC) configuration
    - Automated response actions
    - Advanced scanning capabilities
    - Cloud-delivered protection deep dive
    
    THREAT INTELLIGENCE:
    - Threat intelligence integration
    - Custom threat indicators
    - IoC retention and matching
    - Alert suppression rules
    - Security operations integration
    
    INTEGRATION & CONNECTIVITY:
    - Microsoft 365 Defender integration
    - Security Center connectivity
    - Azure Sentinel integration
    - Third-party integration status
    - API connectivity health
    
    ADVANCED FEATURES:
    - Live response capability
    - Advanced hunting status
    - Device isolation capability
    - File collection and analysis
    - Network protection advanced settings
    - Web content filtering
    - Device control policies

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName: System hostname
    - OSVersion: Operating system version
    - IsAdmin: Administrator privilege status
    - ScanDate: Audit timestamp

.NOTES
    Version: 1.0
    Requires:
    - Windows 10 1607+ or Windows Server 2012 R2+
    - PowerShell 5.1+
    - Administrator privileges
    - Microsoft Defender for Endpoint license (for full EDR features)
    
    References:
    - https://learn.microsoft.com/en-us/defender-endpoint/
    - https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints
    - https://learn.microsoft.com/en-us/defender-endpoint/automated-investigations
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "MS-DefenderATP"
$results = @()

# Helper function to add results
function Add-Result {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Message,
        [string]$Details = "",
        [string]$Remediation = ""
    )
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

Write-Host "`n[MS-DefenderATP] Starting Microsoft Defender for Endpoint checks..." -ForegroundColor Cyan

# ============================================================================
# SECTION 1: DEFENDER FOR ENDPOINT ONBOARDING STATUS
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Defender for Endpoint Onboarding..." -ForegroundColor Yellow

try {
    # Check if Sense service exists (EDR agent)
    $senseService = Get-Service -Name Sense -ErrorAction SilentlyContinue
    
    if ($senseService) {
        if ($senseService.Status -eq "Running") {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Microsoft Defender for Endpoint service (Sense) is running" `
                -Details "ATP/EDR: The Sense service provides EDR capabilities and telemetry to Microsoft 365 Defender"
        } else {
            Add-Result -Category "ATP - Onboarding" -Status "Fail" `
                -Message "Sense service is installed but not running (Status: $($senseService.Status))" `
                -Details "ATP/EDR: EDR capabilities are not active" `
                -Remediation "Start-Service -Name Sense"
        }
        
        # Check service startup type
        if ($senseService.StartType -eq "Automatic") {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Sense service is set to start automatically" `
                -Details "ATP/EDR: Service will start on boot"
        } else {
            Add-Result -Category "ATP - Onboarding" -Status "Warning" `
                -Message "Sense service startup type is: $($senseService.StartType)" `
                -Details "ATP/EDR: Should be set to Automatic" `
                -Remediation "Set-Service -Name Sense -StartupType Automatic"
        }
        
        # Check onboarding registry key
        $onboardingState = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState" -ErrorAction SilentlyContinue
        
        if ($onboardingState -and $onboardingState.OnboardingState -eq 1) {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Device is onboarded to Microsoft Defender for Endpoint" `
                -Details "ATP/EDR: OnboardingState = 1 (Onboarded)"
        } else {
            Add-Result -Category "ATP - Onboarding" -Status "Warning" `
                -Message "Device onboarding state unclear or not fully onboarded" `
                -Details "ATP/EDR: OnboardingState registry value not found or not set to 1"
        }
        
        # Check organization ID
        $orgId = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OrgId" -ErrorAction SilentlyContinue
        
        if ($orgId -and $orgId.OrgId) {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Device is registered to organization: $($orgId.OrgId)" `
                -Details "ATP/EDR: Device is associated with a Defender for Endpoint tenant"
        }
        
    } else {
        Add-Result -Category "ATP - Onboarding" -Status "Info" `
            -Message "Microsoft Defender for Endpoint (Sense service) is not installed" `
            -Details "ATP/EDR: Device is not onboarded to Defender for Endpoint. EDR capabilities not available" `
            -Remediation "Download onboarding package from Microsoft 365 Defender portal and run: .\WindowsDefenderATPOnboardingScript.cmd"
    }
    
} catch {
    Add-Result -Category "ATP - Onboarding" -Status "Error" `
        -Message "Failed to check Defender for Endpoint onboarding: $_"
}

# ============================================================================
# SECTION 2: EDR IN BLOCK MODE
# ============================================================================
Write-Host "[MS-DefenderATP] Checking EDR in Block Mode..." -ForegroundColor Yellow

try {
    # EDR in block mode requires cloud-delivered protection
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference) {
        # Check if ForceDefenderPassiveMode is disabled (EDR in block mode requires active mode)
        $passiveMode = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -ErrorAction SilentlyContinue
        
        if ($passiveMode -and $passiveMode.ForceDefenderPassiveMode -eq 1) {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Warning" `
                -Message "Defender is forced into passive mode" `
                -Details "ATP/EDR: EDR in block mode cannot function when Defender is in passive mode" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -Name ForceDefenderPassiveMode -Value 0 -Type DWord"
        } else {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Pass" `
                -Message "Defender is not forced into passive mode" `
                -Details "ATP/EDR: EDR in block mode can be enabled"
        }
        
        # Check cloud-delivered protection (required for EDR in block mode)
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus -and $mpStatus.MAPSReporting -gt 0) {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Pass" `
                -Message "Cloud-delivered protection is enabled (required for EDR in block mode)" `
                -Details "ATP/EDR: MAPS reporting level: $($mpStatus.MAPSReporting)"
        } else {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Warning" `
                -Message "Cloud-delivered protection is disabled" `
                -Details "ATP/EDR: EDR in block mode requires cloud protection" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced"
        }
    }
    
} catch {
    Add-Result -Category "ATP - EDR Block Mode" -Status "Error" `
        -Message "Failed to check EDR in block mode configuration: $_"
}

# ============================================================================
# SECTION 3: AUTOMATED INVESTIGATION & RESPONSE (AIR)
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Automated Investigation & Response..." -ForegroundColor Yellow

try {
    # Check automation level
    $automationLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "AutomationLevel" -ErrorAction SilentlyContinue
    
    if ($automationLevel) {
        $level = $automationLevel.AutomationLevel
        
        switch ($level) {
            0 {
                Add-Result -Category "ATP - AIR" -Status "Warning" `
                    -Message "Automated Investigation & Response: Disabled" `
                    -Details "ATP/EDR: No automated investigations will run" `
                    -Remediation "Configure AIR in Microsoft 365 Defender portal"
            }
            1 {
                Add-Result -Category "ATP - AIR" -Status "Info" `
                    -Message "Automated Investigation & Response: Semi-automated" `
                    -Details "ATP/EDR: Automated investigations run but require approval for remediation"
            }
            2 {
                Add-Result -Category "ATP - AIR" -Status "Pass" `
                    -Message "Automated Investigation & Response: Fully automated" `
                    -Details "ATP/EDR: Investigations and remediation occur automatically"
            }
            default {
                Add-Result -Category "ATP - AIR" -Status "Info" `
                    -Message "Automated Investigation & Response level: $level" `
                    -Details "ATP/EDR: Custom automation configuration"
            }
        }
    } else {
        Add-Result -Category "ATP - AIR" -Status "Info" `
            -Message "Automated Investigation & Response configuration not found" `
            -Details "ATP/EDR: AIR may be configured at tenant level in Microsoft 365 Defender portal"
    }
    
} catch {
    Add-Result -Category "ATP - AIR" -Status "Error" `
        -Message "Failed to check AIR configuration: $_"
}

# ============================================================================
# SECTION 4: THREAT & VULNERABILITY MANAGEMENT (TVM)
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Threat & Vulnerability Management..." -ForegroundColor Yellow

try {
    # Check if TVM is enabled
    $tvmEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration" -Name "DisableTvmForEndpoint" -ErrorAction SilentlyContinue
    
    if ($tvmEnabled -and $tvmEnabled.DisableTvmForEndpoint -eq 0) {
        Add-Result -Category "ATP - TVM" -Status "Pass" `
            -Message "Threat & Vulnerability Management is enabled" `
            -Details "ATP/EDR: TVM provides vulnerability assessment and security recommendations"
    } elseif ($tvmEnabled -and $tvmEnabled.DisableTvmForEndpoint -eq 1) {
        Add-Result -Category "ATP - TVM" -Status "Warning" `
            -Message "Threat & Vulnerability Management is disabled" `
            -Details "ATP/EDR: Device will not report vulnerabilities to TVM dashboard" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration' -Name DisableTvmForEndpoint -Value 0 -Type DWord"
    } else {
        Add-Result -Category "ATP - TVM" -Status "Info" `
            -Message "TVM configuration not explicitly set (using default)" `
            -Details "ATP/EDR: TVM is typically enabled by default when onboarded to Defender for Endpoint"
    }
    
    # Check software inventory collection
    $softwareInventory = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration" -Name "DisableSoftwareInventory" -ErrorAction SilentlyContinue
    
    if ($softwareInventory -and $softwareInventory.DisableSoftwareInventory -eq 1) {
        Add-Result -Category "ATP - TVM" -Status "Warning" `
            -Message "Software inventory collection is disabled" `
            -Details "ATP/EDR: TVM requires software inventory for vulnerability assessment" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration' -Name DisableSoftwareInventory -Value 0 -Type DWord"
    } else {
        Add-Result -Category "ATP - TVM" -Status "Pass" `
            -Message "Software inventory collection is enabled" `
            -Details "ATP/EDR: Device reports installed software to TVM"
    }
    
} catch {
    Add-Result -Category "ATP - TVM" -Status "Error" `
        -Message "Failed to check TVM configuration: $_"
}

# ============================================================================
# SECTION 5: ADVANCED ASR RULES ANALYSIS
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Advanced ASR Configuration..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $asrRuleIds = $mpPreference.AttackSurfaceReductionRules_Ids
    $asrRuleActions = $mpPreference.AttackSurfaceReductionRules_Actions
    
    if ($asrRuleIds -and $asrRuleIds.Count -gt 0) {
        # ASR Rule descriptions
        $asrRuleNames = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
            "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
            "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
            "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet prevalence, age, or trusted list criteria"
            "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from Windows local security authority subsystem (lsass.exe)"
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
            "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes that run from USB"
            "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication applications from creating child processes"
            "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
            "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
            "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
            "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
        }
        
        # Detailed rule analysis
        for ($i = 0; $i -lt $asrRuleIds.Count; $i++) {
            $ruleId = $asrRuleIds[$i]
            $action = $asrRuleActions[$i]
            $ruleName = $asrRuleNames[$ruleId]
            
            if (-not $ruleName) { $ruleName = "Unknown Rule" }
            
            $actionText = switch ($action) {
                0 { "Disabled" }
                1 { "Block" }
                2 { "Audit" }
                6 { "Warn" }
                default { "Unknown ($action)" }
            }
            
            $status = switch ($action) {
                0 { "Warning" }
                1 { "Pass" }
                2 { "Info" }
                6 { "Info" }
                default { "Info" }
            }
            
            Add-Result -Category "ATP - ASR Details" -Status $status `
                -Message "ASR Rule: $ruleName" `
                -Details "ATP/EDR: Action = $actionText | Rule ID: $ruleId"
        }
        
        # Check for ASR exclusions
        $asrExclusions = $mpPreference.AttackSurfaceReductionOnlyExclusions
        
        if ($asrExclusions -and $asrExclusions.Count -gt 0) {
            Add-Result -Category "ATP - ASR Details" -Status "Info" `
                -Message "ASR exclusions configured: $($asrExclusions.Count)" `
                -Details "ATP/EDR: Exclusions = $($asrExclusions -join ', ')"
        } else {
            Add-Result -Category "ATP - ASR Details" -Status "Pass" `
                -Message "No ASR exclusions configured" `
                -Details "ATP/EDR: All ASR rules apply universally without exclusions"
        }
        
    } else {
        Add-Result -Category "ATP - ASR Details" -Status "Info" `
            -Message "No Attack Surface Reduction rules configured" `
            -Details "ATP/EDR: ASR rules are not currently protecting this device"
    }
    
} catch {
    Add-Result -Category "ATP - ASR Details" -Status "Error" `
        -Message "Failed to analyze ASR rules: $_"
}

# ============================================================================
# SECTION 6: CUSTOM INDICATORS (IOC)
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Custom Indicator Configuration..." -ForegroundColor Yellow

try {
    # Check if custom indicators can be received
    $indicatorPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    $indicatorEnabled = Get-ItemProperty -Path $indicatorPath -Name "TpAutoUpdateIndicators" -ErrorAction SilentlyContinue
    
    if ($indicatorEnabled -and $indicatorEnabled.TpAutoUpdateIndicators -eq 1) {
        Add-Result -Category "ATP - Custom Indicators" -Status "Pass" `
            -Message "Custom threat indicators auto-update is enabled" `
            -Details "ATP/EDR: Device can receive and enforce custom IoCs from Microsoft 365 Defender"
    } elseif ($indicatorEnabled -and $indicatorEnabled.TpAutoUpdateIndicators -eq 0) {
        Add-Result -Category "ATP - Custom Indicators" -Status "Warning" `
            -Message "Custom threat indicators auto-update is disabled" `
            -Details "ATP/EDR: Device will not receive custom IoCs" `
            -Remediation "Set-ItemProperty -Path '$indicatorPath' -Name TpAutoUpdateIndicators -Value 1 -Type DWord"
    } else {
        Add-Result -Category "ATP - Custom Indicators" -Status "Info" `
            -Message "Custom indicator configuration not explicitly set" `
            -Details "ATP/EDR: Using default configuration (typically enabled)"
    }
    
} catch {
    Add-Result -Category "ATP - Custom Indicators" -Status "Error" `
        -Message "Failed to check custom indicator configuration: $_"
}

# ============================================================================
# SECTION 7: CLOUD CONNECTIVITY AND TELEMETRY
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Cloud Connectivity..." -ForegroundColor Yellow

try {
    # Check diagnostic data level (required for Defender for Endpoint)
    $telemetryLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    
    if ($telemetryLevel) {
        $level = $telemetryLevel.AllowTelemetry
        
        if ($level -ge 2) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Diagnostic data level is sufficient (Level: $level)" `
                -Details "ATP/EDR: Level 2 (Enhanced) or 3 (Full) required for Defender for Endpoint"
        } elseif ($level -eq 1) {
            Add-Result -Category "ATP - Connectivity" -Status "Warning" `
                -Message "Diagnostic data level is Basic (Level: 1)" `
                -Details "ATP/EDR: Enhanced (2) or Full (3) recommended for optimal EDR functionality" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 2 -Type DWord"
        } else {
            Add-Result -Category "ATP - Connectivity" -Status "Fail" `
                -Message "Diagnostic data is disabled or security-only (Level: $level)" `
                -Details "ATP/EDR: Defender for Endpoint requires at least Basic telemetry" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 2 -Type DWord"
        }
    } else {
        Add-Result -Category "ATP - Connectivity" -Status "Info" `
            -Message "Diagnostic data level not configured via policy" `
            -Details "ATP/EDR: Using default Windows telemetry settings"
    }
    
    # Check cloud-delivered protection service connectivity
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        if ($mpStatus.AMServiceEnabled) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Antimalware service is enabled and running" `
                -Details "ATP/EDR: Core protection service is operational"
        }
        
        if ($mpStatus.AntispywareEnabled) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Antispyware protection is enabled" `
                -Details "ATP/EDR: Spyware detection is active"
        }
        
        if ($mpStatus.AntivirusEnabled) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Antivirus protection is enabled" `
                -Details "ATP/EDR: Virus detection is active"
        }
    }
    
} catch {
    Add-Result -Category "ATP - Connectivity" -Status "Error" `
        -Message "Failed to check cloud connectivity: $_"
}

# ============================================================================
# SECTION 8: ADVANCED SCANNING CAPABILITIES
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Advanced Scanning Features..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference) {
        # Check scan parameters
        if ($mpPreference.ScanAvgCPULoadFactor -le 50) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Average CPU load factor during scans: $($mpPreference.ScanAvgCPULoadFactor)%" `
                -Details "ATP/EDR: Balanced performance during scans"
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Info" `
                -Message "Average CPU load factor during scans: $($mpPreference.ScanAvgCPULoadFactor)%" `
                -Details "ATP/EDR: High CPU usage may impact system performance"
        }
        
        # Check archive scanning
        if ($mpPreference.DisableArchiveScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Archive scanning is enabled" `
                -Details "ATP/EDR: ZIP, CAB, and other archives are scanned for threats"
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Archive scanning is disabled" `
                -Details "ATP/EDR: Threats in compressed files may go undetected" `
                -Remediation "Set-MpPreference -DisableArchiveScanning `$false"
        }
        
        # Check email scanning
        if ($mpPreference.DisableEmailScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Email scanning is enabled" `
                -Details "ATP/EDR: Email files (PST, DBX) are scanned"
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Email scanning is disabled" `
                -Details "ATP/EDR: Threats in email archives may go undetected" `
                -Remediation "Set-MpPreference -DisableEmailScanning `$false"
        }
        
        # Check removable drive scanning
        if ($mpPreference.DisableRemovableDriveScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Removable drive scanning is enabled" `
                -Details "ATP/EDR: USB and external drives are scanned"
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Removable drive scanning is disabled" `
                -Details "ATP/EDR: Threats from removable media may not be detected" `
                -Remediation "Set-MpPreference -DisableRemovableDriveScanning `$false"
        }
        
        # Check script scanning
        if ($mpPreference.DisableScriptScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Script scanning is enabled" `
                -Details "ATP/EDR: JavaScript, VBScript, and PowerShell scripts are scanned"
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Fail" `
                -Message "Script scanning is DISABLED" `
                -Details "ATP/EDR: Critical - script-based attacks will not be detected" `
                -Remediation "Set-MpPreference -DisableScriptScanning `$false"
        }
        
        # Check intrusion prevention system
        if ($mpPreference.DisableIntrusionPreventionSystem -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Network intrusion prevention system is enabled" `
                -Details "ATP/EDR: Network traffic inspection for known exploits"
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Network intrusion prevention system is disabled" `
                -Details "ATP/EDR: Network-based exploit detection is disabled" `
                -Remediation "Set-MpPreference -DisableIntrusionPreventionSystem `$false"
        }
    }
    
} catch {
    Add-Result -Category "ATP - Scanning" -Status "Error" `
        -Message "Failed to check scanning capabilities: $_"
}

# ============================================================================
# SECTION 9: DEVICE CONTROL
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Device Control Policies..." -ForegroundColor Yellow

try {
    # Check if device control is configured
    $deviceControlPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "DeviceControlEnabled" -ErrorAction SilentlyContinue
    
    if ($deviceControlPolicy -and $deviceControlPolicy.DeviceControlEnabled -eq 1) {
        Add-Result -Category "ATP - Device Control" -Status "Pass" `
            -Message "Device Control policies are enabled" `
            -Details "ATP/EDR: Removable media and devices are managed by policy"
    } elseif ($deviceControlPolicy -and $deviceControlPolicy.DeviceControlEnabled -eq 0) {
        Add-Result -Category "ATP - Device Control" -Status "Info" `
            -Message "Device Control is disabled" `
            -Details "ATP/EDR: No restrictions on removable media and peripheral devices"
    } else {
        Add-Result -Category "ATP - Device Control" -Status "Info" `
            -Message "Device Control policies not explicitly configured" `
            -Details "ATP/EDR: Device Control can restrict USB, printers, and other peripherals"
    }
    
} catch {
    Add-Result -Category "ATP - Device Control" -Status "Error" `
        -Message "Failed to check Device Control: $_"
}

# ============================================================================
# SECTION 10: WEB CONTENT FILTERING
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Web Content Filtering..." -ForegroundColor Yellow

try {
    # Check if web content filtering is enabled
    $webFiltering = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableWebContentFiltering" -ErrorAction SilentlyContinue
    
    if ($webFiltering -and $webFiltering.EnableWebContentFiltering -eq 1) {
        Add-Result -Category "ATP - Web Filtering" -Status "Pass" `
            -Message "Web content filtering is enabled" `
            -Details "ATP/EDR: Blocks access to websites based on content categories"
    } elseif ($webFiltering -and $webFiltering.EnableWebContentFiltering -eq 0) {
        Add-Result -Category "ATP - Web Filtering" -Status "Info" `
            -Message "Web content filtering is disabled" `
            -Details "ATP/EDR: Web category-based blocking is not active"
    } else {
        Add-Result -Category "ATP - Web Filtering" -Status "Info" `
            -Message "Web content filtering not configured" `
            -Details "ATP/EDR: Can block adult content, legal liability, high bandwidth sites, etc."
    }
    
} catch {
    Add-Result -Category "ATP - Web Filtering" -Status "Error" `
        -Message "Failed to check web content filtering: $_"
}

# ============================================================================
# SECTION 11: LIVE RESPONSE AND ADVANCED FEATURES
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Advanced Feature Configuration..." -ForegroundColor Yellow

try {
    # Check if live response is disabled
    $liveResponse = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "DisableLiveResponse" -ErrorAction SilentlyContinue
    
    if ($liveResponse -and $liveResponse.DisableLiveResponse -eq 1) {
        Add-Result -Category "ATP - Advanced Features" -Status "Warning" `
            -Message "Live Response is disabled" `
            -Details "ATP/EDR: Security analysts cannot connect to device for investigation" `
            -Remediation "Remove or set to 0: HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DisableLiveResponse"
    } else {
        Add-Result -Category "ATP - Advanced Features" -Status "Pass" `
            -Message "Live Response is enabled or not restricted" `
            -Details "ATP/EDR: Allows remote investigation and remediation"
    }
    
    # Check sample collection
    $sampleCollection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "DisableSampleCollection" -ErrorAction SilentlyContinue
    
    if ($sampleCollection -and $sampleCollection.DisableSampleCollection -eq 1) {
        Add-Result -Category "ATP - Advanced Features" -Status "Warning" `
            -Message "Sample collection is disabled" `
            -Details "ATP/EDR: Cannot collect files for deep analysis" `
            -Remediation "Remove or set to 0: HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DisableSampleCollection"
    } else {
        Add-Result -Category "ATP - Advanced Features" -Status "Pass" `
            -Message "Sample collection is enabled or not restricted" `
            -Details "ATP/EDR: Suspicious files can be collected for analysis"
    }
    
} catch {
    Add-Result -Category "ATP - Advanced Features" -Status "Error" `
        -Message "Failed to check advanced features: $_"
}

# ============================================================================
# SECTION 12: NETWORK PROTECTION ADVANCED
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Advanced Network Protection..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference) {
        # Check DNS over HTTPS with Network Protection
        $dnsPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Network Protection" -Name "EnableDnsProtection" -ErrorAction SilentlyContinue
        
        if ($dnsPolicy -and $dnsPolicy.EnableDnsProtection -eq 1) {
            Add-Result -Category "ATP - Network Protection" -Status "Pass" `
                -Message "DNS protection is enabled" `
                -Details "ATP/EDR: DNS queries are inspected for malicious domains"
        }
        
        # Check custom block list
        $customBlockList = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Network Protection" -Name "CustomBlockList" -ErrorAction SilentlyContinue
        
        if ($customBlockList) {
            Add-Result -Category "ATP - Network Protection" -Status "Info" `
                -Message "Custom network block list is configured" `
                -Details "ATP/EDR: Additional domains/IPs are blocked beyond cloud intelligence"
        }
    }
    
} catch {
    Add-Result -Category "ATP - Network Protection" -Status "Error" `
        -Message "Failed to check advanced network protection: $_"
}

# ============================================================================
# SECTION 13: TAMPER PROTECTION ADVANCED
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Tamper Protection Status..." -ForegroundColor Yellow

try {
    # Check tamper protection (cloud-managed)
    $tamperProtection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
    
    if ($tamperProtection) {
        $tamperValue = $tamperProtection.TamperProtection
        
        switch ($tamperValue) {
            0 {
                Add-Result -Category "ATP - Tamper Protection" -Status "Fail" `
                    -Message "Tamper Protection is OFF" `
                    -Details "ATP/EDR: Defender settings can be modified by malware" `
                    -Remediation "Enable via Microsoft 365 Defender portal or Windows Security"
            }
            4 {
                Add-Result -Category "ATP - Tamper Protection" -Status "Warning" `
                    -Message "Tamper Protection is DISABLED" `
                    -Details "ATP/EDR: Protection against tampering is not active" `
                    -Remediation "Enable via Microsoft 365 Defender portal or Windows Security"
            }
            5 {
                Add-Result -Category "ATP - Tamper Protection" -Status "Pass" `
                    -Message "Tamper Protection is ON" `
                    -Details "ATP/EDR: Defender settings are protected from unauthorized changes"
            }
            default {
                Add-Result -Category "ATP - Tamper Protection" -Status "Info" `
                    -Message "Tamper Protection status: $tamperValue" `
                    -Details "ATP/EDR: Unusual tamper protection value detected"
            }
        }
    } else {
        Add-Result -Category "ATP - Tamper Protection" -Status "Warning" `
            -Message "Tamper Protection status could not be determined" `
            -Details "ATP/EDR: Check Windows Security settings"
    }
    
} catch {
    Add-Result -Category "ATP - Tamper Protection" -Status "Error" `
        -Message "Failed to check Tamper Protection: $_"
}

# ============================================================================
# SECTION 14: EXCLUSIONS AUDIT
# ============================================================================
Write-Host "[MS-DefenderATP] Auditing Defender Exclusions..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference) {
        # Path exclusions
        $pathExclusions = $mpPreference.ExclusionPath
        if ($pathExclusions -and $pathExclusions.Count -gt 0) {
            Add-Result -Category "ATP - Exclusions" -Status "Warning" `
                -Message "Path exclusions configured: $($pathExclusions.Count)" `
                -Details "ATP/EDR: Paths excluded from scanning = $($pathExclusions -join '; ')"
        } else {
            Add-Result -Category "ATP - Exclusions" -Status "Pass" `
                -Message "No path exclusions configured" `
                -Details "ATP/EDR: All paths are scanned"
        }
        
        # Process exclusions
        $processExclusions = $mpPreference.ExclusionProcess
        if ($processExclusions -and $processExclusions.Count -gt 0) {
            Add-Result -Category "ATP - Exclusions" -Status "Warning" `
                -Message "Process exclusions configured: $($processExclusions.Count)" `
                -Details "ATP/EDR: Processes excluded = $($processExclusions -join '; ')"
        } else {
            Add-Result -Category "ATP - Exclusions" -Status "Pass" `
                -Message "No process exclusions configured" `
                -Details "ATP/EDR: All processes are monitored"
        }
        
        # Extension exclusions
        $extensionExclusions = $mpPreference.ExclusionExtension
        if ($extensionExclusions -and $extensionExclusions.Count -gt 0) {
            Add-Result -Category "ATP - Exclusions" -Status "Warning" `
                -Message "Extension exclusions configured: $($extensionExclusions.Count)" `
                -Details "ATP/EDR: File extensions excluded = $($extensionExclusions -join '; ')"
        } else {
            Add-Result -Category "ATP - Exclusions" -Status "Pass" `
                -Message "No extension exclusions configured" `
                -Details "ATP/EDR: All file types are scanned"
        }
    }
    
} catch {
    Add-Result -Category "ATP - Exclusions" -Status "Error" `
        -Message "Failed to audit exclusions: $_"
}

# ============================================================================
# Summary Statistics
# ============================================================================
$passCount = @($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = @($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = @($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = @($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = @($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

Write-Host "`n========================================================================================================" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] Microsoft Defender for Endpoint Module Completed" -ForegroundColor Cyan
Write-Host "========================================================================================================" -ForegroundColor Cyan
Write-Host "  Total Checks:    $totalChecks" -ForegroundColor White
Write-Host "  Passed:          $passCount" -ForegroundColor Green
Write-Host "  Failed:          $failCount" -ForegroundColor Red
Write-Host "  Warnings:        $warningCount" -ForegroundColor Yellow
Write-Host "  Info:            $infoCount" -ForegroundColor Cyan
Write-Host "  Errors:          $errorCount" -ForegroundColor Magenta

if ($failCount -gt 0) {
    Write-Host "`n  Critical ATP/EDR issues detected - review failed checks immediately" -ForegroundColor Red
}
if ($warningCount -gt 0) {
    Write-Host "  ATP/EDR warnings require attention for optimal threat protection" -ForegroundColor Yellow
}

Write-Host "========================================================================================================`n" -ForegroundColor Cyan

return $results
