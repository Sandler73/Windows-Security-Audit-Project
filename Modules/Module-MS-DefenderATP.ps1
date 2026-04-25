# Module-MS-DefenderATP.ps1
# Microsoft Defender for Endpoint (Advanced Threat Protection) Module
# Version: 6.1.2
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
    Version: 6.1.2
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
$moduleVersion = "6.1.2"

# Helper function to add results
function Add-Result {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Message,
        [string]$Details     = "",
        [string]$Remediation = "",
        [ValidateSet("Critical","High","Medium","Low","Informational")]
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
        $regItem = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($regItem) { return $regItem.$Name }
    }
    catch { <# Expected: item may not exist #> }
    return $Default
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
                -Details "ATP/EDR: The Sense service provides EDR capabilities and telemetry to Microsoft 365 Defender" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Onboarding" -Status "Fail" `
                -Message "Sense service is installed but not running (Status: $($senseService.Status))" `
                -Details "ATP/EDR: EDR capabilities are not active" `
                -Remediation "Start-Service -Name Sense" `
                -Severity "High" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check service startup type
        if ($senseService.StartType -eq "Automatic") {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Sense service is set to start automatically" `
                -Details "ATP/EDR: Service will start on boot" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Onboarding" -Status "Warning" `
                -Message "Sense service startup type is: $($senseService.StartType)" `
                -Details "ATP/EDR: Should be set to Automatic" `
                -Remediation "Set-Service -Name Sense -StartupType Automatic" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check onboarding registry key
        $onboardingState = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState" -ErrorAction SilentlyContinue
        
        if ($onboardingState -and $onboardingState.OnboardingState -eq 1) {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Device is onboarded to Microsoft Defender for Endpoint" `
                -Details "ATP/EDR: OnboardingState = 1 (Onboarded)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Onboarding" -Status "Warning" `
                -Message "Device onboarding state unclear or not fully onboarded" `
                -Details "ATP/EDR: OnboardingState registry value not found or not set to 1" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check organization ID
        $orgId = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OrgId" -ErrorAction SilentlyContinue
        
        if ($orgId -and $orgId.OrgId) {
            Add-Result -Category "ATP - Onboarding" -Status "Pass" `
                -Message "Device is registered to organization: $($orgId.OrgId)" `
                -Details "ATP/EDR: Device is associated with a Defender for Endpoint tenant" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
    } else {
        Add-Result -Category "ATP - Onboarding" -Status "Info" `
            -Message "Microsoft Defender for Endpoint (Sense service) is not installed" `
            -Details "ATP/EDR: Device is not onboarded to Defender for Endpoint. EDR capabilities not available" `
            -Remediation "Download onboarding package from Microsoft 365 Defender portal and run: .\WindowsDefenderATPOnboardingScript.cmd" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - Onboarding" -Status "Error" `
        -Message "Failed to check Defender for Endpoint onboarding: $_" `
        -Severity "Medium"
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
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -Name ForceDefenderPassiveMode -Value 0 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Pass" `
                -Message "Defender is not forced into passive mode" `
                -Details "ATP/EDR: EDR in block mode can be enabled" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check cloud-delivered protection (required for EDR in block mode)
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus -and $mpStatus.MAPSReporting -gt 0) {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Pass" `
                -Message "Cloud-delivered protection is enabled (required for EDR in block mode)" `
                -Details "ATP/EDR: MAPS reporting level: $($mpStatus.MAPSReporting)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - EDR Block Mode" -Status "Warning" `
                -Message "Cloud-delivered protection is disabled" `
                -Details "ATP/EDR: EDR in block mode requires cloud protection" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
    }
    
} catch {
    Add-Result -Category "ATP - EDR Block Mode" -Status "Error" `
        -Message "Failed to check EDR in block mode configuration: $_" `
        -Severity "Medium"
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
                    -Remediation "Configure AIR in Microsoft 365 Defender portal" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
            1 {
                Add-Result -Category "ATP - AIR" -Status "Info" `
                    -Message "Automated Investigation & Response: Semi-automated" `
                    -Details "ATP/EDR: Automated investigations run but require approval for remediation" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
            2 {
                Add-Result -Category "ATP - AIR" -Status "Pass" `
                    -Message "Automated Investigation & Response: Fully automated" `
                    -Details "ATP/EDR: Investigations and remediation occur automatically" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
            default {
                Add-Result -Category "ATP - AIR" -Status "Info" `
                    -Message "Automated Investigation & Response level: $level" `
                    -Details "ATP/EDR: Custom automation configuration" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
        }
    } else {
        Add-Result -Category "ATP - AIR" -Status "Info" `
            -Message "Automated Investigation & Response configuration not found" `
            -Details "ATP/EDR: AIR may be configured at tenant level in Microsoft 365 Defender portal" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - AIR" -Status "Error" `
        -Message "Failed to check AIR configuration: $_" `
        -Severity "Medium"
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
            -Details "ATP/EDR: TVM provides vulnerability assessment and security recommendations" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } elseif ($tvmEnabled -and $tvmEnabled.DisableTvmForEndpoint -eq 1) {
        Add-Result -Category "ATP - TVM" -Status "Warning" `
            -Message "Threat & Vulnerability Management is disabled" `
            -Details "ATP/EDR: Device will not report vulnerabilities to TVM dashboard" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration' -Name DisableTvmForEndpoint -Value 0 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - TVM" -Status "Info" `
            -Message "TVM configuration not explicitly set (using default)" `
            -Details "ATP/EDR: TVM is typically enabled by default when onboarded to Defender for Endpoint" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
    # Check software inventory collection
    $softwareInventory = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration" -Name "DisableSoftwareInventory" -ErrorAction SilentlyContinue
    
    if ($softwareInventory -and $softwareInventory.DisableSoftwareInventory -eq 1) {
        Add-Result -Category "ATP - TVM" -Status "Warning" `
            -Message "Software inventory collection is disabled" `
            -Details "ATP/EDR: TVM requires software inventory for vulnerability assessment" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration' -Name DisableSoftwareInventory -Value 0 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - TVM" -Status "Pass" `
            -Message "Software inventory collection is enabled" `
            -Details "ATP/EDR: Device reports installed software to TVM" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - TVM" -Status "Error" `
        -Message "Failed to check TVM configuration: $_" `
        -Severity "Medium"
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
                -Details "ATP/EDR: Action = $actionText | Rule ID: $ruleId" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        }
        
        # Check for ASR exclusions
        $asrExclusions = $mpPreference.AttackSurfaceReductionOnlyExclusions
        
        if ($asrExclusions -and $asrExclusions.Count -gt 0) {
            Add-Result -Category "ATP - ASR Details" -Status "Info" `
                -Message "ASR exclusions configured: $($asrExclusions.Count)" `
                -Details "ATP/EDR: Exclusions = $($asrExclusions -join ', ')" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        } else {
            Add-Result -Category "ATP - ASR Details" -Status "Pass" `
                -Message "No ASR exclusions configured" `
                -Details "ATP/EDR: All ASR rules apply universally without exclusions" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        }
        
    } else {
        Add-Result -Category "ATP - ASR Details" -Status "Info" `
            -Message "No Attack Surface Reduction rules configured" `
            -Details "ATP/EDR: ASR rules are not currently protecting this device" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
    }
    
} catch {
    Add-Result -Category "ATP - ASR Details" -Status "Error" `
        -Message "Failed to analyze ASR rules: $_" `
        -Severity "Medium"
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
            -Details "ATP/EDR: Device can receive and enforce custom IoCs from Microsoft 365 Defender" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } elseif ($indicatorEnabled -and $indicatorEnabled.TpAutoUpdateIndicators -eq 0) {
        Add-Result -Category "ATP - Custom Indicators" -Status "Warning" `
            -Message "Custom threat indicators auto-update is disabled" `
            -Details "ATP/EDR: Device will not receive custom IoCs" `
            -Remediation "Set-ItemProperty -Path '$indicatorPath' -Name TpAutoUpdateIndicators -Value 1 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - Custom Indicators" -Status "Info" `
            -Message "Custom indicator configuration not explicitly set" `
            -Details "ATP/EDR: Using default configuration (typically enabled)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - Custom Indicators" -Status "Error" `
        -Message "Failed to check custom indicator configuration: $_" `
        -Severity "Medium"
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
                -Details "ATP/EDR: Level 2 (Enhanced) or 3 (Full) required for Defender for Endpoint" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } elseif ($level -eq 1) {
            Add-Result -Category "ATP - Connectivity" -Status "Warning" `
                -Message "Diagnostic data level is Basic (Level: 1)" `
                -Details "ATP/EDR: Enhanced (2) or Full (3) recommended for optimal EDR functionality" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 2 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Connectivity" -Status "Fail" `
                -Message "Diagnostic data is disabled or security-only (Level: $level)" `
                -Details "ATP/EDR: Defender for Endpoint requires at least Basic telemetry" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 2 -Type DWord" `
                -Severity "High" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
    } else {
        Add-Result -Category "ATP - Connectivity" -Status "Info" `
            -Message "Diagnostic data level not configured via policy" `
            -Details "ATP/EDR: Using default Windows telemetry settings" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
    # Check cloud-delivered protection service connectivity
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        if ($mpStatus.AMServiceEnabled) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Antimalware service is enabled and running" `
                -Details "ATP/EDR: Core protection service is operational" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        if ($mpStatus.AntispywareEnabled) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Antispyware protection is enabled" `
                -Details "ATP/EDR: Spyware detection is active" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        if ($mpStatus.AntivirusEnabled) {
            Add-Result -Category "ATP - Connectivity" -Status "Pass" `
                -Message "Antivirus protection is enabled" `
                -Details "ATP/EDR: Virus detection is active" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
    }
    
} catch {
    Add-Result -Category "ATP - Connectivity" -Status "Error" `
        -Message "Failed to check cloud connectivity: $_" `
        -Severity "Medium"
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
                -Message "Average CPU load factor during scans: $($mpPreference.ScanAvgCPULoadFactor)`%" `
                -Details "ATP/EDR: Balanced performance during scans" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Info" `
                -Message "Average CPU load factor during scans: $($mpPreference.ScanAvgCPULoadFactor)`%" `
                -Details "ATP/EDR: High CPU usage may impact system performance" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check archive scanning
        if ($mpPreference.DisableArchiveScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Archive scanning is enabled" `
                -Details "ATP/EDR: ZIP, CAB, and other archives are scanned for threats" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Archive scanning is disabled" `
                -Details "ATP/EDR: Threats in compressed files may go undetected" `
                -Remediation "Set-MpPreference -DisableArchiveScanning `$false" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check email scanning
        if ($mpPreference.DisableEmailScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Email scanning is enabled" `
                -Details "ATP/EDR: Email files (PST, DBX) are scanned" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Email scanning is disabled" `
                -Details "ATP/EDR: Threats in email archives may go undetected" `
                -Remediation "Set-MpPreference -DisableEmailScanning `$false" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check removable drive scanning
        if ($mpPreference.DisableRemovableDriveScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Removable drive scanning is enabled" `
                -Details "ATP/EDR: USB and external drives are scanned" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Removable drive scanning is disabled" `
                -Details "ATP/EDR: Threats from removable media may not be detected" `
                -Remediation "Set-MpPreference -DisableRemovableDriveScanning `$false" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check script scanning
        if ($mpPreference.DisableScriptScanning -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Script scanning is enabled" `
                -Details "ATP/EDR: JavaScript, VBScript, and PowerShell scripts are scanned" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Fail" `
                -Message "Script scanning is DISABLED" `
                -Details "ATP/EDR: Critical - script-based attacks will not be detected" `
                -Remediation "Set-MpPreference -DisableScriptScanning `$false" `
                -Severity "High" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Check intrusion prevention system
        if ($mpPreference.DisableIntrusionPreventionSystem -eq $false) {
            Add-Result -Category "ATP - Scanning" -Status "Pass" `
                -Message "Network intrusion prevention system is enabled" `
                -Details "ATP/EDR: Network traffic inspection for known exploits" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Scanning" -Status "Warning" `
                -Message "Network intrusion prevention system is disabled" `
                -Details "ATP/EDR: Network-based exploit detection is disabled" `
                -Remediation "Set-MpPreference -DisableIntrusionPreventionSystem `$false" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
    }
    
} catch {
    Add-Result -Category "ATP - Scanning" -Status "Error" `
        -Message "Failed to check scanning capabilities: $_" `
        -Severity "Medium"
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
            -Details "ATP/EDR: Removable media and devices are managed by policy" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } elseif ($deviceControlPolicy -and $deviceControlPolicy.DeviceControlEnabled -eq 0) {
        Add-Result -Category "ATP - Device Control" -Status "Info" `
            -Message "Device Control is disabled" `
            -Details "ATP/EDR: No restrictions on removable media and peripheral devices" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - Device Control" -Status "Info" `
            -Message "Device Control policies not explicitly configured" `
            -Details "ATP/EDR: Device Control can restrict USB, printers, and other peripherals" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - Device Control" -Status "Error" `
        -Message "Failed to check Device Control: $_" `
        -Severity "Medium"
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
            -Details "ATP/EDR: Blocks access to websites based on content categories" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } elseif ($webFiltering -and $webFiltering.EnableWebContentFiltering -eq 0) {
        Add-Result -Category "ATP - Web Filtering" -Status "Info" `
            -Message "Web content filtering is disabled" `
            -Details "ATP/EDR: Web category-based blocking is not active" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - Web Filtering" -Status "Info" `
            -Message "Web content filtering not configured" `
            -Details "ATP/EDR: Can block adult content, legal liability, high bandwidth sites, etc." `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - Web Filtering" -Status "Error" `
        -Message "Failed to check web content filtering: $_" `
        -Severity "Medium"
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
            -Remediation "Remove or set to 0: HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DisableLiveResponse" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - Advanced Features" -Status "Pass" `
            -Message "Live Response is enabled or not restricted" `
            -Details "ATP/EDR: Allows remote investigation and remediation" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
    # Check sample collection
    $sampleCollection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "DisableSampleCollection" -ErrorAction SilentlyContinue
    
    if ($sampleCollection -and $sampleCollection.DisableSampleCollection -eq 1) {
        Add-Result -Category "ATP - Advanced Features" -Status "Warning" `
            -Message "Sample collection is disabled" `
            -Details "ATP/EDR: Cannot collect files for deep analysis" `
            -Remediation "Remove or set to 0: HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DisableSampleCollection" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    } else {
        Add-Result -Category "ATP - Advanced Features" -Status "Pass" `
            -Message "Sample collection is enabled or not restricted" `
            -Details "ATP/EDR: Suspicious files can be collected for analysis" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - Advanced Features" -Status "Error" `
        -Message "Failed to check advanced features: $_" `
        -Severity "Medium"
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
                -Details "ATP/EDR: DNS queries are inspected for malicious domains" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1' }
        }
        
        # Check custom block list
        $customBlockList = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Network Protection" -Name "CustomBlockList" -ErrorAction SilentlyContinue
        
        if ($customBlockList) {
            Add-Result -Category "ATP - Network Protection" -Status "Info" `
                -Message "Custom network block list is configured" `
                -Details "ATP/EDR: Additional domains/IPs are blocked beyond cloud intelligence" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1' }
        }
    }
    
} catch {
    Add-Result -Category "ATP - Network Protection" -Status "Error" `
        -Message "Failed to check advanced network protection: $_" `
        -Severity "Medium"
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
                    -Remediation "Enable via Microsoft 365 Defender portal or Windows Security" `
                    -Severity "High" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
            4 {
                Add-Result -Category "ATP - Tamper Protection" -Status "Warning" `
                    -Message "Tamper Protection is DISABLED" `
                    -Details "ATP/EDR: Protection against tampering is not active" `
                    -Remediation "Enable via Microsoft 365 Defender portal or Windows Security" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
            5 {
                Add-Result -Category "ATP - Tamper Protection" -Status "Pass" `
                    -Message "Tamper Protection is ON" `
                    -Details "ATP/EDR: Defender settings are protected from unauthorized changes" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
            default {
                Add-Result -Category "ATP - Tamper Protection" -Status "Info" `
                    -Message "Tamper Protection status: $tamperValue" `
                    -Details "ATP/EDR: Unusual tamper protection value detected" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
            }
        }
    } else {
        Add-Result -Category "ATP - Tamper Protection" -Status "Warning" `
            -Message "Tamper Protection status could not be determined" `
            -Details "ATP/EDR: Check Windows Security settings" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
    }
    
} catch {
    Add-Result -Category "ATP - Tamper Protection" -Status "Error" `
        -Message "Failed to check Tamper Protection: $_" `
        -Severity "Medium"
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
                -Details "ATP/EDR: Paths excluded from scanning = $($pathExclusions -join '; ')" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Exclusions" -Status "Pass" `
                -Message "No path exclusions configured" `
                -Details "ATP/EDR: All paths are scanned" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Process exclusions
        $processExclusions = $mpPreference.ExclusionProcess
        if ($processExclusions -and $processExclusions.Count -gt 0) {
            Add-Result -Category "ATP - Exclusions" -Status "Warning" `
                -Message "Process exclusions configured: $($processExclusions.Count)" `
                -Details "ATP/EDR: Processes excluded = $($processExclusions -join '; ')" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Exclusions" -Status "Pass" `
                -Message "No process exclusions configured" `
                -Details "ATP/EDR: All processes are monitored" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
        
        # Extension exclusions
        $extensionExclusions = $mpPreference.ExclusionExtension
        if ($extensionExclusions -and $extensionExclusions.Count -gt 0) {
            Add-Result -Category "ATP - Exclusions" -Status "Warning" `
                -Message "Extension exclusions configured: $($extensionExclusions.Count)" `
                -Details "ATP/EDR: File extensions excluded = $($extensionExclusions -join '; ')" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        } else {
            Add-Result -Category "ATP - Exclusions" -Status "Pass" `
                -Message "No extension exclusions configured" `
                -Details "ATP/EDR: All file types are scanned" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-4'; CIS='8.1' }
        }
    }
    
} catch {
    Add-Result -Category "ATP - Exclusions" -Status "Error" `
        -Message "Failed to audit exclusions: $_" `
        -Severity "Medium"
}


# ============================================================================
# v6.1: Defender Antivirus Component Currency
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Defender Component Currency..." -ForegroundColor Yellow

try {
    $mpStatus = Get-DefenderStatus -Cache $SharedData.Cache
    if ($mpStatus) {
        $sigAge = if ($null -ne $mpStatus.AntivirusSignatureAge) { [int]$mpStatus.AntivirusSignatureAge } else { -1 }
        if ($sigAge -ge 0 -and $sigAge -le 1) {
            Add-Result -Category "ATP - Component Currency" -Status "Pass" `
                -Severity "Low" `
                -Message "Antivirus signatures are current (age: $sigAge day(s))" `
                -Details "Signature freshness within recommended 24-48 hour window" `
                -CrossReferences @{ MS='Defender Signature Currency'; NIST='SI-3' }
        }
        elseif ($sigAge -le 7 -and $sigAge -gt 1) {
            Add-Result -Category "ATP - Component Currency" -Status "Warning" `
                -Severity "Medium" `
                -Message "Antivirus signatures are $sigAge days old" `
                -Details "Signatures should be updated daily; investigate update mechanism" `
                -Remediation "Update-MpSignature" `
                -CrossReferences @{ MS='Defender Signature Currency'; NIST='SI-3' }
        }
        elseif ($sigAge -gt 7) {
            Add-Result -Category "ATP - Component Currency" -Status "Fail" `
                -Severity "High" `
                -Message "Antivirus signatures are $sigAge days old" `
                -Details "Signatures more than 7 days old leave the host exposed to recent threats" `
                -Remediation "Update-MpSignature; verify Windows Update connectivity" `
                -CrossReferences @{ MS='Defender Signature Currency'; NIST='SI-3'; CIS='8.2' }
        }
        else {
            Add-Result -Category "ATP - Component Currency" -Status "Info" `
                -Severity "Informational" `
                -Message "Signature age unavailable" `
                -Details "Get-MpComputerStatus did not return AntivirusSignatureAge"
        }

        $engineVer = $mpStatus.AMEngineVersion
        if ($engineVer) {
            Add-Result -Category "ATP - Component Currency" -Status "Info" `
                -Severity "Informational" `
                -Message "Antimalware engine version: $engineVer" `
                -Details "Verify against the current published engine baseline at the Defender release notes"
        }

        $platformVer = $mpStatus.AMProductVersion
        if ($platformVer) {
            Add-Result -Category "ATP - Component Currency" -Status "Info" `
                -Severity "Informational" `
                -Message "Antimalware platform version: $platformVer" `
                -Details "Platform updates are delivered monthly through Windows Update"
        }

        $nisAge = if ($null -ne $mpStatus.NISSignatureAge) { [int]$mpStatus.NISSignatureAge } else { -1 }
        if ($nisAge -ge 0 -and $nisAge -le 7) {
            Add-Result -Category "ATP - Component Currency" -Status "Pass" `
                -Severity "Low" `
                -Message "Network Inspection System signatures current (age: $nisAge day(s))" `
                -CrossReferences @{ MS='NIS Currency' }
        }
        elseif ($nisAge -gt 7) {
            Add-Result -Category "ATP - Component Currency" -Status "Warning" `
                -Severity "Medium" `
                -Message "Network Inspection System signatures are $nisAge days old" `
                -Remediation "Update-MpSignature -UpdateSource MicrosoftUpdateServer" `
                -CrossReferences @{ MS='NIS Currency' }
        }
    }
    else {
        Add-Result -Category "ATP - Component Currency" -Status "Info" `
            -Severity "Informational" `
            -Message "Defender component currency not assessable" `
            -Details "Get-MpComputerStatus did not return data"
    }
}
catch {
    Add-Result -Category "ATP - Component Currency" -Status "Error" `
        -Severity "Medium" `
        -Message "Failed to query Defender component currency: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Network Protection per-profile state
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Network Protection per-profile state..." -ForegroundColor Yellow

try {
    $netProtPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
    $netProt = Get-RegValue -Path $netProtPath -Name "EnableNetworkProtection" -Default $null

    if ($netProt -eq 1) {
        Add-Result -Category "ATP - Network Protection" -Status "Pass" `
            -Severity "Medium" `
            -Message "Network Protection is enabled in block mode" `
            -Details "EnableNetworkProtection=1 blocks outbound connections to malicious domains" `
            -CrossReferences @{ MS='Network Protection'; NIST='SC-7'; CIS='10.5' }
    }
    elseif ($netProt -eq 2) {
        Add-Result -Category "ATP - Network Protection" -Status "Warning" `
            -Severity "Medium" `
            -Message "Network Protection is in audit mode" `
            -Details "Audit mode logs but does not block. Move to block mode after evaluation." `
            -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
            -CrossReferences @{ MS='Network Protection'; NIST='SC-7' }
    }
    else {
        Add-Result -Category "ATP - Network Protection" -Status "Fail" `
            -Severity "Medium" `
            -Message "Network Protection is not enabled" `
            -Details "Network Protection blocks connections to known-malicious domains and IPs" `
            -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
            -CrossReferences @{ MS='Network Protection'; NIST='SC-7'; CIS='10.5' }
    }
}
catch {
    Add-Result -Category "ATP - Network Protection" -Status "Error" `
        -Severity "Low" `
        -Message "Network Protection state query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Controlled Folder Access protected folders enumeration
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Controlled Folder Access configuration..." -ForegroundColor Yellow

try {
    $cfaPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
    $cfaState = Get-RegValue -Path $cfaPath -Name "EnableControlledFolderAccess" -Default $null

    switch ($cfaState) {
        1 {
            Add-Result -Category "ATP - Controlled Folder Access" -Status "Pass" `
                -Severity "Medium" `
                -Message "Controlled Folder Access is enabled in block mode" `
                -Details "Unauthorized applications cannot modify protected folders" `
                -CrossReferences @{ MS='CFA'; NIST='SI-7' }
        }
        2 {
            Add-Result -Category "ATP - Controlled Folder Access" -Status "Warning" `
                -Severity "Medium" `
                -Message "Controlled Folder Access is in audit mode" `
                -Details "Events are logged but writes are not blocked" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -CrossReferences @{ MS='CFA' }
        }
        3 {
            Add-Result -Category "ATP - Controlled Folder Access" -Status "Pass" `
                -Severity "Low" `
                -Message "Controlled Folder Access is in block-disk-modification-only mode" `
                -CrossReferences @{ MS='CFA' }
        }
        default {
            Add-Result -Category "ATP - Controlled Folder Access" -Status "Fail" `
                -Severity "Medium" `
                -Message "Controlled Folder Access is not enabled" `
                -Details "Ransomware-style writes to user folders are not restricted" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -CrossReferences @{ MS='CFA'; NIST='SI-7' }
        }
    }

    try {
        $protectedFolders = (Get-MpPreference -ErrorAction Stop).ControlledFolderAccessProtectedFolders
        $folderCount = if ($protectedFolders) { @($protectedFolders).Count } else { 0 }
        Add-Result -Category "ATP - Controlled Folder Access" -Status "Info" `
            -Severity "Informational" `
            -Message "Protected folders configured: $folderCount" `
            -Details "Default-protected folders are always covered; this count reflects custom additions"
    }
    catch { <# Expected: Get-MpPreference may not be available #> }

    try {
        $allowedApps = (Get-MpPreference -ErrorAction Stop).ControlledFolderAccessAllowedApplications
        $appCount = if ($allowedApps) { @($allowedApps).Count } else { 0 }
        Add-Result -Category "ATP - Controlled Folder Access" -Status "Info" `
            -Severity "Informational" `
            -Message "Allowed applications configured: $appCount" `
            -Details "Custom application allowlist for Controlled Folder Access"
    }
    catch { <# Expected: Get-MpPreference may not be available #> }
}
catch {
    Add-Result -Category "ATP - Controlled Folder Access" -Status "Error" `
        -Severity "Low" `
        -Message "CFA configuration query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: SmartScreen enhanced phishing protection
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Enhanced Phishing Protection..." -ForegroundColor Yellow

try {
    $eppPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
    $serviceEnabled = Get-RegValue -Path $eppPath -Name "ServiceEnabled" -Default $null
    $notifyMalicious = Get-RegValue -Path $eppPath -Name "NotifyMalicious" -Default $null
    $notifyPasswordReuse = Get-RegValue -Path $eppPath -Name "NotifyPasswordReuse" -Default $null
    $notifyUnsafeApp = Get-RegValue -Path $eppPath -Name "NotifyUnsafeApp" -Default $null

    if ($serviceEnabled -eq 1) {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Pass" `
            -Severity "Medium" `
            -Message "Enhanced Phishing Protection service is enabled" `
            -Details "Windows 11 22H2+ feature monitoring password entry on phishing sites" `
            -CrossReferences @{ MS='EPP'; NIST='AT-2' }
    }
    else {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Fail" `
            -Severity "Medium" `
            -Message "Enhanced Phishing Protection service is not enabled" `
            -Details "Available on Windows 11 22H2 and later. Earlier OS versions can ignore this finding." `
            -Remediation "Set-ItemProperty -Path '$eppPath' -Name 'ServiceEnabled' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='EPP' }
    }

    if ($notifyMalicious -eq 1) {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Pass" `
            -Severity "Low" `
            -Message "User notification on malicious password entry is enabled" `
            -CrossReferences @{ MS='EPP NotifyMalicious' }
    }
    else {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Warning" `
            -Severity "Low" `
            -Message "User notification on malicious password entry is disabled" `
            -Remediation "Set-ItemProperty -Path '$eppPath' -Name 'NotifyMalicious' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='EPP NotifyMalicious' }
    }

    if ($notifyPasswordReuse -eq 1) {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Pass" `
            -Severity "Low" `
            -Message "User notification on password reuse is enabled" `
            -CrossReferences @{ MS='EPP NotifyPasswordReuse' }
    }
    else {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Warning" `
            -Severity "Low" `
            -Message "User notification on password reuse is disabled" `
            -Remediation "Set-ItemProperty -Path '$eppPath' -Name 'NotifyPasswordReuse' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='EPP NotifyPasswordReuse' }
    }

    if ($notifyUnsafeApp -eq 1) {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Pass" `
            -Severity "Low" `
            -Message "User notification on unsafe app password storage is enabled" `
            -CrossReferences @{ MS='EPP NotifyUnsafeApp' }
    }
    else {
        Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Warning" `
            -Severity "Low" `
            -Message "User notification on unsafe app password storage is disabled" `
            -Remediation "Set-ItemProperty -Path '$eppPath' -Name 'NotifyUnsafeApp' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='EPP NotifyUnsafeApp' }
    }
}
catch {
    Add-Result -Category "ATP - Enhanced Phishing Protection" -Status "Error" `
        -Severity "Low" `
        -Message "Enhanced Phishing Protection query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Windows Defender Application Control (WDAC) policy enumeration
# ============================================================================
Write-Host "[MS-DefenderATP] Checking WDAC policy state..." -ForegroundColor Yellow

try {
    $ciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
    $ciDeployedPolicies = Get-ChildItem -Path $ciPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne "Default" }

    if ($ciDeployedPolicies -and @($ciDeployedPolicies).Count -gt 0) {
        $policyCount = @($ciDeployedPolicies).Count
        Add-Result -Category "ATP - Application Control" -Status "Pass" `
            -Severity "High" `
            -Message "WDAC policies deployed: $policyCount" `
            -Details "Multiple-policy WDAC active. Each policy GUID corresponds to a deployed policy file." `
            -CrossReferences @{ MS='WDAC'; NIST='CM-7'; CIS='2.3.10.5' }
    }
    else {
        Add-Result -Category "ATP - Application Control" -Status "Warning" `
            -Severity "Medium" `
            -Message "No WDAC multiple-policy deployments detected" `
            -Details "Single-policy or no WDAC. Modern WDAC supports multiple concurrent policies for greater flexibility." `
            -CrossReferences @{ MS='WDAC' }
    }

    try {
        $ciEvents = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 1 -ErrorAction Stop
        if ($ciEvents) {
            Add-Result -Category "ATP - Application Control" -Status "Pass" `
                -Severity "Low" `
                -Message "Code Integrity event log is active and recording" `
                -Details "WDAC enforcement and audit events are being captured" `
                -CrossReferences @{ MS='WDAC Logging' }
        }
    }
    catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        Add-Result -Category "ATP - Application Control" -Status "Warning" `
            -Severity "Low" `
            -Message "Code Integrity event log not found" `
            -Details "Microsoft-Windows-CodeIntegrity/Operational log unavailable on this system" `
            -CrossReferences @{ MS='WDAC Logging' }
    }
    catch { <# Expected: log may not exist on older OS versions #> }
}
catch {
    Add-Result -Category "ATP - Application Control" -Status "Error" `
        -Severity "Low" `
        -Message "WDAC policy enumeration failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Defender for Endpoint device tags and group assignment
# ============================================================================
Write-Host "[MS-DefenderATP] Checking device tags and group assignment..." -ForegroundColor Yellow

try {
    $tagPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"
    $deviceTag = Get-RegValue -Path $tagPath -Name "Group" -Default $null

    if ($deviceTag) {
        Add-Result -Category "ATP - Device Tagging" -Status "Pass" `
            -Severity "Low" `
            -Message "Device tag configured: $deviceTag" `
            -Details "Tags enable device grouping and dynamic targeting in the Defender portal" `
            -CrossReferences @{ MS='Device Tagging' }
    }
    else {
        Add-Result -Category "ATP - Device Tagging" -Status "Info" `
            -Severity "Informational" `
            -Message "No device tag configured at the local policy level" `
            -Details "Tags may be assigned via Intune or directly in the Defender portal" `
            -CrossReferences @{ MS='Device Tagging' }
    }
}
catch {
    Add-Result -Category "ATP - Device Tagging" -Status "Error" `
        -Severity "Low" `
        -Message "Device tag query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Defender for Identity sensor detection
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Defender for Identity sensor..." -ForegroundColor Yellow

try {
    $aatpService = Get-Service -Name "AATPSensor","AATPSensorUpdater" -ErrorAction SilentlyContinue
    if ($aatpService) {
        $running = @($aatpService | Where-Object { $_.Status -eq 'Running' }).Count
        Add-Result -Category "ATP - Defender for Identity" -Status "Pass" `
            -Severity "Medium" `
            -Message "Defender for Identity sensor present ($running of $($aatpService.Count) services running)" `
            -Details "AATP/MDI sensor monitors AD activity for identity-based threats" `
            -CrossReferences @{ MS='Defender for Identity'; NIST='AC-2' }
    }
    else {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs -and $cs.DomainRole -in @(4,5)) {
            Add-Result -Category "ATP - Defender for Identity" -Status "Warning" `
                -Severity "Medium" `
                -Message "Defender for Identity sensor not detected on domain controller" `
                -Details "MDI sensor recommended on all domain controllers for identity threat detection" `
                -CrossReferences @{ MS='Defender for Identity'; NIST='AU-12' }
        }
        else {
            Add-Result -Category "ATP - Defender for Identity" -Status "Info" `
                -Severity "Informational" `
                -Message "Defender for Identity sensor not present (non-DC host)" `
                -Details "MDI sensor is typically installed only on domain controllers and AD FS servers"
        }
    }
}
catch {
    Add-Result -Category "ATP - Defender for Identity" -Status "Error" `
        -Severity "Low" `
        -Message "Defender for Identity sensor query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Per-rule ASR audit/block mode detail
# ============================================================================
Write-Host "[MS-DefenderATP] Checking individual ASR rule states..." -ForegroundColor Yellow

$asrRules = @{
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email/webmail'
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office child process creation'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office executable content creation'
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office code injection'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JavaScript/VBScript downloaded executables'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block obfuscated script execution'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API from Office macros'
    '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'Block executables not meeting prevalence/age/trust'
    'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced ransomware protection'
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS'
    'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creation from PSExec/WMI commands'
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted USB processes'
    '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication child processes'
    '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader child process creation'
    'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
}

try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    $configuredIds = @($mpPref.AttackSurfaceReductionRules_Ids)
    $configuredActions = @($mpPref.AttackSurfaceReductionRules_Actions)

    $blockCount = 0; $auditCount = 0; $disabledCount = 0; $unsetCount = 0

    foreach ($ruleGuid in $asrRules.Keys) {
        $ruleName = $asrRules[$ruleGuid]
        $idx = -1
        for ($i = 0; $i -lt $configuredIds.Count; $i++) {
            if ($configuredIds[$i] -eq $ruleGuid) { $idx = $i; break }
        }

        if ($idx -lt 0) {
            $unsetCount++
            Add-Result -Category "ATP - ASR Per-Rule" -Status "Warning" `
                -Severity "Low" `
                -Message "ASR rule not configured: $ruleName" `
                -Details "Rule ID: $ruleGuid" `
                -Remediation "Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Enabled" `
                -CrossReferences @{ MS="ASR $ruleGuid" }
        }
        else {
            $action = $configuredActions[$idx]
            switch ($action) {
                1 {
                    $blockCount++
                    Add-Result -Category "ATP - ASR Per-Rule" -Status "Pass" `
                        -Severity "Low" `
                        -Message "ASR block: $ruleName" `
                        -Details "Rule actively blocking; ID: $ruleGuid" `
                        -CrossReferences @{ MS="ASR $ruleGuid" }
                }
                2 {
                    $auditCount++
                    Add-Result -Category "ATP - ASR Per-Rule" -Status "Warning" `
                        -Severity "Low" `
                        -Message "ASR audit-only: $ruleName" `
                        -Details "Rule logging without blocking; promote to block after evaluation. ID: $ruleGuid" `
                        -Remediation "Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Enabled" `
                        -CrossReferences @{ MS="ASR $ruleGuid" }
                }
                6 {
                    Add-Result -Category "ATP - ASR Per-Rule" -Status "Info" `
                        -Severity "Informational" `
                        -Message "ASR warn mode: $ruleName" `
                        -Details "User can override the block. ID: $ruleGuid" `
                        -CrossReferences @{ MS="ASR $ruleGuid" }
                }
                default {
                    $disabledCount++
                    Add-Result -Category "ATP - ASR Per-Rule" -Status "Fail" `
                        -Severity "Medium" `
                        -Message "ASR rule explicitly disabled: $ruleName" `
                        -Details "Action code: $action; ID: $ruleGuid" `
                        -Remediation "Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Enabled" `
                        -CrossReferences @{ MS="ASR $ruleGuid" }
                }
            }
        }
    }

    Add-Result -Category "ATP - ASR Per-Rule" -Status "Info" `
        -Severity "Informational" `
        -Message "ASR rule summary: $blockCount block, $auditCount audit, $disabledCount disabled, $unsetCount unset" `
        -Details "Total rules in catalog: $($asrRules.Count)"
}
catch {
    Add-Result -Category "ATP - ASR Per-Rule" -Status "Error" `
        -Severity "Medium" `
        -Message "Per-rule ASR enumeration failed: $($_.Exception.Message)" `
        -Details "Get-MpPreference may be unavailable or Defender may not be installed"
}

# ============================================================================
# v6.1: Defender for Endpoint Plan detection (P1 vs P2)
# ============================================================================
Write-Host "[MS-DefenderATP] Detecting Defender for Endpoint plan tier..." -ForegroundColor Yellow

try {
    $airReg = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
    $organizationId = Get-RegValue -Path $airReg -Name "OrgId" -Default $null

    if ($organizationId) {
        Add-Result -Category "ATP - Plan Detection" -Status "Pass" `
            -Severity "Low" `
            -Message "Tenant onboarded (OrgId present)" `
            -Details "Plan tier (P1 vs P2) is determined at tenant licensing level and not directly inspectable at the endpoint" `
            -CrossReferences @{ MS='MDE Onboarding' }

        $airServices = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
        if ($airServices -and $airServices.Status -eq 'Running') {
            Add-Result -Category "ATP - Plan Detection" -Status "Pass" `
                -Severity "Low" `
                -Message "Sense service running (P1 baseline minimum verified)" `
                -CrossReferences @{ MS='Sense Service' }
        }

        $tvmIndicator = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\ConfigurationManager" -Name "ConfigVersion" -Default $null
        if ($tvmIndicator) {
            Add-Result -Category "ATP - Plan Detection" -Status "Info" `
                -Severity "Informational" `
                -Message "Configuration management indicator present (suggests P2 capabilities)" `
                -Details "Config version: $tvmIndicator. P2 features include AIR, TVM, and Live Response."
        }
    }
    else {
        Add-Result -Category "ATP - Plan Detection" -Status "Info" `
            -Severity "Informational" `
            -Message "No Defender for Endpoint tenant onboarding detected" `
            -Details "OrgId registry value absent. Endpoint may use Defender Antivirus only."
    }
}
catch {
    Add-Result -Category "ATP - Plan Detection" -Status "Error" `
        -Severity "Low" `
        -Message "Plan tier detection failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Live Response capability verification
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Live Response capability..." -ForegroundColor Yellow

try {
    $lrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
    $lrEnabled = Get-RegValue -Path $lrPath -Name "LiveResponseEnabled" -Default $null
    $lrUnsignedScripts = Get-RegValue -Path $lrPath -Name "LiveResponseUnsignedScriptsEnabled" -Default $null

    if ($lrEnabled -eq 1) {
        Add-Result -Category "ATP - Live Response" -Status "Pass" `
            -Severity "Medium" `
            -Message "Live Response is enabled" `
            -Details "SOC analysts can establish remote shell sessions for incident investigation" `
            -CrossReferences @{ MS='Live Response'; NIST='IR-4' }
    }
    elseif ($lrEnabled -eq 0) {
        Add-Result -Category "ATP - Live Response" -Status "Warning" `
            -Severity "Medium" `
            -Message "Live Response is explicitly disabled" `
            -Details "Disabling Live Response limits incident response capability" `
            -Remediation "Set-ItemProperty -Path '$lrPath' -Name 'LiveResponseEnabled' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='Live Response'; NIST='IR-4' }
    }
    else {
        Add-Result -Category "ATP - Live Response" -Status "Info" `
            -Severity "Informational" `
            -Message "Live Response policy not configured locally" `
            -Details "Live Response setting may be controlled by tenant-level policy in the Defender portal"
    }

    if ($lrUnsignedScripts -eq 1) {
        Add-Result -Category "ATP - Live Response" -Status "Warning" `
            -Severity "Medium" `
            -Message "Unsigned Live Response scripts are permitted" `
            -Details "Allowing unsigned scripts increases risk if SOC credentials are compromised" `
            -Remediation "Set-ItemProperty -Path '$lrPath' -Name 'LiveResponseUnsignedScriptsEnabled' -Value 0 -Type DWord" `
            -CrossReferences @{ MS='Live Response Scripts' }
    }
    elseif ($lrUnsignedScripts -eq 0) {
        Add-Result -Category "ATP - Live Response" -Status "Pass" `
            -Severity "Low" `
            -Message "Unsigned Live Response scripts are restricted" `
            -CrossReferences @{ MS='Live Response Scripts' }
    }
}
catch {
    Add-Result -Category "ATP - Live Response" -Status "Error" `
        -Severity "Low" `
        -Message "Live Response query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Defender for Cloud Apps integration indicators
# ============================================================================
Write-Host "[MS-DefenderATP] Checking Defender for Cloud Apps integration..." -ForegroundColor Yellow

try {
    $mcasIndicators = @(
        "HKLM:\SOFTWARE\Microsoft\Cloud App Security",
        "HKLM:\SOFTWARE\Policies\Microsoft\Cloud App Security"
    )

    $mcasFound = $false
    foreach ($mcasPath in $mcasIndicators) {
        if (Test-Path $mcasPath -ErrorAction SilentlyContinue) {
            $mcasFound = $true
            break
        }
    }

    if ($mcasFound) {
        Add-Result -Category "ATP - Cloud Apps Integration" -Status "Pass" `
            -Severity "Low" `
            -Message "Defender for Cloud Apps integration indicators present" `
            -Details "Endpoint discovery integration with MDCA detected" `
            -CrossReferences @{ MS='MDCA Integration' }
    }
    else {
        Add-Result -Category "ATP - Cloud Apps Integration" -Status "Info" `
            -Severity "Informational" `
            -Message "Defender for Cloud Apps integration not detected at the endpoint" `
            -Details "MDCA integration is typically configured at the tenant level; absence does not indicate the feature is unused"
    }

    $samplePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
    $sampleSubmission = Get-RegValue -Path $samplePath -Name "AllowSampleCollection" -Default $null
    if ($sampleSubmission -eq 1) {
        Add-Result -Category "ATP - Cloud Apps Integration" -Status "Pass" `
            -Severity "Low" `
            -Message "Sample collection enabled (supports MDE/MDCA correlation)" `
            -CrossReferences @{ MS='Sample Collection' }
    }
    elseif ($sampleSubmission -eq 0) {
        Add-Result -Category "ATP - Cloud Apps Integration" -Status "Warning" `
            -Severity "Low" `
            -Message "Sample collection is disabled" `
            -Details "Sample collection enables cloud-based analysis of suspicious files" `
            -Remediation "Set-ItemProperty -Path '$samplePath' -Name 'AllowSampleCollection' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='Sample Collection' }
    }
}
catch {
    Add-Result -Category "ATP - Cloud Apps Integration" -Status "Error" `
        -Severity "Low" `
        -Message "Cloud Apps integration query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Custom IOC management state
# ============================================================================
Write-Host "[MS-DefenderATP] Checking custom IOC management..." -ForegroundColor Yellow

try {
    $ti = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TIIndicators"
    if (Test-Path $ti -ErrorAction SilentlyContinue) {
        $tiSubkeys = Get-ChildItem -Path $ti -ErrorAction SilentlyContinue
        $iocCount = if ($tiSubkeys) { @($tiSubkeys).Count } else { 0 }
        if ($iocCount -gt 0) {
            Add-Result -Category "ATP - Custom IOC Management" -Status "Pass" `
                -Severity "Low" `
                -Message "Custom threat indicators present: $iocCount" `
                -Details "Tenant-specific IOCs deployed to this endpoint" `
                -CrossReferences @{ MS='Custom IOCs'; NIST='SI-3' }
        }
        else {
            Add-Result -Category "ATP - Custom IOC Management" -Status "Info" `
                -Severity "Informational" `
                -Message "No custom IOCs deployed at the endpoint" `
                -Details "IOCs may be managed at the tenant level in the Defender portal"
        }
    }
    else {
        Add-Result -Category "ATP - Custom IOC Management" -Status "Info" `
            -Severity "Informational" `
            -Message "Custom IOC indicator registry path not present" `
            -Details "TIIndicators registry hive absent; tenant-level IOCs may still be active"
    }
}
catch {
    Add-Result -Category "ATP - Custom IOC Management" -Status "Error" `
        -Severity "Low" `
        -Message "Custom IOC query failed: $($_.Exception.Message)"
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

$categoryStats = @{}
foreach ($r in $results) {
    if (-not $categoryStats.ContainsKey($r.Category)) { $categoryStats[$r.Category] = 0 }
    $categoryStats[$r.Category]++
}

$severityStats = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
foreach ($r in ($results | Where-Object { $_.Status -eq "Fail" })) {
    $sev = if ($r.PSObject.Properties['Severity']) { $r.Severity } else { 'Medium' }
    if ($severityStats.ContainsKey($sev)) { $severityStats[$sev]++ }
}

Write-Host "`n[MS-DefenderATP] ======================================================================" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] MODULE COMPLETED -- v$moduleVersion" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] ======================================================================" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] Total Checks Executed: $totalChecks" -ForegroundColor White
Write-Host "[MS-DefenderATP]" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] Results Summary:" -ForegroundColor Cyan
$pctPass = if ($totalChecks -gt 0) { [Math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }
Write-Host "[MS-DefenderATP]   Passed:   $($passCount.ToString().PadLeft(3)) ($pctPass`%)" -ForegroundColor Green
Write-Host "[MS-DefenderATP]   Failed:   $($failCount.ToString().PadLeft(3))" -ForegroundColor Red
Write-Host "[MS-DefenderATP]   Warnings: $($warnCount.ToString().PadLeft(3))" -ForegroundColor Yellow
Write-Host "[MS-DefenderATP]   Info:     $($infoCount.ToString().PadLeft(3))" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP]   Errors:   $($errorCount.ToString().PadLeft(3))" -ForegroundColor Magenta
Write-Host "[MS-DefenderATP]" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] Check Categories:" -ForegroundColor Cyan
foreach ($cat in ($categoryStats.Keys | Sort-Object)) {
    Write-Host "[MS-DefenderATP]   $($cat.PadRight(45)): $($categoryStats[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
}
Write-Host "[MS-DefenderATP]" -ForegroundColor Cyan
Write-Host "[MS-DefenderATP] Failed Check Severity:" -ForegroundColor Cyan
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
    $sevColor = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; 'Low' { 'Cyan' }; default { 'Gray' } }
    Write-Host "[MS-DefenderATP]   $($sev.PadRight(15)): $($severityStats[$sev])" -ForegroundColor $sevColor
}
Write-Host "[MS-DefenderATP] ======================================================================`n" -ForegroundColor Cyan

return $results

# ============================================================================
# Standalone Execution Support
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host "  Microsoft Defender for Endpoint (ATP) -- Standalone Test v$moduleVersion" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor White

    $standaloneData = @{
        ComputerName = $env:COMPUTERNAME; OSVersion = ''; IPAddresses = @()
        ScanDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath = $PSScriptRoot; Cache = $null
    }
    try { $osi = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue; $standaloneData.OSVersion = "$($osi.Caption) (Build $($osi.BuildNumber))" } catch { $standaloneData.OSVersion = "Windows" }
    try { $standaloneData.IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress) } catch { $standaloneData.IPAddresses = @("N/A") }

    $commonLibPath = Join-Path (Split-Path $PSScriptRoot -Parent) "shared_components\audit-common.ps1"
    if (Test-Path $commonLibPath) {
        try { . $commonLibPath; $sc = New-SharedDataCache -OSInfo (Get-OSInfo); Invoke-CacheWarmUp -Cache $sc; $standaloneData.Cache = $sc; Write-Host "  Cache: Enabled" -ForegroundColor Green } catch { Write-Host "  Cache: Not available" -ForegroundColor Yellow }
    }

    Write-Host "  Hostname: $($standaloneData.ComputerName) | OS: $($standaloneData.OSVersion) | Admin: $($standaloneData.IsAdmin)" -ForegroundColor Gray
    Write-Host "=" * 80 -ForegroundColor White

    Write-Host "`n  Status Distribution:" -ForegroundColor White
    foreach ($st in @("Pass","Fail","Warning","Info","Error")) {
        $c = @($results | Where-Object { $_.Status -eq $st }).Count
        if ($c -gt 0) { $p = [Math]::Round(($c/$results.Count)*100,1); $b = "#"*[Math]::Floor($p/2); $cl = switch($st){"Pass"{"Green"};"Fail"{"Red"};"Warning"{"Yellow"};"Info"{"Cyan"};default{"Magenta"}}; Write-Host "    $($st.PadRight(8)): $($c.ToString().PadLeft(3)) `($($p.ToString().PadLeft(5))`%`) $b" -ForegroundColor $cl }
    }

    Write-Host "`n  Category Coverage:" -ForegroundColor White
    $cc = @{}; foreach ($r in $results) { if (-not $cc.ContainsKey($r.Category)) { $cc[$r.Category] = 0 }; $cc[$r.Category]++ }
    foreach ($k in ($cc.Keys | Sort-Object)) { Write-Host "    $($k.PadRight(45)): $($cc[$k].ToString().PadLeft(3))" -ForegroundColor Gray }

    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  MS-DefenderATP module standalone test complete -- $($results.Count) checks" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
