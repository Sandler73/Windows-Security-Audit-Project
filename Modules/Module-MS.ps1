# Module-MS.ps1
# Microsoft Security Baseline Compliance Module
# Version: 6.1.2 - Comprehensive Edition
# Based on Microsoft Security Compliance Toolkit and Security Baselines

<#
.SYNOPSIS
    Comprehensive Microsoft Security Baseline compliance checks.

.DESCRIPTION
    This module performs exhaustive checks aligned with Microsoft Security Baselines including:
    
    DEFENDER & PROTECTION:
    - Windows Defender Antivirus (real-time, cloud, PUA, scanning)
    - Exploit Protection (DEP, SEHOP, ASLR, CFG)
    - Attack Surface Reduction (ASR) rules
    - Network Protection
    - Controlled Folder Access (Ransomware Protection)
    - Microsoft Defender SmartScreen
    - Microsoft Defender Application Guard
    - Microsoft Defender for Endpoint integration
    
    DEVICE SECURITY:
    - Device Guard / Windows Defender Application Control (WDAC)
    - Credential Guard
    - Hypervisor-protected Code Integrity (HVCI)
    - Virtualization-based Security (VBS)
    - Secure Boot
    - TPM (Trusted Platform Module)
    - BitLocker Drive Encryption
    
    ACCESS CONTROL:
    - Windows Hello for Business
    - Credential protection mechanisms
    - LSASS protection
    - WDigest credential caching
    - Cached logon limits
    - User Account Control (UAC)
    - Local Administrator protection
    
    APPLICATION CONTROL:
    - AppLocker policies
    - Code Integrity policies
    - Windows Defender Application Control
    - PowerShell security (v2, Script Block Logging, Transcription, Constrained Language Mode)
    
    NETWORK SECURITY:
    - Windows Firewall (all profiles)
    - SMB security (SMBv1, signing, encryption)
    - LLMNR and NetBIOS over TCP/IP
    - NTLM authentication settings
    - LDAP signing and channel binding
    - DNS client security
    - Network authentication protocols
    
    REMOTE ACCESS:
    - Remote Desktop Protocol (RDP) security
    - Network Level Authentication (NLA)
    - RDP encryption levels
    - Windows Remote Management (WinRM)
    - Remote Assistance
    
    SYSTEM HARDENING:
    - Windows Update configuration
    - Local Security Policies
    - Audit policies (Advanced Audit Policy Configuration)
    - Event Log settings and retention
    - Anonymous access restrictions
    - Services security configuration
    - Registry permissions on critical keys
    - File system permissions on system folders
    
    MICROSOFT APPLICATIONS:
    - Microsoft Edge security policies
    - Microsoft Office security settings
    - Microsoft Store policies
    
    LEGACY PROTOCOLS & FEATURES:
    - Outdated protocol status (SSL/TLS versions)
    - Legacy authentication methods
    - Deprecated Windows features
    - Print Spooler service (PrintNightmare)
    - Windows Script Host restrictions

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName: System hostname
    - OSVersion: Operating system version
    - IsAdmin: Administrator privilege status
    - ScanDate: Audit timestamp
    - RemediateIssues: Remediation flag

.NOTES
    Version: 6.1.2 - Comprehensive Edition
    Based on: 
    - Microsoft Security Compliance Toolkit (SCT)
    - Microsoft Security Baselines (Windows 10/11, Server 2016/2019/2022)
    - Windows Security Baselines (latest releases)
    - Microsoft Defender for Endpoint recommendations
    - Azure Security Benchmark for Windows
    
    Requires: 
    - Windows 10/11 or Windows Server 2016+
    - PowerShell 5.1+
    - Administrator privileges (for complete results)
    
    References:
    - https://www.microsoft.com/en-us/download/details.aspx?id=55319
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/
    - https://learn.microsoft.com/en-us/defender-endpoint/
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "MS"
$results = @()
$moduleVersion = "6.1.2"

# Helper function to add results with consistent formatting
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

Write-Host "`n[MS] Starting Microsoft Security Baseline checks..." -ForegroundColor Cyan

# ============================================================================
# SECTION 1: WINDOWS DEFENDER ANTIVIRUS
# ============================================================================
Write-Host "[MS] Checking Windows Defender Antivirus Configuration..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    
    # Real-time protection
    if ($mpStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Real-time protection is enabled" `
            -Details "MS Baseline: Real-time scanning provides continuous protection against malware" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Real-time protection is DISABLED" `
            -Details "MS Baseline: Critical security feature disabled - system is vulnerable" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Behavior monitoring
    if ($mpStatus.BehaviorMonitorEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Behavior monitoring is enabled" `
            -Details "MS Baseline: Detects malicious behavior patterns and anomalous activities" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Behavior monitoring is disabled" `
            -Details "MS Baseline: Disables heuristic detection capabilities" `
            -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # IOAV (IE/Outlook/Attachments) protection
    if ($mpStatus.IoavProtectionEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "IOAV protection (downloaded files and attachments) is enabled" `
            -Details "MS Baseline: Scans downloads and email attachments before opening" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "IOAV protection is disabled" `
            -Details "MS Baseline: Downloaded files and attachments are not scanned" `
            -Remediation "Set-MpPreference -DisableIOAVProtection `$false" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # On-access protection
    if ($mpStatus.OnAccessProtectionEnabled) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "On-access protection is enabled" `
            -Details "MS Baseline: Files are scanned when accessed, preventing execution of malware" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "On-access protection is disabled" `
            -Details "MS Baseline: Files are not scanned when accessed" `
            -Remediation "Set-MpPreference -DisableOnAccessProtection `$false" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Cloud-delivered protection (MAPS)
    if ($mpStatus.MAPSReporting -gt 0) {
        $mapsLevel = switch ($mpStatus.MAPSReporting) {
            1 { "Basic" }
            2 { "Advanced" }
            default { "Unknown" }
        }
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Cloud-delivered protection is enabled (Level: $mapsLevel)" `
            -Details "MS Baseline: Cloud protection provides rapid threat response and zero-day protection" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Cloud-delivered protection is disabled" `
            -Details "MS Baseline: System lacks cloud-based threat intelligence" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Automatic sample submission
    if ($mpPreference.SubmitSamplesConsent -eq 1 -or $mpPreference.SubmitSamplesConsent -eq 3) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Automatic sample submission is enabled" `
            -Details "MS Baseline: Helps Microsoft identify and respond to new threats" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "Automatic sample submission is not fully enabled" `
            -Details "MS Baseline: Consider enabling to improve threat intelligence" `
            -Remediation "Set-MpPreference -SubmitSamplesConsent SendSafeSamples" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # PUA (Potentially Unwanted Applications) protection
    if ($mpPreference.PUAProtection -eq 1) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "PUA (Potentially Unwanted Applications) protection is enabled" `
            -Details "MS Baseline: Blocks potentially unwanted software like adware and bundleware" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } elseif ($mpPreference.PUAProtection -eq 2) {
        Add-Result -Category "MS - Defender AV" -Status "Info" `
            -Message "PUA protection is in audit mode" `
            -Details "MS Baseline: Consider enabling block mode for active protection" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "PUA protection is disabled" `
            -Details "MS Baseline: System vulnerable to potentially unwanted applications" `
            -Remediation "Set-MpPreference -PUAProtection Enabled" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Check signature update age
    $signatureAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
    if ($signatureAge.Days -eq 0) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Antivirus signatures were updated today" `
            -Details "MS Baseline: Signatures are current (updated: $($mpStatus.AntivirusSignatureLastUpdated))" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } elseif ($signatureAge.Days -le 3) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Antivirus signatures are $($signatureAge.Days) day(s) old" `
            -Details "MS Baseline: Signatures are reasonably current" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } elseif ($signatureAge.Days -le 7) {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "Antivirus signatures are $($signatureAge.Days) days old" `
            -Details "MS Baseline: Update signatures more frequently for better protection" `
            -Remediation "Update-MpSignature" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Fail" `
            -Message "Antivirus signatures are severely outdated `($($signatureAge.Days) days old)" `
            -Details "MS Baseline: Critical - outdated signatures leave system vulnerable" `
            -Remediation "Update-MpSignature" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Scan frequency
    if ($mpStatus.QuickScanAge -le 7) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Quick scan performed within the last 7 days" `
            -Details "MS Baseline: Regular scanning is occurring (last scan: $($mpStatus.QuickScanAge) days ago)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Warning" `
            -Message "Last quick scan was $($mpStatus.QuickScanAge) days ago" `
            -Details "MS Baseline: Schedule regular scans to detect dormant threats" `
            -Remediation "Start-MpScan -ScanType QuickScan" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Full scan age
    if ($mpStatus.FullScanAge -le 30) {
        Add-Result -Category "MS - Defender AV" -Status "Pass" `
            -Message "Full scan performed within the last 30 days" `
            -Details "MS Baseline: Comprehensive scan completed recently `($($mpStatus.FullScanAge) days ago)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    } else {
        Add-Result -Category "MS - Defender AV" -Status "Info" `
            -Message "Last full scan was $($mpStatus.FullScanAge) days ago" `
            -Details "MS Baseline: Consider scheduling monthly full scans" `
            -Remediation "Start-MpScan -ScanType FullScan" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
    # Tamper Protection
    try {
        $tamperProtection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        if ($tamperProtection -and $tamperProtection.TamperProtection -eq 5) {
            Add-Result -Category "MS - Defender AV" -Status "Pass" `
                -Message "Tamper Protection is enabled" `
                -Details "MS Baseline: Prevents malicious apps from changing security settings" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
        } else {
            Add-Result -Category "MS - Defender AV" -Status "Warning" `
                -Message "Tamper Protection may not be enabled" `
                -Details "MS Baseline: Enable via Windows Security or Intune to protect Defender settings" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
        }
    } catch {
        Add-Result -Category "MS - Defender AV" -Status "Info" `
            -Message "Could not verify Tamper Protection status" `
            -Details "MS Baseline: Check via Windows Security `> Virus & threat protection settings" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='8.1'; STIG='V-220916' }
    }
    
} catch {
    Add-Result -Category "MS - Defender AV" -Status "Error" `
        -Message "Failed to check Windows Defender Antivirus: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 2: EXPLOIT PROTECTION (EMET REPLACEMENT)
# ============================================================================
Write-Host "[MS] Checking Exploit Protection Configuration..." -ForegroundColor Yellow

try {
    $exploitProtection = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    
    if ($exploitProtection) {
        # DEP (Data Execution Prevention)
        if ($exploitProtection.DEP.Enable -eq "ON" -or $exploitProtection.DEP.Enable -eq "NOTSET") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "Data Execution Prevention (DEP) is enabled" `
                -Details "MS Baseline: DEP prevents code execution in data-only memory pages" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        } else {
            Add-Result -Category "MS - Exploit Protection" -Status "Warning" `
                -Message "DEP may not be optimally configured" `
                -Details "MS Baseline: Ensure DEP is enabled system-wide for exploit mitigation" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        # SEHOP (Structured Exception Handler Overwrite Protection)
        if ($exploitProtection.SEHOP.Enable -eq "ON" -or $exploitProtection.SEHOP.Enable -eq "NOTSET") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "SEHOP (Structured Exception Handler Overwrite Protection) is enabled" `
                -Details "MS Baseline: Protects against SEH overwrites, a common exploitation technique" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        # ASLR (Address Space Layout Randomization)
        if ($exploitProtection.ASLR.ForceRelocateImages -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "ASLR Force Relocate Images is enabled" `
                -Details "MS Baseline: Randomizes memory addresses to prevent memory corruption exploits" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        # Bottom-up ASLR
        if ($exploitProtection.ASLR.BottomUp -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "Bottom-up ASLR is enabled" `
                -Details "MS Baseline: Randomizes bottom-up memory allocations" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        # High Entropy ASLR
        if ($exploitProtection.ASLR.HighEntropy -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "High Entropy ASLR is enabled" `
                -Details "MS Baseline: Provides 64-bit ASLR for enhanced randomization" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        # Control Flow Guard
        if ($exploitProtection.CFG.Enable -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "Control Flow Guard (CFG) is enabled" `
                -Details "MS Baseline: Protects against control flow hijacking attacks" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        } else {
            Add-Result -Category "MS - Exploit Protection" -Status "Info" `
                -Message "Control Flow Guard is not universally enabled" `
                -Details "MS Baseline: CFG provides additional exploit mitigation for compatible applications" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        # Mandatory ASLR
        if ($exploitProtection.ASLR.ForceRelocateImages -eq "ON") {
            Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
                -Message "Mandatory ASLR is configured" `
                -Details "MS Baseline: Forces ASLR even for images not compiled with /DYNAMICBASE" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        }
        
        Add-Result -Category "MS - Exploit Protection" -Status "Pass" `
            -Message "Exploit Protection settings are configured" `
            -Details "MS Baseline: System-wide exploit mitigations are in place" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
    } else {
        Add-Result -Category "MS - Exploit Protection" -Status "Warning" `
            -Message "Could not verify Exploit Protection configuration" `
            -Details "MS Baseline: Ensure exploit mitigations are enabled via Windows Security" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
    }
} catch {
    Add-Result -Category "MS - Exploit Protection" -Status "Error" `
        -Message "Failed to check Exploit Protection: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 3: ATTACK SURFACE REDUCTION (ASR) RULES
# ============================================================================
Write-Host "[MS] Checking Attack Surface Reduction Rules..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $asrRuleIds = $mpPreference.AttackSurfaceReductionRules_Ids
    $asrRuleActions = $mpPreference.AttackSurfaceReductionRules_Actions
    
    if ($asrRuleIds -and $asrRuleIds.Count -gt 0) {
        $enabledCount = ($asrRuleActions | Where-Object { $_ -eq 1 }).Count
        $auditCount = ($asrRuleActions | Where-Object { $_ -eq 2 }).Count
        $disabledCount = ($asrRuleActions | Where-Object { $_ -eq 0 }).Count
        
        Add-Result -Category "MS - ASR" -Status "Pass" `
            -Message "Attack Surface Reduction rules are configured `($($asrRuleIds.Count) rules)" `
            -Details "MS Baseline: ASR reduces attack vectors. Enabled: $enabledCount, Audit: $auditCount, Disabled: $disabledCount" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        
        # Recommended ASR rules per Microsoft baseline
        $recommendedRules = @{
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
        }
        
        $configuredRecommended = 0
        foreach ($ruleId in $asrRuleIds) {
            if ($recommendedRules.ContainsKey($ruleId)) {
                $configuredRecommended++
            }
        }
        
        if ($configuredRecommended -ge 10) {
            Add-Result -Category "MS - ASR" -Status "Pass" `
                -Message "Most recommended ASR rules are configured ($configuredRecommended of $($recommendedRules.Count))" `
                -Details "MS Baseline: Comprehensive ASR rule coverage provides strong attack mitigation" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        } elseif ($configuredRecommended -ge 5) {
            Add-Result -Category "MS - ASR" -Status "Warning" `
                -Message "Some recommended ASR rules are configured ($configuredRecommended of $($recommendedRules.Count))" `
                -Details "MS Baseline: Consider enabling additional recommended rules for better protection" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        } else {
            Add-Result -Category "MS - ASR" -Status "Warning" `
                -Message "Few recommended ASR rules are configured ($configuredRecommended of $($recommendedRules.Count))" `
                -Details "MS Baseline: Enable recommended ASR rules to reduce attack surface" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
        }
        
    } else {
        Add-Result -Category "MS - ASR" -Status "Warning" `
            -Message "No Attack Surface Reduction rules are configured" `
            -Details "MS Baseline: ASR rules provide critical protection against modern attack techniques" `
            -Remediation "Add-MpPreference -AttackSurfaceReductionRules_Ids 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' -AttackSurfaceReductionRules_Actions Enabled" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; NSA='Attack Surface Reduction' }
    }
    
} catch {
    Add-Result -Category "MS - ASR" -Status "Error" `
        -Message "Failed to check ASR rules: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 4: NETWORK PROTECTION
# ============================================================================
Write-Host "[MS] Checking Network Protection..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $networkProtection = $mpPreference.EnableNetworkProtection
    
    switch ($networkProtection) {
        0 {
            Add-Result -Category "MS - Network Protection" -Status "Fail" `
                -Message "Network Protection is disabled" `
                -Details "MS Baseline: System lacks protection against malicious network connections" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1' }
        }
        1 {
            Add-Result -Category "MS - Network Protection" -Status "Pass" `
                -Message "Network Protection is enabled (Block mode)" `
                -Details "MS Baseline: Blocks connections to malicious domains and IPs via SmartScreen" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1' }
        }
        2 {
            Add-Result -Category "MS - Network Protection" -Status "Warning" `
                -Message "Network Protection is in Audit mode" `
                -Details "MS Baseline: Threats are logged but not blocked - enable Block mode" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1' }
        }
        default {
            Add-Result -Category "MS - Network Protection" -Status "Warning" `
                -Message "Network Protection status is unknown" `
                -Details "MS Baseline: Verify Network Protection configuration" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1' }
        }
    }
    
} catch {
    Add-Result -Category "MS - Network Protection" -Status "Error" `
        -Message "Failed to check Network Protection: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 5: CONTROLLED FOLDER ACCESS (RANSOMWARE PROTECTION)
# ============================================================================
Write-Host "[MS] Checking Controlled Folder Access..." -ForegroundColor Yellow

try {
    $mpPreference = Get-MpPreference -ErrorAction Stop
    
    $controlledFolderAccess = $mpPreference.EnableControlledFolderAccess
    
    switch ($controlledFolderAccess) {
        0 {
            Add-Result -Category "MS - Ransomware Protection" -Status "Warning" `
                -Message "Controlled Folder Access is disabled" `
                -Details "MS Baseline: Important folders are not protected from ransomware" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-28'; CIS='8.1' }
        }
        1 {
            Add-Result -Category "MS - Ransomware Protection" -Status "Pass" `
                -Message "Controlled Folder Access is enabled (Block mode)" `
                -Details "MS Baseline: Protected folders are guarded against unauthorized changes by untrusted apps" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-28'; CIS='8.1' }
            
            # List protected folders
            $protectedFolders = $mpPreference.ControlledFolderAccessProtectedFolders
            if ($protectedFolders) {
                Add-Result -Category "MS - Ransomware Protection" -Status "Info" `
                    -Message "Custom protected folders configured: $($protectedFolders.Count)" `
                    -Details "MS Baseline: Additional folders beyond defaults are protected: $($protectedFolders -join ', ')" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-28'; CIS='8.1' }
            }
            
            # List allowed applications
            $allowedApps = $mpPreference.ControlledFolderAccessAllowedApplications
            if ($allowedApps) {
                Add-Result -Category "MS - Ransomware Protection" -Status "Info" `
                    -Message "Allowed applications for Controlled Folder Access: $($allowedApps.Count)" `
                    -Details "MS Baseline: Trusted apps with folder access: $($allowedApps -join ', ')" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-28'; CIS='8.1' }
            }
        }
        2 {
            Add-Result -Category "MS - Ransomware Protection" -Status "Info" `
                -Message "Controlled Folder Access is in Audit mode" `
                -Details "MS Baseline: Events are logged but not blocked - consider enabling Block mode" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-28'; CIS='8.1' }
        }
        default {
            Add-Result -Category "MS - Ransomware Protection" -Status "Warning" `
                -Message "Controlled Folder Access status is unknown" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-28'; CIS='8.1' }
        }
    }
    
} catch {
    Add-Result -Category "MS - Ransomware Protection" -Status "Error" `
        -Message "Failed to check Controlled Folder Access: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 6: SMARTSCREEN CONFIGURATION
# ============================================================================
Write-Host "[MS] Checking SmartScreen Configuration..." -ForegroundColor Yellow

# Windows Defender SmartScreen for apps and files
try {
    $smartScreenEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    
    if ($smartScreenEnabled) {
        $value = $smartScreenEnabled.SmartScreenEnabled
        
        switch ($value) {
            "Off" {
                Add-Result -Category "MS - SmartScreen" -Status "Fail" `
                    -Message "Windows SmartScreen is disabled" `
                    -Details "MS Baseline: System lacks protection against malicious downloads and applications" `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value 'Warn'" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
            }
            "Warn" {
                Add-Result -Category "MS - SmartScreen" -Status "Pass" `
                    -Message "Windows SmartScreen is enabled (Warn mode)" `
                    -Details "MS Baseline: Users are warned about unrecognized apps before running" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
            }
            "RequireAdmin" {
                Add-Result -Category "MS - SmartScreen" -Status "Pass" `
                    -Message "Windows SmartScreen is enabled (Require Admin mode)" `
                    -Details "MS Baseline: Admin approval required for unrecognized apps - strongest protection" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
            }
            default {
                Add-Result -Category "MS - SmartScreen" -Status "Info" `
                    -Message "Windows SmartScreen configuration: $value" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
            }
        }
    }
} catch {
    Add-Result -Category "MS - SmartScreen" -Status "Error" `
        -Message "Failed to check SmartScreen: $_" `
        -Severity "Medium"
}

# SmartScreen for Microsoft Edge
try {
    $edgeSmartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    
    if ($edgeSmartScreen -and $edgeSmartScreen.SmartScreenEnabled -eq 1) {
        Add-Result -Category "MS - SmartScreen" -Status "Pass" `
            -Message "Microsoft Edge SmartScreen is enabled" `
            -Details "MS Baseline: Web-based threat protection is active in Edge browser" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
    } elseif ($edgeSmartScreen -and $edgeSmartScreen.SmartScreenEnabled -eq 0) {
        Add-Result -Category "MS - SmartScreen" -Status "Warning" `
            -Message "Microsoft Edge SmartScreen is disabled" `
            -Details "MS Baseline: Edge lacks protection against phishing and malicious websites" `
            -Remediation "Configure via Group Policy: Computer Configuration `> Administrative Templates `> Microsoft Edge `> SmartScreen settings" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
    } else {
        Add-Result -Category "MS - SmartScreen" -Status "Info" `
            -Message "Microsoft Edge SmartScreen policy not configured (using default)" `
            -Details "MS Baseline: SmartScreen is enabled by default in Edge unless explicitly disabled" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
    }
    
    # SmartScreen for potentially unwanted apps in Edge
    $edgePUA = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -ErrorAction SilentlyContinue
    
    if ($edgePUA -and $edgePUA.SmartScreenPuaEnabled -eq 1) {
        Add-Result -Category "MS - SmartScreen" -Status "Pass" `
            -Message "Edge SmartScreen PUA blocking is enabled" `
            -Details "MS Baseline: Blocks potentially unwanted applications in downloads" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-3'; CIS='18.9.85' }
    }
    
} catch {
    # Edge may not be installed or configured via policy
}

# ============================================================================
# SECTION 7: DEVICE GUARD / WDAC (WINDOWS DEFENDER APPLICATION CONTROL)
# ============================================================================
Write-Host "[MS] Checking Device Guard and Application Control..." -ForegroundColor Yellow

try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        # Check if virtualization-based security is available
        $vbsStatus = $deviceGuard.VirtualizationBasedSecurityStatus
        
        switch ($vbsStatus) {
            0 {
                Add-Result -Category "MS - Device Guard" -Status "Info" `
                    -Message "Virtualization-based security (VBS) is not enabled" `
                    -Details "MS Baseline: VBS requires UEFI, Secure Boot, and compatible hardware (TPM 2.0, CPU virtualization)" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
            }
            1 {
                Add-Result -Category "MS - Device Guard" -Status "Pass" `
                    -Message "Virtualization-based security is enabled but not running" `
                    -Details "MS Baseline: VBS is configured but may require system restart" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
            }
            2 {
                Add-Result -Category "MS - Device Guard" -Status "Pass" `
                    -Message "Virtualization-based security is enabled and running" `
                    -Details "MS Baseline: Hardware-based security isolation is active for critical system components" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
            }
        }
        
        # Check Credential Guard
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "MS - Device Guard" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "MS Baseline: Domain credentials are protected in virtualized container, preventing Pass-the-Hash attacks" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        } else {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "Credential Guard is not running" `
                -Details "MS Baseline: Enable on domain-joined systems for credential protection (requires VBS)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        }
        
        # Check HVCI (Hypervisor-protected Code Integrity)
        if ($deviceGuard.SecurityServicesRunning -contains 2) {
            Add-Result -Category "MS - Device Guard" -Status "Pass" `
                -Message "Hypervisor-protected Code Integrity (HVCI) is running" `
                -Details "MS Baseline: Kernel-mode code integrity is enforced by hypervisor, preventing kernel exploits" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        } else {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "HVCI is not running" `
                -Details "MS Baseline: Memory Integrity provides kernel-mode code integrity protection (requires VBS)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        }
        
        # Check Code Integrity Policy
        $ciPolicy = $deviceGuard.CodeIntegrityPolicyEnforcementStatus
        
        switch ($ciPolicy) {
            0 {
                Add-Result -Category "MS - Device Guard" -Status "Info" `
                    -Message "Code Integrity Policy is not enforced" `
                    -Details "MS Baseline: WDAC/Device Guard application control not configured" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
            }
            1 {
                Add-Result -Category "MS - Device Guard" -Status "Pass" `
                    -Message "Code Integrity Policy is enforced" `
                    -Details "MS Baseline: Application whitelisting via WDAC is active - only approved software can run" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
            }
            2 {
                Add-Result -Category "MS - Device Guard" -Status "Info" `
                    -Message "Code Integrity Policy is in audit mode" `
                    -Details "MS Baseline: WDAC is monitoring but not blocking unauthorized applications" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
            }
        }
        
        # Check Secure Boot requirement
        if ($deviceGuard.SecureBootRequired) {
            Add-Result -Category "MS - Device Guard" -Status "Pass" `
                -Message "Secure Boot is required by Device Guard configuration" `
                -Details "MS Baseline: Boot integrity is enforced via UEFI Secure Boot" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        }
        
        # Check available security properties
        if ($deviceGuard.AvailableSecurityProperties -contains 1) {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "Hardware security: Base virtualization support available" `
                -Details "MS Baseline: System supports hardware-based security features" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        }
        
        if ($deviceGuard.AvailableSecurityProperties -contains 2) {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "Hardware security: Secure Boot available" `
                -Details "MS Baseline: UEFI Secure Boot is supported" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        }
        
        if ($deviceGuard.AvailableSecurityProperties -contains 3) {
            Add-Result -Category "MS - Device Guard" -Status "Info" `
                -Message "Hardware security: DMA Protection available" `
                -Details "MS Baseline: Kernel DMA Protection prevents DMA attacks" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        }
        
    } else {
        Add-Result -Category "MS - Device Guard" -Status "Info" `
            -Message "Device Guard information not available" `
            -Details "MS Baseline: May require specific hardware/firmware support (UEFI, TPM 2.0, CPU virtualization)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
    }
    
} catch {
    Add-Result -Category "MS - Device Guard" -Status "Error" `
        -Message "Failed to check Device Guard: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 8: CREDENTIAL PROTECTION
# ============================================================================
Write-Host "[MS] Checking Credential Protection Settings..." -ForegroundColor Yellow

# Check LSASS as Protected Process Light (PPL)
try {
    $lsassProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    
    if ($lsassProtection -and $lsassProtection.RunAsPPL -eq 1) {
        Add-Result -Category "MS - Credential Protection" -Status "Pass" `
            -Message "LSASS is running as Protected Process Light (PPL)" `
            -Details "MS Baseline: LSASS process is protected from memory dumping attacks (mimikatz, etc.)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    } else {
        Add-Result -Category "MS - Credential Protection" -Status "Warning" `
            -Message "LSASS PPL is not enabled" `
            -Details "MS Baseline: LSASS vulnerable to credential dumping tools like mimikatz" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord; Restart-Computer" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check LSASS PPL: $_" `
        -Severity "Medium"
}

# Check WDigest credential caching (should be disabled)
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "MS - Credential Protection" -Status "Pass" `
            -Message "WDigest plaintext credential storage is disabled" `
            -Details "MS Baseline: Prevents plaintext passwords in memory (critical for credential theft prevention)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "MS - Credential Protection" -Status "Fail" `
            -Message "WDigest plaintext credential storage is ENABLED" `
            -Details "MS Baseline: Critical vulnerability - passwords stored in plaintext in LSASS memory" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    } else {
        Add-Result -Category "MS - Credential Protection" -Status "Pass" `
            -Message "WDigest is disabled by default (Windows 10/Server 2016+)" `
            -Details "MS Baseline: Secure default configuration on modern Windows" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check WDigest: $_" `
        -Severity "Medium"
}

# Check cached credentials limit
try {
    $cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
    
    if ($cachedLogons) {
        $count = $cachedLogons.CachedLogonsCount
        
        if ($count -le 4) {
            Add-Result -Category "MS - Credential Protection" -Status "Pass" `
                -Message "Cached logon count is limited to $count" `
                -Details "MS Baseline: Limits exposure to offline password attacks on domain credentials" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
        } elseif ($count -le 10) {
            Add-Result -Category "MS - Credential Protection" -Status "Warning" `
                -Message "Cached logon count is $count" `
                -Details "MS Baseline: Consider reducing to 4 or fewer for enhanced security" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
        } else {
            Add-Result -Category "MS - Credential Protection" -Status "Fail" `
                -Message "Cached logon count is high ($count)" `
                -Details "MS Baseline: Excessive cached credentials increase offline attack surface" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4 -Type DWord" `
                -Severity "High" `
                -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
        }
    } else {
        Add-Result -Category "MS - Credential Protection" -Status "Info" `
            -Message "Cached logon count not explicitly configured (using default: 10)" `
            -Details "MS Baseline: Consider setting to 4 or lower" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check cached logon count: $_" `
        -Severity "Medium"
}

# Check LAN Manager authentication level
try {
    $lmCompatibility = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
    
    if ($lmCompatibility) {
        $level = $lmCompatibility.LmCompatibilityLevel
        
        if ($level -ge 5) {
            Add-Result -Category "MS - Credential Protection" -Status "Pass" `
                -Message "LAN Manager authentication level is set to $level (NTLMv2 only)" `
                -Details "MS Baseline: Only NTLMv2 responses are sent, refusing LM and NTLM (most secure)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
        } elseif ($level -ge 3) {
            Add-Result -Category "MS - Credential Protection" -Status "Warning" `
                -Message "LAN Manager authentication level is $level" `
                -Details "MS Baseline: Consider setting to 5 for NTLMv2-only authentication" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
        } else {
            Add-Result -Category "MS - Credential Protection" -Status "Fail" `
                -Message "LAN Manager authentication level is weak ($level)" `
                -Details "MS Baseline: Allows weak LM/NTLM authentication protocols" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
                -Severity "High" `
                -CrossReferences @{ NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
        }
    }
} catch {
    Add-Result -Category "MS - Credential Protection" -Status "Error" `
        -Message "Failed to check LAN Manager authentication level: $_" `
        -Severity "Medium"
}


# ============================================================================
# SECTION 9: WINDOWS HELLO FOR BUSINESS
# ============================================================================
Write-Host "[MS] Checking Windows Hello for Business..." -ForegroundColor Yellow

try {
    $whfbPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue
    
    if ($whfbPolicy) {
        $enabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        
        if ($enabled -and $enabled.Enabled -eq 1) {
            Add-Result -Category "MS - Windows Hello" -Status "Pass" `
                -Message "Windows Hello for Business is enabled via policy" `
                -Details "MS Baseline: Modern passwordless authentication with biometrics or PIN is available" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
            
            # Check PIN complexity requirements
            $pinComplexity = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -ErrorAction SilentlyContinue
            
            if ($pinComplexity) {
                $minLength = $pinComplexity.MinimumPINLength
                if ($minLength -ge 6) {
                    Add-Result -Category "MS - Windows Hello" -Status "Pass" `
                        -Message "Windows Hello PIN minimum length is $minLength" `
                        -Details "MS Baseline: PIN complexity requirements meet security standards" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
                } else {
                    Add-Result -Category "MS - Windows Hello" -Status "Warning" `
                        -Message "Windows Hello PIN minimum length is $minLength" `
                        -Details "MS Baseline: Consider increasing to 6 or more characters" `
                        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name MinimumPINLength -Value 6 -Type DWord" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
                }
                
                # Check if uppercase letters are required
                $requireUppercase = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "UppercaseLetters" -ErrorAction SilentlyContinue
                if ($requireUppercase -and $requireUppercase.UppercaseLetters -eq 1) {
                    Add-Result -Category "MS - Windows Hello" -Status "Info" `
                        -Message "Windows Hello PIN requires uppercase letters" `
                        -Details "MS Baseline: Enhanced PIN complexity enabled" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
                }
                
                # Check if special characters are required
                $requireSpecial = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "SpecialCharacters" -ErrorAction SilentlyContinue
                if ($requireSpecial -and $requireSpecial.SpecialCharacters -eq 1) {
                    Add-Result -Category "MS - Windows Hello" -Status "Info" `
                        -Message "Windows Hello PIN requires special characters" `
                        -Details "MS Baseline: Enhanced PIN complexity enabled" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
                }
            }
            
            # Check biometric settings
            $biometrics = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\Biometrics" -ErrorAction SilentlyContinue
            if ($biometrics) {
                $enableBio = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\Biometrics" -Name "Enabled" -ErrorAction SilentlyContinue
                if ($enableBio -and $enableBio.Enabled -eq 1) {
                    Add-Result -Category "MS - Windows Hello" -Status "Pass" `
                        -Message "Windows Hello biometric authentication is enabled" `
                        -Details "MS Baseline: Biometric authentication (face, fingerprint) available for passwordless login" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
                }
            }
            
        } else {
            Add-Result -Category "MS - Windows Hello" -Status "Info" `
                -Message "Windows Hello for Business is not enabled via policy" `
                -Details "MS Baseline: Consider enabling for passwordless authentication" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
        }
    } else {
        Add-Result -Category "MS - Windows Hello" -Status "Info" `
            -Message "Windows Hello for Business policy not configured" `
            -Details "MS Baseline: WHFB provides biometric and PIN-based authentication" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-2(1)'; CIS='18.9.27' }
    }
    
} catch {
    Add-Result -Category "MS - Windows Hello" -Status "Error" `
        -Message "Failed to check Windows Hello configuration: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 10: BITLOCKER ENCRYPTION
# ============================================================================
Write-Host "[MS] Checking BitLocker Drive Encryption..." -ForegroundColor Yellow

try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    
    if ($bitlockerVolumes) {
        foreach ($volume in $bitlockerVolumes) {
            $mountPoint = $volume.MountPoint
            $protectionStatus = $volume.ProtectionStatus
            $encryptionPercentage = $volume.EncryptionPercentage
            $volumeType = $volume.VolumeType
            
            if ($protectionStatus -eq "On") {
                Add-Result -Category "MS - BitLocker" -Status "Pass" `
                    -Message "BitLocker is enabled on $mountPoint" `
                    -Details "MS Baseline: Drive is encrypted ($encryptionPercentage`% complete), Type: $volumeType" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
            } elseif ($protectionStatus -eq "Off" -and $volumeType -eq "OperatingSystem") {
                Add-Result -Category "MS - BitLocker" -Status "Fail" `
                    -Message "BitLocker is NOT enabled on OS drive $mountPoint" `
                    -Details "MS Baseline: Critical - Operating system drive should be encrypted" `
                    -Remediation "Enable-BitLocker -MountPoint '$mountPoint' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector" `
                    -Severity "High" `
                    -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
            } elseif ($protectionStatus -eq "Off") {
                Add-Result -Category "MS - BitLocker" -Status "Warning" `
                    -Message "BitLocker is NOT enabled on $mountPoint" `
                    -Details "MS Baseline: Consider encrypting all fixed drives (Type: $volumeType)" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
            }
            
            # Check encryption method
            if ($protectionStatus -eq "On") {
                $encryptionMethod = $volume.EncryptionMethod
                if ($encryptionMethod -like "*Aes256*") {
                    Add-Result -Category "MS - BitLocker" -Status "Pass" `
                        -Message "BitLocker on $mountPoint uses strong encryption: $encryptionMethod" `
                        -Details "MS Baseline: AES-256 encryption meets security requirements" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
                } else {
                    Add-Result -Category "MS - BitLocker" -Status "Warning" `
                        -Message "BitLocker on $mountPoint uses: $encryptionMethod" `
                        -Details "MS Baseline: Consider upgrading to XTS-AES256 for new deployments" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
                }
                
                # Check key protectors
                $keyProtectors = $volume.KeyProtector
                if ($keyProtectors) {
                    $tpmPresent = $keyProtectors | Where-Object { $_.KeyProtectorType -eq "Tpm" }
                    $recoveryKeyPresent = $keyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
                    
                    if ($tpmPresent) {
                        Add-Result -Category "MS - BitLocker" -Status "Pass" `
                            -Message "BitLocker on $mountPoint is protected by TPM" `
                            -Details "MS Baseline: Hardware-based key protection active" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
                    }
                    
                    if ($recoveryKeyPresent) {
                        Add-Result -Category "MS - BitLocker" -Status "Pass" `
                            -Message "BitLocker on $mountPoint has recovery key configured" `
                            -Details "MS Baseline: Recovery option available for password reset scenarios" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
                    } else {
                        Add-Result -Category "MS - BitLocker" -Status "Warning" `
                            -Message "BitLocker on $mountPoint lacks recovery key" `
                            -Details "MS Baseline: Add recovery password for emergency access" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
                    }
                }
            }
        }
        
        # Check BitLocker startup authentication settings
        $startupAuth = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -ErrorAction SilentlyContinue
        if ($startupAuth -and $startupAuth.UseTPM -eq 1) {
            Add-Result -Category "MS - BitLocker" -Status "Pass" `
                -Message "BitLocker configured to use TPM for startup authentication" `
                -Details "MS Baseline: Hardware-based pre-boot authentication enabled" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
        }
        
    } else {
        Add-Result -Category "MS - BitLocker" -Status "Info" `
            -Message "BitLocker status could not be determined" `
            -Details "MS Baseline: BitLocker may not be available on this edition of Windows" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
    }
    
} catch {
    Add-Result -Category "MS - BitLocker" -Status "Info" `
        -Message "BitLocker not available or could not be checked" `
        -Details "MS Baseline: Requires Windows Pro, Enterprise, or Education edition" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='SC-28'; CIS='3.11'; STIG='V-220920' }
}

# ============================================================================
# SECTION 11: TPM (TRUSTED PLATFORM MODULE)
# ============================================================================
Write-Host "[MS] Checking Trusted Platform Module (TPM)..." -ForegroundColor Yellow

try {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    
    if ($tpm) {
        if ($tpm.TpmPresent) {
            Add-Result -Category "MS - TPM" -Status "Pass" `
                -Message "TPM is present on this system" `
                -Details "MS Baseline: Hardware security module available for cryptographic operations" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
            
            if ($tpm.TpmReady) {
                Add-Result -Category "MS - TPM" -Status "Pass" `
                    -Message "TPM is ready and operational" `
                    -Details "MS Baseline: TPM is initialized and available for security features" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
            } else {
                Add-Result -Category "MS - TPM" -Status "Warning" `
                    -Message "TPM is present but not ready" `
                    -Details "MS Baseline: TPM may need to be initialized in BIOS/UEFI" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
            }
            
            if ($tpm.TpmEnabled) {
                Add-Result -Category "MS - TPM" -Status "Pass" `
                    -Message "TPM is enabled" `
                    -Details "MS Baseline: TPM can be used by security features like BitLocker and Windows Hello" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
            } else {
                Add-Result -Category "MS - TPM" -Status "Fail" `
                    -Message "TPM is present but disabled" `
                    -Details "MS Baseline: Enable TPM in BIOS/UEFI settings" `
                    -Remediation "Enable TPM in system BIOS/UEFI settings" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
            }
            
            if ($tpm.TpmActivated) {
                Add-Result -Category "MS - TPM" -Status "Pass" `
                    -Message "TPM is activated" `
                    -Details "MS Baseline: TPM ownership has been taken" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
            }
            
            # Check TPM version
            $tpmVersion = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
            if ($tpmVersion) {
                $specVersion = $tpmVersion.SpecVersion
                if ($specVersion -like "2.0*") {
                    Add-Result -Category "MS - TPM" -Status "Pass" `
                        -Message "TPM 2.0 is installed" `
                        -Details "MS Baseline: Modern TPM version (2.0) supports latest security features" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
                } else {
                    Add-Result -Category "MS - TPM" -Status "Warning" `
                        -Message "TPM version: $specVersion" `
                        -Details "MS Baseline: TPM 2.0 is recommended for modern Windows security features" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
                }
            }
            
        } else {
            Add-Result -Category "MS - TPM" -Status "Warning" `
                -Message "TPM is not present on this system" `
                -Details "MS Baseline: Hardware security features like BitLocker, Credential Guard require TPM" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
        }
    } else {
        Add-Result -Category "MS - TPM" -Status "Info" `
            -Message "TPM status could not be determined" `
            -Details "MS Baseline: TPM information not available" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
    }
    
} catch {
    Add-Result -Category "MS - TPM" -Status "Error" `
        -Message "Failed to check TPM: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 12: SECURE BOOT
# ============================================================================
Write-Host "[MS] Checking Secure Boot..." -ForegroundColor Yellow

try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot) {
        Add-Result -Category "MS - Secure Boot" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "MS Baseline: UEFI Secure Boot prevents unauthorized bootloaders and rootkits" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-7'; NSA='Boot Security'; STIG='V-220970' }
    } else {
        Add-Result -Category "MS - Secure Boot" -Status "Fail" `
            -Message "Secure Boot is NOT enabled" `
            -Details "MS Baseline: System vulnerable to boot-level malware and rootkits" `
            -Remediation "Enable Secure Boot in UEFI/BIOS settings" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-7'; NSA='Boot Security'; STIG='V-220970' }
    }
    
} catch {
    Add-Result -Category "MS - Secure Boot" -Status "Info" `
        -Message "Secure Boot status cannot be determined" `
        -Details "MS Baseline: System may use Legacy BIOS instead of UEFI, or cmdlet not available" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='SI-7'; NSA='Boot Security'; STIG='V-220970' }
}

# ============================================================================
# SECTION 13: REMOTE DESKTOP PROTOCOL (RDP) SECURITY
# ============================================================================
Write-Host "[MS] Checking Remote Desktop Security..." -ForegroundColor Yellow

try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "MS - RDP Security" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "MS Baseline: RDP disabled eliminates remote access attack surface" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
    } else {
        # RDP is enabled, check security settings
        Add-Result -Category "MS - RDP Security" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "MS Baseline: Verify RDP security settings are properly configured" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        
        # Check Network Level Authentication (NLA)
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Network Level Authentication (NLA) is required" `
                -Details "MS Baseline: NLA requires authentication before establishing full RDP session" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        } else {
            Add-Result -Category "MS - RDP Security" -Status "Fail" `
                -Message "RDP: Network Level Authentication is NOT required" `
                -Details "MS Baseline: Critical - enable NLA to prevent pre-authentication attacks" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord" `
                -Severity "High" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        }
        
        # Check encryption level
        $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        
        if ($encLevel -and $encLevel.MinEncryptionLevel -ge 3) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Encryption level is set to High" `
                -Details "MS Baseline: Strong encryption protects RDP sessions (128-bit or higher)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        } else {
            Add-Result -Category "MS - RDP Security" -Status "Warning" `
                -Message "RDP: Encryption level may not be set to High" `
                -Details "MS Baseline: Set to High for strongest encryption" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        }
        
        # Check Security Layer
        $secLayer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
        
        if ($secLayer -and $secLayer.SecurityLayer -eq 2) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Security layer is set to SSL (TLS)" `
                -Details "MS Baseline: TLS encryption protects RDP connections" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        } else {
            Add-Result -Category "MS - RDP Security" -Status "Warning" `
                -Message "RDP: Security layer not set to SSL/TLS" `
                -Details "MS Baseline: Configure TLS for encrypted connections" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 2 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        }
        
        # Check if admin approval mode is enabled for RDP
        $adminApproval = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue
        
        if ($adminApproval -and $adminApproval.LocalAccountTokenFilterPolicy -eq 0) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Local account token filter policy is enabled" `
                -Details "MS Baseline: Prevents remote use of local admin accounts except actual Administrator" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        }
        
        # Check Restricted Admin mode
        $restrictedAdmin = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue
        
        if ($restrictedAdmin -and $restrictedAdmin.DisableRestrictedAdmin -eq 0) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Restricted Admin mode is enabled" `
                -Details "MS Baseline: Protects credentials when connecting to potentially compromised systems" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        } elseif (-not $restrictedAdmin) {
            Add-Result -Category "MS - RDP Security" -Status "Pass" `
                -Message "RDP: Restricted Admin mode is available (not disabled)" `
                -Details "MS Baseline: Can be used with mstsc.exe /restrictedAdmin" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.65'; STIG='V-220940' }
        }
    }
    
} catch {
    Add-Result -Category "MS - RDP Security" -Status "Error" `
        -Message "Failed to check RDP security: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 14: POWERSHELL SECURITY
# ============================================================================
Write-Host "[MS] Checking PowerShell Security Settings..." -ForegroundColor Yellow

# Check PowerShell v2 status (should be removed/disabled)
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    
    if ($psv2) {
        if ($psv2.State -eq "Disabled") {
            Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
                -Message "PowerShell v2 is disabled" `
                -Details "MS Baseline: PowerShell v2 lacks security features and enables downgrade attacks" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
        } else {
            Add-Result -Category "MS - PowerShell Security" -Status "Fail" `
                -Message "PowerShell v2 is ENABLED" `
                -Details "MS Baseline: Critical - remove PowerShell v2 to prevent bypass of v5+ security features" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart" `
                -Severity "High" `
                -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
        }
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Info" `
        -Message "Could not check PowerShell v2 status" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
}

# Check PowerShell Script Block Logging
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "MS Baseline: Logs PowerShell commands and scripts for security monitoring (Event ID 4104)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
        
        # Check if logging suspicious scripts only
        $logInvocation = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -ErrorAction SilentlyContinue
        if ($logInvocation -and $logInvocation.EnableScriptBlockInvocationLogging -eq 1) {
            Add-Result -Category "MS - PowerShell Security" -Status "Info" `
                -Message "PowerShell Script Block Invocation Logging is enabled" `
                -Details "MS Baseline: Additional detailed logging of script block execution" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
        }
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Warning" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "MS Baseline: Enable for security monitoring and incident response" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell Script Block Logging: $_" `
        -Severity "Medium"
}

# Check PowerShell Transcription
try {
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    
    if ($transcription -and $transcription.EnableTranscripting -eq 1) {
        $outputDir = $transcription.OutputDirectory
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Transcription is enabled" `
            -Details "MS Baseline: Complete session logging to: $outputDir" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "MS Baseline: Transcription provides complete PowerShell session logs for forensics" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell Transcription: $_" `
        -Severity "Medium"
}

# Check Module Logging
try {
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    
    if ($moduleLogging -and $moduleLogging.EnableModuleLogging -eq 1) {
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Module Logging is enabled" `
            -Details "MS Baseline: Logs pipeline execution details (Event ID 4103)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    }
} catch {
    # Module logging is less critical
}

# Check Constrained Language Mode
try {
    if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell is running in Constrained Language Mode" `
            -Details "MS Baseline: Restricts potentially dangerous PowerShell features when enforced via AppLocker/WDAC" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Info" `
            -Message "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode" `
            -Details "MS Baseline: Constrained Language Mode is typically enforced via AppLocker or WDAC policies" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell Language Mode: $_" `
        -Severity "Medium"
}

# Check execution policy
try {
    $execPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    
    if ($execPolicy -eq "Restricted" -or $execPolicy -eq "AllSigned") {
        Add-Result -Category "MS - PowerShell Security" -Status "Pass" `
            -Message "PowerShell execution policy is set to: $execPolicy" `
            -Details "MS Baseline: Restrictive execution policy limits script execution" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    } elseif ($execPolicy -eq "RemoteSigned") {
        Add-Result -Category "MS - PowerShell Security" -Status "Info" `
            -Message "PowerShell execution policy is: RemoteSigned" `
            -Details "MS Baseline: Allows local scripts, requires signature for downloaded scripts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    } else {
        Add-Result -Category "MS - PowerShell Security" -Status "Warning" `
            -Message "PowerShell execution policy is: $execPolicy" `
            -Details "MS Baseline: Consider more restrictive policy (AllSigned or RemoteSigned)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-3'; NSA='PowerShell Security'; STIG='V-220950' }
    }
} catch {
    Add-Result -Category "MS - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell execution policy: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 15: WINDOWS FIREWALL
# ============================================================================
Write-Host "[MS] Checking Windows Firewall Baseline..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Private", "Public")

foreach ($profileName in $firewallProfiles) {
    try {
        $fwProfileObj = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        # Firewall enabled status
        if ($fwProfileObj.Enabled) {
            Add-Result -Category "MS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Firewall is enabled" `
                -Details "MS Baseline: Network filtering is active for $profileName networks" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        } else {
            Add-Result -Category "MS - Firewall" -Status "Fail" `
                -Message "$profileName Profile: Firewall is DISABLED" `
                -Details "MS Baseline: Critical - system lacks network protection" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        }
        
        # Default inbound action
        if ($fwProfileObj.DefaultInboundAction -eq "Block") {
            Add-Result -Category "MS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Default inbound is Block" `
                -Details "MS Baseline: Default deny reduces attack surface (whitelist approach)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        } else {
            Add-Result -Category "MS - Firewall" -Status "Fail" `
                -Message "$profileName Profile: Default inbound is Allow" `
                -Details "MS Baseline: Allows all inbound traffic by default - security risk" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        }
        
        # Default outbound action
        if ($fwProfileObj.DefaultOutboundAction -eq "Block") {
            Add-Result -Category "MS - Firewall" -Status "Info" `
                -Message "$profileName Profile: Default outbound is Block (highly restrictive)" `
                -Details "MS Baseline: Outbound filtering enabled - may require additional rules" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        } else {
            Add-Result -Category "MS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Default outbound is Allow" `
                -Details "MS Baseline: Standard configuration - outbound traffic allowed" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        }
        
        # Logging settings
        if ($fwProfileObj.LogBlocked -eq "True") {
            Add-Result -Category "MS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Blocked connections are logged" `
                -Details "MS Baseline: Firewall logs blocked traffic for security monitoring" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        } else {
            Add-Result -Category "MS - Firewall" -Status "Info" `
                -Message "$profileName Profile: Blocked connections are not logged" `
                -Details "MS Baseline: Enable logging for security monitoring" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -LogBlocked True" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        }
        
        # Notification settings
        if ($fwProfileObj.NotifyOnListen -eq "True") {
            Add-Result -Category "MS - Firewall" -Status "Info" `
                -Message "$profileName Profile: User notifications enabled" `
                -Details "MS Baseline: Users are notified when apps are blocked" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-7'; CIS='9.1'; STIG='V-220814' }
        }
        
    } catch {
        Add-Result -Category "MS - Firewall" -Status "Error" `
            -Message "Failed to check $profileName firewall profile: $_" `
            -Severity "Medium"
    }
}

# ============================================================================
# SECTION 16: SMB SECURITY
# ============================================================================
Write-Host "[MS] Checking SMB Security Baseline..." -ForegroundColor Yellow

# Check SMBv1 (should be disabled)
try {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    
    if ($smb1Feature.State -eq "Disabled") {
        Add-Result -Category "MS - SMB Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "MS Baseline: SMBv1 has critical vulnerabilities (WannaCry, NotPetya, EternalBlue)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
    } else {
        Add-Result -Category "MS - SMB Security" -Status "Fail" `
            -Message "SMBv1 protocol is ENABLED" `
            -Details "MS Baseline: Critical vulnerability - immediate remediation required" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -Severity "High" `
            -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
    }
} catch {
    Add-Result -Category "MS - SMB Security" -Status "Error" `
        -Message "Failed to check SMBv1 status: $_" `
        -Severity "Medium"
}

# Check SMB server configuration
try {
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer) {
        # SMB signing (server)
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB server signing is required" `
                -Details "MS Baseline: Prevents man-in-the-middle and relay attacks on SMB traffic" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        } else {
            Add-Result -Category "MS - SMB Security" -Status "Fail" `
                -Message "SMB server signing is not required" `
                -Details "MS Baseline: SMB traffic vulnerable to tampering and relay attacks" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
        
        if ($smbServer.EnableSecuritySignature) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB server signing is enabled" `
                -Details "MS Baseline: Server can negotiate SMB signing with clients" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
        
        # SMB encryption
        if ($smbServer.EncryptData) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB encryption is globally enabled" `
                -Details "MS Baseline: All SMB traffic is encrypted for confidentiality" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        } else {
            Add-Result -Category "MS - SMB Security" -Status "Info" `
                -Message "SMB encryption is not globally enabled" `
                -Details "MS Baseline: Consider enabling for sensitive data transfers" `
                -Remediation "Set-SmbServerConfiguration -EncryptData `$true -Force" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
        
        # Reject unencrypted access
        if ($smbServer.RejectUnencryptedAccess) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB rejects unencrypted access" `
                -Details "MS Baseline: Forces clients to use encryption" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
        
        # SMBv2/v3 status
        if ($smbServer.EnableSMB2Protocol) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMBv2/v3 protocol is enabled" `
                -Details "MS Baseline: Modern SMB protocol with security enhancements active" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        } else {
            Add-Result -Category "MS - SMB Security" -Status "Fail" `
                -Message "SMBv2/v3 protocol is disabled" `
                -Details "MS Baseline: Only SMBv1 available - critical security issue" `
                -Remediation "Set-SmbServerConfiguration -EnableSMB2Protocol `$true -Force" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
    }
} catch {
    Add-Result -Category "MS - SMB Security" -Status "Error" `
        -Message "Failed to check SMB server configuration: $_" `
        -Severity "Medium"
}

# Check SMB client configuration
try {
    $smbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
    
    if ($smbClient) {
        # Client signing
        if ($smbClient.RequireSecuritySignature) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB client signing is required" `
                -Details "MS Baseline: Client requires SMB signing from servers" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
        
        if ($smbClient.EnableSecuritySignature) {
            Add-Result -Category "MS - SMB Security" -Status "Pass" `
                -Message "SMB client signing is enabled" `
                -Details "MS Baseline: Client can use SMB signing when available" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; NSA='SMB Security'; STIG='V-220830' }
        }
    }
} catch {
    Add-Result -Category "MS - SMB Security" -Status "Error" `
        -Message "Failed to check SMB client configuration: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 17: USER ACCOUNT CONTROL (UAC)
# ============================================================================
Write-Host "[MS] Checking User Account Control (UAC)..." -ForegroundColor Yellow

try {
    $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    
    if ($uacEnabled -and $uacEnabled.EnableLUA -eq 1) {
        Add-Result -Category "MS - UAC" -Status "Pass" `
            -Message "User Account Control (UAC) is enabled" `
            -Details "MS Baseline: UAC provides privilege separation and consent prompts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
    } else {
        Add-Result -Category "MS - UAC" -Status "Fail" `
            -Message "User Account Control is DISABLED" `
            -Details "MS Baseline: Critical - all processes run with full privileges" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord; Restart-Computer" `
            -Severity "High" `
            -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
    }
    
    # Check UAC prompt behavior for administrators
    $adminPrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    
    if ($adminPrompt) {
        $promptValue = $adminPrompt.ConsentPromptBehaviorAdmin
        
        switch ($promptValue) {
            0 { 
                Add-Result -Category "MS - UAC" -Status "Fail" `
                    -Message "UAC: Admins - Elevate without prompting" `
                    -Details "MS Baseline: No UAC prompts for administrators - security bypass" `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord" `
                    -Severity "High" `
                    -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
            }
            1 { 
                Add-Result -Category "MS - UAC" -Status "Warning" `
                    -Message "UAC: Admins - Prompt for credentials on secure desktop" `
                    -Details "MS Baseline: Secure, but credential entry required" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
            }
            2 { 
                Add-Result -Category "MS - UAC" -Status "Pass" `
                    -Message "UAC: Admins - Prompt for consent on secure desktop" `
                    -Details "MS Baseline: Recommended setting - prompts on isolated desktop" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
            }
            3 { 
                Add-Result -Category "MS - UAC" -Status "Info" `
                    -Message "UAC: Admins - Prompt for credentials" `
                    -Details "MS Baseline: Prompts for credentials without secure desktop" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
            }
            4 { 
                Add-Result -Category "MS - UAC" -Status "Info" `
                    -Message "UAC: Admins - Prompt for consent" `
                    -Details "MS Baseline: Prompts without secure desktop" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
            }
            5 { 
                Add-Result -Category "MS - UAC" -Status "Pass" `
                    -Message "UAC: Admins - Prompt for consent for non-Windows binaries" `
                    -Details "MS Baseline: Default setting - prompts for non-Microsoft applications" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
            }
        }
    }
    
    # Check UAC prompt behavior for standard users
    $userPrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
    
    if ($userPrompt) {
        $promptValue = $userPrompt.ConsentPromptBehaviorUser
        
        if ($promptValue -eq 0) {
            Add-Result -Category "MS - UAC" -Status "Pass" `
                -Message "UAC: Standard users - Auto deny elevation requests" `
                -Details "MS Baseline: Most restrictive - users cannot elevate" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
        } elseif ($promptValue -eq 1) {
            Add-Result -Category "MS - UAC" -Status "Pass" `
                -Message "UAC: Standard users - Prompt for credentials on secure desktop" `
                -Details "MS Baseline: Secure credential prompting" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
        } elseif ($promptValue -eq 3) {
            Add-Result -Category "MS - UAC" -Status "Warning" `
                -Message "UAC: Standard users - Prompt for credentials" `
                -Details "MS Baseline: Prompts without secure desktop" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
        }
    }
    
    # Check if UAC prompts on secure desktop
    $secureDesktop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue
    
    if ($secureDesktop -and $secureDesktop.PromptOnSecureDesktop -eq 1) {
        Add-Result -Category "MS - UAC" -Status "Pass" `
            -Message "UAC prompts appear on secure desktop" `
            -Details "MS Baseline: Prevents UI automation attacks on UAC prompts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
    } else {
        Add-Result -Category "MS - UAC" -Status "Warning" `
            -Message "UAC prompts do not use secure desktop" `
            -Details "MS Baseline: Vulnerable to UI automation and clickjacking" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
    }
    
    # Check detection of application installations
    $detectInstalls = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue
    
    if ($detectInstalls -and $detectInstalls.EnableInstallerDetection -eq 1) {
        Add-Result -Category "MS - UAC" -Status "Pass" `
            -Message "UAC: Application installation detection is enabled" `
            -Details "MS Baseline: Prompts when installer programs are detected" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
    }
    
    # Check if built-in admin is restricted
    $filterAdmin = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue
    
    if ($filterAdmin -and $filterAdmin.FilterAdministratorToken -eq 1) {
        Add-Result -Category "MS - UAC" -Status "Pass" `
            -Message "UAC: Built-in Administrator account runs in Admin Approval Mode" `
            -Details "MS Baseline: Built-in admin subject to UAC prompts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-6'; CIS='2.3.17'; STIG='V-220932' }
    }
    
} catch {
    Add-Result -Category "MS - UAC" -Status "Error" `
        -Message "Failed to check UAC settings: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 18: WINDOWS UPDATE
# ============================================================================
Write-Host "[MS] Checking Windows Update Configuration..." -ForegroundColor Yellow

try {
    # Check automatic update settings
    $auOptions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    
    if ($auOptions -and $auOptions.NoAutoUpdate -eq 1) {
        Add-Result -Category "MS - Windows Update" -Status "Fail" `
            -Message "Automatic Updates are DISABLED" `
            -Details "MS Baseline: Critical - system not receiving security updates" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
    } else {
        Add-Result -Category "MS - Windows Update" -Status "Pass" `
            -Message "Automatic Updates are enabled" `
            -Details "MS Baseline: System configured to receive security updates" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
    }
    
    # Check update installation behavior
    $auConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
    
    if ($auConfig) {
        $option = $auConfig.AUOptions
        
        switch ($option) {
            2 { 
                Add-Result -Category "MS - Windows Update" -Status "Warning" `
                    -Message "Windows Update: Notify before download" `
                    -Details "MS Baseline: Manual intervention required - consider auto-install" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
            }
            3 { 
                Add-Result -Category "MS - Windows Update" -Status "Pass" `
                    -Message "Windows Update: Auto download and notify for install" `
                    -Details "MS Baseline: Updates downloaded automatically" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
            }
            4 { 
                Add-Result -Category "MS - Windows Update" -Status "Pass" `
                    -Message "Windows Update: Auto download and schedule install" `
                    -Details "MS Baseline: Recommended - fully automated updates" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
            }
            5 { 
                Add-Result -Category "MS - Windows Update" -Status "Pass" `
                    -Message "Windows Update: Automatic updates with local admin control" `
                    -Details "MS Baseline: Auto updates with user choice" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
            }
        }
    }
    
    # Check last update installation
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($updateSession) {
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        
        if ($historyCount -gt 0) {
            $updateHistory = $updateSearcher.QueryHistory(0, 1)
            foreach ($update in $updateHistory) {
                $lastUpdate = $update.Date
                $daysSinceUpdate = ((Get-Date) - $lastUpdate).Days
                
                if ($daysSinceUpdate -le 30) {
                    Add-Result -Category "MS - Windows Update" -Status "Pass" `
                        -Message "Recent update installed $daysSinceUpdate day(s) ago" `
                        -Details "MS Baseline: System is receiving updates (last: $lastUpdate)" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
                } else {
                    Add-Result -Category "MS - Windows Update" -Status "Warning" `
                        -Message "Last update was $daysSinceUpdate days ago" `
                        -Details "MS Baseline: Check Windows Update for pending updates" `
                        -Remediation "Install-Module PSWindowsUpdate; Get-WindowsUpdate; Install-WindowsUpdate" `
                        -Severity "Medium" `
                        -CrossReferences @{ NIST='SI-2'; CISA='BOD 22-01' }
                }
            }
        }
    }
    
} catch {
    Add-Result -Category "MS - Windows Update" -Status "Error" `
        -Message "Failed to check Windows Update: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 19: MICROSOFT DEFENDER APPLICATION GUARD
# ============================================================================
Write-Host "[MS] Checking Microsoft Defender Application Guard..." -ForegroundColor Yellow

try {
    $wdagFeature = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -ErrorAction SilentlyContinue
    
    if ($wdagFeature -and $wdagFeature.State -eq "Enabled") {
        Add-Result -Category "MS - Application Guard" -Status "Pass" `
            -Message "Microsoft Defender Application Guard is enabled" `
            -Details "MS Baseline: Isolated browsing sessions protect against web-based attacks" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-39' }
        
        # Check Application Guard settings
        $wdagSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -ErrorAction SilentlyContinue
        
        if ($wdagSettings) {
            $allowPersistence = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -ErrorAction SilentlyContinue
            if ($allowPersistence -and $allowPersistence.AllowPersistence -eq 0) {
                Add-Result -Category "MS - Application Guard" -Status "Pass" `
                    -Message "Application Guard: Persistence is disabled" `
                    -Details "MS Baseline: Container data is deleted after session ends" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='SC-39' }
            }
        }
    } elseif ($wdagFeature -and $wdagFeature.State -eq "Disabled") {
        Add-Result -Category "MS - Application Guard" -Status "Info" `
            -Message "Microsoft Defender Application Guard is not enabled" `
            -Details "MS Baseline: WDAG provides hardware-isolated browsing (requires Hyper-V)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-39' }
    } else {
        Add-Result -Category "MS - Application Guard" -Status "Info" `
            -Message "Microsoft Defender Application Guard is not available" `
            -Details "MS Baseline: Requires Windows 10/11 Pro/Enterprise and compatible hardware" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-39' }
    }
    
} catch {
    Add-Result -Category "MS - Application Guard" -Status "Info" `
        -Message "Application Guard check not applicable or unavailable" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='SC-39' }
}

# ============================================================================
# SECTION 20: LEGACY PROTOCOLS AND FEATURES
# ============================================================================
Write-Host "[MS] Checking Legacy Protocols and Features..." -ForegroundColor Yellow

# Check LLMNR (should be disabled)
try {
    $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
        Add-Result -Category "MS - Legacy Protocols" -Status "Pass" `
            -Message "LLMNR (Link-Local Multicast Name Resolution) is disabled" `
            -Details "MS Baseline: Prevents LLMNR poisoning attacks (Responder, Inveigh)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    } else {
        Add-Result -Category "MS - Legacy Protocols" -Status "Warning" `
            -Message "LLMNR is enabled or not configured" `
            -Details "MS Baseline: Vulnerable to name resolution poisoning attacks" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    }
} catch {
    Add-Result -Category "MS - Legacy Protocols" -Status "Error" `
        -Message "Failed to check LLMNR: $_" `
        -Severity "Medium"
}

# Check NetBIOS over TCP/IP
try {
    $netbiosSettings = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction SilentlyContinue
    
    $netbiosEnabled = $false
    foreach ($adapter in $netbiosSettings) {
        if ($adapter.TcpipNetbiosOptions -eq 0 -or $adapter.TcpipNetbiosOptions -eq 1) {
            $netbiosEnabled = $true
            break
        }
    }
    
    if ($netbiosEnabled) {
        Add-Result -Category "MS - Legacy Protocols" -Status "Warning" `
            -Message "NetBIOS over TCP/IP is enabled on one or more adapters" `
            -Details "MS Baseline: Vulnerable to NBNS poisoning attacks" `
            -Remediation "Disable NetBIOS over TCP/IP in network adapter TCP/IP settings" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    } else {
        Add-Result -Category "MS - Legacy Protocols" -Status "Pass" `
            -Message "NetBIOS over TCP/IP is disabled" `
            -Details "MS Baseline: Prevents NetBIOS name resolution attacks" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    }
} catch {
    Add-Result -Category "MS - Legacy Protocols" -Status "Error" `
        -Message "Failed to check NetBIOS: $_" `
        -Severity "Medium"
}

# Check Print Spooler service (PrintNightmare vulnerability)
try {
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    
    if ($spooler) {
        if ($spooler.Status -eq "Running" -and $spooler.StartType -ne "Disabled") {
            # Check if this is a domain controller or print server
            $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
            
            if (-not $isDC) {
                Add-Result -Category "MS - Legacy Features" -Status "Warning" `
                    -Message "Print Spooler service is running" `
                    -Details "MS Baseline: Print Spooler has history of vulnerabilities (PrintNightmare). Disable if not needed" `
                    -Remediation "Stop-Service -Name Spooler; Set-Service -Name Spooler -StartupType Disabled" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
            } else {
                Add-Result -Category "MS - Legacy Features" -Status "Info" `
                    -Message "Print Spooler service is running (Domain Controller)" `
                    -Details "MS Baseline: Required on DCs but ensure patches applied and RpcAuthnLevelPrivacyEnabled set" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
            }
            
            # Check Point and Print restrictions
            $pointAndPrint = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
            
            if ($pointAndPrint -and $pointAndPrint.RestrictDriverInstallationToAdministrators -eq 1) {
                Add-Result -Category "MS - Legacy Features" -Status "Pass" `
                    -Message "Point and Print: Driver installation restricted to administrators" `
                    -Details "MS Baseline: Mitigates PrintNightmare exploitation" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
            } else {
                Add-Result -Category "MS - Legacy Features" -Status "Warning" `
                    -Message "Point and Print: Driver installation not restricted" `
                    -Details "MS Baseline: Vulnerable to PrintNightmare" `
                    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Value 1 -Type DWord" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
            }
        } else {
            Add-Result -Category "MS - Legacy Features" -Status "Pass" `
                -Message "Print Spooler service is disabled" `
                -Details "MS Baseline: Eliminates Print Spooler attack surface" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
        }
    }
} catch {
    Add-Result -Category "MS - Legacy Features" -Status "Error" `
        -Message "Failed to check Print Spooler: $_" `
        -Severity "Medium"
}

# Check Windows Script Host
try {
    $wsh = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
    
    if ($wsh -and $wsh.Enabled -eq 0) {
        Add-Result -Category "MS - Legacy Features" -Status "Pass" `
            -Message "Windows Script Host is disabled" `
            -Details "MS Baseline: Prevents VBS/JS script execution via WScript/CScript" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    } elseif ($wsh -and $wsh.Enabled -eq 1) {
        Add-Result -Category "MS - Legacy Features" -Status "Info" `
            -Message "Windows Script Host is enabled" `
            -Details "MS Baseline: Consider disabling if not required for legitimate scripts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    }
} catch {
    # WSH settings may not be configured
}

# Check AutoRun/AutoPlay settings
try {
    $autoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    
    if ($autoRun -and $autoRun.NoDriveTypeAutoRun -eq 255) {
        Add-Result -Category "MS - Legacy Features" -Status "Pass" `
            -Message "AutoRun is disabled for all drive types" `
            -Details "MS Baseline: Prevents automatic execution from removable media" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    } else {
        Add-Result -Category "MS - Legacy Features" -Status "Warning" `
            -Message "AutoRun may not be fully disabled" `
            -Details "MS Baseline: Disable AutoRun to prevent malware spread via USB" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-7'; CIS='5.1' }
    }
} catch {
    Add-Result -Category "MS - Legacy Features" -Status "Error" `
        -Message "Failed to check AutoRun: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 21: AUDIT POLICIES
# ============================================================================
Write-Host "[MS] Checking Audit Policy Configuration..." -ForegroundColor Yellow

try {
    # Check if Advanced Audit Policy is configured
    $auditCategories = @(
        "Logon/Logoff"
        "Account Logon"
        "Object Access"
        "Privilege Use"
        "System"
        "Policy Change"
        "Account Management"
    )
    
    $auditConfigured = $false
    
    foreach ($category in $auditCategories) {
        try {
            $auditResult = auditpol /get /category:"$category" 2>&1
            if ($auditResult -match "Success and Failure|Success") {
                $auditConfigured = $true
                break
            }
        } catch {
            continue
        }
    }
    
    if ($auditConfigured) {
        Add-Result -Category "MS - Audit Policy" -Status "Pass" `
            -Message "Advanced Audit Policy is configured" `
            -Details "MS Baseline: Security event logging is enabled for monitoring" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    } else {
        Add-Result -Category "MS - Audit Policy" -Status "Warning" `
            -Message "Advanced Audit Policy may not be fully configured" `
            -Details "MS Baseline: Enable comprehensive audit logging for security monitoring" `
            -Remediation "Configure via Group Policy: Computer Configuration `> Windows Settings `> Security Settings `> Advanced Audit Policy Configuration" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    }
    
    # Check specific critical audit settings
    $logonAudit = auditpol /get /subcategory:"Logon" 2>&1
    if ($logonAudit -match "Success and Failure") {
        Add-Result -Category "MS - Audit Policy" -Status "Pass" `
            -Message "Audit Policy: Logon events are audited (Success and Failure)" `
            -Details "MS Baseline: Tracks successful and failed logon attempts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    } elseif ($logonAudit -match "Success") {
        Add-Result -Category "MS - Audit Policy" -Status "Warning" `
            -Message "Audit Policy: Only successful logons are audited" `
            -Details "MS Baseline: Enable failure auditing to detect brute force attacks" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    }
    
    $processCreation = auditpol /get /subcategory:"Process Creation" 2>&1
    if ($processCreation -match "Success") {
        Add-Result -Category "MS - Audit Policy" -Status "Pass" `
            -Message "Audit Policy: Process Creation is audited" `
            -Details "MS Baseline: Tracks process execution for security monitoring (Event ID 4688)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    }
    
} catch {
    Add-Result -Category "MS - Audit Policy" -Status "Error" `
        -Message "Failed to check Audit Policy: $_" `
        -Severity "Medium"
}

# Check command line auditing in process creation events
try {
    $cmdLineAudit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    
    if ($cmdLineAudit -and $cmdLineAudit.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Add-Result -Category "MS - Audit Policy" -Status "Pass" `
            -Message "Command line auditing in process creation events is enabled" `
            -Details "MS Baseline: Process creation events include full command line for forensics" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    } else {
        Add-Result -Category "MS - Audit Policy" -Status "Info" `
            -Message "Command line auditing in process creation events is not enabled" `
            -Details "MS Baseline: Enable for enhanced forensic capabilities" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-2'; CIS='17.1'; STIG='V-220748' }
    }
} catch {
    Add-Result -Category "MS - Audit Policy" -Status "Error" `
        -Message "Failed to check command line auditing: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 22: EVENT LOG CONFIGURATION
# ============================================================================
Write-Host "[MS] Checking Event Log Configuration..." -ForegroundColor Yellow

$criticalLogs = @("Application", "System", "Security")

foreach ($logName in $criticalLogs) {
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        
        # Check if log is enabled
        if ($log.IsEnabled) {
            Add-Result -Category "MS - Event Logs" -Status "Pass" `
                -Message "$logName log is enabled" `
                -Details "MS Baseline: Critical event log is active" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
        } else {
            Add-Result -Category "MS - Event Logs" -Status "Fail" `
                -Message "$logName log is DISABLED" `
                -Details "MS Baseline: Critical event logging disabled" `
                -Remediation "wevtutil sl $logName /e:true" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
        }
        
        # Check log size
        $maxSize = $log.MaximumSizeInBytes / 1MB
        if ($maxSize -ge 32) {
            Add-Result -Category "MS - Event Logs" -Status "Pass" `
                -Message "$logName log size is ${maxSize}MB" `
                -Details "MS Baseline: Adequate log retention capacity" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
        } else {
            Add-Result -Category "MS - Event Logs" -Status "Warning" `
                -Message "$logName log size is only ${maxSize}MB" `
                -Details "MS Baseline: Consider increasing to 32MB or higher" `
                -Remediation "wevtutil sl $logName /ms:33554432" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
        }
        
        # Check retention policy (for Security log especially)
        if ($logName -eq "Security") {
            if ($log.LogMode -eq "Circular") {
                Add-Result -Category "MS - Event Logs" -Status "Warning" `
                    -Message "Security log uses circular overwrite" `
                    -Details "MS Baseline: Old events are overwritten - consider 'Retain' or increase size" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
            } elseif ($log.LogMode -eq "Retain") {
                Add-Result -Category "MS - Event Logs" -Status "Pass" `
                    -Message "Security log retention prevents overwriting" `
                    -Details "MS Baseline: Events are retained (manual archive required when full)" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
            }
        }
        
    } catch {
        Add-Result -Category "MS - Event Logs" -Status "Error" `
            -Message "Failed to check $logName log: $_" `
            -Severity "Medium"
    }
}

# Check PowerShell event logs
try {
    $psLog = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -ErrorAction Stop
    
    if ($psLog.IsEnabled) {
        Add-Result -Category "MS - Event Logs" -Status "Pass" `
            -Message "PowerShell Operational log is enabled" `
            -Details "MS Baseline: PowerShell activity logging active" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
    } else {
        Add-Result -Category "MS - Event Logs" -Status "Warning" `
            -Message "PowerShell Operational log is disabled" `
            -Details "MS Baseline: Enable for PowerShell security monitoring" `
            -Remediation "wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AU-4'; CIS='18.9.26' }
    }
} catch {
    # PowerShell logs may not be available on older systems
}

# ============================================================================
# SECTION 23: ANONYMOUS ACCESS RESTRICTIONS
# ============================================================================
Write-Host "[MS] Checking Anonymous Access Restrictions..." -ForegroundColor Yellow

try {
    # Restrict anonymous access to Named Pipes and Shares
    $restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymous -and $restrictAnonymous.RestrictAnonymous -ge 1) {
        Add-Result -Category "MS - Anonymous Access" -Status "Pass" `
            -Message "Anonymous access to SAM accounts and shares is restricted" `
            -Details "MS Baseline: RestrictAnonymous = $($restrictAnonymous.RestrictAnonymous) (1=Some restrictions, 2=No anonymous)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-14'; CIS='2.3.10'; STIG='V-220936' }
    } else {
        Add-Result -Category "MS - Anonymous Access" -Status "Warning" `
            -Message "Anonymous access is not restricted" `
            -Details "MS Baseline: Anonymous users can enumerate accounts and shares" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-14'; CIS='2.3.10'; STIG='V-220936' }
    }
    
    # Check if anonymous SID/Name translation is restricted
    $restrictAnonymousSAM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymousSAM -and $restrictAnonymousSAM.RestrictAnonymousSAM -eq 1) {
        Add-Result -Category "MS - Anonymous Access" -Status "Pass" `
            -Message "Anonymous SAM enumeration is restricted" `
            -Details "MS Baseline: Anonymous users cannot enumerate SAM accounts" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-14'; CIS='2.3.10'; STIG='V-220936' }
    } else {
        Add-Result -Category "MS - Anonymous Access" -Status "Warning" `
            -Message "Anonymous SAM enumeration is not restricted" `
            -Details "MS Baseline: Anonymous users can enumerate account information" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-14'; CIS='2.3.10'; STIG='V-220936' }
    }
    
    # Check anonymous pipe and share access
    $everyoneIncludes = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -ErrorAction SilentlyContinue
    
    if ($everyoneIncludes -and $everyoneIncludes.EveryoneIncludesAnonymous -eq 0) {
        Add-Result -Category "MS - Anonymous Access" -Status "Pass" `
            -Message "Anonymous users are not included in Everyone group" `
            -Details "MS Baseline: Restricts anonymous access to resources" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-14'; CIS='2.3.10'; STIG='V-220936' }
    } else {
        Add-Result -Category "MS - Anonymous Access" -Status "Warning" `
            -Message "Anonymous users may be included in Everyone group" `
            -Details "MS Baseline: Anonymous users have access to 'Everyone' permissions" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name EveryoneIncludesAnonymous -Value 0 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-14'; CIS='2.3.10'; STIG='V-220936' }
    }
    
} catch {
    Add-Result -Category "MS - Anonymous Access" -Status "Error" `
        -Message "Failed to check anonymous access restrictions: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 24: LDAP SIGNING AND CHANNEL BINDING
# ============================================================================
Write-Host "[MS] Checking LDAP Security Settings..." -ForegroundColor Yellow

try {
    # Check LDAP client signing
    $ldapClientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue
    
    if ($ldapClientSigning) {
        $signingLevel = $ldapClientSigning.LDAPClientIntegrity
        
        if ($signingLevel -eq 2) {
            Add-Result -Category "MS - LDAP Security" -Status "Pass" `
                -Message "LDAP client signing is required (Negotiate signing)" `
                -Details "MS Baseline: LDAP traffic is signed to prevent tampering" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        } elseif ($signingLevel -eq 1) {
            Add-Result -Category "MS - LDAP Security" -Status "Warning" `
                -Message "LDAP client signing is negotiated but not required" `
                -Details "MS Baseline: Consider requiring signing for all LDAP traffic" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name LDAPClientIntegrity -Value 2 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        } else {
            Add-Result -Category "MS - LDAP Security" -Status "Fail" `
                -Message "LDAP client signing is disabled" `
                -Details "MS Baseline: LDAP traffic vulnerable to tampering and man-in-the-middle" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name LDAPClientIntegrity -Value 2 -Type DWord" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        }
    }
    
    # Check LDAP server signing (for domain controllers)
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    
    if ($isDC) {
        $ldapServerSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
        
        if ($ldapServerSigning -and $ldapServerSigning.LDAPServerIntegrity -eq 2) {
            Add-Result -Category "MS - LDAP Security" -Status "Pass" `
                -Message "LDAP server signing is required (Domain Controller)" `
                -Details "MS Baseline: Domain controller requires signed LDAP communications" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        } elseif ($ldapServerSigning) {
            Add-Result -Category "MS - LDAP Security" -Status "Warning" `
                -Message "LDAP server signing not required (Domain Controller)" `
                -Details "MS Baseline: Consider requiring LDAP signing on domain controllers" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Value 2 -Type DWord; Restart-Computer" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        }
        
        # Check LDAP channel binding
        $channelBinding = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
        
        if ($channelBinding -and $channelBinding.LdapEnforceChannelBinding -eq 2) {
            Add-Result -Category "MS - LDAP Security" -Status "Pass" `
                -Message "LDAP channel binding is enforced (Domain Controller)" `
                -Details "MS Baseline: Prevents LDAP relay attacks" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        } elseif ($channelBinding -and $channelBinding.LdapEnforceChannelBinding -eq 1) {
            Add-Result -Category "MS - LDAP Security" -Status "Warning" `
                -Message "LDAP channel binding is enabled but not enforced" `
                -Details "MS Baseline: Consider enforcing for maximum protection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -Value 2 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-8'; CIS='18.3.4' }
        }
    }
    
} catch {
    Add-Result -Category "MS - LDAP Security" -Status "Error" `
        -Message "Failed to check LDAP security: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 25: DNS CLIENT SECURITY
# ============================================================================
Write-Host "[MS] Checking DNS Client Security..." -ForegroundColor Yellow

try {
    # Check DNS over HTTPS (DoH)
    $dohEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -ErrorAction SilentlyContinue
    
    if ($dohEnabled -and $dohEnabled.EnableAutoDoh -eq 2) {
        Add-Result -Category "MS - DNS Security" -Status "Pass" `
            -Message "DNS over HTTPS (DoH) is enabled" `
            -Details "MS Baseline: DNS queries are encrypted for privacy" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-20' }
    } elseif ($dohEnabled -and $dohEnabled.EnableAutoDoh -eq 1) {
        Add-Result -Category "MS - DNS Security" -Status "Info" `
            -Message "DNS over HTTPS is available but not enforced" `
            -Details "MS Baseline: DoH will be used when available" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-20' }
    } else {
        Add-Result -Category "MS - DNS Security" -Status "Info" `
            -Message "DNS over HTTPS is not configured" `
            -Details "MS Baseline: Consider enabling DoH for DNS query privacy" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SC-20' }
    }
    
} catch {
    Add-Result -Category "MS - DNS Security" -Status "Error" `
        -Message "Failed to check DNS security: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 26: MICROSOFT EDGE SECURITY POLICIES
# ============================================================================
Write-Host "[MS] Checking Microsoft Edge Security Policies..." -ForegroundColor Yellow

try {
    # Check if Edge policies are configured
    $edgePolicies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
    
    if ($edgePolicies) {
        # Site isolation
        $siteIsolation = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SitePerProcess" -ErrorAction SilentlyContinue
        if ($siteIsolation -and $siteIsolation.SitePerProcess -eq 1) {
            Add-Result -Category "MS - Edge Security" -Status "Pass" `
                -Message "Edge: Site isolation is enabled" `
                -Details "MS Baseline: Each site runs in isolated process (Spectre mitigation)" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-6' }
        }
        
        # Password manager
        $passwordManager = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue
        if ($passwordManager) {
            if ($passwordManager.PasswordManagerEnabled -eq 1) {
                Add-Result -Category "MS - Edge Security" -Status "Pass" `
                    -Message "Edge: Password manager is enabled" `
                    -Details "MS Baseline: Built-in password management available" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-6' }
            } else {
                Add-Result -Category "MS - Edge Security" -Status "Info" `
                    -Message "Edge: Password manager is disabled" `
                    -Details "MS Baseline: May be using enterprise password manager" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-6' }
            }
        }
        
        # SSL minimum version
        $sslMinVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SSLVersionMin" -ErrorAction SilentlyContinue
        if ($sslMinVersion) {
            $minVer = $sslMinVersion.SSLVersionMin
            if ($minVer -eq "tls1.2" -or $minVer -eq "tls1.3") {
                Add-Result -Category "MS - Edge Security" -Status "Pass" `
                    -Message "Edge: Minimum SSL/TLS version is $minVer" `
                    -Details "MS Baseline: Weak SSL/TLS versions are blocked" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-6' }
            } else {
                Add-Result -Category "MS - Edge Security" -Status "Warning" `
                    -Message "Edge: Minimum SSL/TLS version allows weak protocols" `
                    -Details "MS Baseline: Set to TLS 1.2 minimum" `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name SSLVersionMin -Value 'tls1.2' -Type String" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-6' }
            }
        }
        
        # Extension installation control
        $extensionSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ExtensionInstallBlocklist" -ErrorAction SilentlyContinue
        if ($extensionSettings) {
            Add-Result -Category "MS - Edge Security" -Status "Pass" `
                -Message "Edge: Extension installation restrictions are configured" `
                -Details "MS Baseline: Extension control policies are in place" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-6' }
        }
        
    } else {
        Add-Result -Category "MS - Edge Security" -Status "Info" `
            -Message "Microsoft Edge policies not configured via Group Policy" `
            -Details "MS Baseline: Edge uses default security settings" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-6' }
    }
    
} catch {
    Add-Result -Category "MS - Edge Security" -Status "Info" `
        -Message "Microsoft Edge security policies check not applicable" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='CM-6' }
}

# ============================================================================
# SECTION 27: MICROSOFT OFFICE SECURITY
# ============================================================================
Write-Host "[MS] Checking Microsoft Office Security Settings..." -ForegroundColor Yellow

try {
    # Check Office versions and macro settings
    $officeVersions = @("16.0", "15.0", "14.0") # Office 2016/2019/365, 2013, 2010
    $officeApps = @("Word", "Excel", "PowerPoint", "Outlook")
    
    $officeFound = $false
    
    foreach ($version in $officeVersions) {
        foreach ($app in $officeApps) {
            $macroSetting = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security" -Name "VBAWarnings" -ErrorAction SilentlyContinue
            
            if ($macroSetting) {
                $officeFound = $true
                $warningLevel = $macroSetting.VBAWarnings
                
                switch ($warningLevel) {
                    1 {
                        Add-Result -Category "MS - Office Security" -Status "Fail" `
                            -Message "Office ${app}: Macros enabled without warnings" `
                            -Details "MS Baseline: Critical - all macros run without notification" `
                            -Remediation "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security' -Name VBAWarnings -Value 3 -Type DWord" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='CM-6' }
                    }
                    2 {
                        Add-Result -Category "MS - Office Security" -Status "Pass" `
                            -Message "Office ${app}: Macros disabled (all except digitally signed)" `
                            -Details "MS Baseline: Only signed macros with trusted publishers can run" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='CM-6' }
                    }
                    3 {
                        Add-Result -Category "MS - Office Security" -Status "Pass" `
                            -Message "Office ${app}: Macros disabled with notification" `
                            -Details "MS Baseline: User prompted before enabling macros" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='CM-6' }
                    }
                    4 {
                        Add-Result -Category "MS - Office Security" -Status "Pass" `
                            -Message "Office ${app}: Macros disabled (all)" `
                            -Details "MS Baseline: Most secure - all macros are blocked" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='CM-6' }
                    }
                }
                break
            }
        }
        if ($officeFound) { break }
    }
    
    # Check if Office is using protected view
    foreach ($version in $officeVersions) {
        $protectedView = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\Common\Security\FileBlock" -ErrorAction SilentlyContinue
        if ($protectedView) {
            Add-Result -Category "MS - Office Security" -Status "Pass" `
                -Message "Office: Protected View policies are configured" `
                -Details "MS Baseline: Files from potentially unsafe sources open in Protected View" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-6' }
            break
        }
    }
    
    if (-not $officeFound) {
        Add-Result -Category "MS - Office Security" -Status "Info" `
            -Message "Microsoft Office installation not detected or policies not configured" `
            -Details "MS Baseline: Office security settings are not applicable" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-6' }
    }
    
} catch {
    Add-Result -Category "MS - Office Security" -Status "Info" `
        -Message "Microsoft Office security check not applicable" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='CM-6' }
}

# ============================================================================
# SECTION 28: MICROSOFT STORE POLICIES
# ============================================================================
Write-Host "[MS] Checking Microsoft Store Policies..." -ForegroundColor Yellow

try {
    # Check if Store is disabled
    $storeDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue
    
    if ($storeDisabled -and $storeDisabled.RemoveWindowsStore -eq 1) {
        Add-Result -Category "MS - Microsoft Store" -Status "Info" `
            -Message "Microsoft Store is disabled" `
            -Details "MS Baseline: Store access blocked (common in enterprise environments)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='CM-11' }
    } else {
        # Check Store update settings
        $autoDownload = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -ErrorAction SilentlyContinue
        
        if ($autoDownload -and $autoDownload.AutoDownload -eq 2) {
            Add-Result -Category "MS - Microsoft Store" -Status "Info" `
                -Message "Microsoft Store: Auto-download is disabled" `
                -Details "MS Baseline: Store apps require manual approval" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-11' }
        } elseif ($autoDownload -and $autoDownload.AutoDownload -eq 4) {
            Add-Result -Category "MS - Microsoft Store" -Status "Pass" `
                -Message "Microsoft Store: Auto-download and install is enabled" `
                -Details "MS Baseline: Store apps update automatically" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-11' }
        }
    }
    
} catch {
    Add-Result -Category "MS - Microsoft Store" -Status "Info" `
        -Message "Microsoft Store policies not configured" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='CM-11' }
}

# ============================================================================
# SECTION 29: WINRM (WINDOWS REMOTE MANAGEMENT) SECURITY
# ============================================================================
Write-Host "[MS] Checking Windows Remote Management Security..." -ForegroundColor Yellow

try {
    $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    
    if ($winrmService -and $winrmService.Status -eq "Running") {
        Add-Result -Category "MS - WinRM Security" -Status "Info" `
            -Message "Windows Remote Management (WinRM) service is running" `
            -Details "MS Baseline: Verify WinRM security configuration if remote management is required" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
        
        # Check if WinRM is configured
        try {
            $winrmConfig = winrm get winrm/config 2>&1
            
            if ($winrmConfig -match "AllowUnencrypted\s*=\s*false") {
                Add-Result -Category "MS - WinRM Security" -Status "Pass" `
                    -Message "WinRM: Unencrypted traffic is blocked" `
                    -Details "MS Baseline: WinRM requires encrypted connections" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
            } elseif ($winrmConfig -match "AllowUnencrypted\s*=\s*true") {
                Add-Result -Category "MS - WinRM Security" -Status "Fail" `
                    -Message "WinRM: Unencrypted traffic is ALLOWED" `
                    -Details "MS Baseline: Critical - WinRM traffic can be sent in cleartext" `
                    -Remediation "winrm set winrm/config/service '@{AllowUnencrypted=`"false`"}'" `
                    -Severity "High" `
                    -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
            }
            
            if ($winrmConfig -match "Basic\s*=\s*false") {
                Add-Result -Category "MS - WinRM Security" -Status "Pass" `
                    -Message "WinRM: Basic authentication is disabled" `
                    -Details "MS Baseline: Prevents weak authentication over WinRM" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
            } elseif ($winrmConfig -match "Basic\s*=\s*true") {
                Add-Result -Category "MS - WinRM Security" -Status "Warning" `
                    -Message "WinRM: Basic authentication is enabled" `
                    -Details "MS Baseline: Weak authentication method - use Kerberos or Certificate" `
                    -Remediation "winrm set winrm/config/service/auth '@{Basic=`"false`"}'" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
            }
            
        } catch {
            Add-Result -Category "MS - WinRM Security" -Status "Info" `
                -Message "WinRM configuration could not be retrieved" `
                -Details "WinRM may not be configured: $_" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
        }
        
    } else {
        Add-Result -Category "MS - WinRM Security" -Status "Pass" `
            -Message "Windows Remote Management service is not running" `
            -Details "MS Baseline: WinRM remote management is disabled" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-17'; CIS='18.9.102' }
    }
    
} catch {
    Add-Result -Category "MS - WinRM Security" -Status "Error" `
        -Message "Failed to check WinRM: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 30: REMOTE ASSISTANCE
# ============================================================================
Write-Host "[MS] Checking Remote Assistance Configuration..." -ForegroundColor Yellow

try {
    $remoteAssist = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
    
    if ($remoteAssist -and $remoteAssist.fAllowToGetHelp -eq 0) {
        Add-Result -Category "MS - Remote Assistance" -Status "Pass" `
            -Message "Remote Assistance is disabled" `
            -Details "MS Baseline: Remote Assistance connections are not allowed" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-17' }
    } elseif ($remoteAssist -and $remoteAssist.fAllowToGetHelp -eq 1) {
        Add-Result -Category "MS - Remote Assistance" -Status "Warning" `
            -Message "Remote Assistance is enabled" `
            -Details "MS Baseline: Consider disabling if not required for support" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0 -Type DWord" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='AC-17' }
        
        # Check if unsolicited assistance is allowed
        $unsolicited = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowUnsolicited" -ErrorAction SilentlyContinue
        
        if ($unsolicited -and $unsolicited.fAllowUnsolicited -eq 1) {
            Add-Result -Category "MS - Remote Assistance" -Status "Fail" `
                -Message "Remote Assistance: Unsolicited assistance is allowed" `
                -Details "MS Baseline: Remote users can connect without invitation - security risk" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowUnsolicited -Value 0 -Type DWord" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='AC-17' }
        }
    }
    
} catch {
    Add-Result -Category "MS - Remote Assistance" -Status "Error" `
        -Message "Failed to check Remote Assistance: $_" `
        -Severity "Medium"
}

# ============================================================================
# SECTION 31: APPLOCKER CONFIGURATION
# ============================================================================
Write-Host "[MS] Checking AppLocker Configuration..." -ForegroundColor Yellow

try {
    $applockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    
    if ($applockerService) {
        if ($applockerService.Status -eq "Running") {
            Add-Result -Category "MS - AppLocker" -Status "Pass" `
                -Message "AppLocker service (Application Identity) is running" `
                -Details "MS Baseline: AppLocker application control is active" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7(5)'; STIG='V-220862' }
            
            # Check if policies are configured
            try {
                $applockerPolicies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
                
                if ($applockerPolicies -and $applockerPolicies.RuleCollections) {
                    $ruleCount = 0
                    foreach ($collection in $applockerPolicies.RuleCollections) {
                        $ruleCount += $collection.Count
                    }
                    
                    if ($ruleCount -gt 0) {
                        Add-Result -Category "MS - AppLocker" -Status "Pass" `
                            -Message "AppLocker policies are configured ($ruleCount rules)" `
                            -Details "MS Baseline: Application whitelisting is enforced" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='CM-7(5)'; STIG='V-220862' }
                    } else {
                        Add-Result -Category "MS - AppLocker" -Status "Info" `
                            -Message "AppLocker service is running but no policies configured" `
                            -Details "MS Baseline: Configure AppLocker rules for application control" `
                            -Severity "Medium" `
                            -CrossReferences @{ NIST='CM-7(5)'; STIG='V-220862' }
                    }
                }
            } catch {
                Add-Result -Category "MS - AppLocker" -Status "Info" `
                    -Message "AppLocker policy status could not be determined" `
                    -Details "AppLocker cmdlets may not be available" `
                    -Severity "Medium" `
                    -CrossReferences @{ NIST='CM-7(5)'; STIG='V-220862' }
            }
        } else {
            Add-Result -Category "MS - AppLocker" -Status "Info" `
                -Message "AppLocker service is not running" `
                -Details "MS Baseline: Application control via AppLocker is not active" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='CM-7(5)'; STIG='V-220862' }
        }
    }
    
} catch {
    Add-Result -Category "MS - AppLocker" -Status "Info" `
        -Message "AppLocker not available or configured on this system" `
        -Severity "Medium" `
        -CrossReferences @{ NIST='CM-7(5)'; STIG='V-220862' }
}

# ============================================================================
# SECTION 32: LOCAL ADMINISTRATOR PASSWORD SOLUTION (LAPS)
# ============================================================================
Write-Host "[MS] Checking for LAPS Configuration..." -ForegroundColor Yellow

try {
    # Check if LAPS is installed
    $lapsInstalled = Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll" -ErrorAction SilentlyContinue
    
    if ($lapsInstalled) {
        Add-Result -Category "MS - LAPS" -Status "Pass" `
            -Message "Microsoft LAPS is installed" `
            -Details "MS Baseline: Local Administrator Password Solution provides automated password management" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5'; CIS='18.2.1' }
        
        # Check if LAPS is enabled
        $lapsEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -ErrorAction SilentlyContinue
        
        if ($lapsEnabled -and $lapsEnabled.AdmPwdEnabled -eq 1) {
            Add-Result -Category "MS - LAPS" -Status "Pass" `
                -Message "LAPS is enabled and managing local admin passwords" `
                -Details "MS Baseline: Local administrator passwords are automatically rotated" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-5'; CIS='18.2.1' }
        } else {
            Add-Result -Category "MS - LAPS" -Status "Warning" `
                -Message "LAPS is installed but not enabled" `
                -Details "MS Baseline: Enable LAPS via Group Policy" `
                -Remediation "Configure via GPO: Computer Configuration `> Policies `> Administrative Templates `> LAPS" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='IA-5'; CIS='18.2.1' }
        }
    } else {
        Add-Result -Category "MS - LAPS" -Status "Info" `
            -Message "Microsoft LAPS is not installed" `
            -Details "MS Baseline: Consider deploying LAPS for local administrator password management" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='IA-5'; CIS='18.2.1' }
    }
    
} catch {
    Add-Result -Category "MS - LAPS" -Status "Error" `
        -Message "Failed to check LAPS: $_" `
        -Severity "Medium"
}

Write-Host "`n[MS] Sections 1-32 checks complete" -ForegroundColor Cyan


# ============================================================================
# v6.1: Windows 11 24H2 / Server 2025 baseline alignment
# ============================================================================
Write-Host "[MS] Checking Windows 11 24H2 / Server 2025 baseline alignment..." -ForegroundColor Yellow

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $build = [int]$os.BuildNumber
        $product = $os.ProductType
        $productLabel = switch ($product) {
            1 { 'Workstation' }
            2 { 'Domain Controller' }
            3 { 'Member Server' }
            default { 'Unknown' }
        }

        if ($build -ge 26100) {
            $osLabel = if ($product -eq 1) { 'Windows 11 24H2' } else { 'Windows Server 2025' }
            Add-Result -Category "MS - Modern Baseline" -Status "Pass" `
                -Severity "Low" `
                -Message "OS at $osLabel build level (build $build, $productLabel)" `
                -Details "Microsoft Security Baseline 24H2 / Server 2025 applicable" `
                -CrossReferences @{ MS='Baseline 24H2/2025'; Build="$build" }
        }
        elseif ($build -ge 22631) {
            Add-Result -Category "MS - Modern Baseline" -Status "Pass" `
                -Severity "Low" `
                -Message "OS at Windows 11 23H2 build level (build $build, $productLabel)" `
                -Details "Microsoft Security Baseline 23H2 applicable; consider 24H2 upgrade path" `
                -CrossReferences @{ MS='Baseline 23H2'; Build="$build" }
        }
        elseif ($build -ge 22000) {
            Add-Result -Category "MS - Modern Baseline" -Status "Info" `
                -Severity "Informational" `
                -Message "OS at Windows 11 21H2/22H2 baseline (build $build, $productLabel)" `
                -CrossReferences @{ MS='Baseline 21H2/22H2' }
        }
        elseif ($build -ge 19041) {
            Add-Result -Category "MS - Modern Baseline" -Status "Info" `
                -Severity "Informational" `
                -Message "OS at Windows 10 baseline (build $build); plan for Windows 11 transition by October 2025" `
                -CrossReferences @{ MS='Baseline Win10' }
        }
        elseif ($build -ge 17763) {
            Add-Result -Category "MS - Modern Baseline" -Status "Warning" `
                -Severity "Medium" `
                -Message "OS at Windows 10 1809/Server 2019 baseline (build $build)" `
                -CrossReferences @{ MS='Baseline 1809/2019' }
        }
        else {
            Add-Result -Category "MS - Modern Baseline" -Status "Fail" `
                -Severity "High" `
                -Message "OS below current support window (build $build)" `
                -CrossReferences @{ MS='Unsupported OS' }
        }
    }
}
catch {
    Add-Result -Category "MS - Modern Baseline" -Status "Error" `
        -Severity "Medium" `
        -Message "OS baseline detection failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Microsoft Edge security baseline
# ============================================================================
Write-Host "[MS] Checking Microsoft Edge security baseline..." -ForegroundColor Yellow

try {
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

    $smartScreen = Get-RegValue -Path $edgePath -Name "SmartScreenEnabled" -Default $null
    if ($smartScreen -eq 1) {
        Add-Result -Category "MS - Edge Baseline" -Status "Pass" `
            -Severity "Medium" `
            -Message "Edge SmartScreen enabled" `
            -CrossReferences @{ MS='Edge SmartScreen' }
    }
    elseif ($smartScreen -eq 0) {
        Add-Result -Category "MS - Edge Baseline" -Status "Fail" `
            -Severity "High" `
            -Message "Edge SmartScreen explicitly disabled" `
            -Remediation "Set-ItemProperty -Path '$edgePath' -Name 'SmartScreenEnabled' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='Edge SmartScreen' }
    }
    else {
        Add-Result -Category "MS - Edge Baseline" -Status "Info" `
            -Severity "Informational" `
            -Message "Edge SmartScreen policy not configured (default enabled)" `
            -CrossReferences @{ MS='Edge SmartScreen' }
    }

    $smartScreenOverride = Get-RegValue -Path $edgePath -Name "PreventSmartScreenPromptOverride" -Default $null
    if ($smartScreenOverride -eq 1) {
        Add-Result -Category "MS - Edge Baseline" -Status "Pass" `
            -Severity "Medium" `
            -Message "Edge SmartScreen prompt override prevented for malicious sites" `
            -CrossReferences @{ MS='Edge SmartScreen Override' }
    }
    else {
        Add-Result -Category "MS - Edge Baseline" -Status "Warning" `
            -Severity "Medium" `
            -Message "Edge SmartScreen override prevention not configured" `
            -Remediation "Set-ItemProperty -Path '$edgePath' -Name 'PreventSmartScreenPromptOverride' -Value 1 -Type DWord" `
            -CrossReferences @{ MS='Edge SmartScreen Override' }
    }

    $passwordMgr = Get-RegValue -Path $edgePath -Name "PasswordManagerEnabled" -Default $null
    if ($passwordMgr -eq 0) {
        Add-Result -Category "MS - Edge Baseline" -Status "Pass" `
            -Severity "Low" `
            -Message "Edge built-in password manager disabled (enterprise password tooling expected)" `
            -CrossReferences @{ MS='Edge Password Mgr' }
    }
    elseif ($passwordMgr -eq 1 -or $null -eq $passwordMgr) {
        Add-Result -Category "MS - Edge Baseline" -Status "Info" `
            -Severity "Informational" `
            -Message "Edge built-in password manager enabled (default)" `
            -CrossReferences @{ MS='Edge Password Mgr' }
    }

    $autofillCC = Get-RegValue -Path $edgePath -Name "AutofillCreditCardEnabled" -Default $null
    if ($autofillCC -eq 0) {
        Add-Result -Category "MS - Edge Baseline" -Status "Pass" `
            -Severity "Medium" `
            -Message "Edge credit card autofill disabled" `
            -CrossReferences @{ MS='Edge CC Autofill' }
    }
    else {
        Add-Result -Category "MS - Edge Baseline" -Status "Warning" `
            -Severity "Medium" `
            -Message "Edge credit card autofill not explicitly disabled" `
            -Remediation "Set-ItemProperty -Path '$edgePath' -Name 'AutofillCreditCardEnabled' -Value 0 -Type DWord" `
            -CrossReferences @{ MS='Edge CC Autofill' }
    }

    $tlsMin = Get-RegValue -Path $edgePath -Name "SSLVersionMin" -Default $null
    if ($tlsMin -eq 'tls1.2' -or $tlsMin -eq 'tls1.3') {
        Add-Result -Category "MS - Edge Baseline" -Status "Pass" `
            -Severity "Medium" `
            -Message "Edge minimum TLS version: $tlsMin" `
            -CrossReferences @{ MS='Edge TLS Min' }
    }
    elseif ($null -eq $tlsMin) {
        Add-Result -Category "MS - Edge Baseline" -Status "Info" `
            -Severity "Informational" `
            -Message "Edge minimum TLS version not configured (browser default)" `
            -CrossReferences @{ MS='Edge TLS Min' }
    }
    else {
        Add-Result -Category "MS - Edge Baseline" -Status "Warning" `
            -Severity "Medium" `
            -Message "Edge minimum TLS version below 1.2: $tlsMin" `
            -Remediation "Set-ItemProperty -Path '$edgePath' -Name 'SSLVersionMin' -Value 'tls1.2' -Type String" `
            -CrossReferences @{ MS='Edge TLS Min' }
    }

    $cookiesPolicy = Get-RegValue -Path $edgePath -Name "DefaultCookiesSetting" -Default $null
    if ($cookiesPolicy -eq 4) {
        Add-Result -Category "MS - Edge Baseline" -Status "Pass" `
            -Severity "Low" `
            -Message "Edge cookies session-only by default" `
            -CrossReferences @{ MS='Edge Cookies' }
    }
}
catch {
    Add-Result -Category "MS - Edge Baseline" -Status "Error" `
        -Severity "Medium" `
        -Message "Edge baseline assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Microsoft 365 Apps for Enterprise security baseline
# ============================================================================
Write-Host "[MS] Checking Microsoft 365 Apps security baseline..." -ForegroundColor Yellow

try {
    $officePath = "HKLM:\SOFTWARE\Policies\Microsoft\Office"
    $officePresent = Test-Path $officePath -ErrorAction SilentlyContinue

    if ($officePresent) {
        Add-Result -Category "MS - M365 Apps Baseline" -Status "Pass" `
            -Severity "Low" `
            -Message "Office policy infrastructure present" `
            -CrossReferences @{ MS='M365 Apps Baseline' }

        $excelPath = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security"
        $excelMacroBlock = Get-RegValue -Path $excelPath -Name "VBAWarnings" -Default $null
        if ($excelMacroBlock -eq 4) {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Pass" `
                -Severity "High" `
                -Message "Excel: macros disabled with no notification (most restrictive)" `
                -CrossReferences @{ MS='Office Macros' }
        }
        elseif ($excelMacroBlock -eq 3) {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Pass" `
                -Severity "Medium" `
                -Message "Excel: digitally signed macros only" `
                -CrossReferences @{ MS='Office Macros' }
        }
        elseif ($null -ne $excelMacroBlock) {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Warning" `
                -Severity "High" `
                -Message "Excel: macro setting permissive (VBAWarnings=$excelMacroBlock)" `
                -CrossReferences @{ MS='Office Macros' }
        }

        $internetMacroBlock = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security" -Name "BlockContentExecutionFromInternet" -Default $null
        if ($internetMacroBlock -eq 1) {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Pass" `
                -Severity "High" `
                -Message "Excel: macro execution from Internet zone blocked" `
                -CrossReferences @{ MS='Office Internet Macros' }
        }
        else {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Warning" `
                -Severity "High" `
                -Message "Excel: Internet macro block not configured" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security' -Name 'BlockContentExecutionFromInternet' -Value 1 -Type DWord" `
                -CrossReferences @{ MS='Office Internet Macros' }
        }

        $protectedView = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Default $null
        if ($protectedView -eq 0 -or $null -eq $protectedView) {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Pass" `
                -Severity "Medium" `
                -Message "Word: Protected View enabled for Internet files" `
                -CrossReferences @{ MS='Office Protected View' }
        }
        elseif ($protectedView -eq 1) {
            Add-Result -Category "MS - M365 Apps Baseline" -Status "Fail" `
                -Severity "High" `
                -Message "Word: Protected View disabled for Internet files" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security\ProtectedView' -Name 'DisableInternetFilesInPV' -Value 0 -Type DWord" `
                -CrossReferences @{ MS='Office Protected View' }
        }
    }
    else {
        Add-Result -Category "MS - M365 Apps Baseline" -Status "Info" `
            -Severity "Informational" `
            -Message "Microsoft Office policy infrastructure not present (Office not installed or unmanaged)" `
            -CrossReferences @{ MS='M365 Apps Baseline' }
    }
}
catch {
    Add-Result -Category "MS - M365 Apps Baseline" -Status "Error" `
        -Severity "Medium" `
        -Message "M365 Apps baseline assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Microsoft Security Compliance Toolkit (MSCT) signal extraction
# ============================================================================
Write-Host "[MS] Checking Security Compliance Toolkit deployment indicators..." -ForegroundColor Yellow

try {
    $lgpoMarker = Test-Path "HKLM:\SOFTWARE\LGPO" -ErrorAction SilentlyContinue
    if ($lgpoMarker) {
        Add-Result -Category "MS - SCT Indicators" -Status "Info" `
            -Severity "Informational" `
            -Message "LGPO marker present (Microsoft Security Compliance Toolkit deployment evidence)" `
            -Details "Microsoft Security Compliance Toolkit (SCT) provides Local Group Policy Object (LGPO) deployment of baselines" `
            -CrossReferences @{ MS='SCT'; Tool='LGPO' }
    }

    $policyManager = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device" -Name "EnrolledBy" -Default $null
    if ($policyManager) {
        Add-Result -Category "MS - SCT Indicators" -Status "Info" `
            -Severity "Informational" `
            -Message "Policy Manager evidence: $policyManager (Intune/CSP deployment likely)" `
            -CrossReferences @{ MS='Policy Manager' }
    }

    $gpoEnforcementPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State"
    if (Test-Path $gpoEnforcementPath -ErrorAction SilentlyContinue) {
        Add-Result -Category "MS - SCT Indicators" -Status "Pass" `
            -Severity "Low" `
            -Message "Group Policy state infrastructure present" `
            -CrossReferences @{ MS='Group Policy' }
    }
}
catch {
    Add-Result -Category "MS - SCT Indicators" -Status "Error" `
        -Severity "Low" `
        -Message "SCT indicator detection failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Pluton security processor and DRTM signals
# ============================================================================
Write-Host "[MS] Checking Pluton and DRTM signals..." -ForegroundColor Yellow

try {
    $plutonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PlutonHsm"
    if (Test-Path $plutonPath -ErrorAction SilentlyContinue) {
        Add-Result -Category "MS - Pluton/DRTM" -Status "Pass" `
            -Severity "Medium" `
            -Message "Pluton security processor service present" `
            -CrossReferences @{ MS='Pluton' }
    }
    else {
        Add-Result -Category "MS - Pluton/DRTM" -Status "Info" `
            -Severity "Informational" `
            -Message "Pluton not detected (hardware-dependent feature)" `
            -CrossReferences @{ MS='Pluton' }
    }

    $drtm = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "ConfigureSystemGuardLaunch" -Default $null
    if ($drtm -eq 1) {
        Add-Result -Category "MS - Pluton/DRTM" -Status "Pass" `
            -Severity "High" `
            -Message "Dynamic Root of Trust for Measurement (DRTM) configured" `
            -Details "System Guard Secure Launch protects firmware integrity through DRTM" `
            -CrossReferences @{ MS='DRTM'; NIST='SI-7' }
    }
    elseif ($drtm -eq 0) {
        Add-Result -Category "MS - Pluton/DRTM" -Status "Warning" `
            -Severity "Medium" `
            -Message "DRTM explicitly disabled" `
            -CrossReferences @{ MS='DRTM' }
    }
    else {
        Add-Result -Category "MS - Pluton/DRTM" -Status "Info" `
            -Severity "Informational" `
            -Message "DRTM policy not configured" `
            -CrossReferences @{ MS='DRTM' }
    }
}
catch {
    Add-Result -Category "MS - Pluton/DRTM" -Status "Error" `
        -Severity "Low" `
        -Message "Pluton/DRTM query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Smart App Control state
# ============================================================================
Write-Host "[MS] Checking Smart App Control state..." -ForegroundColor Yellow

try {
    $sacPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
    $sacState = Get-RegValue -Path $sacPath -Name "VerifiedAndReputablePolicyState" -Default $null

    switch ($sacState) {
        0 {
            Add-Result -Category "MS - Smart App Control" -Status "Info" `
                -Severity "Informational" `
                -Message "Smart App Control: Off" `
                -Details "Smart App Control restricts execution to verified-and-reputable applications; once turned off it cannot be re-enabled without OS reinstall" `
                -CrossReferences @{ MS='Smart App Control' }
        }
        1 {
            Add-Result -Category "MS - Smart App Control" -Status "Pass" `
                -Severity "High" `
                -Message "Smart App Control: Enforce mode" `
                -CrossReferences @{ MS='Smart App Control' }
        }
        2 {
            Add-Result -Category "MS - Smart App Control" -Status "Info" `
                -Severity "Informational" `
                -Message "Smart App Control: Evaluation mode" `
                -CrossReferences @{ MS='Smart App Control' }
        }
        default {
            Add-Result -Category "MS - Smart App Control" -Status "Info" `
                -Severity "Informational" `
                -Message "Smart App Control: state not assessable (Win11 22H2+ feature)" `
                -CrossReferences @{ MS='Smart App Control' }
        }
    }
}
catch {
    Add-Result -Category "MS - Smart App Control" -Status "Error" `
        -Severity "Low" `
        -Message "Smart App Control query failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: Microsoft cloud-managed update channels
# ============================================================================
Write-Host "[MS] Checking cloud-managed update channels..." -ForegroundColor Yellow

try {
    $ufbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $branch = Get-RegValue -Path $ufbPath -Name "BranchReadinessLevel" -Default $null
    switch ($branch) {
        16 {
            Add-Result -Category "MS - Update Channels" -Status "Pass" `
                -Severity "Low" `
                -Message "Update channel: General Availability (semi-annual production)" `
                -CrossReferences @{ MS='Update Channel' }
        }
        32 {
            Add-Result -Category "MS - Update Channels" -Status "Info" `
                -Severity "Informational" `
                -Message "Update channel: General Availability with deferral" `
                -CrossReferences @{ MS='Update Channel' }
        }
        $null {
            Add-Result -Category "MS - Update Channels" -Status "Info" `
                -Severity "Informational" `
                -Message "Update channel policy not configured (Windows Update default)" `
                -CrossReferences @{ MS='Update Channel' }
        }
        default {
            Add-Result -Category "MS - Update Channels" -Status "Warning" `
                -Severity "Medium" `
                -Message "Update channel non-standard: BranchReadinessLevel=$branch" `
                -CrossReferences @{ MS='Update Channel' }
        }
    }

    $deferQuality = Get-RegValue -Path $ufbPath -Name "DeferQualityUpdatesPeriodInDays" -Default $null
    if ($null -ne $deferQuality -and $deferQuality -gt 30) {
        Add-Result -Category "MS - Update Channels" -Status "Warning" `
            -Severity "High" `
            -Message "Quality update deferral exceeds 30 days ($deferQuality days)" `
            -Details "Extended deferral leaves the system exposed to known vulnerabilities" `
            -CrossReferences @{ MS='Update Deferral' }
    }
    elseif ($null -ne $deferQuality) {
        Add-Result -Category "MS - Update Channels" -Status "Pass" `
            -Severity "Low" `
            -Message "Quality update deferral within reasonable bounds ($deferQuality days)" `
            -CrossReferences @{ MS='Update Deferral' }
    }
}
catch {
    Add-Result -Category "MS - Update Channels" -Status "Error" `
        -Severity "Low" `
        -Message "Update channel query failed: $($_.Exception.Message)"
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

Write-Host "`n[MS] ======================================================================" -ForegroundColor Cyan
Write-Host "[MS] MODULE COMPLETED -- v$moduleVersion" -ForegroundColor Cyan
Write-Host "[MS] ======================================================================" -ForegroundColor Cyan
Write-Host "[MS] Total Checks Executed: $totalChecks" -ForegroundColor White
Write-Host "[MS]" -ForegroundColor Cyan
Write-Host "[MS] Results Summary:" -ForegroundColor Cyan
$pctPass = if ($totalChecks -gt 0) { [Math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }
Write-Host "[MS]   Passed:   $($passCount.ToString().PadLeft(3)) ($pctPass`%)" -ForegroundColor Green
Write-Host "[MS]   Failed:   $($failCount.ToString().PadLeft(3))" -ForegroundColor Red
Write-Host "[MS]   Warnings: $($warnCount.ToString().PadLeft(3))" -ForegroundColor Yellow
Write-Host "[MS]   Info:     $($infoCount.ToString().PadLeft(3))" -ForegroundColor Cyan
Write-Host "[MS]   Errors:   $($errorCount.ToString().PadLeft(3))" -ForegroundColor Magenta
Write-Host "[MS]" -ForegroundColor Cyan
Write-Host "[MS] Check Categories:" -ForegroundColor Cyan
foreach ($cat in ($categoryStats.Keys | Sort-Object)) {
    Write-Host "[MS]   $($cat.PadRight(45)): $($categoryStats[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
}
Write-Host "[MS]" -ForegroundColor Cyan
Write-Host "[MS] Failed Check Severity:" -ForegroundColor Cyan
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
    $sevColor = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; 'Low' { 'Cyan' }; default { 'Gray' } }
    Write-Host "[MS]   $($sev.PadRight(15)): $($severityStats[$sev])" -ForegroundColor $sevColor
}
Write-Host "[MS] ======================================================================`n" -ForegroundColor Cyan

return $results

# ============================================================================
# Standalone Execution Support
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host "  Microsoft Security Baseline -- Standalone Test v$moduleVersion" -ForegroundColor Cyan
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
    Write-Host "  MS module standalone test complete -- $($results.Count) checks" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
