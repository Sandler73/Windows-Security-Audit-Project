# module-acsc.ps1
# ACSC Essential Eight Compliance Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against the Australian Cyber Security Centre (ACSC)
# Essential Eight mitigation strategies with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    ACSC Essential Eight compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with the ACSC Essential Eight strategies:
    - E1: Application Control (whitelisting, AppLocker, WDAC)
    - E2: Patch Applications (third-party patching, browser updates)
    - E3: Configure Microsoft Office Macro Settings (macro restrictions, trust)
    - E4: User Application Hardening (Flash, ads, Java, OLE blocking)
    - E5: Restrict Administrative Privileges (admin count, UAC, token filtering)
    - E6: Patch Operating Systems (OS updates, hotfix recency, EOL detection)
    - E7: Multi-Factor Authentication (Windows Hello, credential guard, smart card)
    - E8: Regular Backups (VSS, System Restore, BitLocker recovery)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: ACSC Essential Eight Maturity Model (July 2023),
                ACSC Strategies to Mitigate Cyber Security Incidents
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-acsc.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "ACSC"
$moduleVersion = "6.0"
$results = @()

# ---------------------------------------------------------------------------
# Helper function to add results with severity and cross-references
# ---------------------------------------------------------------------------
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
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) { return $item.$Name }
    } catch { }
    return $Default
}

Write-Host "`n[$moduleName] Starting ACSC Essential Eight checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# E1 -- Application Control
# ===========================================================================
Write-Host "[ACSC] Checking E1 -- Application Control..." -ForegroundColor Yellow

    # E1.1: AppLocker service status
    try {
        $applockerSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        if ($null -ne $applockerSvc -and $applockerSvc.Status -eq 'Running') {
            Add-Result -Category "ACSC - E1 App Control" -Status "Pass" `
                -Message "E1.1: AppLocker service (AppIDSvc) is running" `
                -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)'; CIS='6.1' }
        } elseif ($null -ne $applockerSvc) {
            Add-Result -Category "ACSC - E1 App Control" -Status "Warning" `
                -Message "E1.1: AppLocker service exists but is not running (status: $($applockerSvc.Status))" `
                -Remediation "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service AppIDSvc" `
                -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)'; CIS='6.1' }
        } else {
            Add-Result -Category "ACSC - E1 App Control" -Status "Fail" `
                -Message "E1.1: AppLocker service (AppIDSvc) is not available" `
                -Remediation "Enable AppLocker via Group Policy or deploy WDAC policies" `
                -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)'; CIS='6.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E1 App Control" -Status "Error" `
            -Message "E1.1: AppLocker service check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)' }
    }
    # E1.2: AppLocker executable rules
    try {
        $exeRules = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' }
        $ruleCount = if ($null -ne $exeRules) { @($exeRules.Count) } else { 0 }
        if ($ruleCount -gt 0) {
            Add-Result -Category "ACSC - E1 App Control" -Status "Pass" `
                -Message "E1.2: AppLocker executable rules are configured ($ruleCount rule collection(s))" `
                -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)' }
        } else {
            Add-Result -Category "ACSC - E1 App Control" -Status "Warning" `
                -Message "E1.2: No AppLocker executable rules detected" `
                -Remediation "Configure AppLocker executable rules via Group Policy" `
                -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)' }
        }
    } catch {
        Add-Result -Category "ACSC - E1 App Control" -Status "Info" `
            -Message "E1.2: Could not query AppLocker policy (may not be configured)" `
            -Severity "High" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)' }
    }
    # E1.3: WDAC (Windows Defender Application Control) status
    try {
        $wdacStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction SilentlyContinue
        if ($null -ne $wdacStatus -and $wdacStatus.CodeIntegrityPolicyEnforcementStatus -eq 2) {
            Add-Result -Category "ACSC - E1 App Control" -Status "Pass" `
                -Message "E1.3: Windows Defender Application Control (WDAC) is enforced" `
                -Severity "Critical" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)'; STIG='V-63597' }
        } elseif ($null -ne $wdacStatus -and $wdacStatus.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Add-Result -Category "ACSC - E1 App Control" -Status "Warning" `
                -Message "E1.3: WDAC is in audit mode (not enforcing)" `
                -Remediation "Switch WDAC policy from audit to enforced mode" `
                -Severity "High" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)'; STIG='V-63597' }
        } else {
            Add-Result -Category "ACSC - E1 App Control" -Status "Info" `
                -Message "E1.3: WDAC is not configured" `
                -Remediation "Deploy a WDAC code integrity policy" `
                -Severity "High" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)'; STIG='V-63597' }
        }
    } catch {
        Add-Result -Category "ACSC - E1 App Control" -Status "Error" `
            -Message "E1.3: WDAC check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E1'; NIST='CM-7(5)' }
    }
    # E1.4: Software Restriction Policies (SRP)
    try {
        $srpLevel = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "DefaultLevel" -Default $null
        if ($null -ne $srpLevel -and $srpLevel -eq 0) {
            Add-Result -Category "ACSC - E1 App Control" -Status "Pass" `
                -Message "E1.4: Software Restriction Policies set to Disallowed by default" `
                -Severity "High" -CrossReferences @{ ACSC='E1'; NIST='CM-7(2)' }
        } elseif ($null -ne $srpLevel) {
            Add-Result -Category "ACSC - E1 App Control" -Status "Info" `
                -Message "E1.4: Software Restriction Policies configured (default level=$srpLevel)" `
                -Severity "Medium" -CrossReferences @{ ACSC='E1'; NIST='CM-7(2)' }
        } else {
            Add-Result -Category "ACSC - E1 App Control" -Status "Info" `
                -Message "E1.4: Software Restriction Policies not configured" `
                -Severity "Low" -CrossReferences @{ ACSC='E1'; NIST='CM-7(2)' }
        }
    } catch {
        Add-Result -Category "ACSC - E1 App Control" -Status "Error" `
            -Message "E1.4: SRP check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E1'; NIST='CM-7(2)' }
    }
    # E1.5: PowerShell Constrained Language Mode
    try {
        $langMode = $ExecutionContext.SessionState.LanguageMode
        if ($langMode -eq 'ConstrainedLanguage') {
            Add-Result -Category "ACSC - E1 App Control" -Status "Pass" `
                -Message "E1.5: PowerShell is in Constrained Language Mode" `
                -Severity "High" -CrossReferences @{ ACSC='E1'; NIST='CM-7'; CIS='18.9.100' }
        } else {
            Add-Result -Category "ACSC - E1 App Control" -Status "Info" `
                -Message "E1.5: PowerShell is in $langMode mode (ConstrainedLanguage recommended for hardened systems)" `
                -Severity "Medium" -CrossReferences @{ ACSC='E1'; NIST='CM-7'; CIS='18.9.100' }
        }
    } catch {
        Add-Result -Category "ACSC - E1 App Control" -Status "Error" `
            -Message "E1.5: Language mode check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E1'; NIST='CM-7' }
    }

# ===========================================================================
# E2 -- Patch Applications
# ===========================================================================
Write-Host "[ACSC] Checking E2 -- Patch Applications..." -ForegroundColor Yellow

    # E2.1: Microsoft Office version/updates
    try {
        $officeKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
            "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstalledPackages"
        )
        $officeVer = $null
        foreach ($key in $officeKeys) {
            $ver = Get-RegValue -Path $key -Name "VersionToReport" -Default $null
            if ($null -ne $ver) { $officeVer = $ver; break }
        }
        if ($null -ne $officeVer) {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Info" `
                -Message "E2.1: Microsoft Office version detected: $officeVer" `
                -Details "Verify this is the latest available version for your channel" `
                -Severity "High" -CrossReferences @{ ACSC='E2'; NIST='SI-2'; ISO27001='A.8.8' }
        } else {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Info" `
                -Message "E2.1: Microsoft Office not detected via Click-to-Run" `
                -Severity "Informational" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ACSC - E2 Patch Apps" -Status "Error" `
            -Message "E2.1: Office version check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
    }
    # E2.2: .NET Framework version
    try {
        $dotnetRel = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release" -Default 0
        $dotnetVer = switch ([int]$dotnetRel) {
            {$_ -ge 533320} { "4.8.1+" }
            {$_ -ge 528040} { "4.8" }
            {$_ -ge 461808} { "4.7.2" }
            {$_ -ge 461308} { "4.7.1" }
            {$_ -ge 460798} { "4.7" }
            {$_ -ge 394802} { "4.6.2" }
            default { "below 4.6.2 (release $dotnetRel)" }
        }
        if ([int]$dotnetRel -ge 528040) {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Pass" `
                -Message "E2.2: .NET Framework version $dotnetVer is current" `
                -Severity "Medium" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
        } else {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Warning" `
                -Message "E2.2: .NET Framework version $dotnetVer -- update recommended" `
                -Remediation "Install latest .NET Framework via Windows Update" `
                -Severity "Medium" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ACSC - E2 Patch Apps" -Status "Error" `
            -Message "E2.2: .NET Framework check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
    }
    # E2.3: Java Runtime installed (flag for review)
    try {
        $javaPath = Get-RegValue -Path "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment" -Name "CurrentVersion" -Default $null
        if ($null -ne $javaPath) {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Warning" `
                -Message "E2.3: Java Runtime Environment detected (version: $javaPath) -- verify patched" `
                -Remediation "Update Java to latest version or remove if not needed" `
                -Severity "High" -CrossReferences @{ ACSC='E2'; NIST='SI-2'; CIS='2.2.1' }
        } else {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Pass" `
                -Message "E2.3: Java Runtime Environment not detected (reduced attack surface)" `
                -Severity "Low" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ACSC - E2 Patch Apps" -Status "Error" `
            -Message "E2.3: Java check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
    }
    # E2.4: Adobe Flash (should be removed)
    try {
        $flash = Get-RegValue -Path "HKLM:\SOFTWARE\Macromedia\FlashPlayer" -Name "CurrentVersion" -Default $null
        if ($null -eq $flash) {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Pass" `
                -Message "E2.4: Adobe Flash Player not detected (EOL removed)" `
                -Severity "Informational" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
        } else {
            Add-Result -Category "ACSC - E2 Patch Apps" -Status "Fail" `
                -Message "E2.4: Adobe Flash Player is STILL INSTALLED (version: $flash) -- EOL since Dec 2020" `
                -Remediation "Uninstall Adobe Flash Player immediately" `
                -Severity "Critical" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ACSC - E2 Patch Apps" -Status "Error" `
            -Message "E2.4: Flash check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E2'; NIST='SI-2' }
    }

# ===========================================================================
# E3 -- Configure Microsoft Office Macro Settings
# ===========================================================================
Write-Host "[ACSC] Checking E3 -- Office Macro Settings..." -ForegroundColor Yellow

    # E3.1: VBA macro execution policy
    try {
        $vbaMacro = Get-RegValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" -Name "VBAWarnings" -Default $null
        if ($null -ne $vbaMacro -and $vbaMacro -eq 4) {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Pass" `
                -Message "E3.1: Word VBA macros are disabled without notification" `
                -Severity "Critical" -CrossReferences @{ ACSC='E3'; NIST='SI-3'; CIS='1.1.1' }
        } elseif ($null -ne $vbaMacro -and $vbaMacro -eq 3) {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Warning" `
                -Message "E3.1: Word VBA macros require digital signature" `
                -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        } elseif ($null -ne $vbaMacro -and $vbaMacro -eq 2) {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Warning" `
                -Message "E3.1: Word VBA macros disabled with notification (user can enable)" `
                -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        } else {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Fail" `
                -Message "E3.1: Word VBA macro policy is not configured or set to enable" `
                -Remediation "Set VBAWarnings to 4 via Group Policy for all Office apps" `
                -Severity "Critical" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "ACSC - E3 Office Macros" -Status "Error" `
            -Message "E3.1: Word macro policy check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
    }
    # E3.2: Excel VBA macros
    try {
        $xlMacro = Get-RegValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Default $null
        if ($null -ne $xlMacro -and $xlMacro -ge 3) {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Pass" `
                -Message "E3.2: Excel VBA macro restrictions are configured (level=$xlMacro)" `
                -Severity "Critical" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        } else {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Fail" `
                -Message "E3.2: Excel VBA macro restrictions are not configured" `
                -Remediation "Set VBAWarnings to 4 via Group Policy for Excel" `
                -Severity "Critical" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "ACSC - E3 Office Macros" -Status "Error" `
            -Message "E3.2: Excel macro check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
    }
    # E3.3: Block macros from Internet-sourced files
    try {
        $blockInet = Get-RegValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" -Name "blockcontentexecutionfrominternet" -Default $null
        if ($null -ne $blockInet -and $blockInet -eq 1) {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Pass" `
                -Message "E3.3: Macros from Internet-sourced documents are blocked (Word)" `
                -Severity "Critical" -CrossReferences @{ ACSC='E3'; NIST='SI-3'; CMMC='SI.L2-3.14.2' }
        } else {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Fail" `
                -Message "E3.3: Internet-sourced macro blocking is NOT configured for Word" `
                -Remediation "Enable blockcontentexecutionfrominternet via GPO for all Office apps" `
                -Severity "Critical" -CrossReferences @{ ACSC='E3'; NIST='SI-3'; CMMC='SI.L2-3.14.2' }
        }
    } catch {
        Add-Result -Category "ACSC - E3 Office Macros" -Status "Error" `
            -Message "E3.3: Internet macro block check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
    }
    # E3.4: Win32 API calls from macros disabled
    try {
        $win32api = Get-RegValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" -Name "AccessVBOM" -Default $null
        if ($null -ne $win32api -and $win32api -eq 0) {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Pass" `
                -Message "E3.4: VBA access to Office object model is restricted" `
                -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        } else {
            Add-Result -Category "ACSC - E3 Office Macros" -Status "Warning" `
                -Message "E3.4: VBA access to Office object model may not be restricted" `
                -Remediation "Disable 'Trust access to the VBA project object model' via GPO" `
                -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "ACSC - E3 Office Macros" -Status "Error" `
            -Message "E3.4: VBA object model access check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E3'; NIST='SI-3' }
    }

# ===========================================================================
# E4 -- User Application Hardening
# ===========================================================================
Write-Host "[ACSC] Checking E4 -- User Application Hardening..." -ForegroundColor Yellow

    # E4.1: Flash content blocked in Office
    try {
        $flashKB = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Name "Compatibility Flags" -Default $null
        if ($null -ne $flashKB -and $flashKB -eq 1024) {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Pass" `
                -Message "E4.1: Flash content is blocked in Office via COM killbit" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SC-18'; CIS='2.7' }
        } else {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Info" `
                -Message "E4.1: Flash COM killbit not explicitly set (Flash may be EOL/removed already)" `
                -Severity "Low" -CrossReferences @{ ACSC='E4'; NIST='SC-18' }
        }
    } catch {
        Add-Result -Category "ACSC - E4 App Hardening" -Status "Error" `
            -Message "E4.1: Flash killbit check failed: $_" `
            -Severity "Low" -CrossReferences @{ ACSC='E4'; NIST='SC-18' }
    }
    # E4.2: OLE package activation blocked
    try {
        $oleBlock = Get-RegValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" -Name "PackagerPrompt" -Default $null
        if ($null -ne $oleBlock -and $oleBlock -eq 2) {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Pass" `
                -Message "E4.2: OLE package activation is blocked in Word" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SI-3' }
        } else {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Warning" `
                -Message "E4.2: OLE package activation may not be blocked in Word" `
                -Remediation "Set PackagerPrompt to 2 via GPO to block OLE packages" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "ACSC - E4 App Hardening" -Status "Error" `
            -Message "E4.2: OLE package check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SI-3' }
    }
    # E4.3: SmartScreen enabled
    try {
        $smartScreen = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Default $null
        if ($null -eq $smartScreen -or $smartScreen -ge 1) {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Pass" `
                -Message "E4.3: Windows SmartScreen is enabled" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SI-3'; CIS='18.9.85.1.1' }
        } else {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Fail" `
                -Message "E4.3: Windows SmartScreen is DISABLED" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 1" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SI-3'; CIS='18.9.85.1.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E4 App Hardening" -Status "Error" `
            -Message "E4.3: SmartScreen check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='SI-3' }
    }
    # E4.4: Windows Script Host access restricted
    try {
        $wshDisabled = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Default $null
        if ($null -ne $wshDisabled -and $wshDisabled -eq 0) {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Pass" `
                -Message "E4.4: Windows Script Host is disabled" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='CM-7' }
        } else {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Warning" `
                -Message "E4.4: Windows Script Host is enabled (vector for .vbs/.js malware)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 0" `
                -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='CM-7' }
        }
    } catch {
        Add-Result -Category "ACSC - E4 App Hardening" -Status "Error" `
            -Message "E4.4: WSH check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E4'; NIST='CM-7' }
    }
    # E4.5: AutoPlay disabled
    try {
        $autoplay = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default 0
        if ($autoplay -ge 255) {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Pass" `
                -Message "E4.5: AutoPlay is disabled for all drive types" `
                -Severity "Medium" -CrossReferences @{ ACSC='E4'; NIST='MP-7'; CIS='18.9.8.1' }
        } else {
            Add-Result -Category "ACSC - E4 App Hardening" -Status "Warning" `
                -Message "E4.5: AutoPlay is not fully disabled (value=$autoplay)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "Medium" -CrossReferences @{ ACSC='E4'; NIST='MP-7'; CIS='18.9.8.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E4 App Hardening" -Status "Error" `
            -Message "E4.5: AutoPlay check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E4'; NIST='MP-7' }
    }

# ===========================================================================
# E5 -- Restrict Administrative Privileges
# ===========================================================================
Write-Host "[ACSC] Checking E5 -- Restrict Administrative Privileges..." -ForegroundColor Yellow

    # E5.1: Administrator group count
    try {
        $admins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
        $adminCount = $admins.Count
        if ($adminCount -le 2) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Pass" `
                -Message "E5.1: Administrator group has $adminCount member(s) -- minimal privilege" `
                -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='AC-6(5)'; CIS='1.1.3' }
        } elseif ($adminCount -le 4) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Warning" `
                -Message "E5.1: Administrator group has $adminCount members -- review recommended" `
                -Remediation "Review and minimize administrator group membership" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6(5)'; CIS='1.1.3' }
        } else {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Fail" `
                -Message "E5.1: Administrator group has $adminCount members -- excessive" `
                -Remediation "Remove unnecessary accounts from Administrators group" `
                -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='AC-6(5)'; CIS='1.1.3' }
        }
    } catch {
        Add-Result -Category "ACSC - E5 Admin Privs" -Status "Error" `
            -Message "E5.1: Admin group check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='AC-6(5)' }
    }
    # E5.2: UAC enabled
    try {
        $uac = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default 0
        if ($uac -eq 1) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Pass" `
                -Message "E5.2: User Account Control (UAC) is enabled" `
                -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='AC-6'; CIS='2.3.17.6' }
        } else {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Fail" `
                -Message "E5.2: UAC is DISABLED" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='AC-6'; CIS='2.3.17.6' }
        }
    } catch {
        Add-Result -Category "ACSC - E5 Admin Privs" -Status "Error" `
            -Message "E5.2: UAC check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='AC-6' }
    }
    # E5.3: UAC prompt behavior for admins
    try {
        $consent = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Default $null
        if ($null -ne $consent -and $consent -eq 2) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Pass" `
                -Message "E5.3: Admin UAC prompt requires consent on secure desktop" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6(1)'; CIS='2.3.17.1' }
        } elseif ($null -ne $consent -and $consent -le 3) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Warning" `
                -Message "E5.3: Admin UAC prompt behavior is set to level $consent (recommend 2)" `
                -Remediation "Set ConsentPromptBehaviorAdmin to 2 (prompt for consent on secure desktop)" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6(1)'; CIS='2.3.17.1' }
        } else {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Fail" `
                -Message "E5.3: Admin UAC prompt behavior is weak (value=$consent)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6(1)'; CIS='2.3.17.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E5 Admin Privs" -Status "Error" `
            -Message "E5.3: UAC prompt check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6(1)' }
    }
    # E5.4: Local admin token filtering
    try {
        $tokenFilter = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Default 0
        if ($tokenFilter -eq 0) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Pass" `
                -Message "E5.4: Local admin token filtering is active (blocks remote elevation)" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6'; NSA='AdminToken' }
        } else {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Fail" `
                -Message "E5.4: Local admin token filtering is DISABLED -- lateral movement risk" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 0" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6'; NSA='AdminToken' }
        }
    } catch {
        Add-Result -Category "ACSC - E5 Admin Privs" -Status "Error" `
            -Message "E5.4: Token filtering check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-6' }
    }
    # E5.5: LSA protection (RunAsPPL)
    try {
        $lsaPPL = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default 0
        if ($lsaPPL -eq 1) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Pass" `
                -Message "E5.5: LSA protection (RunAsPPL) is enabled" `
                -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='SC-4'; NSA='LSA' }
        } else {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Fail" `
                -Message "E5.5: LSA protection is NOT enabled -- credential theft risk" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='SC-4'; NSA='LSA' }
        }
    } catch {
        Add-Result -Category "ACSC - E5 Admin Privs" -Status "Error" `
            -Message "E5.5: LSA protection check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E5'; NIST='SC-4' }
    }
    # E5.6: Guest account disabled
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guest -and $guest.Enabled -eq $false) {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Pass" `
                -Message "E5.6: Guest account is disabled" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-2'; CIS='1.1.1' }
        } else {
            Add-Result -Category "ACSC - E5 Admin Privs" -Status "Fail" `
                -Message "E5.6: Guest account is ENABLED" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-2'; CIS='1.1.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E5 Admin Privs" -Status "Error" `
            -Message "E5.6: Guest account check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E5'; NIST='AC-2' }
    }

# ===========================================================================
# E6 -- Patch Operating Systems
# ===========================================================================
Write-Host "[ACSC] Checking E6 -- Patch Operating Systems..." -ForegroundColor Yellow

    # E6.1: Windows Update service running
    try {
        $wuSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($null -ne $wuSvc -and $wuSvc.Status -eq 'Running') {
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Pass" `
                -Message "E6.1: Windows Update service is running" `
                -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; CIS='18.9.101' }
        } else {
            $svcStatus = if ($null -ne $wuSvc) { $wuSvc.Status } else { "Not Found" }
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Fail" `
                -Message "E6.1: Windows Update service is not running (status: $svcStatus)" `
                -Remediation "Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv" `
                -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; CIS='18.9.101' }
        }
    } catch {
        Add-Result -Category "ACSC - E6 Patch OS" -Status "Error" `
            -Message "E6.1: Windows Update check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2' }
    }
    # E6.2: Recent hotfix recency
    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
        if ($null -ne $hotfixes -and $hotfixes.Count -gt 0) {
            $latest = $hotfixes[0]
            $daysSince = if ($null -ne $latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
            if ($daysSince -le 14) {
                Add-Result -Category "ACSC - E6 Patch OS" -Status "Pass" `
                    -Message "E6.2: OS patches current -- latest hotfix $($latest.HotFixID) installed $daysSince day(s) ago" `
                    -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; ISO27001='A.8.8' }
            } elseif ($daysSince -le 30) {
                Add-Result -Category "ACSC - E6 Patch OS" -Status "Warning" `
                    -Message "E6.2: Latest hotfix $($latest.HotFixID) is $daysSince days old -- ACSC recommends within 48 hours for critical" `
                    -Remediation "Run Windows Update immediately" `
                    -Severity "High" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; ISO27001='A.8.8' }
            } else {
                Add-Result -Category "ACSC - E6 Patch OS" -Status "Fail" `
                    -Message "E6.2: System is $daysSince days behind on OS patches" `
                    -Remediation "Immediately run Windows Update and install all pending updates" `
                    -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; ISO27001='A.8.8' }
            }
        } else {
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Warning" `
                -Message "E6.2: No hotfix information available" `
                -Severity "High" -CrossReferences @{ ACSC='E6'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ACSC - E6 Patch OS" -Status "Error" `
            -Message "E6.2: Hotfix recency check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2' }
    }
    # E6.3: OS version supported (not EOL)
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $buildNum = [int]$osInfo.BuildNumber
        $osCaption = $osInfo.Caption
        # Windows 10 builds below 19044 (21H2) are EOL
        # Windows 11 builds below 22621 (22H2) are nearing EOL
        $isEOL = $false
        if ($osCaption -match 'Windows 10' -and $buildNum -lt 19044) { $isEOL = $true }
        if ($osCaption -match 'Windows Server 2012') { $isEOL = $true }
        if ($osCaption -match 'Windows Server 2016' -and $buildNum -lt 14393) { $isEOL = $true }
        if (-not $isEOL) {
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Pass" `
                -Message "E6.3: OS version $osCaption (Build $buildNum) is supported" `
                -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; STIG='V-220706' }
        } else {
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Fail" `
                -Message "E6.3: OS version $osCaption (Build $buildNum) may be end-of-life" `
                -Remediation "Upgrade to a supported version of Windows" `
                -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; STIG='V-220706' }
        }
    } catch {
        Add-Result -Category "ACSC - E6 Patch OS" -Status "Error" `
            -Message "E6.3: OS version check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ACSC='E6'; NIST='SI-2' }
    }
    # E6.4: Auto-update not disabled
    try {
        $noAU = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Default 0
        if ($noAU -eq 0) {
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Pass" `
                -Message "E6.4: Automatic OS updates are not disabled by policy" `
                -Severity "High" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; CIS='18.9.101.2' }
        } else {
            Add-Result -Category "ACSC - E6 Patch OS" -Status "Fail" `
                -Message "E6.4: Automatic updates are DISABLED by policy" `
                -Remediation "Remove NoAutoUpdate policy to allow automatic updates" `
                -Severity "High" -CrossReferences @{ ACSC='E6'; NIST='SI-2'; CIS='18.9.101.2' }
        }
    } catch {
        Add-Result -Category "ACSC - E6 Patch OS" -Status "Error" `
            -Message "E6.4: Auto-update check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E6'; NIST='SI-2' }
    }

# ===========================================================================
# E7 -- Multi-Factor Authentication
# ===========================================================================
Write-Host "[ACSC] Checking E7 -- Multi-Factor Authentication..." -ForegroundColor Yellow

    # E7.1: Credential Guard (hardware MFA complement)
    try {
        $credGuard = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Default 0
        $lsaCfg = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Default 0
        if ($credGuard -eq 1 -and $lsaCfg -ge 1) {
            Add-Result -Category "ACSC - E7 MFA" -Status "Pass" `
                -Message "E7.1: Credential Guard is enabled (VBS=$credGuard, LsaCfg=$lsaCfg)" `
                -Severity "High" -CrossReferences @{ ACSC='E7'; NIST='IA-2(1)'; NSA='CredGuard' }
        } else {
            Add-Result -Category "ACSC - E7 MFA" -Status "Warning" `
                -Message "E7.1: Credential Guard is not fully configured (VBS=$credGuard, LsaCfg=$lsaCfg)" `
                -Remediation "Enable Credential Guard via Group Policy Device Guard settings" `
                -Severity "High" -CrossReferences @{ ACSC='E7'; NIST='IA-2(1)'; NSA='CredGuard' }
        }
    } catch {
        Add-Result -Category "ACSC - E7 MFA" -Status "Error" `
            -Message "E7.1: Credential Guard check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E7'; NIST='IA-2(1)' }
    }
    # E7.2: Windows Hello for Business readiness
    try {
        $helloEnabled = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -Default $null
        if ($null -ne $helloEnabled -and $helloEnabled -eq 1) {
            Add-Result -Category "ACSC - E7 MFA" -Status "Pass" `
                -Message "E7.2: Windows Hello for Business is enabled via policy" `
                -Severity "High" -CrossReferences @{ ACSC='E7'; NIST='IA-2(1)' }
        } else {
            Add-Result -Category "ACSC - E7 MFA" -Status "Info" `
                -Message "E7.2: Windows Hello for Business is not configured via policy" `
                -Remediation "Enable Windows Hello for Business via GPO for MFA support" `
                -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='IA-2(1)' }
        }
    } catch {
        Add-Result -Category "ACSC - E7 MFA" -Status "Error" `
            -Message "E7.2: Windows Hello check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='IA-2(1)' }
    }
    # E7.3: Smart card removal behavior
    try {
        $scRemove = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -Default "0"
        if ($scRemove -eq "1" -or $scRemove -eq "2") {
            $behavior = if ($scRemove -eq "1") { "Lock Workstation" } else { "Force Logoff" }
            Add-Result -Category "ACSC - E7 MFA" -Status "Pass" `
                -Message "E7.3: Smart card removal behavior is configured ($behavior)" `
                -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='IA-2'; CIS='2.3.7.1' }
        } else {
            Add-Result -Category "ACSC - E7 MFA" -Status "Info" `
                -Message "E7.3: Smart card removal behavior is not enforced (value=$scRemove)" `
                -Remediation "Set ScRemoveOption to 1 (Lock) or 2 (Force Logoff)" `
                -Severity "Low" -CrossReferences @{ ACSC='E7'; NIST='IA-2'; CIS='2.3.7.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E7 MFA" -Status "Error" `
            -Message "E7.3: Smart card removal check failed: $_" `
            -Severity "Low" -CrossReferences @{ ACSC='E7'; NIST='IA-2' }
    }
    # E7.4: Screen lock timeout
    try {
        $lockTimeout = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default $null
        if ($null -ne $lockTimeout -and [int]$lockTimeout -le 900) {
            Add-Result -Category "ACSC - E7 MFA" -Status "Pass" `
                -Message "E7.4: Screen lock timeout is $lockTimeout seconds (15 min or less)" `
                -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='AC-11'; CIS='2.3.7.3' }
        } elseif ($null -ne $lockTimeout) {
            Add-Result -Category "ACSC - E7 MFA" -Status "Warning" `
                -Message "E7.4: Screen lock timeout is $lockTimeout seconds (recommend 900 or less)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900" `
                -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='AC-11'; CIS='2.3.7.3' }
        } else {
            Add-Result -Category "ACSC - E7 MFA" -Status "Fail" `
                -Message "E7.4: Machine inactivity timeout is not configured" `
                -Remediation "Set InactivityTimeoutSecs to 900 or less" `
                -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='AC-11'; CIS='2.3.7.3' }
        }
    } catch {
        Add-Result -Category "ACSC - E7 MFA" -Status "Error" `
            -Message "E7.4: Screen lock timeout check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E7'; NIST='AC-11' }
    }

# ===========================================================================
# E8 -- Regular Backups
# ===========================================================================
Write-Host "[ACSC] Checking E8 -- Regular Backups..." -ForegroundColor Yellow

    # E8.1: Volume Shadow Copy service
    try {
        $vssSvc = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if ($null -ne $vssSvc -and $vssSvc.StartType -ne 'Disabled') {
            Add-Result -Category "ACSC - E8 Backups" -Status "Pass" `
                -Message "E8.1: Volume Shadow Copy service is available (start type: $($vssSvc.StartType))" `
                -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; ISO27001='A.8.13' }
        } else {
            Add-Result -Category "ACSC - E8 Backups" -Status "Warning" `
                -Message "E8.1: Volume Shadow Copy service is disabled" `
                -Remediation "Set-Service -Name VSS -StartupType Manual" `
                -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; ISO27001='A.8.13' }
        }
    } catch {
        Add-Result -Category "ACSC - E8 Backups" -Status "Error" `
            -Message "E8.1: VSS check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
    }
    # E8.2: System Restore enabled
    try {
        $srDisabled = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Default 0
        if ($srDisabled -ne 1) {
            Add-Result -Category "ACSC - E8 Backups" -Status "Pass" `
                -Message "E8.2: System Restore is enabled" `
                -Severity "Medium" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; ISO27001='A.8.13' }
        } else {
            Add-Result -Category "ACSC - E8 Backups" -Status "Warning" `
                -Message "E8.2: System Restore is DISABLED by policy" `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name DisableSR" `
                -Severity "Medium" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; ISO27001='A.8.13' }
        }
    } catch {
        Add-Result -Category "ACSC - E8 Backups" -Status "Error" `
            -Message "E8.2: System Restore check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
    }
    # E8.3: BitLocker recovery key availability
    try {
        $blVol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($null -ne $blVol) {
            $hasRecovery = @($blVol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
            if ($hasRecovery.Count -gt 0) {
                Add-Result -Category "ACSC - E8 Backups" -Status "Pass" `
                    -Message "E8.3: BitLocker recovery password is configured -- $($hasRecovery.Count) key protector(s)" `
                    -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; ISO27001='A.8.24' }
            } else {
                Add-Result -Category "ACSC - E8 Backups" -Status "Warning" `
                    -Message "E8.3: No BitLocker recovery password found -- backup recovery risk" `
                    -Remediation "Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector" `
                    -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; ISO27001='A.8.24' }
            }
        } else {
            Add-Result -Category "ACSC - E8 Backups" -Status "Info" `
                -Message "E8.3: BitLocker not enabled -- recovery key check not applicable" `
                -Severity "Informational" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
        }
    } catch {
        Add-Result -Category "ACSC - E8 Backups" -Status "Error" `
            -Message "E8.3: BitLocker recovery check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
    }
    # E8.4: Windows Backup service
    try {
        $wbSvc = Get-Service -Name SDRSVC -ErrorAction SilentlyContinue
        if ($null -ne $wbSvc -and $wbSvc.StartType -ne 'Disabled') {
            Add-Result -Category "ACSC - E8 Backups" -Status "Pass" `
                -Message "E8.4: Windows Backup service (SDRSVC) is available" `
                -Severity "Medium" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
        } else {
            Add-Result -Category "ACSC - E8 Backups" -Status "Info" `
                -Message "E8.4: Windows Backup service is disabled or not available" `
                -Remediation "Consider enabling backup services or deploying enterprise backup solution" `
                -Severity "Medium" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
        }
    } catch {
        Add-Result -Category "ACSC - E8 Backups" -Status "Error" `
            -Message "E8.4: Backup service check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
    }
    # E8.5: Controlled folder access (ransomware protection for backups)
    try {
        $cfa = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $cfa -and $cfa -eq 1) {
            Add-Result -Category "ACSC - E8 Backups" -Status "Pass" `
                -Message "E8.5: Controlled Folder Access protects backup data from ransomware" `
                -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; CIS='18.9.47.4.1' }
        } else {
            Add-Result -Category "ACSC - E8 Backups" -Status "Warning" `
                -Message "E8.5: Controlled Folder Access not enabled -- backup data unprotected from ransomware" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9'; CIS='18.9.47.4.1' }
        }
    } catch {
        Add-Result -Category "ACSC - E8 Backups" -Status "Error" `
            -Message "E8.5: Controlled Folder Access check failed: $_" `
            -Severity "High" -CrossReferences @{ ACSC='E8'; NIST='CP-9' }
    }

# ===========================================================================
# Module Summary
# ===========================================================================
$passCount    = @($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount    = @($results | Where-Object { $_.Status -eq "Fail" }).Count
$warnCount    = @($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount    = @($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount   = @($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks  = $results.Count
$passPct      = if ($totalChecks -gt 0) { [Math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }

Write-Host "`n$("=" * 80)" -ForegroundColor White
Write-Host "  [ACSC] Essential Eight Module Complete (v$moduleVersion)" -ForegroundColor Cyan
Write-Host "$("=" * 80)" -ForegroundColor White
Write-Host "  Total Checks: $totalChecks  |  Pass: $passCount ($passPct`%)  |  Fail: $failCount  |  Warn: $warnCount  |  Info: $infoCount  |  Error: $errorCount" -ForegroundColor White

# Category breakdown
Write-Host "`n  Category Breakdown:" -ForegroundColor White
$catGroups = @{}
foreach ($r in $results) {
    $catKey = $r.Category
    if (-not $catGroups.ContainsKey($catKey)) { $catGroups[$catKey] = 0 }
    $catGroups[$catKey]++
}
foreach ($cat in ($catGroups.Keys | Sort-Object)) {
    Write-Host "    $($cat.PadRight(55)): $($catGroups[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
}

# Severity distribution for failures
$failResults = @($results | Where-Object { $_.Status -eq "Fail" })
if ($failResults.Count -gt 0) {
    Write-Host "`n  Failed Check Severity Distribution:" -ForegroundColor Yellow
    foreach ($sev in @("Critical","High","Medium","Low")) {
        $sevCount = @($failResults | Where-Object { $_.Severity -eq $sev }).Count
        if ($sevCount -gt 0) {
            $color = switch ($sev) { "Critical" { "Red" }; "High" { "Red" }; "Medium" { "Yellow" }; default { "White" } }
            Write-Host "    $($sev.PadRight(12)): $sevCount" -ForegroundColor $color
        }
    }
}
Write-Host "$("=" * 80)`n" -ForegroundColor White

return $results

# ===========================================================================
# Standalone Execution Support
# ===========================================================================
if ($MyInvocation.ScriptName -eq "" -or $MyInvocation.ScriptName -eq $MyInvocation.MyCommand.Path) {
    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  ACSC Essential Eight -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
    Write-Host "$("=" * 80)" -ForegroundColor White

    $standaloneData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion    = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        IPAddresses  = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" }).IPAddress)
        IsAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScanDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    $commonLib = Join-Path (Split-Path $PSScriptRoot) "shared_components\audit-common.ps1"
    if (Test-Path $commonLib) {
        try {
            . $commonLib
            $osInfoObj = Get-OSInfo
            $cache = New-SharedDataCache -OSInfo $osInfoObj
            Invoke-CacheWarmUp -Cache $cache
            $standaloneData.Cache = $cache
            $summary = Get-CacheSummary -Cache $cache
            Write-Host "  Cache: Enabled `($($summary.ServicesCount) services, $($summary.RegistryCacheCount) registry keys`)" -ForegroundColor Green
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

    $SharedData = $standaloneData
    $useCache = ($null -ne $SharedData.Cache)

    Write-Host "[ACSC] Executing checks with standalone environment...`n" -ForegroundColor Cyan
    $script:results = @()

    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  DETAILED STANDALONE RESULTS" -ForegroundColor Cyan
    Write-Host "$("=" * 80)" -ForegroundColor White
    Write-Host "  Generated $($results.Count) audit results`n" -ForegroundColor White

    Write-Host "  Status Distribution:" -ForegroundColor White
    foreach ($statusType in @("Pass", "Fail", "Warning", "Info", "Error")) {
        $count = @($results | Where-Object { $_.Status -eq $statusType }).Count
        if ($count -gt 0 -and $results.Count -gt 0) {
            $pct = [Math]::Round(($count / $results.Count) * 100, 1)
            $barLen = [Math]::Floor($pct / 2)
            $bar = "#" * $barLen
            $color = switch ($statusType) { "Pass" { "Green" }; "Fail" { "Red" }; "Warning" { "Yellow" }; "Info" { "Cyan" }; default { "Magenta" } }
            Write-Host "    $($statusType.PadRight(8)): $($count.ToString().PadLeft(3)) `($($pct.ToString().PadLeft(5))`%`) $bar" -ForegroundColor $color
        }
    }

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
    Write-Host "  ACSC module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}

# ============================================================================
# End of ACSC Essential Eight module (Module-ACSC.ps1)
# ============================================================================
