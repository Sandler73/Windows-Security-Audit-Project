# module-soc2.ps1
# SOC 2 Trust Service Criteria Compliance Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against AICPA SOC 2 Type II Trust Service Criteria (2017)
# with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    SOC 2 Trust Service Criteria compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with AICPA SOC 2 Type II Trust Service Criteria (2017) including:
    - CC5: Control Activities (access controls, segregation, change management)
    - CC6: Logical and Physical Access (authentication, authorization, encryption, network)
    - CC7: System Operations (incident detection, response, backup, recovery, monitoring)
    - CC8: Change Management (configuration, patching, baseline validation)
    - A1: Availability (uptime readiness, redundancy, capacity, disaster recovery)
    - C1: Confidentiality (data classification, encryption, disposal, DLP indicators)
    - CC3-CC4: Risk Assessment and Monitoring (vulnerability, event logging, alerting)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: AICPA TSP Section 100 (2017), SOC 2 Type II Reporting Framework
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-soc2.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "SOC2"
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

Write-Host "`n[$moduleName] Starting SOC 2 Trust Service Criteria compliance checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# CC5 -- Control Activities
# ===========================================================================
Write-Host "[SOC2] Checking CC5 -- Control Activities..." -ForegroundColor Yellow

    # CC5.1a: Access controls -- UAC enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Pass" `
                -Message "CC5.1a: Access controls -- UAC enabled -- properly configured" `
                -Details "CC5.1: Logical access security over information assets through UAC enforcement" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC5.1'; NIST='AC-3'; ISO27001='A.5.15' }
        } else {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Fail" `
                -Message "CC5.1a: Access controls -- UAC enabled -- not configured (Value=$val)" `
                -Details "CC5.1: Logical access security over information assets through UAC enforcement" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC5.1'; NIST='AC-3'; ISO27001='A.5.15' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Error" `
            -Message "CC5.1a: Access controls -- UAC enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC5.1'; NIST='AC-3'; ISO27001='A.5.15' }
    }
    # CC5.1b: Segregation -- UAC admin consent
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Pass" `
                -Message "CC5.1b: Segregation -- UAC admin consent -- properly configured" `
                -Details "CC5.1: Segregation of duties requires admin consent prompts" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC5.1'; NIST='AC-6'; CIS='2.3.17.3' }
        } else {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Fail" `
                -Message "CC5.1b: Segregation -- UAC admin consent -- not configured (Value=$val)" `
                -Details "CC5.1: Segregation of duties requires admin consent prompts" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC5.1'; NIST='AC-6'; CIS='2.3.17.3' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Error" `
            -Message "CC5.1b: Segregation -- UAC admin consent -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC5.1'; NIST='AC-6'; CIS='2.3.17.3' }
    }
    # CC5.2: Access restriction -- admin count
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $cnt = if ($null -ne $admins) { @($admins).Count } else { 0 }
        if ($cnt -le 3) {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Pass" `
                -Message "CC5.2: Local admin count is $cnt (appropriate)" -Details "CC5.2: Least privilege access" `
                -Severity "High" -CrossReferences @{ SOC2='CC5.2'; NIST='AC-6'; ISO27001='A.5.2' }
        } else {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Warning" `
                -Message "CC5.2: Local admin count is $cnt (excessive)" -Details "CC5.2: Review administrative access" `
                -Remediation "Review and minimize administrator group membership" `
                -Severity "High" -CrossReferences @{ SOC2='CC5.2'; NIST='AC-6'; ISO27001='A.5.2' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Error" `
            -Message "CC5.2: Access restriction -- admin count -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC5.2'; NIST='AC-6' }
    }
    # CC5.3: Change control -- Script Block Logging
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Pass" `
                -Message "CC5.3: Change control -- Script Block Logging -- properly configured" `
                -Details "CC5.3: Change activities must be logged for control verification" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC5.3'; NIST='CM-6'; CIS='18.9.100.1' }
        } else {
            Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Fail" `
                -Message "CC5.3: Change control -- Script Block Logging -- not configured (Value=$val)" `
                -Details "CC5.3: Change activities must be logged for control verification" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC5.3'; NIST='CM-6'; CIS='18.9.100.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC5 Control Activities" -Status "Error" `
            -Message "CC5.3: Change control -- Script Block Logging -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC5.3'; NIST='CM-6'; CIS='18.9.100.1' }
    }

# ===========================================================================
# CC6 -- Logical and Physical Access Controls
# ===========================================================================
Write-Host "[SOC2] Checking CC6 -- Logical and Physical Access Controls..." -ForegroundColor Yellow

    # CC6.1a: Authentication -- NTLMv2 only
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default $null
        if ($null -ne $val -and $val -ge 5) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1a: Authentication -- NTLMv2 only -- properly configured" `
                -Details "CC6.1: Strong authentication mechanisms for system access" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-2'; CIS='2.3.11.7'; ISO27001='A.8.5' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1a: Authentication -- NTLMv2 only -- not configured (Value=$val)" `
                -Details "CC6.1: Strong authentication mechanisms for system access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-2'; CIS='2.3.11.7'; ISO27001='A.8.5' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1a: Authentication -- NTLMv2 only -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='IA-2'; CIS='2.3.11.7'; ISO27001='A.8.5' }
    }
    # CC6.1b: Authentication -- LSASS protection
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1b: Authentication -- LSASS protection -- properly configured" `
                -Details "CC6.1: Credential stores must be protected from unauthorized extraction" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5(13)'; CIS='18.3.1' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1b: Authentication -- LSASS protection -- not configured (Value=$val)" `
                -Details "CC6.1: Credential stores must be protected from unauthorized extraction" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5(13)'; CIS='18.3.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1b: Authentication -- LSASS protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5(13)'; CIS='18.3.1' }
    }
    # CC6.1c: Authentication -- WDigest disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1c: Authentication -- WDigest disabled -- properly configured" `
                -Details "CC6.1: Plaintext credential caching compromises logical access security" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5(13)'; CIS='18.3.6' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1c: Authentication -- WDigest disabled -- not configured (Value=$val)" `
                -Details "CC6.1: Plaintext credential caching compromises logical access security" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5(13)'; CIS='18.3.6' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1c: Authentication -- WDigest disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5(13)'; CIS='18.3.6' }
    }
    # CC6.1d: Authentication -- LM hash disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1d: Authentication -- LM hash disabled -- properly configured" `
                -Details "CC6.1: Weak credential storage must be eliminated" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5'; CIS='2.3.11.5' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1d: Authentication -- LM hash disabled -- not configured (Value=$val)" `
                -Details "CC6.1: Weak credential storage must be eliminated" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5'; CIS='2.3.11.5' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1d: Authentication -- LM hash disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5'; CIS='2.3.11.5' }
    }
    # CC6.1e: Authentication -- password policy
    try {
        $netAcct = net accounts 2>&1
        $minLen = 0
        foreach ($line in $netAcct) { if ($line -match "Minimum password length\s+(\d+)") { $minLen = [int]$Matches[1] } }
        if ($minLen -ge 14) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1e: Password length $minLen chars (meets requirement)" `
                -Details "CC6.1: Authentication strength supports logical access controls" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5'; CIS='1.1.4' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1e: Password length $minLen (requires `>= 14)" `
                -Details "CC6.1: Weak passwords undermine logical access security" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5'; CIS='1.1.4' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1e: Authentication -- password policy -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='IA-5' }
    }
    # CC6.1f: Authentication -- account lockout
    try {
        $netAcct = net accounts 2>&1
        $lockT = 0
        foreach ($line in $netAcct) { if ($line -match "Lockout threshold\s+(\d+)") { $lockT = [int]$Matches[1] } }
        if ($lockT -gt 0 -and $lockT -le 5) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1f: Account lockout at $lockT attempts" `
                -Details "CC6.1: Brute-force protection for logical access" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.1'; NIST='AC-7'; CIS='1.2.1' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1f: Account lockout threshold is $lockT (requires 1-5)" `
                -Details "CC6.1: No lockout allows unlimited authentication attempts" `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.1'; NIST='AC-7'; CIS='1.2.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1f: Authentication -- account lockout -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='AC-7' }
    }
    # CC6.1g: Authentication -- Guest account
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guest -and $guest.Enabled -eq $false) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.1g: Guest account disabled" -Details "CC6.1: No anonymous access" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.1'; NIST='AC-2'; ISO27001='A.5.18' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.1g: Guest account ENABLED" -Details "CC6.1: Anonymous access violates logical access" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.1'; NIST='AC-2'; ISO27001='A.5.18' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.1g: Authentication -- Guest account -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.1'; NIST='AC-2' }
    }
    # CC6.2a: Encryption -- BitLocker policy
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Default $null
        if ($null -ne $val -and $val -ge 7) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.2a: Encryption -- BitLocker policy -- properly configured" `
                -Details "CC6.2: Data at rest encryption protects logical access to stored information" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-28'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.2a: Encryption -- BitLocker policy -- not configured (Value=$val)" `
                -Details "CC6.2: Data at rest encryption protects logical access to stored information" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name EncryptionMethodWithXtsOs -Value 7" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-28'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.2a: Encryption -- BitLocker policy -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.2'; NIST='SC-28'; ISO27001='A.8.24' }
    }
    # CC6.2b: Encryption -- TLS 1.2 enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.2b: Encryption -- TLS 1.2 enabled -- properly configured" `
                -Details "CC6.2: Transit encryption for data communications" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-8'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.2b: Encryption -- TLS 1.2 enabled -- not configured (Value=$val)" `
                -Details "CC6.2: Transit encryption for data communications" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-8'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.2b: Encryption -- TLS 1.2 enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.2'; NIST='SC-8'; ISO27001='A.8.24' }
    }
    # CC6.2c: Deprecated protocols -- SSL 2.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.2c: Deprecated protocols -- SSL 2.0 disabled -- properly configured" `
                -Details "CC6.2: Insecure protocols must be disabled" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-13' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.2c: Deprecated protocols -- SSL 2.0 disabled -- not configured (Value=$val)" `
                -Details "CC6.2: Insecure protocols must be disabled" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-13' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.2c: Deprecated protocols -- SSL 2.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.2'; NIST='SC-13' }
    }
    # CC6.2d: Deprecated protocols -- SSL 3.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.2d: Deprecated protocols -- SSL 3.0 disabled -- properly configured" `
                -Details "CC6.2: SSL 3.0 POODLE vulnerability" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-13' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.2d: Deprecated protocols -- SSL 3.0 disabled -- not configured (Value=$val)" `
                -Details "CC6.2: SSL 3.0 POODLE vulnerability" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC6.2'; NIST='SC-13' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.2d: Deprecated protocols -- SSL 3.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC6.2'; NIST='SC-13' }
    }
    # CC6.3: Network security -- firewall all profiles
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $allOn = $true
        foreach ($fw in $fwProfiles) { if ($fw.Enabled -ne $true) { $allOn = $false } }
        if ($allOn -and $null -ne $fwProfiles) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.3: All firewall profiles enabled" -Details "CC6.3: Logical/physical access boundaries" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.3'; NIST='SC-7'; ISO27001='A.8.20' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.3: Not all firewall profiles enabled" `
                -Remediation "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" `
                -Severity "High" -CrossReferences @{ SOC2='CC6.3'; NIST='SC-7'; ISO27001='A.8.20' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.3: Network security -- firewall all profiles -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.3'; NIST='SC-7' }
    }
    # CC6.4: Session management -- inactivity timeout
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.4: Session management -- inactivity timeout -- properly configured" `
                -Details "CC6.4: Sessions must timeout to prevent unauthorized logical access" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.4'; NIST='AC-12'; CIS='2.3.7.3' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.4: Session management -- inactivity timeout -- not configured (Value=$val)" `
                -Details "CC6.4: Sessions must timeout to prevent unauthorized logical access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.4'; NIST='AC-12'; CIS='2.3.7.3' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.4: Session management -- inactivity timeout -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.4'; NIST='AC-12'; CIS='2.3.7.3' }
    }
    # CC6.5: Credential protection -- Credential Guard
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.5: Credential protection -- Credential Guard -- properly configured" `
                -Details "CC6.5: Credential isolation protects authentication mechanisms" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.5'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.5: Credential protection -- Credential Guard -- not configured (Value=$val)" `
                -Details "CC6.5: Credential isolation protects authentication mechanisms" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -Value 1" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.5'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.5: Credential protection -- Credential Guard -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.5'; NIST='IA-5(13)'; ISO27001='A.8.2' }
    }
    # CC6.6: NLA for RDP
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.6: NLA for RDP -- properly configured" `
                -Details "CC6.6: Network Level Authentication for remote access" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.6'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.6: NLA for RDP -- not configured (Value=$val)" `
                -Details "CC6.6: Network Level Authentication for remote access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.6'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.6: NLA for RDP -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.6'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
    }
    # CC6.7: Anonymous enumeration restricted
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.7: Anonymous enumeration restricted -- properly configured" `
                -Details "CC6.7: Anonymous access must be restricted" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.7'; NIST='AC-14'; CIS='2.3.10.6' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.7: Anonymous enumeration restricted -- not configured (Value=$val)" `
                -Details "CC6.7: Anonymous access must be restricted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.7'; NIST='AC-14'; CIS='2.3.10.6' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.7: Anonymous enumeration restricted -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.7'; NIST='AC-14'; CIS='2.3.10.6' }
    }
    # CC6.8: SMB signing required
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.8: SMB signing required -- properly configured" `
                -Details "CC6.8: Network communication integrity for logical access paths" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.8'; NIST='SC-8'; CIS='2.3.9.2' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.8: SMB signing required -- not configured (Value=$val)" `
                -Details "CC6.8: Network communication integrity for logical access paths" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.8'; NIST='SC-8'; CIS='2.3.9.2' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.8: SMB signing required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.8'; NIST='SC-8'; CIS='2.3.9.2' }
    }
    # CC6.9: LLMNR disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Pass" `
                -Message "CC6.9: LLMNR disabled -- properly configured" `
                -Details "CC6.9: Broadcast protocols enable network poisoning" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.9'; NIST='SC-20'; CIS='18.5.4.2' }
        } else {
            Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Fail" `
                -Message "CC6.9: LLMNR disabled -- not configured (Value=$val)" `
                -Details "CC6.9: Broadcast protocols enable network poisoning" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC6.9'; NIST='SC-20'; CIS='18.5.4.2' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC6 Logical Access" -Status "Error" `
            -Message "CC6.9: LLMNR disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC6.9'; NIST='SC-20'; CIS='18.5.4.2' }
    }

# ===========================================================================
# CC7 -- System Operations
# ===========================================================================
Write-Host "[SOC2] Checking CC7 -- System Operations..." -ForegroundColor Yellow

    # CC7.1: Event monitoring -- Event Log service
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.1: Event monitoring -- Event Log service -- service running" `
                -Details "CC7.1: Detect anomalies/incidents via event monitoring" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.1'; NIST='AU-2'; ISO27001='A.8.16' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.1: Event monitoring -- Event Log service -- service not running (Status=$svcSt)" `
                -Details "CC7.1: Detect anomalies/incidents via event monitoring" `
                -Remediation "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.1'; NIST='AU-2'; ISO27001='A.8.16' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.1: Event monitoring -- Event Log service -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC7.1'; NIST='AU-2'; ISO27001='A.8.16' }
    }
    # CC7.2: Incident detection -- logon auditing
    try {
        $ao = auditpol /get /category:"Logon/Logoff" 2>&1
        $ok = $false
        foreach ($l in $ao) { if ($l -match "Logon" -and $l -match "Success") { $ok = $true } }
        if ($ok) {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.2: Logon auditing enabled for incident detection" `
                -Details "CC7.2: Monitor system for anomalies" -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.2'; NIST='AU-2'; CIS='17.5.1' }
        } else {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.2: Logon auditing NOT enabled" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -Severity "Critical" -CrossReferences @{ SOC2='CC7.2'; NIST='AU-2'; CIS='17.5.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.2: Incident detection -- logon auditing -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC7.2'; NIST='AU-2' }
    }
    # CC7.3: Security log capacity
    try {
        $sz = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
        $mb = [Math]::Round($sz / 1MB, 0)
        if ($sz -ge 1073741824) {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.3: Security log ${mb}MB -- adequate for incident investigation" `
                -Severity "High" -CrossReferences @{ SOC2='CC7.3'; NIST='AU-4' }
        } else {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.3: Security log ${mb}MB (requires `>= 1024MB)" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "High" -CrossReferences @{ SOC2='CC7.3'; NIST='AU-4' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.3: Security log capacity -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC7.3'; NIST='AU-4' }
    }
    # CC7.4: Malware protection -- Defender running
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.4: Malware protection -- Defender running -- service running" `
                -Details "CC7.4: Protect against malicious software" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.4'; NIST='SI-3' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.4: Malware protection -- Defender running -- service not running (Status=$svcSt)" `
                -Details "CC7.4: Protect against malicious software" `
                -Remediation "Start-Service -Name WinDefend" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.4'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.4: Malware protection -- Defender running -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC7.4'; NIST='SI-3' }
    }
    # CC7.5: Real-time protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.5: Real-time protection -- properly configured" `
                -Details "CC7.5: Continuous monitoring for malicious activity" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.5'; NIST='SI-3'; CIS='18.9.47.9.1' }
        } else {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.5: Real-time protection -- not configured (Value=$val)" `
                -Details "CC7.5: Continuous monitoring for malicious activity" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.5'; NIST='SI-3'; CIS='18.9.47.9.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.5: Real-time protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC7.5'; NIST='SI-3'; CIS='18.9.47.9.1' }
    }
    # CC7.6: Network protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.6: Network protection -- properly configured" `
                -Details "CC7.6: Network-level threat detection supports incident response" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC7.6'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
        } else {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.6: Network protection -- not configured (Value=$val)" `
                -Details "CC7.6: Network-level threat detection supports incident response" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC7.6'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.6: Network protection -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC7.6'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
    }
    # CC7.7: Controlled folder access
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.7: Controlled folder access -- properly configured" `
                -Details "CC7.7: Ransomware protection for critical data stores" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC7.7'; NIST='SI-3' }
        } else {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.7: Controlled folder access -- not configured (Value=$val)" `
                -Details "CC7.7: Ransomware protection for critical data stores" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC7.7'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.7: Controlled folder access -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC7.7'; NIST='SI-3' }
    }
    # CC7.8: SMBv1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Pass" `
                -Message "CC7.8: SMBv1 disabled -- properly configured" `
                -Details "CC7.8: SMBv1 attack vector must be eliminated" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.8'; NIST='CM-7'; ISO27001='A.8.9' }
        } else {
            Add-Result -Category "SOC2 - CC7 Operations" -Status "Fail" `
                -Message "CC7.8: SMBv1 disabled -- not configured (Value=$val)" `
                -Details "CC7.8: SMBv1 attack vector must be eliminated" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ SOC2='CC7.8'; NIST='CM-7'; ISO27001='A.8.9' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC7 Operations" -Status "Error" `
            -Message "CC7.8: SMBv1 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ SOC2='CC7.8'; NIST='CM-7'; ISO27001='A.8.9' }
    }

# ===========================================================================
# CC8 -- Change Management
# ===========================================================================
Write-Host "[SOC2] Checking CC8 -- Change Management..." -ForegroundColor Yellow

    # CC8.1a: Configuration baseline -- auto updates
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Default $null
        if ($null -ne $val -and $val -ge 4) {
            Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Pass" `
                -Message "CC8.1a: Configuration baseline -- auto updates -- properly configured" `
                -Details "CC8.1: Changes to infrastructure are managed through change management processes" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC8.1'; NIST='SI-2'; CIS='18.9.101.2' }
        } else {
            Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Fail" `
                -Message "CC8.1a: Configuration baseline -- auto updates -- not configured (Value=$val)" `
                -Details "CC8.1: Changes to infrastructure are managed through change management processes" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -Value 4" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC8.1'; NIST='SI-2'; CIS='18.9.101.2' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Error" `
            -Message "CC8.1a: Configuration baseline -- auto updates -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC8.1'; NIST='SI-2'; CIS='18.9.101.2' }
    }
    # CC8.1b: Patch management -- Update service
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Pass" `
                -Message "CC8.1b: Patch management -- Update service -- service running" `
                -Details "CC8.1: Update delivery for controlled change management" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC8.1'; NIST='SI-2' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Fail" `
                -Message "CC8.1b: Patch management -- Update service -- service not running (Status=$svcSt)" `
                -Details "CC8.1: Update delivery for controlled change management" `
                -Remediation "Start-Service -Name wuauserv" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC8.1'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Error" `
            -Message "CC8.1b: Patch management -- Update service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC8.1'; NIST='SI-2' }
    }
    # CC8.2: Authorized changes -- UAC secure desktop
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Pass" `
                -Message "CC8.2: Authorized changes -- UAC secure desktop -- properly configured" `
                -Details "CC8.2: Configuration changes require authorized elevation" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC8.2'; NIST='AC-6'; CIS='2.3.17.7' }
        } else {
            Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Fail" `
                -Message "CC8.2: Authorized changes -- UAC secure desktop -- not configured (Value=$val)" `
                -Details "CC8.2: Configuration changes require authorized elevation" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1" `
                -Severity "High" `
                -CrossReferences @{ SOC2='CC8.2'; NIST='AC-6'; CIS='2.3.17.7' }
        }
    } catch {
        Add-Result -Category "SOC2 - CC8 Change Mgmt" -Status "Error" `
            -Message "CC8.2: Authorized changes -- UAC secure desktop -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='CC8.2'; NIST='AC-6'; CIS='2.3.17.7' }
    }

# ===========================================================================
# A1 -- Availability
# ===========================================================================
Write-Host "[SOC2] Checking A1 -- Availability..." -ForegroundColor Yellow

    # A1.1: Recovery capability -- VSS service
    try {
        $svc = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "SOC2 - A1 Availability" -Status "Pass" `
                -Message "A1.1: Recovery capability -- VSS service -- service running" `
                -Details "A1.1: Recovery mechanisms maintain service availability" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='A1.1'; NIST='CP-9'; ISO27001='A.8.13' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "SOC2 - A1 Availability" -Status "Warning" `
                -Message "A1.1: Recovery capability -- VSS service -- service not running (Status=$svcSt)" `
                -Details "A1.1: Recovery mechanisms maintain service availability" `
                -Remediation "Set-Service -Name VSS -StartupType Manual" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='A1.1'; NIST='CP-9'; ISO27001='A.8.13' }
        }
    } catch {
        Add-Result -Category "SOC2 - A1 Availability" -Status "Error" `
            -Message "A1.1: Recovery capability -- VSS service -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ SOC2='A1.1'; NIST='CP-9'; ISO27001='A.8.13' }
    }
    # A1.2: Time sync -- W32Time service
    try {
        $svc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "SOC2 - A1 Availability" -Status "Pass" `
                -Message "A1.2: Time sync -- W32Time service -- service running" `
                -Details "A1.2: System clock accuracy for availability monitoring" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='A1.2'; NIST='AU-8' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "SOC2 - A1 Availability" -Status "Fail" `
                -Message "A1.2: Time sync -- W32Time service -- service not running (Status=$svcSt)" `
                -Details "A1.2: System clock accuracy for availability monitoring" `
                -Remediation "Start-Service -Name W32Time" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='A1.2'; NIST='AU-8' }
        }
    } catch {
        Add-Result -Category "SOC2 - A1 Availability" -Status "Error" `
            -Message "A1.2: Time sync -- W32Time service -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ SOC2='A1.2'; NIST='AU-8' }
    }
    # A1.3: Availability protection -- DEP enforcement
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Default $null
        if ($null -ne $val -and $val -ne 0) {
            Add-Result -Category "SOC2 - A1 Availability" -Status "Pass" `
                -Message "A1.3: Availability protection -- DEP enforcement -- properly configured" `
                -Details "A1.3: Exploit mitigations protect system availability" `
                -Severity "High" `
                -CrossReferences @{ SOC2='A1.3'; NIST='SI-16'; CIS='18.3.2' }
        } else {
            Add-Result -Category "SOC2 - A1 Availability" -Status "Fail" `
                -Message "A1.3: Availability protection -- DEP enforcement -- not configured (Value=$val)" `
                -Details "A1.3: Exploit mitigations protect system availability" `
                -Remediation "bcdedit /set nx AlwaysOn" `
                -Severity "High" `
                -CrossReferences @{ SOC2='A1.3'; NIST='SI-16'; CIS='18.3.2' }
        }
    } catch {
        Add-Result -Category "SOC2 - A1 Availability" -Status "Error" `
            -Message "A1.3: Availability protection -- DEP enforcement -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='A1.3'; NIST='SI-16'; CIS='18.3.2' }
    }

# ===========================================================================
# C1 -- Confidentiality
# ===========================================================================
Write-Host "[SOC2] Checking C1 -- Confidentiality..." -ForegroundColor Yellow

    # C1.1: Confidential data encryption -- BitLocker
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($null -ne $bl -and $bl.ProtectionStatus -eq "On") {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Pass" `
                -Message "C1.1: BitLocker active -- confidential data encrypted at rest" `
                -Severity "High" -CrossReferences @{ SOC2='C1.1'; NIST='SC-28'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Fail" `
                -Message "C1.1: BitLocker NOT active" `
                -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256" `
                -Severity "High" -CrossReferences @{ SOC2='C1.1'; NIST='SC-28'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Error" `
            -Message "C1.1: Confidential data encryption -- BitLocker -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ SOC2='C1.1'; NIST='SC-28' }
    }
    # C1.2: Data disposal -- pagefile cleared
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Pass" `
                -Message "C1.2: Data disposal -- pagefile cleared -- properly configured" `
                -Details "C1.2: Confidential data in memory must be cleared at shutdown" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.2'; NIST='SC-4'; CIS='2.3.11.9' }
        } else {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Fail" `
                -Message "C1.2: Data disposal -- pagefile cleared -- not configured (Value=$val)" `
                -Details "C1.2: Confidential data in memory must be cleared at shutdown" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.2'; NIST='SC-4'; CIS='2.3.11.9' }
        }
    } catch {
        Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Error" `
            -Message "C1.2: Data disposal -- pagefile cleared -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ SOC2='C1.2'; NIST='SC-4'; CIS='2.3.11.9' }
    }
    # C1.3: DLP -- clipboard redirection disabled (RDP)
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Pass" `
                -Message "C1.3: DLP -- clipboard redirection disabled (RDP) -- properly configured" `
                -Details "C1.3: Prevent unauthorized confidential data transfer via RDP" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.3'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
        } else {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Fail" `
                -Message "C1.3: DLP -- clipboard redirection disabled (RDP) -- not configured (Value=$val)" `
                -Details "C1.3: Prevent unauthorized confidential data transfer via RDP" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableClip -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.3'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
        }
    } catch {
        Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Error" `
            -Message "C1.3: DLP -- clipboard redirection disabled (RDP) -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ SOC2='C1.3'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
    }
    # C1.4: Legal notice banner
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Default $null
        if ($null -ne $val -and $val -ne "") {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Pass" `
                -Message "C1.4: Legal notice banner -- properly configured" `
                -Details "C1.4: Login banner communicates confidentiality requirements" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.4'; NIST='AC-8'; ISO27001='A.5.10' }
        } else {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Fail" `
                -Message "C1.4: Legal notice banner -- not configured (Value=$val)" `
                -Details "C1.4: Login banner communicates confidentiality requirements" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'Authorized use only. Confidential.'" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.4'; NIST='AC-8'; ISO27001='A.5.10' }
        }
    } catch {
        Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Error" `
            -Message "C1.4: Legal notice banner -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ SOC2='C1.4'; NIST='AC-8'; ISO27001='A.5.10' }
    }
    # C1.5: Autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Pass" `
                -Message "C1.5: Autoplay disabled -- properly configured" `
                -Details "C1.5: Removable media auto-execution threatens confidential data" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.5'; NIST='MP-7'; CIS='18.9.8.3' }
        } else {
            Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Fail" `
                -Message "C1.5: Autoplay disabled -- not configured (Value=$val)" `
                -Details "C1.5: Removable media auto-execution threatens confidential data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "Medium" `
                -CrossReferences @{ SOC2='C1.5'; NIST='MP-7'; CIS='18.9.8.3' }
        }
    } catch {
        Add-Result -Category "SOC2 - C1 Confidentiality" -Status "Error" `
            -Message "C1.5: Autoplay disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ SOC2='C1.5'; NIST='MP-7'; CIS='18.9.8.3' }
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
Write-Host "  [SOC2] SOC 2 Trust Service Criteria Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
    Write-Host "  SOC 2 Trust Service Criteria Module -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[SOC2] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  SOC2 module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}

# ============================================================================
# End of SOC2 Windows Security Baseline Module (Module-SOC2.ps1)
# ============================================================================
