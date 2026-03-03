# module-hipaa.ps1
# HIPAA Security Rule Compliance Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against HIPAA Security Rule (45 CFR Part 164 Subpart C)
# with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    HIPAA Security Rule compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with HIPAA Security Rule (45 CFR Part 164 Subpart C) including:
    - 164.312(a) Access Control (unique user ID, emergency access, automatic logoff, encryption)
    - 164.312(b) Audit Controls (event logging, monitoring, log retention, integrity)
    - 164.312(c) Integrity Controls (data integrity, hash validation, tamper evidence)
    - 164.312(d) Person or Entity Authentication (MFA, credentials, session controls)
    - 164.312(e) Transmission Security (encryption in transit, TLS, integrity controls)
    - 164.310 Physical Safeguards -- Technical (workstation security, media, screen lock)
    - 164.308 Administrative Safeguards -- Technical (risk assessment, backup, audit review)
    - HITECH Act Breach Readiness (encryption status, breach detection, data at rest)
    - ePHI Protection Controls (data classification readiness, minimum necessary, disposal)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: HIPAA Security Rule (45 CFR 164.302-318), HITECH Act, HHS Guidance on Risk Analysis
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-hipaa.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "HIPAA"
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

Write-Host "`n[$moduleName] Starting HIPAA Security Rule compliance checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# 164.312(a) Access Control
# ===========================================================================
Write-Host "[HIPAA] Checking 164.312(a) Access Control..." -ForegroundColor Yellow

    # 164.312(a)(1): Access control -- UAC enforcement
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(1): Access control -- UAC enforcement -- properly configured" `
                -Details "164.312(a)(1): Access control mechanisms must enforce authorized access to ePHI" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)(1)'; NIST='AC-3'; ISO27001='A.5.15'; PCIDSS='2.2.1' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(1): Access control -- UAC enforcement -- not configured (Value=$val)" `
                -Details "164.312(a)(1): Access control mechanisms must enforce authorized access to ePHI" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)(1)'; NIST='AC-3'; ISO27001='A.5.15'; PCIDSS='2.2.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(1): Access control -- UAC enforcement -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(a)(1)'; NIST='AC-3'; ISO27001='A.5.15'; PCIDSS='2.2.1' }
    }
    # 164.312(a)(2)(i): Unique user identification -- local account inventory
    try {
        $localUsers = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true })
        $userCount = $localUsers.Count
        Add-Result -Category "HIPAA - Access Control" -Status "Info" `
            -Message "164.312(a)(2)(i): $userCount enabled local user accounts found" `
            -Details "164.312(a)(2)(i) Unique User Identification: Each user accessing ePHI must have a unique ID" `
            -Severity "Informational" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='IA-2'; PCIDSS='8.1.1' }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(i): Unique user identification -- local account inventory -- check failed: $_" `
            -Severity "Informational" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='IA-2' }
    }
    # 164.312(a)(2)(i)b: Unique user identification -- Guest account disabled
    try {
        $guestAcct = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guestAcct -and $guestAcct.Enabled -eq $false) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(i)b: Guest account is disabled" `
                -Details "164.312(a)(2)(i): Shared/anonymous accounts violate unique user identification" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='AC-2'; ISO27001='A.5.18' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(2)(i)b: Guest account is ENABLED" `
                -Details "164.312(a)(2)(i): Guest account allows anonymous access to ePHI systems" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='AC-2'; ISO27001='A.5.18' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(i)b: Unique user identification -- Guest account disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='AC-2' }
    }
    # 164.312(a)(2)(i)c: Unique user identification -- admin account count
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $adminCount = if ($null -ne $localAdmins) { @($localAdmins).Count } else { 0 }
        if ($adminCount -le 3) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(i)c: $adminCount local administrator accounts (appropriate)" `
                -Details "164.312(a)(2)(i): Administrative access to ePHI systems is limited" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='AC-6'; PCIDSS='7.1.1' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Warning" `
                -Message "164.312(a)(2)(i)c: $adminCount local administrator accounts (review needed)" `
                -Details "164.312(a)(2)(i): Excessive admin accounts increase ePHI exposure risk" `
                -Remediation "Review and minimize administrator group membership" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='AC-6'; PCIDSS='7.1.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(i)c: Unique user identification -- admin account count -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(i)'; NIST='AC-6' }
    }
    # 164.312(a)(2)(iii): Automatic logoff -- inactivity timeout
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(iii): Automatic logoff -- inactivity timeout -- properly configured" `
                -Details "164.312(a)(2)(iii): Automatic logoff protects ePHI on unattended workstations" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-11'; PCIDSS='8.3.9'; CIS='2.3.7.3' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(2)(iii): Automatic logoff -- inactivity timeout -- not configured (Value=$val)" `
                -Details "164.312(a)(2)(iii): Automatic logoff protects ePHI on unattended workstations" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-11'; PCIDSS='8.3.9'; CIS='2.3.7.3' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(iii): Automatic logoff -- inactivity timeout -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-11'; PCIDSS='8.3.9'; CIS='2.3.7.3' }
    }
    # 164.312(a)(2)(iii)b: Automatic logoff -- screen saver lock
    try {
        $val = Get-RegValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Default $null
        if ($null -ne $val -and $val -eq "1") {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(iii)b: Automatic logoff -- screen saver lock -- properly configured" `
                -Details "164.312(a)(2)(iii): Screen saver must require authentication to unlock" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-11(1)'; CIS='2.3.1.2' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(2)(iii)b: Automatic logoff -- screen saver lock -- not configured (Value=$val)" `
                -Details "164.312(a)(2)(iii): Screen saver must require authentication to unlock" `
                -Remediation "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-11(1)'; CIS='2.3.1.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(iii)b: Automatic logoff -- screen saver lock -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-11(1)'; CIS='2.3.1.2' }
    }
    # 164.312(a)(2)(iii)c: Automatic logoff -- RDP idle disconnect
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Default $null
        if ($null -ne $val -and $val -le 900000) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(iii)c: Automatic logoff -- RDP idle disconnect -- properly configured" `
                -Details "164.312(a)(2)(iii): Remote sessions accessing ePHI must auto-disconnect when idle" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(2)(iii)c: Automatic logoff -- RDP idle disconnect -- not configured (Value=$val)" `
                -Details "164.312(a)(2)(iii): Remote sessions accessing ePHI must auto-disconnect when idle" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -Value 900000" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(iii)c: Automatic logoff -- RDP idle disconnect -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(iii)'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
    }
    # 164.312(a)(2)(iv): Encryption of ePHI -- BitLocker status
    try {
        $blStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($null -ne $blStatus -and $blStatus.ProtectionStatus -eq "On") {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(iv): BitLocker encryption active on system drive" `
                -Details "164.312(a)(2)(iv) Encryption/Decryption: ePHI at rest is encrypted" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iv)'; NIST='SC-28'; PCIDSS='3.4.1'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(2)(iv): BitLocker NOT active -- ePHI at rest may be unencrypted" `
                -Details "164.312(a)(2)(iv) Encryption/Decryption: Addressable but strongly recommended" `
                -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iv)'; NIST='SC-28'; PCIDSS='3.4.1'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(iv): Encryption of ePHI -- BitLocker status -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(iv)'; NIST='SC-28' }
    }
    # 164.312(a)(2)(iv)b: Encryption of ePHI -- BitLocker encryption method
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Default $null
        if ($null -ne $val -and $val -ge 7) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(2)(iv)b: Encryption of ePHI -- BitLocker encryption method -- properly configured" `
                -Details "164.312(a)(2)(iv): Encryption must use AES-256 or equivalent for ePHI protection" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iv)'; NIST='SC-13'; PCIDSS='3.4.2' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(2)(iv)b: Encryption of ePHI -- BitLocker encryption method -- not configured (Value=$val)" `
                -Details "164.312(a)(2)(iv): Encryption must use AES-256 or equivalent for ePHI protection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name EncryptionMethodWithXtsOs -Value 7" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(a)(2)(iv)'; NIST='SC-13'; PCIDSS='3.4.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(2)(iv)b: Encryption of ePHI -- BitLocker encryption method -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.312(a)(2)(iv)'; NIST='SC-13'; PCIDSS='3.4.2' }
    }
    # 164.312(a)(3): Access control -- anonymous enumeration restricted
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(3): Access control -- anonymous enumeration restricted -- properly configured" `
                -Details "164.312(a): Anonymous enumeration of system resources must be restricted" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='AC-14'; CIS='2.3.10.6' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(3): Access control -- anonymous enumeration restricted -- not configured (Value=$val)" `
                -Details "164.312(a): Anonymous enumeration of system resources must be restricted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='AC-14'; CIS='2.3.10.6' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(3): Access control -- anonymous enumeration restricted -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)'; NIST='AC-14'; CIS='2.3.10.6' }
    }
    # 164.312(a)(4): Access control -- UAC admin approval mode
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(4): Access control -- UAC admin approval mode -- properly configured" `
                -Details "164.312(a): Administrative access must require explicit consent for elevation" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='AC-6'; CIS='2.3.17.3' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(4): Access control -- UAC admin approval mode -- not configured (Value=$val)" `
                -Details "164.312(a): Administrative access must require explicit consent for elevation" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='AC-6'; CIS='2.3.17.3' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(4): Access control -- UAC admin approval mode -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(a)'; NIST='AC-6'; CIS='2.3.17.3' }
    }
    # 164.312(a)(5): Access control -- LSASS protection
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(5): Access control -- LSASS protection -- properly configured" `
                -Details "164.312(a): Credential store must be protected against unauthorized extraction" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5(13)'; CIS='18.3.1' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(5): Access control -- LSASS protection -- not configured (Value=$val)" `
                -Details "164.312(a): Credential store must be protected against unauthorized extraction" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5(13)'; CIS='18.3.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(5): Access control -- LSASS protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5(13)'; CIS='18.3.1' }
    }
    # 164.312(a)(6): Access control -- WDigest disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(6): Access control -- WDigest disabled -- properly configured" `
                -Details "164.312(a): Plaintext credential caching must be disabled to protect user authentication" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5(13)'; CIS='18.3.6' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(6): Access control -- WDigest disabled -- not configured (Value=$val)" `
                -Details "164.312(a): Plaintext credential caching must be disabled to protect user authentication" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5(13)'; CIS='18.3.6' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(6): Access control -- WDigest disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5(13)'; CIS='18.3.6' }
    }
    # 164.312(a)(7): Access control -- NTLMv2 only
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default $null
        if ($null -ne $val -and $val -ge 5) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(7): Access control -- NTLMv2 only -- properly configured" `
                -Details "164.312(a): Only strong authentication protocols permitted for ePHI access" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-2'; CIS='2.3.11.7' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(7): Access control -- NTLMv2 only -- not configured (Value=$val)" `
                -Details "164.312(a): Only strong authentication protocols permitted for ePHI access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-2'; CIS='2.3.11.7' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(7): Access control -- NTLMv2 only -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-2'; CIS='2.3.11.7' }
    }
    # 164.312(a)(8): Access control -- LM hash storage disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Access Control" -Status "Pass" `
                -Message "164.312(a)(8): Access control -- LM hash storage disabled -- properly configured" `
                -Details "164.312(a): Weak credential storage enables unauthorized ePHI access" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5'; CIS='2.3.11.5' }
        } else {
            Add-Result -Category "HIPAA - Access Control" -Status "Fail" `
                -Message "164.312(a)(8): Access control -- LM hash storage disabled -- not configured (Value=$val)" `
                -Details "164.312(a): Weak credential storage enables unauthorized ePHI access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5'; CIS='2.3.11.5' }
        }
    } catch {
        Add-Result -Category "HIPAA - Access Control" -Status "Error" `
            -Message "164.312(a)(8): Access control -- LM hash storage disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(a)'; NIST='IA-5'; CIS='2.3.11.5' }
    }

# ===========================================================================
# 164.312(b) Audit Controls
# ===========================================================================
Write-Host "[HIPAA] Checking 164.312(b) Audit Controls..." -ForegroundColor Yellow

    # 164.312(b)(1): Audit controls -- Event Log service
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(1): Audit controls -- Event Log service -- service running" `
                -Details "164.312(b): Hardware/software/procedural mechanisms to record ePHI access" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; ISO27001='A.8.15'; PCIDSS='10.2.1' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(1): Audit controls -- Event Log service -- service not running (Status=$svcSt)" `
                -Details "164.312(b): Hardware/software/procedural mechanisms to record ePHI access" `
                -Remediation "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; ISO27001='A.8.15'; PCIDSS='10.2.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(1): Audit controls -- Event Log service -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; ISO27001='A.8.15'; PCIDSS='10.2.1' }
    }
    # 164.312(b)(2): Audit controls -- Logon event auditing
    try {
        $auditOut = auditpol /get /category:"Logon/Logoff" 2>&1
        $logonAudit = $false
        foreach ($line in $auditOut) { if ($line -match "Logon" -and $line -match "Success") { $logonAudit = $true } }
        if ($logonAudit) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(2): Logon event auditing enabled for ePHI access tracking" `
                -Details "164.312(b): All ePHI access attempts must generate audit records" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; CIS='17.5.1'; PCIDSS='10.2.1' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(2): Logon auditing NOT enabled -- ePHI access untracked" `
                -Details "164.312(b): Cannot demonstrate access accountability without logon auditing" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; CIS='17.5.1'; PCIDSS='10.2.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(2): Audit controls -- Logon event auditing -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2' }
    }
    # 164.312(b)(3): Audit controls -- Account Management auditing
    try {
        $auditOut = auditpol /get /category:"Account Management" 2>&1
        $acctAudit = $false
        foreach ($line in $auditOut) { if ($line -match "User Account Management" -and $line -match "Success") { $acctAudit = $true } }
        if ($acctAudit) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(3): Account management auditing enabled" `
                -Details "164.312(b): User account changes affecting ePHI access are tracked" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; CIS='17.1.1' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(3): Account management auditing NOT enabled" `
                -Details "164.312(b): Access control changes to ePHI systems are untracked" `
                -Remediation "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2'; CIS='17.1.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(3): Audit controls -- Account Management auditing -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-2' }
    }
    # 164.312(b)(4): Audit controls -- Policy Change auditing
    try {
        $auditOut = auditpol /get /category:"Policy Change" 2>&1
        $polAudit = $false
        foreach ($line in $auditOut) { if ($line -match "Audit Policy Change" -and $line -match "Success") { $polAudit = $true } }
        if ($polAudit) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(4): Security policy change auditing enabled" `
                -Details "164.312(b): Changes to audit configuration are themselves audited" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='17.7.1' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(4): Policy change auditing NOT enabled" `
                -Details "164.312(b): Audit policy tampering cannot be detected" `
                -Remediation "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='17.7.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(4): Audit controls -- Policy Change auditing -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12' }
    }
    # 164.312(b)(5): Audit controls -- Object Access auditing
    try {
        $auditOut = auditpol /get /category:"Object Access" 2>&1
        $objAudit = $false
        foreach ($line in $auditOut) { if ($line -match "File System" -and ($line -match "Success" -or $line -match "Failure")) { $objAudit = $true } }
        if ($objAudit) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(5): File system object access auditing enabled" `
                -Details "164.312(b): File-level access to ePHI stores can be monitored" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='17.6.1' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Warning" `
                -Message "164.312(b)(5): Object access auditing NOT configured" `
                -Details "164.312(b): Cannot track file-level ePHI access without object auditing" `
                -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='17.6.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(5): Audit controls -- Object Access auditing -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12' }
    }
    # 164.312(b)(6): Audit log retention -- Security log size
    try {
        $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
        $secLogMB = [Math]::Round($secLogSize / 1MB, 0)
        if ($secLogSize -ge 1073741824) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(6): Security log size is ${secLogMB}MB (`>= 1024MB)" `
                -Details "164.312(b): HIPAA requires 6-year retention; adequate local log size supports this" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-4'; PCIDSS='10.3.1' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(6): Security log size is ${secLogMB}MB (requires `>= 1024MB)" `
                -Details "164.312(b): Insufficient log capacity for HIPAA retention requirements" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-4'; PCIDSS='10.3.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(6): Audit log retention -- Security log size -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-4' }
    }
    # 164.312(b)(7): Audit controls -- PowerShell Script Block Logging
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(7): Audit controls -- PowerShell Script Block Logging -- properly configured" `
                -Details "164.312(b): PowerShell script execution must be logged for ePHI system forensics" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='18.9.100.1' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(7): Audit controls -- PowerShell Script Block Logging -- not configured (Value=$val)" `
                -Details "164.312(b): PowerShell script execution must be logged for ePHI system forensics" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='18.9.100.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(7): Audit controls -- PowerShell Script Block Logging -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='18.9.100.1' }
    }
    # 164.312(b)(8): Audit controls -- PowerShell Transcription
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(8): Audit controls -- PowerShell Transcription -- properly configured" `
                -Details "164.312(b): PowerShell transcription provides detailed command history for investigations" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='18.9.100.2' }
        } else {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(8): Audit controls -- PowerShell Transcription -- not configured (Value=$val)" `
                -Details "164.312(b): PowerShell transcription provides detailed command history for investigations" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='18.9.100.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(8): Audit controls -- PowerShell Transcription -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-12'; CIS='18.9.100.2' }
    }
    # 164.312(b)(9): Time synchronization -- W32Time
    try {
        $svc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "HIPAA - Audit Controls" -Status "Pass" `
                -Message "164.312(b)(9): Time synchronization -- W32Time -- service running" `
                -Details "164.312(b): Accurate timestamps are essential for audit trail integrity and correlation" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-8'; PCIDSS='10.6.1' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "HIPAA - Audit Controls" -Status "Fail" `
                -Message "164.312(b)(9): Time synchronization -- W32Time -- service not running (Status=$svcSt)" `
                -Details "164.312(b): Accurate timestamps are essential for audit trail integrity and correlation" `
                -Remediation "Start-Service -Name W32Time; Set-Service -Name W32Time -StartupType Automatic" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-8'; PCIDSS='10.6.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Audit Controls" -Status "Error" `
            -Message "164.312(b)(9): Time synchronization -- W32Time -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(b)'; NIST='AU-8'; PCIDSS='10.6.1' }
    }

# ===========================================================================
# 164.312(c) Integrity Controls
# ===========================================================================
Write-Host "[HIPAA] Checking 164.312(c) Integrity Controls..." -ForegroundColor Yellow

    # 164.312(c)(1): Integrity -- SMB signing required (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Integrity" -Status "Pass" `
                -Message "164.312(c)(1): Integrity -- SMB signing required (server) -- properly configured" `
                -Details "164.312(c)(1): ePHI must not be improperly altered or destroyed during network transfer" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-8'; CIS='2.3.9.2' }
        } else {
            Add-Result -Category "HIPAA - Integrity" -Status "Fail" `
                -Message "164.312(c)(1): Integrity -- SMB signing required (server) -- not configured (Value=$val)" `
                -Details "164.312(c)(1): ePHI must not be improperly altered or destroyed during network transfer" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-8'; CIS='2.3.9.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Integrity" -Status "Error" `
            -Message "164.312(c)(1): Integrity -- SMB signing required (server) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-8'; CIS='2.3.9.2' }
    }
    # 164.312(c)(2): Integrity -- SMB signing required (client)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Integrity" -Status "Pass" `
                -Message "164.312(c)(2): Integrity -- SMB signing required (client) -- properly configured" `
                -Details "164.312(c)(1): Client-side message signing ensures ePHI transit integrity" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-8'; CIS='2.3.9.5' }
        } else {
            Add-Result -Category "HIPAA - Integrity" -Status "Fail" `
                -Message "164.312(c)(2): Integrity -- SMB signing required (client) -- not configured (Value=$val)" `
                -Details "164.312(c)(1): Client-side message signing ensures ePHI transit integrity" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-8'; CIS='2.3.9.5' }
        }
    } catch {
        Add-Result -Category "HIPAA - Integrity" -Status "Error" `
            -Message "164.312(c)(2): Integrity -- SMB signing required (client) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-8'; CIS='2.3.9.5' }
    }
    # 164.312(c)(3): Integrity -- Secure Boot verification
    try {
        try {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBoot -eq $true) {
                Add-Result -Category "HIPAA - Integrity" -Status "Pass" `
                    -Message "164.312(c)(3): Secure Boot is enabled -- boot integrity verified" `
                    -Details "164.312(c)(1): Boot chain integrity protects ePHI processing environment" `
                    -Severity "High" `
                    -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-7'; ISO27001='A.8.25' }
            } else {
                Add-Result -Category "HIPAA - Integrity" -Status "Fail" `
                    -Message "164.312(c)(3): Secure Boot is NOT enabled" `
                    -Details "164.312(c)(1): Boot tampering could compromise ePHI processing integrity" `
                    -Remediation "Enable Secure Boot in UEFI firmware settings" `
                    -Severity "High" `
                    -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-7'; ISO27001='A.8.25' }
            }
        } catch {
            Add-Result -Category "HIPAA - Integrity" -Status "Info" `
                -Message "164.312(c)(3): Secure Boot status could not be determined" `
                -Details "164.312(c)(1): System may use legacy BIOS" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-7' }
        }
    } catch {
        Add-Result -Category "HIPAA - Integrity" -Status "Error" `
            -Message "164.312(c)(3): Integrity -- Secure Boot verification -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-7' }
    }
    # 164.312(c)(4): Integrity -- DEP enforcement
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Default $null
        if ($null -ne $val -and $val -ne 0) {
            Add-Result -Category "HIPAA - Integrity" -Status "Pass" `
                -Message "164.312(c)(4): Integrity -- DEP enforcement -- properly configured" `
                -Details "164.312(c)(1): Data Execution Prevention protects against code injection affecting ePHI" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-16'; CIS='18.3.2' }
        } else {
            Add-Result -Category "HIPAA - Integrity" -Status "Fail" `
                -Message "164.312(c)(4): Integrity -- DEP enforcement -- not configured (Value=$val)" `
                -Details "164.312(c)(1): Data Execution Prevention protects against code injection affecting ePHI" `
                -Remediation "bcdedit /set nx AlwaysOn" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-16'; CIS='18.3.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Integrity" -Status "Error" `
            -Message "164.312(c)(4): Integrity -- DEP enforcement -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SI-16'; CIS='18.3.2' }
    }
    # 164.312(c)(5): Integrity -- pagefile cleared at shutdown
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Integrity" -Status "Pass" `
                -Message "164.312(c)(5): Integrity -- pagefile cleared at shutdown -- properly configured" `
                -Details "164.312(c)(1): ePHI remnants in pagefile must be cleared to maintain integrity" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-4'; CIS='2.3.11.9' }
        } else {
            Add-Result -Category "HIPAA - Integrity" -Status "Fail" `
                -Message "164.312(c)(5): Integrity -- pagefile cleared at shutdown -- not configured (Value=$val)" `
                -Details "164.312(c)(1): ePHI remnants in pagefile must be cleared to maintain integrity" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-4'; CIS='2.3.11.9' }
        }
    } catch {
        Add-Result -Category "HIPAA - Integrity" -Status "Error" `
            -Message "164.312(c)(5): Integrity -- pagefile cleared at shutdown -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.312(c)(1)'; NIST='SC-4'; CIS='2.3.11.9' }
    }

# ===========================================================================
# 164.312(d) Person or Entity Authentication
# ===========================================================================
Write-Host "[HIPAA] Checking 164.312(d) Person or Entity Authentication..." -ForegroundColor Yellow

    # 164.312(d)(1): Authentication -- password length
    try {
        $netAcct = net accounts 2>&1
        $minLen = 0
        foreach ($line in $netAcct) { if ($line -match "Minimum password length\s+(\d+)") { $minLen = [int]$Matches[1] } }
        if ($minLen -ge 14) {
            Add-Result -Category "HIPAA - Authentication" -Status "Pass" `
                -Message "164.312(d)(1): Minimum password length is $minLen characters" `
                -Details "164.312(d): Strong authentication ensures proper ePHI access verification" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='IA-5'; CIS='1.1.4'; PCIDSS='8.3.6' }
        } else {
            Add-Result -Category "HIPAA - Authentication" -Status "Fail" `
                -Message "164.312(d)(1): Minimum password length is $minLen (requires `>= 14)" `
                -Details "164.312(d): Weak passwords allow unauthorized ePHI access" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='IA-5'; CIS='1.1.4'; PCIDSS='8.3.6' }
        }
    } catch {
        Add-Result -Category "HIPAA - Authentication" -Status "Error" `
            -Message "164.312(d)(1): Authentication -- password length -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(d)'; NIST='IA-5' }
    }
    # 164.312(d)(2): Authentication -- account lockout
    try {
        $netAcct = net accounts 2>&1
        $lockThresh = 0
        foreach ($line in $netAcct) { if ($line -match "Lockout threshold\s+(\d+)") { $lockThresh = [int]$Matches[1] } }
        if ($lockThresh -gt 0 -and $lockThresh -le 5) {
            Add-Result -Category "HIPAA - Authentication" -Status "Pass" `
                -Message "164.312(d)(2): Account lockout threshold is $lockThresh attempts" `
                -Details "164.312(d): Lockout policy prevents brute-force access to ePHI systems" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='AC-7'; CIS='1.2.1'; PCIDSS='8.3.4' }
        } else {
            Add-Result -Category "HIPAA - Authentication" -Status "Fail" `
                -Message "164.312(d)(2): Account lockout threshold is $lockThresh (requires 1-5)" `
                -Details "164.312(d): No lockout allows unlimited authentication attempts" `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='AC-7'; CIS='1.2.1'; PCIDSS='8.3.4' }
        }
    } catch {
        Add-Result -Category "HIPAA - Authentication" -Status "Error" `
            -Message "164.312(d)(2): Authentication -- account lockout -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(d)'; NIST='AC-7' }
    }
    # 164.312(d)(3): Authentication -- password history
    try {
        $netAcct = net accounts 2>&1
        $pwHist = 0
        foreach ($line in $netAcct) { if ($line -match "Length of password history maintained\s+(\d+)") { $pwHist = [int]$Matches[1] } }
        if ($pwHist -ge 24) {
            Add-Result -Category "HIPAA - Authentication" -Status "Pass" `
                -Message "164.312(d)(3): Password history enforces $pwHist previous passwords" `
                -Details "164.312(d): Password reuse prevention strengthens ePHI authentication" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='IA-5(1)'; CIS='1.1.1' }
        } else {
            Add-Result -Category "HIPAA - Authentication" -Status "Fail" `
                -Message "164.312(d)(3): Password history is $pwHist (requires `>= 24)" `
                -Details "164.312(d): Low history enables credential reuse for ePHI access" `
                -Remediation "net accounts /uniquepw:24" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='IA-5(1)'; CIS='1.1.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Authentication" -Status "Error" `
            -Message "164.312(d)(3): Authentication -- password history -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.312(d)'; NIST='IA-5(1)' }
    }
    # 164.312(d)(4): Authentication -- NLA required for RDP
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Authentication" -Status "Pass" `
                -Message "164.312(d)(4): Authentication -- NLA required for RDP -- properly configured" `
                -Details "164.312(d): Network Level Authentication verifies identity before session establishment" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
        } else {
            Add-Result -Category "HIPAA - Authentication" -Status "Fail" `
                -Message "164.312(d)(4): Authentication -- NLA required for RDP -- not configured (Value=$val)" `
                -Details "164.312(d): Network Level Authentication verifies identity before session establishment" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(d)'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Authentication" -Status "Error" `
            -Message "164.312(d)(4): Authentication -- NLA required for RDP -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(d)'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
    }

# ===========================================================================
# 164.312(e) Transmission Security
# ===========================================================================
Write-Host "[HIPAA] Checking 164.312(e) Transmission Security..." -ForegroundColor Yellow

    # 164.312(e)(1)a: Transmission security -- TLS 1.2 enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(1)a: Transmission security -- TLS 1.2 enabled -- properly configured" `
                -Details "164.312(e)(1): ePHI transmitted over electronic networks must be encrypted" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-8'; PCIDSS='4.2.1'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(1)a: Transmission security -- TLS 1.2 enabled -- not configured (Value=$val)" `
                -Details "164.312(e)(1): ePHI transmitted over electronic networks must be encrypted" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-8'; PCIDSS='4.2.1'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(1)a: Transmission security -- TLS 1.2 enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-8'; PCIDSS='4.2.1'; ISO27001='A.8.24' }
    }
    # 164.312(e)(1)b: Transmission security -- SSL 2.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(1)b: Transmission security -- SSL 2.0 disabled -- properly configured" `
                -Details "164.312(e)(1): Insecure protocols must be disabled to protect ePHI in transit" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(1)b: Transmission security -- SSL 2.0 disabled -- not configured (Value=$val)" `
                -Details "164.312(e)(1): Insecure protocols must be disabled to protect ePHI in transit" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(1)b: Transmission security -- SSL 2.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
    }
    # 164.312(e)(1)c: Transmission security -- SSL 3.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(1)c: Transmission security -- SSL 3.0 disabled -- properly configured" `
                -Details "164.312(e)(1): SSL 3.0 POODLE vulnerability threatens ePHI confidentiality" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(1)c: Transmission security -- SSL 3.0 disabled -- not configured (Value=$val)" `
                -Details "164.312(e)(1): SSL 3.0 POODLE vulnerability threatens ePHI confidentiality" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(1)c: Transmission security -- SSL 3.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
    }
    # 164.312(e)(1)d: Transmission security -- TLS 1.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(1)d: Transmission security -- TLS 1.0 disabled -- properly configured" `
                -Details "164.312(e)(1): TLS 1.0 known vulnerabilities endanger ePHI transmission security" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(1)d: Transmission security -- TLS 1.0 disabled -- not configured (Value=$val)" `
                -Details "164.312(e)(1): TLS 1.0 known vulnerabilities endanger ePHI transmission security" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(1)d: Transmission security -- TLS 1.0 disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
    }
    # 164.312(e)(1)e: Transmission security -- TLS 1.1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(1)e: Transmission security -- TLS 1.1 disabled -- properly configured" `
                -Details "164.312(e)(1): TLS 1.1 is deprecated and should not be used for ePHI" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(1)e: Transmission security -- TLS 1.1 disabled -- not configured (Value=$val)" `
                -Details "164.312(e)(1): TLS 1.1 is deprecated and should not be used for ePHI" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(1)e: Transmission security -- TLS 1.1 disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(e)(1)'; NIST='SC-13'; PCIDSS='4.2.2' }
    }
    # 164.312(e)(2)a: Transmission security -- WinRM encryption required
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(2)a: Transmission security -- WinRM encryption required -- properly configured" `
                -Details "164.312(e)(2)(ii): Encryption mechanism to encrypt ePHI during remote management" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='SC-8'; CIS='18.9.102.1.3' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(2)a: Transmission security -- WinRM encryption required -- not configured (Value=$val)" `
                -Details "164.312(e)(2)(ii): Encryption mechanism to encrypt ePHI during remote management" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Value 0" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='SC-8'; CIS='18.9.102.1.3' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(2)a: Transmission security -- WinRM encryption required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='SC-8'; CIS='18.9.102.1.3' }
    }
    # 164.312(e)(2)b: Transmission security -- WinRM basic auth disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(2)b: Transmission security -- WinRM basic auth disabled -- properly configured" `
                -Details "164.312(e)(2)(ii): Basic auth transmits credentials in cleartext -- risk to ePHI access" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='IA-2'; CIS='18.9.102.1.1' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(2)b: Transmission security -- WinRM basic auth disabled -- not configured (Value=$val)" `
                -Details "164.312(e)(2)(ii): Basic auth transmits credentials in cleartext -- risk to ePHI access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowBasic -Value 0" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='IA-2'; CIS='18.9.102.1.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(2)b: Transmission security -- WinRM basic auth disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='IA-2'; CIS='18.9.102.1.1' }
    }
    # 164.312(e)(2)c: Transmission security -- RDP encryption level
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Default $null
        if ($null -ne $val -and $val -ge 3) {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Pass" `
                -Message "164.312(e)(2)c: Transmission security -- RDP encryption level -- properly configured" `
                -Details "164.312(e)(2)(ii): Remote Desktop sessions accessing ePHI must use high encryption" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='SC-8'; CIS='18.9.65.3.9.2' }
        } else {
            Add-Result -Category "HIPAA - Transmission Security" -Status "Fail" `
                -Message "164.312(e)(2)c: Transmission security -- RDP encryption level -- not configured (Value=$val)" `
                -Details "164.312(e)(2)(ii): Remote Desktop sessions accessing ePHI must use high encryption" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='SC-8'; CIS='18.9.65.3.9.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Transmission Security" -Status "Error" `
            -Message "164.312(e)(2)c: Transmission security -- RDP encryption level -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.312(e)(2)(ii)'; NIST='SC-8'; CIS='18.9.65.3.9.2' }
    }

# ===========================================================================
# 164.310 Physical Safeguards -- Technical Aspects
# ===========================================================================
Write-Host "[HIPAA] Checking 164.310 Physical Safeguards -- Technical Aspects..." -ForegroundColor Yellow

    # 164.310(b): Workstation use -- screen saver enabled
    try {
        $val = Get-RegValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Default $null
        if ($null -ne $val -and $val -eq "1") {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Pass" `
                -Message "164.310(b): Workstation use -- screen saver enabled -- properly configured" `
                -Details "164.310(b): Workstations with ePHI access must activate screen protection when idle" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.310(b)'; NIST='AC-11'; CIS='2.3.1.1' }
        } else {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Fail" `
                -Message "164.310(b): Workstation use -- screen saver enabled -- not configured (Value=$val)" `
                -Details "164.310(b): Workstations with ePHI access must activate screen protection when idle" `
                -Remediation "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.310(b)'; NIST='AC-11'; CIS='2.3.1.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Physical Safeguards" -Status "Error" `
            -Message "164.310(b): Workstation use -- screen saver enabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.310(b)'; NIST='AC-11'; CIS='2.3.1.1' }
    }
    # 164.310(b)b: Workstation use -- screen saver timeout
    try {
        $val = Get-RegValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Pass" `
                -Message "164.310(b)b: Workstation use -- screen saver timeout -- properly configured" `
                -Details "164.310(b): Screen saver must activate within 15 minutes to protect ePHI visibility" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.310(b)'; NIST='AC-11'; CIS='2.3.1.3' }
        } else {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Fail" `
                -Message "164.310(b)b: Workstation use -- screen saver timeout -- not configured (Value=$val)" `
                -Details "164.310(b): Screen saver must activate within 15 minutes to protect ePHI visibility" `
                -Remediation "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 900" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.310(b)'; NIST='AC-11'; CIS='2.3.1.3' }
        }
    } catch {
        Add-Result -Category "HIPAA - Physical Safeguards" -Status "Error" `
            -Message "164.310(b)b: Workstation use -- screen saver timeout -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.310(b)'; NIST='AC-11'; CIS='2.3.1.3' }
    }
    # 164.310(d)(1): Device/media controls -- autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Pass" `
                -Message "164.310(d)(1): Device/media controls -- autoplay disabled -- properly configured" `
                -Details "164.310(d)(1): Removable media must not auto-execute to prevent ePHI system compromise" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.310(d)(1)'; NIST='MP-7'; CIS='18.9.8.3' }
        } else {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Fail" `
                -Message "164.310(d)(1): Device/media controls -- autoplay disabled -- not configured (Value=$val)" `
                -Details "164.310(d)(1): Removable media must not auto-execute to prevent ePHI system compromise" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.310(d)(1)'; NIST='MP-7'; CIS='18.9.8.3' }
        }
    } catch {
        Add-Result -Category "HIPAA - Physical Safeguards" -Status "Error" `
            -Message "164.310(d)(1): Device/media controls -- autoplay disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.310(d)(1)'; NIST='MP-7'; CIS='18.9.8.3' }
    }
    # 164.310(d)(2): Device/media controls -- USB storage restrictions
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Pass" `
                -Message "164.310(d)(2): Device/media controls -- USB storage restrictions -- properly configured" `
                -Details "164.310(d)(2)(iii): Removable storage must be controlled to prevent ePHI exfiltration" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.310(d)(2)(iii)'; NIST='MP-7'; CIS='18.9.28.1' }
        } else {
            Add-Result -Category "HIPAA - Physical Safeguards" -Status "Warning" `
                -Message "164.310(d)(2): Device/media controls -- USB storage restrictions -- not configured (Value=$val)" `
                -Details "164.310(d)(2)(iii): Removable storage must be controlled to prevent ePHI exfiltration" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name Deny_All -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.310(d)(2)(iii)'; NIST='MP-7'; CIS='18.9.28.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Physical Safeguards" -Status "Error" `
            -Message "164.310(d)(2): Device/media controls -- USB storage restrictions -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.310(d)(2)(iii)'; NIST='MP-7'; CIS='18.9.28.1' }
    }

# ===========================================================================
# 164.308 Administrative Safeguards -- Technical Aspects
# ===========================================================================
Write-Host "[HIPAA] Checking 164.308 Administrative Safeguards -- Technical Aspects..." -ForegroundColor Yellow

    # 164.308(a)(1)(ii)(A): Risk analysis -- vulnerability mgmt service
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(1)(ii)(A): Risk analysis -- vulnerability mgmt service -- service running" `
                -Details "164.308(a)(1)(ii)(A): Risk analysis requires maintained systems with current patches" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.308(a)(1)(ii)(A)'; NIST='RA-3'; CISA='Patch Management' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "HIPAA - Administrative" -Status "Fail" `
                -Message "164.308(a)(1)(ii)(A): Risk analysis -- vulnerability mgmt service -- service not running (Status=$svcSt)" `
                -Details "164.308(a)(1)(ii)(A): Risk analysis requires maintained systems with current patches" `
                -Remediation "Start-Service -Name wuauserv; Set-Service -Name wuauserv -StartupType Automatic" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.308(a)(1)(ii)(A)'; NIST='RA-3'; CISA='Patch Management' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(1)(ii)(A): Risk analysis -- vulnerability mgmt service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.308(a)(1)(ii)(A)'; NIST='RA-3'; CISA='Patch Management' }
    }
    # 164.308(a)(1)(ii)(A)b: Risk analysis -- auto updates enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Default $null
        if ($null -ne $val -and $val -ge 4) {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(1)(ii)(A)b: Risk analysis -- auto updates enabled -- properly configured" `
                -Details "164.308(a)(1)(ii)(A): Automatic updates reduce vulnerability window for ePHI systems" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.308(a)(1)(ii)(A)'; NIST='SI-2'; CIS='18.9.101.2' }
        } else {
            Add-Result -Category "HIPAA - Administrative" -Status "Fail" `
                -Message "164.308(a)(1)(ii)(A)b: Risk analysis -- auto updates enabled -- not configured (Value=$val)" `
                -Details "164.308(a)(1)(ii)(A): Automatic updates reduce vulnerability window for ePHI systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -Value 4" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='164.308(a)(1)(ii)(A)'; NIST='SI-2'; CIS='18.9.101.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(1)(ii)(A)b: Risk analysis -- auto updates enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='164.308(a)(1)(ii)(A)'; NIST='SI-2'; CIS='18.9.101.2' }
    }
    # 164.308(a)(5): Security awareness -- Defender service
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(5): Security awareness -- Defender service -- service running" `
                -Details "164.308(a)(5)(ii)(B): Anti-malware protection as part of security awareness program" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "HIPAA - Administrative" -Status "Fail" `
                -Message "164.308(a)(5): Security awareness -- Defender service -- service not running (Status=$svcSt)" `
                -Details "164.308(a)(5)(ii)(B): Anti-malware protection as part of security awareness program" `
                -Remediation "Start-Service -Name WinDefend; Set-Service -Name WinDefend -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(5): Security awareness -- Defender service -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3' }
    }
    # 164.308(a)(5)b: Security awareness -- real-time AV protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(5)b: Security awareness -- real-time AV protection -- properly configured" `
                -Details "164.308(a)(5)(ii)(B): Real-time anti-malware is a fundamental ePHI protection" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3'; CIS='18.9.47.9.1' }
        } else {
            Add-Result -Category "HIPAA - Administrative" -Status "Fail" `
                -Message "164.308(a)(5)b: Security awareness -- real-time AV protection -- not configured (Value=$val)" `
                -Details "164.308(a)(5)(ii)(B): Real-time anti-malware is a fundamental ePHI protection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3'; CIS='18.9.47.9.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(5)b: Security awareness -- real-time AV protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3'; CIS='18.9.47.9.1' }
    }
    # 164.308(a)(5)c: Security awareness -- Defender not disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(5)c: Security awareness -- Defender not disabled -- properly configured" `
                -Details "164.308(a)(5)(ii)(B): Anti-malware must not be administratively disabled on ePHI systems" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3'; CIS='18.9.47.1' }
        } else {
            Add-Result -Category "HIPAA - Administrative" -Status "Fail" `
                -Message "164.308(a)(5)c: Security awareness -- Defender not disabled -- not configured (Value=$val)" `
                -Details "164.308(a)(5)(ii)(B): Anti-malware must not be administratively disabled on ePHI systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3'; CIS='18.9.47.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(5)c: Security awareness -- Defender not disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='164.308(a)(5)'; NIST='SI-3'; CIS='18.9.47.1' }
    }
    # 164.308(a)(7): Contingency plan -- VSS service available
    try {
        $svc = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(7): Contingency plan -- VSS service available -- service running" `
                -Details "164.308(a)(7)(ii)(A): Data backup capability must exist for ePHI recovery" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.308(a)(7)'; NIST='CP-9'; SOC2='A1.2' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "HIPAA - Administrative" -Status "Warning" `
                -Message "164.308(a)(7): Contingency plan -- VSS service available -- service not running (Status=$svcSt)" `
                -Details "164.308(a)(7)(ii)(A): Data backup capability must exist for ePHI recovery" `
                -Remediation "Set-Service -Name VSS -StartupType Manual" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.308(a)(7)'; NIST='CP-9'; SOC2='A1.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(7): Contingency plan -- VSS service available -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.308(a)(7)'; NIST='CP-9'; SOC2='A1.2' }
    }
    # 164.308(a)(7)b: Contingency plan -- System Restore
    try {
        $srDisabled = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Default 0
        if ($srDisabled -ne 1) {
            Add-Result -Category "HIPAA - Administrative" -Status "Pass" `
                -Message "164.308(a)(7)b: System Restore is enabled for OS recovery" `
                -Details "164.308(a)(7)(ii)(B): Disaster recovery capability supports ePHI availability" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.308(a)(7)'; NIST='CP-10'; SOC2='A1.2' }
        } else {
            Add-Result -Category "HIPAA - Administrative" -Status "Warning" `
                -Message "164.308(a)(7)b: System Restore is DISABLED" `
                -Details "164.308(a)(7)(ii)(B): Ensure alternative recovery mechanisms exist" `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name DisableSR" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='164.308(a)(7)'; NIST='CP-10'; SOC2='A1.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - Administrative" -Status "Error" `
            -Message "164.308(a)(7)b: Contingency plan -- System Restore -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='164.308(a)(7)'; NIST='CP-10' }
    }

# ===========================================================================
# HITECH Act & ePHI Protection
# ===========================================================================
Write-Host "[HIPAA] Checking HITECH Act & ePHI Protection..." -ForegroundColor Yellow

    # HITECH-1: Breach readiness -- firewall enabled all profiles
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $allEnabled = $true
        foreach ($fw in $fwProfiles) { if ($fw.Enabled -ne $true) { $allEnabled = $false } }
        if ($allEnabled -and $null -ne $fwProfiles) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-1: All firewall profiles are enabled" `
                -Details "HITECH Breach Notification: Network boundary protection reduces breach probability" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SC-7'; ISO27001='A.8.20' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-1: Not all firewall profiles are enabled" `
                -Details "HITECH Breach Notification: Disabled firewall increases breach exposure" `
                -Remediation "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SC-7'; ISO27001='A.8.20' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-1: Breach readiness -- firewall enabled all profiles -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='SC-7' }
    }
    # HITECH-2: ePHI protection -- cloud sync controlled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-2: ePHI protection -- cloud sync controlled -- properly configured" `
                -Details "HITECH: Uncontrolled cloud sync could result in unauthorized ePHI disclosure" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='AC-20'; GDPR='Art.28' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Warning" `
                -Message "HITECH-2: ePHI protection -- cloud sync controlled -- not configured (Value=$val)" `
                -Details "HITECH: Uncontrolled cloud sync could result in unauthorized ePHI disclosure" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name DisableFileSyncNGSC -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='AC-20'; GDPR='Art.28' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-2: ePHI protection -- cloud sync controlled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='AC-20'; GDPR='Art.28' }
    }
    # HITECH-3: ePHI protection -- clipboard redirection disabled (RDP)
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-3: ePHI protection -- clipboard redirection disabled (RDP) -- properly configured" `
                -Details "HITECH: RDP clipboard sharing enables ePHI data exfiltration" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-3: ePHI protection -- clipboard redirection disabled (RDP) -- not configured (Value=$val)" `
                -Details "HITECH: RDP clipboard sharing enables ePHI data exfiltration" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableClip -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-3: ePHI protection -- clipboard redirection disabled (RDP) -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
    }
    # HITECH-4: ePHI protection -- drive redirection disabled (RDP)
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-4: ePHI protection -- drive redirection disabled (RDP) -- properly configured" `
                -Details "HITECH: RDP drive mapping enables unauthorized ePHI file transfer" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='AC-4'; CIS='18.9.65.3.3.2' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-4: ePHI protection -- drive redirection disabled (RDP) -- not configured (Value=$val)" `
                -Details "HITECH: RDP drive mapping enables unauthorized ePHI file transfer" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCdm -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='AC-4'; CIS='18.9.65.3.3.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-4: ePHI protection -- drive redirection disabled (RDP) -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='AC-4'; CIS='18.9.65.3.3.2' }
    }
    # HITECH-5: ePHI protection -- network protection enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-5: ePHI protection -- network protection enabled -- properly configured" `
                -Details "HITECH: Network protection blocks malicious connections that could expose ePHI" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-5: ePHI protection -- network protection enabled -- not configured (Value=$val)" `
                -Details "HITECH: Network protection blocks malicious connections that could expose ePHI" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-5: ePHI protection -- network protection enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
    }
    # HITECH-6: ePHI protection -- controlled folder access
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-6: ePHI protection -- controlled folder access -- properly configured" `
                -Details "HITECH: Ransomware protection is essential for ePHI data stores" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-6: ePHI protection -- controlled folder access -- not configured (Value=$val)" `
                -Details "HITECH: Ransomware protection is essential for ePHI data stores" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-6: ePHI protection -- controlled folder access -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
    }
    # HITECH-7: ePHI protection -- SMBv1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-7: ePHI protection -- SMBv1 disabled -- properly configured" `
                -Details "HITECH: SMBv1 is a critical ransomware vector threatening ePHI systems" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='CM-7'; ISO27001='A.8.9'; STIG='V-220968' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-7: ePHI protection -- SMBv1 disabled -- not configured (Value=$val)" `
                -Details "HITECH: SMBv1 is a critical ransomware vector threatening ePHI systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='CM-7'; ISO27001='A.8.9'; STIG='V-220968' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-7: ePHI protection -- SMBv1 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='CM-7'; ISO27001='A.8.9'; STIG='V-220968' }
    }
    # HITECH-8: ePHI protection -- Credential Guard
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-8: ePHI protection -- Credential Guard -- properly configured" `
                -Details "HITECH: Credential isolation protects authentication to ePHI systems" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Fail" `
                -Message "HITECH-8: ePHI protection -- Credential Guard -- not configured (Value=$val)" `
                -Details "HITECH: Credential isolation protects authentication to ePHI systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -Value 1" `
                -Severity "High" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-8: ePHI protection -- Credential Guard -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='IA-5(13)'; ISO27001='A.8.2' }
    }
    # HITECH-9: ePHI protection -- telemetry minimized
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Pass" `
                -Message "HITECH-9: ePHI protection -- telemetry minimized -- properly configured" `
                -Details "HITECH: Minimize data collection to reduce incidental ePHI exposure" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SC-7'; GDPR='Art.25' }
        } else {
            Add-Result -Category "HIPAA - ePHI Protection" -Status "Warning" `
                -Message "HITECH-9: ePHI protection -- telemetry minimized -- not configured (Value=$val)" `
                -Details "HITECH: Minimize data collection to reduce incidental ePHI exposure" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ HIPAA='HITECH'; NIST='SC-7'; GDPR='Art.25' }
        }
    } catch {
        Add-Result -Category "HIPAA - ePHI Protection" -Status "Error" `
            -Message "HITECH-9: ePHI protection -- telemetry minimized -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ HIPAA='HITECH'; NIST='SC-7'; GDPR='Art.25' }
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
Write-Host "  [HIPAA] HIPAA Security Rule Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
    Write-Host "  HIPAA Security Rule Module -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[HIPAA] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  HIPAA module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}

# ============================================================================
# End of HIPAA Compliance Module (Module-HIPAA.ps1)
# ============================================================================
