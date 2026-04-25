# module-gdpr.ps1
# GDPR Technical Measures Compliance Module for Windows Security Audit
# Version: 6.1.2
#
# Evaluates Windows configuration against EU General Data Protection Regulation (2016/679)
# with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    GDPR Technical Measures compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with EU General Data Protection Regulation (2016/679) including:
    - Article 25: Data Protection by Design and Default (privacy settings, minimization)
    - Article 32(1)(a): Encryption (BitLocker, EFS, TLS, certificate management)
    - Article 32(1)(b): Confidentiality and Integrity (access control, authentication, UAC)
    - Article 32(1)(c): Availability and Resilience (backup, VSS, recovery, services)
    - Article 32(1)(d): Testing and Evaluation (audit logging, security assessment readiness)
    - Articles 33-34: Breach Notification Readiness (logging, detection, response capability)
    - Article 5: Data Processing Principles -- Technical (integrity, storage limitation)
    - Privacy-Enhancing Technologies (telemetry, tracking, diagnostic data controls)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: GDPR (2016/679), EDPB Guidelines, ENISA Guidance on GDPR Technical Measures
    Version: 6.1.2

.EXAMPLE
    $results = & .\modules\module-gdpr.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "GDPR"
$moduleVersion = "6.1.2"
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
    } catch { <# Expected: item may not exist #> }
    return $Default
}

Write-Host "`n[$moduleName] Starting GDPR Technical Measures compliance checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# Article 25 -- Data Protection by Design and Default
# ===========================================================================
Write-Host "[GDPR] Checking Article 25 -- Data Protection by Design and Default..." -ForegroundColor Yellow

    # Art.25(1)a: Privacy by design -- telemetry minimized
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(1)a: Privacy by design -- telemetry minimized -- properly configured" `
                -Details "Art.25(1): Data collection must be minimized by design; reduce telemetry to Security level" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-7'; ISO27001='A.5.10' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Warning" `
                -Message "Art.25(1)a: Privacy by design -- telemetry minimized -- not configured (Value=$val)" `
                -Details "Art.25(1): Data collection must be minimized by design; reduce telemetry to Security level" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 0" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-7'; ISO27001='A.5.10' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(1)a: Privacy by design -- telemetry minimized -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-7'; ISO27001='A.5.10' }
    }
    # Art.25(1)b: Privacy by design -- advertising ID disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(1)b: Privacy by design -- advertising ID disabled -- properly configured" `
                -Details "Art.25(1): Advertising ID tracks users across applications; must be disabled by default" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-7' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Fail" `
                -Message "Art.25(1)b: Privacy by design -- advertising ID disabled -- not configured (Value=$val)" `
                -Details "Art.25(1): Advertising ID tracks users across applications; must be disabled by default" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name DisabledByGroupPolicy -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-7' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(1)b: Privacy by design -- advertising ID disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-7' }
    }
    # Art.25(1)c: Privacy by design -- WiFi Sense disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(1)c: Privacy by design -- WiFi Sense disabled -- properly configured" `
                -Details "Art.25(1): Automatic WiFi sharing may transmit personal data to untrusted networks" `
                -Severity "Low" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-8' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Info" `
                -Message "Art.25(1)c: Privacy by design -- WiFi Sense disabled -- not configured (Value=$val)" `
                -Details "Art.25(1): Automatic WiFi sharing may transmit personal data to untrusted networks" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name AutoConnectAllowedOEM -Value 0" `
                -Severity "Low" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-8' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(1)c: Privacy by design -- WiFi Sense disabled -- check failed: $_" `
            -Severity "Low" `
            -CrossReferences @{ GDPR='Art.25(1)'; NIST='SC-8' }
    }
    # Art.25(1)d: Privacy by design -- SmartScreen filter
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(1)d: Privacy by design -- SmartScreen filter -- properly configured" `
                -Details "Art.25(1): SmartScreen protects against phishing that targets personal data" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SI-3'; CIS='18.9.85.1.1' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Fail" `
                -Message "Art.25(1)d: Privacy by design -- SmartScreen filter -- not configured (Value=$val)" `
                -Details "Art.25(1): SmartScreen protects against phishing that targets personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(1)'; NIST='SI-3'; CIS='18.9.85.1.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(1)d: Privacy by design -- SmartScreen filter -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25(1)'; NIST='SI-3'; CIS='18.9.85.1.1' }
    }
    # Art.25(2)a: Privacy by default -- OneDrive sync controlled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(2)a: Privacy by default -- OneDrive sync controlled -- properly configured" `
                -Details "Art.25(2): Cloud sync must be controlled to prevent unintended personal data processing" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='AC-20'; ISO27001='A.5.23' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Info" `
                -Message "Art.25(2)a: Privacy by default -- OneDrive sync controlled -- not configured (Value=$val)" `
                -Details "Art.25(2): Cloud sync must be controlled to prevent unintended personal data processing" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name DisableFileSyncNGSC -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='AC-20'; ISO27001='A.5.23' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(2)a: Privacy by default -- OneDrive sync controlled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25(2)'; NIST='AC-20'; ISO27001='A.5.23' }
    }
    # Art.25(2)b: Privacy by default -- Cortana disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(2)b: Privacy by default -- Cortana disabled -- properly configured" `
                -Details "Art.25(2): Voice assistants process personal data; disable unless explicitly consented" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Info" `
                -Message "Art.25(2)b: Privacy by default -- Cortana disabled -- not configured (Value=$val)" `
                -Details "Art.25(2): Voice assistants process personal data; disable unless explicitly consented" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(2)b: Privacy by default -- Cortana disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
    }
    # Art.25(2)c: Privacy by default -- location services controlled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(2)c: Privacy by default -- location services controlled -- properly configured" `
                -Details "Art.25(2): Location data is personal data; must be controlled by default" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Info" `
                -Message "Art.25(2)c: Privacy by default -- location services controlled -- not configured (Value=$val)" `
                -Details "Art.25(2): Location data is personal data; must be controlled by default" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name DisableLocation -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(2)c: Privacy by default -- location services controlled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
    }
    # Art.25(2)d: Privacy by default -- customer experience program
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(2)d: Privacy by default -- customer experience program -- properly configured" `
                -Details "Art.25(2): Customer Experience Improvement Program transmits usage data" `
                -Severity "Low" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Info" `
                -Message "Art.25(2)d: Privacy by default -- customer experience program -- not configured (Value=$val)" `
                -Details "Art.25(2): Customer Experience Improvement Program transmits usage data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name CEIPEnable -Value 0" `
                -Severity "Low" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(2)d: Privacy by default -- customer experience program -- check failed: $_" `
            -Severity "Low" `
            -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
    }
    # Art.25(2)e: Privacy by default -- error reporting controlled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(2)e: Privacy by default -- error reporting controlled -- properly configured" `
                -Details "Art.25(2): Error reports may contain personal data; control transmission" `
                -Severity "Low" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Info" `
                -Message "Art.25(2)e: Privacy by default -- error reporting controlled -- not configured (Value=$val)" `
                -Details "Art.25(2): Error reports may contain personal data; control transmission" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name Disabled -Value 1" `
                -Severity "Low" `
                -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(2)e: Privacy by default -- error reporting controlled -- check failed: $_" `
            -Severity "Low" `
            -CrossReferences @{ GDPR='Art.25(2)'; NIST='SC-7' }
    }

# ===========================================================================
# Article 32(1)(a) -- Encryption
# ===========================================================================
Write-Host "[GDPR] Checking Article 32(1)(a) -- Encryption..." -ForegroundColor Yellow

    # Art.32(1)(a)-1: Encryption -- BitLocker status
    try {
        $blStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($null -ne $blStatus -and $blStatus.ProtectionStatus -eq "On") {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Pass" `
                -Message "Art.32(1)(a)-1: BitLocker encryption active on system drive" `
                -Details "Art.32(1)(a): Pseudonymisation and encryption of personal data" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-28'; ISO27001='A.8.24'; 'PCI-DSS'='3.4.1' }
        } else {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Fail" `
                -Message "Art.32(1)(a)-1: BitLocker NOT active -- personal data at rest may be unencrypted" `
                -Details "Art.32(1)(a): Encryption is a key technical measure for GDPR compliance" `
                -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-28'; ISO27001='A.8.24'; 'PCI-DSS'='3.4.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Encryption" -Status "Error" `
            -Message "Art.32(1)(a)-1: Encryption -- BitLocker status -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-28' }
    }
    # Art.32(1)(a)-2: Encryption -- TLS 1.2 enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Pass" `
                -Message "Art.32(1)(a)-2: Encryption -- TLS 1.2 enabled -- properly configured" `
                -Details "Art.32(1)(a): Personal data in transit must be encrypted with current protocols" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-8'; ISO27001='A.8.24'; 'PCI-DSS'='4.2.1'; HIPAA='164.312(e)(1)' }
        } else {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Fail" `
                -Message "Art.32(1)(a)-2: Encryption -- TLS 1.2 enabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(a): Personal data in transit must be encrypted with current protocols" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-8'; ISO27001='A.8.24'; 'PCI-DSS'='4.2.1'; HIPAA='164.312(e)(1)' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Encryption" -Status "Error" `
            -Message "Art.32(1)(a)-2: Encryption -- TLS 1.2 enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-8'; ISO27001='A.8.24'; 'PCI-DSS'='4.2.1'; HIPAA='164.312(e)(1)' }
    }
    # Art.32(1)(a)-3: Encryption -- SSL 2.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Pass" `
                -Message "Art.32(1)(a)-3: Encryption -- SSL 2.0 disabled -- properly configured" `
                -Details "Art.32(1)(a): Deprecated encryption protocols must be disabled for personal data protection" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Fail" `
                -Message "Art.32(1)(a)-3: Encryption -- SSL 2.0 disabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(a): Deprecated encryption protocols must be disabled for personal data protection" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Encryption" -Status "Error" `
            -Message "Art.32(1)(a)-3: Encryption -- SSL 2.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
    }
    # Art.32(1)(a)-4: Encryption -- SSL 3.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Pass" `
                -Message "Art.32(1)(a)-4: Encryption -- SSL 3.0 disabled -- properly configured" `
                -Details "Art.32(1)(a): SSL 3.0 POODLE vulnerability threatens personal data confidentiality" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Fail" `
                -Message "Art.32(1)(a)-4: Encryption -- SSL 3.0 disabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(a): SSL 3.0 POODLE vulnerability threatens personal data confidentiality" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Encryption" -Status "Error" `
            -Message "Art.32(1)(a)-4: Encryption -- SSL 3.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
    }
    # Art.32(1)(a)-5: Encryption -- TLS 1.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Pass" `
                -Message "Art.32(1)(a)-5: Encryption -- TLS 1.0 disabled -- properly configured" `
                -Details "Art.32(1)(a): TLS 1.0 has known weaknesses; not appropriate for personal data" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "GDPR - Art.32 Encryption" -Status "Fail" `
                -Message "Art.32(1)(a)-5: Encryption -- TLS 1.0 disabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(a): TLS 1.0 has known weaknesses; not appropriate for personal data" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Encryption" -Status "Error" `
            -Message "Art.32(1)(a)-5: Encryption -- TLS 1.0 disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='SC-13'; ISO27001='A.8.24' }
    }

# ===========================================================================
# Article 32(1)(b) -- Confidentiality and Integrity
# ===========================================================================
Write-Host "[GDPR] Checking Article 32(1)(b) -- Confidentiality and Integrity..." -ForegroundColor Yellow

    # Art.32(1)(b)-1: Confidentiality -- UAC enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-1: Confidentiality -- UAC enabled -- properly configured" `
                -Details "Art.32(1)(b): Access control ensures ongoing confidentiality of personal data" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-3'; ISO27001='A.5.15' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-1: Confidentiality -- UAC enabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Access control ensures ongoing confidentiality of personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-3'; ISO27001='A.5.15' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-1: Confidentiality -- UAC enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-3'; ISO27001='A.5.15' }
    }
    # Art.32(1)(b)-2: Confidentiality -- LSASS protection
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-2: Confidentiality -- LSASS protection -- properly configured" `
                -Details "Art.32(1)(b): Credential protection prevents unauthorized personal data access" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-2: Confidentiality -- LSASS protection -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Credential protection prevents unauthorized personal data access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-2: Confidentiality -- LSASS protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
    }
    # Art.32(1)(b)-3: Confidentiality -- WDigest disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-3: Confidentiality -- WDigest disabled -- properly configured" `
                -Details "Art.32(1)(b): Plaintext credential caching threatens personal data confidentiality" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-3: Confidentiality -- WDigest disabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Plaintext credential caching threatens personal data confidentiality" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-3: Confidentiality -- WDigest disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
    }
    # Art.32(1)(b)-4: Confidentiality -- NTLMv2 only
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default $null
        if ($null -ne $val -and $val -ge 5) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-4: Confidentiality -- NTLMv2 only -- properly configured" `
                -Details "Art.32(1)(b): Strong authentication protects confidentiality of personal data access" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-2'; ISO27001='A.8.5'; CIS='2.3.11.7' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-4: Confidentiality -- NTLMv2 only -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Strong authentication protects confidentiality of personal data access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-2'; ISO27001='A.8.5'; CIS='2.3.11.7' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-4: Confidentiality -- NTLMv2 only -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-2'; ISO27001='A.8.5'; CIS='2.3.11.7' }
    }
    # Art.32(1)(b)-5: Integrity -- SMB signing required
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-5: Integrity -- SMB signing required -- properly configured" `
                -Details "Art.32(1)(b): Data integrity during network transfer protects personal data" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SC-8'; ISO27001='A.8.5' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-5: Integrity -- SMB signing required -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Data integrity during network transfer protects personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SC-8'; ISO27001='A.8.5' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-5: Integrity -- SMB signing required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SC-8'; ISO27001='A.8.5' }
    }
    # Art.32(1)(b)-6: Confidentiality -- password policy
    try {
        $netAcct = net accounts 2>&1
        $minLen = 0
        foreach ($line in $netAcct) { if ($line -match "Minimum password length\s+(\d+)") { $minLen = [int]$Matches[1] } }
        if ($minLen -ge 14) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-6: Minimum password length is $minLen characters" `
                -Details "Art.32(1)(b): Strong authentication protects personal data confidentiality" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5'; ISO27001='A.5.17' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-6: Minimum password length is $minLen (requires `>= 14)" `
                -Details "Art.32(1)(b): Weak authentication undermines personal data confidentiality" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5'; ISO27001='A.5.17' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-6: Confidentiality -- password policy -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='IA-5' }
    }
    # Art.32(1)(b)-7: Confidentiality -- firewall all profiles
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $allEnabled = $true
        foreach ($fw in $fwProfiles) { if ($fw.Enabled -ne $true) { $allEnabled = $false } }
        if ($allEnabled -and $null -ne $fwProfiles) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-7: All firewall profiles enabled" `
                -Details "Art.32(1)(b): Network boundary protection for personal data systems" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SC-7'; ISO27001='A.8.20' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-7: Not all firewall profiles enabled" `
                -Details "Art.32(1)(b): Firewall gaps threaten personal data confidentiality" `
                -Remediation "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SC-7'; ISO27001='A.8.20' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-7: Confidentiality -- firewall all profiles -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SC-7' }
    }
    # Art.32(1)(b)-8: Confidentiality -- anonymous enumeration blocked
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-8: Confidentiality -- anonymous enumeration blocked -- properly configured" `
                -Details "Art.32(1)(b): Anonymous access to personal data systems must be restricted" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-14'; ISO27001='A.8.5'; CIS='2.3.10.6' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-8: Confidentiality -- anonymous enumeration blocked -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Anonymous access to personal data systems must be restricted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-14'; ISO27001='A.8.5'; CIS='2.3.10.6' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-8: Confidentiality -- anonymous enumeration blocked -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-14'; ISO27001='A.8.5'; CIS='2.3.10.6' }
    }
    # Art.32(1)(b)-9: Confidentiality -- Guest account disabled
    try {
        $guestAcct = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guestAcct -and $guestAcct.Enabled -eq $false) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-9: Guest account disabled -- no anonymous access" `
                -Details "Art.32(1)(b): Anonymous accounts violate access control requirements" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-2'; ISO27001='A.5.18' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-9: Guest account is ENABLED" `
                -Details "Art.32(1)(b): Anonymous access violates GDPR access control" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-2'; ISO27001='A.5.18' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-9: Confidentiality -- Guest account disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-2' }
    }
    # Art.32(1)(b)-10: Confidentiality -- inactivity timeout
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-10: Confidentiality -- inactivity timeout -- properly configured" `
                -Details "Art.32(1)(b): Screen lock prevents unauthorized viewing of personal data" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-11'; CIS='2.3.7.3' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-10: Confidentiality -- inactivity timeout -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Screen lock prevents unauthorized viewing of personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-11'; CIS='2.3.7.3' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-10: Confidentiality -- inactivity timeout -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-11'; CIS='2.3.7.3' }
    }

# ===========================================================================
# Article 32(1)(c) -- Availability and Resilience
# ===========================================================================
Write-Host "[GDPR] Checking Article 32(1)(c) -- Availability and Resilience..." -ForegroundColor Yellow

    # Art.32(1)(c)-1: Availability -- VSS service
    try {
        $svc = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Pass" `
                -Message "Art.32(1)(c)-1: Availability -- VSS service -- service running" `
                -Details "Art.32(1)(c): Ability to restore availability and access to personal data in timely manner" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CP-9'; ISO27001='A.8.13' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Warning" `
                -Message "Art.32(1)(c)-1: Availability -- VSS service -- service not running (Status=$svcSt)" `
                -Details "Art.32(1)(c): Ability to restore availability and access to personal data in timely manner" `
                -Remediation "Set-Service -Name VSS -StartupType Manual" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CP-9'; ISO27001='A.8.13' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Availability" -Status "Error" `
            -Message "Art.32(1)(c)-1: Availability -- VSS service -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CP-9'; ISO27001='A.8.13' }
    }
    # Art.32(1)(c)-2: Availability -- Windows Update service
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Pass" `
                -Message "Art.32(1)(c)-2: Availability -- Windows Update service -- service running" `
                -Details "Art.32(1)(c): System resilience requires current security patches" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-2'; ISO27001='A.8.8' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Fail" `
                -Message "Art.32(1)(c)-2: Availability -- Windows Update service -- service not running (Status=$svcSt)" `
                -Details "Art.32(1)(c): System resilience requires current security patches" `
                -Remediation "Start-Service -Name wuauserv; Set-Service -Name wuauserv -StartupType Automatic" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-2'; ISO27001='A.8.8' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Availability" -Status "Error" `
            -Message "Art.32(1)(c)-2: Availability -- Windows Update service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-2'; ISO27001='A.8.8' }
    }
    # Art.32(1)(c)-3: Availability -- Defender service
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Pass" `
                -Message "Art.32(1)(c)-3: Availability -- Defender service -- service running" `
                -Details "Art.32(1)(c): Anti-malware protection ensures system resilience for personal data processing" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Fail" `
                -Message "Art.32(1)(c)-3: Availability -- Defender service -- service not running (Status=$svcSt)" `
                -Details "Art.32(1)(c): Anti-malware protection ensures system resilience for personal data processing" `
                -Remediation "Start-Service -Name WinDefend; Set-Service -Name WinDefend -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Availability" -Status "Error" `
            -Message "Art.32(1)(c)-3: Availability -- Defender service -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1' }
    }
    # Art.32(1)(c)-4: Resilience -- real-time protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Pass" `
                -Message "Art.32(1)(c)-4: Resilience -- real-time protection -- properly configured" `
                -Details "Art.32(1)(c): Real-time protection ensures resilience against malware threats to personal data" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1'; CIS='18.9.47.9.1' }
        } else {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Fail" `
                -Message "Art.32(1)(c)-4: Resilience -- real-time protection -- not configured (Value=$val)" `
                -Details "Art.32(1)(c): Real-time protection ensures resilience against malware threats to personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1'; CIS='18.9.47.9.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Availability" -Status "Error" `
            -Message "Art.32(1)(c)-4: Resilience -- real-time protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1'; CIS='18.9.47.9.1' }
    }
    # Art.32(1)(c)-5: Resilience -- SMBv1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Pass" `
                -Message "Art.32(1)(c)-5: Resilience -- SMBv1 disabled -- properly configured" `
                -Details "Art.32(1)(c): SMBv1 (WannaCry vector) threatens availability of personal data systems" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CM-7'; ISO27001='A.8.9' }
        } else {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Fail" `
                -Message "Art.32(1)(c)-5: Resilience -- SMBv1 disabled -- not configured (Value=$val)" `
                -Details "Art.32(1)(c): SMBv1 (WannaCry vector) threatens availability of personal data systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CM-7'; ISO27001='A.8.9' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Availability" -Status "Error" `
            -Message "Art.32(1)(c)-5: Resilience -- SMBv1 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CM-7'; ISO27001='A.8.9' }
    }
    # Art.32(1)(c)-6: Resilience -- controlled folder access
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Pass" `
                -Message "Art.32(1)(c)-6: Resilience -- controlled folder access -- properly configured" `
                -Details "Art.32(1)(c): Ransomware protection preserves availability of personal data stores" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1' }
        } else {
            Add-Result -Category "GDPR - Art.32 Availability" -Status "Fail" `
                -Message "Art.32(1)(c)-6: Resilience -- controlled folder access -- not configured (Value=$val)" `
                -Details "Art.32(1)(c): Ransomware protection preserves availability of personal data stores" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Availability" -Status "Error" `
            -Message "Art.32(1)(c)-6: Resilience -- controlled folder access -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='SI-3'; ISO27001='A.8.1' }
    }

# ===========================================================================
# Article 32(1)(d) -- Testing and Evaluation
# ===========================================================================
Write-Host "[GDPR] Checking Article 32(1)(d) -- Testing and Evaluation..." -ForegroundColor Yellow

    # Art.32(1)(d)-1: Testing -- Event Log service operational
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "GDPR - Art.32 Testing" -Status "Pass" `
                -Message "Art.32(1)(d)-1: Testing -- Event Log service operational -- service running" `
                -Details "Art.32(1)(d): Regular testing of security measures requires audit trail capability" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-2'; ISO27001='A.8.15' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "GDPR - Art.32 Testing" -Status "Fail" `
                -Message "Art.32(1)(d)-1: Testing -- Event Log service operational -- service not running (Status=$svcSt)" `
                -Details "Art.32(1)(d): Regular testing of security measures requires audit trail capability" `
                -Remediation "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-2'; ISO27001='A.8.15' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Testing" -Status "Error" `
            -Message "Art.32(1)(d)-1: Testing -- Event Log service operational -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-2'; ISO27001='A.8.15' }
    }
    # Art.32(1)(d)-2: Testing -- audit policy: Logon events
    try {
        $auditOut = auditpol /get /category:"Logon/Logoff" 2>&1
        $logonAudit = $false
        foreach ($line in $auditOut) { if ($line -match "Logon" -and $line -match "Success") { $logonAudit = $true } }
        if ($logonAudit) {
            Add-Result -Category "GDPR - Art.32 Testing" -Status "Pass" `
                -Message "Art.32(1)(d)-2: Logon auditing enables access testing and evaluation" `
                -Details "Art.32(1)(d): Testing effectiveness of technical measures" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-2'; ISO27001='A.8.15' }
        } else {
            Add-Result -Category "GDPR - Art.32 Testing" -Status "Fail" `
                -Message "Art.32(1)(d)-2: Logon auditing NOT enabled -- testing capability impaired" `
                -Details "Art.32(1)(d): Cannot evaluate access control effectiveness without auditing" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-2'; ISO27001='A.8.15' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Testing" -Status "Error" `
            -Message "Art.32(1)(d)-2: Testing -- audit policy: Logon events -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-2' }
    }
    # Art.32(1)(d)-3: Testing -- PowerShell Script Block Logging
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.32 Testing" -Status "Pass" `
                -Message "Art.32(1)(d)-3: Testing -- PowerShell Script Block Logging -- properly configured" `
                -Details "Art.32(1)(d): Script execution logging supports security testing and evaluation" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-12'; ISO27001='A.8.9'; CIS='18.9.100.1' }
        } else {
            Add-Result -Category "GDPR - Art.32 Testing" -Status "Fail" `
                -Message "Art.32(1)(d)-3: Testing -- PowerShell Script Block Logging -- not configured (Value=$val)" `
                -Details "Art.32(1)(d): Script execution logging supports security testing and evaluation" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-12'; ISO27001='A.8.9'; CIS='18.9.100.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Testing" -Status "Error" `
            -Message "Art.32(1)(d)-3: Testing -- PowerShell Script Block Logging -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.32(1)(d)'; NIST='AU-12'; ISO27001='A.8.9'; CIS='18.9.100.1' }
    }

# ===========================================================================
# Articles 33-34 -- Breach Notification Readiness
# ===========================================================================
Write-Host "[GDPR] Checking Articles 33-34 -- Breach Notification Readiness..." -ForegroundColor Yellow

    # Art.33(1): Breach detection -- Security log capacity
    try {
        $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
        $secLogMB = [Math]::Round($secLogSize / 1MB, 0)
        if ($secLogSize -ge 1073741824) {
            Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Pass" `
                -Message "Art.33(1): Security log is ${secLogMB}MB -- adequate for 72-hour breach notification" `
                -Details "Art.33(1): Breach must be reported to SA within 72 hours; logs enable detection" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.33(1)'; NIST='AU-4'; ISO27001='A.5.28' }
        } else {
            Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Fail" `
                -Message "Art.33(1): Security log is ${secLogMB}MB -- may not support breach investigation" `
                -Details "Art.33(1): Insufficient logging impairs 72-hour notification capability" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.33(1)'; NIST='AU-4'; ISO27001='A.5.28' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Error" `
            -Message "Art.33(1): Breach detection -- Security log capacity -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.33(1)'; NIST='AU-4' }
    }
    # Art.33(2): Breach notification -- time sync service
    try {
        $svc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Pass" `
                -Message "Art.33(2): Breach notification -- time sync service -- service running" `
                -Details "Art.33(2): Accurate timestamps enable precise breach timeline reconstruction" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.33(2)'; NIST='AU-8'; 'PCI-DSS'='10.6.1' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Fail" `
                -Message "Art.33(2): Breach notification -- time sync service -- service not running (Status=$svcSt)" `
                -Details "Art.33(2): Accurate timestamps enable precise breach timeline reconstruction" `
                -Remediation "Start-Service -Name W32Time; Set-Service -Name W32Time -StartupType Automatic" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.33(2)'; NIST='AU-8'; 'PCI-DSS'='10.6.1' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Error" `
            -Message "Art.33(2): Breach notification -- time sync service -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.33(2)'; NIST='AU-8'; 'PCI-DSS'='10.6.1' }
    }
    # Art.33(3): Breach detection -- network protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Pass" `
                -Message "Art.33(3): Breach detection -- network protection -- properly configured" `
                -Details "Art.33(3): Network protection aids breach detection and data exfiltration prevention" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.33(3)'; NIST='SI-4'; ISO27001='A.8.16' }
        } else {
            Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Fail" `
                -Message "Art.33(3): Breach detection -- network protection -- not configured (Value=$val)" `
                -Details "Art.33(3): Network protection aids breach detection and data exfiltration prevention" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.33(3)'; NIST='SI-4'; ISO27001='A.8.16' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.33-34 Breach" -Status "Error" `
            -Message "Art.33(3): Breach detection -- network protection -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.33(3)'; NIST='SI-4'; ISO27001='A.8.16' }
    }

# ===========================================================================
# Article 5 & 17 -- Data Processing Principles
# ===========================================================================
Write-Host "[GDPR] Checking Article 5 & 17 -- Data Processing Principles..." -ForegroundColor Yellow

    # Art.5(1)(f): Integrity and confidentiality -- Credential Guard
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Pass" `
                -Message "Art.5(1)(f): Integrity and confidentiality -- Credential Guard -- properly configured" `
                -Details "Art.5(1)(f): Processing must ensure appropriate security including protection against unauthorized access" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.5(1)(f)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        } else {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Fail" `
                -Message "Art.5(1)(f): Integrity and confidentiality -- Credential Guard -- not configured (Value=$val)" `
                -Details "Art.5(1)(f): Processing must ensure appropriate security including protection against unauthorized access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -Value 1" `
                -Severity "High" `
                -CrossReferences @{ GDPR='Art.5(1)(f)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.5 Principles" -Status "Error" `
            -Message "Art.5(1)(f): Integrity and confidentiality -- Credential Guard -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ GDPR='Art.5(1)(f)'; NIST='IA-5(13)'; ISO27001='A.8.2' }
    }
    # Art.5(1)(f)b: Integrity -- LM hash storage disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Pass" `
                -Message "Art.5(1)(f)b: Integrity -- LM hash storage disabled -- properly configured" `
                -Details "Art.5(1)(f): Weak credential storage threatens security of personal data processing" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.5(1)(f)'; NIST='IA-5'; CIS='2.3.11.5' }
        } else {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Fail" `
                -Message "Art.5(1)(f)b: Integrity -- LM hash storage disabled -- not configured (Value=$val)" `
                -Details "Art.5(1)(f): Weak credential storage threatens security of personal data processing" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ GDPR='Art.5(1)(f)'; NIST='IA-5'; CIS='2.3.11.5' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.5 Principles" -Status "Error" `
            -Message "Art.5(1)(f)b: Integrity -- LM hash storage disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ GDPR='Art.5(1)(f)'; NIST='IA-5'; CIS='2.3.11.5' }
    }
    # Art.17: Right to erasure -- pagefile cleared at shutdown
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Pass" `
                -Message "Art.17: Right to erasure -- pagefile cleared at shutdown -- properly configured" `
                -Details "Art.17 Right to erasure: Memory residue containing personal data must be cleared" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.17'; NIST='SC-4'; ISO27001='A.8.10'; CIS='2.3.11.9' }
        } else {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Fail" `
                -Message "Art.17: Right to erasure -- pagefile cleared at shutdown -- not configured (Value=$val)" `
                -Details "Art.17 Right to erasure: Memory residue containing personal data must be cleared" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.17'; NIST='SC-4'; ISO27001='A.8.10'; CIS='2.3.11.9' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.5 Principles" -Status "Error" `
            -Message "Art.17: Right to erasure -- pagefile cleared at shutdown -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.17'; NIST='SC-4'; ISO27001='A.8.10'; CIS='2.3.11.9' }
    }
    # Art.25(3): Clipboard redirection -- RDP data leakage
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Pass" `
                -Message "Art.25(3): Clipboard redirection -- RDP data leakage -- properly configured" `
                -Details "Art.25: RDP clipboard enables uncontrolled personal data transfer" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='AC-4'; ISO27001='A.8.12' }
        } else {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Fail" `
                -Message "Art.25(3): Clipboard redirection -- RDP data leakage -- not configured (Value=$val)" `
                -Details "Art.25: RDP clipboard enables uncontrolled personal data transfer" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableClip -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='AC-4'; ISO27001='A.8.12' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.5 Principles" -Status "Error" `
            -Message "Art.25(3): Clipboard redirection -- RDP data leakage -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25'; NIST='AC-4'; ISO27001='A.8.12' }
    }
    # Art.25(4): Drive redirection -- RDP data leakage
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Pass" `
                -Message "Art.25(4): Drive redirection -- RDP data leakage -- properly configured" `
                -Details "Art.25: RDP drive mapping enables unauthorized personal data file transfer" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='AC-4'; ISO27001='A.8.12' }
        } else {
            Add-Result -Category "GDPR - Art.5 Principles" -Status "Fail" `
                -Message "Art.25(4): Drive redirection -- RDP data leakage -- not configured (Value=$val)" `
                -Details "Art.25: RDP drive mapping enables unauthorized personal data file transfer" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCdm -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='AC-4'; ISO27001='A.8.12' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.5 Principles" -Status "Error" `
            -Message "Art.25(4): Drive redirection -- RDP data leakage -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25'; NIST='AC-4'; ISO27001='A.8.12' }
    }
    # Art.25(5): Privacy -- autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(5): Privacy -- autoplay disabled -- properly configured" `
                -Details "Art.25: AutoPlay from removable media could introduce malware targeting personal data" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='MP-7'; CIS='18.9.8.3' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Fail" `
                -Message "Art.25(5): Privacy -- autoplay disabled -- not configured (Value=$val)" `
                -Details "Art.25: AutoPlay from removable media could introduce malware targeting personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='MP-7'; CIS='18.9.8.3' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(5): Privacy -- autoplay disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25'; NIST='MP-7'; CIS='18.9.8.3' }
    }
    # Art.25(6): Privacy -- LLMNR disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Pass" `
                -Message "Art.25(6): Privacy -- LLMNR disabled -- properly configured" `
                -Details "Art.25: Broadcast protocols enable network poisoning that could expose personal data" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='SC-20'; CIS='18.5.4.2' }
        } else {
            Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Fail" `
                -Message "Art.25(6): Privacy -- LLMNR disabled -- not configured (Value=$val)" `
                -Details "Art.25: Broadcast protocols enable network poisoning that could expose personal data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.25'; NIST='SC-20'; CIS='18.5.4.2' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.25 Privacy by Design" -Status "Error" `
            -Message "Art.25(6): Privacy -- LLMNR disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.25'; NIST='SC-20'; CIS='18.5.4.2' }
    }
    # Art.32(1)(b)-11: Confidentiality -- legal notice banner
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Default $null
        if ($null -ne $val -and $val -ne "") {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Pass" `
                -Message "Art.32(1)(b)-11: Confidentiality -- legal notice banner -- properly configured" `
                -Details "Art.32(1)(b): Login banner informs users of data protection obligations" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-8'; ISO27001='A.5.10' }
        } else {
            Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Fail" `
                -Message "Art.32(1)(b)-11: Confidentiality -- legal notice banner -- not configured (Value=$val)" `
                -Details "Art.32(1)(b): Login banner informs users of data protection obligations" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'This system processes personal data under GDPR. Authorized use only.'" `
                -Severity "Medium" `
                -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-8'; ISO27001='A.5.10' }
        }
    } catch {
        Add-Result -Category "GDPR - Art.32 Confidentiality" -Status "Error" `
            -Message "Art.32(1)(b)-11: Confidentiality -- legal notice banner -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='AC-8'; ISO27001='A.5.10' }
    }


# ===========================================================================
# v6.1: ePrivacy Directive technical controls
# ===========================================================================
Write-Host "[GDPR] Checking ePrivacy Directive technical controls..." -ForegroundColor Yellow

try {
    $tlsv12Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default $null
    if ($null -eq $tlsv12Server -or $tlsv12Server -eq 1) {
        Add-Result -Category "GDPR - ePrivacy Directive" -Status "Pass" `
            -Severity "Medium" `
            -Message "ePrivacy Art. 5 Confidentiality of communications (TLS 1.2 available)" `
            -Details "Directive 2002/58/EC requires confidentiality of electronic communications" `
            -CrossReferences @{ ePrivacy='Art.5'; Directive='2002/58/EC'; NIST='SC-8' }
    }
    else {
        Add-Result -Category "GDPR - ePrivacy Directive" -Status "Fail" `
            -Severity "High" `
            -Message "ePrivacy Art. 5 TLS 1.2 disabled (communications confidentiality at risk)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -Type DWord" `
            -CrossReferences @{ ePrivacy='Art.5'; Directive='2002/58/EC' }
    }

    $smbSigning = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default 0
    if ($smbSigning -eq 1) {
        Add-Result -Category "GDPR - ePrivacy Directive" -Status "Pass" `
            -Severity "Medium" `
            -Message "ePrivacy Art. 4 Communications integrity protection (SMB signing required)" `
            -CrossReferences @{ ePrivacy='Art.4'; Directive='2002/58/EC'; NIST='SC-8(1)' }
    }
    else {
        Add-Result -Category "GDPR - ePrivacy Directive" -Status "Fail" `
            -Severity "Medium" `
            -Message "ePrivacy Art. 4 SMB signing not required (integrity protection gap)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord" `
            -CrossReferences @{ ePrivacy='Art.4'; Directive='2002/58/EC' }
    }

    $cookiePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $defaultCookies = Get-RegValue -Path $cookiePath -Name "DefaultCookiesSetting" -Default $null
    if ($defaultCookies -eq 4) {
        Add-Result -Category "GDPR - ePrivacy Directive" -Status "Pass" `
            -Severity "Low" `
            -Message "ePrivacy Art. 5(3) Browser cookie consent enforced (session-only by default)" `
            -CrossReferences @{ ePrivacy='Art.5(3)'; Directive='2002/58/EC' }
    }
    else {
        Add-Result -Category "GDPR - ePrivacy Directive" -Status "Info" `
            -Severity "Informational" `
            -Message "ePrivacy Art. 5(3) Browser cookie policy at default (consent typically managed at site level)" `
            -CrossReferences @{ ePrivacy='Art.5(3)' }
    }
}
catch {
    Add-Result -Category "GDPR - ePrivacy Directive" -Status "Error" `
        -Severity "Medium" `
        -Message "ePrivacy Directive control assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Schrems II / international transfer technical safeguards
# ===========================================================================
Write-Host "[GDPR] Checking international transfer technical safeguards..." -ForegroundColor Yellow

try {
    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "GDPR - International Transfers" -Status "Pass" `
            -Severity "High" `
            -Message "Schrems II Supplementary measure: at-rest encryption active" `
            -Details "EDPB Recommendations 01/2020 cite encryption as a primary technical supplementary measure for international transfers" `
            -CrossReferences @{ GDPR='Art.46'; EDPB='Rec 01/2020'; Schrems='II' }
    }
    else {
        Add-Result -Category "GDPR - International Transfers" -Status "Fail" `
            -Severity "High" `
            -Message "Schrems II No at-rest encryption (international transfer safeguard insufficient)" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ GDPR='Art.46'; EDPB='Rec 01/2020' }
    }

    $fipsPolicy = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -Default 0
    if ($fipsPolicy -eq 1) {
        Add-Result -Category "GDPR - International Transfers" -Status "Pass" `
            -Severity "Medium" `
            -Message "Schrems II FIPS-validated cryptography enforced (strong encryption supplementary measure)" `
            -CrossReferences @{ GDPR='Art.46'; EDPB='Rec 01/2020' }
    }
    else {
        Add-Result -Category "GDPR - International Transfers" -Status "Warning" `
            -Severity "Medium" `
            -Message "Schrems II FIPS-only mode not enforced" `
            -Details "FIPS-validated cryptography strengthens encryption-as-supplementary-measure for international transfers" `
            -CrossReferences @{ GDPR='Art.46'; EDPB='Rec 01/2020' }
    }

    $tls10 = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
    $tls11 = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default $null
    if (($null -eq $tls10 -or $tls10 -eq 0) -and ($null -eq $tls11 -or $tls11 -eq 0)) {
        Add-Result -Category "GDPR - International Transfers" -Status "Pass" `
            -Severity "Medium" `
            -Message "Schrems II Legacy TLS protocols disabled (transit encryption strengthened)" `
            -CrossReferences @{ GDPR='Art.46'; EDPB='Rec 01/2020' }
    }
    else {
        Add-Result -Category "GDPR - International Transfers" -Status "Fail" `
            -Severity "High" `
            -Message "Schrems II Legacy TLS enabled (TLS 1.0=$tls10 TLS 1.1=$tls11)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -Type DWord" `
            -CrossReferences @{ GDPR='Art.46'; EDPB='Rec 01/2020' }
    }
}
catch {
    Add-Result -Category "GDPR - International Transfers" -Status "Error" `
        -Severity "Medium" `
        -Message "International transfer safeguard assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Data subject rights enabling technical controls
# ===========================================================================
Write-Host "[GDPR] Checking data subject rights enabling controls..." -ForegroundColor Yellow

try {
    $auditFileAccess = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -like '*File System*' }
    if ($auditFileAccess -and $auditFileAccess.Setting -ne 'No Auditing') {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 15 Right of access enabled by file system audit logging" `
            -Details "Audit logging supports identification of personal data processing activities for access requests" `
            -CrossReferences @{ GDPR='Art.15'; NIST='AU-3' }
    }
    else {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Warning" `
            -Severity "Medium" `
            -Message "Art. 15 File system auditing not active" `
            -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
            -CrossReferences @{ GDPR='Art.15' }
    }

    $vssService = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vssService -and $vssService.StartType -in @('Manual','Automatic')) {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 16 Right to rectification supported (VSS available for point-in-time recovery)" `
            -CrossReferences @{ GDPR='Art.16'; NIST='CP-9' }
    }
    else {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Warning" `
            -Severity "Medium" `
            -Message "Art. 16 Volume Shadow Copy service disabled (rectification audit trail limited)" `
            -Remediation "Set-Service -Name VSS -StartupType Manual" `
            -CrossReferences @{ GDPR='Art.16' }
    }

    $rbActive = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\bam" -ErrorAction SilentlyContinue
    if ($rbActive) {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Pass" `
            -Severity "Low" `
            -Message "Art. 17 Right to erasure: Background Activity Moderator tracks process execution for evidence of completion" `
            -CrossReferences @{ GDPR='Art.17' }
    }
    else {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Info" `
            -Severity "Informational" `
            -Message "Art. 17 BAM service registry not present (typical on Server SKUs)" `
            -CrossReferences @{ GDPR='Art.17' }
    }

    $jsonExport = Get-Command 'ConvertTo-Json' -ErrorAction SilentlyContinue
    $csvExport = Get-Command 'Export-Csv' -ErrorAction SilentlyContinue
    if ($jsonExport -and $csvExport) {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Pass" `
            -Severity "Low" `
            -Message "Art. 20 Right to data portability: standard export cmdlets available (JSON, CSV)" `
            -Details "Native PowerShell export to machine-readable formats supports portability requests" `
            -CrossReferences @{ GDPR='Art.20' }
    }

    $userAccountAudit = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -eq 'User Account Management' }
    if ($userAccountAudit -and $userAccountAudit.Setting -ne 'No Auditing') {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 21 Right to object: account management auditing tracks consent withdrawals" `
            -CrossReferences @{ GDPR='Art.21'; NIST='AC-2(4)' }
    }
    else {
        Add-Result -Category "GDPR - Data Subject Rights" -Status "Warning" `
            -Severity "Medium" `
            -Message "Art. 21 User account management auditing not active" `
            -Remediation "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable" `
            -CrossReferences @{ GDPR='Art.21' }
    }
}
catch {
    Add-Result -Category "GDPR - Data Subject Rights" -Status "Error" `
        -Severity "Medium" `
        -Message "Data subject rights assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Article 28 (Processor) technical safeguards
# ===========================================================================
Write-Host "[GDPR] Checking Article 28 processor technical safeguards..." -ForegroundColor Yellow

try {
    $auditObjAccess = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -like '*File System*' }
    if ($auditObjAccess -and $auditObjAccess.Setting -ne 'No Auditing') {
        Add-Result -Category "GDPR - Art. 28 Processor" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 28(3)(h) Processor obligation: audit information availability" `
            -Details "File system auditing produces evidence required for Art. 28 processor inspections" `
            -CrossReferences @{ GDPR='Art.28(3)(h)'; NIST='AU-2' }
    }
    else {
        Add-Result -Category "GDPR - Art. 28 Processor" -Status "Warning" `
            -Severity "Medium" `
            -Message "Art. 28(3)(h) Processor cannot demonstrate audit availability without logging" `
            -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
            -CrossReferences @{ GDPR='Art.28(3)(h)' }
    }

    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "GDPR - Art. 28 Processor" -Status "Pass" `
            -Severity "High" `
            -Message "Art. 28(3)(c) Processor confidentiality obligation supported by drive encryption" `
            -CrossReferences @{ GDPR='Art.28(3)(c)'; NIST='SC-28' }
    }
    else {
        Add-Result -Category "GDPR - Art. 28 Processor" -Status "Fail" `
            -Severity "High" `
            -Message "Art. 28(3)(c) Processor lacks drive encryption for confidentiality obligation" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ GDPR='Art.28(3)(c)' }
    }
}
catch {
    Add-Result -Category "GDPR - Art. 28 Processor" -Status "Error" `
        -Severity "Medium" `
        -Message "Article 28 processor assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Article 32(1)(b) ongoing CIA + resilience
# ===========================================================================
Write-Host "[GDPR] Checking Article 32(1)(b) ongoing CIA + resilience..." -ForegroundColor Yellow

try {
    $defenderStatus = Get-DefenderStatus -Cache $SharedData.Cache
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Pass" `
            -Severity "Medium" `
            -Message "Confidentiality + integrity: real-time malware protection active" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='SI-3' }
    }
    else {
        Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Fail" `
            -Severity "High" `
            -Message "Confidentiality + integrity weakened: no real-time malware protection" `
            -CrossReferences @{ GDPR='Art.32(1)(b)' }
    }

    $vssService = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    $bitsService = Get-Service -Name 'BITS' -ErrorAction SilentlyContinue
    if ($vssService -and $bitsService -and ($vssService.StartType -in @('Manual','Automatic')) -and ($bitsService.StartType -in @('Manual','Automatic'))) {
        Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Pass" `
            -Severity "Medium" `
            -Message "Resilience: backup and update infrastructure available (VSS + BITS)" `
            -CrossReferences @{ GDPR='Art.32(1)(b)'; NIST='CP-9' }
    }
    else {
        Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Warning" `
            -Severity "Medium" `
            -Message "Resilience infrastructure incomplete (VSS or BITS disabled)" `
            -CrossReferences @{ GDPR='Art.32(1)(b)' }
    }

    $sysRestore = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableSR" -Default 0
    if ($sysRestore -eq 0) {
        Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Pass" `
            -Severity "Low" `
            -Message "Availability: System Restore enabled for incident recovery" `
            -CrossReferences @{ GDPR='Art.32(1)(c)'; NIST='CP-10' }
    }
    else {
        Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Warning" `
            -Severity "Medium" `
            -Message "Availability: System Restore disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'DisableSR' -Value 0 -Type DWord; Enable-ComputerRestore -Drive 'C:\\'" `
            -CrossReferences @{ GDPR='Art.32(1)(c)' }
    }
}
catch {
    Add-Result -Category "GDPR - Art. 32(1)(b) CIA + Resilience" -Status "Error" `
        -Severity "Medium" `
        -Message "CIA + resilience assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Article 35 DPIA-related technical evidence
# ===========================================================================
Write-Host "[GDPR] Checking Article 35 DPIA evidence indicators..." -ForegroundColor Yellow

try {
    $sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
    if ($sysmonService) {
        Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 35 DPIA Risk monitoring infrastructure present (Sysmon detected)" `
            -Details "Sysmon supports detailed system activity monitoring for high-risk processing assessment" `
            -CrossReferences @{ GDPR='Art.35'; NIST='RA-3' }
    }
    else {
        Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Info" `
            -Severity "Informational" `
            -Message "Art. 35 No Sysmon monitoring detected (alternate monitoring may exist)" `
            -CrossReferences @{ GDPR='Art.35' }
    }

    $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
    if ($secLogSize -ge 268435456) {
        $secLogMB = [Math]::Round($secLogSize / 1MB, 0)
        Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 35 Audit retention adequate for DPIA evidence (${secLogMB} MB)" `
            -CrossReferences @{ GDPR='Art.35'; NIST='AU-11' }
    }
    else {
        Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Warning" `
            -Severity "Medium" `
            -Message "Art. 35 Security log undersized for DPIA evidence retention" `
            -Remediation "wevtutil sl Security /ms:268435456" `
            -CrossReferences @{ GDPR='Art.35' }
    }

    $eventLogService = Get-Service -Name 'EventLog' -ErrorAction SilentlyContinue
    if ($eventLogService -and $eventLogService.Status -eq 'Running') {
        Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Pass" `
            -Severity "Medium" `
            -Message "Art. 35 Event log infrastructure operational for ongoing risk assessment" `
            -CrossReferences @{ GDPR='Art.35'; NIST='AU-2' }
    }
    else {
        Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Fail" `
            -Severity "Critical" `
            -Message "Art. 35 Event log service not running (no audit trail collection)" `
            -CrossReferences @{ GDPR='Art.35' }
    }
}
catch {
    Add-Result -Category "GDPR - Art. 35 DPIA Evidence" -Status "Error" `
        -Severity "Medium" `
        -Message "DPIA evidence assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Pseudonymisation and data minimisation indicators
# ===========================================================================
Write-Host "[GDPR] Checking pseudonymisation and data minimisation..." -ForegroundColor Yellow

try {
    $cgEnabled = Test-CredentialGuardEnabled
    if ($cgEnabled) {
        Add-Result -Category "GDPR - Pseudonymisation" -Status "Pass" `
            -Severity "Medium" `
            -Message "Pseudonymisation: credential isolation prevents re-identification through credential theft" `
            -Details "Credential Guard separates secrets from re-identification attack vectors" `
            -CrossReferences @{ GDPR='Art.32(1)(a)'; NIST='IA-5(1)' }
    }
    else {
        Add-Result -Category "GDPR - Pseudonymisation" -Status "Warning" `
            -Severity "Medium" `
            -Message "Pseudonymisation: Credential Guard not active (re-identification risk via credential theft)" `
            -CrossReferences @{ GDPR='Art.32(1)(a)' }
    }

    $userListPolicy = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Default 0
    if ($userListPolicy -eq 1) {
        Add-Result -Category "GDPR - Pseudonymisation" -Status "Pass" `
            -Severity "Low" `
            -Message "Data minimisation: last logged-on user not displayed at sign-in" `
            -CrossReferences @{ GDPR='Art.5(1)(c)' }
    }
    else {
        Add-Result -Category "GDPR - Pseudonymisation" -Status "Warning" `
            -Severity "Low" `
            -Message "Data minimisation: previous user identity displayed at sign-in screen" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Type DWord" `
            -CrossReferences @{ GDPR='Art.5(1)(c)' }
    }

    $telemetryLevel = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Default 3
    if ($telemetryLevel -le 1) {
        Add-Result -Category "GDPR - Pseudonymisation" -Status "Pass" `
            -Severity "Medium" `
            -Message "Data minimisation: telemetry restricted to Security/Required level ($telemetryLevel)" `
            -CrossReferences @{ GDPR='Art.5(1)(c)' }
    }
    else {
        Add-Result -Category "GDPR - Pseudonymisation" -Status "Warning" `
            -Severity "Medium" `
            -Message "Data minimisation: telemetry level permits enhanced/optional data collection (level $telemetryLevel)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1 -Type DWord" `
            -CrossReferences @{ GDPR='Art.5(1)(c)' }
    }
}
catch {
    Add-Result -Category "GDPR - Pseudonymisation" -Status "Error" `
        -Severity "Medium" `
        -Message "Pseudonymisation assessment failed: $($_.Exception.Message)"
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
Write-Host "  [GDPR] GDPR Technical Measures Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
Write-Host "`n  Failed Check Severity Distribution:" -ForegroundColor Yellow
foreach ($sev in @("Critical","High","Medium","Low")) {
    $sevCount = @($failResults | Where-Object { $_.Severity -eq $sev }).Count
    $color = switch ($sev) { "Critical" { "Red" }; "High" { "Red" }; "Medium" { "Yellow" }; default { "White" } }
    Write-Host "    $($sev.PadRight(12)): $sevCount" -ForegroundColor $color
}
Write-Host "$("=" * 80)`n" -ForegroundColor White

return $results

# ===========================================================================
# Standalone Execution Support
# ===========================================================================
if ($MyInvocation.ScriptName -eq "" -or $MyInvocation.ScriptName -eq $MyInvocation.MyCommand.Path) {
    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  GDPR Technical Measures Module -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[GDPR] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  GDPR module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
