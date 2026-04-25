# module-iso27001.ps1
# ISO/IEC 27001:2022 Compliance Module for Windows Security Audit
# Version: 6.1.2
#
# Evaluates Windows configuration against ISO/IEC 27001:2022 Annex A controls
# with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    ISO/IEC 27001:2022 compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with ISO/IEC 27001:2022 Annex A controls including:
    - A.5 Organizational Controls (policies, access, asset management, incidents)
    - A.6 People Controls (screening, awareness, remote working)
    - A.7 Physical Controls (equipment security, clear desk, media)
    - A.8 Technological Controls (endpoints, privileged access, authentication,
    -     malware, vulnerabilities, configuration, backup, logging, monitoring,
    -     network security, cryptography, secure development lifecycle)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: ISO/IEC 27001:2022, ISO/IEC 27002:2022
    Version: 6.1.2

.EXAMPLE
    $results = & .\modules\module-iso27001.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "ISO27001"
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

Write-Host "`n[$moduleName] Starting ISO/IEC 27001:2022 compliance checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# A.5 Organizational Controls
# ===========================================================================
Write-Host "[ISO27001] Checking A.5 Organizational Controls..." -ForegroundColor Yellow

    # A.5.1: Policies for information security
    try {
        $gpoApplied = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" -Name "DCName" -Default $null
        if ($null -ne $gpoApplied) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.1: Group Policy actively applied from domain controller" `
                -Details "A.5.1 Policies for information security: Centralized policy management detected" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.1'; NIST='PL-1'; SOC2='CC1.1' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Info" `
                -Message "A.5.1: No domain Group Policy detected (standalone system)" `
                -Details "A.5.1 Policies for information security: Consider centralized policy management" `
                -Severity "Low" `
                -CrossReferences @{ ISO27001='A.5.1'; NIST='PL-1'; SOC2='CC1.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.1: Policies for information security -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.5.1'; NIST='PL-1' }
    }
    # A.5.2: Information security roles and responsibilities
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $adminCount = if ($null -ne $localAdmins) { @($localAdmins).Count } else { 0 }
        if ($adminCount -le 3) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.2: Local administrator group has $adminCount members (appropriate)" `
                -Details "A.5.2 Roles and responsibilities: Limited admin membership supports segregation of duties" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.2'; NIST='AC-6'; CIS='1.1' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Warning" `
                -Message "A.5.2: Local administrator group has $adminCount members (excessive)" `
                -Details "A.5.2 Roles and responsibilities: Too many administrators weakens role segregation" `
                -Remediation "Review and remove unnecessary members from local Administrators group" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.2'; NIST='AC-6'; CIS='1.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.2: Information security roles and responsibilities -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.5.2'; NIST='AC-6' }
    }
    # A.5.9: Inventory of information and other associated assets
    try {
        $swCount = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue).Count
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Info" `
            -Message "A.5.9: Software inventory contains $swCount items" `
            -Details "A.5.9 Inventory of assets: Registry-based software inventory is available" `
            -Severity "Informational" `
            -CrossReferences @{ ISO27001='A.5.9'; NIST='CM-8'; CIS='2.1' }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.9: Inventory of information and other associated assets -- check failed: $_" `
            -Severity "Informational" `
            -CrossReferences @{ ISO27001='A.5.9'; NIST='CM-8' }
    }
    # A.5.10: Acceptable use -- login banner
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Default $null
        if ($null -ne $val -and $val -ne "") {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.10: Acceptable use -- login banner -- properly configured" `
                -Details "A.5.10 Acceptable use: Login banner must display acceptable use policy" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.10'; NIST='AC-8'; STIG='V-220858'; CIS='2.3.7.4' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.10: Acceptable use -- login banner -- not configured (Value=$val)" `
                -Details "A.5.10 Acceptable use: Login banner must display acceptable use policy" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'Authorized use only'" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.10'; NIST='AC-8'; STIG='V-220858'; CIS='2.3.7.4' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.10: Acceptable use -- login banner -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.5.10'; NIST='AC-8'; STIG='V-220858'; CIS='2.3.7.4' }
    }
    # A.5.15: Access control -- UAC enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.15: Access control -- UAC enabled -- properly configured" `
                -Details "A.5.15 Access control: UAC enforces least-privilege access control policy" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.5.15'; NIST='AC-3'; CIS='2.3.17.1'; STIG='V-220926' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.15: Access control -- UAC enabled -- not configured (Value=$val)" `
                -Details "A.5.15 Access control: UAC enforces least-privilege access control policy" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.5.15'; NIST='AC-3'; CIS='2.3.17.1'; STIG='V-220926' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.15: Access control -- UAC enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.5.15'; NIST='AC-3'; CIS='2.3.17.1'; STIG='V-220926' }
    }
    # A.5.17: Authentication information -- password length
    try {
        $netAcct = net accounts 2>&1
        $minLen = 0
        foreach ($line in $netAcct) { if ($line -match "Minimum password length\s+(\d+)") { $minLen = [int]$Matches[1] } }
        if ($minLen -ge 14) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.17: Minimum password length is $minLen characters" `
                -Details "A.5.17 Authentication information: Strong password policy enforced" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.17'; NIST='IA-5'; CIS='1.1.4'; STIG='V-220718'; 'PCI-DSS'='8.3.6' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.17: Minimum password length is $minLen (requires `>= 14)" `
                -Details "A.5.17 Authentication information: Weak passwords undermine access control" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.17'; NIST='IA-5'; CIS='1.1.4'; STIG='V-220718'; 'PCI-DSS'='8.3.6' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.17: Authentication information -- password length -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.5.17'; NIST='IA-5' }
    }
    # A.5.17b: Authentication information -- password history
    try {
        $netAcct = net accounts 2>&1
        $pwHist = 0
        foreach ($line in $netAcct) { if ($line -match "Length of password history maintained\s+(\d+)") { $pwHist = [int]$Matches[1] } }
        if ($pwHist -ge 24) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.17b: Password history enforces $pwHist previous passwords" `
                -Details "A.5.17 Authentication information: Password reuse effectively prevented" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.17'; NIST='IA-5(1)'; CIS='1.1.1' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.17b: Password history is $pwHist (requires `>= 24)" `
                -Details "A.5.17 Authentication information: Low password history enables credential reuse" `
                -Remediation "net accounts /uniquepw:24" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.17'; NIST='IA-5(1)'; CIS='1.1.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.17b: Authentication information -- password history -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.5.17'; NIST='IA-5(1)' }
    }
    # A.5.17c: Authentication information -- account lockout
    try {
        $netAcct = net accounts 2>&1
        $lockThresh = 0
        foreach ($line in $netAcct) { if ($line -match "Lockout threshold\s+(\d+)") { $lockThresh = [int]$Matches[1] } }
        if ($lockThresh -gt 0 -and $lockThresh -le 5) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.17c: Account lockout threshold is $lockThresh attempts" `
                -Details "A.5.17 Authentication information: Brute-force protection enabled" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.17'; NIST='AC-7'; CIS='1.2.1'; 'PCI-DSS'='8.3.4' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.17c: Account lockout threshold is $lockThresh (requires 1-5)" `
                -Details "A.5.17 Authentication information: No lockout enables brute-force attacks" `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.17'; NIST='AC-7'; CIS='1.2.1'; 'PCI-DSS'='8.3.4' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.17c: Authentication information -- account lockout -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.5.17'; NIST='AC-7' }
    }
    # A.5.18: Access rights -- non-expiring passwords
    try {
        $neverExpire = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true })
        if ($neverExpire.Count -eq 0) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.18: No enabled accounts have non-expiring passwords" `
                -Details "A.5.18 Access rights: All active accounts enforce password rotation" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.18'; NIST='AC-2'; CIS='1.1.5' }
        } else {
            $names = ($neverExpire | Select-Object -First 5 -ExpandProperty Name) -join ", "
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Warning" `
                -Message "A.5.18: $($neverExpire.Count) account(s) have non-expiring passwords ($names)" `
                -Details "A.5.18 Access rights: Non-expiring passwords weaken periodic access review" `
                -Remediation "Set-LocalUser -Name '<account`>' -PasswordNeverExpires `$false" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.18'; NIST='AC-2'; CIS='1.1.5' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.18: Access rights -- non-expiring passwords -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.5.18'; NIST='AC-2' }
    }
    # A.5.18b: Access rights -- Guest account disabled
    try {
        $guestAcct = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guestAcct -and $guestAcct.Enabled -eq $false) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.18b: Guest account is disabled" `
                -Details "A.5.18 Access rights: Anonymous access via Guest account is prevented" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.18'; NIST='AC-2'; CIS='1.1'; STIG='V-220929' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.18b: Guest account is ENABLED" `
                -Details "A.5.18 Access rights: Guest account allows unauthorized anonymous access" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.5.18'; NIST='AC-2'; CIS='1.1'; STIG='V-220929' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.18b: Access rights -- Guest account disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.5.18'; NIST='AC-2' }
    }
    # A.5.23: Cloud services -- OneDrive sync policy
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.23: Cloud services -- OneDrive sync policy -- properly configured" `
                -Details "A.5.23 Cloud services: Uncontrolled cloud sync should be governed by policy" `
                -Severity "Low" `
                -CrossReferences @{ ISO27001='A.5.23'; NIST='AC-20'; GDPR='Art.28' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Info" `
                -Message "A.5.23: Cloud services -- OneDrive sync policy -- not configured (Value=$val)" `
                -Details "A.5.23 Cloud services: Uncontrolled cloud sync should be governed by policy" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name DisableFileSyncNGSC -Value 1" `
                -Severity "Low" `
                -CrossReferences @{ ISO27001='A.5.23'; NIST='AC-20'; GDPR='Art.28' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.23: Cloud services -- OneDrive sync policy -- check failed: $_" `
            -Severity "Low" `
            -CrossReferences @{ ISO27001='A.5.23'; NIST='AC-20'; GDPR='Art.28' }
    }
    # A.5.24: Incident management -- Event Log service
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.24: Incident management -- Event Log service -- service running" `
                -Details "A.5.24 Incident management: Event logging is essential for incident detection" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.5.24'; NIST='IR-4'; SOC2='CC7.3' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.24: Incident management -- Event Log service -- service not running (Status=$svcSt)" `
                -Details "A.5.24 Incident management: Event logging is essential for incident detection" `
                -Remediation "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.5.24'; NIST='IR-4'; SOC2='CC7.3' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.24: Incident management -- Event Log service -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.5.24'; NIST='IR-4'; SOC2='CC7.3' }
    }
    # A.5.28: Collection of evidence -- security log size
    try {
        $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
        $secLogMB = [Math]::Round($secLogSize / 1MB, 0)
        if ($secLogSize -ge 1073741824) {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Pass" `
                -Message "A.5.28: Security event log is ${secLogMB}MB (`>= 1024MB)" `
                -Details "A.5.28 Collection of evidence: Adequate log retention for forensic investigation" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.28'; NIST='AU-4'; STIG='V-220961' }
        } else {
            Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Fail" `
                -Message "A.5.28: Security event log is ${secLogMB}MB (requires `>= 1024MB)" `
                -Details "A.5.28 Collection of evidence: Insufficient log space may cause evidence loss" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.5.28'; NIST='AU-4'; STIG='V-220961' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.5 Organizational" -Status "Error" `
            -Message "A.5.28: Collection of evidence -- security log size -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.5.28'; NIST='AU-4' }
    }

# ===========================================================================
# A.6 People Controls
# ===========================================================================
Write-Host "[ISO27001] Checking A.6 People Controls..." -ForegroundColor Yellow

    # A.6.7: Remote working -- RDP NLA required
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Pass" `
                -Message "A.6.7: Remote working -- RDP NLA required -- properly configured" `
                -Details "A.6.7 Remote working: NLA prevents unauthenticated RDP sessions" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='AC-17'; CIS='18.9.65.3.9.1'; STIG='V-220978' }
        } else {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Fail" `
                -Message "A.6.7: Remote working -- RDP NLA required -- not configured (Value=$val)" `
                -Details "A.6.7 Remote working: NLA prevents unauthenticated RDP sessions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='AC-17'; CIS='18.9.65.3.9.1'; STIG='V-220978' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.6 People" -Status "Error" `
            -Message "A.6.7: Remote working -- RDP NLA required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.6.7'; NIST='AC-17'; CIS='18.9.65.3.9.1'; STIG='V-220978' }
    }
    # A.6.7b: Remote working -- RDP encryption level
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Default $null
        if ($null -ne $val -and $val -ge 3) {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Pass" `
                -Message "A.6.7b: Remote working -- RDP encryption level -- properly configured" `
                -Details "A.6.7 Remote working: RDP must use High encryption level for remote sessions" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='SC-8'; CIS='18.9.65.3.9.2' }
        } else {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Fail" `
                -Message "A.6.7b: Remote working -- RDP encryption level -- not configured (Value=$val)" `
                -Details "A.6.7 Remote working: RDP must use High encryption level for remote sessions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='SC-8'; CIS='18.9.65.3.9.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.6 People" -Status "Error" `
            -Message "A.6.7b: Remote working -- RDP encryption level -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.6.7'; NIST='SC-8'; CIS='18.9.65.3.9.2' }
    }
    # A.6.7c: Remote working -- idle session timeout
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Default $null
        if ($null -ne $val -and $val -le 900000) {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Pass" `
                -Message "A.6.7c: Remote working -- idle session timeout -- properly configured" `
                -Details "A.6.7 Remote working: Idle RDP sessions should disconnect to prevent unauthorized access" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
        } else {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Fail" `
                -Message "A.6.7c: Remote working -- idle session timeout -- not configured (Value=$val)" `
                -Details "A.6.7 Remote working: Idle RDP sessions should disconnect to prevent unauthorized access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -Value 900000" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.6 People" -Status "Error" `
            -Message "A.6.7c: Remote working -- idle session timeout -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.6.7'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
    }
    # A.6.7d: Remote working -- CredSSP delegation restricted
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Pass" `
                -Message "A.6.7d: Remote working -- CredSSP delegation restricted -- properly configured" `
                -Details "A.6.7 Remote working: Credential delegation should be restricted for remote sessions" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='IA-5'; NSA='Credential Protection' }
        } else {
            Add-Result -Category "ISO27001 - A.6 People" -Status "Fail" `
                -Message "A.6.7d: Remote working -- CredSSP delegation restricted -- not configured (Value=$val)" `
                -Details "A.6.7 Remote working: Credential delegation should be restricted for remote sessions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name AllowDefaultCredentials -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.6.7'; NIST='IA-5'; NSA='Credential Protection' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.6 People" -Status "Error" `
            -Message "A.6.7d: Remote working -- CredSSP delegation restricted -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.6.7'; NIST='IA-5'; NSA='Credential Protection' }
    }

# ===========================================================================
# A.7 Physical Controls (Technical Aspects)
# ===========================================================================
Write-Host "[ISO27001] Checking A.7 Physical Controls (Technical Aspects)..." -ForegroundColor Yellow

    # A.7.7: Clear desk -- screen saver enabled
    try {
        $val = Get-RegValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Default $null
        if ($null -ne $val -and $val -eq "1") {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Pass" `
                -Message "A.7.7: Clear desk -- screen saver enabled -- properly configured" `
                -Details "A.7.7 Clear desk: Screen saver must activate to protect unattended workstations" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11'; CIS='2.3.1.1' }
        } else {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Fail" `
                -Message "A.7.7: Clear desk -- screen saver enabled -- not configured (Value=$val)" `
                -Details "A.7.7 Clear desk: Screen saver must activate to protect unattended workstations" `
                -Remediation "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11'; CIS='2.3.1.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.7 Physical" -Status "Error" `
            -Message "A.7.7: Clear desk -- screen saver enabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11'; CIS='2.3.1.1' }
    }
    # A.7.7b: Clear desk -- screen saver password protected
    try {
        $val = Get-RegValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Default $null
        if ($null -ne $val -and $val -eq "1") {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Pass" `
                -Message "A.7.7b: Clear desk -- screen saver password protected -- properly configured" `
                -Details "A.7.7 Clear desk: Screen saver must require password to unlock" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11(1)'; CIS='2.3.1.2' }
        } else {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Fail" `
                -Message "A.7.7b: Clear desk -- screen saver password protected -- not configured (Value=$val)" `
                -Details "A.7.7 Clear desk: Screen saver must require password to unlock" `
                -Remediation "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11(1)'; CIS='2.3.1.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.7 Physical" -Status "Error" `
            -Message "A.7.7b: Clear desk -- screen saver password protected -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11(1)'; CIS='2.3.1.2' }
    }
    # A.7.7c: Clear desk -- screen saver timeout
    try {
        $val = Get-RegValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Pass" `
                -Message "A.7.7c: Clear desk -- screen saver timeout -- properly configured" `
                -Details "A.7.7 Clear desk: Screen saver should activate within 15 minutes of inactivity" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11'; CIS='2.3.1.3' }
        } else {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Fail" `
                -Message "A.7.7c: Clear desk -- screen saver timeout -- not configured (Value=$val)" `
                -Details "A.7.7 Clear desk: Screen saver should activate within 15 minutes of inactivity" `
                -Remediation "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 900" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11'; CIS='2.3.1.3' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.7 Physical" -Status "Error" `
            -Message "A.7.7c: Clear desk -- screen saver timeout -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.7.7'; NIST='AC-11'; CIS='2.3.1.3' }
    }
    # A.7.9: Security of assets off-premises -- BitLocker OS drive
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSEncryptionType" -Default $null
        if ($null -ne $val) {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Pass" `
                -Message "A.7.9: Security of assets off-premises -- BitLocker OS drive -- properly configured" `
                -Details "A.7.9 Security of assets off-premises: BitLocker encryption policy is configured for OS drive" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.7.9'; NIST='SC-28'; CIS='18.10.9.1'; STIG='V-220901' }
        } else {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Fail" `
                -Message "A.7.9: Security of assets off-premises -- BitLocker OS drive -- not configured (Value=$val)" `
                -Details "A.7.9 Security of assets off-premises: BitLocker encryption policy is configured for OS drive" `
                -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.7.9'; NIST='SC-28'; CIS='18.10.9.1'; STIG='V-220901' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.7 Physical" -Status "Error" `
            -Message "A.7.9: Security of assets off-premises -- BitLocker OS drive -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.7.9'; NIST='SC-28'; CIS='18.10.9.1'; STIG='V-220901' }
    }
    # A.7.10: Storage media -- autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Pass" `
                -Message "A.7.10: Storage media -- autoplay disabled -- properly configured" `
                -Details "A.7.10 Storage media: AutoPlay disabled prevents automatic execution from removable media" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.7.10'; NIST='MP-7'; CIS='18.9.8.3'; NSA='Application Control' }
        } else {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Fail" `
                -Message "A.7.10: Storage media -- autoplay disabled -- not configured (Value=$val)" `
                -Details "A.7.10 Storage media: AutoPlay disabled prevents automatic execution from removable media" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.7.10'; NIST='MP-7'; CIS='18.9.8.3'; NSA='Application Control' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.7 Physical" -Status "Error" `
            -Message "A.7.10: Storage media -- autoplay disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.7.10'; NIST='MP-7'; CIS='18.9.8.3'; NSA='Application Control' }
    }
    # A.7.10b: Storage media -- autorun disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Pass" `
                -Message "A.7.10b: Storage media -- autorun disabled -- properly configured" `
                -Details "A.7.10 Storage media: AutoRun disabled prevents malware propagation from removable devices" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.7.10'; NIST='MP-7'; CIS='18.9.8.2' }
        } else {
            Add-Result -Category "ISO27001 - A.7 Physical" -Status "Fail" `
                -Message "A.7.10b: Storage media -- autorun disabled -- not configured (Value=$val)" `
                -Details "A.7.10 Storage media: AutoRun disabled prevents malware propagation from removable devices" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.7.10'; NIST='MP-7'; CIS='18.9.8.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.7 Physical" -Status "Error" `
            -Message "A.7.10b: Storage media -- autorun disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.7.10'; NIST='MP-7'; CIS='18.9.8.2' }
    }

# ===========================================================================
# A.8 Technological Controls -- Endpoint & Access
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- Endpoint & Access..." -ForegroundColor Yellow

    # A.8.1a: User endpoint devices -- Windows Defender real-time protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1a: User endpoint devices -- Windows Defender real-time protection -- properly configured" `
                -Details "A.8.1 User endpoint devices: Real-time antimalware protection must be enabled on all endpoints" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.9.1'; CISA='EDR' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1a: User endpoint devices -- Windows Defender real-time protection -- not configured (Value=$val)" `
                -Details "A.8.1 User endpoint devices: Real-time antimalware protection must be enabled on all endpoints" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.9.1'; CISA='EDR' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1a: User endpoint devices -- Windows Defender real-time protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.9.1'; CISA='EDR' }
    }
    # A.8.1b: User endpoint devices -- Windows Defender antispyware
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1b: User endpoint devices -- Windows Defender antispyware -- properly configured" `
                -Details "A.8.1 User endpoint devices: Antispyware protection must not be disabled" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1b: User endpoint devices -- Windows Defender antispyware -- not configured (Value=$val)" `
                -Details "A.8.1 User endpoint devices: Antispyware protection must not be disabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1b: User endpoint devices -- Windows Defender antispyware -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.1' }
    }
    # A.8.1c: User endpoint devices -- Defender service running
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1c: User endpoint devices -- Defender service running -- service running" `
                -Details "A.8.1 User endpoint devices: Windows Defender Antivirus service must be operational" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CISA='EDR' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1c: User endpoint devices -- Defender service running -- service not running (Status=$svcSt)" `
                -Details "A.8.1 User endpoint devices: Windows Defender Antivirus service must be operational" `
                -Remediation "Start-Service -Name WinDefend; Set-Service -Name WinDefend -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CISA='EDR' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1c: User endpoint devices -- Defender service running -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CISA='EDR' }
    }
    # A.8.1d: User endpoint devices -- cloud-delivered protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1d: User endpoint devices -- cloud-delivered protection -- properly configured" `
                -Details "A.8.1 User endpoint devices: Cloud-delivered protection enhances threat detection" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3(10)'; CIS='18.9.47.11.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1d: User endpoint devices -- cloud-delivered protection -- not configured (Value=$val)" `
                -Details "A.8.1 User endpoint devices: Cloud-delivered protection enhances threat detection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name SpyNetReporting -Value 2" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3(10)'; CIS='18.9.47.11.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1d: User endpoint devices -- cloud-delivered protection -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3(10)'; CIS='18.9.47.11.1' }
    }
    # A.8.1e: User endpoint devices -- behavior monitoring
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1e: User endpoint devices -- behavior monitoring -- properly configured" `
                -Details "A.8.1 User endpoint devices: Behavioral analysis detects zero-day threats" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.9.2' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1e: User endpoint devices -- behavior monitoring -- not configured (Value=$val)" `
                -Details "A.8.1 User endpoint devices: Behavioral analysis detects zero-day threats" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableBehaviorMonitoring -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.9.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1e: User endpoint devices -- behavior monitoring -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.9.2' }
    }
    # A.8.1f: User endpoint devices -- PUA protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1f: User endpoint devices -- PUA protection -- properly configured" `
                -Details "A.8.1 User endpoint devices: PUA detection blocks potentially unwanted software" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.15' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1f: User endpoint devices -- PUA protection -- not configured (Value=$val)" `
                -Details "A.8.1 User endpoint devices: PUA detection blocks potentially unwanted software" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name PUAProtection -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.15' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1f: User endpoint devices -- PUA protection -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.15' }
    }
    # A.8.1g: User endpoint devices -- controlled folder access
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.1g: User endpoint devices -- controlled folder access -- properly configured" `
                -Details "A.8.1 User endpoint devices: Controlled folder access prevents ransomware data encryption" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.1g: User endpoint devices -- controlled folder access -- not configured (Value=$val)" `
                -Details "A.8.1 User endpoint devices: Controlled folder access prevents ransomware data encryption" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.1g: User endpoint devices -- controlled folder access -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.1'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
    }

# ===========================================================================
# A.8 Technological Controls -- Privileged Access
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- Privileged Access..." -ForegroundColor Yellow

    # A.8.2a: Privileged access -- UAC admin approval mode
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.2a: Privileged access -- UAC admin approval mode -- properly configured" `
                -Details "A.8.2 Privileged access: Built-in Administrator requires admin approval mode" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6(1)'; CIS='2.3.17.1'; STIG='V-220926' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.2a: Privileged access -- UAC admin approval mode -- not configured (Value=$val)" `
                -Details "A.8.2 Privileged access: Built-in Administrator requires admin approval mode" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6(1)'; CIS='2.3.17.1'; STIG='V-220926' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.2a: Privileged access -- UAC admin approval mode -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6(1)'; CIS='2.3.17.1'; STIG='V-220926' }
    }
    # A.8.2b: Privileged access -- UAC consent prompt behavior (admins)
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.2b: Privileged access -- UAC consent prompt behavior (admins) -- properly configured" `
                -Details "A.8.2 Privileged access: Admins should be prompted for consent on secure desktop" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6'; CIS='2.3.17.3' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.2b: Privileged access -- UAC consent prompt behavior (admins) -- not configured (Value=$val)" `
                -Details "A.8.2 Privileged access: Admins should be prompted for consent on secure desktop" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6'; CIS='2.3.17.3' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.2b: Privileged access -- UAC consent prompt behavior (admins) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6'; CIS='2.3.17.3' }
    }
    # A.8.2c: Privileged access -- UAC secure desktop
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.2c: Privileged access -- UAC secure desktop -- properly configured" `
                -Details "A.8.2 Privileged access: Secure desktop prevents UI spoofing during elevation" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6'; CIS='2.3.17.7'; STIG='V-220930' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.2c: Privileged access -- UAC secure desktop -- not configured (Value=$val)" `
                -Details "A.8.2 Privileged access: Secure desktop prevents UI spoofing during elevation" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6'; CIS='2.3.17.7'; STIG='V-220930' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.2c: Privileged access -- UAC secure desktop -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.2'; NIST='AC-6'; CIS='2.3.17.7'; STIG='V-220930' }
    }
    # A.8.2d: Privileged access -- LSASS protection (RunAsPPL)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.2d: Privileged access -- LSASS protection (RunAsPPL) -- properly configured" `
                -Details "A.8.2 Privileged access: LSASS running as Protected Process prevents credential theft" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.1'; NSA='Credential Protection' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.2d: Privileged access -- LSASS protection (RunAsPPL) -- not configured (Value=$val)" `
                -Details "A.8.2 Privileged access: LSASS running as Protected Process prevents credential theft" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.1'; NSA='Credential Protection' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.2d: Privileged access -- LSASS protection (RunAsPPL) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.1'; NSA='Credential Protection' }
    }
    # A.8.2e: Privileged access -- WDigest disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.2e: Privileged access -- WDigest disabled -- properly configured" `
                -Details "A.8.2 Privileged access: WDigest caches plaintext credentials; must be disabled" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.6'; STIG='V-220929'; NSA='Credential Protection' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.2e: Privileged access -- WDigest disabled -- not configured (Value=$val)" `
                -Details "A.8.2 Privileged access: WDigest caches plaintext credentials; must be disabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.6'; STIG='V-220929'; NSA='Credential Protection' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.2e: Privileged access -- WDigest disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.6'; STIG='V-220929'; NSA='Credential Protection' }
    }
    # A.8.2f: Privileged access -- Credential Guard
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.2f: Privileged access -- Credential Guard -- properly configured" `
                -Details "A.8.2 Privileged access: Credential Guard isolates credentials using virtualization" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.3'; NSA='Credential Protection' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.2f: Privileged access -- Credential Guard -- not configured (Value=$val)" `
                -Details "A.8.2 Privileged access: Credential Guard isolates credentials using virtualization" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.3'; NSA='Credential Protection' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.2f: Privileged access -- Credential Guard -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.2'; NIST='IA-5(13)'; CIS='18.3.3'; NSA='Credential Protection' }
    }

# ===========================================================================
# A.8 Technological Controls -- Authentication & Cryptography
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- Authentication & Cryptography..." -ForegroundColor Yellow

    # A.8.5a: Secure authentication -- LAN Manager level
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default $null
        if ($null -ne $val -and $val -ge 5) {
            Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Pass" `
                -Message "A.8.5a: Secure authentication -- LAN Manager level -- properly configured" `
                -Details "A.8.5 Secure authentication: LM auth level 5 sends NTLMv2 only, refuses LM/NTLM" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.5'; NIST='IA-2'; CIS='2.3.11.7'; STIG='V-220968' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Fail" `
                -Message "A.8.5a: Secure authentication -- LAN Manager level -- not configured (Value=$val)" `
                -Details "A.8.5 Secure authentication: LM auth level 5 sends NTLMv2 only, refuses LM/NTLM" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.5'; NIST='IA-2'; CIS='2.3.11.7'; STIG='V-220968' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Error" `
            -Message "A.8.5a: Secure authentication -- LAN Manager level -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.5'; NIST='IA-2'; CIS='2.3.11.7'; STIG='V-220968' }
    }
    # A.8.5b: Secure authentication -- anonymous enumeration restricted
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Pass" `
                -Message "A.8.5b: Secure authentication -- anonymous enumeration restricted -- properly configured" `
                -Details "A.8.5 Secure authentication: Anonymous enumeration of SAM accounts is restricted" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.5'; NIST='AC-14'; CIS='2.3.10.6'; STIG='V-220936' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Fail" `
                -Message "A.8.5b: Secure authentication -- anonymous enumeration restricted -- not configured (Value=$val)" `
                -Details "A.8.5 Secure authentication: Anonymous enumeration of SAM accounts is restricted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.5'; NIST='AC-14'; CIS='2.3.10.6'; STIG='V-220936' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Error" `
            -Message "A.8.5b: Secure authentication -- anonymous enumeration restricted -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.5'; NIST='AC-14'; CIS='2.3.10.6'; STIG='V-220936' }
    }
    # A.8.5c: Secure authentication -- SMB signing required
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Pass" `
                -Message "A.8.5c: Secure authentication -- SMB signing required -- properly configured" `
                -Details "A.8.5 Secure authentication: SMB signing prevents man-in-the-middle attacks" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.5'; NIST='SC-8'; CIS='2.3.9.2'; NSA='Network Hardening' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Fail" `
                -Message "A.8.5c: Secure authentication -- SMB signing required -- not configured (Value=$val)" `
                -Details "A.8.5 Secure authentication: SMB signing prevents man-in-the-middle attacks" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.5'; NIST='SC-8'; CIS='2.3.9.2'; NSA='Network Hardening' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Authentication" -Status "Error" `
            -Message "A.8.5c: Secure authentication -- SMB signing required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.5'; NIST='SC-8'; CIS='2.3.9.2'; NSA='Network Hardening' }
    }
    # A.8.24a: Use of cryptography -- TLS 1.2 enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Pass" `
                -Message "A.8.24a: Use of cryptography -- TLS 1.2 enabled -- properly configured" `
                -Details "A.8.24 Use of cryptography: TLS 1.2 must be enabled for secure communications" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1'; STIG='V-220964' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Fail" `
                -Message "A.8.24a: Use of cryptography -- TLS 1.2 enabled -- not configured (Value=$val)" `
                -Details "A.8.24 Use of cryptography: TLS 1.2 must be enabled for secure communications" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1'; STIG='V-220964' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Error" `
            -Message "A.8.24a: Use of cryptography -- TLS 1.2 enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1'; STIG='V-220964' }
    }
    # A.8.24b: Use of cryptography -- SSL 2.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Pass" `
                -Message "A.8.24b: Use of cryptography -- SSL 2.0 disabled -- properly configured" `
                -Details "A.8.24 Use of cryptography: SSL 2.0 is insecure and must be disabled" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Fail" `
                -Message "A.8.24b: Use of cryptography -- SSL 2.0 disabled -- not configured (Value=$val)" `
                -Details "A.8.24 Use of cryptography: SSL 2.0 is insecure and must be disabled" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Error" `
            -Message "A.8.24b: Use of cryptography -- SSL 2.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
    }
    # A.8.24c: Use of cryptography -- SSL 3.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Pass" `
                -Message "A.8.24c: Use of cryptography -- SSL 3.0 disabled -- properly configured" `
                -Details "A.8.24 Use of cryptography: SSL 3.0 (POODLE vulnerability) must be disabled" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Fail" `
                -Message "A.8.24c: Use of cryptography -- SSL 3.0 disabled -- not configured (Value=$val)" `
                -Details "A.8.24 Use of cryptography: SSL 3.0 (POODLE vulnerability) must be disabled" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Error" `
            -Message "A.8.24c: Use of cryptography -- SSL 3.0 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
    }
    # A.8.24d: Use of cryptography -- TLS 1.0 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Pass" `
                -Message "A.8.24d: Use of cryptography -- TLS 1.0 disabled -- properly configured" `
                -Details "A.8.24 Use of cryptography: TLS 1.0 has known vulnerabilities and should be disabled" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Fail" `
                -Message "A.8.24d: Use of cryptography -- TLS 1.0 disabled -- not configured (Value=$val)" `
                -Details "A.8.24 Use of cryptography: TLS 1.0 has known vulnerabilities and should be disabled" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Error" `
            -Message "A.8.24d: Use of cryptography -- TLS 1.0 disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
    }
    # A.8.24e: Use of cryptography -- TLS 1.1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Pass" `
                -Message "A.8.24e: Use of cryptography -- TLS 1.1 disabled -- properly configured" `
                -Details "A.8.24 Use of cryptography: TLS 1.1 is deprecated and should be disabled" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Fail" `
                -Message "A.8.24e: Use of cryptography -- TLS 1.1 disabled -- not configured (Value=$val)" `
                -Details "A.8.24 Use of cryptography: TLS 1.1 is deprecated and should be disabled" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Cryptography" -Status "Error" `
            -Message "A.8.24e: Use of cryptography -- TLS 1.1 disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.24'; NIST='SC-13'; 'PCI-DSS'='4.1' }
    }

# ===========================================================================
# A.8 Technological Controls -- Vulnerabilities & Configuration
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- Vulnerabilities & Configuration..." -ForegroundColor Yellow

    # A.8.8a: Management of technical vulnerabilities -- Windows Update auto
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Default $null
        if ($null -ne $val -and $val -ge 4) {
            Add-Result -Category "ISO27001 - A.8 Vulnerabilities" -Status "Pass" `
                -Message "A.8.8a: Management of technical vulnerabilities -- Windows Update auto -- properly configured" `
                -Details "A.8.8 Technical vulnerabilities: Automatic updates should be enabled for timely patching" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.8'; NIST='SI-2'; CIS='18.9.101.2'; CISA='Patch Management' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Vulnerabilities" -Status "Fail" `
                -Message "A.8.8a: Management of technical vulnerabilities -- Windows Update auto -- not configured (Value=$val)" `
                -Details "A.8.8 Technical vulnerabilities: Automatic updates should be enabled for timely patching" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -Value 4" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.8'; NIST='SI-2'; CIS='18.9.101.2'; CISA='Patch Management' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Vulnerabilities" -Status "Error" `
            -Message "A.8.8a: Management of technical vulnerabilities -- Windows Update auto -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.8'; NIST='SI-2'; CIS='18.9.101.2'; CISA='Patch Management' }
    }
    # A.8.8b: Management of technical vulnerabilities -- Windows Update service
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "ISO27001 - A.8 Vulnerabilities" -Status "Pass" `
                -Message "A.8.8b: Management of technical vulnerabilities -- Windows Update service -- service running" `
                -Details "A.8.8 Technical vulnerabilities: Windows Update service must be running for patch delivery" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.8'; NIST='SI-2'; CISA='Patch Management' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "ISO27001 - A.8 Vulnerabilities" -Status "Fail" `
                -Message "A.8.8b: Management of technical vulnerabilities -- Windows Update service -- service not running (Status=$svcSt)" `
                -Details "A.8.8 Technical vulnerabilities: Windows Update service must be running for patch delivery" `
                -Remediation "Start-Service -Name wuauserv; Set-Service -Name wuauserv -StartupType Automatic" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.8'; NIST='SI-2'; CISA='Patch Management' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Vulnerabilities" -Status "Error" `
            -Message "A.8.8b: Management of technical vulnerabilities -- Windows Update service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.8'; NIST='SI-2'; CISA='Patch Management' }
    }
    # A.8.9a: Configuration management -- PowerShell Script Block Logging
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.9a: Configuration management -- PowerShell Script Block Logging -- properly configured" `
                -Details "A.8.9 Configuration management: Script Block Logging records all PowerShell execution for audit" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-6'; CIS='18.9.100.1'; NSA='PowerShell Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Fail" `
                -Message "A.8.9a: Configuration management -- PowerShell Script Block Logging -- not configured (Value=$val)" `
                -Details "A.8.9 Configuration management: Script Block Logging records all PowerShell execution for audit" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-6'; CIS='18.9.100.1'; NSA='PowerShell Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.9a: Configuration management -- PowerShell Script Block Logging -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-6'; CIS='18.9.100.1'; NSA='PowerShell Security' }
    }
    # A.8.9b: Configuration management -- PowerShell Transcription
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.9b: Configuration management -- PowerShell Transcription -- properly configured" `
                -Details "A.8.9 Configuration management: Transcription logs all PowerShell input/output to files" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='AU-12'; CIS='18.9.100.2'; NSA='PowerShell Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Fail" `
                -Message "A.8.9b: Configuration management -- PowerShell Transcription -- not configured (Value=$val)" `
                -Details "A.8.9 Configuration management: Transcription logs all PowerShell input/output to files" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='AU-12'; CIS='18.9.100.2'; NSA='PowerShell Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.9b: Configuration management -- PowerShell Transcription -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.9'; NIST='AU-12'; CIS='18.9.100.2'; NSA='PowerShell Security' }
    }
    # A.8.9c: Configuration management -- PowerShell v2 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine" -Name "PSCompatibleVersion" -Default $null
        if ($null -ne $val) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.9c: Configuration management -- PowerShell v2 disabled -- properly configured" `
                -Details "A.8.9 Configuration management: PowerShell v2 bypasses all logging; check for removal" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-7'; CIS='18.9.100.3'; NSA='PowerShell Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Warning" `
                -Message "A.8.9c: Configuration management -- PowerShell v2 disabled -- not configured (Value=$val)" `
                -Details "A.8.9 Configuration management: PowerShell v2 bypasses all logging; check for removal" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-7'; CIS='18.9.100.3'; NSA='PowerShell Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.9c: Configuration management -- PowerShell v2 disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-7'; CIS='18.9.100.3'; NSA='PowerShell Security' }
    }
    # A.8.9d: Configuration management -- SMBv1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.9d: Configuration management -- SMBv1 disabled -- properly configured" `
                -Details "A.8.9 Configuration management: SMBv1 is a critical attack vector (WannaCry/NotPetya)" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-7'; CIS='18.3.3'; STIG='V-220968'; NSA='Network Hardening' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Fail" `
                -Message "A.8.9d: Configuration management -- SMBv1 disabled -- not configured (Value=$val)" `
                -Details "A.8.9 Configuration management: SMBv1 is a critical attack vector (WannaCry/NotPetya)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-7'; CIS='18.3.3'; STIG='V-220968'; NSA='Network Hardening' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.9d: Configuration management -- SMBv1 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.9'; NIST='CM-7'; CIS='18.3.3'; STIG='V-220968'; NSA='Network Hardening' }
    }
    # A.8.10: Information deletion -- pagefile cleared at shutdown
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.10: Information deletion -- pagefile cleared at shutdown -- properly configured" `
                -Details "A.8.10 Information deletion: Pagefile may contain sensitive data; clear at shutdown" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.10'; NIST='SC-4'; CIS='2.3.11.9'; GDPR='Art.17' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Fail" `
                -Message "A.8.10: Information deletion -- pagefile cleared at shutdown -- not configured (Value=$val)" `
                -Details "A.8.10 Information deletion: Pagefile may contain sensitive data; clear at shutdown" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.10'; NIST='SC-4'; CIS='2.3.11.9'; GDPR='Art.17' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.10: Information deletion -- pagefile cleared at shutdown -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.10'; NIST='SC-4'; CIS='2.3.11.9'; GDPR='Art.17' }
    }
    # A.8.12a: Data leakage prevention -- clipboard redirection disabled in RDP
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.12a: Data leakage prevention -- clipboard redirection disabled in RDP -- properly configured" `
                -Details "A.8.12 Data leakage prevention: Clipboard redirection in RDP enables data exfiltration" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.12'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Fail" `
                -Message "A.8.12a: Data leakage prevention -- clipboard redirection disabled in RDP -- not configured (Value=$val)" `
                -Details "A.8.12 Data leakage prevention: Clipboard redirection in RDP enables data exfiltration" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableClip -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.12'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.12a: Data leakage prevention -- clipboard redirection disabled in RDP -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.12'; NIST='AC-4'; CIS='18.9.65.3.3.1' }
    }
    # A.8.12b: Data leakage prevention -- drive redirection disabled in RDP
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Pass" `
                -Message "A.8.12b: Data leakage prevention -- drive redirection disabled in RDP -- properly configured" `
                -Details "A.8.12 Data leakage prevention: Drive mapping in RDP enables unauthorized file transfer" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.12'; NIST='AC-4'; CIS='18.9.65.3.3.2' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Fail" `
                -Message "A.8.12b: Data leakage prevention -- drive redirection disabled in RDP -- not configured (Value=$val)" `
                -Details "A.8.12 Data leakage prevention: Drive mapping in RDP enables unauthorized file transfer" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCdm -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.12'; NIST='AC-4'; CIS='18.9.65.3.3.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Configuration" -Status "Error" `
            -Message "A.8.12b: Data leakage prevention -- drive redirection disabled in RDP -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.12'; NIST='AC-4'; CIS='18.9.65.3.3.2' }
    }

# ===========================================================================
# A.8 Technological Controls -- Backup & Logging
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- Backup & Logging..." -ForegroundColor Yellow

    # A.8.13a: Information backup -- Volume Shadow Copy available
    try {
        $svc = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "ISO27001 - A.8 Backup" -Status "Pass" `
                -Message "A.8.13a: Information backup -- Volume Shadow Copy available -- service running" `
                -Details "A.8.13 Information backup: VSS provides point-in-time recovery for data protection" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.13'; NIST='CP-9'; SOC2='A1.2' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "ISO27001 - A.8 Backup" -Status "Warning" `
                -Message "A.8.13a: Information backup -- Volume Shadow Copy available -- service not running (Status=$svcSt)" `
                -Details "A.8.13 Information backup: VSS provides point-in-time recovery for data protection" `
                -Remediation "Set-Service -Name VSS -StartupType Manual" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.13'; NIST='CP-9'; SOC2='A1.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Backup" -Status "Error" `
            -Message "A.8.13a: Information backup -- Volume Shadow Copy available -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.13'; NIST='CP-9'; SOC2='A1.2' }
    }
    # A.8.13b: Information backup -- System Restore status
    try {
        $srStatus = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "RPSessionInterval" -Default $null
        $srDisabled = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Default 0
        if ($srDisabled -ne 1) {
            $intervalMsg = if ($null -ne $srStatus) { " (restore point interval: $srStatus seconds)" } else { "" }
            Add-Result -Category "ISO27001 - A.8 Backup" -Status "Pass" `
                -Message "A.8.13b: System Restore is enabled$intervalMsg" `
                -Details "A.8.13 Information backup: System Restore provides OS recovery capability" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.13'; NIST='CP-9'; SOC2='A1.2' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Backup" -Status "Warning" `
                -Message "A.8.13b: System Restore is DISABLED by policy" `
                -Details "A.8.13 Information backup: Ensure alternative backup/recovery mechanisms exist" `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name DisableSR" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.13'; NIST='CP-9'; SOC2='A1.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Backup" -Status "Error" `
            -Message "A.8.13b: Information backup -- System Restore status -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.13'; NIST='CP-9' }
    }
    # A.8.15a: Logging -- audit policy: Logon Events
    try {
        $auditOutput = auditpol /get /category:"Logon/Logoff" 2>&1
        $logonSuccess = $false
        foreach ($line in $auditOutput) {
            if ($line -match "Logon" -and $line -match "Success") { $logonSuccess = $true }
        }
        if ($logonSuccess) {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Pass" `
                -Message "A.8.15a: Logon event auditing is enabled" `
                -Details "A.8.15 Logging: Logon events are captured for access monitoring" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-2'; CIS='17.5.1'; STIG='V-220958' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Fail" `
                -Message "A.8.15a: Logon event auditing is NOT enabled" `
                -Details "A.8.15 Logging: Cannot track access without logon event auditing" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-2'; CIS='17.5.1'; STIG='V-220958' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Logging" -Status "Error" `
            -Message "A.8.15a: Logging -- audit policy: Logon Events -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-2' }
    }
    # A.8.15b: Logging -- audit policy: Account Management
    try {
        $auditOutput = auditpol /get /category:"Account Management" 2>&1
        $acctAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "User Account Management" -and $line -match "Success") { $acctAudit = $true }
        }
        if ($acctAudit) {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Pass" `
                -Message "A.8.15b: Account management auditing is enabled" `
                -Details "A.8.15 Logging: Account changes are captured for compliance" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-2'; CIS='17.1.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Fail" `
                -Message "A.8.15b: Account management auditing is NOT enabled" `
                -Details "A.8.15 Logging: Account modifications cannot be tracked without auditing" `
                -Remediation "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-2'; CIS='17.1.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Logging" -Status "Error" `
            -Message "A.8.15b: Logging -- audit policy: Account Management -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-2' }
    }
    # A.8.15c: Logging -- audit policy: Object Access
    try {
        $auditOutput = auditpol /get /category:"Object Access" 2>&1
        $objAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "File System" -and ($line -match "Success" -or $line -match "Failure")) { $objAudit = $true }
        }
        if ($objAudit) {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Pass" `
                -Message "A.8.15c: File system object access auditing is enabled" `
                -Details "A.8.15 Logging: File access events are captured for data protection monitoring" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12'; CIS='17.6.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Warning" `
                -Message "A.8.15c: File system object access auditing is NOT configured" `
                -Details "A.8.15 Logging: Consider enabling file access auditing for sensitive data paths" `
                -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12'; CIS='17.6.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Logging" -Status "Error" `
            -Message "A.8.15c: Logging -- audit policy: Object Access -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12' }
    }
    # A.8.15d: Logging -- audit policy: Policy Change
    try {
        $auditOutput = auditpol /get /category:"Policy Change" 2>&1
        $policyAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "Audit Policy Change" -and $line -match "Success") { $policyAudit = $true }
        }
        if ($policyAudit) {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Pass" `
                -Message "A.8.15d: Policy change auditing is enabled" `
                -Details "A.8.15 Logging: Security policy modifications are tracked" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12'; CIS='17.7.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Fail" `
                -Message "A.8.15d: Policy change auditing is NOT enabled" `
                -Details "A.8.15 Logging: Unauthorized policy changes cannot be detected" `
                -Remediation "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12'; CIS='17.7.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Logging" -Status "Error" `
            -Message "A.8.15d: Logging -- audit policy: Policy Change -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12' }
    }
    # A.8.15e: Logging -- audit policy: Privilege Use
    try {
        $auditOutput = auditpol /get /category:"Privilege Use" 2>&1
        $privAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "Sensitive Privilege Use" -and $line -match "Success") { $privAudit = $true }
        }
        if ($privAudit) {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Pass" `
                -Message "A.8.15e: Sensitive privilege use auditing is enabled" `
                -Details "A.8.15 Logging: Privileged operations are tracked for accountability" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12'; CIS='17.8.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Warning" `
                -Message "A.8.15e: Sensitive privilege use auditing is NOT configured" `
                -Details "A.8.15 Logging: Enable for privileged operation accountability" `
                -Remediation "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12'; CIS='17.8.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Logging" -Status "Error" `
            -Message "A.8.15e: Logging -- audit policy: Privilege Use -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.15'; NIST='AU-12' }
    }
    # A.8.16: Monitoring activities -- Windows Event Log
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Pass" `
                -Message "A.8.16: Monitoring activities -- Windows Event Log -- service running" `
                -Details "A.8.16 Monitoring activities: Central event logging service must be operational" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.16'; NIST='AU-6'; SOC2='CC4.1' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "ISO27001 - A.8 Logging" -Status "Fail" `
                -Message "A.8.16: Monitoring activities -- Windows Event Log -- service not running (Status=$svcSt)" `
                -Details "A.8.16 Monitoring activities: Central event logging service must be operational" `
                -Remediation "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.16'; NIST='AU-6'; SOC2='CC4.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Logging" -Status "Error" `
            -Message "A.8.16: Monitoring activities -- Windows Event Log -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.16'; NIST='AU-6'; SOC2='CC4.1' }
    }

# ===========================================================================
# A.8 Technological Controls -- Network Security
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- Network Security..." -ForegroundColor Yellow

    # A.8.20a: Network security -- firewall enabled (Domain profile)
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $domainFw = $fwProfiles | Where-Object { $_.Name -eq "Domain" }
        if ($null -ne $domainFw -and $domainFw.Enabled -eq $true) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20a: Firewall enabled on Domain profile" `
                -Details "A.8.20 Network security: Domain network firewall provides boundary protection" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='9.1.1'; STIG='V-220908' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20a: Firewall DISABLED on Domain profile" `
                -Details "A.8.20 Network security: All firewall profiles must be enabled" `
                -Remediation "Set-NetFirewallProfile -Profile Domain -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='9.1.1'; STIG='V-220908' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20a: Network security -- firewall enabled (Domain profile) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7' }
    }
    # A.8.20b: Network security -- firewall enabled (Private profile)
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $privateFw = $fwProfiles | Where-Object { $_.Name -eq "Private" }
        if ($null -ne $privateFw -and $privateFw.Enabled -eq $true) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20b: Firewall enabled on Private profile" `
                -Details "A.8.20 Network security: Private network firewall provides boundary protection" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='9.2.1'; STIG='V-220909' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20b: Firewall DISABLED on Private profile" `
                -Details "A.8.20 Network security: All firewall profiles must be enabled" `
                -Remediation "Set-NetFirewallProfile -Profile Private -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='9.2.1'; STIG='V-220909' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20b: Network security -- firewall enabled (Private profile) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7' }
    }
    # A.8.20c: Network security -- firewall enabled (Public profile)
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $publicFw = $fwProfiles | Where-Object { $_.Name -eq "Public" }
        if ($null -ne $publicFw -and $publicFw.Enabled -eq $true) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20c: Firewall enabled on Public profile" `
                -Details "A.8.20 Network security: Public network firewall provides boundary protection" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='9.3.1'; STIG='V-220912' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20c: Firewall DISABLED on Public profile" `
                -Details "A.8.20 Network security: Public profile is most critical for boundary defense" `
                -Remediation "Set-NetFirewallProfile -Profile Public -Enabled True" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='9.3.1'; STIG='V-220912' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20c: Network security -- firewall enabled (Public profile) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7' }
    }
    # A.8.20d: Network security -- LLMNR disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20d: Network security -- LLMNR disabled -- properly configured" `
                -Details "A.8.20 Network security: LLMNR enables name poisoning attacks on local networks" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-20'; CIS='18.5.4.2'; NSA='Network Protocol Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20d: Network security -- LLMNR disabled -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: LLMNR enables name poisoning attacks on local networks" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-20'; CIS='18.5.4.2'; NSA='Network Protocol Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20d: Network security -- LLMNR disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-20'; CIS='18.5.4.2'; NSA='Network Protocol Security' }
    }
    # A.8.20e: Network security -- NetBIOS over TCP/IP
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20e: Network security -- NetBIOS over TCP/IP -- properly configured" `
                -Details "A.8.20 Network security: NetBIOS NodeType=2 (P-node) prevents broadcast name resolution" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-20'; NSA='Network Protocol Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20e: Network security -- NetBIOS over TCP/IP -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: NetBIOS NodeType=2 (P-node) prevents broadcast name resolution" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name NodeType -Value 2" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-20'; NSA='Network Protocol Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20e: Network security -- NetBIOS over TCP/IP -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-20'; NSA='Network Protocol Security' }
    }
    # A.8.20f: Network security -- WPAD disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20f: Network security -- WPAD disabled -- properly configured" `
                -Details "A.8.20 Network security: WPAD auto-proxy discovery enables traffic interception" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.5.21.1'; NSA='Network Protocol Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20f: Network security -- WPAD disabled -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: WPAD auto-proxy discovery enables traffic interception" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name WpadOverride -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.5.21.1'; NSA='Network Protocol Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20f: Network security -- WPAD disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.5.21.1'; NSA='Network Protocol Security' }
    }
    # A.8.20g: Network security -- Remote Desktop disabled (if not needed)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20g: Network security -- Remote Desktop disabled (if not needed) -- properly configured" `
                -Details "A.8.20 Network security: RDP should be disabled unless explicitly required" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='AC-17'; CIS='18.9.65.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Info" `
                -Message "A.8.20g: Network security -- Remote Desktop disabled (if not needed) -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: RDP should be disabled unless explicitly required" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='AC-17'; CIS='18.9.65.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20g: Network security -- Remote Desktop disabled (if not needed) -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='AC-17'; CIS='18.9.65.1' }
    }

# ===========================================================================
# A.8 Technological Controls -- SDLC & Hardening
# ===========================================================================
Write-Host "[ISO27001] Checking A.8 Technological Controls -- SDLC & Hardening..." -ForegroundColor Yellow

    # A.8.25a: Secure development -- DEP enforcement
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Default $null
        if ($null -ne $val -and $val -ne 0) {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Pass" `
                -Message "A.8.25a: Secure development -- DEP enforcement -- properly configured" `
                -Details "A.8.25 Secure development: DEP (Data Execution Prevention) must be enforced" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-16'; CIS='18.3.2'; STIG='V-220726' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Fail" `
                -Message "A.8.25a: Secure development -- DEP enforcement -- not configured (Value=$val)" `
                -Details "A.8.25 Secure development: DEP (Data Execution Prevention) must be enforced" `
                -Remediation "bcdedit /set nx AlwaysOn" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-16'; CIS='18.3.2'; STIG='V-220726' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Error" `
            -Message "A.8.25a: Secure development -- DEP enforcement -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-16'; CIS='18.3.2'; STIG='V-220726' }
    }
    # A.8.25b: Secure development -- SEHOP enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Pass" `
                -Message "A.8.25b: Secure development -- SEHOP enabled -- properly configured" `
                -Details "A.8.25 Secure development: SEHOP prevents structured exception handler exploitation" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-16'; NSA='Exploit Mitigation' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Fail" `
                -Message "A.8.25b: Secure development -- SEHOP enabled -- not configured (Value=$val)" `
                -Details "A.8.25 Secure development: SEHOP prevents structured exception handler exploitation" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name DisableExceptionChainValidation -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-16'; NSA='Exploit Mitigation' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Error" `
            -Message "A.8.25b: Secure development -- SEHOP enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-16'; NSA='Exploit Mitigation' }
    }
    # A.8.25c: Secure development -- Secure Boot status
    try {
        try {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBoot -eq $true) {
                Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Pass" `
                    -Message "A.8.25c: Secure Boot is enabled" `
                    -Details "A.8.25 Secure development: UEFI Secure Boot verifies boot integrity" `
                    -Severity "High" `
                    -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-7'; CIS='1.1.1' }
            } else {
                Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Fail" `
                    -Message "A.8.25c: Secure Boot is NOT enabled" `
                    -Details "A.8.25 Secure development: Enable Secure Boot in UEFI firmware settings" `
                    -Remediation "Enable Secure Boot in UEFI/BIOS firmware settings" `
                    -Severity "High" `
                    -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-7'; CIS='1.1.1' }
            }
        } catch {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Info" `
                -Message "A.8.25c: Secure Boot status could not be determined (may not be UEFI)" `
                -Details "A.8.25 Secure development: System may use legacy BIOS without Secure Boot support" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-7' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Error" `
            -Message "A.8.25c: Secure development -- Secure Boot status -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.25'; NIST='SI-7' }
    }
    # A.8.25d: Secure development -- VBS enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Pass" `
                -Message "A.8.25d: Secure development -- VBS enabled -- properly configured" `
                -Details "A.8.25 Secure development: Virtualization-based security isolates critical OS functions" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SC-39'; CIS='18.8.5.1'; NSA='Boot Security' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Fail" `
                -Message "A.8.25d: Secure development -- VBS enabled -- not configured (Value=$val)" `
                -Details "A.8.25 Secure development: Virtualization-based security isolates critical OS functions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -Value 1" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.25'; NIST='SC-39'; CIS='18.8.5.1'; NSA='Boot Security' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Error" `
            -Message "A.8.25d: Secure development -- VBS enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.25'; NIST='SC-39'; CIS='18.8.5.1'; NSA='Boot Security' }
    }
    # A.8.9e: Configuration management -- Windows Remote Management (WinRM) hardened
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Pass" `
                -Message "A.8.9e: Configuration management -- Windows Remote Management (WinRM) hardened -- properly configured" `
                -Details "A.8.9 Configuration management: WinRM basic authentication exposes credentials in cleartext" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='IA-2'; CIS='18.9.102.1.1'; NSA='Remote Access' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Fail" `
                -Message "A.8.9e: Configuration management -- Windows Remote Management (WinRM) hardened -- not configured (Value=$val)" `
                -Details "A.8.9 Configuration management: WinRM basic authentication exposes credentials in cleartext" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowBasic -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='IA-2'; CIS='18.9.102.1.1'; NSA='Remote Access' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Error" `
            -Message "A.8.9e: Configuration management -- Windows Remote Management (WinRM) hardened -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.9'; NIST='IA-2'; CIS='18.9.102.1.1'; NSA='Remote Access' }
    }
    # A.8.9f: Configuration management -- WinRM unencrypted traffic disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Pass" `
                -Message "A.8.9f: Configuration management -- WinRM unencrypted traffic disabled -- properly configured" `
                -Details "A.8.9 Configuration management: WinRM must encrypt all management traffic" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='SC-8'; CIS='18.9.102.1.3' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Fail" `
                -Message "A.8.9f: Configuration management -- WinRM unencrypted traffic disabled -- not configured (Value=$val)" `
                -Details "A.8.9 Configuration management: WinRM must encrypt all management traffic" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.9'; NIST='SC-8'; CIS='18.9.102.1.3' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Hardening" -Status "Error" `
            -Message "A.8.9f: Configuration management -- WinRM unencrypted traffic disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.9'; NIST='SC-8'; CIS='18.9.102.1.3' }
    }
    # A.8.20h: Network security -- IPv6 source routing disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20h: Network security -- IPv6 source routing disabled -- properly configured" `
                -Details "A.8.20 Network security: IPv6 source routing can bypass network controls" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.2' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20h: Network security -- IPv6 source routing disabled -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: IPv6 source routing can bypass network controls" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisableIPSourceRouting -Value 2" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20h: Network security -- IPv6 source routing disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.2' }
    }
    # A.8.20i: Network security -- IPv4 source routing disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20i: Network security -- IPv4 source routing disabled -- properly configured" `
                -Details "A.8.20 Network security: IP source routing can bypass network security controls" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.3' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20i: Network security -- IPv4 source routing disabled -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: IP source routing can bypass network security controls" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name DisableIPSourceRouting -Value 2" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.3' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20i: Network security -- IPv4 source routing disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.3' }
    }
    # A.8.20j: Network security -- ICMP redirects ignored
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Pass" `
                -Message "A.8.20j: Network security -- ICMP redirects ignored -- properly configured" `
                -Details "A.8.20 Network security: ICMP redirects can manipulate routing tables" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.4' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Fail" `
                -Message "A.8.20j: Network security -- ICMP redirects ignored -- not configured (Value=$val)" `
                -Details "A.8.20 Network security: ICMP redirects can manipulate routing tables" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name EnableICMPRedirect -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.4' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Network Security" -Status "Error" `
            -Message "A.8.20j: Network security -- ICMP redirects ignored -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.20'; NIST='SC-7'; CIS='18.4.4' }
    }
    # A.8.7a: Protection against malware -- scan downloads
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.7a: Protection against malware -- scan downloads -- properly configured" `
                -Details "A.8.7 Protection against malware: All downloads must be scanned in real-time" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.7'; NIST='SI-3'; CIS='18.9.47.9.3' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.7a: Protection against malware -- scan downloads -- not configured (Value=$val)" `
                -Details "A.8.7 Protection against malware: All downloads must be scanned in real-time" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableIOAVProtection -Value 0" `
                -Severity "High" `
                -CrossReferences @{ ISO27001='A.8.7'; NIST='SI-3'; CIS='18.9.47.9.3' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.7a: Protection against malware -- scan downloads -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ ISO27001='A.8.7'; NIST='SI-3'; CIS='18.9.47.9.3' }
    }
    # A.8.7b: Protection against malware -- automatic sample submission
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Pass" `
                -Message "A.8.7b: Protection against malware -- automatic sample submission -- properly configured" `
                -Details "A.8.7 Protection against malware: Automatic sample submission enhances threat intelligence" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.7'; NIST='SI-3'; CIS='18.9.47.11.2' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Fail" `
                -Message "A.8.7b: Protection against malware -- automatic sample submission -- not configured (Value=$val)" `
                -Details "A.8.7 Protection against malware: Automatic sample submission enhances threat intelligence" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name SubmitSamplesConsent -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.7'; NIST='SI-3'; CIS='18.9.47.11.2' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Endpoint Devices" -Status "Error" `
            -Message "A.8.7b: Protection against malware -- automatic sample submission -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.7'; NIST='SI-3'; CIS='18.9.47.11.2' }
    }
    # A.8.3a: Information access restriction -- LM hash storage disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.3a: Information access restriction -- LM hash storage disabled -- properly configured" `
                -Details "A.8.3 Information access restriction: LM hashes are cryptographically weak and easily cracked" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.3'; NIST='IA-5'; CIS='2.3.11.5'; STIG='V-220725' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.3a: Information access restriction -- LM hash storage disabled -- not configured (Value=$val)" `
                -Details "A.8.3 Information access restriction: LM hashes are cryptographically weak and easily cracked" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ ISO27001='A.8.3'; NIST='IA-5'; CIS='2.3.11.5'; STIG='V-220725' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.3a: Information access restriction -- LM hash storage disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ ISO27001='A.8.3'; NIST='IA-5'; CIS='2.3.11.5'; STIG='V-220725' }
    }
    # A.8.3b: Information access restriction -- cached logon credentials limited
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Default $null
        if ($null -ne $val -and $val -le 4) {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Pass" `
                -Message "A.8.3b: Information access restriction -- cached logon credentials limited -- properly configured" `
                -Details "A.8.3 Information access restriction: Limit cached logon credentials to minimize exposure" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.3'; NIST='IA-5'; CIS='2.3.11.1' }
        } else {
            Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Fail" `
                -Message "A.8.3b: Information access restriction -- cached logon credentials limited -- not configured (Value=$val)" `
                -Details "A.8.3 Information access restriction: Limit cached logon credentials to minimize exposure" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4" `
                -Severity "Medium" `
                -CrossReferences @{ ISO27001='A.8.3'; NIST='IA-5'; CIS='2.3.11.1' }
        }
    } catch {
        Add-Result -Category "ISO27001 - A.8 Privileged Access" -Status "Error" `
            -Message "A.8.3b: Information access restriction -- cached logon credentials limited -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ ISO27001='A.8.3'; NIST='IA-5'; CIS='2.3.11.1' }
    }


# ===========================================================================
# v6.1: ISO 27002:2022 implementation guidance references
# ===========================================================================
Write-Host "[ISO27001] Checking ISO 27002:2022 implementation references..." -ForegroundColor Yellow

try {
    $cgEnabled = Test-CredentialGuardEnabled
    if ($cgEnabled) {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Pass" `
            -Severity "High" `
            -Message "27002 Sec.5.16 Identity management: privileged identity isolation active" `
            -Details "ISO/IEC 27002:2022 Sec.5.16 covers identity management implementation guidance" `
            -CrossReferences @{ ISO27001='A.5.16'; ISO27002='5.16'; NIST='IA-5' }
    }
    else {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Warning" `
            -Severity "High" `
            -Message "27002 Sec.5.16 Credential Guard inactive (identity management gap)" `
            -CrossReferences @{ ISO27001='A.5.16'; ISO27002='5.16' }
    }

    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Pass" `
            -Severity "High" `
            -Message "27002 Sec.8.24 Use of cryptography: at-rest encryption operational" `
            -CrossReferences @{ ISO27001='A.8.24'; ISO27002='8.24'; NIST='SC-28' }
    }
    else {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Fail" `
            -Severity "High" `
            -Message "27002 Sec.8.24 No at-rest encryption implementation" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ ISO27001='A.8.24'; ISO27002='8.24' }
    }

    $defenderStatus = Get-DefenderStatus -Cache $SharedData.Cache
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Pass" `
            -Severity "High" `
            -Message "27002 Sec.8.7 Protection against malware: real-time protection active" `
            -CrossReferences @{ ISO27001='A.8.7'; ISO27002='8.7'; NIST='SI-3' }
    }
    else {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Fail" `
            -Severity "Critical" `
            -Message "27002 Sec.8.7 Malware protection inactive" `
            -CrossReferences @{ ISO27001='A.8.7'; ISO27002='8.7' }
    }

    $auditPS = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default 0
    if ($auditPS -eq 1) {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Pass" `
            -Severity "Medium" `
            -Message "27002 Sec.8.15 Logging: PowerShell script block logging operational" `
            -CrossReferences @{ ISO27001='A.8.15'; ISO27002='8.15'; NIST='AU-12' }
    }
    else {
        Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Warning" `
            -Severity "Medium" `
            -Message "27002 Sec.8.15 Logging gap: PowerShell script block logging disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord" `
            -CrossReferences @{ ISO27001='A.8.15'; ISO27002='8.15' }
    }
}
catch {
    Add-Result -Category "ISO27001 - 27002:2022 Guidance" -Status "Error" `
        -Severity "Medium" `
        -Message "ISO 27002:2022 guidance assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: ISO/IEC 27017 (Cloud Services) and 27018 (PII in Cloud)
# ===========================================================================
Write-Host "[ISO27001] Checking ISO 27017/27018 cloud-extension controls..." -ForegroundColor Yellow

try {
    $tlsv12Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default $null
    if ($null -eq $tlsv12Server -or $tlsv12Server -eq 1) {
        Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Pass" `
            -Severity "High" `
            -Message "27017 CLD.13.1 Network segregation in cloud: TLS 1.2 available" `
            -Details "ISO/IEC 27017 Cloud Services adds cloud-specific guidance to ISO 27002 controls" `
            -CrossReferences @{ ISO27017='CLD.13.1'; ISO27001='A.8.20' }
    }
    else {
        Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Fail" `
            -Severity "High" `
            -Message "27017 CLD.13.1 TLS 1.2 disabled (cloud transit encryption gap)" `
            -CrossReferences @{ ISO27017='CLD.13.1' }
    }

    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Pass" `
            -Severity "High" `
            -Message "27018 PII protection in cloud: at-rest encryption (Sec.7 Data minimization)" `
            -Details "ISO/IEC 27018 PII processor controls require encryption of PII in cloud environments" `
            -CrossReferences @{ ISO27018='Sec.7'; ISO27001='A.8.24' }
    }
    else {
        Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Fail" `
            -Severity "Critical" `
            -Message "27018 PII at-rest encryption inactive" `
            -CrossReferences @{ ISO27018='Sec.7' }
    }

    $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
    if ($secLogSize -ge 268435456) {
        Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Pass" `
            -Severity "Medium" `
            -Message "27018 Sec.A.10 Customer monitoring: audit retention adequate" `
            -CrossReferences @{ ISO27018='A.10'; ISO27001='A.8.15' }
    }
    else {
        Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Warning" `
            -Severity "Medium" `
            -Message "27018 Sec.A.10 Audit log retention below customer monitoring baseline" `
            -Remediation "wevtutil sl Security /ms:268435456" `
            -CrossReferences @{ ISO27018='A.10' }
    }
}
catch {
    Add-Result -Category "ISO27001 - 27017/27018 Cloud" -Status "Error" `
        -Severity "Medium" `
        -Message "Cloud extension assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: ISO/IEC 27701 (Privacy Information Management)
# ===========================================================================
Write-Host "[ISO27001] Checking ISO 27701 privacy management controls..." -ForegroundColor Yellow

try {
    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Pass" `
            -Severity "High" `
            -Message "27701 Sec.6.13.2 Privacy by design: PII protection through encryption" `
            -CrossReferences @{ ISO27701='6.13.2'; ISO27001='A.8.24' }
    }
    else {
        Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Fail" `
            -Severity "High" `
            -Message "27701 Sec.6.13.2 Privacy by design gap: PII at-rest unprotected" `
            -CrossReferences @{ ISO27701='6.13.2' }
    }

    $auditUserMgmt = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -eq 'User Account Management' }
    if ($auditUserMgmt -and $auditUserMgmt.Setting -ne 'No Auditing') {
        Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Pass" `
            -Severity "Medium" `
            -Message "27701 Sec.7.2.7 PII transfer recording: account management audited" `
            -CrossReferences @{ ISO27701='7.2.7'; ISO27001='A.5.34' }
    }
    else {
        Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Warning" `
            -Severity "Medium" `
            -Message "27701 Sec.7.2.7 User account management auditing not active" `
            -Remediation "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable" `
            -CrossReferences @{ ISO27701='7.2.7' }
    }

    $userListPolicy = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Default 0
    if ($userListPolicy -eq 1) {
        Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Pass" `
            -Severity "Low" `
            -Message "27701 Sec.7.4.5 PII minimisation: previous user not displayed at sign-in" `
            -CrossReferences @{ ISO27701='7.4.5' }
    }
    else {
        Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Warning" `
            -Severity "Low" `
            -Message "27701 Sec.7.4.5 Previous user displayed at sign-in (PII exposure)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Type DWord" `
            -CrossReferences @{ ISO27701='7.4.5' }
    }
}
catch {
    Add-Result -Category "ISO27001 - 27701 Privacy" -Status "Error" `
        -Severity "Medium" `
        -Message "ISO 27701 privacy assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Statement of Applicability (SoA) generation support
# ===========================================================================
Write-Host "[ISO27001] Computing Statement of Applicability summary..." -ForegroundColor Yellow

try {
    $isoResults = @($results | Where-Object { $_.Module -eq 'ISO27001' })
    $applicableControls = @($isoResults | Where-Object { $_.Status -in @('Pass','Fail','Warning') })
    $passedControls = @($isoResults | Where-Object { $_.Status -eq 'Pass' })
    $failedControls = @($isoResults | Where-Object { $_.Status -eq 'Fail' })

    $applicabilityRate = if ($applicableControls.Count -gt 0) {
        [Math]::Round(($passedControls.Count / $applicableControls.Count) * 100, 1)
    } else { 0 }

    Add-Result -Category "ISO27001 - SoA Summary" -Status "Info" `
        -Severity "Informational" `
        -Message "SoA: ${applicabilityRate}% of $($applicableControls.Count) applicable controls implemented ($($passedControls.Count) pass, $($failedControls.Count) fail)" `
        -Details "ISO 27001 Sec.6.1.3(d) Statement of Applicability documents control implementation status. This is an automated technical-control summary; full SoA requires organizational assessment." `
        -CrossReferences @{ ISO27001='Sec.6.1.3(d)' }

    if ($failedControls.Count -gt 0) {
        Add-Result -Category "ISO27001 - SoA Summary" -Status "Warning" `
            -Severity "Medium" `
            -Message "SoA: $($failedControls.Count) controls require risk treatment plan documentation" `
            -Details "Failed controls require corresponding entries in the risk treatment plan (Sec.6.1.3(b))" `
            -CrossReferences @{ ISO27001='Sec.6.1.3(b)' }
    }
}
catch {
    Add-Result -Category "ISO27001 - SoA Summary" -Status "Error" `
        -Severity "Low" `
        -Message "SoA computation failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: ISO/IEC 27005 (Risk Management) and 27031 (ICT Continuity)
# ===========================================================================
Write-Host "[ISO27001] Checking ISO 27005 risk and 27031 ICT continuity evidence..." -ForegroundColor Yellow

try {
    $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
    if ($secLogSize -ge 268435456) {
        Add-Result -Category "ISO27001 - 27005 Risk" -Status "Pass" `
            -Severity "Medium" `
            -Message "27005 Sec.8 Risk monitoring: audit log capacity supports trend analysis" `
            -CrossReferences @{ ISO27005='Sec.8'; ISO27001='A.8.16' }
    }
    else {
        Add-Result -Category "ISO27001 - 27005 Risk" -Status "Warning" `
            -Severity "Medium" `
            -Message "27005 Sec.8 Audit log undersized for risk trend analysis" `
            -CrossReferences @{ ISO27005='Sec.8' }
    }

    $vssService = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vssService -and $vssService.StartType -in @('Manual','Automatic')) {
        Add-Result -Category "ISO27001 - 27031 ICT Continuity" -Status "Pass" `
            -Severity "Medium" `
            -Message "27031 Sec.7 ICT readiness: backup/restore infrastructure operational" `
            -CrossReferences @{ ISO27031='Sec.7'; ISO27001='A.5.30' }
    }
    else {
        Add-Result -Category "ISO27001 - 27031 ICT Continuity" -Status "Warning" `
            -Severity "Medium" `
            -Message "27031 Sec.7 VSS disabled (ICT recovery readiness gap)" `
            -Remediation "Set-Service -Name VSS -StartupType Manual" `
            -CrossReferences @{ ISO27031='Sec.7' }
    }

    $w32time = Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue
    if ($w32time -and $w32time.Status -eq 'Running') {
        Add-Result -Category "ISO27001 - 27031 ICT Continuity" -Status "Pass" `
            -Severity "Low" `
            -Message "27031 Time synchronization for incident reconstruction" `
            -CrossReferences @{ ISO27031='Sec.6'; ISO27001='A.8.17' }
    }
    else {
        Add-Result -Category "ISO27001 - 27031 ICT Continuity" -Status "Warning" `
            -Severity "Medium" `
            -Message "27031 Time service inactive (incident reconstruction impaired)" `
            -Remediation "Start-Service -Name W32Time; Set-Service -Name W32Time -StartupType Automatic" `
            -CrossReferences @{ ISO27031='Sec.6' }
    }

    $sysRestore = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableSR" -Default 0
    if ($sysRestore -eq 0) {
        Add-Result -Category "ISO27001 - 27031 ICT Continuity" -Status "Pass" `
            -Severity "Low" `
            -Message "27031 System restore enabled for rollback recovery" `
            -CrossReferences @{ ISO27031='Sec.7'; ISO27001='A.8.13' }
    }
    else {
        Add-Result -Category "ISO27001 - 27031 ICT Continuity" -Status "Warning" `
            -Severity "Medium" `
            -Message "27031 System Restore disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'DisableSR' -Value 0 -Type DWord; Enable-ComputerRestore -Drive 'C:\\'" `
            -CrossReferences @{ ISO27031='Sec.7' }
    }
}
catch {
    Add-Result -Category "ISO27001 - 27005 Risk" -Status "Error" `
        -Severity "Medium" `
        -Message "ISO 27005 / 27031 assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Annex A.5 Organizational and A.7 Physical control evidence
# ===========================================================================
Write-Host "[ISO27001] Checking Annex A.5/A.7 control technical evidence..." -ForegroundColor Yellow

try {
    $auditPolicyChange = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -eq 'Audit Policy Change' }
    if ($auditPolicyChange -and $auditPolicyChange.Setting -ne 'No Auditing') {
        Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Pass" `
            -Severity "Medium" `
            -Message "A.5.37 Documented operating procedures: change tracking active" `
            -CrossReferences @{ ISO27001='A.5.37' }
    }
    else {
        Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Warning" `
            -Severity "Medium" `
            -Message "A.5.37 Audit policy change tracking inactive" `
            -Remediation "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable" `
            -CrossReferences @{ ISO27001='A.5.37' }
    }

    $autoPlay = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default 0
    if ($autoPlay -eq 255) {
        Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Pass" `
            -Severity "Medium" `
            -Message "A.7.10 Storage media: AutoPlay restricted on all drive types" `
            -CrossReferences @{ ISO27001='A.7.10' }
    }
    else {
        Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Warning" `
            -Severity "Medium" `
            -Message "A.7.10 Storage media: AutoPlay not fully disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord" `
            -CrossReferences @{ ISO27001='A.7.10' }
    }

    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Pass" `
            -Severity "High" `
            -Message "A.7.5 Physical security perimeter: drive encryption mitigates physical theft risk" `
            -CrossReferences @{ ISO27001='A.7.5' }
    }
    else {
        Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Fail" `
            -Severity "High" `
            -Message "A.7.5 Physical security gap: no drive encryption (theft exposure)" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ ISO27001='A.7.5' }
    }
}
catch {
    Add-Result -Category "ISO27001 - Annex A.5/A.7" -Status "Error" `
        -Severity "Medium" `
        -Message "Annex A.5/A.7 evidence assessment failed: $($_.Exception.Message)"
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
Write-Host "  [ISO27001] ISO/IEC 27001:2022 Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
    Write-Host "  ISO/IEC 27001:2022 Module -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[ISO27001] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  ISO27001 module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
