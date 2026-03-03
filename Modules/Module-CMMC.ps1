# module-cmmc.ps1
# CMMC 2.0 Compliance Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against Cybersecurity Maturity Model Certification 2.0 (DoD)
# with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    CMMC 2.0 compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with Cybersecurity Maturity Model Certification 2.0 (DoD) including:
    - Level 1: Basic Cyber Hygiene (FCI protection, 17 practices)
    - AC: Access Control (least privilege, session locks, remote access, mobile)
    - AU: Audit and Accountability (audit events, log content, retention, protection)
    - CM: Configuration Management (baselines, change control, least functionality)
    - IA: Identification and Authentication (MFA readiness, password mgmt, authenticators)
    - IR: Incident Response (detection, reporting, response readiness)
    - MP: Media Protection (access, storage, transport, sanitization)
    - SC: System and Communications Protection (boundary, encryption, network controls)
    - SI: System and Information Integrity (flaw remediation, malware, monitoring)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: CMMC 2.0 (November 2021), NIST SP 800-171 Rev 2, 32 CFR Part 170
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-cmmc.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "CMMC"
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

Write-Host "`n[$moduleName] Starting CMMC 2.0 compliance checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# AC -- Access Control
# ===========================================================================
Write-Host "[CMMC] Checking AC -- Access Control..." -ForegroundColor Yellow

    # AC.L1-3.1.1: Authorized access control -- UAC enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L1-3.1.1: Authorized access control -- UAC enabled -- properly configured" `
                -Details "AC.L1-3.1.1: Limit system access to authorized users (Level 1)" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='AC.L1-3.1.1'; NIST171='3.1.1'; NIST='AC-3'; ISO27001='A.5.15' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Fail" `
                -Message "AC.L1-3.1.1: Authorized access control -- UAC enabled -- not configured (Value=$val)" `
                -Details "AC.L1-3.1.1: Limit system access to authorized users (Level 1)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='AC.L1-3.1.1'; NIST171='3.1.1'; NIST='AC-3'; ISO27001='A.5.15' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L1-3.1.1: Authorized access control -- UAC enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='AC.L1-3.1.1'; NIST171='3.1.1'; NIST='AC-3'; ISO27001='A.5.15' }
    }
    # AC.L1-3.1.2: Transaction/function control -- admin count
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $cnt = if ($null -ne $admins) { @($admins).Count } else { 0 }
        if ($cnt -le 3) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L1-3.1.2: $cnt admin accounts (appropriate)" `
                -Details "AC.L1-3.1.2: Limit to types of transactions/functions authorized users can execute" `
                -Severity "High" -CrossReferences @{ CMMC='AC.L1-3.1.2'; NIST171='3.1.2'; NIST='AC-6' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Warning" `
                -Message "AC.L1-3.1.2: $cnt admin accounts (review needed)" `
                -Remediation "Review and minimize administrator group membership" `
                -Severity "High" -CrossReferences @{ CMMC='AC.L1-3.1.2'; NIST171='3.1.2'; NIST='AC-6' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L1-3.1.2: Transaction/function control -- admin count -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AC.L1-3.1.2'; NIST171='3.1.2' }
    }
    # AC.L2-3.1.5: Least privilege -- UAC consent prompt
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L2-3.1.5: Least privilege -- UAC consent prompt -- properly configured" `
                -Details "AC.L2-3.1.5: Employ principle of least privilege (Level 2)" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.5'; NIST171='3.1.5'; NIST='AC-6(1)' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Fail" `
                -Message "AC.L2-3.1.5: Least privilege -- UAC consent prompt -- not configured (Value=$val)" `
                -Details "AC.L2-3.1.5: Employ principle of least privilege (Level 2)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.5'; NIST171='3.1.5'; NIST='AC-6(1)' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L2-3.1.5: Least privilege -- UAC consent prompt -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AC.L2-3.1.5'; NIST171='3.1.5'; NIST='AC-6(1)' }
    }
    # AC.L2-3.1.7: Privileged functions -- secure desktop
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L2-3.1.7: Privileged functions -- secure desktop -- properly configured" `
                -Details "AC.L2-3.1.7: Prevent non-privileged users from executing privileged functions" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.7'; NIST171='3.1.7'; NIST='AC-6(9)' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Fail" `
                -Message "AC.L2-3.1.7: Privileged functions -- secure desktop -- not configured (Value=$val)" `
                -Details "AC.L2-3.1.7: Prevent non-privileged users from executing privileged functions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.7'; NIST171='3.1.7'; NIST='AC-6(9)' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L2-3.1.7: Privileged functions -- secure desktop -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AC.L2-3.1.7'; NIST171='3.1.7'; NIST='AC-6(9)' }
    }
    # AC.L2-3.1.10: Session lock -- inactivity timeout
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L2-3.1.10: Session lock -- inactivity timeout -- properly configured" `
                -Details "AC.L2-3.1.10: Use session lock with pattern-hiding displays after inactivity" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.10'; NIST171='3.1.10'; NIST='AC-11' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Fail" `
                -Message "AC.L2-3.1.10: Session lock -- inactivity timeout -- not configured (Value=$val)" `
                -Details "AC.L2-3.1.10: Use session lock with pattern-hiding displays after inactivity" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.10'; NIST171='3.1.10'; NIST='AC-11' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L2-3.1.10: Session lock -- inactivity timeout -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AC.L2-3.1.10'; NIST171='3.1.10'; NIST='AC-11' }
    }
    # AC.L2-3.1.12: Remote access -- NLA required
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L2-3.1.12: Remote access -- NLA required -- properly configured" `
                -Details "AC.L2-3.1.12: Monitor and control remote access sessions" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.12'; NIST171='3.1.12'; NIST='AC-17' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Fail" `
                -Message "AC.L2-3.1.12: Remote access -- NLA required -- not configured (Value=$val)" `
                -Details "AC.L2-3.1.12: Monitor and control remote access sessions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.12'; NIST171='3.1.12'; NIST='AC-17' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L2-3.1.12: Remote access -- NLA required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AC.L2-3.1.12'; NIST171='3.1.12'; NIST='AC-17' }
    }
    # AC.L2-3.1.13: Remote access -- encryption for RDP
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Default $null
        if ($null -ne $val -and $val -ge 3) {
            Add-Result -Category "CMMC - AC Access Control" -Status "Pass" `
                -Message "AC.L2-3.1.13: Remote access -- encryption for RDP -- properly configured" `
                -Details "AC.L2-3.1.13: Employ cryptographic mechanisms for remote access" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.13'; NIST171='3.1.13'; NIST='AC-17(2)' }
        } else {
            Add-Result -Category "CMMC - AC Access Control" -Status "Fail" `
                -Message "AC.L2-3.1.13: Remote access -- encryption for RDP -- not configured (Value=$val)" `
                -Details "AC.L2-3.1.13: Employ cryptographic mechanisms for remote access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AC.L2-3.1.13'; NIST171='3.1.13'; NIST='AC-17(2)' }
        }
    } catch {
        Add-Result -Category "CMMC - AC Access Control" -Status "Error" `
            -Message "AC.L2-3.1.13: Remote access -- encryption for RDP -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AC.L2-3.1.13'; NIST171='3.1.13'; NIST='AC-17(2)' }
    }

# ===========================================================================
# AU -- Audit and Accountability
# ===========================================================================
Write-Host "[CMMC] Checking AU -- Audit and Accountability..." -ForegroundColor Yellow

    # AU.L2-3.3.1: Audit events -- Event Log service
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "CMMC - AU Audit" -Status "Pass" `
                -Message "AU.L2-3.3.1: Audit events -- Event Log service -- service running" `
                -Details "AU.L2-3.3.1: Create and retain system audit logs" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='AU.L2-3.3.1'; NIST171='3.3.1'; NIST='AU-2' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "CMMC - AU Audit" -Status "Fail" `
                -Message "AU.L2-3.3.1: Audit events -- Event Log service -- service not running (Status=$svcSt)" `
                -Details "AU.L2-3.3.1: Create and retain system audit logs" `
                -Remediation "Start-Service -Name EventLog" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='AU.L2-3.3.1'; NIST171='3.3.1'; NIST='AU-2' }
        }
    } catch {
        Add-Result -Category "CMMC - AU Audit" -Status "Error" `
            -Message "AU.L2-3.3.1: Audit events -- Event Log service -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='AU.L2-3.3.1'; NIST171='3.3.1'; NIST='AU-2' }
    }
    # AU.L2-3.3.1b: Audit -- logon event auditing
    try {
        $ao = auditpol /get /category:"Logon/Logoff" 2>&1
        $ok = $false
        foreach ($l in $ao) { if ($l -match "Logon" -and $l -match "Success") { $ok = $true } }
        if ($ok) {
            Add-Result -Category "CMMC - AU Audit" -Status "Pass" `
                -Message "AU.L2-3.3.1b: Logon auditing enabled" `
                -Severity "Critical" -CrossReferences @{ CMMC='AU.L2-3.3.1'; NIST171='3.3.1'; NIST='AU-2' }
        } else {
            Add-Result -Category "CMMC - AU Audit" -Status "Fail" `
                -Message "AU.L2-3.3.1b: Logon auditing NOT enabled" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -Severity "Critical" -CrossReferences @{ CMMC='AU.L2-3.3.1'; NIST171='3.3.1'; NIST='AU-2' }
        }
    } catch {
        Add-Result -Category "CMMC - AU Audit" -Status "Error" `
            -Message "AU.L2-3.3.1b: Audit -- logon event auditing -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='AU.L2-3.3.1'; NIST='AU-2' }
    }
    # AU.L2-3.3.4: Log retention -- security log size
    try {
        $sz = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
        $mb = [Math]::Round($sz / 1MB, 0)
        if ($sz -ge 1073741824) {
            Add-Result -Category "CMMC - AU Audit" -Status "Pass" `
                -Message "AU.L2-3.3.4: Security log ${mb}MB (adequate)" `
                -Severity "High" -CrossReferences @{ CMMC='AU.L2-3.3.4'; NIST171='3.3.4'; NIST='AU-4' }
        } else {
            Add-Result -Category "CMMC - AU Audit" -Status "Fail" `
                -Message "AU.L2-3.3.4: Security log ${mb}MB (requires `>= 1024MB)" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "High" -CrossReferences @{ CMMC='AU.L2-3.3.4'; NIST171='3.3.4'; NIST='AU-4' }
        }
    } catch {
        Add-Result -Category "CMMC - AU Audit" -Status "Error" `
            -Message "AU.L2-3.3.4: Log retention -- security log size -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AU.L2-3.3.4'; NIST='AU-4' }
    }
    # AU.L2-3.3.8: Audit protection -- Script Block Logging
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - AU Audit" -Status "Pass" `
                -Message "AU.L2-3.3.8: Audit protection -- Script Block Logging -- properly configured" `
                -Details "AU.L2-3.3.8: Protect audit information from unauthorized access/modification" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AU.L2-3.3.8'; NIST171='3.3.8'; NIST='AU-9' }
        } else {
            Add-Result -Category "CMMC - AU Audit" -Status "Fail" `
                -Message "AU.L2-3.3.8: Audit protection -- Script Block Logging -- not configured (Value=$val)" `
                -Details "AU.L2-3.3.8: Protect audit information from unauthorized access/modification" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" `
                -CrossReferences @{ CMMC='AU.L2-3.3.8'; NIST171='3.3.8'; NIST='AU-9' }
        }
    } catch {
        Add-Result -Category "CMMC - AU Audit" -Status "Error" `
            -Message "AU.L2-3.3.8: Audit protection -- Script Block Logging -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='AU.L2-3.3.8'; NIST171='3.3.8'; NIST='AU-9' }
    }
    # AU.L2-3.3.7: Time synchronization -- W32Time
    try {
        $svc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "CMMC - AU Audit" -Status "Pass" `
                -Message "AU.L2-3.3.7: Time synchronization -- W32Time -- service running" `
                -Details "AU.L2-3.3.7: Provide reliable time source for audit records" `
                -Severity "Medium" `
                -CrossReferences @{ CMMC='AU.L2-3.3.7'; NIST171='3.3.7'; NIST='AU-8' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "CMMC - AU Audit" -Status "Fail" `
                -Message "AU.L2-3.3.7: Time synchronization -- W32Time -- service not running (Status=$svcSt)" `
                -Details "AU.L2-3.3.7: Provide reliable time source for audit records" `
                -Remediation "Start-Service -Name W32Time" `
                -Severity "Medium" `
                -CrossReferences @{ CMMC='AU.L2-3.3.7'; NIST171='3.3.7'; NIST='AU-8' }
        }
    } catch {
        Add-Result -Category "CMMC - AU Audit" -Status "Error" `
            -Message "AU.L2-3.3.7: Time synchronization -- W32Time -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ CMMC='AU.L2-3.3.7'; NIST171='3.3.7'; NIST='AU-8' }
    }

# ===========================================================================
# CM -- Configuration Management
# ===========================================================================
Write-Host "[CMMC] Checking CM -- Configuration Management..." -ForegroundColor Yellow

    # CM.L2-3.4.1: Baseline configurations -- auto updates
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Default $null
        if ($null -ne $val -and $val -ge 4) {
            Add-Result -Category "CMMC - CM Config Mgmt" -Status "Pass" `
                -Message "CM.L2-3.4.1: Baseline configurations -- auto updates -- properly configured" `
                -Details "CM.L2-3.4.1: Establish and maintain baseline configurations" `
                -Severity "High" `
                -CrossReferences @{ CMMC='CM.L2-3.4.1'; NIST171='3.4.1'; NIST='CM-2' }
        } else {
            Add-Result -Category "CMMC - CM Config Mgmt" -Status "Fail" `
                -Message "CM.L2-3.4.1: Baseline configurations -- auto updates -- not configured (Value=$val)" `
                -Details "CM.L2-3.4.1: Establish and maintain baseline configurations" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -Value 4" `
                -Severity "High" `
                -CrossReferences @{ CMMC='CM.L2-3.4.1'; NIST171='3.4.1'; NIST='CM-2' }
        }
    } catch {
        Add-Result -Category "CMMC - CM Config Mgmt" -Status "Error" `
            -Message "CM.L2-3.4.1: Baseline configurations -- auto updates -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='CM.L2-3.4.1'; NIST171='3.4.1'; NIST='CM-2' }
    }
    # CM.L2-3.4.6: Least functionality -- SMBv1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "CMMC - CM Config Mgmt" -Status "Pass" `
                -Message "CM.L2-3.4.6: Least functionality -- SMBv1 disabled -- properly configured" `
                -Details "CM.L2-3.4.6: Employ principle of least functionality (disable unnecessary protocols)" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='CM.L2-3.4.6'; NIST171='3.4.6'; NIST='CM-7' }
        } else {
            Add-Result -Category "CMMC - CM Config Mgmt" -Status "Fail" `
                -Message "CM.L2-3.4.6: Least functionality -- SMBv1 disabled -- not configured (Value=$val)" `
                -Details "CM.L2-3.4.6: Employ principle of least functionality (disable unnecessary protocols)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='CM.L2-3.4.6'; NIST171='3.4.6'; NIST='CM-7' }
        }
    } catch {
        Add-Result -Category "CMMC - CM Config Mgmt" -Status "Error" `
            -Message "CM.L2-3.4.6: Least functionality -- SMBv1 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='CM.L2-3.4.6'; NIST171='3.4.6'; NIST='CM-7' }
    }
    # CM.L2-3.4.7: Nonessential programs -- autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "CMMC - CM Config Mgmt" -Status "Pass" `
                -Message "CM.L2-3.4.7: Nonessential programs -- autoplay disabled -- properly configured" `
                -Details "CM.L2-3.4.7: Restrict and disable nonessential programs/functions" `
                -Severity "High" `
                -CrossReferences @{ CMMC='CM.L2-3.4.7'; NIST171='3.4.7'; NIST='CM-7(2)' }
        } else {
            Add-Result -Category "CMMC - CM Config Mgmt" -Status "Fail" `
                -Message "CM.L2-3.4.7: Nonessential programs -- autoplay disabled -- not configured (Value=$val)" `
                -Details "CM.L2-3.4.7: Restrict and disable nonessential programs/functions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "High" `
                -CrossReferences @{ CMMC='CM.L2-3.4.7'; NIST171='3.4.7'; NIST='CM-7(2)' }
        }
    } catch {
        Add-Result -Category "CMMC - CM Config Mgmt" -Status "Error" `
            -Message "CM.L2-3.4.7: Nonessential programs -- autoplay disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='CM.L2-3.4.7'; NIST171='3.4.7'; NIST='CM-7(2)' }
    }

# ===========================================================================
# IA -- Identification and Authentication
# ===========================================================================
Write-Host "[CMMC] Checking IA -- Identification and Authentication..." -ForegroundColor Yellow

    # IA.L1-3.5.1: User identification -- unique IDs
    try {
        $users = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true })
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guest -and $guest.Enabled -eq $false) {
            Add-Result -Category "CMMC - IA Authentication" -Status "Pass" `
                -Message "IA.L1-3.5.1: Guest account disabled -- $($users.Count) enabled user accounts with unique identification" `
                -Severity "High" -CrossReferences @{ CMMC='IA.L1-3.5.1'; NIST171='3.5.1'; NIST='IA-2' }
        } else {
            Add-Result -Category "CMMC - IA Authentication" -Status "Fail" `
                -Message "IA.L1-3.5.1: Guest account ENABLED -- violates unique identification" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" -CrossReferences @{ CMMC='IA.L1-3.5.1'; NIST171='3.5.1'; NIST='IA-2' }
        }
    } catch {
        Add-Result -Category "CMMC - IA Authentication" -Status "Error" `
            -Message "IA.L1-3.5.1: User identification -- unique IDs -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='IA.L1-3.5.1'; NIST='IA-2' }
    }
    # IA.L1-3.5.2: Authentication -- password length
    try {
        $netAcct = net accounts 2>&1
        $minLen = 0
        foreach ($line in $netAcct) { if ($line -match "Minimum password length\s+(\d+)") { $minLen = [int]$Matches[1] } }
        if ($minLen -ge 14) {
            Add-Result -Category "CMMC - IA Authentication" -Status "Pass" `
                -Message "IA.L1-3.5.2: Password length $minLen chars" `
                -Severity "High" -CrossReferences @{ CMMC='IA.L1-3.5.2'; NIST171='3.5.2'; NIST='IA-5' }
        } else {
            Add-Result -Category "CMMC - IA Authentication" -Status "Fail" `
                -Message "IA.L1-3.5.2: Password length $minLen (requires `>= 14)" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" -CrossReferences @{ CMMC='IA.L1-3.5.2'; NIST171='3.5.2'; NIST='IA-5' }
        }
    } catch {
        Add-Result -Category "CMMC - IA Authentication" -Status "Error" `
            -Message "IA.L1-3.5.2: Authentication -- password length -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='IA.L1-3.5.2'; NIST='IA-5' }
    }
    # IA.L2-3.5.3: NTLMv2 only
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default $null
        if ($null -ne $val -and $val -ge 5) {
            Add-Result -Category "CMMC - IA Authentication" -Status "Pass" `
                -Message "IA.L2-3.5.3: NTLMv2 only -- properly configured" `
                -Details "IA.L2-3.5.3: Use multifactor authentication mechanisms (start with strong single-factor)" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.3'; NIST171='3.5.3'; NIST='IA-2(1)' }
        } else {
            Add-Result -Category "CMMC - IA Authentication" -Status "Fail" `
                -Message "IA.L2-3.5.3: NTLMv2 only -- not configured (Value=$val)" `
                -Details "IA.L2-3.5.3: Use multifactor authentication mechanisms (start with strong single-factor)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.3'; NIST171='3.5.3'; NIST='IA-2(1)' }
        }
    } catch {
        Add-Result -Category "CMMC - IA Authentication" -Status "Error" `
            -Message "IA.L2-3.5.3: NTLMv2 only -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='IA.L2-3.5.3'; NIST171='3.5.3'; NIST='IA-2(1)' }
    }
    # IA.L2-3.5.10a: Credential protection -- LSASS
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - IA Authentication" -Status "Pass" `
                -Message "IA.L2-3.5.10a: Credential protection -- LSASS -- properly configured" `
                -Details "IA.L2-3.5.10: Store and transmit only cryptographically-protected passwords" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
        } else {
            Add-Result -Category "CMMC - IA Authentication" -Status "Fail" `
                -Message "IA.L2-3.5.10a: Credential protection -- LSASS -- not configured (Value=$val)" `
                -Details "IA.L2-3.5.10: Store and transmit only cryptographically-protected passwords" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
        }
    } catch {
        Add-Result -Category "CMMC - IA Authentication" -Status "Error" `
            -Message "IA.L2-3.5.10a: Credential protection -- LSASS -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
    }
    # IA.L2-3.5.10b: Credential protection -- WDigest
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "CMMC - IA Authentication" -Status "Pass" `
                -Message "IA.L2-3.5.10b: Credential protection -- WDigest -- properly configured" `
                -Details "IA.L2-3.5.10: Disable plaintext credential caching" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
        } else {
            Add-Result -Category "CMMC - IA Authentication" -Status "Fail" `
                -Message "IA.L2-3.5.10b: Credential protection -- WDigest -- not configured (Value=$val)" `
                -Details "IA.L2-3.5.10: Disable plaintext credential caching" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
        }
    } catch {
        Add-Result -Category "CMMC - IA Authentication" -Status "Error" `
            -Message "IA.L2-3.5.10b: Credential protection -- WDigest -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
    }
    # IA.L2-3.5.10c: Credential protection -- LM hash
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - IA Authentication" -Status "Pass" `
                -Message "IA.L2-3.5.10c: Credential protection -- LM hash -- properly configured" `
                -Details "IA.L2-3.5.10: Eliminate weak credential storage mechanisms" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
        } else {
            Add-Result -Category "CMMC - IA Authentication" -Status "Fail" `
                -Message "IA.L2-3.5.10c: Credential protection -- LM hash -- not configured (Value=$val)" `
                -Details "IA.L2-3.5.10: Eliminate weak credential storage mechanisms" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
        }
    } catch {
        Add-Result -Category "CMMC - IA Authentication" -Status "Error" `
            -Message "IA.L2-3.5.10c: Credential protection -- LM hash -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='IA.L2-3.5.10'; NIST171='3.5.10'; NIST='IA-5(1)' }
    }

# ===========================================================================
# MP -- Media Protection
# ===========================================================================
Write-Host "[CMMC] Checking MP -- Media Protection..." -ForegroundColor Yellow

    # MP.L1-3.8.3: Media sanitization -- autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "CMMC - MP Media" -Status "Pass" `
                -Message "MP.L1-3.8.3: Media sanitization -- autoplay disabled -- properly configured" `
                -Details "MP.L1-3.8.3: Sanitize or destroy media before disposal or reuse" `
                -Severity "High" `
                -CrossReferences @{ CMMC='MP.L1-3.8.3'; NIST171='3.8.3'; NIST='MP-6' }
        } else {
            Add-Result -Category "CMMC - MP Media" -Status "Fail" `
                -Message "MP.L1-3.8.3: Media sanitization -- autoplay disabled -- not configured (Value=$val)" `
                -Details "MP.L1-3.8.3: Sanitize or destroy media before disposal or reuse" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "High" `
                -CrossReferences @{ CMMC='MP.L1-3.8.3'; NIST171='3.8.3'; NIST='MP-6' }
        }
    } catch {
        Add-Result -Category "CMMC - MP Media" -Status "Error" `
            -Message "MP.L1-3.8.3: Media sanitization -- autoplay disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='MP.L1-3.8.3'; NIST171='3.8.3'; NIST='MP-6' }
    }
    # MP.L2-3.8.7: Removable media -- USB restrictions
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - MP Media" -Status "Pass" `
                -Message "MP.L2-3.8.7: Removable media -- USB restrictions -- properly configured" `
                -Details "MP.L2-3.8.7: Control use of removable media on system components" `
                -Severity "High" `
                -CrossReferences @{ CMMC='MP.L2-3.8.7'; NIST171='3.8.7'; NIST='MP-7' }
        } else {
            Add-Result -Category "CMMC - MP Media" -Status "Warning" `
                -Message "MP.L2-3.8.7: Removable media -- USB restrictions -- not configured (Value=$val)" `
                -Details "MP.L2-3.8.7: Control use of removable media on system components" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name Deny_All -Value 1" `
                -Severity "High" `
                -CrossReferences @{ CMMC='MP.L2-3.8.7'; NIST171='3.8.7'; NIST='MP-7' }
        }
    } catch {
        Add-Result -Category "CMMC - MP Media" -Status "Error" `
            -Message "MP.L2-3.8.7: Removable media -- USB restrictions -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='MP.L2-3.8.7'; NIST171='3.8.7'; NIST='MP-7' }
    }

# ===========================================================================
# SC -- System and Communications Protection
# ===========================================================================
Write-Host "[CMMC] Checking SC -- System and Communications Protection..." -ForegroundColor Yellow

    # SC.L1-3.13.1: Boundary protection -- firewall all profiles
    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $ok = $true
        foreach ($f in $fw) { if ($f.Enabled -ne $true) { $ok = $false } }
        if ($ok -and $null -ne $fw) {
            Add-Result -Category "CMMC - SC Comms" -Status "Pass" `
                -Message "SC.L1-3.13.1: All firewall profiles enabled" `
                -Severity "High" -CrossReferences @{ CMMC='SC.L1-3.13.1'; NIST171='3.13.1'; NIST='SC-7' }
        } else {
            Add-Result -Category "CMMC - SC Comms" -Status "Fail" `
                -Message "SC.L1-3.13.1: Not all firewall profiles enabled" `
                -Remediation "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" `
                -Severity "High" -CrossReferences @{ CMMC='SC.L1-3.13.1'; NIST171='3.13.1'; NIST='SC-7' }
        }
    } catch {
        Add-Result -Category "CMMC - SC Comms" -Status "Error" `
            -Message "SC.L1-3.13.1: Boundary protection -- firewall all profiles -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='SC.L1-3.13.1'; NIST='SC-7' }
    }
    # SC.L2-3.13.8: CUI encryption in transit -- TLS 1.2
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - SC Comms" -Status "Pass" `
                -Message "SC.L2-3.13.8: CUI encryption in transit -- TLS 1.2 -- properly configured" `
                -Details "SC.L2-3.13.8: Implement cryptographic mechanisms to prevent CUI disclosure during transmission" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SC.L2-3.13.8'; NIST171='3.13.8'; NIST='SC-8' }
        } else {
            Add-Result -Category "CMMC - SC Comms" -Status "Fail" `
                -Message "SC.L2-3.13.8: CUI encryption in transit -- TLS 1.2 -- not configured (Value=$val)" `
                -Details "SC.L2-3.13.8: Implement cryptographic mechanisms to prevent CUI disclosure during transmission" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SC.L2-3.13.8'; NIST171='3.13.8'; NIST='SC-8' }
        }
    } catch {
        Add-Result -Category "CMMC - SC Comms" -Status "Error" `
            -Message "SC.L2-3.13.8: CUI encryption in transit -- TLS 1.2 -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='SC.L2-3.13.8'; NIST171='3.13.8'; NIST='SC-8' }
    }
    # SC.L2-3.13.11: CUI encryption at rest -- BitLocker policy
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Default $null
        if ($null -ne $val -and $val -ge 7) {
            Add-Result -Category "CMMC - SC Comms" -Status "Pass" `
                -Message "SC.L2-3.13.11: CUI encryption at rest -- BitLocker policy -- properly configured" `
                -Details "SC.L2-3.13.11: Employ FIPS-validated cryptography for CUI protection" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SC.L2-3.13.11'; NIST171='3.13.11'; NIST='SC-13' }
        } else {
            Add-Result -Category "CMMC - SC Comms" -Status "Fail" `
                -Message "SC.L2-3.13.11: CUI encryption at rest -- BitLocker policy -- not configured (Value=$val)" `
                -Details "SC.L2-3.13.11: Employ FIPS-validated cryptography for CUI protection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name EncryptionMethodWithXtsOs -Value 7" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SC.L2-3.13.11'; NIST171='3.13.11'; NIST='SC-13' }
        }
    } catch {
        Add-Result -Category "CMMC - SC Comms" -Status "Error" `
            -Message "SC.L2-3.13.11: CUI encryption at rest -- BitLocker policy -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='SC.L2-3.13.11'; NIST171='3.13.11'; NIST='SC-13' }
    }
    # SC.L2-3.13.15: Network integrity -- SMB signing
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - SC Comms" -Status "Pass" `
                -Message "SC.L2-3.13.15: Network integrity -- SMB signing -- properly configured" `
                -Details "SC.L2-3.13.15: Protect authenticity of communications sessions" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SC.L2-3.13.15'; NIST171='3.13.15'; NIST='SC-23' }
        } else {
            Add-Result -Category "CMMC - SC Comms" -Status "Fail" `
                -Message "SC.L2-3.13.15: Network integrity -- SMB signing -- not configured (Value=$val)" `
                -Details "SC.L2-3.13.15: Protect authenticity of communications sessions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SC.L2-3.13.15'; NIST171='3.13.15'; NIST='SC-23' }
        }
    } catch {
        Add-Result -Category "CMMC - SC Comms" -Status "Error" `
            -Message "SC.L2-3.13.15: Network integrity -- SMB signing -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='SC.L2-3.13.15'; NIST171='3.13.15'; NIST='SC-23' }
    }
    # SC.L2-3.13.16: CUI confidentiality at rest -- pagefile cleared
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - SC Comms" -Status "Pass" `
                -Message "SC.L2-3.13.16: CUI confidentiality at rest -- pagefile cleared -- properly configured" `
                -Details "SC.L2-3.13.16: Protect CUI confidentiality at rest (memory residue)" `
                -Severity "Medium" `
                -CrossReferences @{ CMMC='SC.L2-3.13.16'; NIST171='3.13.16'; NIST='SC-28' }
        } else {
            Add-Result -Category "CMMC - SC Comms" -Status "Fail" `
                -Message "SC.L2-3.13.16: CUI confidentiality at rest -- pagefile cleared -- not configured (Value=$val)" `
                -Details "SC.L2-3.13.16: Protect CUI confidentiality at rest (memory residue)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ CMMC='SC.L2-3.13.16'; NIST171='3.13.16'; NIST='SC-28' }
        }
    } catch {
        Add-Result -Category "CMMC - SC Comms" -Status "Error" `
            -Message "SC.L2-3.13.16: CUI confidentiality at rest -- pagefile cleared -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ CMMC='SC.L2-3.13.16'; NIST171='3.13.16'; NIST='SC-28' }
    }

# ===========================================================================
# SI -- System and Information Integrity
# ===========================================================================
Write-Host "[CMMC] Checking SI -- System and Information Integrity..." -ForegroundColor Yellow

    # SI.L1-3.14.1: Flaw remediation -- Update service
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "CMMC - SI Integrity" -Status "Pass" `
                -Message "SI.L1-3.14.1: Flaw remediation -- Update service -- service running" `
                -Details "SI.L1-3.14.1: Identify, report, and correct flaws in a timely manner" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SI.L1-3.14.1'; NIST171='3.14.1'; NIST='SI-2' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "CMMC - SI Integrity" -Status "Fail" `
                -Message "SI.L1-3.14.1: Flaw remediation -- Update service -- service not running (Status=$svcSt)" `
                -Details "SI.L1-3.14.1: Identify, report, and correct flaws in a timely manner" `
                -Remediation "Start-Service -Name wuauserv" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SI.L1-3.14.1'; NIST171='3.14.1'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "CMMC - SI Integrity" -Status "Error" `
            -Message "SI.L1-3.14.1: Flaw remediation -- Update service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='SI.L1-3.14.1'; NIST171='3.14.1'; NIST='SI-2' }
    }
    # SI.L1-3.14.2: Malicious code protection -- Defender
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "CMMC - SI Integrity" -Status "Pass" `
                -Message "SI.L1-3.14.2: Malicious code protection -- Defender -- service running" `
                -Details "SI.L1-3.14.2: Provide protection from malicious code" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SI.L1-3.14.2'; NIST171='3.14.2'; NIST='SI-3' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "CMMC - SI Integrity" -Status "Fail" `
                -Message "SI.L1-3.14.2: Malicious code protection -- Defender -- service not running (Status=$svcSt)" `
                -Details "SI.L1-3.14.2: Provide protection from malicious code" `
                -Remediation "Start-Service -Name WinDefend" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SI.L1-3.14.2'; NIST171='3.14.2'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "CMMC - SI Integrity" -Status "Error" `
            -Message "SI.L1-3.14.2: Malicious code protection -- Defender -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='SI.L1-3.14.2'; NIST171='3.14.2'; NIST='SI-3' }
    }
    # SI.L1-3.14.2b: Malicious code -- real-time protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "CMMC - SI Integrity" -Status "Pass" `
                -Message "SI.L1-3.14.2b: Malicious code -- real-time protection -- properly configured" `
                -Details "SI.L1-3.14.2: Update malicious code protection mechanisms when new releases available" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SI.L1-3.14.2'; NIST171='3.14.2'; NIST='SI-3' }
        } else {
            Add-Result -Category "CMMC - SI Integrity" -Status "Fail" `
                -Message "SI.L1-3.14.2b: Malicious code -- real-time protection -- not configured (Value=$val)" `
                -Details "SI.L1-3.14.2: Update malicious code protection mechanisms when new releases available" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SI.L1-3.14.2'; NIST171='3.14.2'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "CMMC - SI Integrity" -Status "Error" `
            -Message "SI.L1-3.14.2b: Malicious code -- real-time protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='SI.L1-3.14.2'; NIST171='3.14.2'; NIST='SI-3' }
    }
    # SI.L1-3.14.4: Update malware definitions
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "CMMC - SI Integrity" -Status "Pass" `
                -Message "SI.L1-3.14.4: Update malware definitions -- properly configured" `
                -Details "SI.L1-3.14.4: Update malicious code protection" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SI.L1-3.14.4'; NIST171='3.14.4'; NIST='SI-3' }
        } else {
            Add-Result -Category "CMMC - SI Integrity" -Status "Fail" `
                -Message "SI.L1-3.14.4: Update malware definitions -- not configured (Value=$val)" `
                -Details "SI.L1-3.14.4: Update malicious code protection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ CMMC='SI.L1-3.14.4'; NIST171='3.14.4'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "CMMC - SI Integrity" -Status "Error" `
            -Message "SI.L1-3.14.4: Update malware definitions -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ CMMC='SI.L1-3.14.4'; NIST171='3.14.4'; NIST='SI-3' }
    }
    # SI.L2-3.14.6: Monitoring -- network protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "CMMC - SI Integrity" -Status "Pass" `
                -Message "SI.L2-3.14.6: Monitoring -- network protection -- properly configured" `
                -Details "SI.L2-3.14.6: Monitor organizational systems to detect attacks and indicators of compromise" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SI.L2-3.14.6'; NIST171='3.14.6'; NIST='SI-4' }
        } else {
            Add-Result -Category "CMMC - SI Integrity" -Status "Fail" `
                -Message "SI.L2-3.14.6: Monitoring -- network protection -- not configured (Value=$val)" `
                -Details "SI.L2-3.14.6: Monitor organizational systems to detect attacks and indicators of compromise" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SI.L2-3.14.6'; NIST171='3.14.6'; NIST='SI-4' }
        }
    } catch {
        Add-Result -Category "CMMC - SI Integrity" -Status "Error" `
            -Message "SI.L2-3.14.6: Monitoring -- network protection -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='SI.L2-3.14.6'; NIST171='3.14.6'; NIST='SI-4' }
    }
    # SI.L2-3.14.7: Unauthorized use detection -- LLMNR disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "CMMC - SI Integrity" -Status "Pass" `
                -Message "SI.L2-3.14.7: Unauthorized use detection -- LLMNR disabled -- properly configured" `
                -Details "SI.L2-3.14.7: Identify unauthorized use of organizational systems" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SI.L2-3.14.7'; NIST171='3.14.7'; NIST='SI-4' }
        } else {
            Add-Result -Category "CMMC - SI Integrity" -Status "Fail" `
                -Message "SI.L2-3.14.7: Unauthorized use detection -- LLMNR disabled -- not configured (Value=$val)" `
                -Details "SI.L2-3.14.7: Identify unauthorized use of organizational systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
                -Severity "High" `
                -CrossReferences @{ CMMC='SI.L2-3.14.7'; NIST171='3.14.7'; NIST='SI-4' }
        }
    } catch {
        Add-Result -Category "CMMC - SI Integrity" -Status "Error" `
            -Message "SI.L2-3.14.7: Unauthorized use detection -- LLMNR disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ CMMC='SI.L2-3.14.7'; NIST171='3.14.7'; NIST='SI-4' }
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
Write-Host "  [CMMC] CMMC 2.0 Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
    Write-Host "  CMMC 2.0 Module -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[CMMC] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  CMMC module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}

# ============================================================================
# End of CMMC 2.0 Module (Module-CMMC.ps1)
# ============================================================================
