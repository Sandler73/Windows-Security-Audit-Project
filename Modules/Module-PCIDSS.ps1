# module-pcidss.ps1
# PCI DSS v4.0 Compliance Module for Windows Security Audit
# Version: 6.1.2
#
# Evaluates Windows configuration against Payment Card Industry Data Security Standard v4.0
# with Severity ratings and cross-framework references.

<#
.SYNOPSIS
    PCI DSS v4.0 compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with Payment Card Industry Data Security Standard v4.0 including:
    - Req 1: Network Security Controls (firewall, segmentation, traffic rules)
    - Req 2: Secure Configuration (vendor defaults, system hardening, services)
    - Req 3: Protect Stored Account Data (encryption at rest, key management)
    - Req 4: Strong Cryptography in Transit (TLS, cipher suites, certificate validation)
    - Req 5: Protect Against Malware (antivirus, behavioral analysis, ASR)
    - Req 6: Secure Systems and Software (patching, change control, vulnerability mgmt)
    - Req 7: Restrict Access by Business Need (RBAC, least privilege, authorization)
    - Req 8: Identify Users and Authenticate (passwords, MFA, session controls)
    - Req 10: Log and Monitor All Access (audit trails, NTP, log integrity, SIEM)
    - Req 11: Test Security Regularly (vulnerability scanning readiness, IDS/IPS)
    - Req 12: Organizational Policies (incident response readiness, awareness)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: PCI DSS v4.0 (March 2022), PCI SSC Quick Reference Guide
    Version: 6.1.2

.EXAMPLE
    $results = & .\modules\module-pcidss.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "PCI-DSS"
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

Write-Host "`n[$moduleName] Starting PCI DSS v4.0 compliance checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# Req 1 -- Network Security Controls
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 1 -- Network Security Controls..." -ForegroundColor Yellow

    # 1.2.1a: Firewall enabled -- Domain profile
    try {
        $fwDomain = Get-NetFirewallProfile -Profile Domain -ErrorAction SilentlyContinue
        if ($null -ne $fwDomain -and $fwDomain.Enabled -eq $true) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.2.1a: Windows Firewall enabled on Domain profile" `
                -Details "Req 1.2.1: Network security controls must be active on all network interfaces" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7'; ISO27001='A.8.20'; CIS='9.1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.2.1a: Windows Firewall DISABLED on Domain profile" `
                -Details "Req 1.2.1: Firewall must be enabled to control inbound/outbound traffic" `
                -Remediation "Set-NetFirewallProfile -Profile Domain -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7'; ISO27001='A.8.20'; CIS='9.1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.2.1a: Firewall enabled -- Domain profile -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7' }
    }
    # 1.2.1b: Firewall enabled -- Private profile
    try {
        $fwPrivate = Get-NetFirewallProfile -Profile Private -ErrorAction SilentlyContinue
        if ($null -ne $fwPrivate -and $fwPrivate.Enabled -eq $true) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.2.1b: Windows Firewall enabled on Private profile" `
                -Details "Req 1.2.1: All firewall profiles must be active for CDE protection" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7'; CIS='9.2.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.2.1b: Windows Firewall DISABLED on Private profile" `
                -Details "Req 1.2.1: Firewall must be enabled on all profiles protecting CDE" `
                -Remediation "Set-NetFirewallProfile -Profile Private -Enabled True" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7'; CIS='9.2.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.2.1b: Firewall enabled -- Private profile -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7' }
    }
    # 1.2.1c: Firewall enabled -- Public profile
    try {
        $fwPublic = Get-NetFirewallProfile -Profile Public -ErrorAction SilentlyContinue
        if ($null -ne $fwPublic -and $fwPublic.Enabled -eq $true) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.2.1c: Windows Firewall enabled on Public profile" `
                -Details "Req 1.2.1: Public profile is critical boundary between CDE and untrusted networks" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7'; CIS='9.3.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.2.1c: Windows Firewall DISABLED on Public profile" `
                -Details "Req 1.2.1: Public facing systems must have firewall enabled" `
                -Remediation "Set-NetFirewallProfile -Profile Public -Enabled True" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7'; CIS='9.3.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.2.1c: Firewall enabled -- Public profile -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7' }
    }
    # 1.2.1d: Default inbound action -- Domain (Block)
    try {
        $fwDomain = Get-NetFirewallProfile -Profile Domain -ErrorAction SilentlyContinue
        if ($null -ne $fwDomain -and $fwDomain.DefaultInboundAction -eq "Block") {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.2.1d: Domain profile default inbound action is Block" `
                -Details "Req 1.2.1: Default-deny inbound reduces attack surface" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7(5)'; CIS='9.1.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.2.1d: Domain profile default inbound action is NOT Block" `
                -Details "Req 1.2.1: Default-deny posture required for CDE protection" `
                -Remediation "Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7(5)'; CIS='9.1.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.2.1d: Default inbound action -- Domain (Block) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7(5)' }
    }
    # 1.2.1e: Default inbound action -- Public (Block)
    try {
        $fwPublic = Get-NetFirewallProfile -Profile Public -ErrorAction SilentlyContinue
        if ($null -ne $fwPublic -and $fwPublic.DefaultInboundAction -eq "Block") {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.2.1e: Public profile default inbound action is Block" `
                -Details "Req 1.2.1: Public profile must default-deny all inbound connections" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7(5)'; CIS='9.3.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.2.1e: Public profile default inbound action is NOT Block" `
                -Details "Req 1.2.1: Untrusted networks must be blocked by default" `
                -Remediation "Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7(5)'; CIS='9.3.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.2.1e: Default inbound action -- Public (Block) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='1.2.1'; NIST='SC-7(5)' }
    }
    # 1.2.5: Network access control -- RDP disabled unless required
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.2.5: Network access control -- RDP disabled unless required -- properly configured" `
                -Details "Req 1.2.5: Unnecessary remote access services must be disabled in CDE" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.5'; NIST='AC-17'; CIS='18.9.65.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Warning" `
                -Message "1.2.5: Network access control -- RDP disabled unless required -- not configured (Value=$val)" `
                -Details "Req 1.2.5: Unnecessary remote access services must be disabled in CDE" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.2.5'; NIST='AC-17'; CIS='18.9.65.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.2.5: Network access control -- RDP disabled unless required -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.2.5'; NIST='AC-17'; CIS='18.9.65.1' }
    }
    # 1.3.1: Network traffic restriction -- SMBv1 disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.3.1: Network traffic restriction -- SMBv1 disabled -- properly configured" `
                -Details "Req 1.3.1: Insecure protocols must be disabled within CDE network segments" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='1.3.1'; NIST='CM-7'; ISO27001='A.8.9'; STIG='V-220968' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.3.1: Network traffic restriction -- SMBv1 disabled -- not configured (Value=$val)" `
                -Details "Req 1.3.1: Insecure protocols must be disabled within CDE network segments" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='1.3.1'; NIST='CM-7'; ISO27001='A.8.9'; STIG='V-220968' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.3.1: Network traffic restriction -- SMBv1 disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='1.3.1'; NIST='CM-7'; ISO27001='A.8.9'; STIG='V-220968' }
    }
    # 1.3.2: Network traffic restriction -- LLMNR disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.3.2: Network traffic restriction -- LLMNR disabled -- properly configured" `
                -Details "Req 1.3.2: LLMNR broadcast protocol enables network poisoning within CDE" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.3.2'; NIST='SC-20'; CIS='18.5.4.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.3.2: Network traffic restriction -- LLMNR disabled -- not configured (Value=$val)" `
                -Details "Req 1.3.2: LLMNR broadcast protocol enables network poisoning within CDE" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.3.2'; NIST='SC-20'; CIS='18.5.4.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.3.2: Network traffic restriction -- LLMNR disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.3.2'; NIST='SC-20'; CIS='18.5.4.2' }
    }
    # 1.3.3: Network traffic restriction -- IPv6 source routing disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.3.3: Network traffic restriction -- IPv6 source routing disabled -- properly configured" `
                -Details "Req 1.3.3: Source routing bypasses network segmentation controls" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='1.3.3'; NIST='SC-7'; CIS='18.4.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.3.3: Network traffic restriction -- IPv6 source routing disabled -- not configured (Value=$val)" `
                -Details "Req 1.3.3: Source routing bypasses network segmentation controls" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisableIPSourceRouting -Value 2" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='1.3.3'; NIST='SC-7'; CIS='18.4.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.3.3: Network traffic restriction -- IPv6 source routing disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='1.3.3'; NIST='SC-7'; CIS='18.4.2' }
    }
    # 1.3.4: Network traffic restriction -- IPv4 source routing disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.3.4: Network traffic restriction -- IPv4 source routing disabled -- properly configured" `
                -Details "Req 1.3.4: IP source routing allows attackers to specify packet routes" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='1.3.4'; NIST='SC-7'; CIS='18.4.3' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.3.4: Network traffic restriction -- IPv4 source routing disabled -- not configured (Value=$val)" `
                -Details "Req 1.3.4: IP source routing allows attackers to specify packet routes" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name DisableIPSourceRouting -Value 2" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='1.3.4'; NIST='SC-7'; CIS='18.4.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.3.4: Network traffic restriction -- IPv4 source routing disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='1.3.4'; NIST='SC-7'; CIS='18.4.3' }
    }
    # 1.3.5: Network traffic restriction -- ICMP redirects disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.3.5: Network traffic restriction -- ICMP redirects disabled -- properly configured" `
                -Details "Req 1.3.5: ICMP redirects can manipulate routing to bypass CDE boundaries" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='1.3.5'; NIST='SC-7'; CIS='18.4.4' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.3.5: Network traffic restriction -- ICMP redirects disabled -- not configured (Value=$val)" `
                -Details "Req 1.3.5: ICMP redirects can manipulate routing to bypass CDE boundaries" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name EnableICMPRedirect -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='1.3.5'; NIST='SC-7'; CIS='18.4.4' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.3.5: Network traffic restriction -- ICMP redirects disabled -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='1.3.5'; NIST='SC-7'; CIS='18.4.4' }
    }
    # 1.4.1: Network connections -- SMB signing required (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.4.1: Network connections -- SMB signing required (server) -- properly configured" `
                -Details "Req 1.4.1: SMB signing prevents man-in-the-middle within CDE network" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.4.1'; NIST='SC-8'; CIS='2.3.9.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.4.1: Network connections -- SMB signing required (server) -- not configured (Value=$val)" `
                -Details "Req 1.4.1: SMB signing prevents man-in-the-middle within CDE network" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.4.1'; NIST='SC-8'; CIS='2.3.9.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.4.1: Network connections -- SMB signing required (server) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.4.1'; NIST='SC-8'; CIS='2.3.9.2' }
    }
    # 1.4.2: Network connections -- SMB signing required (client)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Pass" `
                -Message "1.4.2: Network connections -- SMB signing required (client) -- properly configured" `
                -Details "Req 1.4.2: Client-side SMB signing prevents relay attacks targeting cardholder data" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.4.2'; NIST='SC-8'; CIS='2.3.9.5' }
        } else {
            Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Fail" `
                -Message "1.4.2: Network connections -- SMB signing required (client) -- not configured (Value=$val)" `
                -Details "Req 1.4.2: Client-side SMB signing prevents relay attacks targeting cardholder data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='1.4.2'; NIST='SC-8'; CIS='2.3.9.5' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 1 Network Security" -Status "Error" `
            -Message "1.4.2: Network connections -- SMB signing required (client) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='1.4.2'; NIST='SC-8'; CIS='2.3.9.5' }
    }

# ===========================================================================
# Req 2 -- Secure Configuration
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 2 -- Secure Configuration..." -ForegroundColor Yellow

    # 2.2.1a: System hardening -- UAC enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.1a: System hardening -- UAC enabled -- properly configured" `
                -Details "Req 2.2.1: Default security controls like UAC must not be disabled on CDE systems" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.1'; NIST='AC-6'; ISO27001='A.5.15'; STIG='V-220926' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.1a: System hardening -- UAC enabled -- not configured (Value=$val)" `
                -Details "Req 2.2.1: Default security controls like UAC must not be disabled on CDE systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.1'; NIST='AC-6'; ISO27001='A.5.15'; STIG='V-220926' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.1a: System hardening -- UAC enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='2.2.1'; NIST='AC-6'; ISO27001='A.5.15'; STIG='V-220926' }
    }
    # 2.2.1b: System hardening -- autoplay disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default $null
        if ($null -ne $val -and $val -eq 255) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.1b: System hardening -- autoplay disabled -- properly configured" `
                -Details "Req 2.2.1: AutoPlay must be disabled to prevent malware from removable media" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.1'; NIST='MP-7'; CIS='18.9.8.3' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.1b: System hardening -- autoplay disabled -- not configured (Value=$val)" `
                -Details "Req 2.2.1: AutoPlay must be disabled to prevent malware from removable media" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.1'; NIST='MP-7'; CIS='18.9.8.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.1b: System hardening -- autoplay disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='2.2.1'; NIST='MP-7'; CIS='18.9.8.3' }
    }
    # 2.2.2: Vendor defaults -- Guest account disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SAM\SAM\Domains\Account\Users\000001F5" -Name "F" -Default $null
        if ($null -ne $val) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.2: Vendor defaults -- Guest account disabled -- properly configured" `
                -Details "Req 2.2.2: Vendor-supplied defaults and unnecessary accounts must be removed or disabled" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.2'; NIST='AC-2'; CIS='1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Warning" `
                -Message "2.2.2: Vendor defaults -- Guest account disabled -- not configured (Value=$val)" `
                -Details "Req 2.2.2: Vendor-supplied defaults and unnecessary accounts must be removed or disabled" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.2'; NIST='AC-2'; CIS='1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.2: Vendor defaults -- Guest account disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='2.2.2'; NIST='AC-2'; CIS='1.1' }
    }
    # 2.2.2b: Vendor defaults -- Guest account check
    try {
        $guestAcct = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guestAcct -and $guestAcct.Enabled -eq $false) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.2b: Guest account is disabled" `
                -Details "Req 2.2.2: Default vendor accounts are properly disabled" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.2'; NIST='AC-2'; ISO27001='A.5.18' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.2b: Guest account is ENABLED" `
                -Details "Req 2.2.2: Default accounts must be disabled in CDE" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.2'; NIST='AC-2'; ISO27001='A.5.18' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.2b: Vendor defaults -- Guest account check -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='2.2.2'; NIST='AC-2' }
    }
    # 2.2.3: System hardening -- LM hash storage disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.3: System hardening -- LM hash storage disabled -- properly configured" `
                -Details "Req 2.2.3: Weak authentication mechanisms must be disabled in CDE" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.3'; NIST='IA-5'; CIS='2.3.11.5' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.3: System hardening -- LM hash storage disabled -- not configured (Value=$val)" `
                -Details "Req 2.2.3: Weak authentication mechanisms must be disabled in CDE" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.3'; NIST='IA-5'; CIS='2.3.11.5' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.3: System hardening -- LM hash storage disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='2.2.3'; NIST='IA-5'; CIS='2.3.11.5' }
    }
    # 2.2.4: System hardening -- NTLMv2 only
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default $null
        if ($null -ne $val -and $val -ge 5) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.4: System hardening -- NTLMv2 only -- properly configured" `
                -Details "Req 2.2.4: Only NTLMv2 authentication permitted; LM/NTLM must be refused" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.4'; NIST='IA-2'; CIS='2.3.11.7'; STIG='V-220968' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.4: System hardening -- NTLMv2 only -- not configured (Value=$val)" `
                -Details "Req 2.2.4: Only NTLMv2 authentication permitted; LM/NTLM must be refused" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.4'; NIST='IA-2'; CIS='2.3.11.7'; STIG='V-220968' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.4: System hardening -- NTLMv2 only -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='2.2.4'; NIST='IA-2'; CIS='2.3.11.7'; STIG='V-220968' }
    }
    # 2.2.5a: System hardening -- LSASS protection
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.5a: System hardening -- LSASS protection -- properly configured" `
                -Details "Req 2.2.5: Credential protection mechanisms must be enabled on CDE systems" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.5'; NIST='IA-5(13)'; CIS='18.3.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.5a: System hardening -- LSASS protection -- not configured (Value=$val)" `
                -Details "Req 2.2.5: Credential protection mechanisms must be enabled on CDE systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.5'; NIST='IA-5(13)'; CIS='18.3.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.5a: System hardening -- LSASS protection -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='2.2.5'; NIST='IA-5(13)'; CIS='18.3.1' }
    }
    # 2.2.5b: System hardening -- WDigest disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.5b: System hardening -- WDigest disabled -- properly configured" `
                -Details "Req 2.2.5: WDigest caches plaintext credentials; must be disabled in CDE" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.5'; NIST='IA-5(13)'; CIS='18.3.6' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.5b: System hardening -- WDigest disabled -- not configured (Value=$val)" `
                -Details "Req 2.2.5: WDigest caches plaintext credentials; must be disabled in CDE" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='2.2.5'; NIST='IA-5(13)'; CIS='18.3.6' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.5b: System hardening -- WDigest disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='2.2.5'; NIST='IA-5(13)'; CIS='18.3.6' }
    }
    # 2.2.6: System hardening -- PowerShell Constrained Language Mode
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.6: System hardening -- PowerShell Constrained Language Mode -- properly configured" `
                -Details "Req 2.2.6: Script execution must be logged for forensic capability in CDE" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.6'; NIST='CM-6'; CIS='18.9.100.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.6: System hardening -- PowerShell Constrained Language Mode -- not configured (Value=$val)" `
                -Details "Req 2.2.6: Script execution must be logged for forensic capability in CDE" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='2.2.6'; NIST='CM-6'; CIS='18.9.100.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.6: System hardening -- PowerShell Constrained Language Mode -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='2.2.6'; NIST='CM-6'; CIS='18.9.100.1' }
    }
    # 2.2.7: Unnecessary services -- Print Spooler (if not needed)
    try {
        $svc = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
        if ($null -eq $svc -or $svc.Status -ne "Running") {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.7: Unnecessary services -- Print Spooler (if not needed) -- service not running (expected)" `
                -Details "Req 2.2.7: Unnecessary services must be disabled to reduce attack surface in CDE" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='2.2.7'; NIST='CM-7'; CIS='5.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.7: Unnecessary services -- Print Spooler (if not needed) -- service is running (should be disabled)" `
                -Details "Req 2.2.7: Unnecessary services must be disabled to reduce attack surface in CDE" `
                -Remediation "Stop-Service -Name Spooler; Set-Service -Name Spooler -StartupType Disabled" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='2.2.7'; NIST='CM-7'; CIS='5.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.7: Unnecessary services -- Print Spooler (if not needed) -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='2.2.7'; NIST='CM-7'; CIS='5.1' }
    }
    # 2.2.7b: Unnecessary services -- Xbox services
    try {
        $svc = Get-Service -Name "XblAuthManager" -ErrorAction SilentlyContinue
        if ($null -eq $svc -or $svc.Status -ne "Running") {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Pass" `
                -Message "2.2.7b: Unnecessary services -- Xbox services -- service not running (expected)" `
                -Details "Req 2.2.7: Gaming services provide no business function in CDE and must be disabled" `
                -Severity "Low" `
                -CrossReferences @{ 'PCI-DSS'='2.2.7'; NIST='CM-7' }
        } else {
            Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Fail" `
                -Message "2.2.7b: Unnecessary services -- Xbox services -- service is running (should be disabled)" `
                -Details "Req 2.2.7: Gaming services provide no business function in CDE and must be disabled" `
                -Remediation "Stop-Service -Name XblAuthManager; Set-Service -Name XblAuthManager -StartupType Disabled" `
                -Severity "Low" `
                -CrossReferences @{ 'PCI-DSS'='2.2.7'; NIST='CM-7' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 2 Secure Config" -Status "Error" `
            -Message "2.2.7b: Unnecessary services -- Xbox services -- check failed: $_" `
            -Severity "Low" `
            -CrossReferences @{ 'PCI-DSS'='2.2.7'; NIST='CM-7' }
    }

# ===========================================================================
# Req 3 -- Protect Stored Account Data
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 3 -- Protect Stored Account Data..." -ForegroundColor Yellow

    # 3.4.1: Encryption at rest -- BitLocker status
    try {
        $blStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($null -ne $blStatus -and $blStatus.ProtectionStatus -eq "On") {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Pass" `
                -Message "3.4.1: BitLocker encryption is active on system drive" `
                -Details "Req 3.4.1: Stored cardholder data must be rendered unreadable" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='3.4.1'; NIST='SC-28'; ISO27001='A.8.24' }
        } elseif ($null -ne $blStatus) {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Fail" `
                -Message "3.4.1: BitLocker is present but NOT active (Status=$($blStatus.ProtectionStatus))" `
                -Details "Req 3.4.1: Full disk encryption must protect stored account data" `
                -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='3.4.1'; NIST='SC-28'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Fail" `
                -Message "3.4.1: BitLocker is NOT available or not configured" `
                -Details "Req 3.4.1: Disk encryption required for CDE systems storing cardholder data" `
                -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='3.4.1'; NIST='SC-28'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Error" `
            -Message "3.4.1: Encryption at rest -- BitLocker status -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='3.4.1'; NIST='SC-28' }
    }
    # 3.4.2: Encryption at rest -- BitLocker encryption method
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Default $null
        if ($null -ne $val -and $val -ge 7) {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Pass" `
                -Message "3.4.2: Encryption at rest -- BitLocker encryption method -- properly configured" `
                -Details "Req 3.4.2: Encryption algorithm must be AES-256 or stronger for cardholder data" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='3.4.2'; NIST='SC-13'; CIS='18.10.9.1.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Fail" `
                -Message "3.4.2: Encryption at rest -- BitLocker encryption method -- not configured (Value=$val)" `
                -Details "Req 3.4.2: Encryption algorithm must be AES-256 or stronger for cardholder data" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name EncryptionMethodWithXtsOs -Value 7" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='3.4.2'; NIST='SC-13'; CIS='18.10.9.1.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Error" `
            -Message "3.4.2: Encryption at rest -- BitLocker encryption method -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='3.4.2'; NIST='SC-13'; CIS='18.10.9.1.2' }
    }
    # 3.5.1: Key management -- pagefile cleared at shutdown
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Pass" `
                -Message "3.5.1: Key management -- pagefile cleared at shutdown -- properly configured" `
                -Details "Req 3.5.1: Sensitive data in memory/pagefile must be cleared to prevent recovery" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='3.5.1'; NIST='SC-4'; CIS='2.3.11.9' }
        } else {
            Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Fail" `
                -Message "3.5.1: Key management -- pagefile cleared at shutdown -- not configured (Value=$val)" `
                -Details "Req 3.5.1: Sensitive data in memory/pagefile must be cleared to prevent recovery" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='3.5.1'; NIST='SC-4'; CIS='2.3.11.9' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 3 Stored Data" -Status "Error" `
            -Message "3.5.1: Key management -- pagefile cleared at shutdown -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='3.5.1'; NIST='SC-4'; CIS='2.3.11.9' }
    }

# ===========================================================================
# Req 4 -- Strong Cryptography in Transit
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 4 -- Strong Cryptography in Transit..." -ForegroundColor Yellow

    # 4.2.1a: TLS 1.2 enabled (client)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.1a: TLS 1.2 enabled (client) -- properly configured" `
                -Details "Req 4.2.1: TLS 1.2+ must be used for all transmissions of cardholder data" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.1'; NIST='SC-8'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.1a: TLS 1.2 enabled (client) -- not configured (Value=$val)" `
                -Details "Req 4.2.1: TLS 1.2+ must be used for all transmissions of cardholder data" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.1'; NIST='SC-8'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.1a: TLS 1.2 enabled (client) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='4.2.1'; NIST='SC-8'; ISO27001='A.8.24' }
    }
    # 4.2.1b: TLS 1.2 enabled (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.1b: TLS 1.2 enabled (server) -- properly configured" `
                -Details "Req 4.2.1: Server-side TLS 1.2 must accept secure connections for card data" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.1'; NIST='SC-8'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.1b: TLS 1.2 enabled (server) -- not configured (Value=$val)" `
                -Details "Req 4.2.1: Server-side TLS 1.2 must accept secure connections for card data" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.1'; NIST='SC-8'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.1b: TLS 1.2 enabled (server) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='4.2.1'; NIST='SC-8'; ISO27001='A.8.24' }
    }
    # 4.2.2a: SSL 2.0 disabled (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.2a: SSL 2.0 disabled (server) -- properly configured" `
                -Details "Req 4.2.2: SSL 2.0 has critical vulnerabilities and must be disabled" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.2a: SSL 2.0 disabled (server) -- not configured (Value=$val)" `
                -Details "Req 4.2.2: SSL 2.0 has critical vulnerabilities and must be disabled" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.2a: SSL 2.0 disabled (server) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
    }
    # 4.2.2b: SSL 3.0 disabled (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.2b: SSL 3.0 disabled (server) -- properly configured" `
                -Details "Req 4.2.2: SSL 3.0 (POODLE) must be disabled for PCI compliance" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.2b: SSL 3.0 disabled (server) -- not configured (Value=$val)" `
                -Details "Req 4.2.2: SSL 3.0 (POODLE) must be disabled for PCI compliance" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name Enabled -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.2b: SSL 3.0 disabled (server) -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
    }
    # 4.2.2c: TLS 1.0 disabled (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.2c: TLS 1.0 disabled (server) -- properly configured" `
                -Details "Req 4.2.2: TLS 1.0 has known vulnerabilities; migration deadline passed June 2018" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.2c: TLS 1.0 disabled (server) -- not configured (Value=$val)" `
                -Details "Req 4.2.2: TLS 1.0 has known vulnerabilities; migration deadline passed June 2018" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.2c: TLS 1.0 disabled (server) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
    }
    # 4.2.2d: TLS 1.1 disabled (server)
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.2d: TLS 1.1 disabled (server) -- properly configured" `
                -Details "Req 4.2.2: TLS 1.1 is deprecated; PCI DSS v4.0 requires TLS 1.2 minimum" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.2d: TLS 1.1 disabled (server) -- not configured (Value=$val)" `
                -Details "Req 4.2.2: TLS 1.1 is deprecated; PCI DSS v4.0 requires TLS 1.2 minimum" `
                -Remediation "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.2d: TLS 1.1 disabled (server) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='4.2.2'; NIST='SC-13'; ISO27001='A.8.24' }
    }
    # 4.2.3: WinRM basic auth disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.3: WinRM basic auth disabled -- properly configured" `
                -Details "Req 4.2.3: Basic authentication transmits credentials in cleartext over network" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.3'; NIST='IA-2'; CIS='18.9.102.1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.3: WinRM basic auth disabled -- not configured (Value=$val)" `
                -Details "Req 4.2.3: Basic authentication transmits credentials in cleartext over network" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowBasic -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.3'; NIST='IA-2'; CIS='18.9.102.1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.3: WinRM basic auth disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='4.2.3'; NIST='IA-2'; CIS='18.9.102.1.1' }
    }
    # 4.2.4: WinRM unencrypted traffic disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Pass" `
                -Message "4.2.4: WinRM unencrypted traffic disabled -- properly configured" `
                -Details "Req 4.2.4: All remote management traffic must be encrypted" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.4'; NIST='SC-8'; CIS='18.9.102.1.3' }
        } else {
            Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Fail" `
                -Message "4.2.4: WinRM unencrypted traffic disabled -- not configured (Value=$val)" `
                -Details "Req 4.2.4: All remote management traffic must be encrypted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='4.2.4'; NIST='SC-8'; CIS='18.9.102.1.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 4 Crypto Transit" -Status "Error" `
            -Message "4.2.4: WinRM unencrypted traffic disabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='4.2.4'; NIST='SC-8'; CIS='18.9.102.1.3' }
    }

# ===========================================================================
# Req 5 -- Protect Against Malware
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 5 -- Protect Against Malware..." -ForegroundColor Yellow

    # 5.2.1a: Anti-malware -- real-time protection enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.1a: Anti-malware -- real-time protection enabled -- properly configured" `
                -Details "Req 5.2.1: Anti-malware solution must provide real-time protection on all CDE systems" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; ISO27001='A.8.7'; CIS='18.9.47.9.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.1a: Anti-malware -- real-time protection enabled -- not configured (Value=$val)" `
                -Details "Req 5.2.1: Anti-malware solution must provide real-time protection on all CDE systems" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; ISO27001='A.8.7'; CIS='18.9.47.9.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.1a: Anti-malware -- real-time protection enabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; ISO27001='A.8.7'; CIS='18.9.47.9.1' }
    }
    # 5.2.1b: Anti-malware -- Defender not disabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.1b: Anti-malware -- Defender not disabled -- properly configured" `
                -Details "Req 5.2.1: Anti-malware engine must be active and not administratively disabled" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; CIS='18.9.47.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.1b: Anti-malware -- Defender not disabled -- not configured (Value=$val)" `
                -Details "Req 5.2.1: Anti-malware engine must be active and not administratively disabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 0" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; CIS='18.9.47.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.1b: Anti-malware -- Defender not disabled -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; CIS='18.9.47.1' }
    }
    # 5.2.1c: Anti-malware -- Defender service running
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.1c: Anti-malware -- Defender service running -- service running" `
                -Details "Req 5.2.1: Anti-malware service must be operational for continuous protection" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; CISA='EDR' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.1c: Anti-malware -- Defender service running -- service not running (Status=$svcSt)" `
                -Details "Req 5.2.1: Anti-malware service must be operational for continuous protection" `
                -Remediation "Start-Service -Name WinDefend; Set-Service -Name WinDefend -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; CISA='EDR' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.1c: Anti-malware -- Defender service running -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='5.2.1'; NIST='SI-3'; CISA='EDR' }
    }
    # 5.2.2: Anti-malware -- behavior monitoring
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.2: Anti-malware -- behavior monitoring -- properly configured" `
                -Details "Req 5.2.2: Behavioral analysis detects malware that evades signature-based detection" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.2.2'; NIST='SI-3'; CIS='18.9.47.9.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.2: Anti-malware -- behavior monitoring -- not configured (Value=$val)" `
                -Details "Req 5.2.2: Behavioral analysis detects malware that evades signature-based detection" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableBehaviorMonitoring -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.2.2'; NIST='SI-3'; CIS='18.9.47.9.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.2: Anti-malware -- behavior monitoring -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='5.2.2'; NIST='SI-3'; CIS='18.9.47.9.2' }
    }
    # 5.2.3: Anti-malware -- cloud-delivered protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Default $null
        if ($null -ne $val -and $val -eq 2) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.3: Anti-malware -- cloud-delivered protection -- properly configured" `
                -Details "Req 5.2.3: Cloud intelligence enhances malware detection speed and accuracy" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.2.3'; NIST='SI-3(10)'; CIS='18.9.47.11.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.3: Anti-malware -- cloud-delivered protection -- not configured (Value=$val)" `
                -Details "Req 5.2.3: Cloud intelligence enhances malware detection speed and accuracy" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name SpyNetReporting -Value 2" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.2.3'; NIST='SI-3(10)'; CIS='18.9.47.11.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.3: Anti-malware -- cloud-delivered protection -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='5.2.3'; NIST='SI-3(10)'; CIS='18.9.47.11.1' }
    }
    # 5.2.4: Anti-malware -- download scanning (IOAV)
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.4: Anti-malware -- download scanning (IOAV) -- properly configured" `
                -Details "Req 5.2.4: All downloaded files must be scanned before execution" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.2.4'; NIST='SI-3'; CIS='18.9.47.9.3' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.4: Anti-malware -- download scanning (IOAV) -- not configured (Value=$val)" `
                -Details "Req 5.2.4: All downloaded files must be scanned before execution" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableIOAVProtection -Value 0" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.2.4'; NIST='SI-3'; CIS='18.9.47.9.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.4: Anti-malware -- download scanning (IOAV) -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='5.2.4'; NIST='SI-3'; CIS='18.9.47.9.3' }
    }
    # 5.2.5: Anti-malware -- PUA protection
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.2.5: Anti-malware -- PUA protection -- properly configured" `
                -Details "Req 5.2.5: Potentially unwanted applications must be detected and blocked" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='5.2.5'; NIST='SI-3'; CIS='18.9.47.15' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.2.5: Anti-malware -- PUA protection -- not configured (Value=$val)" `
                -Details "Req 5.2.5: Potentially unwanted applications must be detected and blocked" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name PUAProtection -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='5.2.5'; NIST='SI-3'; CIS='18.9.47.15' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.2.5: Anti-malware -- PUA protection -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='5.2.5'; NIST='SI-3'; CIS='18.9.47.15' }
    }
    # 5.3.1: Anti-malware -- automatic updates
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.3.1: Anti-malware -- automatic updates -- properly configured" `
                -Details "Req 5.3.1: Malware definitions must be updated automatically from authorized sources" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.3.1'; NIST='SI-3'; CIS='18.9.47.12.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.3.1: Anti-malware -- automatic updates -- not configured (Value=$val)" `
                -Details "Req 5.3.1: Malware definitions must be updated automatically from authorized sources" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates' -Name ForceUpdateFromMU -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.3.1'; NIST='SI-3'; CIS='18.9.47.12.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.3.1: Anti-malware -- automatic updates -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='5.3.1'; NIST='SI-3'; CIS='18.9.47.12.1' }
    }
    # 5.3.2: Anti-malware -- controlled folder access
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Pass" `
                -Message "5.3.2: Anti-malware -- controlled folder access -- properly configured" `
                -Details "Req 5.3.2: Ransomware protection must be enabled to protect cardholder data stores" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.3.2'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Fail" `
                -Message "5.3.2: Anti-malware -- controlled folder access -- not configured (Value=$val)" `
                -Details "Req 5.3.2: Ransomware protection must be enabled to protect cardholder data stores" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='5.3.2'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 5 Malware" -Status "Error" `
            -Message "5.3.2: Anti-malware -- controlled folder access -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='5.3.2'; NIST='SI-3'; CIS='18.9.47.5.1.1' }
    }

# ===========================================================================
# Req 6 -- Develop and Maintain Secure Systems
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 6 -- Develop and Maintain Secure Systems..." -ForegroundColor Yellow

    # 6.3.1: Vulnerability management -- auto updates
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Default $null
        if ($null -ne $val -and $val -ge 4) {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Pass" `
                -Message "6.3.1: Vulnerability management -- auto updates -- properly configured" `
                -Details "Req 6.3.1: Security patches must be installed within defined timeframe (critical: 30 days)" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.1'; NIST='SI-2'; ISO27001='A.8.8'; CISA='Patch Management' }
        } else {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Fail" `
                -Message "6.3.1: Vulnerability management -- auto updates -- not configured (Value=$val)" `
                -Details "Req 6.3.1: Security patches must be installed within defined timeframe (critical: 30 days)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -Value 4" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.1'; NIST='SI-2'; ISO27001='A.8.8'; CISA='Patch Management' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Error" `
            -Message "6.3.1: Vulnerability management -- auto updates -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='6.3.1'; NIST='SI-2'; ISO27001='A.8.8'; CISA='Patch Management' }
    }
    # 6.3.2: Vulnerability management -- Windows Update service
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Pass" `
                -Message "6.3.2: Vulnerability management -- Windows Update service -- service running" `
                -Details "Req 6.3.2: Update delivery mechanism must be functional for timely patching" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.2'; NIST='SI-2'; CISA='Patch Management' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Fail" `
                -Message "6.3.2: Vulnerability management -- Windows Update service -- service not running (Status=$svcSt)" `
                -Details "Req 6.3.2: Update delivery mechanism must be functional for timely patching" `
                -Remediation "Start-Service -Name wuauserv; Set-Service -Name wuauserv -StartupType Automatic" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.2'; NIST='SI-2'; CISA='Patch Management' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Error" `
            -Message "6.3.2: Vulnerability management -- Windows Update service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='6.3.2'; NIST='SI-2'; CISA='Patch Management' }
    }
    # 6.3.3: Change control -- DEP enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Default $null
        if ($null -ne $val -and $val -ne 0) {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Pass" `
                -Message "6.3.3: Change control -- DEP enabled -- properly configured" `
                -Details "Req 6.3.3: Exploit protection must be active on CDE systems" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.3'; NIST='SI-16'; CIS='18.3.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Fail" `
                -Message "6.3.3: Change control -- DEP enabled -- not configured (Value=$val)" `
                -Details "Req 6.3.3: Exploit protection must be active on CDE systems" `
                -Remediation "bcdedit /set nx AlwaysOn" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.3'; NIST='SI-16'; CIS='18.3.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Error" `
            -Message "6.3.3: Change control -- DEP enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='6.3.3'; NIST='SI-16'; CIS='18.3.2' }
    }
    # 6.3.4: Change control -- ASLR enforcement
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -Default $null
        if ($null -ne $val) {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Pass" `
                -Message "6.3.4: Change control -- ASLR enforcement -- properly configured" `
                -Details "Req 6.3.4: Address space layout randomization (ASLR) must be enabled system-wide" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.4'; NIST='SI-16'; CIS='18.3.3' }
        } else {
            Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Warning" `
                -Message "6.3.4: Change control -- ASLR enforcement -- not configured (Value=$val)" `
                -Details "Req 6.3.4: Address space layout randomization (ASLR) must be enabled system-wide" `
                -Remediation "Set-ProcessMitigation -System -Enable ForceRelocateImages" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='6.3.4'; NIST='SI-16'; CIS='18.3.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 6 Secure Systems" -Status "Error" `
            -Message "6.3.4: Change control -- ASLR enforcement -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='6.3.4'; NIST='SI-16'; CIS='18.3.3' }
    }

# ===========================================================================
# Req 7 -- Restrict Access by Business Need
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 7 -- Restrict Access by Business Need..." -ForegroundColor Yellow

    # 7.1.1: Least privilege -- admin account count
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $adminCount = if ($null -ne $localAdmins) { @($localAdmins).Count } else { 0 }
        if ($adminCount -le 2) {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Pass" `
                -Message "7.1.1: Local administrator group has $adminCount members" `
                -Details "Req 7.1.1: Access limited to minimum needed for business function" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='7.1.1'; NIST='AC-6'; ISO27001='A.5.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Warning" `
                -Message "7.1.1: Local administrator group has $adminCount members (review needed)" `
                -Details "Req 7.1.1: Excessive admin access in CDE increases risk of unauthorized data access" `
                -Remediation "Review administrator group membership; remove non-essential accounts" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='7.1.1'; NIST='AC-6'; ISO27001='A.5.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Error" `
            -Message "7.1.1: Least privilege -- admin account count -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='7.1.1'; NIST='AC-6' }
    }
    # 7.2.1: Access restriction -- anonymous enumeration restricted
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Default $null
        if ($null -ne $val -and $val -ge 1) {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Pass" `
                -Message "7.2.1: Access restriction -- anonymous enumeration restricted -- properly configured" `
                -Details "Req 7.2.1: Anonymous access to CDE resources must be restricted" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='7.2.1'; NIST='AC-14'; CIS='2.3.10.6' }
        } else {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Fail" `
                -Message "7.2.1: Access restriction -- anonymous enumeration restricted -- not configured (Value=$val)" `
                -Details "Req 7.2.1: Anonymous access to CDE resources must be restricted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='7.2.1'; NIST='AC-14'; CIS='2.3.10.6' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Error" `
            -Message "7.2.1: Access restriction -- anonymous enumeration restricted -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='7.2.1'; NIST='AC-14'; CIS='2.3.10.6' }
    }
    # 7.2.2: Access restriction -- anonymous SAM enumeration
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Pass" `
                -Message "7.2.2: Access restriction -- anonymous SAM enumeration -- properly configured" `
                -Details "Req 7.2.2: Anonymous enumeration of SAM accounts must be prevented" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='7.2.2'; NIST='AC-14'; CIS='2.3.10.7' }
        } else {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Fail" `
                -Message "7.2.2: Access restriction -- anonymous SAM enumeration -- not configured (Value=$val)" `
                -Details "Req 7.2.2: Anonymous enumeration of SAM accounts must be prevented" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='7.2.2'; NIST='AC-14'; CIS='2.3.10.7' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Error" `
            -Message "7.2.2: Access restriction -- anonymous SAM enumeration -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='7.2.2'; NIST='AC-14'; CIS='2.3.10.7' }
    }
    # 7.2.3: Access restriction -- anonymous SID translation blocked
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Pass" `
                -Message "7.2.3: Access restriction -- anonymous SID translation blocked -- properly configured" `
                -Details "Req 7.2.3: Anonymous SID/Name translation must be disabled" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='7.2.3'; NIST='AC-14'; STIG='V-220936' }
        } else {
            Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Fail" `
                -Message "7.2.3: Access restriction -- anonymous SID translation blocked -- not configured (Value=$val)" `
                -Details "Req 7.2.3: Anonymous SID/Name translation must be disabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name TurnOffAnonymousBlock -Value 1" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='7.2.3'; NIST='AC-14'; STIG='V-220936' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 7 Access Control" -Status "Error" `
            -Message "7.2.3: Access restriction -- anonymous SID translation blocked -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='7.2.3'; NIST='AC-14'; STIG='V-220936' }
    }

# ===========================================================================
# Req 8 -- Identify Users and Authenticate Access
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 8 -- Identify Users and Authenticate Access..." -ForegroundColor Yellow

    # 8.3.1: Password length -- minimum 12 characters
    try {
        $netAcct = net accounts 2>&1
        $minLen = 0
        foreach ($line in $netAcct) { if ($line -match "Minimum password length\s+(\d+)") { $minLen = [int]$Matches[1] } }
        if ($minLen -ge 12) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.1: Minimum password length is $minLen characters" `
                -Details "Req 8.3.6: PCI DSS v4.0 requires minimum 12 characters (14 recommended)" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.6'; NIST='IA-5'; CIS='1.1.4'; ISO27001='A.5.17' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.1: Minimum password length is $minLen (requires `>= 12)" `
                -Details "Req 8.3.6: PCI DSS v4.0 mandates minimum 12-character passwords" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.6'; NIST='IA-5'; CIS='1.1.4'; ISO27001='A.5.17' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.1: Password length -- minimum 12 characters -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='8.3.6'; NIST='IA-5' }
    }
    # 8.3.4: Account lockout -- threshold
    try {
        $netAcct = net accounts 2>&1
        $lockThresh = 0
        foreach ($line in $netAcct) { if ($line -match "Lockout threshold\s+(\d+)") { $lockThresh = [int]$Matches[1] } }
        if ($lockThresh -gt 0 -and $lockThresh -le 10) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.4: Account lockout threshold is $lockThresh attempts" `
                -Details "Req 8.3.4: PCI DSS requires lockout after not more than 10 attempts" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.4'; NIST='AC-7'; CIS='1.2.1'; ISO27001='A.5.17' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.4: Account lockout threshold is $lockThresh (requires 1-10)" `
                -Details "Req 8.3.4: Lockout policy prevents brute-force credential attacks" `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.4'; NIST='AC-7'; CIS='1.2.1'; ISO27001='A.5.17' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.4: Account lockout -- threshold -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='8.3.4'; NIST='AC-7' }
    }
    # 8.3.5: Account lockout -- duration
    try {
        $netAcct = net accounts 2>&1
        $lockDur = 0
        foreach ($line in $netAcct) { if ($line -match "Lockout duration.*?\s+(\d+)") { $lockDur = [int]$Matches[1] } }
        if ($lockDur -ge 30) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.5: Account lockout duration is $lockDur minutes" `
                -Details "Req 8.3.5: Lockout must remain for minimum 30 minutes or until admin unlocks" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='8.3.5'; NIST='AC-7'; CIS='1.2.2' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.5: Account lockout duration is $lockDur minutes (requires `>= 30)" `
                -Details "Req 8.3.5: Short lockout duration allows rapid brute-force retry" `
                -Remediation "net accounts /lockoutduration:30" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='8.3.5'; NIST='AC-7'; CIS='1.2.2' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.5: Account lockout -- duration -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='8.3.5'; NIST='AC-7' }
    }
    # 8.3.7: Password history -- prevent reuse
    try {
        $netAcct = net accounts 2>&1
        $pwHist = 0
        foreach ($line in $netAcct) { if ($line -match "Length of password history maintained\s+(\d+)") { $pwHist = [int]$Matches[1] } }
        if ($pwHist -ge 4) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.7: Password history enforces $pwHist previous passwords" `
                -Details "Req 8.3.7: PCI requires passwords differ from last 4 (24 recommended)" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='8.3.7'; NIST='IA-5(1)'; CIS='1.1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.7: Password history is $pwHist (requires `>= 4)" `
                -Details "Req 8.3.7: Low history count enables credential reuse patterns" `
                -Remediation "net accounts /uniquepw:24" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='8.3.7'; NIST='IA-5(1)'; CIS='1.1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.7: Password history -- prevent reuse -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='8.3.7'; NIST='IA-5(1)' }
    }
    # 8.3.9a: Session timeout -- machine inactivity limit
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default $null
        if ($null -ne $val -and $val -le 900) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.9a: Session timeout -- machine inactivity limit -- properly configured" `
                -Details "Req 8.3.9: Sessions must time out after 15 minutes of inactivity" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.9'; NIST='AC-12'; CIS='2.3.7.3' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.9a: Session timeout -- machine inactivity limit -- not configured (Value=$val)" `
                -Details "Req 8.3.9: Sessions must time out after 15 minutes of inactivity" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.9'; NIST='AC-12'; CIS='2.3.7.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.9a: Session timeout -- machine inactivity limit -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='8.3.9'; NIST='AC-12'; CIS='2.3.7.3' }
    }
    # 8.3.9b: Session timeout -- RDP idle disconnect
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Default $null
        if ($null -ne $val -and $val -le 900000) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.9b: Session timeout -- RDP idle disconnect -- properly configured" `
                -Details "Req 8.3.9: Remote sessions must disconnect after 15 minutes of inactivity" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.9'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.9b: Session timeout -- RDP idle disconnect -- not configured (Value=$val)" `
                -Details "Req 8.3.9: Remote sessions must disconnect after 15 minutes of inactivity" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -Value 900000" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.9'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.9b: Session timeout -- RDP idle disconnect -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='8.3.9'; NIST='AC-12'; CIS='18.9.65.3.10.1' }
    }
    # 8.3.10: NLA required for RDP
    try {
        $val = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.10: NLA required for RDP -- properly configured" `
                -Details "Req 8.3.10: Network Level Authentication prevents unauthenticated RDP sessions" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.10'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.10: NLA required for RDP -- not configured (Value=$val)" `
                -Details "Req 8.3.10: Network Level Authentication prevents unauthenticated RDP sessions" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='8.3.10'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.10: NLA required for RDP -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='8.3.10'; NIST='AC-17'; CIS='18.9.65.3.9.1' }
    }
    # 8.3.11: Credential delegation restricted
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials" -Default $null
        if ($null -ne $val -and $val -eq 0) {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Pass" `
                -Message "8.3.11: Credential delegation restricted -- properly configured" `
                -Details "Req 8.3.11: Credential delegation must be restricted to prevent credential theft" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='8.3.11'; NIST='IA-5' }
        } else {
            Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Fail" `
                -Message "8.3.11: Credential delegation restricted -- not configured (Value=$val)" `
                -Details "Req 8.3.11: Credential delegation must be restricted to prevent credential theft" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name AllowDefaultCredentials -Value 0" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='8.3.11'; NIST='IA-5' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 8 Authentication" -Status "Error" `
            -Message "8.3.11: Credential delegation restricted -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='8.3.11'; NIST='IA-5' }
    }

# ===========================================================================
# Req 10 -- Log and Monitor All Access
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 10 -- Log and Monitor All Access..." -ForegroundColor Yellow

    # 10.2.1a: Audit capability -- Event Log service running
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.2.1a: Audit capability -- Event Log service running -- service running" `
                -Details "Req 10.2.1: Audit logging must be operational on all CDE systems" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='10.2.1'; NIST='AU-2'; ISO27001='A.8.15' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.2.1a: Audit capability -- Event Log service running -- service not running (Status=$svcSt)" `
                -Details "Req 10.2.1: Audit logging must be operational on all CDE systems" `
                -Remediation "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='10.2.1'; NIST='AU-2'; ISO27001='A.8.15' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.2.1a: Audit capability -- Event Log service running -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='10.2.1'; NIST='AU-2'; ISO27001='A.8.15' }
    }
    # 10.2.1b: Audit policy -- Logon events
    try {
        $auditOutput = auditpol /get /category:"Logon/Logoff" 2>&1
        $logonAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "Logon" -and ($line -match "Success" -or $line -match "Failure")) { $logonAudit = $true }
        }
        if ($logonAudit) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.2.1b: Logon event auditing is enabled" `
                -Details "Req 10.2.1: All individual access to cardholder data must be logged" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='10.2.1'; NIST='AU-2'; CIS='17.5.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.2.1b: Logon event auditing is NOT enabled" `
                -Details "Req 10.2.1: Cannot track CDE access without logon auditing" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='10.2.1'; NIST='AU-2'; CIS='17.5.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.2.1b: Audit policy -- Logon events -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='10.2.1'; NIST='AU-2' }
    }
    # 10.2.2: Audit policy -- Account Management
    try {
        $auditOutput = auditpol /get /category:"Account Management" 2>&1
        $acctAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "User Account Management" -and $line -match "Success") { $acctAudit = $true }
        }
        if ($acctAudit) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.2.2: Account management auditing is enabled" `
                -Details "Req 10.2.2: All actions by privileged users must be logged" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.2.2'; NIST='AU-2'; CIS='17.1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.2.2: Account management auditing NOT enabled" `
                -Details "Req 10.2.2: Privileged account changes cannot be tracked" `
                -Remediation "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.2.2'; NIST='AU-2'; CIS='17.1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.2.2: Audit policy -- Account Management -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='10.2.2'; NIST='AU-2' }
    }
    # 10.2.3: Audit policy -- Object Access
    try {
        $auditOutput = auditpol /get /category:"Object Access" 2>&1
        $objAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "File System" -and ($line -match "Success" -or $line -match "Failure")) { $objAudit = $true }
        }
        if ($objAudit) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.2.3: Object access auditing is enabled" `
                -Details "Req 10.2.3: Access to all cardholder data objects must be logged" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.2.3'; NIST='AU-12'; CIS='17.6.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Warning" `
                -Message "10.2.3: Object access auditing NOT configured" `
                -Details "Req 10.2.3: File system access to CDE data paths should be audited" `
                -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.2.3'; NIST='AU-12'; CIS='17.6.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.2.3: Audit policy -- Object Access -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='10.2.3'; NIST='AU-12' }
    }
    # 10.2.4: Audit policy -- Policy Change
    try {
        $auditOutput = auditpol /get /category:"Policy Change" 2>&1
        $polAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "Audit Policy Change" -and $line -match "Success") { $polAudit = $true }
        }
        if ($polAudit) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.2.4: Policy change auditing is enabled" `
                -Details "Req 10.2.4: Audit log changes must be detected and recorded" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='10.2.4'; NIST='AU-12'; CIS='17.7.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.2.4: Policy change auditing NOT enabled" `
                -Details "Req 10.2.4: Cannot detect audit policy tampering without this audit" `
                -Remediation "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable" `
                -Severity "Critical" `
                -CrossReferences @{ 'PCI-DSS'='10.2.4'; NIST='AU-12'; CIS='17.7.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.2.4: Audit policy -- Policy Change -- check failed: $_" `
            -Severity "Critical" `
            -CrossReferences @{ 'PCI-DSS'='10.2.4'; NIST='AU-12' }
    }
    # 10.2.5: Audit policy -- Privilege Use
    try {
        $auditOutput = auditpol /get /category:"Privilege Use" 2>&1
        $privAudit = $false
        foreach ($line in $auditOutput) {
            if ($line -match "Sensitive Privilege Use" -and ($line -match "Success" -or $line -match "Failure")) { $privAudit = $true }
        }
        if ($privAudit) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.2.5: Sensitive privilege use auditing is enabled" `
                -Details "Req 10.2.5: Elevation of privileges and use of admin rights must be logged" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.2.5'; NIST='AU-12'; CIS='17.8.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Warning" `
                -Message "10.2.5: Sensitive privilege use auditing NOT configured" `
                -Details "Req 10.2.5: Privileged operations in CDE should be tracked" `
                -Remediation "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.2.5'; NIST='AU-12'; CIS='17.8.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.2.5: Audit policy -- Privilege Use -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='10.2.5'; NIST='AU-12' }
    }
    # 10.3.1: Log retention -- Security log size
    try {
        $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
        $secLogMB = [Math]::Round($secLogSize / 1MB, 0)
        if ($secLogSize -ge 1073741824) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.3.1: Security event log is ${secLogMB}MB (`>= 1024MB)" `
                -Details "Req 10.3.1: Logs must be retained for 12 months (3 months immediately available)" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.3.1'; NIST='AU-4'; ISO27001='A.5.28' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.3.1: Security event log is ${secLogMB}MB (requires `>= 1024MB)" `
                -Details "Req 10.3.1: Insufficient log capacity for PCI DSS retention requirements" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.3.1'; NIST='AU-4'; ISO27001='A.5.28' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.3.1: Log retention -- Security log size -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='10.3.1'; NIST='AU-4' }
    }
    # 10.3.2: Log retention -- Application log size
    try {
        $appLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize" -Default 0
        $appLogMB = [Math]::Round($appLogSize / 1MB, 0)
        if ($appLogSize -ge 268435456) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.3.2: Application event log is ${appLogMB}MB (`>= 256MB)" `
                -Details "Req 10.3.2: Application logs support incident investigation timelines" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='10.3.2'; NIST='AU-4'; CIS='18.9.27.1.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Warning" `
                -Message "10.3.2: Application event log is ${appLogMB}MB (recommend `>= 256MB)" `
                -Details "Req 10.3.2: Consider increasing for adequate incident investigation window" `
                -Remediation "wevtutil sl Application /ms:268435456" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='10.3.2'; NIST='AU-4'; CIS='18.9.27.1.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.3.2: Log retention -- Application log size -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='10.3.2'; NIST='AU-4' }
    }
    # 10.6.1: Time synchronization -- W32Time service
    try {
        $svc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.6.1: Time synchronization -- W32Time service -- service running" `
                -Details "Req 10.6.1: Time synchronization is critical for accurate audit trail timestamps" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.6.1'; NIST='AU-8'; CIS='18.5.14.1' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.6.1: Time synchronization -- W32Time service -- service not running (Status=$svcSt)" `
                -Details "Req 10.6.1: Time synchronization is critical for accurate audit trail timestamps" `
                -Remediation "Start-Service -Name W32Time; Set-Service -Name W32Time -StartupType Automatic; w32tm /resync" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.6.1'; NIST='AU-8'; CIS='18.5.14.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.6.1: Time synchronization -- W32Time service -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='10.6.1'; NIST='AU-8'; CIS='18.5.14.1' }
    }
    # 10.5.1: Log protection -- PowerShell Script Block Logging
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Pass" `
                -Message "10.5.1: Log protection -- PowerShell Script Block Logging -- properly configured" `
                -Details "Req 10.5.1: All script execution must be logged for audit trail completeness" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.5.1'; NIST='AU-12'; CIS='18.9.100.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Fail" `
                -Message "10.5.1: Log protection -- PowerShell Script Block Logging -- not configured (Value=$val)" `
                -Details "Req 10.5.1: All script execution must be logged for audit trail completeness" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='10.5.1'; NIST='AU-12'; CIS='18.9.100.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 10 Logging" -Status "Error" `
            -Message "10.5.1: Log protection -- PowerShell Script Block Logging -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='10.5.1'; NIST='AU-12'; CIS='18.9.100.1' }
    }

# ===========================================================================
# Req 11 -- Test Security of Systems and Networks Regularly
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 11 -- Test Security of Systems and Networks Regularly..." -ForegroundColor Yellow

    # 11.3.1: Vulnerability scanning readiness -- Windows Update
    try {
        $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "PCI-DSS - Req 11 Testing" -Status "Pass" `
                -Message "11.3.1: Vulnerability scanning readiness -- Windows Update -- service running" `
                -Details "Req 11.3.1: Systems must be scan-ready with update mechanisms operational" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='11.3.1'; NIST='RA-5' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "PCI-DSS - Req 11 Testing" -Status "Fail" `
                -Message "11.3.1: Vulnerability scanning readiness -- Windows Update -- service not running (Status=$svcSt)" `
                -Details "Req 11.3.1: Systems must be scan-ready with update mechanisms operational" `
                -Remediation "Start-Service -Name wuauserv" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='11.3.1'; NIST='RA-5' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 11 Testing" -Status "Error" `
            -Message "11.3.1: Vulnerability scanning readiness -- Windows Update -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='11.3.1'; NIST='RA-5' }
    }
    # 11.5.1: IDS/IPS readiness -- network protection enabled
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Default $null
        if ($null -ne $val -and $val -eq 1) {
            Add-Result -Category "PCI-DSS - Req 11 Testing" -Status "Pass" `
                -Message "11.5.1: IDS/IPS readiness -- network protection enabled -- properly configured" `
                -Details "Req 11.5.1: Network-based intrusion detection capabilities must be present in CDE" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='11.5.1'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
        } else {
            Add-Result -Category "PCI-DSS - Req 11 Testing" -Status "Fail" `
                -Message "11.5.1: IDS/IPS readiness -- network protection enabled -- not configured (Value=$val)" `
                -Details "Req 11.5.1: Network-based intrusion detection capabilities must be present in CDE" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" `
                -CrossReferences @{ 'PCI-DSS'='11.5.1'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 11 Testing" -Status "Error" `
            -Message "11.5.1: IDS/IPS readiness -- network protection enabled -- check failed: $_" `
            -Severity "High" `
            -CrossReferences @{ 'PCI-DSS'='11.5.1'; NIST='SI-4'; CIS='18.9.47.5.3.1' }
    }

# ===========================================================================
# Req 12 -- Support Information Security with Policies and Programs
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 12 -- Support Information Security with Policies and Programs..." -ForegroundColor Yellow

    # 12.1.1: Security policy -- legal notice banner
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Default $null
        if ($null -ne $val -and $val -ne "") {
            Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Pass" `
                -Message "12.1.1: Security policy -- legal notice banner -- properly configured" `
                -Details "Req 12.1.1: Systems must display security policy notice at login" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='12.1.1'; NIST='AC-8'; ISO27001='A.5.10' }
        } else {
            Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Fail" `
                -Message "12.1.1: Security policy -- legal notice banner -- not configured (Value=$val)" `
                -Details "Req 12.1.1: Systems must display security policy notice at login" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'Authorized use only. All activity is monitored.'" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='12.1.1'; NIST='AC-8'; ISO27001='A.5.10' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Error" `
            -Message "12.1.1: Security policy -- legal notice banner -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='12.1.1'; NIST='AC-8'; ISO27001='A.5.10' }
    }
    # 12.1.2: Security policy -- legal notice caption
    try {
        $val = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Default $null
        if ($null -ne $val -and $val -ne "") {
            Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Pass" `
                -Message "12.1.2: Security policy -- legal notice caption -- properly configured" `
                -Details "Req 12.1.2: Login banner must include title identifying the security notice" `
                -Severity "Low" `
                -CrossReferences @{ 'PCI-DSS'='12.1.2'; NIST='AC-8'; CIS='2.3.7.4' }
        } else {
            Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Fail" `
                -Message "12.1.2: Security policy -- legal notice caption -- not configured (Value=$val)" `
                -Details "Req 12.1.2: Login banner must include title identifying the security notice" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeCaption -Value 'Security Notice'" `
                -Severity "Low" `
                -CrossReferences @{ 'PCI-DSS'='12.1.2'; NIST='AC-8'; CIS='2.3.7.4' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Error" `
            -Message "12.1.2: Security policy -- legal notice caption -- check failed: $_" `
            -Severity "Low" `
            -CrossReferences @{ 'PCI-DSS'='12.1.2'; NIST='AC-8'; CIS='2.3.7.4' }
    }
    # 12.10.1: Incident response -- Event Collector service
    try {
        $svc = Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq "Running") {
            Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Pass" `
                -Message "12.10.1: Incident response -- Event Collector service -- service running" `
                -Details "Req 12.10.1: Event collection capability supports incident response procedures" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='12.10.1'; NIST='IR-4'; SOC2='CC7.3' }
        } else {
            $svcSt = if ($null -ne $svc) { $svc.Status } else { "Not Found" }
            Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Info" `
                -Message "12.10.1: Incident response -- Event Collector service -- service not running (Status=$svcSt)" `
                -Details "Req 12.10.1: Event collection capability supports incident response procedures" `
                -Remediation "Start-Service -Name Wecsvc; Set-Service -Name Wecsvc -StartupType Automatic" `
                -Severity "Medium" `
                -CrossReferences @{ 'PCI-DSS'='12.10.1'; NIST='IR-4'; SOC2='CC7.3' }
        }
    } catch {
        Add-Result -Category "PCI-DSS - Req 12 Policies" -Status "Error" `
            -Message "12.10.1: Incident response -- Event Collector service -- check failed: $_" `
            -Severity "Medium" `
            -CrossReferences @{ 'PCI-DSS'='12.10.1'; NIST='IR-4'; SOC2='CC7.3' }
    }


# ===========================================================================
# v6.1: PCI DSS v4.0/v4.0.1 Customized Approach support
# ===========================================================================
Write-Host "[PCI-DSS] Checking PCI DSS v4.0/v4.0.1 Customized Approach indicators..." -ForegroundColor Yellow

try {
    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Pass" `
            -Severity "High" `
            -Message "Req 3.5.1 Customized Approach: encryption controls implemented" `
            -Details "PCI DSS v4.0.1 effective March 2025; Customized Approach permits alternative implementations meeting Customized Approach Objectives" `
            -CrossReferences @{ PCIDSS='3.5.1'; PCIDSS_v40='Customized Approach'; Version='4.0.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Fail" `
            -Severity "Critical" `
            -Message "Req 3.5.1 No drive encryption (PAN protection insufficient)" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ PCIDSS='3.5.1'; PCIDSS_v40='Customized Approach' }
    }

    $tlsv12Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default $null
    if ($null -eq $tlsv12Server -or $tlsv12Server -eq 1) {
        Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Pass" `
            -Severity "High" `
            -Message "Req 4.2.1 Strong cryptography for transmission (TLS 1.2 available)" `
            -CrossReferences @{ PCIDSS='4.2.1'; Version='4.0.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Fail" `
            -Severity "Critical" `
            -Message "Req 4.2.1 TLS 1.2 disabled server-side" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -Type DWord" `
            -CrossReferences @{ PCIDSS='4.2.1' }
    }

    $tlsv10 = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
    if ($tlsv10 -eq 0) {
        Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Pass" `
            -Severity "High" `
            -Message "Req 2.2.5 Insecure protocol disabled (TLS 1.0)" `
            -CrossReferences @{ PCIDSS='2.2.5' }
    }
    elseif ($tlsv10 -eq 1) {
        Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Fail" `
            -Severity "Critical" `
            -Message "Req 2.2.5 TLS 1.0 enabled (insecure protocol forbidden)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -Type DWord" `
            -CrossReferences @{ PCIDSS='2.2.5' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - v4.0 Customized Approach" -Status "Error" `
        -Severity "Medium" `
        -Message "Customized Approach indicator assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: SAQ type indicator
# ===========================================================================
Write-Host "[PCI-DSS] Checking SAQ environment indicators..." -ForegroundColor Yellow

try {
    $iisService = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    $sqlService = Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue
    $sqlExpress = Get-Service -Name 'MSSQL$*' -ErrorAction SilentlyContinue

    $hasWebServer = ($iisService -and $iisService.Status -eq 'Running')
    $hasDatabase = (($sqlService -and $sqlService.Status -eq 'Running') -or ($sqlExpress -and ($sqlExpress | Where-Object { $_.Status -eq 'Running' })))

    if ($hasWebServer -and $hasDatabase) {
        Add-Result -Category "PCI-DSS - SAQ Indicator" -Status "Info" `
            -Severity "Informational" `
            -Message "SAQ Indicator: Web server + database detected (likely SAQ A-EP, SAQ D-Merchant, or full PCI DSS scope)" `
            -Details "Self-Assessment Questionnaire selection depends on payment channel; consult acquirer/QSA" `
            -CrossReferences @{ PCIDSS='SAQ'; PCISSC='SAQ Guidance' }
    }
    elseif ($hasWebServer) {
        Add-Result -Category "PCI-DSS - SAQ Indicator" -Status "Info" `
            -Severity "Informational" `
            -Message "SAQ Indicator: Web server present without database (possible SAQ A-EP if redirect/iframe processing)" `
            -CrossReferences @{ PCIDSS='SAQ' }
    }
    elseif ($hasDatabase) {
        Add-Result -Category "PCI-DSS - SAQ Indicator" -Status "Info" `
            -Severity "Informational" `
            -Message "SAQ Indicator: Database present without web server (possible storage system in scope)" `
            -CrossReferences @{ PCIDSS='SAQ' }
    }
    else {
        Add-Result -Category "PCI-DSS - SAQ Indicator" -Status "Info" `
            -Severity "Informational" `
            -Message "SAQ Indicator: No web/database services running (workstation or non-CDE server)" `
            -CrossReferences @{ PCIDSS='SAQ' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - SAQ Indicator" -Status "Error" `
        -Severity "Low" `
        -Message "SAQ indicator detection failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Cardholder data discovery readiness
# ===========================================================================
Write-Host "[PCI-DSS] Checking cardholder data discovery readiness..." -ForegroundColor Yellow

try {
    $auditFileAccess = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -like '*File System*' }
    if ($auditFileAccess -and $auditFileAccess.Setting -ne 'No Auditing') {
        Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 3.2.1 File access auditing supports CHD discovery investigations" `
            -Details "PCI DSS v4.0 Req 3.2.1 requires identification and removal of stored sensitive authentication data" `
            -CrossReferences @{ PCIDSS='3.2.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Fail" `
            -Severity "High" `
            -Message "Req 3.2.1 File system auditing inactive (CHD discovery impaired)" `
            -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
            -CrossReferences @{ PCIDSS='3.2.1' }
    }

    $defenderStatus = Get-DefenderStatus -Cache $SharedData.Cache
    if ($defenderStatus) {
        Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 5.2.1 Anti-malware mechanism present (file content inspection capable)" `
            -CrossReferences @{ PCIDSS='5.2.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Fail" `
            -Severity "Critical" `
            -Message "Req 5.2.1 Anti-malware mechanism not present" `
            -CrossReferences @{ PCIDSS='5.2.1' }
    }

    $secLogSize = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Default 0
    if ($secLogSize -ge 1073741824) {
        $secLogMB = [Math]::Round($secLogSize / 1MB, 0)
        Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 10.5.1 One year of audit log retention supported (${secLogMB} MB)" `
            -CrossReferences @{ PCIDSS='10.5.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Warning" `
            -Severity "High" `
            -Message "Req 10.5.1 Local audit log capacity below one-year retention baseline" `
            -Details "PCI DSS v4.0 Req 10.5.1 requires audit log history retention for at least 12 months" `
            -Remediation "wevtutil sl Security /ms:1073741824" `
            -CrossReferences @{ PCIDSS='10.5.1' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - CHD Discovery" -Status "Error" `
        -Severity "Medium" `
        -Message "CHD discovery readiness assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Network segmentation validation indicators
# ===========================================================================
Write-Host "[PCI-DSS] Checking network segmentation validation indicators..." -ForegroundColor Yellow

try {
    $fwProfiles = Get-CachedFirewallStatus -Cache $SharedData.Cache
    if ($fwProfiles) {
        $disabled = @($fwProfiles | Where-Object { -not $_.Enabled })
        if ($disabled.Count -eq 0) {
            Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Pass" `
                -Severity "High" `
                -Message "Req 1.4.1 Host firewall enabled across all profiles (segmentation enforcement)" `
                -CrossReferences @{ PCIDSS='1.4.1' }
        }
        else {
            $names = ($disabled.Name -join ', ')
            Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Fail" `
                -Severity "High" `
                -Message "Req 1.4.1 Firewall disabled on profile(s): $names" `
                -Remediation "Set-NetFirewallProfile -Profile $names -Enabled True" `
                -CrossReferences @{ PCIDSS='1.4.1' }
        }
    }

    $listening = Get-ListeningPorts -Cache $SharedData.Cache
    if ($listening) {
        $publicListeners = @($listening | Where-Object { $_.LocalAddress -in @('0.0.0.0','::') })
        $publicPortCount = $publicListeners.Count
        if ($publicPortCount -gt 20) {
            Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Warning" `
                -Severity "Medium" `
                -Message "Req 1.2.1 Network attack surface elevated ($publicPortCount listeners on all interfaces)" `
                -Details "PCI DSS Req 1.2.1 requires explicit justification for permitted services and ports" `
                -CrossReferences @{ PCIDSS='1.2.1' }
        }
        else {
            Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Pass" `
                -Severity "Low" `
                -Message "Req 1.2.1 Network listeners within expected baseline ($publicPortCount on all interfaces)" `
                -CrossReferences @{ PCIDSS='1.2.1' }
        }
    }

    $netBios = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Default 1
    if ($netBios -eq 2) {
        Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 1.2.6 Insecure protocol restricted: NetBIOS broadcast disabled" `
            -CrossReferences @{ PCIDSS='1.2.6' }
    }
    else {
        Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Warning" `
            -Severity "Medium" `
            -Message "Req 1.2.6 NetBIOS broadcast permitted" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Value 2 -Type DWord" `
            -CrossReferences @{ PCIDSS='1.2.6' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - Network Segmentation" -Status "Error" `
        -Severity "Medium" `
        -Message "Network segmentation validation failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Sensitive Authentication Data (SAD) post-authorization storage
# ===========================================================================
Write-Host "[PCI-DSS] Checking SAD storage prohibition indicators..." -ForegroundColor Yellow

try {
    $auditObjAccess = Get-CachedAuditPolicy -Cache $SharedData.Cache | Where-Object { $_.Subcategory -like '*File System*' }
    if ($auditObjAccess -and $auditObjAccess.Setting -ne 'No Auditing') {
        Add-Result -Category "PCI-DSS - SAD Prohibition" -Status "Pass" `
            -Severity "High" `
            -Message "Req 3.3.1 Sensitive Authentication Data prohibition: file write auditing detects SAD storage" `
            -Details "PCI DSS Req 3.3.1 prohibits storage of full track data, CAV2/CVC2/CVV2/CID, or PIN/PIN block after authorization" `
            -CrossReferences @{ PCIDSS='3.3.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - SAD Prohibition" -Status "Warning" `
            -Severity "High" `
            -Message "Req 3.3.1 File system auditing inactive (SAD storage detection impaired)" `
            -Remediation "auditpol /set /subcategory:'File System' /success:enable /failure:enable" `
            -CrossReferences @{ PCIDSS='3.3.1' }
    }

    $defenderStatus = Get-DefenderStatus -Cache $SharedData.Cache
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "PCI-DSS - SAD Prohibition" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 3.3.1.1 Anti-malware can scan for SAD-bearing payloads" `
            -CrossReferences @{ PCIDSS='3.3.1.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - SAD Prohibition" -Status "Fail" `
            -Severity "Critical" `
            -Message "Req 3.3.1.1 Real-time anti-malware not active" `
            -CrossReferences @{ PCIDSS='3.3.1.1' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - SAD Prohibition" -Status "Error" `
        -Severity "Medium" `
        -Message "SAD prohibition assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: Requirement 9 Physical Security technical evidence
# ===========================================================================
Write-Host "[PCI-DSS] Checking Req 9 physical security technical evidence..." -ForegroundColor Yellow

try {
    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Pass" `
            -Severity "High" `
            -Message "Req 9.5.1 Physical media protection: drive encryption mitigates theft" `
            -CrossReferences @{ PCIDSS='9.5.1' }
    }
    else {
        Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Fail" `
            -Severity "High" `
            -Message "Req 9.5.1 No drive encryption (physical theft of CHD risk)" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ PCIDSS='9.5.1' }
    }

    $autoPlay = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default 0
    if ($autoPlay -eq 255) {
        Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 9.4.6 Removable media: AutoPlay disabled across all drive types" `
            -CrossReferences @{ PCIDSS='9.4.6' }
    }
    else {
        Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Warning" `
            -Severity "Medium" `
            -Message "Req 9.4.6 AutoPlay not fully disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord" `
            -CrossReferences @{ PCIDSS='9.4.6' }
    }

    $idleTimeout = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default 0
    if ($idleTimeout -gt 0 -and $idleTimeout -le 900) {
        Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Pass" `
            -Severity "Medium" `
            -Message "Req 8.2.8 Console session lock at $idleTimeout seconds (physical access mitigation)" `
            -CrossReferences @{ PCIDSS='8.2.8' }
    }
    else {
        Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Fail" `
            -Severity "High" `
            -Message "Req 8.2.8 Inactivity timeout absent or excessive ($idleTimeout seconds)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord" `
            -CrossReferences @{ PCIDSS='8.2.8' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - Req 9 Physical" -Status "Error" `
        -Severity "Medium" `
        -Message "Req 9 physical security assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: PCI PIN Security and 3DS Core Standard alignment
# ===========================================================================
Write-Host "[PCI-DSS] Checking PIN Security and 3DS technical alignment..." -ForegroundColor Yellow

try {
    $fipsPolicy = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -Default 0
    if ($fipsPolicy -eq 1) {
        Add-Result -Category "PCI-DSS - PIN Security" -Status "Pass" `
            -Severity "High" `
            -Message "PIN Security Req 32-9: FIPS-validated cryptography active" `
            -Details "PCI PIN Security Requirements v3.1 mandate use of FIPS-approved cryptographic modules" `
            -CrossReferences @{ PCIPIN='32-9'; PCISSC='PIN Security' }
    }
    else {
        Add-Result -Category "PCI-DSS - PIN Security" -Status "Warning" `
            -Severity "High" `
            -Message "PIN Security Req 32-9: FIPS-only cryptography mode not enforced" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled' -Value 1 -Type DWord; Restart-Computer" `
            -CrossReferences @{ PCIPIN='32-9' }
    }

    $tpm = Get-CimInstance -Namespace 'root\CIMv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.IsActivated_InitialValue) {
        Add-Result -Category "PCI-DSS - PIN Security" -Status "Pass" `
            -Severity "High" `
            -Message "PIN Security: hardware key storage available (TPM activated)" `
            -CrossReferences @{ PCIPIN='Hardware Crypto' }
    }
    else {
        Add-Result -Category "PCI-DSS - PIN Security" -Status "Warning" `
            -Severity "High" `
            -Message "PIN Security: TPM not activated (hardware-backed keys unavailable)" `
            -CrossReferences @{ PCIPIN='Hardware Crypto' }
    }

    $tlsv12Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default $null
    if ($null -eq $tlsv12Server -or $tlsv12Server -eq 1) {
        Add-Result -Category "PCI-DSS - 3DS Core" -Status "Pass" `
            -Severity "High" `
            -Message "3DS Core Req P1: TLS 1.2 minimum for 3D Secure messages" `
            -Details "PCI 3DS Core Security Standard P1 mandates TLS 1.2 or higher for 3DS protocol messages" `
            -CrossReferences @{ PCI3DS='P1'; PCISSC='3DS Core' }
    }
    else {
        Add-Result -Category "PCI-DSS - 3DS Core" -Status "Fail" `
            -Severity "Critical" `
            -Message "3DS Core Req P1: TLS 1.2 disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -Type DWord" `
            -CrossReferences @{ PCI3DS='P1' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - PIN Security" -Status "Error" `
        -Severity "Medium" `
        -Message "PIN Security and 3DS assessment failed: $($_.Exception.Message)"
}

# ===========================================================================
# v6.1: PCI Software Security Framework (SSF) alignment
# ===========================================================================
Write-Host "[PCI-DSS] Checking Software Security Framework technical indicators..." -ForegroundColor Yellow

try {
    $auditPS = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default 0
    if ($auditPS -eq 1) {
        Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Pass" `
            -Severity "Medium" `
            -Message "SSF SLC Sec.5: Script execution traceability for software lifecycle audit" `
            -Details "PCI Software Security Framework Secure Software Lifecycle (SLC) Standard covers software production controls" `
            -CrossReferences @{ PCISSF='SLC-5'; PCISSC='SSF' }
    }
    else {
        Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Warning" `
            -Severity "Medium" `
            -Message "SSF SLC: PowerShell script logging disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord" `
            -CrossReferences @{ PCISSF='SLC-5' }
    }

    $autoUpdate = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Default 0
    if ($autoUpdate -eq 0) {
        Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Pass" `
            -Severity "High" `
            -Message "SSF SSS Sec.10: Patch management mechanism active" `
            -Details "PCI Secure Software Standard Sec.10 covers vulnerability remediation processes" `
            -CrossReferences @{ PCISSF='SSS-10' }
    }
    else {
        Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Fail" `
            -Severity "High" `
            -Message "SSF SSS Sec.10: Automatic patching disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0 -Type DWord" `
            -CrossReferences @{ PCISSF='SSS-10' }
    }

    $sbEnabled = Test-SecureBootEnabled
    if ($sbEnabled) {
        Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Pass" `
            -Severity "High" `
            -Message "SSF SSS Sec.4: Software integrity protection (Secure Boot active)" `
            -CrossReferences @{ PCISSF='SSS-4' }
    }
    else {
        Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Fail" `
            -Severity "High" `
            -Message "SSF SSS Sec.4: Secure Boot inactive (boot-stage software integrity gap)" `
            -CrossReferences @{ PCISSF='SSS-4' }
    }
}
catch {
    Add-Result -Category "PCI-DSS - SSF Alignment" -Status "Error" `
        -Severity "Medium" `
        -Message "SSF alignment assessment failed: $($_.Exception.Message)"
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
Write-Host "  [PCI-DSS] PCI DSS v4.0 Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
    Write-Host "  PCI DSS v4.0 Module -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[PCI-DSS] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  PCI-DSS module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
