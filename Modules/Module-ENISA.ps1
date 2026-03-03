# module-enisa.ps1
# ENISA Cybersecurity Guidelines Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against ENISA (European Union Agency for
# Cybersecurity) guidelines and recommendations with Severity ratings
# and cross-framework references.

<#
.SYNOPSIS
    ENISA cybersecurity guidelines compliance checks for Windows systems.

.DESCRIPTION
    This module assesses alignment with ENISA cybersecurity recommendations including:
    - GP.1: Network Security (firewall, segmentation, protocol hardening)
    - GP.2: Identity and Access Management (accounts, passwords, privileges)
    - GP.3: Patch and Vulnerability Management (OS updates, application patches)
    - GP.4: Cryptographic Controls (encryption, TLS, certificate management)
    - GP.5: Logging and Monitoring (event logs, audit policy, retention)
    - GP.6: Data Protection (BitLocker, backup, data classification)
    - GP.7: Incident Response Readiness (event forwarding, recovery)
    - GP.8: System Hardening (services, features, attack surface)
    - GP.9: Email and Web Security (SmartScreen, browser hardening)
    - GP.10: Endpoint Protection (antivirus, EDR, exploit mitigation)

    Each result includes Severity (Critical/High/Medium/Low/Informational)
    and CrossReferences mapping to related frameworks.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: ENISA Good Practices for IoT and Smart Infrastructures (2019),
                ENISA Threat Landscape (2023), EU Cybersecurity Act (2019/881)
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-enisa.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "ENISA"
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

Write-Host "`n[$moduleName] Starting ENISA cybersecurity guideline checks (v$moduleVersion)..." -ForegroundColor Cyan

# ===========================================================================
# GP.1 -- Network Security
# ===========================================================================
Write-Host "[ENISA] Checking GP.1 -- Network Security..." -ForegroundColor Yellow

    # GP.1.1: Firewall -- Domain profile enabled
    try {
        $domainFw = (Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue).Enabled
        if ($domainFw -eq $true) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.1: Windows Firewall Domain profile is enabled" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; CIS='9.1.1' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.1: Windows Firewall Domain profile is DISABLED" `
                -Remediation "Set-NetFirewallProfile -Name Domain -Enabled True" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; CIS='9.1.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.1: Firewall Domain profile check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.2: Firewall -- Private profile enabled
    try {
        $privateFw = (Get-NetFirewallProfile -Name Private -ErrorAction SilentlyContinue).Enabled
        if ($privateFw -eq $true) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.2: Windows Firewall Private profile is enabled" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; CIS='9.2.1' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.2: Windows Firewall Private profile is DISABLED" `
                -Remediation "Set-NetFirewallProfile -Name Private -Enabled True" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; CIS='9.2.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.2: Firewall Private profile check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.3: Firewall -- Public profile enabled
    try {
        $publicFw = (Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue).Enabled
        if ($publicFw -eq $true) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.3: Windows Firewall Public profile is enabled" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; CIS='9.3.1' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.3: Windows Firewall Public profile is DISABLED" `
                -Remediation "Set-NetFirewallProfile -Name Public -Enabled True" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; CIS='9.3.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.3: Firewall Public profile check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.4: Firewall -- Default inbound block (Domain)
    try {
        $defaultIn = (Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue).DefaultInboundAction
        if ($defaultIn -eq 'Block' -or $defaultIn -eq 1) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.4: Firewall Domain profile blocks inbound by default" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7(5)'; CIS='9.1.2' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.4: Firewall Domain profile does NOT block inbound by default" `
                -Remediation "Set-NetFirewallProfile -Name Domain -DefaultInboundAction Block" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7(5)'; CIS='9.1.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.4: Firewall default inbound check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7(5)' }
    }
    # GP.1.5: SMBv1 protocol disabled
    try {
        $smbv1Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Default $null
        $smbv1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $smbDisabled = ($smbv1Server -eq 0) -or ($null -ne $smbv1Feature -and $smbv1Feature.State -eq 'Disabled')
        if ($smbDisabled) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.5: SMBv1 protocol is disabled" `
                -Details "Legacy SMB protocol is a significant attack vector (WannaCry, EternalBlue)" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; STIG='V-73299' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.5: SMBv1 protocol is ENABLED -- critical security risk" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; STIG='V-73299' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.5: SMBv1 check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.6: SMB signing required
    try {
        $smbSign = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default 0
        if ($smbSign -eq 1) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.6: SMB signing is required on server" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8'; CIS='2.3.9.2' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.6: SMB signing is NOT required" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8'; CIS='2.3.9.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.6: SMB signing check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8' }
    }
    # GP.1.7: LLMNR disabled
    try {
        $llmnr = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default $null
        if ($null -ne $llmnr -and $llmnr -eq 0) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.7: LLMNR is disabled (prevents name resolution poisoning)" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; NSA='LLMNR' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.7: LLMNR is ENABLED -- vulnerable to poisoning attacks" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; NSA='LLMNR' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.7: LLMNR check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.8: NetBIOS over TCP/IP disabled
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
        $nbEnabled = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
        if ($nbEnabled.Count -eq 0 -and $null -ne $adapters) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.8: NetBIOS over TCP/IP is disabled on all adapters" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; NSA='NetBIOS' }
        } else {
            $nbCount = $nbEnabled.Count
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Warning" `
                -Message "GP.1.8: NetBIOS over TCP/IP is enabled on $nbCount adapter(s)" `
                -Remediation "Disable NetBIOS via adapter properties or DHCP option 001" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; NSA='NetBIOS' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.8: NetBIOS check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.9: Remote Desktop NLA required
    try {
        $nla = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default 0
        if ($nla -eq 1) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.9: Network Level Authentication (NLA) is required for RDP" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='IA-2'; CIS='18.9.65.3.9.2' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Fail" `
                -Message "GP.1.9: NLA is NOT required for RDP -- vulnerable to pre-auth attacks" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='IA-2'; CIS='18.9.65.3.9.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.9: RDP NLA check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='IA-2' }
    }
    # GP.1.10: IPv6 source routing disabled
    try {
        $ipv6sr = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Default $null
        if ($null -ne $ipv6sr -and $ipv6sr -eq 2) {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                -Message "GP.1.10: IPv6 source routing is fully disabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; STIG='V-73503' }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Warning" `
                -Message "GP.1.10: IPv6 source routing is not fully disabled (value=$ipv6sr)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisableIPSourceRouting -Value 2" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7'; STIG='V-73503' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.10: IPv6 source routing check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.1'; NIST='SC-7' }
    }
    # GP.1.11: WinRM service hardened
    try {
        $winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        $winrmHTTPS = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Default $null
        if ($null -ne $winrmSvc -and $winrmSvc.Status -eq 'Running') {
            if ($null -ne $winrmHTTPS -and $winrmHTTPS -eq 0) {
                Add-Result -Category "ENISA - GP.1 Network Security" -Status "Pass" `
                    -Message "GP.1.11: WinRM is running with encrypted traffic enforced" `
                    -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8'; CIS='18.9.102.1.1' }
            } else {
                Add-Result -Category "ENISA - GP.1 Network Security" -Status "Warning" `
                    -Message "GP.1.11: WinRM is running but unencrypted traffic may be allowed" `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Value 0" `
                    -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8'; CIS='18.9.102.1.1' }
            }
        } else {
            Add-Result -Category "ENISA - GP.1 Network Security" -Status "Info" `
                -Message "GP.1.11: WinRM service is not running" `
                -Severity "Informational" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.1 Network Security" -Status "Error" `
            -Message "GP.1.11: WinRM hardening check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.1'; NIST='SC-8' }
    }

# ===========================================================================
# GP.2 -- Identity and Access Management
# ===========================================================================
Write-Host "[ENISA] Checking GP.2 -- Identity and Access Management..." -ForegroundColor Yellow

    # GP.2.1: Guest account disabled
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -ne $guest -and $guest.Enabled -eq $false) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.1: Guest account is disabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-2'; CIS='1.1.1' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.1: Guest account is ENABLED -- unauthorized access risk" `
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-2'; CIS='1.1.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.1: Guest account check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-2' }
    }
    # GP.2.2: Administrator account renamed
    try {
        $admin = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' } | Select-Object -First 1
        if ($null -ne $admin -and $admin.Name -ne 'Administrator') {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.2: Built-in Administrator account has been renamed to '$($admin.Name)'" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='AC-2'; CIS='1.1.2' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Warning" `
                -Message "GP.2.2: Built-in Administrator account has default name" `
                -Remediation "Rename-LocalUser -Name Administrator -NewName [unique_name]" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='AC-2'; CIS='1.1.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.2: Administrator rename check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='AC-2' }
    }
    # GP.2.3: Password minimum length (14+)
    try {
        $secPol = & net accounts 2>&1
        $minLen = ($secPol | Select-String "Minimum password length").ToString() -replace '\D',''
        $minLen = [int]$minLen
        if ($minLen -ge 14) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.3: Minimum password length is $minLen characters" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5'; CIS='1.1.4' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.3: Minimum password length is $minLen (ENISA recommends 14+)" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5'; CIS='1.1.4' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.3: Password length check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5' }
    }
    # GP.2.4: Password complexity enabled
    try {
        $complexity = ($secPol | Select-String -Pattern "complexity" -SimpleMatch)
        $complexOn = $null -ne $complexity -and $complexity.ToString() -match '(Yes|1|Enabled)'
        if ($complexOn) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.4: Password complexity requirements are enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5(1)'; CIS='1.1.5' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.4: Password complexity requirements are NOT enabled" `
                -Remediation "Enable via Local Security Policy or GPO" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5(1)'; CIS='1.1.5' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.4: Password complexity check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5(1)' }
    }
    # GP.2.5: Account lockout threshold
    try {
        $lockThresh = ($secPol | Select-String "Lockout threshold").ToString() -replace '\D',''
        $lockThresh = if ($lockThresh) { [int]$lockThresh } else { 0 }
        if ($lockThresh -gt 0 -and $lockThresh -le 5) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.5: Account lockout threshold is $lockThresh attempts" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-7'; CIS='1.2.1' }
        } elseif ($lockThresh -gt 5) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Warning" `
                -Message "GP.2.5: Account lockout threshold is $lockThresh (ENISA recommends 5 or fewer)" `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='AC-7'; CIS='1.2.1' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.5: Account lockout is NOT configured -- brute force risk" `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-7'; CIS='1.2.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.5: Account lockout check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-7' }
    }
    # GP.2.6: UAC enabled
    try {
        $uac = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default 0
        if ($uac -eq 1) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.6: User Account Control (UAC) is enabled" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.2'; NIST='AC-6'; CIS='2.3.17.6' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.6: UAC is DISABLED -- privilege escalation risk" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.2'; NIST='AC-6'; CIS='2.3.17.6' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.6: UAC check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.2'; NIST='AC-6' }
    }
    # GP.2.7: Administrator group membership
    try {
        $admins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
        $adminCount = $admins.Count
        if ($adminCount -le 3) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.7: Administrator group has $adminCount member(s) -- appropriate" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-6(5)'; CIS='1.1.3' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Warning" `
                -Message "GP.2.7: Administrator group has $adminCount members -- review needed" `
                -Remediation "Review and minimize administrator group membership" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-6(5)'; CIS='1.1.3' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.7: Admin group membership check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='AC-6(5)' }
    }
    # GP.2.8: Password history (24+)
    try {
        $pwHist = ($secPol | Select-String "password history").ToString() -replace '\D',''
        $pwHist = if ($pwHist) { [int]$pwHist } else { 0 }
        if ($pwHist -ge 24) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.8: Password history enforces $pwHist unique passwords" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5(1)'; CIS='1.1.1' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.8: Password history is $pwHist (ENISA recommends 24+)" `
                -Remediation "net accounts /uniquepw:24" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5(1)'; CIS='1.1.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.8: Password history check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.2'; NIST='IA-5(1)' }
    }
    # GP.2.9: LSA protection (RunAsPPL)
    try {
        $runAsPPL = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default 0
        if ($runAsPPL -eq 1) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.9: LSA protection (RunAsPPL) is enabled" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.2'; NIST='SC-4'; NSA='LSA' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Fail" `
                -Message "GP.2.9: LSA protection is NOT enabled -- credential theft risk" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.2'; NIST='SC-4'; NSA='LSA' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.9: LSA protection check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.2'; NIST='SC-4' }
    }
    # GP.2.10: Credential Guard
    try {
        $credGuard = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Default 0
        $lsaCfg = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Default 0
        if ($credGuard -eq 1 -and $lsaCfg -ge 1) {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Pass" `
                -Message "GP.2.10: Credential Guard is enabled (VBS=$credGuard, LsaCfg=$lsaCfg)" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='SC-39'; NSA='CredGuard' }
        } else {
            Add-Result -Category "ENISA - GP.2 IAM" -Status "Warning" `
                -Message "GP.2.10: Credential Guard is not fully configured (VBS=$credGuard, LsaCfg=$lsaCfg)" `
                -Remediation "Enable via Group Policy: Device Guard `> Turn On Virtualization Based Security" `
                -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='SC-39'; NSA='CredGuard' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.2 IAM" -Status "Error" `
            -Message "GP.2.10: Credential Guard check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.2'; NIST='SC-39' }
    }

# ===========================================================================
# GP.3 -- Patch and Vulnerability Management
# ===========================================================================
Write-Host "[ENISA] Checking GP.3 -- Patch and Vulnerability Management..." -ForegroundColor Yellow

    # GP.3.1: Windows Update service running
    try {
        $wuSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($null -ne $wuSvc -and $wuSvc.Status -eq 'Running') {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Pass" `
                -Message "GP.3.1: Windows Update service is running" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; CIS='18.9.101' }
        } else {
            $svcStatus = if ($null -ne $wuSvc) { $wuSvc.Status } else { "Not Found" }
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Fail" `
                -Message "GP.3.1: Windows Update service is not running (status: $svcStatus)" `
                -Remediation "Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; CIS='18.9.101' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Error" `
            -Message "GP.3.1: Windows Update service check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
    }
    # GP.3.2: Recent hotfix installation
    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
        if ($null -ne $hotfixes -and $hotfixes.Count -gt 0) {
            $latestHotfix = $hotfixes[0]
            $daysSince = if ($null -ne $latestHotfix.InstalledOn) { ((Get-Date) - $latestHotfix.InstalledOn).Days } else { 999 }
            if ($daysSince -le 30) {
                Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Pass" `
                    -Message "GP.3.2: Latest hotfix installed $daysSince day(s) ago -- $($latestHotfix.HotFixID)" `
                    -Severity "Critical" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; ISO27001='A.8.8' }
            } elseif ($daysSince -le 60) {
                Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Warning" `
                    -Message "GP.3.2: Latest hotfix is $daysSince days old -- $($latestHotfix.HotFixID)" `
                    -Remediation "Run Windows Update to install latest patches" `
                    -Severity "High" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; ISO27001='A.8.8' }
            } else {
                Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Fail" `
                    -Message "GP.3.2: System is $daysSince days behind on updates -- $($latestHotfix.HotFixID)" `
                    -Remediation "Immediately run Windows Update" `
                    -Severity "Critical" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; ISO27001='A.8.8' }
            }
        } else {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Warning" `
                -Message "GP.3.2: No hotfix information available" `
                -Severity "High" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Error" `
            -Message "GP.3.2: Hotfix check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
    }
    # GP.3.3: Auto-update configuration
    try {
        $auOpt = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Default 0
        if ($auOpt -eq 0) {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Pass" `
                -Message "GP.3.3: Automatic updates are not disabled by policy" `
                -Severity "High" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; CIS='18.9.101.2' }
        } else {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Fail" `
                -Message "GP.3.3: Automatic updates are DISABLED by policy" `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate" `
                -Severity "High" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2'; CIS='18.9.101.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Error" `
            -Message "GP.3.3: Auto-update check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
    }
    # GP.3.4: PowerShell version current
    try {
        $psVer = $PSVersionTable.PSVersion
        if ($psVer.Major -ge 7) {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Pass" `
                -Message "GP.3.4: PowerShell version $psVer is current" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
        } elseif ($psVer.Major -eq 5 -and $psVer.Minor -ge 1) {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Info" `
                -Message "GP.3.4: PowerShell $psVer -- consider upgrading to PowerShell 7+" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
        } else {
            Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Warning" `
                -Message "GP.3.4: PowerShell $psVer is outdated -- upgrade recommended" `
                -Remediation "Install latest PowerShell from https://github.com/PowerShell/PowerShell" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.3 Patch Mgmt" -Status "Error" `
            -Message "GP.3.4: PowerShell version check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.3'; NIST='SI-2' }
    }

# ===========================================================================
# GP.4 -- Cryptographic Controls
# ===========================================================================
Write-Host "[ENISA] Checking GP.4 -- Cryptographic Controls..." -ForegroundColor Yellow

    # GP.4.1: BitLocker system drive
    try {
        $blVol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($null -ne $blVol -and $blVol.ProtectionStatus -eq 'On') {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Pass" `
                -Message "GP.4.1: System drive is encrypted with BitLocker `($($blVol.EncryptionMethod)`)" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.4'; NIST='SC-28'; ISO27001='A.8.24' }
        } elseif ($null -ne $blVol -and $blVol.VolumeStatus -eq 'EncryptionInProgress') {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Warning" `
                -Message "GP.4.1: System drive encryption is in progress" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-28'; ISO27001='A.8.24' }
        } else {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Fail" `
                -Message "GP.4.1: System drive is NOT encrypted -- data at rest exposure" `
                -Remediation "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.4'; NIST='SC-28'; ISO27001='A.8.24' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Error" `
            -Message "GP.4.1: BitLocker check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.4'; NIST='SC-28' }
    }
    # GP.4.2: TLS 1.0 disabled
    try {
        $tls10Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $tls10Server -and $tls10Server -eq 0) {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Pass" `
                -Message "GP.4.2: TLS 1.0 server is disabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8'; CIS='18.4.2' }
        } else {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Warning" `
                -Message "GP.4.2: TLS 1.0 server may be enabled (not explicitly disabled)" `
                -Remediation "Disable TLS 1.0 via registry under SCHANNEL Protocols" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8'; CIS='18.4.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Error" `
            -Message "GP.4.2: TLS 1.0 check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8' }
    }
    # GP.4.3: TLS 1.1 disabled
    try {
        $tls11Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default $null
        if ($null -ne $tls11Server -and $tls11Server -eq 0) {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Pass" `
                -Message "GP.4.3: TLS 1.1 server is disabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8' }
        } else {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Warning" `
                -Message "GP.4.3: TLS 1.1 server may be enabled (not explicitly disabled)" `
                -Remediation "Disable TLS 1.1 via registry under SCHANNEL Protocols" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Error" `
            -Message "GP.4.3: TLS 1.1 check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8' }
    }
    # GP.4.4: SSL 3.0 disabled
    try {
        $ssl3 = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
        if ($null -ne $ssl3 -and $ssl3 -eq 0) {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Pass" `
                -Message "GP.4.4: SSL 3.0 is disabled (POODLE protection)" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8'; STIG='V-73805' }
        } else {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Warning" `
                -Message "GP.4.4: SSL 3.0 may be enabled -- vulnerable to POODLE" `
                -Remediation "Disable SSL 3.0 via registry under SCHANNEL Protocols" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8'; STIG='V-73805' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Error" `
            -Message "GP.4.4: SSL 3.0 check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-8' }
    }
    # GP.4.5: NULL cipher suites disabled
    try {
        $nullCipher = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Default $null
        if ($null -ne $nullCipher -and $nullCipher -eq 0) {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Pass" `
                -Message "GP.4.5: NULL cipher suites are explicitly disabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-13' }
        } else {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Info" `
                -Message "GP.4.5: NULL cipher status not explicitly configured (OS defaults apply)" `
                -Remediation "Explicitly disable NULL ciphers via SCHANNEL registry" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.4'; NIST='SC-13' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Error" `
            -Message "GP.4.5: NULL cipher check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-13' }
    }
    # GP.4.6: RC4 cipher disabled
    try {
        $rc4_128 = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled" -Default $null
        if ($null -ne $rc4_128 -and $rc4_128 -eq 0) {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Pass" `
                -Message "GP.4.6: RC4 cipher is disabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-13' }
        } else {
            Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Warning" `
                -Message "GP.4.6: RC4 cipher may not be explicitly disabled" `
                -Remediation "Disable RC4 ciphers via SCHANNEL registry" `
                -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-13' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.4 Cryptography" -Status "Error" `
            -Message "GP.4.6: RC4 cipher check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.4'; NIST='SC-13' }
    }

# ===========================================================================
# GP.5 -- Logging and Monitoring
# ===========================================================================
Write-Host "[ENISA] Checking GP.5 -- Logging and Monitoring..." -ForegroundColor Yellow

    # GP.5.1: Security event log size (1024MB+)
    try {
        $secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
        $secLogMB = [Math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
        if ($secLogMB -ge 1024) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.1: Security log size is ${secLogMB}MB (adequate)" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-4'; CIS='18.9.27.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Warning" `
                -Message "GP.5.1: Security log size is ${secLogMB}MB (ENISA recommends 1024MB+)" `
                -Remediation "wevtutil sl Security /ms:1073741824" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-4'; CIS='18.9.27.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.1: Security log size check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-4' }
    }
    # GP.5.2: Audit logon events
    try {
        $auditPol = & auditpol /get /category:* 2>&1
        $logonAudit = $auditPol | Select-String "Logon" | Select-Object -First 1
        $hasAudit = $null -ne $logonAudit -and $logonAudit.ToString() -match '(Success and Failure|Success|Failure)'
        if ($hasAudit) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.2: Logon event auditing is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.5.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Fail" `
                -Message "GP.5.2: Logon event auditing is not fully configured" `
                -Remediation "auditpol /set /subcategory:Logon /success:enable /failure:enable" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.5.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.2: Audit logon check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2' }
    }
    # GP.5.3: Audit privilege use
    try {
        $privAudit = $auditPol | Select-String "Sensitive Privilege Use" | Select-Object -First 1
        $hasPrivAudit = $null -ne $privAudit -and $privAudit.ToString() -match '(Success and Failure|Success|Failure)'
        if ($hasPrivAudit) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.3: Sensitive privilege use auditing is enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.8.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Warning" `
                -Message "GP.5.3: Sensitive privilege use auditing is not configured" `
                -Remediation "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.8.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.3: Privilege use audit check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2' }
    }
    # GP.5.4: Audit account management
    try {
        $acctAudit = $auditPol | Select-String "User Account Management" | Select-Object -First 1
        $hasAcctAudit = $null -ne $acctAudit -and $acctAudit.ToString() -match '(Success and Failure|Success|Failure)'
        if ($hasAcctAudit) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.4: Account management auditing is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.1.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Fail" `
                -Message "GP.5.4: Account management auditing is not configured" `
                -Remediation "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.1.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.4: Account management audit check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2' }
    }
    # GP.5.5: Audit policy change
    try {
        $polAudit = $auditPol | Select-String "Audit Policy Change" | Select-Object -First 1
        $hasPolAudit = $null -ne $polAudit -and $polAudit.ToString() -match '(Success and Failure|Success|Failure)'
        if ($hasPolAudit) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.5: Audit policy change auditing is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.7.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Fail" `
                -Message "GP.5.5: Audit policy change auditing is not configured" `
                -Remediation "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2'; CIS='17.7.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.5: Audit policy change check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-2' }
    }
    # GP.5.6: PowerShell script block logging
    try {
        $sbLog = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default 0
        if ($sbLog -eq 1) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.6: PowerShell script block logging is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3'; CIS='18.9.100.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Fail" `
                -Message "GP.5.6: PowerShell script block logging is NOT enabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3'; CIS='18.9.100.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.6: PowerShell logging check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3' }
    }
    # GP.5.7: PowerShell module logging
    try {
        $modLog = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Default 0
        if ($modLog -eq 1) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.7: PowerShell module logging is enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3'; CIS='18.9.100.2' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Warning" `
                -Message "GP.5.7: PowerShell module logging is not enabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Value 1" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3'; CIS='18.9.100.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.7: PowerShell module logging check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3' }
    }
    # GP.5.8: Command line in process creation events
    try {
        $cmdLine = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Default 0
        if ($cmdLine -eq 1) {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Pass" `
                -Message "GP.5.8: Command line auditing in process creation is enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3'; CIS='18.8.3.1' }
        } else {
            Add-Result -Category "ENISA - GP.5 Logging" -Status "Warning" `
                -Message "GP.5.8: Command line auditing in process creation is not enabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3'; CIS='18.8.3.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.5 Logging" -Status "Error" `
            -Message "GP.5.8: Command line audit check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.5'; NIST='AU-3' }
    }

# ===========================================================================
# GP.6 -- Data Protection
# ===========================================================================
Write-Host "[ENISA] Checking GP.6 -- Data Protection..." -ForegroundColor Yellow

    # GP.6.1: Volume Shadow Copy service
    try {
        $vssSvc = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if ($null -ne $vssSvc -and $vssSvc.StartType -ne 'Disabled') {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Pass" `
                -Message "GP.6.1: Volume Shadow Copy service is available (start type: $($vssSvc.StartType))" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9'; ISO27001='A.8.13' }
        } else {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Warning" `
                -Message "GP.6.1: Volume Shadow Copy service is disabled" `
                -Remediation "Set-Service -Name VSS -StartupType Manual" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9'; ISO27001='A.8.13' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Error" `
            -Message "GP.6.1: VSS check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9' }
    }
    # GP.6.2: System Restore enabled
    try {
        $srDisabled = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Default 0
        if ($srDisabled -ne 1) {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Pass" `
                -Message "GP.6.2: System Restore is enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9'; ISO27001='A.8.13' }
        } else {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Warning" `
                -Message "GP.6.2: System Restore is DISABLED by policy" `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name DisableSR" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9'; ISO27001='A.8.13' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Error" `
            -Message "GP.6.2: System Restore check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9' }
    }
    # GP.6.3: Windows Recycle Bin not disabled
    try {
        $recycleBin = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -Default 0
        if ($recycleBin -ne 1) {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Pass" `
                -Message "GP.6.3: Recycle Bin is enabled (data recovery available)" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9' }
        } else {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Info" `
                -Message "GP.6.3: Recycle Bin is disabled by policy" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Error" `
            -Message "GP.6.3: Recycle Bin check failed: $_" `
            -Severity "Low" -CrossReferences @{ ENISA='GP.6'; NIST='CP-9' }
    }
    # GP.6.4: Controlled folder access (anti-ransomware)
    try {
        $cfa = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Default $null
        if ($null -ne $cfa -and $cfa -eq 1) {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Pass" `
                -Message "GP.6.4: Controlled Folder Access (anti-ransomware) is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.6'; NIST='SC-7'; CIS='18.9.47.4.1' }
        } else {
            Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Warning" `
                -Message "GP.6.4: Controlled Folder Access is not enabled" `
                -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.6'; NIST='SC-7'; CIS='18.9.47.4.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.6 Data Protection" -Status "Error" `
            -Message "GP.6.4: Controlled Folder Access check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.6'; NIST='SC-7' }
    }

# ===========================================================================
# GP.7 -- Incident Response Readiness
# ===========================================================================
Write-Host "[ENISA] Checking GP.7 -- Incident Response Readiness..." -ForegroundColor Yellow

    # GP.7.1: Windows Event Forwarding service
    try {
        $wefSvc = Get-Service -Name Wecsvc -ErrorAction SilentlyContinue
        if ($null -ne $wefSvc -and $wefSvc.Status -eq 'Running') {
            Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Pass" `
                -Message "GP.7.1: Windows Event Forwarding (WEF) service is running" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.7'; NIST='IR-4'; ISO27001='A.5.24' }
        } else {
            Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Info" `
                -Message "GP.7.1: Windows Event Forwarding service is not running (consider for centralized logging)" `
                -Remediation "Set-Service -Name Wecsvc -StartupType Automatic; Start-Service Wecsvc" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.7'; NIST='IR-4'; ISO27001='A.5.24' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Error" `
            -Message "GP.7.1: WEF service check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.7'; NIST='IR-4' }
    }
    # GP.7.2: Windows Error Reporting
    try {
        $werDisabled = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Default 0
        if ($werDisabled -ne 1) {
            Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Pass" `
                -Message "GP.7.2: Windows Error Reporting is enabled (crash data available for analysis)" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.7'; NIST='IR-6' }
        } else {
            Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Info" `
                -Message "GP.7.2: Windows Error Reporting is disabled by policy" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.7'; NIST='IR-6' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Error" `
            -Message "GP.7.2: WER check failed: $_" `
            -Severity "Low" -CrossReferences @{ ENISA='GP.7'; NIST='IR-6' }
    }
    # GP.7.3: Crash dump configuration
    try {
        $crashDump = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Default 0
        if ($crashDump -ge 1) {
            $dumpType = switch ($crashDump) { 1 { "Complete" }; 2 { "Kernel" }; 3 { "Small (minidump)" }; 7 { "Automatic" }; default { "Type $crashDump" } }
            Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Pass" `
                -Message "GP.7.3: Crash dump is configured ($dumpType) for incident analysis" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.7'; NIST='IR-4' }
        } else {
            Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Info" `
                -Message "GP.7.3: Crash dumps are disabled -- limits post-incident analysis" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.7'; NIST='IR-4' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.7 Incident Response" -Status "Error" `
            -Message "GP.7.3: Crash dump check failed: $_" `
            -Severity "Low" -CrossReferences @{ ENISA='GP.7'; NIST='IR-4' }
    }

# ===========================================================================
# GP.8 -- System Hardening
# ===========================================================================
Write-Host "[ENISA] Checking GP.8 -- System Hardening..." -ForegroundColor Yellow

    # GP.8.1: Secure Boot enabled
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $true) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.1: Secure Boot is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.8'; NIST='SI-7'; STIG='V-73523' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Warning" `
                -Message "GP.8.1: Secure Boot is not enabled or not supported" `
                -Remediation "Enable Secure Boot in UEFI/BIOS settings" `
                -Severity "High" -CrossReferences @{ ENISA='GP.8'; NIST='SI-7'; STIG='V-73523' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Info" `
            -Message "GP.8.1: Secure Boot status could not be determined (may require UEFI)" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='SI-7' }
    }
    # GP.8.2: DEP (Data Execution Prevention) enabled
    try {
        $depPolicy = & bcdedit /enum 2>&1 | Select-String "nx"
        $depEnabled = $null -ne $depPolicy -and $depPolicy.ToString() -match '(AlwaysOn|OptOut)'
        if ($depEnabled) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.2: Data Execution Prevention (DEP) is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.8'; NIST='SI-16'; CIS='18.3.1' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Warning" `
                -Message "GP.8.2: DEP may not be fully enabled" `
                -Remediation "bcdedit /set nx AlwaysOn" `
                -Severity "High" -CrossReferences @{ ENISA='GP.8'; NIST='SI-16'; CIS='18.3.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Error" `
            -Message "GP.8.2: DEP check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.8'; NIST='SI-16' }
    }
    # GP.8.3: AutoPlay disabled
    try {
        $autoplay = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default 0
        if ($autoplay -ge 255) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.3: AutoPlay is disabled for all drives (value=$autoplay)" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='MP-7'; CIS='18.9.8.1' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Warning" `
                -Message "GP.8.3: AutoPlay may not be fully disabled (value=$autoplay)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='MP-7'; CIS='18.9.8.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Error" `
            -Message "GP.8.3: AutoPlay check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='MP-7' }
    }
    # GP.8.4: Autorun disabled
    try {
        $autorun = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Default 0
        if ($autorun -eq 1) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.4: Autorun default behavior is disabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='MP-7'; CIS='18.9.8.2' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Warning" `
                -Message "GP.8.4: Autorun may not be disabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='MP-7'; CIS='18.9.8.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Error" `
            -Message "GP.8.4: Autorun check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='MP-7' }
    }
    # GP.8.5: Remote Registry service disabled
    try {
        $remReg = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
        if ($null -ne $remReg -and $remReg.Status -ne 'Running') {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.5: Remote Registry service is not running (start type: $($remReg.StartType))" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='CM-7'; CIS='5.27' }
        } elseif ($null -ne $remReg) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Fail" `
                -Message "GP.8.5: Remote Registry service is RUNNING -- disable for hardening" `
                -Remediation "Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='CM-7'; CIS='5.27' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.5: Remote Registry service is not installed" `
                -Severity "Informational" -CrossReferences @{ ENISA='GP.8'; NIST='CM-7' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Error" `
            -Message "GP.8.5: Remote Registry check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='CM-7' }
    }
    # GP.8.6: Anonymous SID enumeration disabled
    try {
        $anonSid = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Default 0
        if ($anonSid -eq 1) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.6: Anonymous SID/Name translation is restricted" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='AC-14'; CIS='2.3.10.2' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Fail" `
                -Message "GP.8.6: Anonymous SID/Name translation is NOT restricted" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='AC-14'; CIS='2.3.10.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Error" `
            -Message "GP.8.6: Anonymous SID check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='AC-14' }
    }
    # GP.8.7: Cached logon credentials limited
    try {
        $cachedLogons = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Default "10"
        $cachedVal = [int]$cachedLogons
        if ($cachedVal -le 4) {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Pass" `
                -Message "GP.8.7: Cached logon credentials limited to $cachedVal" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='IA-5'; CIS='2.3.2.1' }
        } else {
            Add-Result -Category "ENISA - GP.8 Hardening" -Status "Warning" `
                -Message "GP.8.7: Cached logon credentials set to $cachedVal (recommend 4 or fewer)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='IA-5'; CIS='2.3.2.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.8 Hardening" -Status "Error" `
            -Message "GP.8.7: Cached logon check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.8'; NIST='IA-5' }
    }

# ===========================================================================
# GP.9 -- Email and Web Security
# ===========================================================================
Write-Host "[ENISA] Checking GP.9 -- Email and Web Security..." -ForegroundColor Yellow

    # GP.9.1: SmartScreen enabled
    try {
        $smartScreen = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Default $null
        if ($null -eq $smartScreen -or $smartScreen -ge 1) {
            Add-Result -Category "ENISA - GP.9 Web Security" -Status "Pass" `
                -Message "GP.9.1: Windows SmartScreen is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.9'; NIST='SI-3'; CIS='18.9.85.1.1' }
        } else {
            Add-Result -Category "ENISA - GP.9 Web Security" -Status "Fail" `
                -Message "GP.9.1: Windows SmartScreen is DISABLED" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 1" `
                -Severity "High" -CrossReferences @{ ENISA='GP.9'; NIST='SI-3'; CIS='18.9.85.1.1' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.9 Web Security" -Status "Error" `
            -Message "GP.9.1: SmartScreen check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.9'; NIST='SI-3' }
    }
    # GP.9.2: Internet Explorer enhanced security (server)
    try {
        $ieEsc = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Default $null
        if ($null -ne $ieEsc -and $ieEsc -eq 1) {
            Add-Result -Category "ENISA - GP.9 Web Security" -Status "Pass" `
                -Message "GP.9.2: Internet Explorer Enhanced Security Configuration is enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.9'; NIST='SC-18' }
        } else {
            Add-Result -Category "ENISA - GP.9 Web Security" -Status "Info" `
                -Message "GP.9.2: IE Enhanced Security not detected (may not apply to workstations)" `
                -Severity "Low" -CrossReferences @{ ENISA='GP.9'; NIST='SC-18' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.9 Web Security" -Status "Error" `
            -Message "GP.9.2: IE ESC check failed: $_" `
            -Severity "Low" -CrossReferences @{ ENISA='GP.9'; NIST='SC-18' }
    }
    # GP.9.3: Attachment download security zone
    try {
        $attachZone = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Default $null
        if ($null -eq $attachZone -or $attachZone -eq 2) {
            Add-Result -Category "ENISA - GP.9 Web Security" -Status "Pass" `
                -Message "GP.9.3: Downloaded file zone information is preserved (Mark of the Web)" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.9'; NIST='SI-3' }
        } else {
            Add-Result -Category "ENISA - GP.9 Web Security" -Status "Warning" `
                -Message "GP.9.3: Zone information may not be preserved for downloaded files" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.9'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.9 Web Security" -Status "Error" `
            -Message "GP.9.3: Attachment zone check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.9'; NIST='SI-3' }
    }

# ===========================================================================
# GP.10 -- Endpoint Protection
# ===========================================================================
Write-Host "[ENISA] Checking GP.10 -- Endpoint Protection..." -ForegroundColor Yellow

    # GP.10.1: Windows Defender real-time protection
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($null -ne $mpPref -and $mpPref.DisableRealtimeMonitoring -eq $false) {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                -Message "GP.10.1: Windows Defender real-time protection is enabled" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.4.3' }
        } else {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Fail" `
                -Message "GP.10.1: Windows Defender real-time protection is DISABLED" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
                -Severity "Critical" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.4.3' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.1: Defender real-time check failed: $_" `
            -Severity "Critical" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3' }
    }
    # GP.10.2: Defender signature age
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($null -ne $mpStatus) {
            $sigAge = $mpStatus.AntivirusSignatureAge
            if ($sigAge -le 1) {
                Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                    -Message "GP.10.2: Defender signatures are current ($sigAge day(s) old)" `
                    -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.12' }
            } elseif ($sigAge -le 7) {
                Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Warning" `
                    -Message "GP.10.2: Defender signatures are $sigAge days old (update recommended)" `
                    -Remediation "Update-MpSignature" `
                    -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.12' }
            } else {
                Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Fail" `
                    -Message "GP.10.2: Defender signatures are severely outdated ($sigAge days)" `
                    -Remediation "Update-MpSignature" `
                    -Severity "Critical" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.12' }
            }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.2: Defender signature check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3' }
    }
    # GP.10.3: Cloud-delivered protection
    try {
        if ($null -ne $mpPref -and $mpPref.MAPSReporting -ge 1) {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                -Message "GP.10.3: Cloud-delivered protection (MAPS) is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3' }
        } else {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Warning" `
                -Message "GP.10.3: Cloud-delivered protection (MAPS) is not enabled" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.3: Cloud protection check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3' }
    }
    # GP.10.4: PUA protection
    try {
        if ($null -ne $mpPref -and $mpPref.PUAProtection -eq 1) {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                -Message "GP.10.4: Potentially Unwanted Application (PUA) protection is enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.15' }
        } else {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Warning" `
                -Message "GP.10.4: PUA protection is not enabled" `
                -Remediation "Set-MpPreference -PUAProtection Enabled" `
                -Severity "Medium" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3'; CIS='18.9.47.15' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.4: PUA protection check failed: $_" `
            -Severity "Medium" -CrossReferences @{ ENISA='GP.10'; NIST='SI-3' }
    }
    # GP.10.5: Network protection
    try {
        if ($null -ne $mpPref -and $mpPref.EnableNetworkProtection -eq 1) {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                -Message "GP.10.5: Network protection is enabled (blocks malicious network connections)" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SC-7'; CIS='18.9.47.4.2' }
        } else {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Warning" `
                -Message "GP.10.5: Network protection is not enabled" `
                -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SC-7'; CIS='18.9.47.4.2' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.5: Network protection check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SC-7' }
    }
    # GP.10.6: Behavior monitoring
    try {
        if ($null -ne $mpPref -and $mpPref.DisableBehaviorMonitoring -eq $false) {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                -Message "GP.10.6: Behavior monitoring is enabled" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-4' }
        } else {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Fail" `
                -Message "GP.10.6: Behavior monitoring is DISABLED" `
                -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-4' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.6: Behavior monitoring check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-4' }
    }
    # GP.10.7: ASLR enforcement
    try {
        $aslr = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Default $null
        if ($null -eq $aslr -or $aslr -ne 0) {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Pass" `
                -Message "GP.10.7: ASLR is not disabled (OS default protections active)" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-16' }
        } else {
            Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Fail" `
                -Message "GP.10.7: ASLR appears to be disabled" `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name MoveImages" `
                -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-16' }
        }
    } catch {
        Add-Result -Category "ENISA - GP.10 Endpoint" -Status "Error" `
            -Message "GP.10.7: ASLR check failed: $_" `
            -Severity "High" -CrossReferences @{ ENISA='GP.10'; NIST='SI-16' }
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
Write-Host "  [ENISA] ENISA Cybersecurity Guidelines Module Complete (v$moduleVersion)" -ForegroundColor Cyan
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
    Write-Host "  ENISA Cybersecurity Guidelines -- Standalone Execution (v$moduleVersion)" -ForegroundColor Cyan
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

    Write-Host "[ENISA] Executing checks with standalone environment...`n" -ForegroundColor Cyan
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
    Write-Host "  ENISA module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}

# ============================================================================
# End of ENISA Cybersecurity Guidelines Module (Module-ENISA.ps1)
# ============================================================================
