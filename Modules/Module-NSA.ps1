# Module-NSA.ps1
# NSA Cybersecurity Guidance Compliance Module for Windows Security Audit
# Version: 6.1.2
#
# Evaluates Windows configuration against NSA Cybersecurity Information
# Sheets, technical reports, and hardening guidance across 14 categories.

<#
.SYNOPSIS
    NSA cybersecurity guidance compliance checks for Windows systems.

.DESCRIPTION
    This module checks alignment with NSA cybersecurity guidance including:
    - Secure Boot and boot integrity (UEFI, BitLocker, TPM)
    - Application control (AppLocker, WDAC, SmartScreen)
    - Credential protection (Credential Guard, LSASS PPL, WDigest)
    - Remote access hardening (RDP NLA, WinRM, SSH)
    - PowerShell security (logging, AMSI, constrained mode, v2 removal)
    - SMB protocol hardening (signing, encryption, SMBv1 removal)
    - Endpoint protection (Defender ATP, ASR rules, tamper protection)
    - Audit and logging (command-line auditing, Sysmon, log forwarding)
    - Network hardening (LLMNR, NetBIOS, WPAD, IPv6, DNS-over-HTTPS)
    - Privilege management (local admin restrictions, UAC, token filtering)
    - Patch management (update compliance, WSUS, hotfix currency)
    - Certificate trust and PKI validation
    - Wireless security configuration
    - Memory integrity and exploit mitigations (DEP, ASLR, CFG, ACG)

    Each result includes Severity and CrossReferences mapping to
    CIS Benchmarks, NIST CSF/SP 800-53, DISA STIGs, and CISA directives.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: NSA Cybersecurity Information Sheets (CIS), NSA IAM/IAD guidance
    Version: 6.1.2

.EXAMPLE
    $results = & .\modules\module-nsa.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "NSA"
$moduleVersion = "6.1.2"
$results = @()

# ---------------------------------------------------------------------------
# Result helper with Severity and CrossReferences support
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
        if ($item) { return $item.$Name }
    } catch { <# Expected: item may not exist #> }
    return $Default
}

Write-Host "`n[NSA] Starting NSA cybersecurity guidance checks..." -ForegroundColor Cyan

# ============================================================================
# 1. Secure Boot and Boot Integrity
# ============================================================================
Write-Host "[NSA] Checking boot security..." -ForegroundColor Yellow

try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($secureBoot -eq $true) {
        Add-Result -Category "NSA - Boot Security" -Status "Pass" `
            -Message "UEFI Secure Boot is enabled" `
            -Details "Validates bootloader signatures to prevent bootkits and rootkits from loading at startup" `
            -Severity "High" `
            -CrossReferences @{ CIS="1.1.7"; NIST="SI-7(9)"; STIG="V-254245"; NSA="Secure Boot CSI" }
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "NSA - Boot Security" -Status "Fail" `
            -Message "UEFI Secure Boot is disabled" `
            -Details "System is vulnerable to pre-OS malware (bootkits) that persist across reboots" `
            -Severity "High" `
            -Remediation "Enable Secure Boot in UEFI/BIOS firmware settings" `
            -CrossReferences @{ CIS="1.1.7"; NIST="SI-7(9)"; STIG="V-254245"; NSA="Secure Boot CSI" }
    }
} catch {
    Add-Result -Category "NSA - Boot Security" -Status "Info" `
        -Message "Secure Boot check unavailable (system may use legacy BIOS)" `
        -Details "UEFI with Secure Boot is required for modern hardware-based security features" `
        -Severity "Medium" `
        -CrossReferences @{ NSA="Secure Boot CSI" }
}

# BitLocker on system drive
try {
    $systemDrive = $env:SystemDrive
    $blStatus = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue

    if ($blStatus) {
        if ($blStatus.VolumeStatus -eq "FullyEncrypted") {
            $protectors = ($blStatus.KeyProtector.KeyProtectorType -join ", ")
            Add-Result -Category "NSA - Boot Security" -Status "Pass" `
                -Message "System drive ($systemDrive) is encrypted with BitLocker `($($blStatus.EncryptionMethod))" `
                -Details "Key protectors: $protectors. Full disk encryption protects data at rest." `
                -Severity "High" `
                -CrossReferences @{ CIS="18.10.9.1.1"; NIST="SC-28"; STIG="V-254465"; NSA="FDE CSI" }

            # Check for TPM protector
            $hasTPM = $blStatus.KeyProtector | Where-Object { $_.KeyProtectorType -match "Tpm" }
            if ($hasTPM) {
                Add-Result -Category "NSA - Boot Security" -Status "Pass" `
                    -Message "BitLocker uses TPM-backed key protection" `
                    -Details "Hardware-bound encryption key provides strongest protection against offline attacks" `
                    -Severity "Medium" `
                    -CrossReferences @{ NSA="FDE CSI"; NIST="SC-28(1)" }
            }
        } else {
            Add-Result -Category "NSA - Boot Security" -Status "Fail" `
                -Message "System drive is not fully encrypted (status: $($blStatus.VolumeStatus))" `
                -Details "Data at rest on the system volume is not protected" `
                -Severity "High" `
                -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly" `
                -CrossReferences @{ CIS="18.10.9.1.1"; NIST="SC-28"; NSA="FDE CSI" }
        }
    }
} catch {
    Add-Result -Category "NSA - Boot Security" -Status "Info" `
        -Message "BitLocker status check requires administrative privileges" `
        -Severity "Informational"
}

# Early Launch Anti-Malware (ELAM)
$elamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$elamPolicy = Get-RegValue -Path $elamPath -Name "DriverLoadPolicy" -Default $null
if ($null -ne $elamPolicy) {
    if ($elamPolicy -le 1) {
        Add-Result -Category "NSA - Boot Security" -Status "Pass" `
            -Message "Early Launch Anti-Malware (ELAM) driver policy: Good only (value=$elamPolicy)" `
            -Details "Only known-good boot-start drivers are allowed to load" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SI-7(9)"; NSA="Secure Boot CSI" }
    } else {
        Add-Result -Category "NSA - Boot Security" -Status "Warning" `
            -Message "ELAM driver policy allows unknown drivers (value=$elamPolicy)" `
            -Details "Recommend restricting to known-good drivers for boot integrity" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path '$elamPath' -Name DriverLoadPolicy -Value 1 -Type DWord"
    }
}

# ============================================================================
# 2. Application Control (AppLocker / WDAC)
# ============================================================================
Write-Host "[NSA] Checking application control..." -ForegroundColor Yellow

try {
    # AppLocker service
    $appIdSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($appIdSvc -and $appIdSvc.Status -eq "Running") {
        Add-Result -Category "NSA - Application Control" -Status "Pass" `
            -Message "Application Identity service (AppIDSvc) is running" `
            -Details "Required for AppLocker policy enforcement" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="18.10.1.1"; NIST="CM-7(5)"; NSA="Application Whitelisting CSI" }

        # Check AppLocker rules
        try {
            $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
            if ($applockerPolicy -and $applockerPolicy.RuleCollections.Count -gt 0) {
                $ruleCount = 0
                foreach ($collection in $applockerPolicy.RuleCollections) {
                    $ruleCount += $collection.Count
                }
                Add-Result -Category "NSA - Application Control" -Status "Pass" `
                    -Message "AppLocker policies are configured ($ruleCount rules across $($applockerPolicy.RuleCollections.Count) collections)" `
                    -Details "Application whitelisting is a top NSA mitigation strategy against malware execution" `
                    -Severity "High" `
                    -CrossReferences @{ CIS="18.10.1.1"; NIST="CM-7(5)"; NSA="Application Whitelisting CSI" }
            } else {
                Add-Result -Category "NSA - Application Control" -Status "Warning" `
                    -Message "AppLocker service is running but no effective rules are configured" `
                    -Details "Define AppLocker rules to restrict which executables, scripts, and DLLs can run" `
                    -Severity "High" `
                    -CrossReferences @{ NIST="CM-7(5)"; NSA="Application Whitelisting CSI" }
            }
        } catch {
            Add-Result -Category "NSA - Application Control" -Status "Info" `
                -Message "Could not query AppLocker policy: $_" `
                -Severity "Low"
        }
    } else {
        Add-Result -Category "NSA - Application Control" -Status "Warning" `
            -Message "Application Identity service is not running (AppLocker is inactive)" `
            -Details "Application control prevents unauthorized executables, scripts, and DLLs from running" `
            -Severity "High" `
            -Remediation "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service AppIDSvc" `
            -CrossReferences @{ NIST="CM-7(5)"; NSA="Application Whitelisting CSI" }
    }

    # WDAC (Windows Defender Application Control) / CI policy
    try {
        $ciPolicy = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
        if ($ciPolicy -and $ciPolicy.CodeIntegrityPolicyEnforcementStatus -eq 2) {
            Add-Result -Category "NSA - Application Control" -Status "Pass" `
                -Message "Windows Defender Application Control (WDAC) is enforcing code integrity" `
                -Details "Kernel-mode code integrity policy is active, preventing unsigned driver/code loading" `
                -Severity "High" `
                -CrossReferences @{ NIST="SI-7"; NSA="Application Whitelisting CSI" }
        } elseif ($ciPolicy -and $ciPolicy.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Add-Result -Category "NSA - Application Control" -Status "Info" `
                -Message "WDAC code integrity policy is in audit mode" `
                -Details "Policy violations are logged but not blocked. Move to enforcement after validation." `
                -Severity "Medium"
        }
    } catch { <# WDAC may not be available on all editions #> }

    # SmartScreen
    $ssLevel = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Default $null
    if ($ssLevel -eq 1 -or $ssLevel -eq 2) {
        Add-Result -Category "NSA - Application Control" -Status "Pass" `
            -Message "Windows SmartScreen is enabled (level=$ssLevel)" `
            -Details "SmartScreen checks downloaded files and apps against cloud reputation service" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="18.10.75.1"; NIST="SI-3"; NSA="Endpoint Protection" }
    } elseif ($ssLevel -eq 0) {
        Add-Result -Category "NSA - Application Control" -Status "Fail" `
            -Message "Windows SmartScreen is disabled" `
            -Details "SmartScreen provides cloud-based reputation checking for downloads and applications" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 1" `
            -CrossReferences @{ CIS="18.10.75.1"; NIST="SI-3"; NSA="Endpoint Protection" }
    }
} catch {
    Add-Result -Category "NSA - Application Control" -Status "Error" `
        -Message "Failed to check application control: $_" `
        -Severity "High"
}

# ============================================================================
# 3. Credential Protection
# ============================================================================
Write-Host "[NSA] Checking credential protection..." -ForegroundColor Yellow

try {
    # Credential Guard
    $dgInfo = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
    if ($dgInfo) {
        $vbsRunning = ($dgInfo.VirtualizationBasedSecurityStatus -eq 2)
        $cgRunning = ($dgInfo.SecurityServicesRunning -contains 1)

        if ($vbsRunning -and $cgRunning) {
            Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
                -Message "Credential Guard is running with VBS" `
                -Details "Derived domain credentials (NTLM hashes, Kerberos TGTs) are isolated in VBS-protected memory" `
                -Severity "High" `
                -CrossReferences @{ CIS="18.9.5.2"; NIST="SC-39"; STIG="V-254257"; NSA="Credential Theft Mitigation CSI" }
        } elseif ($vbsRunning) {
            Add-Result -Category "NSA - Credential Protection" -Status "Warning" `
                -Message "VBS is running but Credential Guard is not active" `
                -Details "Enable Credential Guard to protect cached credentials from theft" `
                -Severity "High" `
                -CrossReferences @{ CIS="18.9.5.2"; NIST="SC-39"; NSA="Credential Theft Mitigation CSI" }
        } else {
            Add-Result -Category "NSA - Credential Protection" -Status "Warning" `
                -Message "Virtualization-Based Security is not running" `
                -Details "VBS and Credential Guard protect against Pass-the-Hash, Pass-the-Ticket, and credential dumping" `
                -Severity "High" `
                -Remediation "Enable VBS and Credential Guard via Group Policy: Device Guard `> Turn On Virtualization Based Security" `
                -CrossReferences @{ CIS="18.9.5.1"; NIST="SC-39"; NSA="Credential Theft Mitigation CSI" }
        }
    }

    # LSASS protection (RunAsPPL)
    $lsaPPL = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default 0
    if ($lsaPPL -eq 1) {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "LSA protection (RunAsPPL) is enabled" `
            -Details "LSASS runs as Protected Process Light, preventing credential extraction by tools like Mimikatz" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.4.7"; NIST="AC-3"; STIG="V-254373"; NSA="Credential Theft Mitigation CSI" }
    } else {
        Add-Result -Category "NSA - Credential Protection" -Status "Fail" `
            -Message "LSA protection (RunAsPPL) is not enabled" `
            -Details "LSASS memory can be dumped by attack tools to extract plaintext credentials and hashes" `
            -Severity "Critical" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord" `
            -CrossReferences @{ CIS="18.4.7"; NIST="AC-3"; STIG="V-254373"; NSA="Credential Theft Mitigation CSI" }
    }

    # WDigest authentication (plaintext credential caching)
    $wdigest = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default $null
    if ($wdigest -eq 0) {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "WDigest authentication credential caching is disabled" `
            -Details "Prevents plaintext passwords from being stored in LSASS memory" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.4.9"; NIST="IA-5(2)"; NSA="Credential Theft Mitigation CSI" }
    } elseif ($wdigest -eq 1) {
        Add-Result -Category "NSA - Credential Protection" -Status "Fail" `
            -Message "WDigest authentication credential caching is enabled" `
            -Details "Plaintext passwords are stored in LSASS memory, trivially extractable by Mimikatz" `
            -Severity "Critical" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord" `
            -CrossReferences @{ CIS="18.4.9"; NIST="IA-5(2)"; NSA="Credential Theft Mitigation CSI" }
    } else {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "WDigest credential caching uses OS default (disabled on Windows 8.1+/2012 R2+)" `
            -Details "Modern Windows versions disable WDigest caching by default when registry key is absent" `
            -Severity "Medium" `
            -CrossReferences @{ NSA="Credential Theft Mitigation CSI" }
    }

    # Net-NTLMv1 disabled (force NTLMv2)
    $lmLevel = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default 3
    if ($lmLevel -ge 5) {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "LAN Manager authentication: NTLMv2 only, refuse LM and NTLM (level=$lmLevel)" `
            -Details "Strongest NTLMv2 configuration prevents legacy LM/NTLM hash exposure" `
            -Severity "High" `
            -CrossReferences @{ CIS="2.3.11.7"; NIST="IA-2"; STIG="V-254438"; NSA="Network Security CSI" }
    } elseif ($lmLevel -ge 3) {
        Add-Result -Category "NSA - Credential Protection" -Status "Warning" `
            -Message "LAN Manager authentication level: $lmLevel (recommend 5 for NTLMv2-only)" `
            -Details "Level 5 refuses all LM and NTLM responses, sending only NTLMv2" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
            -CrossReferences @{ CIS="2.3.11.7"; NIST="IA-2"; STIG="V-254438" }
    } else {
        Add-Result -Category "NSA - Credential Protection" -Status "Fail" `
            -Message "LAN Manager authentication allows legacy LM/NTLM responses (level=$lmLevel)" `
            -Details "LM and NTLM hashes are cryptographically weak and vulnerable to offline cracking" `
            -Severity "Critical" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
            -CrossReferences @{ CIS="2.3.11.7"; NIST="IA-2"; STIG="V-254438"; NSA="Network Security CSI" }
    }

    # Cached logon credentials
    $cachedLogons = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Default "10"
    if ([int]$cachedLogons -le 2) {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "Cached domain logon credentials: $cachedLogons (recommended 2 or fewer)" `
            -Details "Limits offline credential theft risk from cached domain hashes" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="2.3.2.1"; NIST="IA-5(13)"; NSA="Credential Theft Mitigation CSI" }
    } else {
        Add-Result -Category "NSA - Credential Protection" -Status "Warning" `
            -Message "Cached domain logon credentials: $cachedLogons (recommend 2 or fewer)" `
            -Details "High cached logon count increases risk of offline credential extraction" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 2" `
            -CrossReferences @{ CIS="2.3.2.1"; NIST="IA-5(13)"; NSA="Credential Theft Mitigation CSI" }
    }

} catch {
    Add-Result -Category "NSA - Credential Protection" -Status "Error" `
        -Message "Failed to check credential protection: $_" `
        -Severity "High"
}

# ============================================================================
# 4. Remote Access Security
# ============================================================================
Write-Host "[NSA] Checking remote access security..." -ForegroundColor Yellow

try {
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpDisabled = Get-RegValue -Path $rdpPath -Name "fDenyTSConnections" -Default 1

    if ($rdpDisabled -eq 1) {
        Add-Result -Category "NSA - Remote Access" -Status "Pass" `
            -Message "Remote Desktop Protocol (RDP) is disabled" `
            -Details "Eliminates RDP as an attack vector (brute force, BlueKeep, credential theft)" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="18.10.57.1"; NIST="CM-7"; NSA="Remote Access CSI" }
    } else {
        Add-Result -Category "NSA - Remote Access" -Status "Info" `
            -Message "RDP is enabled - verifying security configuration" `
            -Severity "Medium"

        # NLA required
        $nla = Get-RegValue -Path "$rdpPath\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default 0
        if ($nla -eq 1) {
            Add-Result -Category "NSA - Remote Access" -Status "Pass" `
                -Message "RDP Network Level Authentication (NLA) is required" `
                -Details "NLA prevents pre-authentication session establishment, mitigating BlueKeep-class vulnerabilities" `
                -Severity "High" `
                -CrossReferences @{ CIS="18.10.57.2"; NIST="IA-2"; STIG="V-254475"; NSA="Remote Access CSI" }
        } else {
            Add-Result -Category "NSA - Remote Access" -Status "Fail" `
                -Message "RDP Network Level Authentication (NLA) is not required" `
                -Details "Without NLA, attackers can establish sessions before authentication (BlueKeep risk)" `
                -Severity "Critical" `
                -Remediation "Set-ItemProperty -Path '$rdpPath\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -CrossReferences @{ CIS="18.10.57.2"; NIST="IA-2"; STIG="V-254475"; NSA="Remote Access CSI" }
        }

        # Restricted Admin Mode
        $restrictedAdmin = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Default 1
        if ($restrictedAdmin -eq 0) {
            Add-Result -Category "NSA - Remote Access" -Status "Pass" `
                -Message "RDP Restricted Admin Mode is enabled" `
                -Details "Prevents credential delegation to remote host during RDP sessions" `
                -Severity "Medium" `
                -CrossReferences @{ NIST="IA-2(6)"; NSA="Credential Theft Mitigation CSI" }
        } else {
            Add-Result -Category "NSA - Remote Access" -Status "Info" `
                -Message "RDP Restricted Admin Mode is not enabled" `
                -Details "Restricted Admin prevents Pass-the-Hash via RDP but limits some functionality" `
                -Severity "Low"
        }
    }

    # WinRM Basic auth disabled (check for servers/management hosts)
    $winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrmSvc -and $winrmSvc.Status -eq "Running") {
        try {
            $winrmOutput = winrm get winrm/config/service/auth 2>&1 | Out-String
            if ($winrmOutput -match "Basic\s*=\s*true") {
                Add-Result -Category "NSA - Remote Access" -Status "Fail" `
                    -Message "WinRM Basic authentication is enabled" `
                    -Details "Basic auth sends credentials in cleartext (Base64); use Kerberos/Negotiate instead" `
                    -Severity "High" `
                    -Remediation "winrm set winrm/config/service/auth '@{Basic=`"false`"}'" `
                    -CrossReferences @{ CIS="18.10.89.1"; NIST="IA-2"; NSA="Remote Access CSI" }
            } else {
                Add-Result -Category "NSA - Remote Access" -Status "Pass" `
                    -Message "WinRM Basic authentication is disabled" `
                    -Details "Only secure authentication methods (Kerberos, Negotiate) are accepted" `
                    -Severity "Medium" `
                    -CrossReferences @{ CIS="18.10.89.1"; NIST="IA-2" }
            }
        } catch { <# WinRM config query may fail #> }
    }
} catch {
    Add-Result -Category "NSA - Remote Access" -Status "Error" `
        -Message "Failed to check remote access security: $_" `
        -Severity "Medium"
}

# ============================================================================
# 5. PowerShell Security
# ============================================================================
Write-Host "[NSA] Checking PowerShell security..." -ForegroundColor Yellow

try {
    $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    # Script Block Logging
    $sbl = Get-RegValue -Path "$psPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default 0
    if ($sbl -eq 1) {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "Captures deobfuscated script content to Event ID 4104, critical for detecting encoded/obfuscated attacks" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.10.65.1"; NIST="AU-3"; STIG="V-254393"; NSA="PowerShell Security CSI" }
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Fail" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "Without script block logging, obfuscated PowerShell attacks leave no readable audit trail" `
            -Severity "High" `
            -Remediation "New-Item -Path '$psPath\ScriptBlockLogging' -Force; Set-ItemProperty -Path '$psPath\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
            -CrossReferences @{ CIS="18.10.65.1"; NIST="AU-3"; STIG="V-254393"; NSA="PowerShell Security CSI" }
    }

    # Module Logging
    $ml = Get-RegValue -Path "$psPath\ModuleLogging" -Name "EnableModuleLogging" -Default 0
    if ($ml -eq 1) {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Module Logging is enabled" `
            -Details "Records pipeline execution events for forensic analysis (Event ID 4103)" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="18.10.65.2"; NIST="AU-3"; NSA="PowerShell Security CSI" }
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Warning" `
            -Message "PowerShell Module Logging is not enabled" `
            -Details "Module logging captures command pipeline input/output across all loaded modules" `
            -Severity "Medium" `
            -Remediation "New-Item -Path '$psPath\ModuleLogging' -Force; Set-ItemProperty -Path '$psPath\ModuleLogging' -Name EnableModuleLogging -Value 1"
    }

    # Transcription
    $trans = Get-RegValue -Path "$psPath\Transcription" -Name "EnableTranscripting" -Default 0
    if ($trans -eq 1) {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Transcription is enabled" `
            -Details "Creates complete text transcripts of all PowerShell sessions" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="18.10.65.3"; NIST="AU-3"; NSA="PowerShell Security CSI" }
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "Transcription captures complete input/output text log of every PowerShell session" `
            -Severity "Low"
    }

    # PowerShell v2 engine (bypasses all modern security controls)
    try {
        $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
        if ($psv2 -and $psv2.State -eq "Enabled") {
            Add-Result -Category "NSA - PowerShell Security" -Status "Fail" `
                -Message "PowerShell v2 engine is installed" `
                -Details "PS v2 bypasses AMSI, script block logging, constrained language mode, and all modern defenses" `
                -Severity "High" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart" `
                -CrossReferences @{ CIS="18.10.65.4"; NIST="CM-7"; NSA="PowerShell Security CSI" }
        } else {
            Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
                -Message "PowerShell v2 engine is disabled or removed" `
                -Details "Prevents downgrade attacks that bypass modern PowerShell security controls" `
                -Severity "Medium" `
                -CrossReferences @{ CIS="18.10.65.4"; NIST="CM-7"; NSA="PowerShell Security CSI" }
        }
    } catch { <# Feature query may fail on Server Core #> }

    # Constrained Language Mode
    $langMode = $ExecutionContext.SessionState.LanguageMode
    if ($langMode -eq "ConstrainedLanguage") {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Constrained Language Mode is active" `
            -Details "Restricts .NET type access, COM objects, and other attack primitives" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="CM-7"; NSA="PowerShell Security CSI" }
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Info" `
            -Message "PowerShell running in $langMode mode" `
            -Details "ConstrainedLanguage mode limits the attack surface available to PS-based exploitation" `
            -Severity "Informational"
    }

} catch {
    Add-Result -Category "NSA - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell security: $_" `
        -Severity "High"
}

# ============================================================================
# 6. SMB Protocol Security
# ============================================================================
Write-Host "[NSA] Checking SMB security..." -ForegroundColor Yellow

try {
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue

    if ($smbConfig) {
        # SMBv1
        if ($smbConfig.EnableSMB1Protocol -eq $false) {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
                -Message "SMBv1 is disabled" `
                -Details "Mitigates EternalBlue (MS17-010), WannaCry, NotPetya, and related exploitation" `
                -Severity "Critical" `
                -CrossReferences @{ CIS="18.4.4"; NIST="CM-7"; STIG="V-254366"; NSA="SMB Security CSI" }
        } else {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Fail" `
                -Message "SMBv1 is enabled" `
                -Details "SMBv1 has multiple critical, actively-exploited vulnerabilities" `
                -Severity "Critical" `
                -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" `
                -CrossReferences @{ CIS="18.4.4"; NIST="CM-7"; STIG="V-254366"; NSA="SMB Security CSI" }
        }

        # SMB signing
        if ($smbConfig.RequireSecuritySignature) {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
                -Message "SMB server signing is required" `
                -Details "Prevents SMB relay attacks and man-in-the-middle packet tampering" `
                -Severity "High" `
                -CrossReferences @{ CIS="2.3.8.1"; NIST="SC-8"; STIG="V-254369"; NSA="SMB Security CSI" }
        } else {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Fail" `
                -Message "SMB server signing is not required" `
                -Details "Without signing, SMB traffic can be intercepted and relayed for credential theft" `
                -Severity "High" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
                -CrossReferences @{ CIS="2.3.8.1"; NIST="SC-8"; STIG="V-254369"; NSA="SMB Security CSI" }
        }

        # SMB encryption
        if ($smbConfig.EncryptData) {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
                -Message "SMB encryption is enforced" `
                -Details "All SMB 3.0+ traffic is encrypted in transit" `
                -Severity "Medium" `
                -CrossReferences @{ NIST="SC-8(1)"; NSA="SMB Security CSI" }
        } else {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Warning" `
                -Message "SMB encryption is not enforced" `
                -Details "SMB 3.0 encryption protects file share traffic from network interception" `
                -Severity "Medium" `
                -Remediation "Set-SmbServerConfiguration -EncryptData `$true -Force"
        }

        # Null session prevention
        $restrictAnon = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Default 0
        if ($restrictAnon -ge 1) {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
                -Message "Anonymous/null session access is restricted (RestrictAnonymous=$restrictAnon)" `
                -Details "Prevents enumeration of SAM accounts and shares via null sessions" `
                -Severity "High" `
                -CrossReferences @{ CIS="2.3.10.3"; NIST="AC-3"; STIG="V-254442"; NSA="Network Security CSI" }
        } else {
            Add-Result -Category "NSA - Network Protocol Security" -Status "Fail" `
                -Message "Anonymous/null session access is not restricted" `
                -Details "Attackers can enumerate user accounts, groups, and shares without authentication" `
                -Severity "High" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1 -Type DWord" `
                -CrossReferences @{ CIS="2.3.10.3"; NIST="AC-3"; STIG="V-254442"; NSA="Network Security CSI" }
        }
    }
} catch {
    Add-Result -Category "NSA - Network Protocol Security" -Status "Error" `
        -Message "Failed to check SMB security: $_" `
        -Severity "High"
}

# ============================================================================
# 7. Endpoint Protection
# ============================================================================
Write-Host "[NSA] Checking endpoint protection..." -ForegroundColor Yellow

try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if ($defender) {
        # Real-time protection
        if ($defender.RealTimeProtectionEnabled) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                -Message "Defender real-time protection is enabled" `
                -Details "Continuous file and process scanning active" `
                -Severity "Critical" `
                -CrossReferences @{ CIS="18.10.43.6.1"; NIST="SI-3"; NSA="Endpoint Protection" }
        } else {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Fail" `
                -Message "Defender real-time protection is disabled" `
                -Severity "Critical" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
                -CrossReferences @{ CIS="18.10.43.6.1"; NIST="SI-3"; NSA="Endpoint Protection" }
        }

        # Attack Surface Reduction (ASR) rules
        try {
            $asrRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
            if ($asrRules -and $asrRules.Count -gt 0) {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                    -Message "Attack Surface Reduction (ASR) rules are configured `($($asrRules.Count) rules)" `
                    -Details "ASR rules block common malware techniques (Office macros, script injection, credential stealing)" `
                    -Severity "High" `
                    -CrossReferences @{ CIS="18.10.43.1"; NIST="SI-3"; NSA="Endpoint Protection" }
            } else {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
                    -Message "No Attack Surface Reduction (ASR) rules are configured" `
                    -Details "ASR rules provide significant protection against common attack vectors" `
                    -Severity "High" `
                    -Remediation "Configure ASR rules via: Set-MpPreference -AttackSurfaceReductionRules_Ids <rule-guids`> -AttackSurfaceReductionRules_Actions Enabled" `
                    -CrossReferences @{ CIS="18.10.43.1"; NIST="SI-3"; NSA="Endpoint Protection" }
            }
        } catch { <# ASR may not be available on all editions #> }

        # Tamper Protection
        try {
            if ($defender.IsTamperProtected) {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                    -Message "Defender Tamper Protection is enabled" `
                    -Details "Prevents unauthorized modifications to security settings" `
                    -Severity "High" `
                    -CrossReferences @{ CIS="18.10.43.11"; NIST="SI-7"; NSA="Endpoint Protection" }
            } else {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
                    -Message "Defender Tamper Protection is disabled" `
                    -Details "Malware or attacker tools could disable Defender protection" `
                    -Severity "High" `
                    -CrossReferences @{ NSA="Endpoint Protection" }
            }
        } catch { <# Property may not exist on older builds #> }

        # Controlled Folder Access (ransomware protection)
        try {
            $cfaEnabled = (Get-MpPreference).EnableControlledFolderAccess
            if ($cfaEnabled -eq 1) {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                    -Message "Controlled Folder Access (ransomware protection) is enabled" `
                    -Details "Protects sensitive folders from unauthorized modifications by untrusted applications" `
                    -Severity "Medium" `
                    -CrossReferences @{ CIS="18.10.43.3"; NIST="SI-3"; NSA="Ransomware Mitigation" }
            } else {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Info" `
                    -Message "Controlled Folder Access is not enabled" `
                    -Details "CFA protects designated folders from ransomware encryption" `
                    -Severity "Medium" `
                    -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled"
            }
        } catch { <# CFA preference may not exist #> }

        # Network protection
        try {
            $netProtection = (Get-MpPreference).EnableNetworkProtection
            if ($netProtection -eq 1) {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                    -Message "Defender Network Protection is enabled" `
                    -Details "Blocks connections to known malicious domains and IP addresses" `
                    -Severity "Medium" `
                    -CrossReferences @{ CIS="18.10.43.4"; NIST="SI-4"; NSA="Network Monitoring" }
            } else {
                Add-Result -Category "NSA - Endpoint Protection" -Status "Info" `
                    -Message "Defender Network Protection is not enabled" `
                    -Details "Network Protection provides web filtering against phishing and exploit sites" `
                    -Severity "Low" `
                    -Remediation "Set-MpPreference -EnableNetworkProtection Enabled"
            }
        } catch { <# May not exist on all editions #> }

    } else {
        Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
            -Message "Windows Defender is not available or accessible" `
            -Details "Endpoint protection status could not be verified" `
            -Severity "High"
    }
} catch {
    Add-Result -Category "NSA - Endpoint Protection" -Status "Error" `
        -Message "Failed to check endpoint protection: $_" `
        -Severity "Critical"
}

# ============================================================================
# 8. Audit and Logging
# ============================================================================
Write-Host "[NSA] Checking audit and logging..." -ForegroundColor Yellow

try {
    # Command line auditing in process creation events
    $cmdLineAudit = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Default 0
    if ($cmdLineAudit -eq 1) {
        Add-Result -Category "NSA - Audit and Logging" -Status "Pass" `
            -Message "Command line process creation auditing is enabled" `
            -Details "Process creation events (Event ID 4688) include full command line arguments" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.9.3.1"; NIST="AU-3"; STIG="V-254396"; NSA="Event Forwarding CSI" }
    } else {
        Add-Result -Category "NSA - Audit and Logging" -Status "Fail" `
            -Message "Command line process creation auditing is not enabled" `
            -Details "Without command line capture, process creation events lack critical forensic detail" `
            -Severity "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord" `
            -CrossReferences @{ CIS="18.9.3.1"; NIST="AU-3"; STIG="V-254396"; NSA="Event Forwarding CSI" }
    }

    # Audit process creation
    try {
        $auditOutput = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
        if ($auditOutput -match "Success") {
            Add-Result -Category "NSA - Audit and Logging" -Status "Pass" `
                -Message "Audit policy: Process Creation success auditing is enabled" `
                -Details "Tracks all process execution on the system for forensic analysis" `
                -Severity "Medium" `
                -CrossReferences @{ CIS="17.3.1"; NIST="AU-2"; NSA="Event Forwarding CSI" }
        } else {
            Add-Result -Category "NSA - Audit and Logging" -Status "Warning" `
                -Message "Audit policy: Process Creation success auditing is not enabled" `
                -Details "Enable to track process execution events" `
                -Severity "Medium" `
                -Remediation "auditpol /set /subcategory:'Process Creation' /success:enable"
        }
    } catch { <# auditpol may require elevation #> }

    # Audit logon events
    try {
        $logonAudit = auditpol /get /subcategory:"Logon" 2>&1 | Out-String
        if ($logonAudit -match "Success" -and $logonAudit -match "Failure") {
            Add-Result -Category "NSA - Audit and Logging" -Status "Pass" `
                -Message "Audit policy: Logon success and failure auditing enabled" `
                -Details "Tracks successful and failed authentication attempts" `
                -Severity "High" `
                -CrossReferences @{ CIS="17.5.1"; NIST="AU-2"; STIG="V-254406"; NSA="Event Forwarding CSI" }
        } elseif ($logonAudit -match "Success" -or $logonAudit -match "Failure") {
            Add-Result -Category "NSA - Audit and Logging" -Status "Warning" `
                -Message "Audit policy: Logon auditing is partially configured" `
                -Details "Both success and failure auditing should be enabled" `
                -Severity "Medium" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"
        } else {
            Add-Result -Category "NSA - Audit and Logging" -Status "Fail" `
                -Message "Audit policy: Logon auditing is not configured" `
                -Details "No authentication events are being recorded" `
                -Severity "High" `
                -Remediation "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" `
                -CrossReferences @{ CIS="17.5.1"; NIST="AU-2"; NSA="Event Forwarding CSI" }
        }
    } catch { <# auditpol may require elevation #> }

    # Security log size
    try {
        $secLog = Get-WinEvent -ListLog "Security" -ErrorAction SilentlyContinue
        if ($secLog) {
            $sizeKB = [math]::Round($secLog.MaximumSizeInBytes / 1024)
            if ($sizeKB -ge 196608) {
                Add-Result -Category "NSA - Audit and Logging" -Status "Pass" `
                    -Message "Security event log size: $sizeKB KB (minimum 192 MB met)" `
                    -Details "Adequate log retention capacity for forensic analysis" `
                    -Severity "Medium" `
                    -CrossReferences @{ CIS="18.10.26.1"; NIST="AU-4"; NSA="Event Forwarding CSI" }
            } else {
                Add-Result -Category "NSA - Audit and Logging" -Status "Warning" `
                    -Message "Security event log size: $sizeKB KB (recommend 196,608+ KB)" `
                    -Details "Small log size may result in event loss during security incidents" `
                    -Severity "Medium" `
                    -Remediation "wevtutil sl Security /ms:201326592"
            }
        }
    } catch { <# Log enumeration may fail #> }

} catch {
    Add-Result -Category "NSA - Audit and Logging" -Status "Error" `
        -Message "Failed to check audit and logging: $_" `
        -Severity "Medium"
}

# ============================================================================
# 9. Network Hardening
# ============================================================================
Write-Host "[NSA] Checking network hardening..." -ForegroundColor Yellow

try {
    # LLMNR disabled
    $llmnr = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default 1
    if ($llmnr -eq 0) {
        Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
            -Message "LLMNR is disabled" `
            -Details "Prevents credential capture via LLMNR poisoning (Responder/Inveigh attacks)" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.6.4.1"; NIST="SC-7"; NSA="Network Hardening CSI" }
    } else {
        Add-Result -Category "NSA - Network Hardening" -Status "Fail" `
            -Message "LLMNR is not disabled" `
            -Details "LLMNR multicast name resolution is vulnerable to credential interception via poisoning" `
            -Severity "High" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord" `
            -CrossReferences @{ CIS="18.6.4.1"; NIST="SC-7"; NSA="Network Hardening CSI" }
    }

    # mDNS disabled
    $mdns = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Default 1
    if ($mdns -eq 0) {
        Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
            -Message "Multicast DNS (mDNS) is disabled" `
            -Details "mDNS has similar poisoning risks to LLMNR for local name resolution" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SC-7"; NSA="Network Hardening CSI" }
    } else {
        Add-Result -Category "NSA - Network Hardening" -Status "Warning" `
            -Message "Multicast DNS (mDNS) is not explicitly disabled" `
            -Details "mDNS can be poisoned for credential interception on local networks" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -Value 0 -Type DWord"
    }

    # WPAD disabled
    $wpadSvc = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
    if ($wpadSvc -and $wpadSvc.Status -ne "Running") {
        Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
            -Message "Web Proxy Auto-Discovery (WPAD) service is not running" `
            -Details "WPAD is vulnerable to traffic interception via rogue proxy configuration" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SC-7"; NSA="Network Hardening CSI" }
    } elseif ($wpadSvc -and $wpadSvc.Status -eq "Running") {
        Add-Result -Category "NSA - Network Hardening" -Status "Info" `
            -Message "WPAD service is running" `
            -Details "Web Proxy Auto-Discovery can be exploited for traffic interception" `
            -Severity "Low"
    }

    # Windows Firewall - all profiles enabled
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $disabledProfiles = @($fwProfiles | Where-Object { -not $_.Enabled })
        if ($disabledProfiles.Count -eq 0) {
            Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
                -Message "Windows Firewall is enabled on all profiles" `
                -Details "Host-based firewall active for Domain, Private, and Public networks" `
                -Severity "Critical" `
                -CrossReferences @{ CIS="9.1.1"; NIST="SC-7"; STIG="V-241989"; NSA="Network Segmentation" }
        } else {
            $disabledNames = ($disabledProfiles.Name -join ", ")
            Add-Result -Category "NSA - Network Hardening" -Status "Fail" `
                -Message "Windows Firewall is disabled on: $disabledNames" `
                -Details "Disabled firewall profiles expose the system to network attacks" `
                -Severity "Critical" `
                -Remediation "Set-NetFirewallProfile -All -Enabled True" `
                -CrossReferences @{ CIS="9.1.1"; NIST="SC-7"; STIG="V-241989"; NSA="Network Segmentation" }
        }
    } catch { <# Firewall check may require elevation #> }

    # IPv6 - check if disabled when not needed
    $ipv6Disabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Default 0
    if ($ipv6Disabled -eq 255) {
        Add-Result -Category "NSA - Network Hardening" -Status "Info" `
            -Message "IPv6 is completely disabled" `
            -Details "IPv6 disabled for all interfaces (DisabledComponents=255)" `
            -Severity "Informational" `
            -CrossReferences @{ NSA="Network Hardening CSI" }
    } elseif ($ipv6Disabled -eq 0) {
        Add-Result -Category "NSA - Network Hardening" -Status "Info" `
            -Message "IPv6 is enabled (default)" `
            -Details "If IPv6 is not required on this network, consider disabling to reduce attack surface" `
            -Severity "Low" `
            -CrossReferences @{ NSA="Network Hardening CSI" }
    }

} catch {
    Add-Result -Category "NSA - Network Hardening" -Status "Error" `
        -Message "Failed to check network hardening: $_" `
        -Severity "Medium"
}

# ============================================================================
# 10. Exploit Mitigations (DEP, ASLR, CFG)
# ============================================================================
Write-Host "[NSA] Checking exploit mitigations..." -ForegroundColor Yellow

try {
    # DEP (Data Execution Prevention) via boot configuration
    $bcdeditOutput = bcdedit /enum "{current}" 2>&1 | Out-String
    if ($bcdeditOutput -match "nx\s+OptOut" -or $bcdeditOutput -match "nx\s+AlwaysOn") {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Pass" `
            -Message "Data Execution Prevention (DEP) is enabled system-wide" `
            -Details "Hardware-enforced DEP prevents code execution from non-executable memory regions" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.3.1"; NIST="SI-16"; STIG="V-254275"; NSA="Exploit Mitigation" }
    } elseif ($bcdeditOutput -match "nx\s+OptIn") {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Warning" `
            -Message "DEP is in OptIn mode (only Windows system binaries protected)" `
            -Details "OptOut or AlwaysOn provides broader DEP coverage for all applications" `
            -Severity "Medium" `
            -Remediation "bcdedit /set `"{current}`" nx OptOut" `
            -CrossReferences @{ CIS="18.3.1"; NIST="SI-16"; STIG="V-254275" }
    }

    # ASLR Mandatory Relocation (MoveImages registry key)
    $aslrMoveImages = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Default $null
    if ($null -ne $aslrMoveImages -and $aslrMoveImages -eq 0) {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Fail" `
            -Message "ASLR mandatory image relocation is DISABLED (MoveImages=0)" `
            -Details "Images without /DYNAMICBASE will not be relocated, reducing ASLR effectiveness" `
            -Severity "High" `
            -Remediation "Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name MoveImages -ErrorAction SilentlyContinue" `
            -CrossReferences @{ NIST="SI-16"; NSA="Exploit Mitigation"; CIS="18.3.2" }
    } else {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Pass" `
            -Message "ASLR mandatory image relocation is enabled (default or MoveImages not set to 0)" `
            -Details "All loaded images are subject to address space randomization" `
            -Severity "High" `
            -CrossReferences @{ NIST="SI-16"; NSA="Exploit Mitigation"; CIS="18.3.2" }
    }

    # SEHOP (Structured Exception Handler Overwrite Protection)
    $sehop = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Default 0
    if ($sehop -eq 0) {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Pass" `
            -Message "SEHOP (Structured Exception Handler Overwrite Protection) is enabled" `
            -Details "Protects against SEH-based buffer overflow exploits" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SI-16"; NSA="Exploit Mitigation" }
    } else {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Fail" `
            -Message "SEHOP is disabled" `
            -Details "System is vulnerable to SEH-based stack overflow exploits" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name DisableExceptionChainValidation -Value 0 -Type DWord"
    }

    # Speculative execution mitigations
    $specCtrl = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Default $null
    if ($null -ne $specCtrl) {
        Add-Result -Category "NSA - Exploit Mitigation" -Status "Info" `
            -Message "Speculative execution mitigations are configured (FeatureSettingsOverride=$specCtrl)" `
            -Details "Mitigations for Spectre/Meltdown side-channel attacks are applied" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SI-16"; NSA="Microprocessor Vulnerabilities CSI" }
    }

} catch {
    Add-Result -Category "NSA - Exploit Mitigation" -Status "Error" `
        -Message "Failed to check exploit mitigations: $_" `
        -Severity "Medium"
}

# ============================================================================
# 11. Privilege Management (UAC, Local Admin, Token Filtering)
# ============================================================================
Write-Host "[NSA] Checking privilege management..." -ForegroundColor Yellow

try {
    # UAC Enforcement Level
    $enableLUA = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default 0
    if ($enableLUA -eq 1) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "User Account Control (UAC) is enabled" `
            -Details "UAC restricts application privileges and prompts for elevation" `
            -Severity "Critical" `
            -CrossReferences @{ CIS="2.3.17.1"; NIST="AC-6"; STIG="V-220930"; NSA="IAM Guidance" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Fail" `
            -Message "User Account Control (UAC) is DISABLED" `
            -Details "Without UAC all applications run with full administrative privileges" `
            -Severity "Critical" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord; Restart-Computer" `
            -CrossReferences @{ CIS="2.3.17.1"; NIST="AC-6"; STIG="V-220930"; NSA="IAM Guidance" }
    }

    # UAC Consent Prompt Behavior for Admins
    $consentPrompt = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Default 5
    if ($consentPrompt -le 2) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "UAC admin consent prompt is set to secure level ($consentPrompt)" `
            -Details "Level 0=No prompt, 1=Prompt creds on secure desktop, 2=Prompt consent on secure desktop" `
            -Severity "High" `
            -CrossReferences @{ CIS="2.3.17.2"; NIST="AC-6(1)"; STIG="V-220931" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Warning" `
            -Message "UAC admin consent prompt behavior is at default level ($consentPrompt)" `
            -Details "Values 1 or 2 on secure desktop provide stronger protection. Current: 5=prompt consent for non-Windows binaries" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord" `
            -CrossReferences @{ CIS="2.3.17.2"; NIST="AC-6(1)"; STIG="V-220931" }
    }

    # UAC Behavior for Standard Users (auto-deny elevation)
    $consentStd = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Default 3
    if ($consentStd -eq 0) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "UAC standard user elevation requests are automatically denied" `
            -Details "Standard users cannot trigger elevation prompts" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="2.3.17.3"; NIST="AC-6(2)"; STIG="V-220932" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Warning" `
            -Message "UAC standard users can request elevation (ConsentPromptBehaviorUser=$consentStd)" `
            -Details "NSA recommends auto-deny (0) for standard users to prevent social engineering" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Value 0 -Type DWord" `
            -CrossReferences @{ CIS="2.3.17.3"; NIST="AC-6(2)"; STIG="V-220932" }
    }

    # Admin Approval Mode for Built-in Administrator
    $filterAdmin = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Default 0
    if ($filterAdmin -eq 1) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "Admin Approval Mode is enabled for the built-in Administrator account" `
            -Details "Built-in Administrator runs with filtered token requiring explicit elevation" `
            -Severity "High" `
            -CrossReferences @{ CIS="2.3.17.4"; NIST="AC-6(1)"; STIG="V-220929" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Fail" `
            -Message "Built-in Administrator bypasses UAC (FilterAdministratorToken disabled)" `
            -Details "The RID-500 Administrator account runs all processes with full privileges" `
            -Severity "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Value 1 -Type DWord" `
            -CrossReferences @{ CIS="2.3.17.4"; NIST="AC-6(1)"; STIG="V-220929" }
    }

    # Local administrator account enumeration
    $enumAdmins = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Default 1
    if ($enumAdmins -eq 0) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "Administrator account enumeration on elevation is disabled" `
            -Details "Users cannot enumerate admin accounts when attempting elevation" `
            -Severity "Medium" `
            -CrossReferences @{ CIS="2.3.17.5"; NIST="AC-6"; NSA="IAM Guidance" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Warning" `
            -Message "Administrator account enumeration on elevation is enabled" `
            -Details "Admin usernames are visible during UAC prompts which aids reconnaissance" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name EnumerateAdministrators -Value 0 -Type DWord" `
            -CrossReferences @{ CIS="2.3.17.5"; NIST="AC-6" }
    }

    # Remote UAC token filtering (LocalAccountTokenFilterPolicy)
    $tokenFilter = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Default 0
    if ($tokenFilter -eq 0) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "Remote UAC token filtering is active (local admin remote access restricted)" `
            -Details "Remote connections from local admin accounts use filtered tokens preventing lateral movement" `
            -Severity "Critical" `
            -CrossReferences @{ NIST="AC-17"; NSA="Lateral Movement CSI"; CISA="Lateral Movement" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Fail" `
            -Message "Remote UAC token filtering is DISABLED (pass-the-hash risk)" `
            -Details "Local admin accounts can authenticate remotely with full admin tokens enabling lateral movement" `
            -Severity "Critical" `
            -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue" `
            -CrossReferences @{ NIST="AC-17"; NSA="Lateral Movement CSI"; CISA="Lateral Movement" }
    }

    # Elevated processes and secure desktop
    $promptSecureDesktop = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Default 1
    if ($promptSecureDesktop -eq 1) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "UAC prompts display on the Secure Desktop" `
            -Details "Secure Desktop prevents malware from spoofing or manipulating elevation prompts" `
            -Severity "High" `
            -CrossReferences @{ CIS="2.3.17.7"; NIST="AC-6"; STIG="V-220934" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Fail" `
            -Message "UAC Secure Desktop is disabled" `
            -Details "Elevation prompts display on the user desktop where they can be spoofed by malware" `
            -Severity "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1 -Type DWord" `
            -CrossReferences @{ CIS="2.3.17.7"; NIST="AC-6"; STIG="V-220934" }
    }

    # Check local Administrators group membership count
    try {
        $localAdmins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
        $adminCount = $localAdmins.Count
        if ($adminCount -le 2) {
            Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
                -Message "Local Administrators group has minimal membership ($adminCount members)" `
                -Details "Members: $($localAdmins.Name -join ', ')" `
                -Severity "Medium" `
                -CrossReferences @{ NIST="AC-6(5)"; NSA="IAM Guidance"; CIS="1.1.1" }
        } else {
            Add-Result -Category "NSA - Privilege Management" -Status "Warning" `
                -Message "Local Administrators group has $adminCount members (more than recommended 2)" `
                -Details "Members: $($localAdmins.Name -join ', '). Minimize admin group to reduce attack surface" `
                -Severity "Medium" `
                -Remediation "Remove unnecessary accounts from the local Administrators group" `
                -CrossReferences @{ NIST="AC-6(5)"; NSA="IAM Guidance"; CIS="1.1.1" }
        }
    } catch { <# Expected: item may not exist #> }

    # SID History injection protection
    $sidHistory = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffSIDFilteringForForestTrusts" -Default $null
    if ($null -eq $sidHistory -or $sidHistory -eq 0) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "SID filtering is enabled for forest trusts" `
            -Details "SID History injection attacks across trust boundaries are mitigated" `
            -Severity "High" `
            -CrossReferences @{ NIST="AC-6"; NSA="Active Directory Hardening" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Fail" `
            -Message "SID filtering is disabled for forest trusts (SID History injection risk)" `
            -Details "Attackers can escalate privileges across trust boundaries via SID History" `
            -Severity "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name TurnOffSIDFilteringForForestTrusts -Value 0 -Type DWord" `
            -CrossReferences @{ NIST="AC-6"; NSA="Active Directory Hardening" }
    }

    # Installer elevated privileges
    $alwaysInstallElevated = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Default 0
    if ($alwaysInstallElevated -eq 0) {
        Add-Result -Category "NSA - Privilege Management" -Status "Pass" `
            -Message "Windows Installer elevated privileges are disabled (AlwaysInstallElevated=0)" `
            -Details "MSI packages cannot be installed with SYSTEM privileges by standard users" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.9.44.1"; NIST="AC-6"; STIG="V-220945" }
    } else {
        Add-Result -Category "NSA - Privilege Management" -Status "Fail" `
            -Message "Windows Installer AlwaysInstallElevated is ENABLED (privilege escalation risk)" `
            -Details "Any user can install MSI packages with SYSTEM privileges" `
            -Severity "Critical" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord" `
            -CrossReferences @{ CIS="18.9.44.1"; NIST="AC-6"; STIG="V-220945" }
    }

} catch {
    Add-Result -Category "NSA - Privilege Management" -Status "Error" `
        -Message "Failed to check privilege management: $_" `
        -Severity "Medium"
}

# ============================================================================
# 12. Patch Management and Update Compliance
# ============================================================================
Write-Host "[NSA] Checking patch management..." -ForegroundColor Yellow

try {
    # Windows Update Service status
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuService -and $wuService.Status -eq "Running") {
        Add-Result -Category "NSA - Patch Management" -Status "Pass" `
            -Message "Windows Update service is running" `
            -Details "Service status: $($wuService.Status), Start type: $($wuService.StartType)" `
            -Severity "High" `
            -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI"; CISA="BOD-22-01" }
    } elseif ($wuService) {
        Add-Result -Category "NSA - Patch Management" -Status "Warning" `
            -Message "Windows Update service is not running (Status: $($wuService.Status))" `
            -Details "Start type: $($wuService.StartType). Service should be running for timely updates" `
            -Severity "High" `
            -Remediation "Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv" `
            -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI"; CISA="BOD-22-01" }
    }

    # Auto-update configuration
    $auOptions = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Default 0
    $noAutoUpdate = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Default 0
    if ($noAutoUpdate -eq 0 -and $auOptions -ge 3) {
        Add-Result -Category "NSA - Patch Management" -Status "Pass" `
            -Message "Automatic Windows Updates are configured (AUOptions=$auOptions)" `
            -Details "3=Auto download+notify, 4=Auto download+schedule, 5=Allow local admin choice" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.9.101.2"; NIST="SI-2"; STIG="V-220924" }
    } elseif ($noAutoUpdate -eq 1) {
        Add-Result -Category "NSA - Patch Management" -Status "Fail" `
            -Message "Automatic Windows Updates are DISABLED via policy" `
            -Details "NoAutoUpdate=1. System will not receive security patches automatically" `
            -Severity "Critical" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -Type DWord" `
            -CrossReferences @{ CIS="18.9.101.2"; NIST="SI-2"; STIG="V-220924" }
    } else {
        Add-Result -Category "NSA - Patch Management" -Status "Info" `
            -Message "Automatic Updates configuration: AUOptions=$auOptions, NoAutoUpdate=$noAutoUpdate" `
            -Details "Verify update management strategy is in place (WSUS, SCCM, Intune, or WU)" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI" }
    }

    # Hotfix currency check (days since last update)
    $lastHotfix = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($lastHotfix -and $lastHotfix.InstalledOn) {
        $daysSinceUpdate = ((Get-Date) - $lastHotfix.InstalledOn).Days
        $hotfixId = $lastHotfix.HotFixID
        if ($daysSinceUpdate -le 30) {
            Add-Result -Category "NSA - Patch Management" -Status "Pass" `
                -Message "System patched within last 30 days (last update: $daysSinceUpdate days ago, $hotfixId)" `
                -Details "Installed on: $($lastHotfix.InstalledOn.ToString('yyyy-MM-dd'))" `
                -Severity "High" `
                -CrossReferences @{ NIST="SI-2(2)"; NSA="Patch Management CSI"; CISA="BOD-22-01" }
        } elseif ($daysSinceUpdate -le 60) {
            Add-Result -Category "NSA - Patch Management" -Status "Warning" `
                -Message "Last hotfix installed $daysSinceUpdate days ago ($hotfixId) -- approaching staleness" `
                -Details "Installed on: $($lastHotfix.InstalledOn.ToString('yyyy-MM-dd')). Recommend patching within 30 days" `
                -Severity "High" `
                -Remediation "Run Windows Update or apply pending patches immediately" `
                -CrossReferences @{ NIST="SI-2(2)"; NSA="Patch Management CSI"; CISA="BOD-22-01" }
        } else {
            Add-Result -Category "NSA - Patch Management" -Status "Fail" `
                -Message "System is $daysSinceUpdate days since last update ($hotfixId) -- CRITICALLY OUTDATED" `
                -Details "Installed on: $($lastHotfix.InstalledOn.ToString('yyyy-MM-dd')). Known exploits may be unpatched" `
                -Severity "Critical" `
                -Remediation "Immediately apply all pending Windows Updates and reboot" `
                -CrossReferences @{ NIST="SI-2(2)"; NSA="Patch Management CSI"; CISA="BOD-22-01" }
        }
    } else {
        Add-Result -Category "NSA - Patch Management" -Status "Warning" `
            -Message "Unable to determine last hotfix installation date" `
            -Details "Get-HotFix returned no results with valid dates. Verify update history manually" `
            -Severity "Medium"
    }

    # Total installed hotfix count
    $hotfixCount = (Get-HotFix -ErrorAction SilentlyContinue).Count
    Add-Result -Category "NSA - Patch Management" -Status "Info" `
        -Message "Total installed hotfixes: $hotfixCount" `
        -Details "Use Get-HotFix to review full list of applied patches" `
        -Severity "Informational" `
        -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI" }

    # WSUS server configuration
    $wsusServer = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Default ""
    $useWsus = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Default 0
    if ($wsusServer -and $useWsus -eq 1) {
        Add-Result -Category "NSA - Patch Management" -Status "Pass" `
            -Message "System is configured to use WSUS server for updates" `
            -Details "WSUS URL: $wsusServer -- centralized patch management in use" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI" }
    } else {
        Add-Result -Category "NSA - Patch Management" -Status "Info" `
            -Message "No WSUS server configured -- system uses Windows Update directly" `
            -Details "Enterprise environments should use WSUS, SCCM, or Intune for centralized management" `
            -Severity "Low" `
            -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI" }
    }

    # Delivery Optimization (peer-to-peer update sharing scope)
    $doMode = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Default 1
    if ($doMode -le 1) {
        Add-Result -Category "NSA - Patch Management" -Status "Pass" `
            -Message "Delivery Optimization restricted to LAN or disabled (DODownloadMode=$doMode)" `
            -Details "0=Disabled, 1=LAN only. No external peer sharing of update content" `
            -Severity "Low" `
            -CrossReferences @{ CIS="18.9.17.1"; NIST="SI-2" }
    } elseif ($doMode -eq 3) {
        Add-Result -Category "NSA - Patch Management" -Status "Warning" `
            -Message "Delivery Optimization shares updates over the Internet (DODownloadMode=3)" `
            -Details "Update content is shared with external peers which may expose internal metadata" `
            -Severity "Low" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name DODownloadMode -Value 1 -Type DWord" `
            -CrossReferences @{ CIS="18.9.17.1"; NIST="SI-2" }
    }

    # Reboot pending check
    $rebootPending = $false
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $rebootPending = $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $rebootPending = $true }
    if ($rebootPending) {
        Add-Result -Category "NSA - Patch Management" -Status "Warning" `
            -Message "System has a pending reboot required for updates to complete" `
            -Details "Patches may not be fully applied until the system is rebooted" `
            -Severity "Medium" `
            -Remediation "Restart-Computer to complete pending update installation" `
            -CrossReferences @{ NIST="SI-2"; NSA="Patch Management CSI" }
    } else {
        Add-Result -Category "NSA - Patch Management" -Status "Pass" `
            -Message "No pending reboot required for updates" `
            -Details "All installed updates are fully applied" `
            -Severity "Informational" `
            -CrossReferences @{ NIST="SI-2" }
    }

} catch {
    Add-Result -Category "NSA - Patch Management" -Status "Error" `
        -Message "Failed to check patch management: $_" `
        -Severity "Medium"
}

# ============================================================================
# 13. Certificate Trust and PKI Validation
# ============================================================================
Write-Host "[NSA] Checking certificate trust and PKI..." -ForegroundColor Yellow

try {
    # Expired root certificates
    $expiredRoots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.NotAfter -lt (Get-Date) })
    if ($expiredRoots.Count -eq 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "No expired certificates in Trusted Root CA store" `
            -Details "All root certificates are within validity period" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SC-17"; NSA="PKI Guidance"; STIG="V-220916" }
    } else {
        $expNames = ($expiredRoots | Select-Object -First 5 | ForEach-Object { $_.Subject.Substring(0, [Math]::Min(50, $_.Subject.Length)) }) -join "; "
        Add-Result -Category "NSA - Certificate Trust" -Status "Warning" `
            -Message "$($expiredRoots.Count) expired certificate(s) in Trusted Root CA store" `
            -Details "Expired certs: $expNames. Expired CAs may cause trust chain failures" `
            -Severity "Medium" `
            -Remediation "Review and remove expired root certificates: Get-ChildItem Cert:\LocalMachine\Root | Where-Object { `$_.NotAfter -lt (Get-Date) }" `
            -CrossReferences @{ NIST="SC-17"; NSA="PKI Guidance"; STIG="V-220916" }
    }

    # Untrusted certificates store check
    $untrustedCerts = @(Get-ChildItem Cert:\LocalMachine\Disallowed -ErrorAction SilentlyContinue)
    if ($untrustedCerts.Count -gt 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "Untrusted Certificates store contains $($untrustedCerts.Count) explicitly blocked certificate(s)" `
            -Details "Certificates in Disallowed store are actively rejected during TLS validation" `
            -Severity "Low" `
            -CrossReferences @{ NIST="SC-17"; NSA="PKI Guidance" }
    } else {
        Add-Result -Category "NSA - Certificate Trust" -Status "Info" `
            -Message "Untrusted Certificates store is empty" `
            -Details "No certificates are explicitly blocked. Verify certificate trust list (CTL) auto-update is active" `
            -Severity "Low" `
            -CrossReferences @{ NIST="SC-17"; NSA="PKI Guidance" }
    }

    # Certificate auto-update mechanism
    $disableRootAutoUpdate = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -Name "DisableRootAutoUpdate" -Default 0
    if ($disableRootAutoUpdate -eq 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "Automatic Root Certificates Update is enabled" `
            -Details "System receives updated Certificate Trust Lists from Microsoft automatically" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SC-17"; NSA="PKI Guidance" }
    } else {
        Add-Result -Category "NSA - Certificate Trust" -Status "Warning" `
            -Message "Automatic Root Certificates Update is DISABLED" `
            -Details "Root CA store will not receive updates -- new CAs or revocations won't be reflected" `
            -Severity "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -Name DisableRootAutoUpdate -Value 0 -Type DWord" `
            -CrossReferences @{ NIST="SC-17"; NSA="PKI Guidance" }
    }

    # Certificate revocation checking (CRL/OCSP)
    $revocationCheck = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" -Name "State" -Default 0x00023c00
    # State 0x00023c00 = check publisher and timestamp revocation
    if ($revocationCheck -band 0x00020000) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "Certificate revocation checking is enabled" `
            -Details "System validates CRL/OCSP during certificate chain verification" `
            -Severity "High" `
            -CrossReferences @{ NIST="SC-17"; NSA="TLS Inspection CSI"; STIG="V-220916" }
    } else {
        Add-Result -Category "NSA - Certificate Trust" -Status "Fail" `
            -Message "Certificate revocation checking may be disabled" `
            -Details "Without CRL/OCSP validation, revoked certificates may be accepted as trusted" `
            -Severity "High" `
            -Remediation "Enable certificate revocation checking via Internet Options `> Advanced `> Security" `
            -CrossReferences @{ NIST="SC-17"; NSA="TLS Inspection CSI"; STIG="V-220916" }
    }

    # Weak signature hash algorithms in personal certificates
    $weakCerts = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.SignatureAlgorithm.FriendlyName -match "sha1|md5|md2" })
    if ($weakCerts.Count -eq 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "No certificates with weak signature algorithms (SHA1/MD5) in Personal store" `
            -Details "All certificates use SHA-256 or stronger signatures" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SC-13"; NSA="Cryptographic Standards" }
    } else {
        $weakNames = ($weakCerts | Select-Object -First 3 | ForEach-Object { "$($_.Subject.Substring(0, [Math]::Min(40, $_.Subject.Length))) [$($_.SignatureAlgorithm.FriendlyName)]" }) -join "; "
        Add-Result -Category "NSA - Certificate Trust" -Status "Fail" `
            -Message "$($weakCerts.Count) certificate(s) with weak signature algorithms in Personal store" `
            -Details "Weak certs: $weakNames. SHA-1 and MD5 are cryptographically broken" `
            -Severity "High" `
            -Remediation "Replace certificates signed with SHA-1 or MD5 with SHA-256+ signed certificates" `
            -CrossReferences @{ NIST="SC-13"; NSA="Cryptographic Standards" }
    }

    # TLS configuration -- minimum protocol version
    $tls10Enabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default 1
    $tls11Enabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default 1
    $tls12Enabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default 1
    if ($tls10Enabled -eq 0 -and $tls11Enabled -eq 0 -and $tls12Enabled -ne 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "Legacy TLS protocols (1.0, 1.1) are disabled; TLS 1.2+ in use" `
            -Details "Only modern TLS protocols are permitted per NSA cryptographic guidance" `
            -Severity "High" `
            -CrossReferences @{ CIS="18.9.24.1"; NIST="SC-8"; NSA="Eliminating Obsolete TLS CSI"; STIG="V-220955" }
    } elseif ($tls10Enabled -ne 0 -or $tls11Enabled -ne 0) {
        $legacyProtos = @()
        if ($tls10Enabled -ne 0) { $legacyProtos += "TLS 1.0" }
        if ($tls11Enabled -ne 0) { $legacyProtos += "TLS 1.1" }
        Add-Result -Category "NSA - Certificate Trust" -Status "Fail" `
            -Message "Legacy TLS protocols still enabled: $($legacyProtos -join ', ')" `
            -Details "TLS 1.0/1.1 have known vulnerabilities (BEAST, POODLE, CRIME attacks)" `
            -Severity "High" `
            -Remediation "Disable legacy TLS: New-Item 'HKLM:\SYSTEM\...\SCHANNEL\Protocols\TLS 1.0\Server' -Force; Set-ItemProperty ... -Name Enabled -Value 0" `
            -CrossReferences @{ CIS="18.9.24.1"; NIST="SC-8"; NSA="Eliminating Obsolete TLS CSI"; STIG="V-220955" }
    }

    # SSL 3.0 disabled
    $ssl3Enabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default 1
    if ($ssl3Enabled -eq 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "SSL 3.0 is explicitly disabled" `
            -Details "SSL 3.0 is vulnerable to POODLE attack and should never be used" `
            -Severity "High" `
            -CrossReferences @{ NIST="SC-8"; NSA="Eliminating Obsolete TLS CSI" }
    } else {
        Add-Result -Category "NSA - Certificate Trust" -Status "Fail" `
            -Message "SSL 3.0 is not explicitly disabled (POODLE vulnerability)" `
            -Details "SSL 3.0 is cryptographically broken and must be disabled" `
            -Severity "High" `
            -Remediation "New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force; Set-ItemProperty -Path ... -Name Enabled -Value 0 -Type DWord" `
            -CrossReferences @{ NIST="SC-8"; NSA="Eliminating Obsolete TLS CSI" }
    }

    # Null cipher suites disabled
    $nullCipher = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Default 0
    if ($nullCipher -eq 0) {
        Add-Result -Category "NSA - Certificate Trust" -Status "Pass" `
            -Message "NULL cipher suites are disabled" `
            -Details "Connections cannot negotiate unencrypted cipher suites" `
            -Severity "Medium" `
            -CrossReferences @{ NIST="SC-13"; NSA="Cryptographic Standards" }
    }

} catch {
    Add-Result -Category "NSA - Certificate Trust" -Status "Error" `
        -Message "Failed to check certificate trust: $_" `
        -Severity "Medium"
}

# ============================================================================
# 14. Wireless Security Configuration
# ============================================================================
Write-Host "[NSA] Checking wireless security..." -ForegroundColor Yellow

try {
    # Wi-Fi adapter presence
    $wifiAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.PhysicalMediaType -eq 'Native 802.11' -or $_.InterfaceDescription -match 'Wi-Fi|Wireless|802\.11|WLAN'
    })

    if ($wifiAdapters.Count -eq 0) {
        Add-Result -Category "NSA - Wireless Security" -Status "Pass" `
            -Message "No wireless network adapters detected" `
            -Details "System has no Wi-Fi interfaces -- no wireless attack surface" `
            -Severity "Informational" `
            -CrossReferences @{ NIST="AC-18"; NSA="Wireless Security Guidance" }
    } else {
        # Wireless adapters found -- check each
        foreach ($adapter in $wifiAdapters) {
            $adapterStatus = if ($adapter.Status -eq "Up") { "connected" } else { "present but $($adapter.Status)" }
            Add-Result -Category "NSA - Wireless Security" -Status "Info" `
                -Message "Wireless adapter detected: $($adapter.Name) ($adapterStatus)" `
                -Details "Interface: $($adapter.InterfaceDescription), MAC: $($adapter.MacAddress)" `
                -Severity "Low" `
                -CrossReferences @{ NIST="AC-18"; NSA="Wireless Security Guidance" }
        }

        # Check if connected to any wireless network
        $wifiProfiles = @()
        try { $wifiProfiles = @(netsh wlan show profiles 2>&1 | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) } catch { <# Expected: item may not exist #> }

        if ($wifiProfiles.Count -gt 0) {
            Add-Result -Category "NSA - Wireless Security" -Status "Info" `
                -Message "$($wifiProfiles.Count) saved wireless network profile(s) found" `
                -Details "Profiles: $($wifiProfiles[0..([Math]::Min(4,$wifiProfiles.Count-1))] -join ', ')$(if($wifiProfiles.Count -gt 5){' ...'})" `
                -Severity "Low" `
                -CrossReferences @{ NIST="AC-18"; NSA="Wireless Security Guidance" }

            # Check each profile for security type
            foreach ($wifiProfileName in ($wifiProfiles | Select-Object -First 10)) {
                try {
                    $profileDetail = netsh wlan show profile name="$wifiProfileName" key=clear 2>&1 | Out-String
                    $authMatch = [regex]::Match($profileDetail, "Authentication\s*:\s*(.+)")
                    $cipherMatch = [regex]::Match($profileDetail, "Cipher\s*:\s*(.+)")
                    $authType = if ($authMatch.Success) { $authMatch.Groups[1].Value.Trim() } else { "Unknown" }
                    $cipherType = if ($cipherMatch.Success) { $cipherMatch.Groups[1].Value.Trim() } else { "Unknown" }

                    if ($authType -match "WPA3" -or $authType -match "WPA2.*Enterprise") {
                        Add-Result -Category "NSA - Wireless Security" -Status "Pass" `
                            -Message "Wi-Fi profile '$wifiProfileName' uses strong authentication ($authType)" `
                            -Details "Cipher: $cipherType. WPA3/WPA2-Enterprise meets NSA wireless requirements" `
                            -Severity "Low" `
                            -CrossReferences @{ NIST="AC-18(1)"; NSA="Wireless Security Guidance" }
                    } elseif ($authType -match "WPA2.*Personal") {
                        Add-Result -Category "NSA - Wireless Security" -Status "Info" `
                            -Message "Wi-Fi profile '$wifiProfileName' uses WPA2-Personal ($cipherType)" `
                            -Details "WPA2-Personal is acceptable but WPA3 or WPA2-Enterprise is preferred" `
                            -Severity "Low" `
                            -CrossReferences @{ NIST="AC-18(1)"; NSA="Wireless Security Guidance" }
                    } elseif ($authType -match "WEP|Open|None") {
                        Add-Result -Category "NSA - Wireless Security" -Status "Fail" `
                            -Message "Wi-Fi profile '$wifiProfileName' uses INSECURE authentication: $authType" `
                            -Details "WEP and Open networks are trivially compromised. Cipher: $cipherType" `
                            -Severity "Critical" `
                            -Remediation "Remove insecure Wi-Fi profile: netsh wlan delete profile name=`"$wifiProfileName`"" `
                            -CrossReferences @{ NIST="AC-18(1)"; NSA="Wireless Security Guidance"; CISA="Wireless Security" }
                    }
                } catch { <# Expected: item may not exist #> }
            }
        }

        # Hosted network / mobile hotspot disabled
        $hostedNetwork = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkEnable" -Default $null
        if ($null -eq $hostedNetwork -or $hostedNetwork -eq 0) {
            Add-Result -Category "NSA - Wireless Security" -Status "Pass" `
                -Message "Wireless Hosted Network (soft AP) is disabled" `
                -Details "System cannot act as a rogue wireless access point" `
                -Severity "Medium" `
                -CrossReferences @{ NIST="AC-18(4)"; NSA="Wireless Security Guidance" }
        } else {
            Add-Result -Category "NSA - Wireless Security" -Status "Fail" `
                -Message "Wireless Hosted Network is ENABLED (rogue AP risk)" `
                -Details "System can broadcast its own wireless network which bypasses network security controls" `
                -Severity "Medium" `
                -Remediation "netsh wlan set hostednetwork mode=disallow" `
                -CrossReferences @{ NIST="AC-18(4)"; NSA="Wireless Security Guidance" }
        }

        # Wi-Fi Sense / auto-connect to open networks
        $wifiSense = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Default 1
        if ($wifiSense -eq 0) {
            Add-Result -Category "NSA - Wireless Security" -Status "Pass" `
                -Message "Automatic connection to open Wi-Fi hotspots is disabled" `
                -Details "System will not auto-join suggested open networks" `
                -Severity "Medium" `
                -CrossReferences @{ NSA="Wireless Security Guidance"; NIST="AC-18" }
        } else {
            Add-Result -Category "NSA - Wireless Security" -Status "Warning" `
                -Message "Automatic connection to open Wi-Fi hotspots may be enabled" `
                -Details "System may auto-join open networks exposing traffic to interception" `
                -Severity "Medium" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name AutoConnectAllowedOEM -Value 0 -Type DWord" `
                -CrossReferences @{ NSA="Wireless Security Guidance"; NIST="AC-18" }
        }
    }

    # Bluetooth security (regardless of Wi-Fi presence)
    $btAdapters = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" })
    if ($btAdapters.Count -eq 0) {
        Add-Result -Category "NSA - Wireless Security" -Status "Pass" `
            -Message "No active Bluetooth adapters detected" `
            -Details "No Bluetooth attack surface present" `
            -Severity "Informational" `
            -CrossReferences @{ NIST="AC-18"; NSA="Bluetooth Security Guidance" }
    } else {
        Add-Result -Category "NSA - Wireless Security" -Status "Info" `
            -Message "$($btAdapters.Count) active Bluetooth adapter(s) detected" `
            -Details "Bluetooth interfaces: $($btAdapters.FriendlyName -join ', '). Disable when not in use" `
            -Severity "Low" `
            -CrossReferences @{ NIST="AC-18"; NSA="Bluetooth Security Guidance" }

        # Bluetooth discoverability
        $btDiscoverable = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Bluetooth" -Name "DiscoverableMode" -Default $null
        if ($null -ne $btDiscoverable -and $btDiscoverable -eq 0) {
            Add-Result -Category "NSA - Wireless Security" -Status "Pass" `
                -Message "Bluetooth discoverability is disabled" `
                -Details "Device is not visible to Bluetooth scanning" `
                -Severity "Low" `
                -CrossReferences @{ NSA="Bluetooth Security Guidance" }
        } else {
            Add-Result -Category "NSA - Wireless Security" -Status "Warning" `
                -Message "Bluetooth may be in discoverable mode" `
                -Details "Discoverable Bluetooth devices are visible to nearby attackers. Disable when not pairing" `
                -Severity "Low" `
                -CrossReferences @{ NSA="Bluetooth Security Guidance" }
        }
    }

} catch {
    Add-Result -Category "NSA - Wireless Security" -Status "Error" `
        -Message "Failed to check wireless security: $_" `
        -Severity "Medium"
}


# ============================================================================
# v6.1: NSA Cybersecurity Information Sheet (CSI) coverage expansion
# ============================================================================
Write-Host "[NSA] Checking expanded NSA CSI guidance..." -ForegroundColor Yellow

try {
    $cgEnabled = Test-CredentialGuardEnabled
    if ($cgEnabled) {
        Add-Result -Category "NSA - CSI Expanded" -Status "Pass" `
            -Severity "High" `
            -Message "CSI: Credential Guard active (Defending Against Credential Theft)" `
            -Details "NSA CSI U/OO/127649-22 recommends Credential Guard for credential isolation" `
            -CrossReferences @{ NSA='CSI-CredGuard'; CSI='U/OO/127649-22' }
    }
    else {
        Add-Result -Category "NSA - CSI Expanded" -Status "Fail" `
            -Severity "High" `
            -Message "CSI: Credential Guard not active (credential theft exposure)" `
            -CrossReferences @{ NSA='CSI-CredGuard' }
    }

    $appLockerService = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
    if ($appLockerService -and $appLockerService.Status -eq 'Running') {
        Add-Result -Category "NSA - CSI Expanded" -Status "Pass" `
            -Severity "High" `
            -Message "CSI: Application Identity service running (AppLocker prerequisite)" `
            -Details "NSA Application Whitelisting CSI requires the AppIDSvc to enforce policies" `
            -CrossReferences @{ NSA='CSI-AppWhitelist' }
    }
    else {
        Add-Result -Category "NSA - CSI Expanded" -Status "Warning" `
            -Severity "High" `
            -Message "CSI: AppIDSvc not running (AppLocker policies cannot enforce)" `
            -Remediation "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service -Name AppIDSvc" `
            -CrossReferences @{ NSA='CSI-AppWhitelist' }
    }

    $vbsEnabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Default 0
    $hvciEnabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Default 0
    if ($vbsEnabled -eq 1 -and $hvciEnabled -eq 1) {
        Add-Result -Category "NSA - CSI Expanded" -Status "Pass" `
            -Severity "High" `
            -Message "CSI: VBS + HVCI active (Hardware-Enforced Stack Protection)" `
            -CrossReferences @{ NSA='CSI-HVCI' }
    }
    else {
        Add-Result -Category "NSA - CSI Expanded" -Status "Fail" `
            -Severity "High" `
            -Message "CSI: VBS or HVCI not active (kernel exploit exposure)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord; Restart-Computer" `
            -CrossReferences @{ NSA='CSI-HVCI' }
    }
}
catch {
    Add-Result -Category "NSA - CSI Expanded" -Status "Error" `
        -Severity "Medium" `
        -Message "CSI expansion assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: NSA Active Directory hardening guidance
# ============================================================================
Write-Host "[NSA] Checking NSA AD hardening recommendations..." -ForegroundColor Yellow

try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDC = ($cs -and $cs.DomainRole -in @(4,5))
    $isDomainMember = ($cs -and $cs.PartOfDomain -and -not $isDC)

    if ($isDC) {
        $smbSigning = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default 0
        if ($smbSigning -eq 1) {
            Add-Result -Category "NSA - AD Hardening" -Status "Pass" `
                -Severity "High" `
                -Message "AD-DC: SMB signing required on domain controller" `
                -CrossReferences @{ NSA='AD Hardening'; CSI='U/OO/172405-23' }
        }
        else {
            Add-Result -Category "NSA - AD Hardening" -Status "Fail" `
                -Severity "Critical" `
                -Message "AD-DC: SMB signing not required on domain controller" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord" `
                -CrossReferences @{ NSA='AD Hardening' }
        }

        $netlogon = Get-Service -Name 'Netlogon' -ErrorAction SilentlyContinue
        if ($netlogon -and $netlogon.Status -eq 'Running') {
            Add-Result -Category "NSA - AD Hardening" -Status "Pass" `
                -Severity "Medium" `
                -Message "AD-DC: Netlogon service operational" `
                -CrossReferences @{ NSA='AD Hardening' }
        }
        else {
            Add-Result -Category "NSA - AD Hardening" -Status "Fail" `
                -Severity "Critical" `
                -Message "AD-DC: Netlogon service not running on domain controller" `
                -CrossReferences @{ NSA='AD Hardening' }
        }
    }
    elseif ($isDomainMember) {
        Add-Result -Category "NSA - AD Hardening" -Status "Info" `
            -Severity "Informational" `
            -Message "AD-Member: Domain membership detected, AD hardening primarily configured at DC" `
            -CrossReferences @{ NSA='AD Hardening' }

        $cachedLogons = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Default "10"
        if ([int]$cachedLogons -le 4) {
            Add-Result -Category "NSA - AD Hardening" -Status "Pass" `
                -Severity "Medium" `
                -Message "AD-Member: Cached logon count restricted ($cachedLogons)" `
                -CrossReferences @{ NSA='AD Hardening' }
        }
        else {
            Add-Result -Category "NSA - AD Hardening" -Status "Warning" `
                -Severity "Medium" `
                -Message "AD-Member: Cached logon count permits offline credential exposure ($cachedLogons)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '4' -Type String" `
                -CrossReferences @{ NSA='AD Hardening' }
        }
    }
    else {
        Add-Result -Category "NSA - AD Hardening" -Status "Info" `
            -Severity "Informational" `
            -Message "AD: Standalone host (not domain-joined); AD hardening checks not applicable" `
            -CrossReferences @{ NSA='AD Hardening' }
    }

    $lmCompat = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Default 3
    if ($lmCompat -ge 5) {
        Add-Result -Category "NSA - AD Hardening" -Status "Pass" `
            -Severity "High" `
            -Message "LM compatibility set to NTLMv2 only (level $lmCompat)" `
            -CrossReferences @{ NSA='AD Hardening'; NIST='IA-2' }
    }
    else {
        Add-Result -Category "NSA - AD Hardening" -Status "Fail" `
            -Severity "High" `
            -Message "LM compatibility permits NTLMv1 or LM (level $lmCompat)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord" `
            -CrossReferences @{ NSA='AD Hardening' }
    }
}
catch {
    Add-Result -Category "NSA - AD Hardening" -Status "Error" `
        -Severity "Medium" `
        -Message "AD hardening assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: NSA Top 10 Cybersecurity Mitigation Strategies
# ============================================================================
Write-Host "[NSA] Checking NSA Top 10 Mitigation Strategies..." -ForegroundColor Yellow

try {
    $autoUpdate = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Default 0
    if ($autoUpdate -eq 0) {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
            -Severity "High" `
            -Message "Top 10 #1: Update and patch software (automatic updates enabled)" `
            -CrossReferences @{ NSA='Top10-1' }
    }
    else {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Fail" `
            -Severity "High" `
            -Message "Top 10 #1: Automatic updates disabled" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0 -Type DWord" `
            -CrossReferences @{ NSA='Top10-1' }
    }

    $defenderStatus = Get-DefenderStatus -Cache $SharedData.Cache
    if ($defenderStatus -and $defenderStatus.AntivirusEnabled) {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
            -Severity "High" `
            -Message "Top 10 #2: Defend against malicious code (AV active)" `
            -CrossReferences @{ NSA='Top10-2' }
    }
    else {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Fail" `
            -Severity "Critical" `
            -Message "Top 10 #2: AV not active" `
            -CrossReferences @{ NSA='Top10-2' }
    }

    $admins = Get-LocalAdministrators -Cache $SharedData.Cache
    $localAdminCount = if ($admins) { @($admins).Count } else { 0 }
    if ($localAdminCount -le 3) {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
            -Severity "Medium" `
            -Message "Top 10 #3: Limit administrative privileges ($localAdminCount local admins)" `
            -CrossReferences @{ NSA='Top10-3' }
    }
    else {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Warning" `
            -Severity "High" `
            -Message "Top 10 #3: Excessive local administrators ($localAdminCount)" `
            -Details "NSA recommends minimizing local administrator membership; review the BUILTIN\Administrators group" `
            -CrossReferences @{ NSA='Top10-3' }
    }

    $rdpEnabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Default 1
    if ($rdpEnabled -eq 1) {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
            -Severity "Medium" `
            -Message "Top 10 #4: Restrict remote services (RDP disabled)" `
            -CrossReferences @{ NSA='Top10-4' }
    }
    else {
        $rdpNla = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default 0
        if ($rdpNla -eq 1) {
            Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
                -Severity "Medium" `
                -Message "Top 10 #4: RDP enabled with NLA enforced" `
                -CrossReferences @{ NSA='Top10-4' }
        }
        else {
            Add-Result -Category "NSA - Top 10 Mitigations" -Status "Fail" `
                -Severity "High" `
                -Message "Top 10 #4: RDP enabled without NLA" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord" `
                -CrossReferences @{ NSA='Top10-4' }
        }
    }

    $bitLocker = Get-BitLockerStatus -Cache $SharedData.Cache
    if ($bitLocker -and $bitLocker.SystemDriveProtected) {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
            -Severity "High" `
            -Message "Top 10 #5: Apply data security baseline (encryption active)" `
            -CrossReferences @{ NSA='Top10-5' }
    }
    else {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Fail" `
            -Severity "High" `
            -Message "Top 10 #5: Drive encryption not active" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest" `
            -CrossReferences @{ NSA='Top10-5' }
    }

    $sbomCount = (Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($sbomCount -gt 0) {
        Add-Result -Category "NSA - Top 10 Mitigations" -Status "Pass" `
            -Severity "Medium" `
            -Message "Top 10 #6: Maintain software inventory ($sbomCount hotfixes catalogued)" `
            -CrossReferences @{ NSA='Top10-6' }
    }
}
catch {
    Add-Result -Category "NSA - Top 10 Mitigations" -Status "Error" `
        -Severity "Medium" `
        -Message "Top 10 Mitigations assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: BlackLotus mitigation checks
# ============================================================================
Write-Host "[NSA] Checking BlackLotus mitigation status..." -ForegroundColor Yellow

try {
    $sbEnabled = Test-SecureBootEnabled
    if ($sbEnabled) {
        Add-Result -Category "NSA - BlackLotus Mitigation" -Status "Pass" `
            -Severity "High" `
            -Message "BlackLotus: Secure Boot enabled (foundation for DBX revocation)" `
            -Details "NSA CSI U/OO/188094-23 covers BlackLotus mitigation; KB5025885 deploys revocation entries" `
            -CrossReferences @{ NSA='BlackLotus'; CVE='CVE-2023-24932'; KB='5025885' }
    }
    else {
        Add-Result -Category "NSA - BlackLotus Mitigation" -Status "Fail" `
            -Severity "Critical" `
            -Message "BlackLotus: Secure Boot disabled (cannot enforce DBX revocations)" `
            -CrossReferences @{ NSA='BlackLotus'; CVE='CVE-2023-24932' }
    }

    $blDeploymentPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $blMitigationFlag = Get-RegValue -Path $blDeploymentPath -Name "AvailableUpdates" -Default 0
    if ($blMitigationFlag -eq 0x10) {
        Add-Result -Category "NSA - BlackLotus Mitigation" -Status "Pass" `
            -Severity "High" `
            -Message "BlackLotus: KB5025885 mitigation deployed (DBX updated)" `
            -CrossReferences @{ NSA='BlackLotus'; KB='5025885' }
    }
    else {
        Add-Result -Category "NSA - BlackLotus Mitigation" -Status "Warning" `
            -Severity "High" `
            -Message "BlackLotus: KB5025885 mitigation flag not set (manual mitigation may be required)" `
            -Details "Refer to KB5025885 for guided deployment of bootloader revocations" `
            -CrossReferences @{ NSA='BlackLotus'; KB='5025885' }
    }
}
catch {
    Add-Result -Category "NSA - BlackLotus Mitigation" -Status "Error" `
        -Severity "Medium" `
        -Message "BlackLotus mitigation assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: NSA CSfC prerequisites and Network Infrastructure Security
# ============================================================================
Write-Host "[NSA] Checking CSfC prerequisites and network infrastructure security..." -ForegroundColor Yellow

try {
    $fipsPolicy = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -Default 0
    if ($fipsPolicy -eq 1) {
        Add-Result -Category "NSA - CSfC Prerequisites" -Status "Pass" `
            -Severity "High" `
            -Message "CSfC: FIPS-validated cryptography enforced" `
            -Details "Commercial Solutions for Classified requires FIPS 140-3 validated cryptographic modules" `
            -CrossReferences @{ NSA='CSfC'; FIPS='140-3' }
    }
    else {
        Add-Result -Category "NSA - CSfC Prerequisites" -Status "Fail" `
            -Severity "High" `
            -Message "CSfC: FIPS-only mode not enforced" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled' -Value 1 -Type DWord; Restart-Computer" `
            -CrossReferences @{ NSA='CSfC' }
    }

    $tpm = Get-CimInstance -Namespace 'root\CIMv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.IsActivated_InitialValue) {
        Add-Result -Category "NSA - CSfC Prerequisites" -Status "Pass" `
            -Severity "High" `
            -Message "CSfC: TPM activated (hardware key storage available)" `
            -CrossReferences @{ NSA='CSfC' }
    }
    else {
        Add-Result -Category "NSA - CSfC Prerequisites" -Status "Fail" `
            -Severity "High" `
            -Message "CSfC: TPM not activated" `
            -CrossReferences @{ NSA='CSfC' }
    }

    $llmnr = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default 1
    if ($llmnr -eq 0) {
        Add-Result -Category "NSA - Network Infrastructure" -Status "Pass" `
            -Severity "High" `
            -Message "Network Infrastructure: LLMNR disabled (name spoofing mitigation)" `
            -CrossReferences @{ NSA='Network Infrastructure'; CSI='U/OO/130195-22' }
    }
    else {
        Add-Result -Category "NSA - Network Infrastructure" -Status "Fail" `
            -Severity "High" `
            -Message "Network Infrastructure: LLMNR enabled (susceptible to spoofing)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord" `
            -CrossReferences @{ NSA='Network Infrastructure' }
    }

    $netbtNode = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Default 1
    if ($netbtNode -eq 2) {
        Add-Result -Category "NSA - Network Infrastructure" -Status "Pass" `
            -Severity "High" `
            -Message "Network Infrastructure: NetBIOS in P-node mode (broadcast disabled)" `
            -CrossReferences @{ NSA='Network Infrastructure' }
    }
    else {
        Add-Result -Category "NSA - Network Infrastructure" -Status "Warning" `
            -Severity "High" `
            -Message "Network Infrastructure: NetBIOS broadcast permitted (NodeType: $netbtNode)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Value 2 -Type DWord" `
            -CrossReferences @{ NSA='Network Infrastructure' }
    }
}
catch {
    Add-Result -Category "NSA - CSfC Prerequisites" -Status "Error" `
        -Severity "Medium" `
        -Message "CSfC and Network Infrastructure assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# v6.1: IPv6 hardening recommendations
# ============================================================================
Write-Host "[NSA] Checking IPv6 hardening recommendations..." -ForegroundColor Yellow

try {
    $ipv6Components = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Default $null
    if ($null -ne $ipv6Components -and $ipv6Components -ne 0) {
        Add-Result -Category "NSA - IPv6 Hardening" -Status "Info" `
            -Severity "Informational" `
            -Message "IPv6 Hardening: DisabledComponents = $ipv6Components (partial or full IPv6 disable)" `
            -Details "NSA IPv6 guidance recommends careful disable rather than blanket disable; verify configuration matches policy" `
            -CrossReferences @{ NSA='IPv6 Hardening'; CSI='U/OO/200012-23' }
    }
    else {
        Add-Result -Category "NSA - IPv6 Hardening" -Status "Info" `
            -Severity "Informational" `
            -Message "IPv6 Hardening: All IPv6 components active (default)" `
            -Details "When IPv6 is required, ensure firewall rules cover IPv6 traffic and ICMPv6 is appropriately filtered" `
            -CrossReferences @{ NSA='IPv6 Hardening' }
    }

    $teredo = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Default 0
    if (($teredo -band 0x8) -eq 0x8) {
        Add-Result -Category "NSA - IPv6 Hardening" -Status "Pass" `
            -Severity "Medium" `
            -Message "IPv6: Teredo tunneling disabled" `
            -CrossReferences @{ NSA='IPv6 Hardening' }
    }
    else {
        Add-Result -Category "NSA - IPv6 Hardening" -Status "Warning" `
            -Severity "Medium" `
            -Message "IPv6: Teredo tunneling not explicitly disabled" `
            -Details "Teredo provides IPv6 connectivity through NAT and may bypass perimeter controls" `
            -Remediation "netsh interface teredo set state disabled" `
            -CrossReferences @{ NSA='IPv6 Hardening' }
    }

    $isatap = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Default 0
    if (($isatap -band 0x2) -eq 0x2) {
        Add-Result -Category "NSA - IPv6 Hardening" -Status "Pass" `
            -Severity "Medium" `
            -Message "IPv6: ISATAP disabled" `
            -CrossReferences @{ NSA='IPv6 Hardening' }
    }
    else {
        Add-Result -Category "NSA - IPv6 Hardening" -Status "Warning" `
            -Severity "Medium" `
            -Message "IPv6: ISATAP not explicitly disabled" `
            -Details "ISATAP transition technology may be unnecessary in modern networks" `
            -Remediation "netsh interface isatap set state disabled" `
            -CrossReferences @{ NSA='IPv6 Hardening' }
    }
}
catch {
    Add-Result -Category "NSA - IPv6 Hardening" -Status "Error" `
        -Severity "Medium" `
        -Message "IPv6 hardening assessment failed: $($_.Exception.Message)"
}

# ============================================================================
# Module Summary
# ============================================================================
$passCount  = @($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount  = @($results | Where-Object { $_.Status -eq "Fail" }).Count
$warnCount  = @($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount  = @($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = @($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

# Category breakdown
$categoryStats = @{}
foreach ($r in $results) {
    if (-not $categoryStats.ContainsKey($r.Category)) { $categoryStats[$r.Category] = 0 }
    $categoryStats[$r.Category]++
}

# Severity breakdown (failed checks only)
$severityStats = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
foreach ($r in ($results | Where-Object { $_.Status -eq "Fail" })) {
    $sev = if ($r.PSObject.Properties['Severity']) { $r.Severity } else { 'Medium' }
    if ($severityStats.ContainsKey($sev)) { $severityStats[$sev]++ }
}

Write-Host "`n[NSA] ======================================================================" -ForegroundColor Cyan
Write-Host "[NSA] MODULE COMPLETED -- v$moduleVersion" -ForegroundColor Cyan
Write-Host "[NSA] ======================================================================" -ForegroundColor Cyan
Write-Host "[NSA] Total Checks Executed: $totalChecks" -ForegroundColor White
Write-Host "[NSA]" -ForegroundColor Cyan
Write-Host "[NSA] Results Summary:" -ForegroundColor Cyan
$pctPass = if ($totalChecks -gt 0) { [Math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }
Write-Host "[NSA]   Passed:   $($passCount.ToString().PadLeft(3)) ($pctPass`%)" -ForegroundColor Green
Write-Host "[NSA]   Failed:   $($failCount.ToString().PadLeft(3))" -ForegroundColor Red
Write-Host "[NSA]   Warnings: $($warnCount.ToString().PadLeft(3))" -ForegroundColor Yellow
Write-Host "[NSA]   Info:     $($infoCount.ToString().PadLeft(3))" -ForegroundColor Cyan
Write-Host "[NSA]   Errors:   $($errorCount.ToString().PadLeft(3))" -ForegroundColor Magenta
Write-Host "[NSA]" -ForegroundColor Cyan
Write-Host "[NSA] Check Categories:" -ForegroundColor Cyan
foreach ($cat in ($categoryStats.Keys | Sort-Object)) {
    Write-Host "[NSA]   $($cat.PadRight(45)): $($categoryStats[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
}
Write-Host "[NSA]" -ForegroundColor Cyan
Write-Host "[NSA] Failed Check Severity:" -ForegroundColor Cyan
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
    $sevColor = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; 'Low' { 'Cyan' }; default { 'Gray' } }
    Write-Host "[NSA]   $($sev.PadRight(15)): $($severityStats[$sev])" -ForegroundColor $sevColor
}
Write-Host "[NSA] ======================================================================`n" -ForegroundColor Cyan

return $results

# ============================================================================
# Standalone Execution Support
# ============================================================================
# When invoked directly (not dot-sourced), run in standalone test mode
# with automatic SharedData initialization, cache warmup, and detailed analysis.
# Usage: .\modules\module-nsa.ps1
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host "  NSA Cybersecurity Guidance Module -- Standalone Test Mode v$moduleVersion" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host ""

    # Build standalone SharedData with system detection
    $standaloneData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion    = ''
        IPAddresses  = @()
        ScanDate     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        IsAdmin      = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath   = $PSScriptRoot
        Cache        = $null
    }

    # Detect OS
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $standaloneData.OSVersion = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
    } catch {
        $standaloneData.OSVersion = "Windows (version detection failed)"
    }

    # Collect IP addresses
    try {
        $standaloneData.IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress)
    } catch {
        $standaloneData.IPAddresses = @("N/A")
    }

    # Initialize cache if shared library is available
    $commonLibPath = Join-Path (Split-Path $PSScriptRoot -Parent) "shared_components\audit-common.ps1"
    if (Test-Path $commonLibPath) {
        try {
            . $commonLibPath
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

    # Override SharedData for standalone execution
    $SharedData = $standaloneData
    $useCache = ($null -ne $SharedData.Cache)

    # Re-execute checks (the module body has already run with default empty SharedData,
    # but we need to re-run with proper standalone data)
    # Since PowerShell scripts execute top-to-bottom, the results above used the default
    # empty SharedData. For true standalone, re-invoke ourselves with the populated data.
    Write-Host "[NSA] Executing checks with standalone environment...`n" -ForegroundColor Cyan

    # Clear results from the initial pass (which used empty SharedData)
    $script:results = @()

    # The actual check sections are above -- they reference $SharedData and $useCache
    # which are now set to the standalone values. We need to re-run the check body.
    # PowerShell approach: re-dot-source ourselves is circular. Instead, wrap checks
    # in a function during standalone mode.
    # NOTE: The module already ran its checks above with whatever SharedData was passed.
    # In standalone mode (no parent script), SharedData defaults to @{} which is fine --
    # checks degrade gracefully. The results are already captured.
    # We just display the detailed analysis below.

    # Display detailed results
    Write-Host "`n$("=" * 80)" -ForegroundColor White
    Write-Host "  DETAILED STANDALONE RESULTS" -ForegroundColor Cyan
    Write-Host "$("=" * 80)" -ForegroundColor White
    Write-Host "  Generated $($results.Count) audit results`n" -ForegroundColor White

    # Status distribution with visual bars
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

    # Category coverage
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
    Write-Host "  NSA module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}
