# Module-NSA.ps1
# NSA Windows Security Guidance Compliance Module
# Version: 5.0
# Based on NSA Cybersecurity Information Sheets and Guidance

<#
.SYNOPSIS
    NSA Windows security guidance compliance checks.

.DESCRIPTION
    This module checks alignment with NSA cybersecurity guidance including:
    - Secure Boot configuration
    - Application whitelisting (AppLocker/WDAC)
    - Credential protection (Credential Guard, LSASS protection)
    - Remote Desktop security
    - PowerShell security (logging, v2 removal)
    - SMB security and signing
    - Windows Defender configuration
    - Audit and logging policies
    - Network hardening (LLMNR, NetBIOS)

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Version: 5.0
    Based on: NSA Cybersecurity Technical Reports
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "NSA"
$results = @()

# Helper function to add results
function Add-Result {
    param($Category, $Status, $Message, $Details = "", $Remediation = "")
    $script:results += [PSCustomObject]@{
        Module = $moduleName
        Category = $Category
        Status = $Status
        Message = $Message
        Details = $Details
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

Write-Host "`n[NSA] Starting NSA cybersecurity guidance checks..." -ForegroundColor Cyan

# ============================================================================
# NSA Guidance: Secure Windows Boot Process
# ============================================================================
Write-Host "[NSA] Checking Boot Security..." -ForegroundColor Yellow

# Check Secure Boot status
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($secureBoot -eq $true) {
        Add-Result -Category "NSA - Boot Security" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "NSA Guidance: Secure Boot protects against bootkit malware"
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "NSA - Boot Security" -Status "Fail" `
            -Message "Secure Boot is disabled" `
            -Details "NSA Guidance: Enable Secure Boot to protect boot process" `
            -Remediation "Enable Secure Boot in UEFI/BIOS settings"
    } else {
        Add-Result -Category "NSA - Boot Security" -Status "Warning" `
            -Message "Secure Boot status cannot be determined (Legacy BIOS?)" `
            -Details "NSA Guidance: UEFI with Secure Boot is recommended"
    }
} catch {
    Add-Result -Category "NSA - Boot Security" -Status "Info" `
        -Message "Unable to check Secure Boot status (may require UEFI)" `
        -Details "NSA Guidance: Verify Secure Boot status in BIOS/UEFI"
}

# Check for BitLocker on system drive
try {
    $systemDrive = $env:SystemDrive
    $bitlockerStatus = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
    
    if ($bitlockerStatus) {
        if ($bitlockerStatus.VolumeStatus -eq "FullyEncrypted") {
            Add-Result -Category "NSA - Boot Security" -Status "Pass" `
                -Message "System drive is encrypted with BitLocker" `
                -Details "NSA Guidance: Full disk encryption protects data at rest"
        } else {
            Add-Result -Category "NSA - Boot Security" -Status "Fail" `
                -Message "System drive is not fully encrypted (Status: $($bitlockerStatus.VolumeStatus))" `
                -Details "NSA Guidance: Enable BitLocker with TPM" `
                -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly"
        }
    }
} catch {
    Add-Result -Category "NSA - Boot Security" -Status "Info" `
        -Message "BitLocker status check requires administrative privileges" `
        -Details "NSA Guidance: Implement full disk encryption"
}

# ============================================================================
# NSA Guidance: Application Whitelisting / AppLocker
# ============================================================================
Write-Host "[NSA] Checking Application Control..." -ForegroundColor Yellow

# Check AppLocker status
try {
    $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($appLockerService) {
        if ($appLockerService.Status -eq "Running") {
            Add-Result -Category "NSA - Application Control" -Status "Pass" `
                -Message "AppLocker service (AppIDSvc) is running" `
                -Details "NSA Guidance: Application whitelisting prevents unauthorized software"
            
            # Check if AppLocker policies exist
            $appLockerPolicies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
            if ($appLockerPolicies) {
                $ruleCount = ($appLockerPolicies.RuleCollections | Measure-Object).Count
                Add-Result -Category "NSA - Application Control" -Status "Pass" `
                    -Message "AppLocker policies are configured ($ruleCount rule collections)" `
                    -Details "NSA Guidance: Application whitelisting is active"
            } else {
                Add-Result -Category "NSA - Application Control" -Status "Warning" `
                    -Message "AppLocker service is running but no policies found" `
                    -Details "NSA Guidance: Configure AppLocker policies" `
                    -Remediation "Configure AppLocker rules via Group Policy"
            }
        } else {
            Add-Result -Category "NSA - Application Control" -Status "Fail" `
                -Message "AppLocker service is not running" `
                -Details "NSA Guidance: Enable application whitelisting" `
                -Remediation "Start-Service AppIDSvc; Set-Service AppIDSvc -StartupType Automatic"
        }
    }
} catch {
    Add-Result -Category "NSA - Application Control" -Status "Error" `
        -Message "Failed to check AppLocker status: $_"
}

# Check Windows Defender Application Control (WDAC) / Device Guard
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($deviceGuard) {
        if ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Add-Result -Category "NSA - Application Control" -Status "Pass" `
                -Message "Windows Defender Application Control is enforced" `
                -Details "NSA Guidance: WDAC/Device Guard provides strong application control"
        } else {
            Add-Result -Category "NSA - Application Control" -Status "Info" `
                -Message "Windows Defender Application Control is not enforced" `
                -Details "NSA Guidance: Consider implementing WDAC for enhanced security"
        }
    }
} catch {
    Add-Result -Category "NSA - Application Control" -Status "Info" `
        -Message "Could not check WDAC/Device Guard status" `
        -Details "NSA Guidance: WDAC provides additional application control"
}

# ============================================================================
# NSA Guidance: Credential Protection
# ============================================================================
Write-Host "[NSA] Checking Credential Protection..." -ForegroundColor Yellow

# Check Credential Guard status
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($deviceGuard) {
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "NSA Guidance: Credential Guard protects against credential theft"
        } else {
            Add-Result -Category "NSA - Credential Protection" -Status "Warning" `
                -Message "Credential Guard is not running" `
                -Details "NSA Guidance: Enable Credential Guard on compatible systems" `
                -Remediation "Enable via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard"
        }
    }
} catch {
    Add-Result -Category "NSA - Credential Protection" -Status "Info" `
        -Message "Could not check Credential Guard status" `
        -Details "NSA Guidance: Credential Guard requires compatible hardware"
}

# Check LSASS protection (RunAsPPL)
try {
    $lsassProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsassProtection -and $lsassProtection.RunAsPPL -eq 1) {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "LSASS is running as Protected Process Light (PPL)" `
            -Details "NSA Guidance: PPL protects LSASS from credential dumping attacks"
    } else {
        Add-Result -Category "NSA - Credential Protection" -Status "Fail" `
            -Message "LSASS is not running as Protected Process" `
            -Details "NSA Guidance: Enable PPL to protect credentials in memory" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1; Restart-Computer"
    }
} catch {
    Add-Result -Category "NSA - Credential Protection" -Status "Error" `
        -Message "Failed to check LSASS protection: $_"
}

# Check for credential caching (WDigest)
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "WDigest credential caching is disabled" `
            -Details "NSA Guidance: Disabled WDigest prevents plaintext credential storage"
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "NSA - Credential Protection" -Status "Fail" `
            -Message "WDigest credential caching is enabled" `
            -Details "NSA Guidance: Disable WDigest to prevent plaintext credential theft" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
    } else {
        Add-Result -Category "NSA - Credential Protection" -Status "Pass" `
            -Message "WDigest credential caching is disabled (default on modern Windows)" `
            -Details "NSA Guidance: WDigest is disabled by default on Windows 8.1+"
    }
} catch {
    Add-Result -Category "NSA - Credential Protection" -Status "Error" `
        -Message "Failed to check WDigest status: $_"
}

# ============================================================================
# NSA Guidance: Remote Desktop Security
# ============================================================================
Write-Host "[NSA] Checking Remote Desktop Security..." -ForegroundColor Yellow

# Check RDP status
try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "NSA - Remote Access" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "NSA Guidance: Disable RDP if not needed"
    } else {
        # RDP is enabled, check security settings
        Add-Result -Category "NSA - Remote Access" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "NSA Guidance: Secure RDP if required for operations"
        
        # Check NLA requirement
        $nlaRequired = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        if ($nlaRequired -and $nlaRequired.UserAuthentication -eq 1) {
            Add-Result -Category "NSA - Remote Access" -Status "Pass" `
                -Message "RDP: Network Level Authentication (NLA) is required" `
                -Details "NSA Guidance: NLA provides additional authentication security"
        } else {
            Add-Result -Category "NSA - Remote Access" -Status "Fail" `
                -Message "RDP: Network Level Authentication is not required" `
                -Details "NSA Guidance: Enable NLA for RDP connections" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
        
        # Check encryption level
        $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        if ($encLevel -and $encLevel.MinEncryptionLevel -ge 3) {
            Add-Result -Category "NSA - Remote Access" -Status "Pass" `
                -Message "RDP: High encryption level is configured" `
                -Details "NSA Guidance: Use strong encryption for RDP"
        } else {
            Add-Result -Category "NSA - Remote Access" -Status "Warning" `
                -Message "RDP: Encryption level may not be set to High" `
                -Details "NSA Guidance: Set RDP encryption to High" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
        }
    }
} catch {
    Add-Result -Category "NSA - Remote Access" -Status "Error" `
        -Message "Failed to check RDP configuration: $_"
}

# ============================================================================
# NSA Guidance: PowerShell Security
# ============================================================================
Write-Host "[NSA] Checking PowerShell Security..." -ForegroundColor Yellow

# Check PowerShell v2 status (should be disabled)
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    if ($psv2) {
        if ($psv2.State -eq "Disabled") {
            Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
                -Message "PowerShell v2 is disabled" `
                -Details "NSA Guidance: Remove PowerShell v2 to prevent downgrade attacks"
        } else {
            Add-Result -Category "NSA - PowerShell Security" -Status "Fail" `
                -Message "PowerShell v2 is enabled" `
                -Details "NSA Guidance: Disable PowerShell v2 (lacks security features)" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
        }
    }
} catch {
    Add-Result -Category "NSA - PowerShell Security" -Status "Info" `
        -Message "Could not check PowerShell v2 status" `
        -Details "NSA Guidance: Verify PowerShell v2 is disabled"
}

# Check PowerShell logging
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "NSA Guidance: Enable comprehensive PowerShell logging"
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Warning" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "NSA Guidance: Enable logging to detect malicious PowerShell activity" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
    }
    
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    if ($moduleLogging -and $moduleLogging.EnableModuleLogging -eq 1) {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Module Logging is enabled" `
            -Details "NSA Guidance: Comprehensive logging aids threat detection"
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Info" `
            -Message "PowerShell Module Logging is not enabled" `
            -Details "NSA Guidance: Enable module logging for comprehensive auditing"
    }
    
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    if ($transcription -and $transcription.EnableTranscripting -eq 1) {
        Add-Result -Category "NSA - PowerShell Security" -Status "Pass" `
            -Message "PowerShell Transcription is enabled" `
            -Details "NSA Guidance: Transcription logs complete PowerShell session activity"
    } else {
        Add-Result -Category "NSA - PowerShell Security" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "NSA Guidance: Enable transcription for full session logging"
    }
} catch {
    Add-Result -Category "NSA - PowerShell Security" -Status "Error" `
        -Message "Failed to check PowerShell logging: $_"
}

# ============================================================================
# NSA Guidance: SMB Security
# ============================================================================
Write-Host "[NSA] Checking SMB Security..." -ForegroundColor Yellow

# Check SMBv1 status (should be disabled)
try {
    $smbv1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol
    if ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $false) {
        Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "NSA Guidance: Disable SMBv1 (vulnerable to WannaCry, NotPetya)"
    } elseif ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $true) {
        Add-Result -Category "NSA - Network Protocol Security" -Status "Fail" `
            -Message "SMBv1 protocol is enabled" `
            -Details "NSA Guidance: SMBv1 has critical vulnerabilities - disable immediately" `
            -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    }
} catch {
    Add-Result -Category "NSA - Network Protocol Security" -Status "Error" `
        -Message "Failed to check SMBv1 status: $_"
}

# Check SMB signing
try {
    $smbSigning = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object RequireSecuritySignature
    if ($smbSigning -and $smbSigning.RequireSecuritySignature -eq $true) {
        Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
            -Message "SMB signing is required" `
            -Details "NSA Guidance: SMB signing prevents man-in-the-middle attacks"
    } else {
        Add-Result -Category "NSA - Network Protocol Security" -Status "Warning" `
            -Message "SMB signing is not required" `
            -Details "NSA Guidance: Require SMB signing to prevent tampering" `
            -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
    }
} catch {
    Add-Result -Category "NSA - Network Protocol Security" -Status "Error" `
        -Message "Failed to check SMB signing: $_"
}

# Check SMB encryption
try {
    $smbEncryption = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EncryptData
    if ($smbEncryption -and $smbEncryption.EncryptData -eq $true) {
        Add-Result -Category "NSA - Network Protocol Security" -Status "Pass" `
            -Message "SMB encryption is enabled" `
            -Details "NSA Guidance: SMB encryption protects data in transit"
    } else {
        Add-Result -Category "NSA - Network Protocol Security" -Status "Info" `
            -Message "SMB encryption is not enabled globally" `
            -Details "NSA Guidance: Consider enabling SMB encryption for sensitive data"
    }
} catch {
    Add-Result -Category "NSA - Network Protocol Security" -Status "Error" `
        -Message "Failed to check SMB encryption: $_"
}

# ============================================================================
# NSA Guidance: Windows Defender / Antivirus
# ============================================================================
Write-Host "[NSA] Checking Endpoint Protection..." -ForegroundColor Yellow

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus) {
        # Real-time protection
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                -Message "Windows Defender real-time protection is enabled" `
                -Details "NSA Guidance: Enable real-time antivirus protection"
        } else {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Fail" `
                -Message "Windows Defender real-time protection is disabled" `
                -Details "NSA Guidance: Enable endpoint protection" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
        }
        
        # Cloud-delivered protection
        if ($defenderStatus.CloudProtectionEnabled) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                -Message "Cloud-delivered protection is enabled" `
                -Details "NSA Guidance: Cloud protection provides rapid threat response"
        } else {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
                -Message "Cloud-delivered protection is disabled" `
                -Details "NSA Guidance: Enable cloud protection for enhanced detection" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced"
        }
        
        # Behavior monitoring
        if ($defenderStatus.BehaviorMonitorEnabled) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                -Message "Behavior monitoring is enabled" `
                -Details "NSA Guidance: Behavior monitoring detects suspicious activity"
        } else {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
                -Message "Behavior monitoring is disabled" `
                -Details "NSA Guidance: Enable behavior monitoring" `
                -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
        }
        
        # IOAV protection
        if ($defenderStatus.IoavProtectionEnabled) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                -Message "Downloaded file and attachment scanning is enabled" `
                -Details "NSA Guidance: IOAV protects against downloaded threats"
        } else {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
                -Message "Downloaded file scanning is disabled" `
                -Details "NSA Guidance: Enable IOAV protection" `
                -Remediation "Set-MpPreference -DisableIOAVProtection `$false"
        }
        
        # Signature updates
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        if ($signatureAge.Days -le 1) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Pass" `
                -Message "Antivirus signatures are current (updated: $($defenderStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')))" `
                -Details "NSA Guidance: Keep antivirus signatures up to date"
        } elseif ($signatureAge.Days -le 7) {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Warning" `
                -Message "Antivirus signatures are $($signatureAge.Days) days old" `
                -Details "NSA Guidance: Update signatures daily" `
                -Remediation "Update-MpSignature"
        } else {
            Add-Result -Category "NSA - Endpoint Protection" -Status "Fail" `
                -Message "Antivirus signatures are outdated ($($signatureAge.Days) days old)" `
                -Details "NSA Guidance: Update immediately" `
                -Remediation "Update-MpSignature"
        }
    }
} catch {
    Add-Result -Category "NSA - Endpoint Protection" -Status "Error" `
        -Message "Failed to check Windows Defender status: $_"
}

# Check Windows Defender Exploit Guard
try {
    $exploitProtection = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    if ($exploitProtection) {
        Add-Result -Category "NSA - Endpoint Protection" -Status "Info" `
            -Message "Exploit Protection settings are configured" `
            -Details "NSA Guidance: Exploit Guard provides additional protection against exploits"
    }
} catch {
    Add-Result -Category "NSA - Endpoint Protection" -Status "Info" `
        -Message "Could not check Exploit Protection status" `
        -Details "NSA Guidance: Configure Exploit Guard for enhanced protection"
}

# ============================================================================
# NSA Guidance: Audit and Logging
# ============================================================================
Write-Host "[NSA] Checking Audit and Logging..." -ForegroundColor Yellow

# Check if Advanced Audit Policy is in use
try {
    $advancedAudit = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    if ($advancedAudit -and $advancedAudit.SCENoApplyLegacyAuditPolicy -eq 1) {
        Add-Result -Category "NSA - Audit and Logging" -Status "Pass" `
            -Message "Advanced Audit Policy is configured" `
            -Details "NSA Guidance: Use Advanced Audit Policy for granular logging"
    } else {
        Add-Result -Category "NSA - Audit and Logging" -Status "Warning" `
            -Message "Advanced Audit Policy may not be in effect" `
            -Details "NSA Guidance: Enable Advanced Audit Policy" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1"
    }
} catch {
    Add-Result -Category "NSA - Audit and Logging" -Status "Error" `
        -Message "Failed to check Advanced Audit Policy: $_"
}

# Check critical audit categories
$criticalAudits = @(
    "Logon/Logoff",
    "Account Management",
    "Process Creation",
    "Privilege Use"
)

foreach ($category in $criticalAudits) {
    try {
        $auditSetting = auditpol /get /category:"$category" 2>$null
        if ($auditSetting -and ($auditSetting -match "Success" -or $auditSetting -match "Failure")) {
            Add-Result -Category "NSA - Audit and Logging" -Status "Pass" `
                -Message "Auditing enabled for: $category" `
                -Details "NSA Guidance: Comprehensive logging aids threat detection"
        } else {
            Add-Result -Category "NSA - Audit and Logging" -Status "Warning" `
                -Message "Auditing not configured for: $category" `
                -Details "NSA Guidance: Enable auditing for security events" `
                -Remediation "auditpol /set /category:'$category' /success:enable /failure:enable"
        }
    } catch {
        # Continue checking other categories
    }
}

# ============================================================================
# NSA Guidance: Network Hardening
# ============================================================================
Write-Host "[NSA] Checking Network Hardening..." -ForegroundColor Yellow

# Check Windows Firewall
try {
    $profiles = @("Domain", "Private", "Public")
    foreach ($profile in $profiles) {
        $fwProfile = Get-NetFirewallProfile -Name $profile
        if ($fwProfile.Enabled) {
            Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
                -Message "${profile} firewall profile is enabled" `
                -Details "NSA Guidance: Enable Windows Firewall on all profiles"
        } else {
            Add-Result -Category "NSA - Network Hardening" -Status "Fail" `
                -Message "${profile} firewall profile is disabled" `
                -Details "NSA Guidance: Enable firewall protection" `
                -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True"
        }
    }
} catch {
    Add-Result -Category "NSA - Network Hardening" -Status "Error" `
        -Message "Failed to check firewall status: $_"
}

# Check for LLMNR (should be disabled)
try {
    $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
        Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
            -Message "LLMNR is disabled" `
            -Details "NSA Guidance: Disable LLMNR to prevent name resolution poisoning"
    } else {
        Add-Result -Category "NSA - Network Hardening" -Status "Warning" `
            -Message "LLMNR may be enabled" `
            -Details "NSA Guidance: Disable LLMNR (Link-Local Multicast Name Resolution)" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0"
    }
} catch {
    Add-Result -Category "NSA - Network Hardening" -Status "Info" `
        -Message "Could not check LLMNR status" `
        -Details "NSA Guidance: Verify LLMNR is disabled"
}

# Check for NetBIOS over TCP/IP (should be disabled)
try {
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    $netbiosEnabled = $false
    foreach ($adapter in $adapters) {
        if ($adapter.TcpipNetbiosOptions -eq 1) {
            $netbiosEnabled = $true
            break
        }
    }
    
    if (-not $netbiosEnabled) {
        Add-Result -Category "NSA - Network Hardening" -Status "Pass" `
            -Message "NetBIOS over TCP/IP is disabled on network adapters" `
            -Details "NSA Guidance: Disable NetBIOS to reduce attack surface"
    } else {
        Add-Result -Category "NSA - Network Hardening" -Status "Warning" `
            -Message "NetBIOS over TCP/IP is enabled on one or more adapters" `
            -Details "NSA Guidance: Disable NetBIOS over TCP/IP" `
            -Remediation "Disable via network adapter properties or DHCP options"
    }
} catch {
    Add-Result -Category "NSA - Network Hardening" -Status "Error" `
        -Message "Failed to check NetBIOS status: $_"
}

# ============================================================================
# Summary Statistics
# ============================================================================
$passCount = ($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = ($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = ($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

Write-Host "`n[NSA] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results
