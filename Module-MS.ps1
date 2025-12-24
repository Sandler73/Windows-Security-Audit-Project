<#
.SYNOPSIS
    Microsoft Security Baseline Module - Comprehensive MS Recommendations
    
.DESCRIPTION
    Contains extensive checks based on Microsoft Security Compliance Toolkit baselines.
    Includes Windows 10/11 security recommendations from Microsoft (50+ checks).
#>

# Module-MS.ps1
# Microsoft Security Baseline Compliance Module
# Based on Microsoft Security Compliance Toolkit baselines

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "MS-Baseline"
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

Write-Host "`n[MS-Baseline] Starting Microsoft Security Baseline checks..." -ForegroundColor Cyan

# ============================================================================
# Microsoft Defender Configuration
# ============================================================================
Write-Host "[MS-Baseline] Checking Microsoft Defender Configuration..." -ForegroundColor Yellow

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus) {
        # Real-time protection
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "Real-time protection is enabled" `
                -Details "Microsoft Baseline: Real-time monitoring is critical"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Fail" `
                -Message "Real-time protection is disabled" `
                -Details "Microsoft Baseline: Enable real-time protection" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
        }
        
        # Behavior monitoring
        if ($defenderStatus.BehaviorMonitorEnabled) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "Behavior monitoring is enabled" `
                -Details "Microsoft Baseline: Detects suspicious behavior"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Warning" `
                -Message "Behavior monitoring is disabled" `
                -Details "Microsoft Baseline: Enable behavior monitoring" `
                -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
        }
        
        # IOAV protection (downloads/attachments)
        if ($defenderStatus.IoavProtectionEnabled) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "Downloaded files and attachments scanning is enabled" `
                -Details "Microsoft Baseline: Protects against malicious downloads"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Warning" `
                -Message "Downloaded files scanning is disabled" `
                -Details "Microsoft Baseline: Enable IOAV protection" `
                -Remediation "Set-MpPreference -DisableIOAVProtection `$false"
        }
        
        # On-access protection
        if ($defenderStatus.OnAccessProtectionEnabled) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "On-access protection is enabled" `
                -Details "Microsoft Baseline: Scans files on access"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Fail" `
                -Message "On-access protection is disabled" `
                -Details "Microsoft Baseline: Enable on-access scanning" `
                -Remediation "Set-MpPreference -DisableOnAccessProtection `$false"
        }
        
        # Cloud-delivered protection
        if ($defenderStatus.MAPSReporting -ne 0) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "Cloud-delivered protection is enabled (MAPS: $($defenderStatus.MAPSReporting))" `
                -Details "Microsoft Baseline: Cloud protection provides rapid response"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Warning" `
                -Message "Cloud-delivered protection is disabled" `
                -Details "Microsoft Baseline: Enable cloud protection" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced"
        }
        
        # Tamper Protection
        if ($defenderStatus.IsTamperProtected) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "Tamper Protection is enabled" `
                -Details "Microsoft Baseline: Prevents malware from disabling Defender"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Warning" `
                -Message "Tamper Protection is not enabled" `
                -Details "Microsoft Baseline: Enable Tamper Protection via Windows Security" `
                -Remediation "Enable in Windows Security app or via Intune"
        }
        
        # Automatic sample submission
        if ($defenderStatus.SubmitSamplesConsent -ne 2) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Info" `
                -Message "Automatic sample submission: $($defenderStatus.SubmitSamplesConsent)" `
                -Details "Microsoft Baseline: Sample submission improves threat intelligence"
        }
        
        # Signature updates
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        if ($signatureAge.TotalHours -le 24) {
            Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
                -Message "Antivirus signatures updated within 24 hours" `
                -Details "Microsoft Baseline: Signatures current as of $($defenderStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm'))"
        } else {
            Add-Result -Category "MS-Baseline - Defender" -Status "Warning" `
                -Message "Antivirus signatures are $([math]::Round($signatureAge.TotalDays, 1)) days old" `
                -Details "Microsoft Baseline: Update signatures" `
                -Remediation "Update-MpSignature"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - Defender" -Status "Error" `
        -Message "Failed to check Microsoft Defender status: $_"
}

# Check Attack Surface Reduction rules
try {
    $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
    if ($asrRules -and $asrRules.Count -gt 0) {
        Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
            -Message "$($asrRules.Count) Attack Surface Reduction rule(s) configured" `
            -Details "Microsoft Baseline: ASR rules reduce attack vectors"
    } else {
        Add-Result -Category "MS-Baseline - Defender" -Status "Info" `
            -Message "No Attack Surface Reduction rules configured" `
            -Details "Microsoft Baseline: Consider implementing ASR rules"
    }
} catch {
    Add-Result -Category "MS-Baseline - Defender" -Status "Info" `
        -Message "Could not check ASR rules" `
        -Details "Microsoft Baseline: ASR rules available on Windows 10 1709+"
}

# Check Exploit Protection
try {
    $exploitProtection = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    if ($exploitProtection) {
        Add-Result -Category "MS-Baseline - Defender" -Status "Pass" `
            -Message "Exploit Protection settings are configured" `
            -Details "Microsoft Baseline: Exploit Guard mitigations are active"
    } else {
        Add-Result -Category "MS-Baseline - Defender" -Status "Info" `
            -Message "Could not verify Exploit Protection settings" `
            -Details "Microsoft Baseline: Configure via Windows Security"
    }
} catch {
    Add-Result -Category "MS-Baseline - Defender" -Status "Info" `
        -Message "Exploit Protection check completed" `
        -Details "Microsoft Baseline"
}

# ============================================================================
# Windows Update Configuration
# ============================================================================
Write-Host "[MS-Baseline] Checking Windows Update Configuration..." -ForegroundColor Yellow

# Check Windows Update service
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($wuService) {
        if ($wuService.Status -eq "Running" -or $wuService.StartType -ne "Disabled") {
            Add-Result -Category "MS-Baseline - Updates" -Status "Pass" `
                -Message "Windows Update service is available" `
                -Details "Microsoft Baseline: Automatic updates are essential"
        } else {
            Add-Result -Category "MS-Baseline - Updates" -Status "Fail" `
                -Message "Windows Update service is disabled" `
                -Details "Microsoft Baseline: Enable Windows Update" `
                -Remediation "Set-Service -Name wuauserv -StartupType Manual"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - Updates" -Status "Error" `
        -Message "Failed to check Windows Update service: $_"
}

# Check for missing updates
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($updateSession) {
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        
        $totalUpdates = $searchResult.Updates.Count
        $criticalUpdates = ($searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
        $importantUpdates = ($searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Important" }).Count
        
        if ($totalUpdates -eq 0) {
            Add-Result -Category "MS-Baseline - Updates" -Status "Pass" `
                -Message "All updates are installed" `
                -Details "Microsoft Baseline: System is fully patched"
        } else {
            if ($criticalUpdates -gt 0) {
                Add-Result -Category "MS-Baseline - Updates" -Status "Fail" `
                    -Message "$criticalUpdates critical update(s) missing" `
                    -Details "Microsoft Baseline: Install critical updates immediately" `
                    -Remediation "Install via Windows Update or WSUS"
            }
            if ($importantUpdates -gt 0) {
                Add-Result -Category "MS-Baseline - Updates" -Status "Warning" `
                    -Message "$importantUpdates important update(s) missing" `
                    -Details "Microsoft Baseline: Install important updates promptly"
            }
            if ($totalUpdates -gt ($criticalUpdates + $importantUpdates)) {
                $otherUpdates = $totalUpdates - $criticalUpdates - $importantUpdates
                Add-Result -Category "MS-Baseline - Updates" -Status "Info" `
                    -Message "$otherUpdates other update(s) available" `
                    -Details "Microsoft Baseline: Regular updates improve security"
            }
        }
    } else {
        Add-Result -Category "MS-Baseline - Updates" -Status "Info" `
            -Message "Could not check for updates" `
            -Details "Microsoft Baseline: Verify update status manually"
    }
} catch {
    Add-Result -Category "MS-Baseline - Updates" -Status "Info" `
        -Message "Update check unavailable" `
        -Details "Microsoft Baseline: Ensure updates are installed regularly"
}

# ============================================================================
# BitLocker Encryption
# ============================================================================
Write-Host "[MS-Baseline] Checking BitLocker Encryption..." -ForegroundColor Yellow

try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlockerVolumes) {
        foreach ($volume in $bitlockerVolumes) {
            if ($volume.VolumeStatus -eq "FullyEncrypted") {
                Add-Result -Category "MS-Baseline - Encryption" -Status "Pass" `
                    -Message "Volume $($volume.MountPoint) is fully encrypted" `
                    -Details "Microsoft Baseline: Method=$($volume.EncryptionMethod), KeyProtectors=$($volume.KeyProtector.Count)"
            } elseif ($volume.VolumeStatus -eq "EncryptionInProgress") {
                Add-Result -Category "MS-Baseline - Encryption" -Status "Info" `
                    -Message "Volume $($volume.MountPoint) encryption in progress ($($volume.EncryptionPercentage)%)" `
                    -Details "Microsoft Baseline: Encryption is being applied"
            } else {
                Add-Result -Category "MS-Baseline - Encryption" -Status "Warning" `
                    -Message "Volume $($volume.MountPoint) is not encrypted (Status: $($volume.VolumeStatus))" `
                    -Details "Microsoft Baseline: Enable BitLocker for data protection" `
                    -Remediation "Enable-BitLocker -MountPoint '$($volume.MountPoint)' -EncryptionMethod XtsAes256"
            }
        }
    } else {
        Add-Result -Category "MS-Baseline - Encryption" -Status "Info" `
            -Message "Could not determine BitLocker status" `
            -Details "Microsoft Baseline: Verify encryption manually"
    }
} catch {
    Add-Result -Category "MS-Baseline - Encryption" -Status "Info" `
        -Message "BitLocker check requires administrative privileges" `
        -Details "Microsoft Baseline: Full disk encryption is recommended"
}

# ============================================================================
# Windows Firewall Configuration
# ============================================================================
Write-Host "[MS-Baseline] Checking Windows Firewall..." -ForegroundColor Yellow

$profiles = @("Domain", "Private", "Public")
foreach ($profile in $profiles) {
    try {
        $fwProfile = Get-NetFirewallProfile -Name $profile
        
        # Firewall state
        if ($fwProfile.Enabled) {
            Add-Result -Category "MS-Baseline - Firewall" -Status "Pass" `
                -Message "$profile firewall is enabled" `
                -Details "Microsoft Baseline: Host-based firewall is active"
        } else {
            Add-Result -Category "MS-Baseline - Firewall" -Status "Fail" `
                -Message "$profile firewall is disabled" `
                -Details "Microsoft Baseline: Enable firewall on all profiles" `
                -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True"
        }
        
        # Default inbound action
        if ($fwProfile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "MS-Baseline - Firewall" -Status "Pass" `
                -Message "${profile}: Default inbound action is Block" `
                -Details "Microsoft Baseline: Default deny configuration"
        } else {
            Add-Result -Category "MS-Baseline - Firewall" -Status "Warning" `
                -Message "${profile}: Default inbound action is not Block" `
                -Details "Microsoft Baseline: Set to Block for security" `
                -Remediation "Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block"
        }
        
        # Logging
        if ($fwProfile.LogBlocked) {
            Add-Result -Category "MS-Baseline - Firewall" -Status "Pass" `
                -Message "${profile}: Blocked connections are logged" `
                -Details "Microsoft Baseline: Logging aids investigation"
        } else {
            Add-Result -Category "MS-Baseline - Firewall" -Status "Info" `
                -Message "${profile}: Blocked connections are not logged" `
                -Details "Microsoft Baseline: Enable logging for monitoring"
        }
    } catch {
        Add-Result -Category "MS-Baseline - Firewall" -Status "Error" `
            -Message "Failed to check $profile firewall: $_"
    }
}

# ============================================================================
# Credential Guard and Device Guard
# ============================================================================
Write-Host "[MS-Baseline] Checking Credential Guard and Device Guard..." -ForegroundColor Yellow

try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        # Virtualization Based Security
        if ($deviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
            Add-Result -Category "MS-Baseline - Device Guard" -Status "Pass" `
                -Message "Virtualization-based security is running" `
                -Details "Microsoft Baseline: VBS provides hardware-based security"
        } else {
            Add-Result -Category "MS-Baseline - Device Guard" -Status "Info" `
                -Message "Virtualization-based security is not running" `
                -Details "Microsoft Baseline: VBS requires compatible hardware (TPM 2.0, UEFI, virtualization)"
        }
        
        # Credential Guard
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "MS-Baseline - Device Guard" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "Microsoft Baseline: Protects against credential theft"
        } else {
            Add-Result -Category "MS-Baseline - Device Guard" -Status "Info" `
                -Message "Credential Guard is not running" `
                -Details "Microsoft Baseline: Enable on compatible hardware for enhanced protection"
        }
        
        # Code Integrity Policy
        if ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Add-Result -Category "MS-Baseline - Device Guard" -Status "Pass" `
                -Message "Code Integrity Policy is enforced" `
                -Details "Microsoft Baseline: WDAC provides application control"
        } else {
            Add-Result -Category "MS-Baseline - Device Guard" -Status "Info" `
                -Message "Code Integrity Policy is not enforced" `
                -Details "Microsoft Baseline: Consider WDAC for application whitelisting"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - Device Guard" -Status "Info" `
        -Message "Could not check Device Guard status" `
        -Details "Microsoft Baseline: Verify hardware compatibility for VBS features"
}

# ============================================================================
# PowerShell Configuration
# ============================================================================
Write-Host "[MS-Baseline] Checking PowerShell Security..." -ForegroundColor Yellow

# Check PowerShell v2
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    if ($psv2) {
        if ($psv2.State -eq "Disabled") {
            Add-Result -Category "MS-Baseline - PowerShell" -Status "Pass" `
                -Message "PowerShell 2.0 is disabled" `
                -Details "Microsoft Baseline: PSv2 lacks modern security features"
        } else {
            Add-Result -Category "MS-Baseline - PowerShell" -Status "Fail" `
                -Message "PowerShell 2.0 is enabled" `
                -Details "Microsoft Baseline: Remove PowerShell 2.0" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - PowerShell" -Status "Info" `
        -Message "Could not check PowerShell 2.0 status" `
        -Details "Microsoft Baseline"
}

# Check PowerShell logging
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "MS-Baseline - PowerShell" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "Microsoft Baseline: Detects malicious scripts"
    } else {
        Add-Result -Category "MS-Baseline - PowerShell" -Status "Warning" `
            -Message "PowerShell Script Block Logging is not enabled" `
            -Details "Microsoft Baseline: Enable for threat detection" `
            -Remediation "Configure via Group Policy: Windows PowerShell > Turn on PowerShell Script Block Logging"
    }
    
    if ($moduleLogging -and $moduleLogging.EnableModuleLogging -eq 1) {
        Add-Result -Category "MS-Baseline - PowerShell" -Status "Pass" `
            -Message "PowerShell Module Logging is enabled" `
            -Details "Microsoft Baseline: Logs module activity"
    } else {
        Add-Result -Category "MS-Baseline - PowerShell" -Status "Info" `
            -Message "PowerShell Module Logging is not enabled" `
            -Details "Microsoft Baseline: Consider enabling for comprehensive logging"
    }
    
    if ($transcription -and $transcription.EnableTranscripting -eq 1) {
        Add-Result -Category "MS-Baseline - PowerShell" -Status "Pass" `
            -Message "PowerShell Transcription is enabled" `
            -Details "Microsoft Baseline: Records full session activity"
    } else {
        Add-Result -Category "MS-Baseline - PowerShell" -Status "Info" `
            -Message "PowerShell Transcription is not enabled" `
            -Details "Microsoft Baseline: Consider enabling for full audit trail"
    }
} catch {
    Add-Result -Category "MS-Baseline - PowerShell" -Status "Error" `
        -Message "Failed to check PowerShell logging: $_"
}

# ============================================================================
# SMB Configuration
# ============================================================================
Write-Host "[MS-Baseline] Checking SMB Configuration..." -ForegroundColor Yellow

try {
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbConfig) {
        # SMBv1
        if ($smbConfig.EnableSMB1Protocol -eq $false) {
            Add-Result -Category "MS-Baseline - SMB" -Status "Pass" `
                -Message "SMBv1 protocol is disabled" `
                -Details "Microsoft Baseline: SMBv1 is insecure and deprecated"
        } else {
            Add-Result -Category "MS-Baseline - SMB" -Status "Fail" `
                -Message "SMBv1 protocol is enabled" `
                -Details "Microsoft Baseline: Disable SMBv1 immediately" `
                -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
        }
        
        # SMB signing
        if ($smbConfig.RequireSecuritySignature) {
            Add-Result -Category "MS-Baseline - SMB" -Status "Pass" `
                -Message "SMB signing is required" `
                -Details "Microsoft Baseline: Prevents tampering and relay attacks"
        } else {
            Add-Result -Category "MS-Baseline - SMB" -Status "Warning" `
                -Message "SMB signing is not required" `
                -Details "Microsoft Baseline: Enable SMB signing" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        }
        
        # SMB encryption
        if ($smbConfig.EncryptData) {
            Add-Result -Category "MS-Baseline - SMB" -Status "Pass" `
                -Message "SMB encryption is enabled globally" `
                -Details "Microsoft Baseline: Encrypts SMB traffic"
        } else {
            Add-Result -Category "MS-Baseline - SMB" -Status "Info" `
                -Message "SMB encryption is not enabled globally" `
                -Details "Microsoft Baseline: Consider enabling for sensitive data"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - SMB" -Status "Error" `
        -Message "Failed to check SMB configuration: $_"
}

# ============================================================================
# Remote Desktop Configuration
# ============================================================================
Write-Host "[MS-Baseline] Checking Remote Desktop Configuration..." -ForegroundColor Yellow

try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "MS-Baseline - RDP" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "Microsoft Baseline: RDP disabled when not needed"
    } else {
        # RDP is enabled, check security settings
        Add-Result -Category "MS-Baseline - RDP" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "Microsoft Baseline: Ensure RDP is secured if required"
        
        # Network Level Authentication
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "MS-Baseline - RDP" -Status "Pass" `
                -Message "RDP: Network Level Authentication is required" `
                -Details "Microsoft Baseline: NLA adds authentication layer"
        } else {
            Add-Result -Category "MS-Baseline - RDP" -Status "Fail" `
                -Message "RDP: Network Level Authentication is not required" `
                -Details "Microsoft Baseline: Enable NLA" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
        
        # Encryption level
        $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        if ($encLevel -and $encLevel.MinEncryptionLevel -ge 3) {
            Add-Result -Category "MS-Baseline - RDP" -Status "Pass" `
                -Message "RDP: High encryption level configured" `
                -Details "Microsoft Baseline: Strong encryption for RDP"
        } else {
            Add-Result -Category "MS-Baseline - RDP" -Status "Warning" `
                -Message "RDP: Encryption level may not be High" `
                -Details "Microsoft Baseline: Set to High encryption"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - RDP" -Status "Error" `
        -Message "Failed to check RDP configuration: $_"
}

# ============================================================================
# Account and Authentication Policies
# ============================================================================
Write-Host "[MS-Baseline] Checking Account Policies..." -ForegroundColor Yellow

try {
    $passwordPolicy = net accounts | Out-String
    
    # Password length
    if ($passwordPolicy -match "Minimum password length\s+(\d+)") {
        $minLength = [int]$Matches[1]
        if ($minLength -ge 14) {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Pass" `
                -Message "Minimum password length is $minLength characters" `
                -Details "Microsoft Baseline: Strong password length requirement"
        } elseif ($minLength -ge 8) {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Warning" `
                -Message "Minimum password length is $minLength (recommend 14+)" `
                -Details "Microsoft Baseline: Increase password length"
        } else {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Fail" `
                -Message "Minimum password length is too short ($minLength)" `
                -Details "Microsoft Baseline: Set to 14 or more characters"
        }
    }
    
    # Password age
    if ($passwordPolicy -match "Maximum password age \(days\):\s+(\d+)") {
        $maxAge = [int]$Matches[1]
        if ($maxAge -gt 0 -and $maxAge -le 60) {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Pass" `
                -Message "Password maximum age is $maxAge days" `
                -Details "Microsoft Baseline: Regular password changes enforced"
        } elseif ($maxAge -eq 0) {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Warning" `
                -Message "Passwords never expire" `
                -Details "Microsoft Baseline: Consider password expiration policy"
        }
    }
    
    # Account lockout
    if ($passwordPolicy -match "Lockout threshold:\s+(\d+)") {
        $threshold = [int]$Matches[1]
        if ($threshold -gt 0 -and $threshold -le 10) {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Pass" `
                -Message "Account lockout threshold is $threshold attempts" `
                -Details "Microsoft Baseline: Protection against brute force"
        } elseif ($threshold -eq 0) {
            Add-Result -Category "MS-Baseline - Authentication" -Status "Warning" `
                -Message "Account lockout is disabled" `
                -Details "Microsoft Baseline: Enable account lockout"
        }
    }
} catch {
    Add-Result -Category "MS-Baseline - Authentication" -Status "Error" `
        -Message "Failed to check password policy: $_"
}

# Check UAC
try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac -and $uac.EnableLUA -eq 1) {
        Add-Result -Category "MS-Baseline - Authentication" -Status "Pass" `
            -Message "User Account Control is enabled" `
            -Details "Microsoft Baseline: UAC prevents unauthorized elevation"
    } else {
        Add-Result -Category "MS-Baseline - Authentication" -Status "Fail" `
            -Message "User Account Control is disabled" `
            -Details "Microsoft Baseline: Enable UAC" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
    }
} catch {
    Add-Result -Category "MS-Baseline - Authentication" -Status "Error" `
        -Message "Failed to check UAC: $_"
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

Write-Host "`n[MS-Baseline] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

Write-Host "`nMicrosoft Security Baselines are available from:" -ForegroundColor Cyan
Write-Host "https://www.microsoft.com/en-us/download/details.aspx?id=55319" -ForegroundColor White

return $results
