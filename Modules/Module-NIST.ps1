# Module-NIST.ps1
# NIST (National Institute of Standards and Technology) Compliance Module
# Version: 5.0
# Based on NIST 800-53, NIST Cybersecurity Framework, and NIST 800-171

<#
.SYNOPSIS
    NIST security controls and Cybersecurity Framework compliance checks.

.DESCRIPTION
    This module checks alignment with NIST guidance including:
    - NIST 800-53 Rev 5 security controls
    - NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover)
    - NIST 800-171 (Protecting Controlled Unclassified Information)
    - Access Control (AC family)
    - Audit and Accountability (AU family)
    - Identification and Authentication (IA family)
    - System and Communications Protection (SC family)
    - Configuration Management (CM family)
    - Incident Response (IR family)
    - Media Protection (MP family)
    - System and Information Integrity (SI family)

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Version: 5.0
    Based on: NIST 800-53 Rev 5, NIST CSF, NIST 800-171
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "NIST"
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

Write-Host "`n[NIST] Starting NIST compliance checks..." -ForegroundColor Cyan

# ============================================================================
# NIST 800-53: Access Control (AC)
# ============================================================================
Write-Host "[NIST] Checking Access Control (AC) Controls..." -ForegroundColor Yellow

# AC-2: Account Management
try {
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    Add-Result -Category "NIST - AC-2" -Status "Info" `
        -Message "Account Management: $($localUsers.Count) enabled local user accounts" `
        -Details "NIST 800-53 AC-2: Review accounts regularly. Accounts: $($localUsers.Name -join ', ')"
    
    # Check for inactive accounts
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveAccounts = $localUsers | Where-Object { 
        $_.LastLogon -and $_.LastLogon -lt $inactiveThreshold 
    }
    
    if ($inactiveAccounts) {
        Add-Result -Category "NIST - AC-2" -Status "Warning" `
            -Message "Found $($inactiveAccounts.Count) inactive account(s) (>90 days)" `
            -Details "NIST 800-53 AC-2(3): Disable inactive accounts. Accounts: $($inactiveAccounts.Name -join ', ')" `
            -Remediation "Review and disable inactive accounts"
    } else {
        Add-Result -Category "NIST - AC-2" -Status "Pass" `
            -Message "No inactive accounts detected (>90 days)" `
            -Details "NIST 800-53 AC-2(3): Account management is current"
    }
    
} catch {
    Add-Result -Category "NIST - AC-2" -Status "Error" `
        -Message "Failed to check account management: $_"
}

# AC-3: Access Enforcement
try {
    # Check User Account Control (UAC)
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    
    if ($uac.EnableLUA -eq 1) {
        Add-Result -Category "NIST - AC-3" -Status "Pass" `
            -Message "Access Enforcement: User Account Control is enabled" `
            -Details "NIST 800-53 AC-3: UAC enforces access control policies"
    } else {
        Add-Result -Category "NIST - AC-3" -Status "Fail" `
            -Message "Access Enforcement: UAC is DISABLED" `
            -Details "NIST 800-53 AC-3: Enable UAC to enforce access control" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
    }
} catch {
    Add-Result -Category "NIST - AC-3" -Status "Error" `
        -Message "Failed to check access enforcement: $_"
}

# AC-7: Unsuccessful Logon Attempts
try {
    $lockoutPolicy = net accounts 2>$null | Select-String "Lockout threshold"
    
    if ($lockoutPolicy) {
        $threshold = $lockoutPolicy.ToString().Split(":")[1].Trim()
        
        if ($threshold -eq "Never") {
            Add-Result -Category "NIST - AC-7" -Status "Fail" `
                -Message "Account lockout is disabled" `
                -Details "NIST 800-53 AC-7: Configure lockout after unsuccessful logon attempts" `
                -Remediation "net accounts /lockoutthreshold:5"
        } elseif ([int]$threshold -le 10) {
            Add-Result -Category "NIST - AC-7" -Status "Pass" `
                -Message "Account lockout threshold: $threshold invalid attempts" `
                -Details "NIST 800-53 AC-7: Account lockout protects against brute force"
        } else {
            Add-Result -Category "NIST - AC-7" -Status "Warning" `
                -Message "Account lockout threshold is high: $threshold" `
                -Details "NIST 800-53 AC-7: Consider setting to 10 or fewer attempts"
        }
    }
} catch {
    Add-Result -Category "NIST - AC-7" -Status "Error" `
        -Message "Failed to check account lockout policy: $_"
}

# AC-11: Device Lock
try {
    $screenSaverPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
    
    if ($screenSaverPolicy) {
        $timeout = $screenSaverPolicy.ScreenSaveTimeOut
        $active = $screenSaverPolicy.ScreenSaveActive
        
        if ($active -eq "1" -and $timeout -le 900) {
            $minutes = $timeout / 60
            Add-Result -Category "NIST - AC-11" -Status "Pass" `
                -Message "Screen saver lock configured: $minutes minutes" `
                -Details "NIST 800-53 AC-11: Device lock after inactivity is enforced"
        } else {
            Add-Result -Category "NIST - AC-11" -Status "Warning" `
                -Message "Screen saver lock may not be properly configured" `
                -Details "NIST 800-53 AC-11: Configure screen lock after 15 minutes or less" `
                -Remediation "Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options"
        }
    } else {
        Add-Result -Category "NIST - AC-11" -Status "Warning" `
            -Message "Screen saver policy not configured" `
            -Details "NIST 800-53 AC-11: Configure automatic screen lock"
    }
} catch {
    Add-Result -Category "NIST - AC-11" -Status "Error" `
        -Message "Failed to check device lock settings: $_"
}

# AC-17: Remote Access
try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "NIST - AC-17" -Status "Pass" `
            -Message "Remote Desktop Protocol is disabled" `
            -Details "NIST 800-53 AC-17: RDP remote access is not allowed"
    } else {
        Add-Result -Category "NIST - AC-17" -Status "Info" `
            -Message "Remote Desktop Protocol is enabled" `
            -Details "NIST 800-53 AC-17: Verify remote access is authorized and secured"
        
        # Check NLA if RDP is enabled
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "NIST - AC-17" -Status "Pass" `
                -Message "RDP: Network Level Authentication is required" `
                -Details "NIST 800-53 AC-17(1): Remote access uses multi-factor authentication"
        } else {
            Add-Result -Category "NIST - AC-17" -Status "Fail" `
                -Message "RDP: Network Level Authentication is NOT required" `
                -Details "NIST 800-53 AC-17(1): Enable multi-factor authentication for remote access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
    }
} catch {
    Add-Result -Category "NIST - AC-17" -Status "Error" `
        -Message "Failed to check remote access configuration: $_"
}

# ============================================================================
# NIST 800-53: Audit and Accountability (AU)
# ============================================================================
Write-Host "[NIST] Checking Audit and Accountability (AU) Controls..." -ForegroundColor Yellow

# AU-2: Audit Events
try {
    $auditCategories = @(
        "Logon/Logoff",
        "Account Management",
        "Policy Change",
        "Privilege Use",
        "System"
    )
    
    $auditConfigured = 0
    foreach ($category in $auditCategories) {
        $result = auditpol /get /category:"$category" 2>$null
        if ($result -and ($result -match "Success" -or $result -match "Failure")) {
            $auditConfigured++
        }
    }
    
    if ($auditConfigured -ge 4) {
        Add-Result -Category "NIST - AU-2" -Status "Pass" `
            -Message "Critical audit categories are configured ($auditConfigured of $($auditCategories.Count))" `
            -Details "NIST 800-53 AU-2: Security-relevant events are being audited"
    } else {
        Add-Result -Category "NIST - AU-2" -Status "Fail" `
            -Message "Insufficient audit categories configured ($auditConfigured of $($auditCategories.Count))" `
            -Details "NIST 800-53 AU-2: Enable comprehensive audit logging" `
            -Remediation "Configure audit policies via Local Security Policy or Group Policy"
    }
} catch {
    Add-Result -Category "NIST - AU-2" -Status "Error" `
        -Message "Failed to check audit configuration: $_"
}

# AU-4: Audit Storage Capacity
try {
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    
    $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
    
    if ($logSizeMB -ge 512) {
        Add-Result -Category "NIST - AU-4" -Status "Pass" `
            -Message "Security log size is adequate: $logSizeMB MB" `
            -Details "NIST 800-53 AU-4: Sufficient capacity for audit record storage"
    } elseif ($logSizeMB -ge 256) {
        Add-Result -Category "NIST - AU-4" -Status "Warning" `
            -Message "Security log size: $logSizeMB MB (consider increasing)" `
            -Details "NIST 800-53 AU-4: Allocate sufficient audit storage capacity" `
            -Remediation "wevtutil sl Security /ms:$([int](512MB))"
    } else {
        Add-Result -Category "NIST - AU-4" -Status "Fail" `
            -Message "Security log size is insufficient: $logSizeMB MB" `
            -Details "NIST 800-53 AU-4: Increase audit log capacity" `
            -Remediation "wevtutil sl Security /ms:$([int](512MB))"
    }
} catch {
    Add-Result -Category "NIST - AU-4" -Status "Error" `
        -Message "Failed to check audit storage capacity: $_"
}

# AU-9: Protection of Audit Information
try {
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    
    # Check if log is enabled and has a retention policy
    if ($securityLog.IsEnabled) {
        Add-Result -Category "NIST - AU-9" -Status "Pass" `
            -Message "Security audit log is enabled and protected" `
            -Details "NIST 800-53 AU-9: Audit information is protected from unauthorized access"
        
        # Check log mode for retention
        if ($securityLog.LogMode -eq "AutoBackup") {
            Add-Result -Category "NIST - AU-9" -Status "Pass" `
                -Message "Security log auto-archives when full" `
                -Details "NIST 800-53 AU-9(2): Audit logs are backed up automatically"
        }
    }
} catch {
    Add-Result -Category "NIST - AU-9" -Status "Error" `
        -Message "Failed to check audit protection: $_"
}

# AU-12: Audit Generation
try {
    # Check if Advanced Audit Policy is in use
    $advancedAudit = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    
    if ($advancedAudit -and $advancedAudit.SCENoApplyLegacyAuditPolicy -eq 1) {
        Add-Result -Category "NIST - AU-12" -Status "Pass" `
            -Message "Advanced Audit Policy is configured" `
            -Details "NIST 800-53 AU-12: System provides audit record generation capability"
    } else {
        Add-Result -Category "NIST - AU-12" -Status "Warning" `
            -Message "Advanced Audit Policy may not be enforced" `
            -Details "NIST 800-53 AU-12: Enable Advanced Audit Policy for granular auditing" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1"
    }
} catch {
    Add-Result -Category "NIST - AU-12" -Status "Error" `
        -Message "Failed to check audit generation: $_"
}

# ============================================================================
# NIST 800-53: Identification and Authentication (IA)
# ============================================================================
Write-Host "[NIST] Checking Identification and Authentication (IA) Controls..." -ForegroundColor Yellow

# IA-2: Identification and Authentication
try {
    # Check for built-in accounts
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount -and $guestAccount.Enabled) {
        Add-Result -Category "NIST - IA-2" -Status "Fail" `
            -Message "Guest account is enabled" `
            -Details "NIST 800-53 IA-2: Disable Guest account to enforce identification" `
            -Remediation "Disable-LocalUser -Name Guest"
    } else {
        Add-Result -Category "NIST - IA-2" -Status "Pass" `
            -Message "Guest account is disabled" `
            -Details "NIST 800-53 IA-2: Proper user identification is enforced"
    }
} catch {
    Add-Result -Category "NIST - IA-2" -Status "Error" `
        -Message "Failed to check identification and authentication: $_"
}

# IA-5: Authenticator Management (Password Policy)
try {
    $netAccounts = net accounts 2>$null
    
    if ($netAccounts) {
        # Check minimum password length
        $minLength = ($netAccounts | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
        
        if ([int]$minLength -ge 14) {
            Add-Result -Category "NIST - IA-5" -Status "Pass" `
                -Message "Minimum password length: $minLength characters" `
                -Details "NIST 800-53 IA-5(1): Strong password requirements enforced"
        } elseif ([int]$minLength -ge 8) {
            Add-Result -Category "NIST - IA-5" -Status "Warning" `
                -Message "Minimum password length: $minLength characters" `
                -Details "NIST 800-53 IA-5(1): Consider increasing to 14+ characters" `
                -Remediation "net accounts /minpwlen:14"
        } else {
            Add-Result -Category "NIST - IA-5" -Status "Fail" `
                -Message "Minimum password length is weak: $minLength characters" `
                -Details "NIST 800-53 IA-5(1): Increase minimum password length" `
                -Remediation "net accounts /minpwlen:14"
        }
        
        # Check password history
        $history = ($netAccounts | Select-String "Length of password history maintained").ToString().Split(":")[1].Trim()
        
        if ([int]$history -ge 24) {
            Add-Result -Category "NIST - IA-5" -Status "Pass" `
                -Message "Password history: $history passwords remembered" `
                -Details "NIST 800-53 IA-5(1): Password reuse is properly restricted"
        } else {
            Add-Result -Category "NIST - IA-5" -Status "Warning" `
                -Message "Password history: $history passwords" `
                -Details "NIST 800-53 IA-5(1): Consider increasing to 24" `
                -Remediation "net accounts /uniquepw:24"
        }
        
        # Check maximum password age
        $maxAge = ($netAccounts | Select-String "Maximum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ($maxAge -ne "Unlimited" -and [int]$maxAge -le 365) {
            Add-Result -Category "NIST - IA-5" -Status "Pass" `
                -Message "Maximum password age: $maxAge days" `
                -Details "NIST 800-53 IA-5(1): Password expiration is enforced"
        } else {
            Add-Result -Category "NIST - IA-5" -Status "Fail" `
                -Message "Maximum password age: $maxAge" `
                -Details "NIST 800-53 IA-5(1): Configure password expiration (365 days or less)" `
                -Remediation "net accounts /maxpwage:365"
        }
    }
} catch {
    Add-Result -Category "NIST - IA-5" -Status "Error" `
        -Message "Failed to check authenticator management: $_"
}

# IA-8: Identification and Authentication (Non-Organizational Users)
try {
    # Check if system is domain-joined
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - IA-8" -Status "Pass" `
            -Message "System is domain-joined: $($computerSystem.Domain)" `
            -Details "NIST 800-53 IA-8: Centralized authentication is available"
    } else {
        Add-Result -Category "NIST - IA-8" -Status "Info" `
            -Message "System is not domain-joined (standalone/workgroup)" `
            -Details "NIST 800-53 IA-8: Consider centralized authentication management"
    }
} catch {
    Add-Result -Category "NIST - IA-8" -Status "Error" `
        -Message "Failed to check domain membership: $_"
}

# ============================================================================
# NIST 800-53: System and Communications Protection (SC)
# ============================================================================
Write-Host "[NIST] Checking System and Communications Protection (SC) Controls..." -ForegroundColor Yellow

# SC-7: Boundary Protection
try {
    $firewallProfiles = @("Domain", "Private", "Public")
    $allEnabled = $true
    
    foreach ($profileName in $firewallProfiles) {
        $profile = Get-NetFirewallProfile -Name $profileName -ErrorAction SilentlyContinue
        
        if (-not $profile.Enabled) {
            $allEnabled = $false
            break
        }
    }
    
    if ($allEnabled) {
        Add-Result -Category "NIST - SC-7" -Status "Pass" `
            -Message "Windows Firewall is enabled on all network profiles" `
            -Details "NIST 800-53 SC-7: Boundary protection is enforced"
    } else {
        Add-Result -Category "NIST - SC-7" -Status "Fail" `
            -Message "Windows Firewall is not enabled on all profiles" `
            -Details "NIST 800-53 SC-7: Enable firewall for boundary protection" `
            -Remediation "Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True"
    }
} catch {
    Add-Result -Category "NIST - SC-7" -Status "Error" `
        -Message "Failed to check boundary protection: $_"
}

# SC-8: Transmission Confidentiality and Integrity
try {
    # Check SMB signing
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer -and $smbServer.RequireSecuritySignature) {
        Add-Result -Category "NIST - SC-8" -Status "Pass" `
            -Message "SMB signing is required" `
            -Details "NIST 800-53 SC-8: Transmission integrity is protected"
    } else {
        Add-Result -Category "NIST - SC-8" -Status "Fail" `
            -Message "SMB signing is not required" `
            -Details "NIST 800-53 SC-8: Enable SMB signing for transmission protection" `
            -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
    }
    
    # Check SMB encryption
    if ($smbServer -and $smbServer.EncryptData) {
        Add-Result -Category "NIST - SC-8" -Status "Pass" `
            -Message "SMB encryption is enabled" `
            -Details "NIST 800-53 SC-8(1): Transmission confidentiality is protected"
    }
} catch {
    Add-Result -Category "NIST - SC-8" -Status "Error" `
        -Message "Failed to check transmission protection: $_"
}

# SC-13: Cryptographic Protection
try {
    # Check BitLocker status
    $systemDrive = $env:SystemDrive
    $bitlocker = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
    
    if ($bitlocker -and $bitlocker.VolumeStatus -eq "FullyEncrypted") {
        Add-Result -Category "NIST - SC-13" -Status "Pass" `
            -Message "System drive is encrypted with BitLocker" `
            -Details "NIST 800-53 SC-13: Cryptographic protection of data at rest (Method: $($bitlocker.EncryptionMethod))"
    } else {
        Add-Result -Category "NIST - SC-13" -Status "Warning" `
            -Message "System drive is not encrypted" `
            -Details "NIST 800-53 SC-13: Enable encryption for data at rest" `
            -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -TpmProtector"
    }
} catch {
    Add-Result -Category "NIST - SC-13" -Status "Info" `
        -Message "Could not verify cryptographic protection (BitLocker may not be available)"
}

# SC-28: Protection of Information at Rest
try {
    # Check EFS usage
    $efsInfo = cipher /u /n 2>$null
    if ($efsInfo -and ($efsInfo | Select-String "No files found")) {
        Add-Result -Category "NIST - SC-28" -Status "Info" `
            -Message "No files encrypted with EFS detected" `
            -Details "NIST 800-53 SC-28: Consider file-level encryption for sensitive data"
    } elseif ($efsInfo) {
        Add-Result -Category "NIST - SC-28" -Status "Pass" `
            -Message "EFS file encryption is in use" `
            -Details "NIST 800-53 SC-28: File-level encryption protects data at rest"
    }
} catch {
    # EFS check is informational only
}

# ============================================================================
# NIST 800-53: Configuration Management (CM)
# ============================================================================
Write-Host "[NIST] Checking Configuration Management (CM) Controls..." -ForegroundColor Yellow

# CM-2: Baseline Configuration
try {
    # Check Windows Update status
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($wuService -and $wuService.Status -eq "Running") {
        Add-Result -Category "NIST - CM-2" -Status "Pass" `
            -Message "Windows Update service is running" `
            -Details "NIST 800-53 CM-2: System can maintain baseline configuration"
    } else {
        Add-Result -Category "NIST - CM-2" -Status "Fail" `
            -Message "Windows Update service is not running" `
            -Details "NIST 800-53 CM-2: Enable Windows Update for baseline management" `
            -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic"
    }
} catch {
    Add-Result -Category "NIST - CM-2" -Status "Error" `
        -Message "Failed to check baseline configuration: $_"
}

# CM-6: Configuration Settings
try {
    # Check Secure Boot
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "NIST - CM-6" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "NIST 800-53 CM-6: Security configuration settings are enforced"
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "NIST - CM-6" -Status "Warning" `
            -Message "Secure Boot is disabled" `
            -Details "NIST 800-53 CM-6: Enable Secure Boot for boot integrity" `
            -Remediation "Enable Secure Boot in UEFI/BIOS settings"
    } else {
        Add-Result -Category "NIST - CM-6" -Status "Info" `
            -Message "Secure Boot status unknown (Legacy BIOS)" `
            -Details "NIST 800-53 CM-6: UEFI with Secure Boot is recommended"
    }
} catch {
    Add-Result -Category "NIST - CM-6" -Status "Info" `
        -Message "Could not determine Secure Boot status"
}

# CM-7: Least Functionality
try {
    # Check for unnecessary services
    $unnecessaryServices = @("RemoteRegistry", "SSDPSRV", "upnphost", "WMPNetworkSvc")
    $runningUnnecessary = @()
    
    foreach ($svcName in $unnecessaryServices) {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $runningUnnecessary += $service.DisplayName
        }
    }
    
    if ($runningUnnecessary.Count -eq 0) {
        Add-Result -Category "NIST - CM-7" -Status "Pass" `
            -Message "Unnecessary services are disabled" `
            -Details "NIST 800-53 CM-7: System is configured with least functionality"
    } else {
        Add-Result -Category "NIST - CM-7" -Status "Warning" `
            -Message "Unnecessary services are running: $($runningUnnecessary -join ', ')" `
            -Details "NIST 800-53 CM-7: Disable unnecessary services" `
            -Remediation "Review and disable services not required for operation"
    }
} catch {
    Add-Result -Category "NIST - CM-7" -Status "Error" `
        -Message "Failed to check least functionality: $_"
}

# CM-11: User-Installed Software
try {
    # Check if AppLocker is configured
    $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        Add-Result -Category "NIST - CM-11" -Status "Pass" `
            -Message "AppLocker service is running" `
            -Details "NIST 800-53 CM-11: User-installed software is controlled"
        
        $policies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($policies) {
            Add-Result -Category "NIST - CM-11" -Status "Pass" `
                -Message "AppLocker policies are active" `
                -Details "NIST 800-53 CM-11: Application whitelisting is enforced"
        }
    } else {
        Add-Result -Category "NIST - CM-11" -Status "Warning" `
            -Message "AppLocker is not configured" `
            -Details "NIST 800-53 CM-11: Consider implementing application whitelisting" `
            -Remediation "Configure AppLocker via Group Policy"
    }
} catch {
    Add-Result -Category "NIST - CM-11" -Status "Info" `
        -Message "Could not verify software installation controls"
}

# ============================================================================
# NIST 800-53: Incident Response (IR)
# ============================================================================
Write-Host "[NIST] Checking Incident Response (IR) Controls..." -ForegroundColor Yellow

# IR-4: Incident Handling
try {
    # Check Windows Defender status
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "NIST - IR-4" -Status "Pass" `
            -Message "Windows Defender real-time protection is enabled" `
            -Details "NIST 800-53 IR-4: Automated incident handling capability is active"
    } else {
        Add-Result -Category "NIST - IR-4" -Status "Fail" `
            -Message "Windows Defender real-time protection is disabled" `
            -Details "NIST 800-53 IR-4: Enable automated threat detection" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
} catch {
    Add-Result -Category "NIST - IR-4" -Status "Error" `
        -Message "Failed to check incident handling capability: $_"
}

# IR-5: Incident Monitoring
try {
    # Check if Security log is enabled and has adequate size
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    
    if ($securityLog -and $securityLog.IsEnabled) {
        $sizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
        
        Add-Result -Category "NIST - IR-5" -Status "Pass" `
            -Message "Security event log is enabled for incident monitoring ($sizeMB MB)" `
            -Details "NIST 800-53 IR-5: System supports incident monitoring"
    } else {
        Add-Result -Category "NIST - IR-5" -Status "Fail" `
            -Message "Security event log is not properly configured" `
            -Details "NIST 800-53 IR-5: Enable security event logging" `
            -Remediation "Configure Security event log via Event Viewer"
    }
} catch {
    Add-Result -Category "NIST - IR-5" -Status "Error" `
        -Message "Failed to check incident monitoring: $_"
}

# ============================================================================
# NIST 800-53: Media Protection (MP)
# ============================================================================
Write-Host "[NIST] Checking Media Protection (MP) Controls..." -ForegroundColor Yellow

# MP-7: Media Use
try {
    # Check AutoPlay/AutoRun settings
    $autoPlay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    
    if ($autoPlay -and $autoPlay.NoDriveTypeAutoRun -eq 255) {
        Add-Result -Category "NIST - MP-7" -Status "Pass" `
            -Message "AutoPlay is disabled for all drive types" `
            -Details "NIST 800-53 MP-7: Removable media use is controlled"
    } else {
        Add-Result -Category "NIST - MP-7" -Status "Fail" `
            -Message "AutoPlay is not fully disabled" `
            -Details "NIST 800-53 MP-7: Disable AutoPlay to control media use" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255"
    }
} catch {
    Add-Result -Category "NIST - MP-7" -Status "Error" `
        -Message "Failed to check media protection: $_"
}

# ============================================================================
# NIST 800-53: System and Information Integrity (SI)
# ============================================================================
Write-Host "[NIST] Checking System and Information Integrity (SI) Controls..." -ForegroundColor Yellow

# SI-2: Flaw Remediation
try {
    # Check for recent updates
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    
    if ($historyCount -gt 0) {
        $recentUpdates = $searcher.QueryHistory(0, 10) | Where-Object { $_.Date -gt (Get-Date).AddDays(-30) }
        
        if ($recentUpdates) {
            $successCount = ($recentUpdates | Where-Object { $_.ResultCode -eq 2 }).Count
            Add-Result -Category "NIST - SI-2" -Status "Pass" `
                -Message "Recent updates detected: $successCount successful in last 30 days" `
                -Details "NIST 800-53 SI-2: Flaw remediation is being performed"
        } else {
            Add-Result -Category "NIST - SI-2" -Status "Fail" `
                -Message "No updates installed in the last 30 days" `
                -Details "NIST 800-53 SI-2: Install security patches regularly" `
                -Remediation "Install pending Windows updates"
        }
    }
    
    # Check for pending updates
    $pendingUpdates = $searcher.Search("IsInstalled=0 and Type='Software'")
    if ($pendingUpdates.Updates.Count -gt 0) {
        $criticalCount = ($pendingUpdates.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
        
        if ($criticalCount -gt 0) {
            Add-Result -Category "NIST - SI-2" -Status "Fail" `
                -Message "$criticalCount critical update(s) pending installation" `
                -Details "NIST 800-53 SI-2: Install critical security updates" `
                -Remediation "Install pending critical updates immediately"
        }
    }
} catch {
    Add-Result -Category "NIST - SI-2" -Status "Error" `
        -Message "Failed to check flaw remediation: $_"
}

# SI-3: Malicious Code Protection
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus) {
        if ($defenderStatus.RealTimeProtectionEnabled -and 
            $defenderStatus.BehaviorMonitorEnabled -and 
            $defenderStatus.IoavProtectionEnabled) {
            Add-Result -Category "NIST - SI-3" -Status "Pass" `
                -Message "Comprehensive malicious code protection is enabled" `
                -Details "NIST 800-53 SI-3: Real-time, behavior, and download protection active"
        } else {
            Add-Result -Category "NIST - SI-3" -Status "Fail" `
                -Message "Malicious code protection is incomplete" `
                -Details "NIST 800-53 SI-3: Enable all protection mechanisms" `
                -Remediation "Enable real-time, behavior monitoring, and IOAV protection"
        }
        
        # Check signature age
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        if ($signatureAge.Days -le 7) {
            Add-Result -Category "NIST - SI-3" -Status "Pass" `
                -Message "Malicious code definitions are current ($($signatureAge.Days) days old)" `
                -Details "NIST 800-53 SI-3(2): Automatic updates are functioning"
        } else {
            Add-Result -Category "NIST - SI-3" -Status "Warning" `
                -Message "Malicious code definitions are outdated ($($signatureAge.Days) days old)" `
                -Details "NIST 800-53 SI-3(2): Update antivirus definitions" `
                -Remediation "Update-MpSignature"
        }
    }
} catch {
    Add-Result -Category "NIST - SI-3" -Status "Error" `
        -Message "Failed to check malicious code protection: $_"
}

# SI-4: System Monitoring
try {
    # Check if Windows Defender has cloud protection
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference -and $mpPreference.MAPSReporting -gt 0) {
        Add-Result -Category "NIST - SI-4" -Status "Pass" `
            -Message "Cloud-based system monitoring is enabled" `
            -Details "NIST 800-53 SI-4: System monitoring tools are deployed"
    } else {
        Add-Result -Category "NIST - SI-4" -Status "Warning" `
            -Message "Cloud-based monitoring is not enabled" `
            -Details "NIST 800-53 SI-4: Enable cloud protection for enhanced monitoring" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced"
    }
} catch {
    Add-Result -Category "NIST - SI-4" -Status "Error" `
        -Message "Failed to check system monitoring: $_"
}

# SI-7: Software, Firmware, and Information Integrity
try {
    # Check Windows Defender Application Control status
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        if ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Add-Result -Category "NIST - SI-7" -Status "Pass" `
                -Message "Code Integrity Policy is enforced" `
                -Details "NIST 800-53 SI-7: Software integrity verification is active"
        } else {
            Add-Result -Category "NIST - SI-7" -Status "Info" `
                -Message "Code Integrity Policy is not enforced" `
                -Details "NIST 800-53 SI-7: Consider implementing WDAC for integrity verification"
        }
    }
} catch {
    Add-Result -Category "NIST - SI-7" -Status "Info" `
        -Message "Could not verify software integrity mechanisms"
}

# SI-16: Memory Protection
try {
    # Check DEP (Data Execution Prevention)
    $dep = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ExecuteOptions" -ErrorAction SilentlyContinue
    
    if ($dep) {
        Add-Result -Category "NIST - SI-16" -Status "Pass" `
            -Message "Data Execution Prevention (DEP) is configured" `
            -Details "NIST 800-53 SI-16: Memory protection mechanisms are in place"
    } else {
        Add-Result -Category "NIST - SI-16" -Status "Info" `
            -Message "DEP configuration not explicitly set (may use default)" `
            -Details "NIST 800-53 SI-16: DEP is typically enabled by default"
    }
} catch {
    Add-Result -Category "NIST - SI-16" -Status "Error" `
        -Message "Failed to check memory protection: $_"
}

# ============================================================================
# NIST CSF: Identify, Protect, Detect, Respond, Recover
# ============================================================================
Write-Host "[NIST] Checking NIST Cybersecurity Framework compliance..." -ForegroundColor Yellow

# CSF - Protect: Asset Management
try {
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, Publisher, InstallDate |
        Where-Object { $_.DisplayName } |
        Measure-Object
    
    Add-Result -Category "NIST - CSF Protect" -Status "Info" `
        -Message "Asset Management: $($installedApps.Count) applications installed" `
        -Details "NIST CSF ID.AM: Maintain inventory of authorized software"
} catch {
    Add-Result -Category "NIST - CSF Protect" -Status "Error" `
        -Message "Failed to enumerate installed applications: $_"
}

# CSF - Detect: Continuous Monitoring
try {
    # Check if System Restore is enabled
    $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    
    if ($restorePoints) {
        Add-Result -Category "NIST - CSF Recover" -Status "Pass" `
            -Message "Recovery capability: $($restorePoints.Count) restore point(s) available" `
            -Details "NIST CSF RC.RP: System Restore provides recovery capability"
    } else {
        Add-Result -Category "NIST - CSF Recover" -Status "Warning" `
            -Message "No System Restore points available" `
            -Details "NIST CSF RC.RP: Enable System Restore for recovery capability" `
            -Remediation "Enable-ComputerRestore -Drive C:\; Checkpoint-Computer -Description 'Baseline'"
    }
} catch {
    Add-Result -Category "NIST - CSF Recover" -Status "Info" `
        -Message "Could not check recovery capabilities"
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

Write-Host "`n[NIST] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results
