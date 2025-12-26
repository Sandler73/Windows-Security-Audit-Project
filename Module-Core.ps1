# Module-Core.ps1
# Core Security Baseline Module
# Version: 5.0
# Performs fundamental Windows security checks

<#
.SYNOPSIS
    Core security baseline checks for Windows systems.

.DESCRIPTION
    This module performs essential security checks including:
    - Windows Defender antivirus status
    - Windows Firewall configuration
    - Windows Update status
    - User Account Control (UAC)
    - Account security and password policies
    - BitLocker encryption status
    - Remote Desktop configuration
    - Network protocol security (SMBv1)
    - System information and disk space

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Version: 5.0
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "Core"
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

Write-Host "`n[Core] Starting core security baseline checks..." -ForegroundColor Cyan

# ============================================================================
# Windows Defender Status
# ============================================================================
Write-Host "[Core] Checking Windows Defender..." -ForegroundColor Yellow

try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defender) {
        # Real-time protection
        if ($defender.RealTimeProtectionEnabled) {
            Add-Result -Category "Core - Antivirus" -Status "Pass" `
                -Message "Windows Defender real-time protection is enabled" `
                -Details "Real-time scanning provides continuous malware protection"
        } else {
            Add-Result -Category "Core - Antivirus" -Status "Fail" `
                -Message "Windows Defender real-time protection is disabled" `
                -Details "System is vulnerable to malware without real-time protection" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
        }
        
        # Signature age
        $signatureAge = (Get-Date) - $defender.AntivirusSignatureLastUpdated
        if ($signatureAge.Days -le 7) {
            Add-Result -Category "Core - Antivirus" -Status "Pass" `
                -Message "Antivirus signatures are up to date (last updated: $($defender.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')))" `
                -Details "Signatures are $($signatureAge.Days) day(s) old"
        } else {
            Add-Result -Category "Core - Antivirus" -Status "Warning" `
                -Message "Antivirus signatures are outdated (last updated: $($defender.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')))" `
                -Details "Signatures are $($signatureAge.Days) day(s) old - should update daily" `
                -Remediation "Update-MpSignature"
        }
        
        # Quick scan age
        if ($defender.QuickScanAge -le 7) {
            Add-Result -Category "Core - Antivirus" -Status "Pass" `
                -Message "Recent malware scan performed ($($defender.QuickScanAge) days ago)" `
                -Details "Regular scans help detect dormant malware"
        } else {
            Add-Result -Category "Core - Antivirus" -Status "Info" `
                -Message "No recent malware scan (last scan: $($defender.QuickScanAge) days ago)" `
                -Details "Consider running regular system scans" `
                -Remediation "Start-MpScan -ScanType QuickScan"
        }
        
        # Cloud-delivered protection
        if ($defender.MAPSReporting -ne 0) {
            Add-Result -Category "Core - Antivirus" -Status "Pass" `
                -Message "Cloud-delivered protection is enabled" `
                -Details "Cloud protection provides rapid response to new threats"
        } else {
            Add-Result -Category "Core - Antivirus" -Status "Warning" `
                -Message "Cloud-delivered protection is disabled" `
                -Details "Cloud protection enhances threat detection" `
                -Remediation "Set-MpPreference -MAPSReporting Advanced"
        }
        
        # Behavior monitoring
        if ($defender.BehaviorMonitorEnabled) {
            Add-Result -Category "Core - Antivirus" -Status "Pass" `
                -Message "Behavior monitoring is enabled" `
                -Details "Detects suspicious behavior patterns"
        } else {
            Add-Result -Category "Core - Antivirus" -Status "Warning" `
                -Message "Behavior monitoring is disabled" `
                -Details "Behavior monitoring helps detect zero-day threats" `
                -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
        }
        
    } else {
        Add-Result -Category "Core - Antivirus" -Status "Warning" `
            -Message "Unable to query Windows Defender status" `
            -Details "May indicate third-party antivirus or Defender is disabled"
    }
} catch {
    Add-Result -Category "Core - Antivirus" -Status "Error" `
        -Message "Failed to check Windows Defender status: $_"
}

# ============================================================================
# Windows Firewall Status
# ============================================================================
Write-Host "[Core] Checking Windows Firewall..." -ForegroundColor Yellow

try {
    $firewallProfiles = @("Domain", "Private", "Public")
    
    foreach ($Coreprofile in $firewallProfiles) {
        $fwProfile = Get-NetFirewallProfile -Name $Coreprofile
        
        if ($fwProfile.Enabled) {
            Add-Result -Category "Core - Firewall" -Status "Pass" `
                -Message "${Coreprofile} firewall profile is enabled" `
                -Details "Host-based firewall provides network-level protection"
        } else {
            Add-Result -Category "Core - Firewall" -Status "Fail" `
                -Message "${Coreprofile} firewall profile is disabled" `
                -Details "System is exposed to network-based attacks" `
                -Remediation "Set-NetFirewallProfile -Name $Coreprofile -Enabled True"
        }
        
        # Check default inbound action
        if ($fwProfile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "Core - Firewall" -Status "Pass" `
                -Message "${Coreprofile} firewall: Default inbound action is Block" `
                -Details "Default deny provides better security posture"
        } else {
            Add-Result -Category "Core - Firewall" -Status "Warning" `
                -Message "${Coreprofile} firewall: Default inbound action is Allow" `
                -Details "Consider setting default inbound action to Block" `
                -Remediation "Set-NetFirewallProfile -Name $Coreprofile -DefaultInboundAction Block"
        }
    }
} catch {
    Add-Result -Category "Core - Firewall" -Status "Error" `
        -Message "Failed to check firewall status: $_"
}

# ============================================================================
# Windows Update Status
# ============================================================================
Write-Host "[Core] Checking Windows Update..." -ForegroundColor Yellow

try {
    $updateService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($updateService) {
        if ($updateService.Status -eq "Running" -or $updateService.StartType -ne "Disabled") {
            Add-Result -Category "Core - Updates" -Status "Pass" `
                -Message "Windows Update service is available" `
                -Details "Service status: $($updateService.Status), Start type: $($updateService.StartType)"
        } else {
            Add-Result -Category "Core - Updates" -Status "Fail" `
                -Message "Windows Update service is disabled" `
                -Details "System cannot receive critical security updates" `
                -Remediation "Set-Service -Name wuauserv -StartupType Manual; Start-Service wuauserv"
        }
    }
    
    # Check for pending updates
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        
        $pendingUpdates = $searchResult.Updates.Count
        $criticalUpdates = ($searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
        
        if ($pendingUpdates -eq 0) {
            Add-Result -Category "Core - Updates" -Status "Pass" `
                -Message "No pending Windows updates" `
                -Details "System is up to date"
        } elseif ($criticalUpdates -gt 0) {
            Add-Result -Category "Core - Updates" -Status "Fail" `
                -Message "$criticalUpdates critical update(s) pending installation" `
                -Details "Total pending updates: $pendingUpdates" `
                -Remediation "Install updates via Windows Update: Start ms-settings:windowsupdate"
        } else {
            Add-Result -Category "Core - Updates" -Status "Warning" `
                -Message "$pendingUpdates update(s) pending installation" `
                -Details "No critical updates, but system should be kept current"
        }
    } catch {
        Add-Result -Category "Core - Updates" -Status "Info" `
            -Message "Could not check for pending updates" `
            -Details "May require elevated privileges or COM object is unavailable"
    }
} catch {
    Add-Result -Category "Core - Updates" -Status "Error" `
        -Message "Failed to check Windows Update service: $_"
}

# ============================================================================
# User Account Control (UAC)
# ============================================================================
Write-Host "[Core] Checking User Account Control..." -ForegroundColor Yellow

try {
    $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    
    if ($uacEnabled -and $uacEnabled.EnableLUA -eq 1) {
        Add-Result -Category "Core - UAC" -Status "Pass" `
            -Message "User Account Control (UAC) is enabled" `
            -Details "UAC prevents unauthorized privilege escalation"
    } else {
        Add-Result -Category "Core - UAC" -Status "Fail" `
            -Message "User Account Control (UAC) is disabled" `
            -Details "System is vulnerable to privilege escalation attacks" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
    }
    
    # Check UAC prompt behavior
    $uacPrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    if ($uacPrompt) {
        $promptLevel = switch ($uacPrompt.ConsentPromptBehaviorAdmin) {
            0 { "Never notify" }
            1 { "Prompt for credentials on secure desktop" }
            2 { "Prompt for consent on secure desktop" }
            3 { "Prompt for credentials" }
            4 { "Prompt for consent" }
            5 { "Prompt for consent for non-Windows binaries" }
            default { "Unknown ($($uacPrompt.ConsentPromptBehaviorAdmin))" }
        }
        
        if ($uacPrompt.ConsentPromptBehaviorAdmin -ge 2) {
            Add-Result -Category "Core - UAC" -Status "Pass" `
                -Message "UAC prompt level: $promptLevel" `
                -Details "Adequate protection against unauthorized elevation"
        } else {
            Add-Result -Category "Core - UAC" -Status "Warning" `
                -Message "UAC prompt level: $promptLevel" `
                -Details "Consider increasing UAC prompt level for better security"
        }
    }
} catch {
    Add-Result -Category "Core - UAC" -Status "Error" `
        -Message "Failed to check UAC status: $_"
}

# ============================================================================
# Account Security
# ============================================================================
Write-Host "[Core] Checking account security..." -ForegroundColor Yellow

try {
    # Check for disabled built-in Administrator account
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount) {
        if ($adminAccount.Enabled -eq $false) {
            Add-Result -Category "Core - Accounts" -Status "Pass" `
                -Message "Built-in Administrator account is disabled" `
                -Details "Reduces attack surface by disabling well-known account"
        } else {
            Add-Result -Category "Core - Accounts" -Status "Fail" `
                -Message "Built-in Administrator account is enabled" `
                -Details "Well-known account is a common attack target" `
                -Remediation "Disable-LocalUser -SID $($adminAccount.SID)"
        }
    }
    
    # Check for disabled Guest account
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Enabled -eq $false) {
            Add-Result -Category "Core - Accounts" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "Prevents anonymous access to system"
        } else {
            Add-Result -Category "Core - Accounts" -Status "Fail" `
                -Message "Guest account is enabled" `
                -Details "Guest account allows anonymous access" `
                -Remediation "Disable-LocalUser -Name Guest"
        }
    }
    
    # Check for accounts without passwords
    $usersWithoutPasswords = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
    if ($usersWithoutPasswords.Count -gt 0) {
        $userList = $usersWithoutPasswords.Name -join ", "
        Add-Result -Category "Core - Accounts" -Status "Fail" `
            -Message "$($usersWithoutPasswords.Count) account(s) without password requirements: $userList" `
            -Details "Accounts without passwords are security vulnerabilities" `
            -Remediation "Set passwords for all accounts or disable them"
    } else {
        Add-Result -Category "Core - Accounts" -Status "Pass" `
            -Message "All enabled accounts require passwords" `
            -Details "Password requirements are enforced"
    }
    
    # Check for inactive accounts
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $inactiveUsers = @()
    
    foreach ($user in $users) {
        if ($user.LastLogon -and $user.LastLogon -lt $inactiveThreshold) {
            $inactiveUsers += $user.Name
        }
    }
    
    if ($inactiveUsers.Count -gt 0) {
        Add-Result -Category "Core - Accounts" -Status "Warning" `
            -Message "$($inactiveUsers.Count) inactive account(s) detected (no login in 90+ days)" `
            -Details "Inactive accounts: $($inactiveUsers -join ', ')" `
            -Remediation "Review and disable or remove inactive accounts"
    } else {
        Add-Result -Category "Core - Accounts" -Status "Pass" `
            -Message "No inactive accounts detected (90+ days)" `
            -Details "Account activity is within acceptable range"
    }
    
} catch {
    Add-Result -Category "Core - Accounts" -Status "Error" `
        -Message "Failed to check account security: $_"
}

# ============================================================================
# Password Policy
# ============================================================================
Write-Host "[Core] Checking password policy..." -ForegroundColor Yellow

try {
    $passwordPolicy = net accounts | Out-String
    
    # Minimum password length
    if ($passwordPolicy -match "Minimum password length\s+(\d+)") {
        $minLength = [int]$Matches[1]
        if ($minLength -ge 8) {
            Add-Result -Category "Core - Password Policy" -Status "Pass" `
                -Message "Minimum password length is $minLength characters" `
                -Details "Meets basic password complexity requirements"
        } else {
            Add-Result -Category "Core - Password Policy" -Status "Fail" `
                -Message "Minimum password length is $minLength characters (should be 8+)" `
                -Details "Weak passwords are easily compromised" `
                -Remediation "net accounts /minpwlen:8"
        }
    }
    
    # Maximum password age
    if ($passwordPolicy -match "Maximum password age \(days\):\s+(\d+)") {
        $maxAge = [int]$Matches[1]
        if ($maxAge -gt 0 -and $maxAge -le 90) {
            Add-Result -Category "Core - Password Policy" -Status "Pass" `
                -Message "Maximum password age is $maxAge days" `
                -Details "Regular password changes are enforced"
        } elseif ($maxAge -eq 0) {
            Add-Result -Category "Core - Password Policy" -Status "Warning" `
                -Message "Passwords are set to never expire" `
                -Details "Consider implementing password expiration policy"
        } else {
            Add-Result -Category "Core - Password Policy" -Status "Info" `
                -Message "Maximum password age is $maxAge days" `
                -Details "Password expiration is configured"
        }
    }
    
    # Account lockout threshold
    if ($passwordPolicy -match "Lockout threshold:\s+(\d+)") {
        $lockoutThreshold = [int]$Matches[1]
        if ($lockoutThreshold -gt 0 -and $lockoutThreshold -le 10) {
            Add-Result -Category "Core - Password Policy" -Status "Pass" `
                -Message "Account lockout threshold is $lockoutThreshold attempts" `
                -Details "Protects against brute force password attacks"
        } elseif ($lockoutThreshold -eq 0) {
            Add-Result -Category "Core - Password Policy" -Status "Fail" `
                -Message "Account lockout is disabled" `
                -Details "No protection against brute force attacks" `
                -Remediation "net accounts /lockoutthreshold:5"
        } else {
            Add-Result -Category "Core - Password Policy" -Status "Warning" `
                -Message "Account lockout threshold is $lockoutThreshold (consider 5-10)" `
                -Details "Lower threshold provides better protection"
        }
    }
    
    # Lockout duration
    if ($passwordPolicy -match "Lockout duration \(minutes\):\s+(\d+)") {
        $lockoutDuration = [int]$Matches[1]
        if ($lockoutDuration -ge 15) {
            Add-Result -Category "Core - Password Policy" -Status "Pass" `
                -Message "Account lockout duration is $lockoutDuration minutes" `
                -Details "Adequate lockout period configured"
        } elseif ($lockoutDuration -gt 0) {
            Add-Result -Category "Core - Password Policy" -Status "Info" `
                -Message "Account lockout duration is $lockoutDuration minutes" `
                -Details "Consider 15+ minutes for better security"
        }
    }
    
} catch {
    Add-Result -Category "Core - Password Policy" -Status "Error" `
        -Message "Failed to check password policy: $_"
}

# ============================================================================
# BitLocker Encryption
# ============================================================================
Write-Host "[Core] Checking disk encryption..." -ForegroundColor Yellow

try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    
    if ($bitlockerVolumes) {
        $encryptedVolumes = $bitlockerVolumes | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" }
        $unencryptedVolumes = $bitlockerVolumes | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" }
        
        if ($encryptedVolumes) {
            foreach ($vol in $encryptedVolumes) {
                Add-Result -Category "Core - Encryption" -Status "Pass" `
                    -Message "Volume $($vol.MountPoint) is encrypted" `
                    -Details "Encryption method: $($vol.EncryptionMethod)"
            }
        }
        
        if ($unencryptedVolumes) {
            foreach ($vol in $unencryptedVolumes) {
                Add-Result -Category "Core - Encryption" -Status "Warning" `
                    -Message "Volume $($vol.MountPoint) is not encrypted" `
                    -Details "Data at rest is not protected" `
                    -Remediation "Enable-BitLocker -MountPoint '$($vol.MountPoint)' -EncryptionMethod XtsAes256 -UsedSpaceOnly"
            }
        }
    } else {
        Add-Result -Category "Core - Encryption" -Status "Info" `
            -Message "Unable to check BitLocker status" `
            -Details "May require elevated privileges or BitLocker is not available"
    }
} catch {
    Add-Result -Category "Core - Encryption" -Status "Info" `
        -Message "BitLocker check skipped (requires elevated privileges)" `
        -Details "Run as Administrator to check disk encryption status"
}

# ============================================================================
# Remote Desktop Configuration
# ============================================================================
Write-Host "[Core] Checking Remote Desktop..." -ForegroundColor Yellow

try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "Core - Remote Access" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "Reduces attack surface when not needed"
    } else {
        # RDP is enabled - check security settings
        Add-Result -Category "Core - Remote Access" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "Ensure RDP is secured with NLA and strong passwords"
        
        # Check Network Level Authentication
        $nlaRequired = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        if ($nlaRequired -and $nlaRequired.UserAuthentication -eq 1) {
            Add-Result -Category "Core - Remote Access" -Status "Pass" `
                -Message "RDP: Network Level Authentication (NLA) is required" `
                -Details "NLA provides additional authentication security"
        } else {
            Add-Result -Category "Core - Remote Access" -Status "Warning" `
                -Message "RDP: Network Level Authentication (NLA) is not required" `
                -Details "NLA should be enabled for secure RDP access" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
    }
} catch {
    Add-Result -Category "Core - Remote Access" -Status "Error" `
        -Message "Failed to check Remote Desktop configuration: $_"
}

# ============================================================================
# SMBv1 Protocol Check
# ============================================================================
Write-Host "[Core] Checking SMBv1 protocol..." -ForegroundColor Yellow

try {
    $smbv1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol
    
    if ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $false) {
        Add-Result -Category "Core - Network Security" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "SMBv1 has known vulnerabilities (WannaCry, NotPetya)"
    } elseif ($smbv1 -and $smbv1.EnableSMB1Protocol -eq $true) {
        Add-Result -Category "Core - Network Security" -Status "Fail" `
            -Message "SMBv1 protocol is enabled" `
            -Details "SMBv1 is vulnerable to ransomware and should be disabled" `
            -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    }
} catch {
    Add-Result -Category "Core - Network Security" -Status "Error" `
        -Message "Failed to check SMBv1 status: $_"
}

# ============================================================================
# System Information
# ============================================================================
Write-Host "[Core] Gathering system information..." -ForegroundColor Yellow

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    
    Add-Result -Category "Core - System Info" -Status "Info" `
        -Message "Computer: $($cs.Name)" `
        -Details "Domain/Workgroup: $($cs.Domain)"
    
    Add-Result -Category "Core - System Info" -Status "Info" `
        -Message "OS: $($os.Caption)" `
        -Details "Version: $($os.Version), Build: $($os.BuildNumber), Architecture: $($os.OSArchitecture)"
    
    $lastBoot = $os.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    Add-Result -Category "Core - System Info" -Status "Info" `
        -Message "Last Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss'))" `
        -Details "Uptime: $([math]::Round($uptime.TotalDays, 2)) days"
} catch {
    Add-Result -Category "Core - System Info" -Status "Error" `
        -Message "Failed to gather system information: $_"
}

# ============================================================================
# Disk Space Check
# ============================================================================
Write-Host "[Core] Checking disk space..." -ForegroundColor Yellow

try {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
    
    foreach ($drive in $drives) {
        $freeSpacePercent = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100, 2)
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        $usedSpaceGB = [math]::Round($drive.Used / 1GB, 2)
        
        if ($freeSpacePercent -ge 20) {
            Add-Result -Category "Core - Disk Space" -Status "Pass" `
                -Message "Drive ${drive}:\ has $freeSpacePercent% free space" `
                -Details "Free: ${freeSpaceGB} GB, Used: ${usedSpaceGB} GB"
        } elseif ($freeSpacePercent -ge 10) {
            Add-Result -Category "Core - Disk Space" -Status "Warning" `
                -Message "Drive ${drive}:\ has only $freeSpacePercent% free space" `
                -Details "Free: ${freeSpaceGB} GB, Used: ${usedSpaceGB} GB" `
                -Remediation "Free up disk space or expand volume"
        } else {
            Add-Result -Category "Core - Disk Space" -Status "Fail" `
                -Message "Drive ${drive}:\ is critically low on space ($freeSpacePercent% free)" `
                -Details "Free: ${freeSpaceGB} GB, Used: ${usedSpaceGB} GB" `
                -Remediation "Immediately free up disk space or expand volume"
        }
    }
} catch {
    Add-Result -Category "Core - Disk Space" -Status "Error" `
        -Message "Failed to check disk space: $_"
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

Write-Host "`n[Core] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results
