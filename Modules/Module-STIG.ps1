# Module-STIG.ps1
# DISA STIG (Security Technical Implementation Guide) Compliance Module
# Version: 5.0
# Based on DISA Windows 10/11 and Windows Server STIGs

<#
.SYNOPSIS
    DISA STIG compliance checks for Windows systems.

.DESCRIPTION
    This module checks alignment with DISA STIGs including:
    - Windows 10/11 Security Technical Implementation Guide
    - Windows Server Security Technical Implementation Guide
    - Account and password policies (CAT I, II, III findings)
    - Audit policies and event logging
    - System hardening and security options
    - Network protocol security
    - Service configuration
    - User rights assignments
    - Windows Defender configuration
    - Remote access security
    - Application and device control
    - Data protection and encryption

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Author: Security Audit Script Project
    Version: 5.0
    Based on: DISA Windows 10/11 STIG, Windows Server STIG
    CAT I = High Severity, CAT II = Medium Severity, CAT III = Low Severity
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "STIG"
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

Write-Host "`n[STIG] Starting DISA STIG compliance checks..." -ForegroundColor Cyan

# ============================================================================
# STIG: Account Policies - Password Requirements (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Account Policies..." -ForegroundColor Yellow

try {
    $netAccounts = net accounts 2>$null
    
    if ($netAccounts) {
        # V-220718: Minimum password length must be 14 characters (CAT II)
        $minLength = ($netAccounts | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
        
        if ([int]$minLength -ge 14) {
            Add-Result -Category "STIG - V-220718 (CAT II)" -Status "Pass" `
                -Message "Minimum password length: $minLength characters" `
                -Details "STIG: Passwords must be at least 14 characters to resist brute force"
        } else {
            Add-Result -Category "STIG - V-220718 (CAT II)" -Status "Fail" `
                -Message "Minimum password length is insufficient: $minLength characters" `
                -Details "STIG: Set minimum password length to 14 or more characters" `
                -Remediation "net accounts /minpwlen:14"
        }
        
        # V-220726: Password history must remember 24 passwords (CAT II)
        $history = ($netAccounts | Select-String "Length of password history maintained").ToString().Split(":")[1].Trim()
        
        if ([int]$history -ge 24) {
            Add-Result -Category "STIG - V-220726 (CAT II)" -Status "Pass" `
                -Message "Password history: $history passwords remembered" `
                -Details "STIG: Prevents password reuse for 24 generations"
        } else {
            Add-Result -Category "STIG - V-220726 (CAT II)" -Status "Fail" `
                -Message "Password history is insufficient: $history passwords" `
                -Details "STIG: Configure password history to remember 24 or more passwords" `
                -Remediation "net accounts /uniquepw:24"
        }
        
        # V-220724: Minimum password age must be 1 day (CAT II)
        $minAge = ($netAccounts | Select-String "Minimum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$minAge -ge 1) {
            Add-Result -Category "STIG - V-220724 (CAT II)" -Status "Pass" `
                -Message "Minimum password age: $minAge day(s)" `
                -Details "STIG: Prevents rapid password cycling to bypass history"
        } else {
            Add-Result -Category "STIG - V-220724 (CAT II)" -Status "Fail" `
                -Message "Minimum password age: $minAge days" `
                -Details "STIG: Set minimum password age to 1 or more days" `
                -Remediation "net accounts /minpwage:1"
        }
        
        # V-220725: Maximum password age must be 60 days or less (CAT II)
        $maxAge = ($netAccounts | Select-String "Maximum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ($maxAge -eq "Unlimited") {
            Add-Result -Category "STIG - V-220725 (CAT II)" -Status "Fail" `
                -Message "Maximum password age is Unlimited" `
                -Details "STIG: Configure password expiration to 60 days or less" `
                -Remediation "net accounts /maxpwage:60"
        } elseif ([int]$maxAge -le 60) {
            Add-Result -Category "STIG - V-220725 (CAT II)" -Status "Pass" `
                -Message "Maximum password age: $maxAge days" `
                -Details "STIG: Password expiration meets requirement"
        } else {
            Add-Result -Category "STIG - V-220725 (CAT II)" -Status "Fail" `
                -Message "Maximum password age is too long: $maxAge days" `
                -Details "STIG: Set maximum password age to 60 days or less" `
                -Remediation "net accounts /maxpwage:60"
        }
        
        # V-220719: Account lockout threshold must be 3 or less (CAT II)
        $lockoutThreshold = ($netAccounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
        
        if ($lockoutThreshold -eq "Never") {
            Add-Result -Category "STIG - V-220719 (CAT II)" -Status "Fail" `
                -Message "Account lockout is disabled" `
                -Details "STIG: Configure account lockout after 3 or fewer invalid attempts" `
                -Remediation "net accounts /lockoutthreshold:3"
        } elseif ([int]$lockoutThreshold -le 3 -and [int]$lockoutThreshold -gt 0) {
            Add-Result -Category "STIG - V-220719 (CAT II)" -Status "Pass" `
                -Message "Account lockout threshold: $lockoutThreshold attempts" `
                -Details "STIG: Account lockout protects against brute force attacks"
        } else {
            Add-Result -Category "STIG - V-220719 (CAT II)" -Status "Fail" `
                -Message "Account lockout threshold is too high: $lockoutThreshold" `
                -Details "STIG: Set lockout threshold to 3 or fewer attempts" `
                -Remediation "net accounts /lockoutthreshold:3"
        }
        
        # V-220720: Lockout duration must be 15 minutes or greater (CAT II)
        $lockoutDuration = ($netAccounts | Select-String "Lockout duration").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$lockoutDuration -ge 15) {
            Add-Result -Category "STIG - V-220720 (CAT II)" -Status "Pass" `
                -Message "Account lockout duration: $lockoutDuration minutes" `
                -Details "STIG: Lockout duration meets requirement"
        } else {
            Add-Result -Category "STIG - V-220720 (CAT II)" -Status "Fail" `
                -Message "Account lockout duration is too short: $lockoutDuration minutes" `
                -Details "STIG: Set lockout duration to 15 minutes or greater" `
                -Remediation "net accounts /lockoutduration:15"
        }
    }
} catch {
    Add-Result -Category "STIG - Account Policy" -Status "Error" `
        -Message "Failed to check account policies: $_"
}

# V-220717: Password complexity must be enabled (CAT II)
try {
    # Note: This is typically enforced via secpol, not easily readable from registry
    Add-Result -Category "STIG - V-220717 (CAT II)" -Status "Info" `
        -Message "Password complexity policy" `
        -Details "STIG: Verify password complexity is enabled via Local Security Policy > Account Policies > Password Policy" `
        -Remediation "Enable 'Password must meet complexity requirements' in Local Security Policy"
} catch {
    Add-Result -Category "STIG - V-220717 (CAT II)" -Status "Error" `
        -Message "Failed to check password complexity: $_"
}

# ============================================================================
# STIG: User Rights Assignment (CAT I, II)
# ============================================================================
Write-Host "[STIG] Checking User Rights Assignment..." -ForegroundColor Yellow

# V-220929: Guest account must be disabled (CAT I)
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount) {
        if ($guestAccount.Enabled) {
            Add-Result -Category "STIG - V-220929 (CAT I)" -Status "Fail" `
                -Message "Guest account is ENABLED" `
                -Details "STIG CAT I: Guest account must be disabled to prevent anonymous access" `
                -Remediation "Disable-LocalUser -Name Guest"
        } else {
            Add-Result -Category "STIG - V-220929 (CAT I)" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "STIG CAT I: Guest account is properly disabled"
        }
    }
} catch {
    Add-Result -Category "STIG - V-220929 (CAT I)" -Status "Error" `
        -Message "Failed to check Guest account: $_"
}

# V-220930: Administrator account must be renamed (CAT II)
try {
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    
    if ($adminAccount) {
        Add-Result -Category "STIG - V-220930 (CAT II)" -Status "Warning" `
            -Message "Built-in Administrator account has not been renamed" `
            -Details "STIG CAT II: Rename built-in Administrator account to reduce targeting" `
            -Remediation "Rename-LocalUser -Name Administrator -NewName <unique_name>"
        
        if ($adminAccount.Enabled) {
            Add-Result -Category "STIG - Account Security" -Status "Warning" `
                -Message "Built-in Administrator account is enabled" `
                -Details "STIG: Consider disabling built-in Administrator account" `
                -Remediation "Disable-LocalUser -Name Administrator"
        }
    }
} catch {
    Add-Result -Category "STIG - V-220930 (CAT II)" -Status "Error" `
        -Message "Failed to check Administrator account: $_"
}

# V-220931: Guest account must be renamed (CAT II)
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount) {
        Add-Result -Category "STIG - V-220931 (CAT II)" -Status "Warning" `
            -Message "Built-in Guest account has not been renamed" `
            -Details "STIG CAT II: Rename Guest account even when disabled" `
            -Remediation "Rename-LocalUser -Name Guest -NewName <unique_name>"
    }
} catch {
    Add-Result -Category "STIG - V-220931 (CAT II)" -Status "Error" `
        -Message "Failed to check Guest account rename: $_"
}

# ============================================================================
# STIG: Audit Policy Configuration (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Audit Policy Configuration..." -ForegroundColor Yellow

# Critical STIG audit subcategories
$stigAuditChecks = @(
    @{STIG="V-220755"; Subcategory="Credential Validation"; Expected="Success and Failure"; CAT="II"},
    @{STIG="V-220756"; Subcategory="Security Group Management"; Expected="Success"; CAT="II"},
    @{STIG="V-220757"; Subcategory="User Account Management"; Expected="Success and Failure"; CAT="II"},
    @{STIG="V-220758"; Subcategory="Plug and Play Events"; Expected="Success"; CAT="II"},
    @{STIG="V-220759"; Subcategory="Process Creation"; Expected="Success"; CAT="II"},
    @{STIG="V-220760"; Subcategory="Account Lockout"; Expected="Failure"; CAT="II"},
    @{STIG="V-220761"; Subcategory="Logoff"; Expected="Success"; CAT="II"},
    @{STIG="V-220762"; Subcategory="Logon"; Expected="Success and Failure"; CAT="II"},
    @{STIG="V-220763"; Subcategory="Special Logon"; Expected="Success"; CAT="II"},
    @{STIG="V-220764"; Subcategory="Removable Storage"; Expected="Success and Failure"; CAT="II"},
    @{STIG="V-220765"; Subcategory="Audit Policy Change"; Expected="Success"; CAT="II"},
    @{STIG="V-220766"; Subcategory="Authentication Policy Change"; Expected="Success"; CAT="II"},
    @{STIG="V-220767"; Subcategory="Authorization Policy Change"; Expected="Success"; CAT="II"},
    @{STIG="V-220768"; Subcategory="Sensitive Privilege Use"; Expected="Success and Failure"; CAT="II"},
    @{STIG="V-220769"; Subcategory="IPsec Driver"; Expected="Success and Failure"; CAT="II"},
    @{STIG="V-220770"; Subcategory="Security State Change"; Expected="Success"; CAT="II"},
    @{STIG="V-220771"; Subcategory="Security System Extension"; Expected="Success"; CAT="II"},
    @{STIG="V-220772"; Subcategory="System Integrity"; Expected="Success and Failure"; CAT="II"}
)

foreach ($check in $stigAuditChecks) {
    try {
        $auditResult = auditpol /get /subcategory:"$($check.Subcategory)" 2>$null
        
        if ($auditResult) {
            $resultText = $auditResult | Out-String
            
            if ($check.Expected -eq "Success and Failure") {
                if ($resultText -match "Success and Failure") {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Pass" `
                        -Message "$($check.Subcategory): Success and Failure auditing enabled" `
                        -Details "STIG: Audit policy is correctly configured"
                } else {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Fail" `
                        -Message "$($check.Subcategory): Not configured for Success and Failure" `
                        -Details "STIG: Enable both Success and Failure auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable /failure:enable"
                }
            } elseif ($check.Expected -eq "Success") {
                if ($resultText -match "Success") {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Pass" `
                        -Message "$($check.Subcategory): Success auditing enabled" `
                        -Details "STIG: Audit policy is correctly configured"
                } else {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Fail" `
                        -Message "$($check.Subcategory): Success auditing not enabled" `
                        -Details "STIG: Enable Success auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable"
                }
            } elseif ($check.Expected -eq "Failure") {
                if ($resultText -match "Failure") {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Pass" `
                        -Message "$($check.Subcategory): Failure auditing enabled" `
                        -Details "STIG: Audit policy is correctly configured"
                } else {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Fail" `
                        -Message "$($check.Subcategory): Failure auditing not enabled" `
                        -Details "STIG: Enable Failure auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /failure:enable"
                }
            }
        } else {
            Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Warning" `
                -Message "$($check.Subcategory): Could not determine audit status" `
                -Details "STIG: Verify audit policy configuration manually"
        }
    } catch {
        # Continue with other checks
    }
}

# ============================================================================
# STIG: Event Log Configuration (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Event Log Configuration..." -ForegroundColor Yellow

# V-220858: Application event log must be 32 MB or greater (CAT II)
try {
    $appLog = Get-WinEvent -ListLog Application -ErrorAction Stop
    $appLogSizeMB = [math]::Round($appLog.MaximumSizeInBytes / 1MB, 2)
    
    if ($appLogSizeMB -ge 32) {
        Add-Result -Category "STIG - V-220858 (CAT II)" -Status "Pass" `
            -Message "Application log size: $appLogSizeMB MB" `
            -Details "STIG: Log capacity is adequate for retention"
    } else {
        Add-Result -Category "STIG - V-220858 (CAT II)" -Status "Fail" `
            -Message "Application log size is insufficient: $appLogSizeMB MB" `
            -Details "STIG: Set Application log to at least 32 MB" `
            -Remediation "wevtutil sl Application /ms:33554432"
    }
} catch {
    Add-Result -Category "STIG - V-220858 (CAT II)" -Status "Error" `
        -Message "Failed to check Application log: $_"
}

# V-220859: Security event log must be 1024 MB or greater (CAT II)
try {
    $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $secLogSizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 2)
    
    if ($secLogSizeMB -ge 1024) {
        Add-Result -Category "STIG - V-220859 (CAT II)" -Status "Pass" `
            -Message "Security log size: $secLogSizeMB MB" `
            -Details "STIG: Security log capacity is adequate"
    } else {
        Add-Result -Category "STIG - V-220859 (CAT II)" -Status "Fail" `
            -Message "Security log size is insufficient: $secLogSizeMB MB" `
            -Details "STIG: Set Security log to at least 1024 MB (1 GB)" `
            -Remediation "wevtutil sl Security /ms:1073741824"
    }
} catch {
    Add-Result -Category "STIG - V-220859 (CAT II)" -Status "Error" `
        -Message "Failed to check Security log: $_"
}

# V-220860: System event log must be 32 MB or greater (CAT II)
try {
    $sysLog = Get-WinEvent -ListLog System -ErrorAction Stop
    $sysLogSizeMB = [math]::Round($sysLog.MaximumSizeInBytes / 1MB, 2)
    
    if ($sysLogSizeMB -ge 32) {
        Add-Result -Category "STIG - V-220860 (CAT II)" -Status "Pass" `
            -Message "System log size: $sysLogSizeMB MB" `
            -Details "STIG: System log capacity is adequate"
    } else {
        Add-Result -Category "STIG - V-220860 (CAT II)" -Status "Fail" `
            -Message "System log size is insufficient: $sysLogSizeMB MB" `
            -Details "STIG: Set System log to at least 32 MB" `
            -Remediation "wevtutil sl System /ms:33554432"
    }
} catch {
    Add-Result -Category "STIG - V-220860 (CAT II)" -Status "Error" `
        -Message "Failed to check System log: $_"
}

# ============================================================================
# STIG: Windows Defender Antivirus (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Windows Defender Configuration..." -ForegroundColor Yellow

# V-253268: Windows Defender AV must be enabled (CAT II)
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    
    if ($defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "STIG - V-253268 (CAT II)" -Status "Pass" `
            -Message "Windows Defender real-time protection is enabled" `
            -Details "STIG: Antivirus protection is active"
    } else {
        Add-Result -Category "STIG - V-253268 (CAT II)" -Status "Fail" `
            -Message "Windows Defender real-time protection is DISABLED" `
            -Details "STIG: Enable real-time antivirus protection immediately" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    
    # Check signature update age
    $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
    
    if ($signatureAge.Days -le 7) {
        Add-Result -Category "STIG - Defender Updates" -Status "Pass" `
            -Message "Antivirus signatures are current ($($signatureAge.Days) days old)" `
            -Details "STIG: Malware definitions are up to date"
    } else {
        Add-Result -Category "STIG - Defender Updates" -Status "Fail" `
            -Message "Antivirus signatures are outdated ($($signatureAge.Days) days old)" `
            -Details "STIG: Update antivirus signatures immediately" `
            -Remediation "Update-MpSignature"
    }
} catch {
    Add-Result -Category "STIG - V-253268 (CAT II)" -Status "Error" `
        -Message "Failed to check Windows Defender: $_"
}

# ============================================================================
# STIG: Security Options (CAT I, II, III)
# ============================================================================
Write-Host "[STIG] Checking Security Options..." -ForegroundColor Yellow

# V-220912: LAN Manager authentication level must be configured (CAT II)
try {
    $lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
    
    if ($lmLevel -and $lmLevel.LmCompatibilityLevel -ge 5) {
        Add-Result -Category "STIG - V-220912 (CAT II)" -Status "Pass" `
            -Message "LAN Manager authentication level: $($lmLevel.LmCompatibilityLevel)" `
            -Details "STIG: Only NTLMv2 authentication is accepted"
    } else {
        Add-Result -Category "STIG - V-220912 (CAT II)" -Status "Fail" `
            -Message "LAN Manager authentication level is insecure" `
            -Details "STIG: Set to 5 (Send NTLMv2 response only, refuse LM & NTLM)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
    }
} catch {
    Add-Result -Category "STIG - V-220912 (CAT II)" -Status "Error" `
        -Message "Failed to check LM authentication level: $_"
}

# V-220908: Anonymous enumeration of SAM accounts must be disabled (CAT II)
try {
    $restrictAnonymousSAM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymousSAM -and $restrictAnonymousSAM.RestrictAnonymousSAM -eq 1) {
        Add-Result -Category "STIG - V-220908 (CAT II)" -Status "Pass" `
            -Message "Anonymous SAM account enumeration is restricted" `
            -Details "STIG: Anonymous users cannot enumerate local accounts"
    } else {
        Add-Result -Category "STIG - V-220908 (CAT II)" -Status "Fail" `
            -Message "Anonymous SAM account enumeration is NOT restricted" `
            -Details "STIG: Prevent anonymous enumeration of SAM accounts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220908 (CAT II)" -Status "Error" `
        -Message "Failed to check anonymous SAM restriction: $_"
}

# V-220909: Anonymous enumeration of shares must be disabled (CAT II)
try {
    $restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymous -and $restrictAnonymous.RestrictAnonymous -eq 1) {
        Add-Result -Category "STIG - V-220909 (CAT II)" -Status "Pass" `
            -Message "Anonymous enumeration of shares is restricted" `
            -Details "STIG: Anonymous users cannot enumerate shares"
    } else {
        Add-Result -Category "STIG - V-220909 (CAT II)" -Status "Warning" `
            -Message "Anonymous share enumeration may not be fully restricted" `
            -Details "STIG: Configure to prevent anonymous share enumeration" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220909 (CAT II)" -Status "Error" `
        -Message "Failed to check anonymous share restriction: $_"
}

# V-220926: UAC must be enabled (CAT I)
try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    
    if ($uac.EnableLUA -eq 1) {
        Add-Result -Category "STIG - V-220926 (CAT I)" -Status "Pass" `
            -Message "User Account Control is enabled" `
            -Details "STIG CAT I: UAC prevents unauthorized privilege elevation"
    } else {
        Add-Result -Category "STIG - V-220926 (CAT I)" -Status "Fail" `
            -Message "User Account Control is DISABLED" `
            -Details "STIG CAT I: Enable UAC immediately - critical security control" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1; Restart-Computer"
    }
    
    # V-220927: UAC elevation prompt for administrators must be configured (CAT II)
    if ($uac.ConsentPromptBehaviorAdmin -ge 2) {
        Add-Result -Category "STIG - V-220927 (CAT II)" -Status "Pass" `
            -Message "UAC admin prompt behavior is configured properly" `
            -Details "STIG: Administrators must consent to elevation"
    } else {
        Add-Result -Category "STIG - V-220927 (CAT II)" -Status "Fail" `
            -Message "UAC admin prompt behavior is too permissive" `
            -Details "STIG: Configure UAC to prompt for consent" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2"
    }
    
    # V-220928: UAC must use secure desktop (CAT II)
    if ($uac.PromptOnSecureDesktop -eq 1) {
        Add-Result -Category "STIG - V-220928 (CAT II)" -Status "Pass" `
            -Message "UAC prompts on secure desktop" `
            -Details "STIG: Secure desktop prevents UI spoofing attacks"
    } else {
        Add-Result -Category "STIG - V-220928 (CAT II)" -Status "Fail" `
            -Message "UAC does NOT use secure desktop" `
            -Details "STIG: Enable secure desktop for UAC prompts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1"
    }
    
} catch {
    Add-Result -Category "STIG - UAC" -Status "Error" `
        -Message "Failed to check UAC configuration: $_"
}

# V-220961: WDigest authentication must be disabled (CAT II)
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Pass" `
            -Message "WDigest authentication is disabled" `
            -Details "STIG: Plaintext password storage in memory is prevented"
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Fail" `
            -Message "WDigest authentication is ENABLED" `
            -Details "STIG: Disable WDigest to prevent credential theft" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
    } else {
        Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Pass" `
            -Message "WDigest is disabled (default on Windows 8.1+)" `
            -Details "STIG: Secure default configuration"
    }
} catch {
    Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Error" `
        -Message "Failed to check WDigest: $_"
}

# ============================================================================
# STIG: Windows Firewall (CAT I)
# ============================================================================
Write-Host "[STIG] Checking Windows Firewall Configuration..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Private", "Public")

foreach ($profileName in $firewallProfiles) {
    try {
        $profile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        # V-220729, V-220730, V-220731: Firewall must be enabled (CAT I)
        $stigId = switch ($profileName) {
            "Domain"  { "V-220729" }
            "Private" { "V-220730" }
            "Public"  { "V-220731" }
        }
        
        if ($profile.Enabled) {
            Add-Result -Category "STIG - $stigId (CAT I)" -Status "Pass" `
                -Message "$profileName Firewall: Enabled" `
                -Details "STIG CAT I: Firewall provides essential network protection"
        } else {
            Add-Result -Category "STIG - $stigId (CAT I)" -Status "Fail" `
                -Message "$profileName Firewall: DISABLED" `
                -Details "STIG CAT I: Enable firewall immediately - critical control" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True"
        }
        
        # V-220732, V-220733, V-220734: Inbound connections must be blocked (CAT II)
        $stigIdInbound = switch ($profileName) {
            "Domain"  { "V-220732" }
            "Private" { "V-220733" }
            "Public"  { "V-220734" }
        }
        
        if ($profile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "STIG - $stigIdInbound (CAT II)" -Status "Pass" `
                -Message "$profileName Firewall: Default inbound is Block" `
                -Details "STIG: Default deny reduces attack surface"
        } else {
            Add-Result -Category "STIG - $stigIdInbound (CAT II)" -Status "Fail" `
                -Message "$profileName Firewall: Default inbound is Allow" `
                -Details "STIG: Set default inbound action to Block" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block"
        }
        
    } catch {
        Add-Result -Category "STIG - Firewall" -Status "Error" `
            -Message "Failed to check $profileName firewall: $_"
    }
}

# ============================================================================
# STIG: Remote Access Security (CAT I, II)
# ============================================================================
Write-Host "[STIG] Checking Remote Access Security..." -ForegroundColor Yellow

# V-220964: Remote Desktop Services must require secure RPC (CAT II)
try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "STIG - V-220964 (CAT II)" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "STIG: RDP is disabled - no remote access risk"
    } else {
        Add-Result -Category "STIG - V-220964 (CAT II)" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "STIG: Verify RDP security settings are properly configured"
        
        # V-220965: RDP must require secure RPC (CAT II)
        $secureRPC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -ErrorAction SilentlyContinue
        
        if ($secureRPC -and $secureRPC.fEncryptRPCTraffic -eq 1) {
            Add-Result -Category "STIG - V-220965 (CAT II)" -Status "Pass" `
                -Message "RDP: Secure RPC communication is required" `
                -Details "STIG: RDP RPC traffic is encrypted"
        }
        
        # V-220966: RDP must use FIPS-compliant encryption (CAT II)
        $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        
        if ($encLevel -and $encLevel.MinEncryptionLevel -ge 3) {
            Add-Result -Category "STIG - V-220966 (CAT II)" -Status "Pass" `
                -Message "RDP: Encryption level is set to High or FIPS" `
                -Details "STIG: RDP uses strong encryption"
        } else {
            Add-Result -Category "STIG - V-220966 (CAT II)" -Status "Fail" `
                -Message "RDP: Encryption level is not set to High" `
                -Details "STIG: Configure RDP to use High encryption" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
        }
        
        # V-220967: NLA must be required (CAT II)
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "STIG - V-220967 (CAT II)" -Status "Pass" `
                -Message "RDP: Network Level Authentication is required" `
                -Details "STIG: NLA provides additional authentication protection"
        } else {
            Add-Result -Category "STIG - V-220967 (CAT II)" -Status "Fail" `
                -Message "RDP: Network Level Authentication is NOT required" `
                -Details "STIG: Enable NLA for RDP" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        }
    }
} catch {
    Add-Result -Category "STIG - Remote Access" -Status "Error" `
        -Message "Failed to check RDP configuration: $_"
}

# ============================================================================
# STIG: SMB Security (CAT II)
# ============================================================================
Write-Host "[STIG] Checking SMB Security..." -ForegroundColor Yellow

# V-220968: SMBv1 must be disabled (CAT II)
try {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    
    if ($smb1Feature.State -eq "Disabled") {
        Add-Result -Category "STIG - V-220968 (CAT II)" -Status "Pass" `
            -Message "SMBv1 protocol is disabled" `
            -Details "STIG: SMBv1 has critical vulnerabilities and is disabled"
    } else {
        Add-Result -Category "STIG - V-220968 (CAT II)" -Status "Fail" `
            -Message "SMBv1 protocol is ENABLED" `
            -Details "STIG: Disable SMBv1 immediately (WannaCry vulnerability)" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    }
} catch {
    Add-Result -Category "STIG - V-220968 (CAT II)" -Status "Error" `
        -Message "Failed to check SMBv1: $_"
}

# V-220969: SMB server must perform signing (CAT II)
try {
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer) {
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "STIG - V-220969 (CAT II)" -Status "Pass" `
                -Message "SMB server signing is required" `
                -Details "STIG: SMB signing prevents tampering and relay attacks"
        } else {
            Add-Result -Category "STIG - V-220969 (CAT II)" -Status "Fail" `
                -Message "SMB server signing is NOT required" `
                -Details "STIG: Enable required SMB signing" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        }
    }
} catch {
    Add-Result -Category "STIG - V-220969 (CAT II)" -Status "Error" `
        -Message "Failed to check SMB signing: $_"
}

# V-220970: SMB client must perform signing (CAT II)
try {
    $smbClientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
    
    if ($smbClientSigning -and $smbClientSigning.RequireSecuritySignature -eq 1) {
        Add-Result -Category "STIG - V-220970 (CAT II)" -Status "Pass" `
            -Message "SMB client signing is required" `
            -Details "STIG: Client-side SMB signing is enforced"
    } else {
        Add-Result -Category "STIG - V-220970 (CAT II)" -Status "Fail" `
            -Message "SMB client signing is NOT required" `
            -Details "STIG: Enable required SMB client signing" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220970 (CAT II)" -Status "Error" `
        -Message "Failed to check SMB client signing: $_"
}

# ============================================================================
# STIG: Data Protection (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Data Protection..." -ForegroundColor Yellow

# V-220958: BitLocker must be enabled on operating system drive (CAT II)
try {
    $systemDrive = $env:SystemDrive
    $bitlocker = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
    
    if ($bitlocker) {
        if ($bitlocker.VolumeStatus -eq "FullyEncrypted") {
            Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Pass" `
                -Message "System drive is encrypted with BitLocker" `
                -Details "STIG: Data at rest is protected (Method: $($bitlocker.EncryptionMethod))"
        } elseif ($bitlocker.VolumeStatus -eq "EncryptionInProgress") {
            Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Info" `
                -Message "System drive encryption in progress: $($bitlocker.EncryptionPercentage)%" `
                -Details "STIG: Allow BitLocker encryption to complete"
        } else {
            Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Fail" `
                -Message "System drive is NOT encrypted (Status: $($bitlocker.VolumeStatus))" `
                -Details "STIG: Enable BitLocker on system drive" `
                -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -TpmProtector"
        }
    }
} catch {
    $errorMsg = $_.Exception.Message
    if ($errorMsg -like "*not supported*" -or $errorMsg -like "*requires*") {
        Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Info" `
            -Message "BitLocker not available on this edition" `
            -Details "STIG: BitLocker requires Pro/Enterprise editions"
    } else {
        Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Error" `
            -Message "Failed to check BitLocker: $_"
    }
}

# ============================================================================
# STIG: PowerShell Security (CAT II)
# ============================================================================
Write-Host "[STIG] Checking PowerShell Security..." -ForegroundColor Yellow

# V-220971: PowerShell v2 must be removed/disabled (CAT II)
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    
    if ($psv2) {
        if ($psv2.State -eq "Disabled") {
            Add-Result -Category "STIG - V-220971 (CAT II)" -Status "Pass" `
                -Message "PowerShell v2 is disabled" `
                -Details "STIG: PowerShell v2 cannot be used for downgrade attacks"
        } else {
            Add-Result -Category "STIG - V-220971 (CAT II)" -Status "Fail" `
                -Message "PowerShell v2 is ENABLED" `
                -Details "STIG: Remove PowerShell v2 to prevent security bypass" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
        }
    }
} catch {
    Add-Result -Category "STIG - V-220971 (CAT II)" -Status "Info" `
        -Message "Could not check PowerShell v2 status"
}

# V-220972: PowerShell Script Block Logging must be enabled (CAT II)
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "STIG - V-220972 (CAT II)" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "STIG: PowerShell commands are logged for security monitoring"
    } else {
        Add-Result -Category "STIG - V-220972 (CAT II)" -Status "Fail" `
            -Message "PowerShell Script Block Logging is NOT enabled" `
            -Details "STIG: Enable Script Block Logging for audit trail" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220972 (CAT II)" -Status "Error" `
        -Message "Failed to check PowerShell logging: $_"
}

# ============================================================================
# STIG: Miscellaneous Security Settings (CAT II, III)
# ============================================================================
Write-Host "[STIG] Checking Miscellaneous Security Settings..." -ForegroundColor Yellow

# V-220973: AutoPlay must be disabled (CAT II)
try {
    $autoPlay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    
    if ($autoPlay -and $autoPlay.NoDriveTypeAutoRun -eq 255) {
        Add-Result -Category "STIG - V-220973 (CAT II)" -Status "Pass" `
            -Message "AutoPlay is disabled for all drive types" `
            -Details "STIG: Prevents automatic execution from removable media"
    } else {
        Add-Result -Category "STIG - V-220973 (CAT II)" -Status "Fail" `
            -Message "AutoPlay is not fully disabled" `
            -Details "STIG: Disable AutoPlay for all drives" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255"
    }
} catch {
    Add-Result -Category "STIG - V-220973 (CAT II)" -Status "Error" `
        -Message "Failed to check AutoPlay: $_"
}

# V-220974: Autorun must be disabled (CAT II)
try {
    $noAutorun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ErrorAction SilentlyContinue
    
    if ($noAutorun -and $noAutorun.NoAutorun -eq 1) {
        Add-Result -Category "STIG - V-220974 (CAT II)" -Status "Pass" `
            -Message "Autorun is disabled" `
            -Details "STIG: Prevents autorun.inf from executing"
    } else {
        Add-Result -Category "STIG - V-220974 (CAT II)" -Status "Fail" `
            -Message "Autorun is NOT disabled" `
            -Details "STIG: Disable Autorun to prevent malware execution" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220974 (CAT II)" -Status "Error" `
        -Message "Failed to check Autorun: $_"
}

# V-220975: Enhanced anti-spoofing must be enabled (CAT III)
try {
    $antiSpoofing = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -ErrorAction SilentlyContinue
    
    if ($antiSpoofing -and $antiSpoofing.EnhancedAntiSpoofing -eq 1) {
        Add-Result -Category "STIG - V-220975 (CAT III)" -Status "Pass" `
            -Message "Enhanced anti-spoofing for facial recognition is enabled" `
            -Details "STIG: Biometric authentication has additional protection"
    } else {
        Add-Result -Category "STIG - V-220975 (CAT III)" -Status "Info" `
            -Message "Enhanced anti-spoofing not configured or not applicable" `
            -Details "STIG: Configure if using Windows Hello facial recognition"
    }
} catch {
    Add-Result -Category "STIG - V-220975 (CAT III)" -Status "Info" `
        -Message "Could not check anti-spoofing (may not be applicable)"
}

# V-220976: Camera access from lock screen must be disabled (CAT II)
try {
    $cameraLockScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -ErrorAction SilentlyContinue
    
    if ($cameraLockScreen -and $cameraLockScreen.NoLockScreenCamera -eq 1) {
        Add-Result -Category "STIG - V-220976 (CAT II)" -Status "Pass" `
            -Message "Camera is disabled on lock screen" `
            -Details "STIG: Prevents unauthorized camera access"
    } else {
        Add-Result -Category "STIG - V-220976 (CAT II)" -Status "Warning" `
            -Message "Camera may be accessible from lock screen" `
            -Details "STIG: Disable camera on lock screen" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name NoLockScreenCamera -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220976 (CAT II)" -Status "Error" `
        -Message "Failed to check lock screen camera: $_"
}

# V-220977: Toast notifications on lock screen must be disabled (CAT II)
try {
    $toastNotifications = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -ErrorAction SilentlyContinue
    
    if ($toastNotifications -and $toastNotifications.NoToastApplicationNotificationOnLockScreen -eq 1) {
        Add-Result -Category "STIG - V-220977 (CAT II)" -Status "Pass" `
            -Message "Toast notifications are disabled on lock screen" `
            -Details "STIG: Prevents information disclosure on lock screen"
    } else {
        Add-Result -Category "STIG - V-220977 (CAT II)" -Status "Warning" `
            -Message "Toast notifications may appear on lock screen" `
            -Details "STIG: Disable notifications on lock screen to prevent info disclosure" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name NoToastApplicationNotificationOnLockScreen -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220977 (CAT II)" -Status "Error" `
        -Message "Failed to check lock screen notifications: $_"
}

# V-220978: Windows Update must be configured properly (CAT II)
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($wuService) {
        if ($wuService.Status -eq "Running") {
            Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Pass" `
                -Message "Windows Update service is running" `
                -Details "STIG: System can receive security updates"
        } else {
            Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Fail" `
                -Message "Windows Update service is not running" `
                -Details "STIG: Enable Windows Update to receive patches" `
                -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic"
        }
    }
    
    # Check if automatic updates are disabled
    $noAutoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    
    if ($noAutoUpdate -and $noAutoUpdate.NoAutoUpdate -eq 1) {
        Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Fail" `
            -Message "Automatic Windows Updates are disabled" `
            -Details "STIG: Enable automatic updates for timely patching" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0"
    }
} catch {
    Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Error" `
        -Message "Failed to check Windows Update: $_"
}

# V-220979: Secure Boot must be enabled (CAT II)
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "STIG: Boot integrity is protected against bootkits and rootkits"
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Fail" `
            -Message "Secure Boot is disabled" `
            -Details "STIG: Enable Secure Boot in UEFI/BIOS firmware" `
            -Remediation "Enable Secure Boot in system firmware settings"
    } else {
        Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Info" `
            -Message "Secure Boot status cannot be determined (Legacy BIOS)" `
            -Details "STIG: UEFI with Secure Boot is required for modern systems"
    }
} catch {
    Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Info" `
        -Message "Could not determine Secure Boot status"
}

# V-220980: Virtualization-based security must be enabled (CAT II)
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        if ($deviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
            Add-Result -Category "STIG - V-220980 (CAT II)" -Status "Pass" `
                -Message "Virtualization-based security is running" `
                -Details "STIG: Hardware-based isolation provides enhanced security"
        } else {
            Add-Result -Category "STIG - V-220980 (CAT II)" -Status "Info" `
                -Message "Virtualization-based security is not running" `
                -Details "STIG: Enable VBS on compatible hardware for enhanced protection"
        }
        
        # Check Credential Guard
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "STIG - Credential Guard" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "STIG: Credentials are protected in isolated environment"
        } else {
            Add-Result -Category "STIG - Credential Guard" -Status "Info" `
                -Message "Credential Guard is not running" `
                -Details "STIG: Enable Credential Guard on compatible systems"
        }
    }
} catch {
    Add-Result -Category "STIG - V-220980 (CAT II)" -Status "Info" `
        -Message "Could not check virtualization-based security"
}

# V-220981: Insecure logons to SMB server must be disabled (CAT II)
try {
    $insecureLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
    
    if ($insecureLogon -and $insecureLogon.AllowInsecureGuestAuth -eq 0) {
        Add-Result -Category "STIG - V-220981 (CAT II)" -Status "Pass" `
            -Message "Insecure guest authentication to SMB servers is disabled" `
            -Details "STIG: Prevents insecure SMB connections"
    } else {
        Add-Result -Category "STIG - V-220981 (CAT II)" -Status "Warning" `
            -Message "Insecure guest authentication may be allowed" `
            -Details "STIG: Disable insecure guest authentication" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name AllowInsecureGuestAuth -Value 0"
    }
} catch {
    Add-Result -Category "STIG - V-220981 (CAT II)" -Status "Error" `
        -Message "Failed to check insecure SMB logon: $_"
}

# V-220982: Network selection prompts must be disabled (CAT II)
try {
    $networkPrompts = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
    
    if ($networkPrompts -and $networkPrompts.DontDisplayNetworkSelectionUI -eq 1) {
        Add-Result -Category "STIG - V-220982 (CAT II)" -Status "Pass" `
            -Message "Network selection UI is disabled on logon" `
            -Details "STIG: Prevents information disclosure at logon screen"
    } else {
        Add-Result -Category "STIG - V-220982 (CAT II)" -Status "Warning" `
            -Message "Network selection UI may appear on logon" `
            -Details "STIG: Disable network selection UI" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name DontDisplayNetworkSelectionUI -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220982 (CAT II)" -Status "Error" `
        -Message "Failed to check network selection UI: $_"
}

# ============================================================================
# STIG: Service Configuration (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Service Configuration..." -ForegroundColor Yellow

# V-220983: Xbox services must be disabled if not needed (CAT II)
$xboxServices = @("XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc")

foreach ($svcName in $xboxServices) {
    try {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        
        if ($service) {
            if ($service.StartType -eq "Disabled") {
                Add-Result -Category "STIG - V-220983 (CAT II)" -Status "Pass" `
                    -Message "Xbox service '$($service.DisplayName)' is disabled" `
                    -Details "STIG: Unnecessary service is disabled"
            } else {
                Add-Result -Category "STIG - V-220983 (CAT II)" -Status "Warning" `
                    -Message "Xbox service '$($service.DisplayName)' is not disabled" `
                    -Details "STIG: Disable Xbox services if not required" `
                    -Remediation "Set-Service -Name $svcName -StartupType Disabled"
            }
        }
    } catch {
        # Service may not exist on this system
    }
}

# ============================================================================
# STIG: Application Security (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Application Security..." -ForegroundColor Yellow

# V-220984: Microsoft consumer experiences must be turned off (CAT II)
try {
    $consumerExperiences = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
    
    if ($consumerExperiences -and $consumerExperiences.DisableWindowsConsumerFeatures -eq 1) {
        Add-Result -Category "STIG - V-220984 (CAT II)" -Status "Pass" `
            -Message "Windows consumer experiences are disabled" `
            -Details "STIG: Prevents automatic installation of suggested apps"
    } else {
        Add-Result -Category "STIG - V-220984 (CAT II)" -Status "Warning" `
            -Message "Windows consumer experiences may be enabled" `
            -Details "STIG: Disable consumer experiences in enterprise environment" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableWindowsConsumerFeatures -Value 1"
    }
} catch {
    Add-Result -Category "STIG - V-220984 (CAT II)" -Status "Error" `
        -Message "Failed to check consumer experiences: $_"
}

# ============================================================================
# STIG Summary and Categorization
# ============================================================================
$passCount = ($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = ($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = ($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

# Count by severity
$catI = ($results | Where-Object { $_.Category -like "*CAT I*" }).Count
$catII = ($results | Where-Object { $_.Category -like "*CAT II*" }).Count
$catIII = ($results | Where-Object { $_.Category -like "*CAT III*" }).Count

Write-Host "`n[STIG] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta
Write-Host "`n  STIG Categories:" -ForegroundColor Cyan
Write-Host "  CAT I (High):   $catI" -ForegroundColor Red
Write-Host "  CAT II (Medium): $catII" -ForegroundColor Yellow
Write-Host "  CAT III (Low):  $catIII" -ForegroundColor Cyan

return $results
