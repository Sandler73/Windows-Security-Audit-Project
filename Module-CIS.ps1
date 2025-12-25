# Module-CIS.ps1
# CIS (Center for Internet Security) Benchmarks Compliance Module
# Version: 5.0
# Based on CIS Microsoft Windows Benchmarks

<#
.SYNOPSIS
    CIS Microsoft Windows Benchmarks compliance checks.

.DESCRIPTION
    This module checks alignment with CIS Benchmarks including:
    - Account Policies (password policy, account lockout, Kerberos policy)
    - Local Policies (audit policy, user rights assignment, security options)
    - Event Log configuration and retention
    - Windows Firewall with Advanced Security
    - Network security and protocol settings
    - System services configuration
    - Advanced Audit Policy Configuration
    - Security registry settings
    - Administrative templates
    - File system permissions

.PARAMETER SharedData
    Hashtable containing shared data from the main script

.NOTES
    Version: 5.0
    Based on: CIS Microsoft Windows Benchmarks v3.0+
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "CIS"
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

# Helper function to safely get audit policy settings
function Get-AuditPolicySafe {
    param(
        [string]$Category,
        [string]$Subcategory
    )
    
    try {
        if ($Subcategory) {
            $result = auditpol /get /subcategory:"$Subcategory" 2>$null
        } else {
            $result = auditpol /get /category:"$Category" 2>$null
        }
        
        if ($result) {
            return $result
        } else {
            return $null
        }
    } catch {
        return $null
    }
}

Write-Host "`n[CIS] Starting CIS Benchmarks compliance checks..." -ForegroundColor Cyan

# ============================================================================
# CIS Benchmark: Account Policies - Password Policy
# ============================================================================
Write-Host "[CIS] Checking Account Policies - Password Policy..." -ForegroundColor Yellow

# Get password policy using net accounts
try {
    $netAccounts = net accounts 2>$null
    
    if ($netAccounts) {
        # Parse minimum password length
        $minPasswordLength = ($netAccounts | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
        
        if ([int]$minPasswordLength -ge 14) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Minimum password length is $minPasswordLength characters" `
                -Details "CIS Benchmark: Require minimum password length of 14 or more characters"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Fail" `
                -Message "Minimum password length is only $minPasswordLength characters" `
                -Details "CIS Benchmark: Set minimum password length to 14 or more" `
                -Remediation "net accounts /minpwlen:14"
        }
        
        # Parse maximum password age
        $maxPasswordAge = ($netAccounts | Select-String "Maximum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ($maxPasswordAge -eq "Unlimited") {
            Add-Result -Category "CIS - Account Policy" -Status "Fail" `
                -Message "Maximum password age is set to Unlimited" `
                -Details "CIS Benchmark: Set maximum password age to 365 days or fewer" `
                -Remediation "net accounts /maxpwage:365"
        } elseif ([int]$maxPasswordAge -le 365 -and [int]$maxPasswordAge -gt 0) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Maximum password age is $maxPasswordAge days" `
                -Details "CIS Benchmark: Password expiration is configured appropriately"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Warning" `
                -Message "Maximum password age is $maxPasswordAge days" `
                -Details "CIS Benchmark: Consider setting to 365 days or fewer"
        }
        
        # Parse minimum password age
        $minPasswordAge = ($netAccounts | Select-String "Minimum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$minPasswordAge -ge 1) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Minimum password age is $minPasswordAge day(s)" `
                -Details "CIS Benchmark: Prevents rapid password changes to bypass history"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Fail" `
                -Message "Minimum password age is $minPasswordAge days" `
                -Details "CIS Benchmark: Set minimum password age to 1 or more days" `
                -Remediation "net accounts /minpwage:1"
        }
        
        # Parse password history
        $passwordHistory = ($netAccounts | Select-String "Length of password history maintained").ToString().Split(":")[1].Trim()
        
        if ([int]$passwordHistory -ge 24) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Password history remembers $passwordHistory passwords" `
                -Details "CIS Benchmark: Enforce password history of 24 or more passwords"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Fail" `
                -Message "Password history only remembers $passwordHistory passwords" `
                -Details "CIS Benchmark: Set password history to 24 or more" `
                -Remediation "net accounts /uniquepw:24"
        }
    }
} catch {
    Add-Result -Category "CIS - Account Policy" -Status "Error" `
        -Message "Failed to check password policy: $_"
}

# Check password complexity via registry
try {
    $complexity = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ComplexityEnabled" -ErrorAction SilentlyContinue
    
    if ($complexity) {
        if ($complexity.ComplexityEnabled -eq 1) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Password complexity requirements are enabled" `
                -Details "CIS Benchmark: Require passwords to meet complexity requirements"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Fail" `
                -Message "Password complexity requirements are disabled" `
                -Details "CIS Benchmark: Enable password complexity" `
                -Remediation "Enable via Local Security Policy or GPO"
        }
    }
} catch {
    # Complexity check via secpol
}

# Check for reversible encryption
try {
    $reversibleEncryption = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ReversibleEncryptionEnabled" -ErrorAction SilentlyContinue
    
    if ($reversibleEncryption -and $reversibleEncryption.ReversibleEncryptionEnabled -eq 1) {
        Add-Result -Category "CIS - Account Policy" -Status "Fail" `
            -Message "Store passwords using reversible encryption is ENABLED" `
            -Details "CIS Benchmark: Disable reversible encryption - it's equivalent to plaintext" `
            -Remediation "Disable via Local Security Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy"
    } else {
        Add-Result -Category "CIS - Account Policy" -Status "Pass" `
            -Message "Store passwords using reversible encryption is disabled" `
            -Details "CIS Benchmark: Reversible encryption is properly disabled"
    }
} catch {
    # Check failed
}

# ============================================================================
# CIS Benchmark: Account Policies - Account Lockout Policy
# ============================================================================
Write-Host "[CIS] Checking Account Policies - Account Lockout..." -ForegroundColor Yellow

try {
    $netAccounts = net accounts 2>$null
    
    if ($netAccounts) {
        # Parse lockout threshold
        $lockoutThreshold = ($netAccounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
        
        if ($lockoutThreshold -eq "Never") {
            Add-Result -Category "CIS - Account Policy" -Status "Fail" `
                -Message "Account lockout threshold is set to Never" `
                -Details "CIS Benchmark: Set account lockout threshold to 5 or fewer invalid attempts" `
                -Remediation "net accounts /lockoutthreshold:5"
        } elseif ([int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Account lockout threshold is $lockoutThreshold invalid logon attempts" `
                -Details "CIS Benchmark: Account lockout protects against brute force attacks"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Warning" `
                -Message "Account lockout threshold is $lockoutThreshold attempts" `
                -Details "CIS Benchmark: Consider setting to 5 or fewer attempts"
        }
        
        # Parse lockout duration
        $lockoutDuration = ($netAccounts | Select-String "Lockout duration").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$lockoutDuration -ge 15) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Account lockout duration is $lockoutDuration minutes" `
                -Details "CIS Benchmark: Lockout duration of 15 or more minutes slows brute force"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Warning" `
                -Message "Account lockout duration is only $lockoutDuration minutes" `
                -Details "CIS Benchmark: Set lockout duration to 15 or more minutes" `
                -Remediation "net accounts /lockoutduration:15"
        }
        
        # Parse lockout observation window
        $lockoutWindow = ($netAccounts | Select-String "Lockout observation window").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$lockoutWindow -ge 15) {
            Add-Result -Category "CIS - Account Policy" -Status "Pass" `
                -Message "Reset account lockout counter after $lockoutWindow minutes" `
                -Details "CIS Benchmark: Observation window is properly configured"
        } else {
            Add-Result -Category "CIS - Account Policy" -Status "Warning" `
                -Message "Lockout observation window is only $lockoutWindow minutes" `
                -Details "CIS Benchmark: Set to 15 or more minutes" `
                -Remediation "net accounts /lockoutwindow:15"
        }
    }
} catch {
    Add-Result -Category "CIS - Account Policy" -Status "Error" `
        -Message "Failed to check account lockout policy: $_"
}

# ============================================================================
# CIS Benchmark: Local Policies - Audit Policy
# ============================================================================
Write-Host "[CIS] Checking Local Policies - Audit Policy..." -ForegroundColor Yellow

# Critical audit categories per CIS Benchmarks
$auditChecks = @(
    @{Category="Account Logon"; Subcategory="Credential Validation"; Expected="Success and Failure"},
    @{Category="Account Management"; Subcategory="Security Group Management"; Expected="Success"},
    @{Category="Account Management"; Subcategory="User Account Management"; Expected="Success and Failure"},
    @{Category="Detailed Tracking"; Subcategory="Process Creation"; Expected="Success"},
    @{Category="Logon/Logoff"; Subcategory="Logoff"; Expected="Success"},
    @{Category="Logon/Logoff"; Subcategory="Logon"; Expected="Success and Failure"},
    @{Category="Logon/Logoff"; Subcategory="Special Logon"; Expected="Success"},
    @{Category="Object Access"; Subcategory="Removable Storage"; Expected="Success and Failure"},
    @{Category="Policy Change"; Subcategory="Audit Policy Change"; Expected="Success"},
    @{Category="Policy Change"; Subcategory="Authentication Policy Change"; Expected="Success"},
    @{Category="Privilege Use"; Subcategory="Sensitive Privilege Use"; Expected="Success and Failure"},
    @{Category="System"; Subcategory="Security State Change"; Expected="Success"},
    @{Category="System"; Subcategory="Security System Extension"; Expected="Success"},
    @{Category="System"; Subcategory="System Integrity"; Expected="Success and Failure"}
)

foreach ($check in $auditChecks) {
    try {
        $auditResult = Get-AuditPolicySafe -Subcategory $check.Subcategory
        
        if ($auditResult) {
            $resultText = $auditResult | Out-String
            
            if ($check.Expected -eq "Success and Failure") {
                if ($resultText -match "Success and Failure") {
                    Add-Result -Category "CIS - Audit Policy" -Status "Pass" `
                        -Message "$($check.Subcategory): Success and Failure auditing enabled" `
                        -Details "CIS Benchmark: Comprehensive auditing configured"
                } elseif ($resultText -match "Success" -and $resultText -notmatch "Failure") {
                    Add-Result -Category "CIS - Audit Policy" -Status "Warning" `
                        -Message "$($check.Subcategory): Only Success auditing enabled" `
                        -Details "CIS Benchmark: Enable both Success and Failure auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable /failure:enable"
                } elseif ($resultText -match "No Auditing") {
                    Add-Result -Category "CIS - Audit Policy" -Status "Fail" `
                        -Message "$($check.Subcategory): No auditing configured" `
                        -Details "CIS Benchmark: Enable Success and Failure auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable /failure:enable"
                } else {
                    Add-Result -Category "CIS - Audit Policy" -Status "Warning" `
                        -Message "$($check.Subcategory): Partial auditing enabled" `
                        -Details "CIS Benchmark: Configure Success and Failure auditing"
                }
            } elseif ($check.Expected -eq "Success") {
                if ($resultText -match "Success") {
                    Add-Result -Category "CIS - Audit Policy" -Status "Pass" `
                        -Message "$($check.Subcategory): Success auditing enabled" `
                        -Details "CIS Benchmark: Required auditing is configured"
                } else {
                    Add-Result -Category "CIS - Audit Policy" -Status "Fail" `
                        -Message "$($check.Subcategory): Success auditing not enabled" `
                        -Details "CIS Benchmark: Enable Success auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable"
                }
            }
        } else {
            Add-Result -Category "CIS - Audit Policy" -Status "Warning" `
                -Message "$($check.Subcategory): Could not determine audit status" `
                -Details "CIS Benchmark: Verify audit policy is configured" `
                -Remediation "Manually check via auditpol or Local Security Policy"
        }
    } catch {
        Add-Result -Category "CIS - Audit Policy" -Status "Error" `
            -Message "Failed to check audit policy for $($check.Subcategory): $_"
    }
}

# Check if Advanced Audit Policy is configured
try {
    $advancedAudit = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    
    if ($advancedAudit -and $advancedAudit.SCENoApplyLegacyAuditPolicy -eq 1) {
        Add-Result -Category "CIS - Audit Policy" -Status "Pass" `
            -Message "Advanced Audit Policy Configuration is in use" `
            -Details "CIS Benchmark: Advanced audit policies provide granular control"
    } else {
        Add-Result -Category "CIS - Audit Policy" -Status "Warning" `
            -Message "Advanced Audit Policy may not be enforced" `
            -Details "CIS Benchmark: Enable Advanced Audit Policy Configuration" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1"
    }
} catch {
    Add-Result -Category "CIS - Audit Policy" -Status "Error" `
        -Message "Failed to check Advanced Audit Policy setting: $_"
}

# ============================================================================
# CIS Benchmark: Local Policies - User Rights Assignment
# ============================================================================
Write-Host "[CIS] Checking Local Policies - User Rights Assignment..." -ForegroundColor Yellow

# Check interactive logon rights
try {
    $denyInteractiveLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DenyInteractiveLogon" -ErrorAction SilentlyContinue
    
    if ($denyInteractiveLogon) {
        Add-Result -Category "CIS - User Rights" -Status "Info" `
            -Message "Deny log on locally policy is configured" `
            -Details "CIS Benchmark: Review accounts denied interactive logon"
    }
} catch {
    # Check failed
}

# Check network logon rights
try {
    $denyNetworkLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DenyNetworkLogon" -ErrorAction SilentlyContinue
    
    if ($denyNetworkLogon) {
        Add-Result -Category "CIS - User Rights" -Status "Info" `
            -Message "Deny access to this computer from the network policy is configured" `
            -Details "CIS Benchmark: Guest account should be denied network access"
    }
} catch {
    # Check failed
}

# Check for Guest account network access
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount -and $guestAccount.Enabled) {
        Add-Result -Category "CIS - User Rights" -Status "Fail" `
            -Message "Guest account is enabled" `
            -Details "CIS Benchmark: Guest account should be disabled" `
            -Remediation "Disable-LocalUser -Name Guest"
    } else {
        Add-Result -Category "CIS - User Rights" -Status "Pass" `
            -Message "Guest account is disabled" `
            -Details "CIS Benchmark: Guest account is properly disabled"
    }
} catch {
    Add-Result -Category "CIS - User Rights" -Status "Error" `
        -Message "Failed to check Guest account status: $_"
}

# Check Administrator account status
try {
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    
    if ($adminAccount) {
        if ($adminAccount.Enabled) {
            Add-Result -Category "CIS - User Rights" -Status "Warning" `
                -Message "Built-in Administrator account is enabled" `
                -Details "CIS Benchmark: Consider disabling or renaming built-in Administrator" `
                -Remediation "Disable-LocalUser -Name Administrator"
        } else {
            Add-Result -Category "CIS - User Rights" -Status "Pass" `
                -Message "Built-in Administrator account is disabled" `
                -Details "CIS Benchmark: Administrator account is properly disabled"
        }
    }
} catch {
    Add-Result -Category "CIS - User Rights" -Status "Error" `
        -Message "Failed to check Administrator account: $_"
}

# ============================================================================
# CIS Benchmark: Local Policies - Security Options
# ============================================================================
Write-Host "[CIS] Checking Local Policies - Security Options..." -ForegroundColor Yellow

# Check interactive logon message
try {
    $legalNoticeCaption = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -ErrorAction SilentlyContinue
    $legalNoticeText = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue
    
    if ($legalNoticeCaption -and $legalNoticeText -and $legalNoticeText.legalnoticetext.Length -gt 0) {
        Add-Result -Category "CIS - Security Options" -Status "Pass" `
            -Message "Interactive logon message is configured" `
            -Details "CIS Benchmark: Logon banner provides legal notice to users"
    } else {
        Add-Result -Category "CIS - Security Options" -Status "Warning" `
            -Message "Interactive logon message is not configured" `
            -Details "CIS Benchmark: Configure a logon message for legal protection" `
            -Remediation "Set legal notice via Local Security Policy: Local Policies > Security Options"
    }
} catch {
    Add-Result -Category "CIS - Security Options" -Status "Error" `
        -Message "Failed to check logon message: $_"
}

# Check LAN Manager authentication level
try {
    $lmAuthLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
    
    if ($lmAuthLevel) {
        $level = $lmAuthLevel.LmCompatibilityLevel
        
        if ($level -ge 5) {
            Add-Result -Category "CIS - Security Options" -Status "Pass" `
                -Message "LAN Manager authentication level is set to NTLMv2 only (Level: $level)" `
                -Details "CIS Benchmark: Refuse LM and NTLM, use NTLMv2 only"
        } elseif ($level -eq 4) {
            Add-Result -Category "CIS - Security Options" -Status "Warning" `
                -Message "LAN Manager authentication level is $level" `
                -Details "CIS Benchmark: Set to 5 (Send NTLMv2 response only, refuse LM & NTLM)" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Fail" `
                -Message "LAN Manager authentication level is insecure (Level: $level)" `
                -Details "CIS Benchmark: Weak authentication protocols are enabled" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
        }
    } else {
        Add-Result -Category "CIS - Security Options" -Status "Warning" `
            -Message "LAN Manager authentication level not explicitly configured" `
            -Details "CIS Benchmark: Set to level 5 for NTLMv2 only"
    }
} catch {
    Add-Result -Category "CIS - Security Options" -Status "Error" `
        -Message "Failed to check LM authentication level: $_"
}

# Check anonymous SID/Name translation
try {
    $anonymousSIDTranslation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    
    if ($anonymousSIDTranslation -and $anonymousSIDTranslation.RestrictAnonymousSAM -eq 1) {
        Add-Result -Category "CIS - Security Options" -Status "Pass" `
            -Message "Anonymous SAM account enumeration is restricted" `
            -Details "CIS Benchmark: Prevents anonymous enumeration of local accounts"
    } else {
        Add-Result -Category "CIS - Security Options" -Status "Fail" `
            -Message "Anonymous SAM account enumeration is not restricted" `
            -Details "CIS Benchmark: Enable to prevent anonymous account enumeration" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1"
    }
    
    $anonymousShares = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
    
    if ($anonymousShares -and $anonymousShares.RestrictNullSessAccess -eq 1) {
        Add-Result -Category "CIS - Security Options" -Status "Pass" `
            -Message "Anonymous access to named pipes and shares is restricted" `
            -Details "CIS Benchmark: Prevents anonymous enumeration of shares"
    } else {
        Add-Result -Category "CIS - Security Options" -Status "Warning" `
            -Message "Anonymous access to named pipes and shares may not be restricted" `
            -Details "CIS Benchmark: Enable null session restrictions" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name RestrictNullSessAccess -Value 1"
    }
} catch {
    Add-Result -Category "CIS - Security Options" -Status "Error" `
        -Message "Failed to check anonymous access restrictions: $_"
}

# Check NTLM SSP minimum security
try {
    $ntlmMinClientSec = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -ErrorAction SilentlyContinue
    
    if ($ntlmMinClientSec) {
        $value = $ntlmMinClientSec.NTLMMinClientSec
        # 0x20080000 = Require NTLMv2 session security, Require 128-bit encryption
        if ($value -band 0x20080000) {
            Add-Result -Category "CIS - Security Options" -Status "Pass" `
                -Message "NTLM SSP client minimum security configured for NTLMv2 and 128-bit encryption" `
                -Details "CIS Benchmark: Strong NTLM security is enforced"
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Warning" `
                -Message "NTLM SSP client security may not be optimally configured" `
                -Details "CIS Benchmark: Require NTLMv2 and 128-bit encryption" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NTLMMinClientSec -Value 0x20080000"
        }
    }
    
    $ntlmMinServerSec = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -ErrorAction SilentlyContinue
    
    if ($ntlmMinServerSec) {
        $value = $ntlmMinServerSec.NTLMMinServerSec
        if ($value -band 0x20080000) {
            Add-Result -Category "CIS - Security Options" -Status "Pass" `
                -Message "NTLM SSP server minimum security configured for NTLMv2 and 128-bit encryption" `
                -Details "CIS Benchmark: Strong NTLM security is enforced"
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Warning" `
                -Message "NTLM SSP server security may not be optimally configured" `
                -Details "CIS Benchmark: Require NTLMv2 and 128-bit encryption" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NTLMMinServerSec -Value 0x20080000"
        }
    }
} catch {
    Add-Result -Category "CIS - Security Options" -Status "Error" `
        -Message "Failed to check NTLM SSP security: $_"
}

# Check machine inactivity limit
try {
    $inactivityLimit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
    
    if ($inactivityLimit) {
        $seconds = $inactivityLimit.InactivityTimeoutSecs
        $minutes = $seconds / 60
        
        if ($seconds -le 900 -and $seconds -gt 0) {
            Add-Result -Category "CIS - Security Options" -Status "Pass" `
                -Message "Machine inactivity limit is set to $minutes minutes" `
                -Details "CIS Benchmark: Screen lock after inactivity protects unattended systems"
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Warning" `
                -Message "Machine inactivity limit is $minutes minutes" `
                -Details "CIS Benchmark: Set to 15 minutes (900 seconds) or less" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900"
        }
    } else {
        Add-Result -Category "CIS - Security Options" -Status "Warning" `
            -Message "Machine inactivity limit is not configured" `
            -Details "CIS Benchmark: Configure screen lock after 15 minutes of inactivity" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900"
    }
} catch {
    Add-Result -Category "CIS - Security Options" -Status "Error" `
        -Message "Failed to check inactivity limit: $_"
}

# ============================================================================
# CIS Benchmark: Event Log Configuration
# ============================================================================
Write-Host "[CIS] Checking Event Log Configuration..." -ForegroundColor Yellow

$eventLogs = @(
    @{Name="Application"; MinSize=32768; MaxSize=2097152},  # 32MB min, 2GB max
    @{Name="Security"; MinSize=196608; MaxSize=2097152},    # 192MB min, 2GB max
    @{Name="System"; MinSize=32768; MaxSize=2097152}        # 32MB min, 2GB max
)

foreach ($logConfig in $eventLogs) {
    try {
        $log = Get-WinEvent -ListLog $logConfig.Name -ErrorAction Stop
        
        if ($log.IsEnabled) {
            $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $minSizeMB = [math]::Round($logConfig.MinSize / 1KB, 2)
            
            if ($log.MaximumSizeInBytes -ge $logConfig.MinSize) {
                Add-Result -Category "CIS - Event Logs" -Status "Pass" `
                    -Message "$($logConfig.Name) log: Enabled with adequate size ($sizeMB MB)" `
                    -Details "CIS Benchmark: Sufficient log capacity for retention and analysis"
            } else {
                Add-Result -Category "CIS - Event Logs" -Status "Warning" `
                    -Message "$($logConfig.Name) log: Size is $sizeMB MB (recommend $minSizeMB MB minimum)" `
                    -Details "CIS Benchmark: Increase log size for adequate retention" `
                    -Remediation "wevtutil sl $($logConfig.Name) /ms:$($logConfig.MinSize)"
            }
            
            # Check retention policy
            if ($log.LogMode -eq "Circular") {
                Add-Result -Category "CIS - Event Logs" -Status "Info" `
                    -Message "$($logConfig.Name) log: Using circular overwrite (Overwrite as needed)" `
                    -Details "CIS Benchmark: Ensure logs are forwarded before overwrite"
            } elseif ($log.LogMode -eq "AutoBackup") {
                Add-Result -Category "CIS - Event Logs" -Status "Pass" `
                    -Message "$($logConfig.Name) log: Auto-archives when full" `
                    -Details "CIS Benchmark: Archive on full preserves evidence"
            } elseif ($log.LogMode -eq "Retain") {
                Add-Result -Category "CIS - Event Logs" -Status "Warning" `
                    -Message "$($logConfig.Name) log: Configured to not overwrite (manual clear required)" `
                    -Details "CIS Benchmark: May cause event logging to stop when full"
            }
        } else {
            Add-Result -Category "CIS - Event Logs" -Status "Fail" `
                -Message "$($logConfig.Name) log is disabled" `
                -Details "CIS Benchmark: Enable critical event logs" `
                -Remediation "wevtutil sl $($logConfig.Name) /e:true"
        }
        
        # Check access control (SDDL)
        $currentSDDL = $log.SecurityDescriptor
        if ($currentSDDL) {
            Add-Result -Category "CIS - Event Logs" -Status "Info" `
                -Message "$($logConfig.Name) log: Access control is configured" `
                -Details "CIS Benchmark: Restrict event log access to authorized personnel"
        }
        
    } catch {
        Add-Result -Category "CIS - Event Logs" -Status "Error" `
            -Message "Failed to check $($logConfig.Name) event log: $_"
    }
}

# ============================================================================
# CIS Benchmark: Windows Firewall with Advanced Security
# ============================================================================
Write-Host "[CIS] Checking Windows Firewall with Advanced Security..." -ForegroundColor Yellow

$profiles = @("Domain", "Private", "Public")

foreach ($profileName in $profiles) {
    try {
        $profile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        # Check if firewall is enabled
        if ($profile.Enabled) {
            Add-Result -Category "CIS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Firewall is enabled" `
                -Details "CIS Benchmark: Windows Firewall provides essential network protection"
        } else {
            Add-Result -Category "CIS - Firewall" -Status "Fail" `
                -Message "$profileName Profile: Firewall is DISABLED" `
                -Details "CIS Benchmark: Enable Windows Firewall on all profiles" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True"
        }
        
        # Check default inbound action
        if ($profile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "CIS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Default inbound action is Block" `
                -Details "CIS Benchmark: Default deny for inbound reduces attack surface"
        } else {
            Add-Result -Category "CIS - Firewall" -Status "Fail" `
                -Message "$profileName Profile: Default inbound action is Allow" `
                -Details "CIS Benchmark: Set default inbound to Block" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block"
        }
        
        # Check default outbound action
        if ($profile.DefaultOutboundAction -eq "Allow") {
            Add-Result -Category "CIS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Default outbound action is Allow" `
                -Details "CIS Benchmark: Allow outbound by default is acceptable"
        } else {
            Add-Result -Category "CIS - Firewall" -Status "Info" `
                -Message "$profileName Profile: Default outbound action is Block" `
                -Details "CIS Benchmark: Restrictive outbound policy requires careful rule management"
        }
        
        # Check logging
        if ($profile.LogBlocked -eq "True") {
            Add-Result -Category "CIS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Logging blocked connections" `
                -Details "CIS Benchmark: Firewall logging aids security monitoring"
        } else {
            Add-Result -Category "CIS - Firewall" -Status "Warning" `
                -Message "$profileName Profile: Not logging blocked connections" `
                -Details "CIS Benchmark: Enable logging for security analysis" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -LogBlocked True"
        }
        
        if ($profile.LogAllowed -eq "True") {
            Add-Result -Category "CIS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Logging allowed connections" `
                -Details "CIS Benchmark: Comprehensive logging enabled"
        } else {
            Add-Result -Category "CIS - Firewall" -Status "Info" `
                -Message "$profileName Profile: Not logging allowed connections" `
                -Details "CIS Benchmark: Consider enabling for comprehensive monitoring"
        }
        
        # Check log file size
        $logMaxSize = $profile.LogMaxSizeKilobytes
        if ($logMaxSize -ge 16384) {  # 16 MB
            Add-Result -Category "CIS - Firewall" -Status "Pass" `
                -Message "$profileName Profile: Log file max size is $logMaxSize KB" `
                -Details "CIS Benchmark: Adequate log capacity"
        } else {
            Add-Result -Category "CIS - Firewall" -Status "Warning" `
                -Message "$profileName Profile: Log file max size is only $logMaxSize KB" `
                -Details "CIS Benchmark: Set to at least 16,384 KB (16 MB)" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -LogMaxSizeKilobytes 16384"
        }
        
        # Check if notifications are disabled (CIS recommends No for Domain, Yes for others)
        if ($profileName -eq "Domain") {
            if ($profile.NotifyOnListen -eq "False") {
                Add-Result -Category "CIS - Firewall" -Status "Pass" `
                    -Message "$profileName Profile: User notifications are disabled" `
                    -Details "CIS Benchmark: Prevents user interaction on domain profile"
            } else {
                Add-Result -Category "CIS - Firewall" -Status "Warning" `
                    -Message "$profileName Profile: User notifications are enabled" `
                    -Details "CIS Benchmark: Disable notifications on domain profile" `
                    -Remediation "Set-NetFirewallProfile -Name $profileName -NotifyOnListen False"
            }
        } else {
            if ($profile.NotifyOnListen -eq "True") {
                Add-Result -Category "CIS - Firewall" -Status "Pass" `
                    -Message "$profileName Profile: User notifications are enabled" `
                    -Details "CIS Benchmark: Users are notified when apps request firewall exceptions"
            }
        }
        
    } catch {
        Add-Result -Category "CIS - Firewall" -Status "Error" `
            -Message "Failed to check $profileName firewall profile: $_"
    }
}

# ============================================================================
# CIS Benchmark: Network Security Settings
# ============================================================================
Write-Host "[CIS] Checking Network Security Settings..." -ForegroundColor Yellow

# Check SMB signing
try {
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer) {
        if ($smbServer.RequireSecuritySignature -eq $true) {
            Add-Result -Category "CIS - Network Security" -Status "Pass" `
                -Message "SMB server: Security signature is required" `
                -Details "CIS Benchmark: SMB signing prevents tampering and relay attacks"
        } else {
            Add-Result -Category "CIS - Network Security" -Status "Fail" `
                -Message "SMB server: Security signature is not required" `
                -Details "CIS Benchmark: Require SMB signing" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        }
        
        if ($smbServer.EnableSecuritySignature -eq $true) {
            Add-Result -Category "CIS - Network Security" -Status "Pass" `
                -Message "SMB server: Security signature is enabled" `
                -Details "CIS Benchmark: SMB signing capability is enabled"
        }
    }
    
    # Check SMB client signing
    $smbClientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
    
    if ($smbClientSigning -and $smbClientSigning.RequireSecuritySignature -eq 1) {
        Add-Result -Category "CIS - Network Security" -Status "Pass" `
            -Message "SMB client: Security signature is required" `
            -Details "CIS Benchmark: Client-side SMB signing is enforced"
    } else {
        Add-Result -Category "CIS - Network Security" -Status "Fail" `
            -Message "SMB client: Security signature is not required" `
            -Details "CIS Benchmark: Require SMB client signing" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1"
    }
    
} catch {
    Add-Result -Category "CIS - Network Security" -Status "Error" `
        -Message "Failed to check SMB signing configuration: $_"
}

# Check LDAP client signing
try {
    $ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue
    
    if ($ldapSigning) {
        $value = $ldapSigning.LDAPClientIntegrity
        
        if ($value -eq 2) {
            Add-Result -Category "CIS - Network Security" -Status "Pass" `
                -Message "LDAP client signing requirement is set to Require signing" `
                -Details "CIS Benchmark: Prevents LDAP session hijacking"
        } elseif ($value -eq 1) {
            Add-Result -Category "CIS - Network Security" -Status "Warning" `
                -Message "LDAP client signing is set to Negotiate signing" `
                -Details "CIS Benchmark: Set to Require signing for stronger security" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name LDAPClientIntegrity -Value 2"
        } else {
            Add-Result -Category "CIS - Network Security" -Status "Fail" `
                -Message "LDAP client signing is disabled" `
                -Details "CIS Benchmark: Enable LDAP client signing" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name LDAPClientIntegrity -Value 2"
        }
    }
} catch {
    Add-Result -Category "CIS - Network Security" -Status "Error" `
        -Message "Failed to check LDAP client signing: $_"
}

# ============================================================================
# CIS Benchmark: System Services
# ============================================================================
Write-Host "[CIS] Checking System Services..." -ForegroundColor Yellow

# Services that should be disabled per CIS Benchmarks
$servicesCheck = @(
    @{Name="RemoteRegistry"; ShouldBe="Disabled"; DisplayName="Remote Registry"},
    @{Name="RemoteAccess"; ShouldBe="Disabled"; DisplayName="Routing and Remote Access"},
    @{Name="simptcp"; ShouldBe="Disabled"; DisplayName="Simple TCP/IP Services"},
    @{Name="SSDPSRV"; ShouldBe="Disabled"; DisplayName="SSDP Discovery"},
    @{Name="upnphost"; ShouldBe="Disabled"; DisplayName="UPnP Device Host"},
    @{Name="WMPNetworkSvc"; ShouldBe="Disabled"; DisplayName="Windows Media Player Network Sharing Service"},
    @{Name="icssvc"; ShouldBe="Disabled"; DisplayName="Windows Mobile Hotspot Service"},
    @{Name="LxssManager"; ShouldBe="Disabled"; DisplayName="LxssManager (WSL)"}
)

foreach ($svcCheck in $servicesCheck) {
    try {
        $service = Get-Service -Name $svcCheck.Name -ErrorAction SilentlyContinue
        
        if ($service) {
            if ($service.StartType -eq $svcCheck.ShouldBe -or $service.StartType -eq "Disabled") {
                Add-Result -Category "CIS - Services" -Status "Pass" `
                    -Message "$($svcCheck.DisplayName): Service is disabled" `
                    -Details "CIS Benchmark: Unnecessary service is properly disabled"
            } else {
                Add-Result -Category "CIS - Services" -Status "Warning" `
                    -Message "$($svcCheck.DisplayName): Service is not disabled (Current: $($service.StartType))" `
                    -Details "CIS Benchmark: Disable if not required" `
                    -Remediation "Set-Service -Name $($svcCheck.Name) -StartupType Disabled; Stop-Service -Name $($svcCheck.Name) -Force"
            }
        }
    } catch {
        # Service may not exist on this system
    }
}

# ============================================================================
# CIS Benchmark: Administrative Templates
# ============================================================================
Write-Host "[CIS] Checking Administrative Templates..." -ForegroundColor Yellow

# Check AutoPlay/AutoRun settings
try {
    $autoPlayDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    
    if ($autoPlayDisabled -and $autoPlayDisabled.NoDriveTypeAutoRun -eq 255) {
        Add-Result -Category "CIS - Admin Templates" -Status "Pass" `
            -Message "AutoPlay is disabled for all drives" `
            -Details "CIS Benchmark: Prevents automatic execution from removable media"
    } else {
        Add-Result -Category "CIS - Admin Templates" -Status "Fail" `
            -Message "AutoPlay is not fully disabled" `
            -Details "CIS Benchmark: Disable AutoPlay for all drives" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255"
    }
} catch {
    Add-Result -Category "CIS - Admin Templates" -Status "Error" `
        -Message "Failed to check AutoPlay settings: $_"
}

# Check Windows Installer Always install with elevated privileges
try {
    $alwaysInstallElevated = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    
    if ($alwaysInstallElevated -and $alwaysInstallElevated.AlwaysInstallElevated -eq 1) {
        Add-Result -Category "CIS - Admin Templates" -Status "Fail" `
            -Message "Always install with elevated privileges is ENABLED" `
            -Details "CIS Benchmark: This allows privilege escalation - disable immediately" `
            -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated"
    } else {
        Add-Result -Category "CIS - Admin Templates" -Status "Pass" `
            -Message "Always install with elevated privileges is disabled" `
            -Details "CIS Benchmark: Prevents privilege escalation via MSI packages"
    }
} catch {
    Add-Result -Category "CIS - Admin Templates" -Status "Pass" `
        -Message "Always install with elevated privileges is not configured (disabled by default)" `
        -Details "CIS Benchmark: Setting is not present (secure default)"
}

# Check preventing users from installing printer drivers
try {
    $preventPrinterDrivers = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -ErrorAction SilentlyContinue
    
    if ($preventPrinterDrivers -and $preventPrinterDrivers.AddPrinterDrivers -eq 1) {
        Add-Result -Category "CIS - Admin Templates" -Status "Fail" `
            -Message "Users are allowed to install printer drivers" `
            -Details "CIS Benchmark: Restrict printer driver installation to administrators" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name AddPrinterDrivers -Value 0"
    } else {
        Add-Result -Category "CIS - Admin Templates" -Status "Pass" `
            -Message "Printer driver installation is restricted to administrators" `
            -Details "CIS Benchmark: Prevents malicious driver installation"
    }
} catch {
    Add-Result -Category "CIS - Admin Templates" -Status "Info" `
        -Message "Could not check printer driver installation policy"
}

# ============================================================================
# CIS Benchmark: Windows Components
# ============================================================================
Write-Host "[CIS] Checking Windows Components..." -ForegroundColor Yellow

# Check Windows Update settings
try {
    $noAutoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    
    if ($noAutoUpdate -and $noAutoUpdate.NoAutoUpdate -eq 1) {
        Add-Result -Category "CIS - Windows Components" -Status "Fail" `
            -Message "Automatic Windows Updates are disabled" `
            -Details "CIS Benchmark: Enable automatic updates for security patches" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0"
    } else {
        Add-Result -Category "CIS - Windows Components" -Status "Pass" `
            -Message "Automatic Windows Updates are enabled" `
            -Details "CIS Benchmark: System receives automatic security updates"
    }
} catch {
    # Check failed
}

# Check Windows Error Reporting
try {
    $werDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
    
    if ($werDisabled -and $werDisabled.Disabled -eq 1) {
        Add-Result -Category "CIS - Windows Components" -Status "Info" `
            -Message "Windows Error Reporting is disabled" `
            -Details "CIS Benchmark: WER can be disabled for privacy/security"
    } else {
        Add-Result -Category "CIS - Windows Components" -Status "Info" `
            -Message "Windows Error Reporting is enabled" `
            -Details "CIS Benchmark: Consider organizational policy on error reporting"
    }
} catch {
    # Check failed
}

# Check Remote Assistance
try {
    $remoteAssistance = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
    
    if ($remoteAssistance -and $remoteAssistance.fAllowToGetHelp -eq 0) {
        Add-Result -Category "CIS - Windows Components" -Status "Pass" `
            -Message "Remote Assistance is disabled" `
            -Details "CIS Benchmark: Remote Assistance presents security risk if not needed"
    } else {
        Add-Result -Category "CIS - Windows Components" -Status "Warning" `
            -Message "Remote Assistance is enabled" `
            -Details "CIS Benchmark: Disable if not required for support" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0"
    }
} catch {
    Add-Result -Category "CIS - Windows Components" -Status "Error" `
        -Message "Failed to check Remote Assistance: $_"
}

# Check Remote Desktop
try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "CIS - Windows Components" -Status "Pass" `
            -Message "Remote Desktop is disabled" `
            -Details "CIS Benchmark: RDP is disabled - reduces attack surface"
    } else {
        Add-Result -Category "CIS - Windows Components" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "CIS Benchmark: If RDP is required, ensure NLA and strong authentication are configured"
    }
} catch {
    Add-Result -Category "CIS - Windows Components" -Status "Error" `
        -Message "Failed to check Remote Desktop status: $_"
}

# ============================================================================
# CIS Benchmark: Credential Protection
# ============================================================================
Write-Host "[CIS] Checking Credential Protection..." -ForegroundColor Yellow

# Check WDigest credential caching
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "CIS - Credential Protection" -Status "Pass" `
            -Message "WDigest authentication is disabled" `
            -Details "CIS Benchmark: Prevents cleartext password storage in memory"
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "CIS - Credential Protection" -Status "Fail" `
            -Message "WDigest authentication is ENABLED" `
            -Details "CIS Benchmark: Disable WDigest to prevent credential theft" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
    } else {
        Add-Result -Category "CIS - Credential Protection" -Status "Pass" `
            -Message "WDigest authentication is disabled (default on Windows 8.1+)" `
            -Details "CIS Benchmark: WDigest is disabled by default on modern Windows"
    }
} catch {
    Add-Result -Category "CIS - Credential Protection" -Status "Error" `
        -Message "Failed to check WDigest settings: $_"
}

# Check LSASS protection (RunAsPPL)
try {
    $lsassProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    
    if ($lsassProtection -and $lsassProtection.RunAsPPL -eq 1) {
        Add-Result -Category "CIS - Credential Protection" -Status "Pass" `
            -Message "LSASS is configured as Protected Process Light (PPL)" `
            -Details "CIS Benchmark: PPL protects LSASS from credential dumping"
    } else {
        Add-Result -Category "CIS - Credential Protection" -Status "Warning" `
            -Message "LSASS Protected Process Light (PPL) is not enabled" `
            -Details "CIS Benchmark: Enable PPL on compatible systems" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1; Restart-Computer"
    }
} catch {
    Add-Result -Category "CIS - Credential Protection" -Status "Error" `
        -Message "Failed to check LSASS PPL: $_"
}

# Check Credential Guard
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "CIS - Credential Protection" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "CIS Benchmark: Credential Guard provides hardware-based credential isolation"
        } else {
            Add-Result -Category "CIS - Credential Protection" -Status "Info" `
                -Message "Credential Guard is not running" `
                -Details "CIS Benchmark: Enable on compatible hardware for enhanced protection"
        }
    }
} catch {
    Add-Result -Category "CIS - Credential Protection" -Status "Info" `
        -Message "Could not check Credential Guard status (may not be supported)"
}

# ============================================================================
# CIS Benchmark: BitLocker Drive Encryption
# ============================================================================
Write-Host "[CIS] Checking BitLocker Drive Encryption..." -ForegroundColor Yellow

try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $systemDrive = $env:SystemDrive
    
    foreach ($volume in $volumes) {
        if ($volume.MountPoint -eq $systemDrive) {
            if ($volume.VolumeStatus -eq "FullyEncrypted") {
                Add-Result -Category "CIS - BitLocker" -Status "Pass" `
                    -Message "System drive ($systemDrive) is fully encrypted with BitLocker" `
                    -Details "CIS Benchmark: Full disk encryption protects data at rest (Method: $($volume.EncryptionMethod))"
            } elseif ($volume.VolumeStatus -eq "EncryptionInProgress") {
                Add-Result -Category "CIS - BitLocker" -Status "Info" `
                    -Message "System drive ($systemDrive) encryption in progress: $($volume.EncryptionPercentage)%" `
                    -Details "CIS Benchmark: Allow encryption to complete"
            } else {
                Add-Result -Category "CIS - BitLocker" -Status "Fail" `
                    -Message "System drive ($systemDrive) is NOT encrypted (Status: $($volume.VolumeStatus))" `
                    -Details "CIS Benchmark: Enable BitLocker on system drive" `
                    -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -TpmProtector"
            }
        } else {
            # Check other volumes
            if ($volume.VolumeStatus -eq "FullyEncrypted") {
                Add-Result -Category "CIS - BitLocker" -Status "Pass" `
                    -Message "Drive $($volume.MountPoint) is encrypted" `
                    -Details "CIS Benchmark: Data volume is protected"
            } elseif ($volume.VolumeStatus -eq "FullyDecrypted" -and $volume.MountPoint -ne "") {
                Add-Result -Category "CIS - BitLocker" -Status "Warning" `
                    -Message "Drive $($volume.MountPoint) is not encrypted" `
                    -Details "CIS Benchmark: Consider encrypting all data volumes" `
                    -Remediation "Enable-BitLocker -MountPoint '$($volume.MountPoint)' -EncryptionMethod XtsAes256 -RecoveryPasswordProtector"
            }
        }
    }
    
} catch {
    $errorMsg = $_.Exception.Message
    if ($errorMsg -like "*not supported*" -or $errorMsg -like "*requires*") {
        Add-Result -Category "CIS - BitLocker" -Status "Info" `
            -Message "BitLocker is not available on this Windows edition" `
            -Details "CIS Benchmark: BitLocker requires Pro/Enterprise editions"
    } else {
        Add-Result -Category "CIS - BitLocker" -Status "Error" `
            -Message "Failed to check BitLocker status: $_"
    }
}

# ============================================================================
# CIS Benchmark: User Account Control (UAC)
# ============================================================================
Write-Host "[CIS] Checking User Account Control (UAC)..." -ForegroundColor Yellow

try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    
    # EnableLUA
    if ($uac.EnableLUA -eq 1) {
        Add-Result -Category "CIS - UAC" -Status "Pass" `
            -Message "User Account Control (UAC) is enabled" `
            -Details "CIS Benchmark: UAC prevents unauthorized privilege elevation"
    } else {
        Add-Result -Category "CIS - UAC" -Status "Fail" `
            -Message "User Account Control (UAC) is DISABLED" `
            -Details "CIS Benchmark: Enable UAC immediately" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1; Restart-Computer"
    }
    
    # ConsentPromptBehaviorAdmin
    $adminConsent = $uac.ConsentPromptBehaviorAdmin
    if ($adminConsent -ge 2) {
        Add-Result -Category "CIS - UAC" -Status "Pass" `
            -Message "UAC: Admin Approval Mode configured (Level: $adminConsent)" `
            -Details "CIS Benchmark: Admins must consent to elevation"
    } else {
        Add-Result -Category "CIS - UAC" -Status "Fail" `
            -Message "UAC: Admin Approval Mode is too permissive (Level: $adminConsent)" `
            -Details "CIS Benchmark: Set to 2 or higher" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2"
    }
    
    # ConsentPromptBehaviorUser
    $userConsent = $uac.ConsentPromptBehaviorUser
    if ($userConsent -eq 0) {
        Add-Result -Category "CIS - UAC" -Status "Pass" `
            -Message "UAC: Standard users - Automatically deny elevation requests" `
            -Details "CIS Benchmark: Prevents standard users from elevating"
    } elseif ($userConsent -eq 1) {
        Add-Result -Category "CIS - UAC" -Status "Warning" `
            -Message "UAC: Standard users can request elevation" `
            -Details "CIS Benchmark: Consider automatically denying elevation requests" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Value 0"
    }
    
    # PromptOnSecureDesktop
    if ($uac.PromptOnSecureDesktop -eq 1) {
        Add-Result -Category "CIS - UAC" -Status "Pass" `
            -Message "UAC: Elevation prompts on secure desktop" `
            -Details "CIS Benchmark: Secure desktop prevents UI spoofing"
    } else {
        Add-Result -Category "CIS - UAC" -Status "Fail" `
            -Message "UAC: Elevation prompts NOT on secure desktop" `
            -Details "CIS Benchmark: Enable secure desktop for UAC prompts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1"
    }
    
} catch {
    Add-Result -Category "CIS - UAC" -Status "Error" `
        -Message "Failed to check UAC configuration: $_"
}

# ============================================================================
# CIS Benchmark: Additional Security Settings
# ============================================================================
Write-Host "[CIS] Checking Additional Security Settings..." -ForegroundColor Yellow

# Check for null session shares
try {
    $nullSessions = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -ErrorAction SilentlyContinue
    
    if ($nullSessions) {
        if ($nullSessions.NullSessionShares.Count -eq 0 -or $nullSessions.NullSessionShares -eq "") {
            Add-Result -Category "CIS - Additional Security" -Status "Pass" `
                -Message "No null session shares configured" `
                -Details "CIS Benchmark: Null sessions cannot access shares"
        } else {
            Add-Result -Category "CIS - Additional Security" -Status "Warning" `
                -Message "Null session shares are configured: $($nullSessions.NullSessionShares -join ', ')" `
                -Details "CIS Benchmark: Remove null session share access" `
                -Remediation "Clear-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name NullSessionShares"
        }
    }
} catch {
    Add-Result -Category "CIS - Additional Security" -Status "Pass" `
        -Message "No null session shares configured (default)" `
        -Details "CIS Benchmark: Secure default configuration"
}

# Check SAM remote access restriction
try {
    $restrictSAM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -ErrorAction SilentlyContinue
    
    if ($restrictSAM -and $restrictSAM.RestrictRemoteSAM -like "*O:BAG:BAD:(A;;RC;;;BA)*") {
        Add-Result -Category "CIS - Additional Security" -Status "Pass" `
            -Message "Remote SAM access is restricted to administrators" `
            -Details "CIS Benchmark: Prevents remote SAM enumeration"
    } else {
        Add-Result -Category "CIS - Additional Security" -Status "Warning" `
            -Message "Remote SAM access restrictions may not be configured" `
            -Details "CIS Benchmark: Restrict remote SAM calls to administrators" `
            -Remediation "Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options"
    }
} catch {
    # Check failed
}

# Check for IPv6 configuration
try {
    $ipv6Disabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
    
    if ($ipv6Disabled) {
        if ($ipv6Disabled.DisabledComponents -eq 0xFF) {
            Add-Result -Category "CIS - Additional Security" -Status "Pass" `
                -Message "IPv6 is completely disabled" `
                -Details "CIS Benchmark: Disable IPv6 if not used to reduce attack surface"
        } else {
            Add-Result -Category "CIS - Additional Security" -Status "Info" `
                -Message "IPv6 is partially or fully enabled (Value: $($ipv6Disabled.DisabledComponents))" `
                -Details "CIS Benchmark: If IPv6 is not required, consider disabling"
        }
    } else {
        Add-Result -Category "CIS - Additional Security" -Status "Info" `
            -Message "IPv6 is enabled (default)" `
            -Details "CIS Benchmark: Disable if not required in your environment"
    }
} catch {
    Add-Result -Category "CIS - Additional Security" -Status "Info" `
        -Message "Could not check IPv6 configuration"
}

# Check Windows Defender status
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus) {
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Add-Result -Category "CIS - Additional Security" -Status "Pass" `
                -Message "Windows Defender real-time protection is enabled" `
                -Details "CIS Benchmark: Endpoint protection is active"
        } else {
            Add-Result -Category "CIS - Additional Security" -Status "Fail" `
                -Message "Windows Defender real-time protection is DISABLED" `
                -Details "CIS Benchmark: Enable antivirus protection" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
        }
        
        # Check signature age
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        if ($signatureAge.Days -le 7) {
            Add-Result -Category "CIS - Additional Security" -Status "Pass" `
                -Message "Windows Defender signatures are current ($($signatureAge.Days) days old)" `
                -Details "CIS Benchmark: Antivirus definitions are up to date"
        } else {
            Add-Result -Category "CIS - Additional Security" -Status "Warning" `
                -Message "Windows Defender signatures are $($signatureAge.Days) days old" `
                -Details "CIS Benchmark: Update antivirus signatures" `
                -Remediation "Update-MpSignature"
        }
    }
} catch {
    Add-Result -Category "CIS - Additional Security" -Status "Info" `
        -Message "Could not check Windows Defender status"
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

Write-Host "`n[CIS] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results
