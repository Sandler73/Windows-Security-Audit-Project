# Module-STIG.ps1
# DISA STIG (Security Technical Implementation Guide) Compliance Module for Windows Security Audit
# Version: 6.0
#
# Evaluates Windows configuration against DISA Windows 10/11 STIG and
# Windows Server STIG with CAT I/II/III severity mapping and cross-framework references.

<#
.SYNOPSIS
    DISA STIG compliance checks for Windows systems.

.DESCRIPTION
    This module checks alignment with DISA STIGs including:
    - Account and password policies (V-220902 through V-220912)
    - User rights assignments (V-220955 through V-220971)
    - Audit policies and event logging (V-220748 through V-220780)
    - Security options and registry hardening (V-220929 through V-220945)
    - Windows Firewall configuration (V-220814 through V-220828)
    - Remote access and RDP security (V-220940 through V-220950)
    - SMB protocol security (V-220830 through V-220845)
    - Data protection and encryption (V-220920 through V-220928)
    - PowerShell security configuration
    - Service and application hardening
    - Credential protection and LSA hardening
    - TLS/SSL protocol enforcement
    - Hardware security (Secure Boot, VBS, UEFI)

    Each finding includes STIG severity category mapping:
      CAT I   = Critical/High (immediate risk)
      CAT II  = Medium/High (significant risk)
      CAT III = Low (minor risk)

    CrossReferences map to NIST SP 800-53, CIS Benchmarks, NSA guidance, and CISA directives.

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName, OSVersion, IsAdmin, Cache (SharedDataCache)

.NOTES
    Requires: PowerShell 5.1+, Administrator privileges for complete results
    Dependencies: audit-common.ps1 (optional, for caching)
    References: DISA Windows 10 STIG V2R8, Windows 11 STIG V1R6,
                Windows Server 2019 STIG V2R8, Windows Server 2022 STIG V1R5
    Version: 6.0

.EXAMPLE
    $results = & .\modules\module-stig.ps1 -SharedData $sharedData
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "STIG"
$moduleVersion = "6.0"
$results = @()

# ---------------------------------------------------------------------------
# Enhanced result helper with Severity and CrossReferences
# ---------------------------------------------------------------------------
function Add-Result {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Message,
        [string]$Details     = "",
        [string]$Remediation = "",
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
        $regItem = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($regItem) { return $regItem.$Name }
    } catch { }
    return $Default
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
                -Details "STIG: Passwords must be at least 14 characters to resist brute force" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220718 (CAT II)" -Status "Fail" `
                -Message "Minimum password length is insufficient: $minLength characters" `
                -Details "STIG: Set minimum password length to 14 or more characters" `
                -Remediation "net accounts /minpwlen:14" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220726: Password history must remember 24 passwords (CAT II)
        $history = ($netAccounts | Select-String "Length of password history maintained").ToString().Split(":")[1].Trim()
        
        if ([int]$history -ge 24) {
            Add-Result -Category "STIG - V-220726 (CAT II)" -Status "Pass" `
                -Message "Password history: $history passwords remembered" `
                -Details "STIG: Prevents password reuse for 24 generations" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220726 (CAT II)" -Status "Fail" `
                -Message "Password history is insufficient: $history passwords" `
                -Details "STIG: Configure password history to remember 24 or more passwords" `
                -Remediation "net accounts /uniquepw:24" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220724: Minimum password age must be 1 day (CAT II)
        $minAge = ($netAccounts | Select-String "Minimum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$minAge -ge 1) {
            Add-Result -Category "STIG - V-220724 (CAT II)" -Status "Pass" `
                -Message "Minimum password age: $minAge day(s)" `
                -Details "STIG: Prevents rapid password cycling to bypass history" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220724 (CAT II)" -Status "Fail" `
                -Message "Minimum password age: $minAge days" `
                -Details "STIG: Set minimum password age to 1 or more days" `
                -Remediation "net accounts /minpwage:1" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220725: Maximum password age must be 60 days or less (CAT II)
        $maxAge = ($netAccounts | Select-String "Maximum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ($maxAge -eq "Unlimited") {
            Add-Result -Category "STIG - V-220725 (CAT II)" -Status "Fail" `
                -Message "Maximum password age is Unlimited" `
                -Details "STIG: Configure password expiration to 60 days or less" `
                -Remediation "net accounts /maxpwage:60" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } elseif ([int]$maxAge -le 60) {
            Add-Result -Category "STIG - V-220725 (CAT II)" -Status "Pass" `
                -Message "Maximum password age: $maxAge days" `
                -Details "STIG: Password expiration meets requirement" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220725 (CAT II)" -Status "Fail" `
                -Message "Maximum password age is too long: $maxAge days" `
                -Details "STIG: Set maximum password age to 60 days or less" `
                -Remediation "net accounts /maxpwage:60" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220719: Account lockout threshold must be 3 or less (CAT II)
        $lockoutThreshold = ($netAccounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
        
        if ($lockoutThreshold -eq "Never") {
            Add-Result -Category "STIG - V-220719 (CAT II)" -Status "Fail" `
                -Message "Account lockout is disabled" `
                -Details "STIG: Configure account lockout after 3 or fewer invalid attempts" `
                -Remediation "net accounts /lockoutthreshold:3" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } elseif ([int]$lockoutThreshold -le 3 -and [int]$lockoutThreshold -gt 0) {
            Add-Result -Category "STIG - V-220719 (CAT II)" -Status "Pass" `
                -Message "Account lockout threshold: $lockoutThreshold attempts" `
                -Details "STIG: Account lockout protects against brute force attacks" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220719 (CAT II)" -Status "Fail" `
                -Message "Account lockout threshold is too high: $lockoutThreshold" `
                -Details "STIG: Set lockout threshold to 3 or fewer attempts" `
                -Remediation "net accounts /lockoutthreshold:3" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220720: Lockout duration must be 15 minutes or greater (CAT II)
        $lockoutDuration = ($netAccounts | Select-String "Lockout duration").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ([int]$lockoutDuration -ge 15) {
            Add-Result -Category "STIG - V-220720 (CAT II)" -Status "Pass" `
                -Message "Account lockout duration: $lockoutDuration minutes" `
                -Details "STIG: Lockout duration meets requirement" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220720 (CAT II)" -Status "Fail" `
                -Message "Account lockout duration is too short: $lockoutDuration minutes" `
                -Details "STIG: Set lockout duration to 15 minutes or greater" `
                -Remediation "net accounts /lockoutduration:15" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - Account Policy" -Status "Error" `
        -Message "Failed to check account policies: $_" `
        -Severity "Medium"
}

# V-220717: Password complexity must be enabled (CAT II)
try {
    # Note: This is typically enforced via secpol, not easily readable from registry
    Add-Result -Category "STIG - V-220717 (CAT II)" -Status "Info" `
        -Message "Password complexity policy" `
        -Details "STIG: Verify password complexity is enabled via Local Security Policy `> Account Policies `> Password Policy" `
        -Remediation "Enable 'Password must meet complexity requirements' in Local Security Policy" `
        -Severity "High" `
        -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
} catch {
    Add-Result -Category "STIG - V-220717 (CAT II)" -Status "Error" `
        -Message "Failed to check password complexity: $_" `
        -Severity "Medium"
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
                -Remediation "Disable-LocalUser -Name Guest" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220929 (CAT I)" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "STIG CAT I: Guest account is properly disabled" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - V-220929 (CAT I)" -Status "Error" `
        -Message "Failed to check Guest account: $_" `
        -Severity "Medium"
}

# V-220930: Administrator account must be renamed (CAT II)
try {
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    
    if ($adminAccount) {
        Add-Result -Category "STIG - V-220930 (CAT II)" -Status "Warning" `
            -Message "Built-in Administrator account has not been renamed" `
            -Details "STIG CAT II: Rename built-in Administrator account to reduce targeting" `
            -Remediation "Rename-LocalUser -Name Administrator -NewName <unique_name`>" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        
        if ($adminAccount.Enabled) {
            Add-Result -Category "STIG - Account Security" -Status "Warning" `
                -Message "Built-in Administrator account is enabled" `
                -Details "STIG: Consider disabling built-in Administrator account" `
                -Remediation "Disable-LocalUser -Name Administrator" `
                -Severity "Medium" `
                -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - V-220930 (CAT II)" -Status "Error" `
        -Message "Failed to check Administrator account: $_" `
        -Severity "Medium"
}

# V-220931: Guest account must be renamed (CAT II)
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($guestAccount) {
        Add-Result -Category "STIG - V-220931 (CAT II)" -Status "Warning" `
            -Message "Built-in Guest account has not been renamed" `
            -Details "STIG CAT II: Rename Guest account even when disabled" `
            -Remediation "Rename-LocalUser -Name Guest -NewName <unique_name`>" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220931 (CAT II)" -Status "Error" `
        -Message "Failed to check Guest account rename: $_" `
        -Severity "Medium"
}

# ============================================================================
# STIG: Audit Policy Configuration (CAT II)
# ============================================================================
Write-Host "[STIG] Checking Audit Policy Configuration..." -ForegroundColor Yellow

try {
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
                        -Details "STIG: Audit policy is correctly configured" `
                        -Severity "Medium" `
                        -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
                } else {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Fail" `
                        -Message "$($check.Subcategory): Not configured for Success and Failure" `
                        -Details "STIG: Enable both Success and Failure auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable /failure:enable" `
                        -Severity "Medium" `
                        -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
                }
            } elseif ($check.Expected -eq "Success") {
                if ($resultText -match "Success") {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Pass" `
                        -Message "$($check.Subcategory): Success auditing enabled" `
                        -Details "STIG: Audit policy is correctly configured" `
                        -Severity "Medium" `
                        -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
                } else {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Fail" `
                        -Message "$($check.Subcategory): Success auditing not enabled" `
                        -Details "STIG: Enable Success auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /success:enable" `
                        -Severity "Medium" `
                        -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
                }
            } elseif ($check.Expected -eq "Failure") {
                if ($resultText -match "Failure") {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Pass" `
                        -Message "$($check.Subcategory): Failure auditing enabled" `
                        -Details "STIG: Audit policy is correctly configured" `
                        -Severity "Medium" `
                        -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
                } else {
                    Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Fail" `
                        -Message "$($check.Subcategory): Failure auditing not enabled" `
                        -Details "STIG: Enable Failure auditing" `
                        -Remediation "auditpol /set /subcategory:'$($check.Subcategory)' /failure:enable" `
                        -Severity "Medium" `
                        -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
                }
            }
        } else {
            Add-Result -Category "STIG - $($check.STIG) (CAT $($check.CAT))" -Status "Warning" `
                -Message "$($check.Subcategory): Could not determine audit status" `
                -Details "STIG: Verify audit policy configuration manually" `
                -Severity "Medium" `
                -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
        }
    } catch {
        # Continue with other checks
    }
}
} catch {
    Add-Result -Category "STIG - Audit Policy" -Status "Error" `
        -Message "Failed to check audit policy configuration: $_" `
        -Severity "Medium"
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
            -Details "STIG: Log capacity is adequate for retention" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220858 (CAT II)" -Status "Fail" `
            -Message "Application log size is insufficient: $appLogSizeMB MB" `
            -Details "STIG: Set Application log to at least 32 MB" `
            -Remediation "wevtutil sl Application /ms:33554432" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220858 (CAT II)" -Status "Error" `
        -Message "Failed to check Application log: $_" `
        -Severity "Medium"
}

# V-220859: Security event log must be 1024 MB or greater (CAT II)
try {
    $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $secLogSizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 2)
    
    if ($secLogSizeMB -ge 1024) {
        Add-Result -Category "STIG - V-220859 (CAT II)" -Status "Pass" `
            -Message "Security log size: $secLogSizeMB MB" `
            -Details "STIG: Security log capacity is adequate" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220859 (CAT II)" -Status "Fail" `
            -Message "Security log size is insufficient: $secLogSizeMB MB" `
            -Details "STIG: Set Security log to at least 1024 MB (1 GB)" `
            -Remediation "wevtutil sl Security /ms:1073741824" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220859 (CAT II)" -Status "Error" `
        -Message "Failed to check Security log: $_" `
        -Severity "Medium"
}

# V-220860: System event log must be 32 MB or greater (CAT II)
try {
    $sysLog = Get-WinEvent -ListLog System -ErrorAction Stop
    $sysLogSizeMB = [math]::Round($sysLog.MaximumSizeInBytes / 1MB, 2)
    
    if ($sysLogSizeMB -ge 32) {
        Add-Result -Category "STIG - V-220860 (CAT II)" -Status "Pass" `
            -Message "System log size: $sysLogSizeMB MB" `
            -Details "STIG: System log capacity is adequate" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220860 (CAT II)" -Status "Fail" `
            -Message "System log size is insufficient: $sysLogSizeMB MB" `
            -Details "STIG: Set System log to at least 32 MB" `
            -Remediation "wevtutil sl System /ms:33554432" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220860 (CAT II)" -Status "Error" `
        -Message "Failed to check System log: $_" `
        -Severity "Medium"
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
            -Details "STIG: Antivirus protection is active" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-253268 (CAT II)" -Status "Fail" `
            -Message "Windows Defender real-time protection is DISABLED" `
            -Details "STIG: Enable real-time antivirus protection immediately" `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
    
    # Check signature update age
    $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
    
    if ($signatureAge.Days -le 7) {
        Add-Result -Category "STIG - Defender Updates" -Status "Pass" `
            -Message "Antivirus signatures are current `($($signatureAge.Days) days old)" `
            -Details "STIG: Malware definitions are up to date" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='V-220916'; NIST='SI-3'; CIS='8.1' }
    } else {
        Add-Result -Category "STIG - Defender Updates" -Status "Fail" `
            -Message "Antivirus signatures are outdated `($($signatureAge.Days) days old)" `
            -Details "STIG: Update antivirus signatures immediately" `
            -Remediation "Update-MpSignature" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220916'; NIST='SI-3'; CIS='8.1' }
    }
} catch {
    Add-Result -Category "STIG - V-253268 (CAT II)" -Status "Error" `
        -Message "Failed to check Windows Defender: $_" `
        -Severity "Medium"
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
            -Details "STIG: Only NTLMv2 authentication is accepted" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220912 (CAT II)" -Status "Fail" `
            -Message "LAN Manager authentication level is insecure" `
            -Details "STIG: Set to 5 (Send NTLMv2 response only, refuse LM & NTLM)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220912 (CAT II)" -Status "Error" `
        -Message "Failed to check LM authentication level: $_" `
        -Severity "Medium"
}

# V-220908: Anonymous enumeration of SAM accounts must be disabled (CAT II)
try {
    $restrictAnonymousSAM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymousSAM -and $restrictAnonymousSAM.RestrictAnonymousSAM -eq 1) {
        Add-Result -Category "STIG - V-220908 (CAT II)" -Status "Pass" `
            -Message "Anonymous SAM account enumeration is restricted" `
            -Details "STIG: Anonymous users cannot enumerate local accounts" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220908 (CAT II)" -Status "Fail" `
            -Message "Anonymous SAM account enumeration is NOT restricted" `
            -Details "STIG: Prevent anonymous enumeration of SAM accounts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220908 (CAT II)" -Status "Error" `
        -Message "Failed to check anonymous SAM restriction: $_" `
        -Severity "Medium"
}

# V-220909: Anonymous enumeration of shares must be disabled (CAT II)
try {
    $restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymous -and $restrictAnonymous.RestrictAnonymous -eq 1) {
        Add-Result -Category "STIG - V-220909 (CAT II)" -Status "Pass" `
            -Message "Anonymous enumeration of shares is restricted" `
            -Details "STIG: Anonymous users cannot enumerate shares" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220909 (CAT II)" -Status "Warning" `
            -Message "Anonymous share enumeration may not be fully restricted" `
            -Details "STIG: Configure to prevent anonymous share enumeration" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220909 (CAT II)" -Status "Error" `
        -Message "Failed to check anonymous share restriction: $_" `
        -Severity "Medium"
}

# V-220926: UAC must be enabled (CAT I)
try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    
    if ($uac.EnableLUA -eq 1) {
        Add-Result -Category "STIG - V-220926 (CAT I)" -Status "Pass" `
            -Message "User Account Control is enabled" `
            -Details "STIG CAT I: UAC prevents unauthorized privilege elevation" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220926 (CAT I)" -Status "Fail" `
            -Message "User Account Control is DISABLED" `
            -Details "STIG CAT I: Enable UAC immediately - critical security control" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1; Restart-Computer" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
    
    # V-220927: UAC elevation prompt for administrators must be configured (CAT II)
    if ($uac.ConsentPromptBehaviorAdmin -ge 2) {
        Add-Result -Category "STIG - V-220927 (CAT II)" -Status "Pass" `
            -Message "UAC admin prompt behavior is configured properly" `
            -Details "STIG: Administrators must consent to elevation" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220927 (CAT II)" -Status "Fail" `
            -Message "UAC admin prompt behavior is too permissive" `
            -Details "STIG: Configure UAC to prompt for consent" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
    
    # V-220928: UAC must use secure desktop (CAT II)
    if ($uac.PromptOnSecureDesktop -eq 1) {
        Add-Result -Category "STIG - V-220928 (CAT II)" -Status "Pass" `
            -Message "UAC prompts on secure desktop" `
            -Details "STIG: Secure desktop prevents UI spoofing attacks" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220928 (CAT II)" -Status "Fail" `
            -Message "UAC does NOT use secure desktop" `
            -Details "STIG: Enable secure desktop for UAC prompts" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
    
} catch {
    Add-Result -Category "STIG - UAC" -Status "Error" `
        -Message "Failed to check UAC configuration: $_" `
        -Severity "Medium"
}

# V-220961: WDigest authentication must be disabled (CAT II)
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    
    if ($wdigest -and $wdigest.UseLogonCredential -eq 0) {
        Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Pass" `
            -Message "WDigest authentication is disabled" `
            -Details "STIG: Plaintext password storage in memory is prevented" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } elseif ($wdigest -and $wdigest.UseLogonCredential -eq 1) {
        Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Fail" `
            -Message "WDigest authentication is ENABLED" `
            -Details "STIG: Disable WDigest to prevent credential theft" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Pass" `
            -Message "WDigest is disabled (default on Windows 8.1+)" `
            -Details "STIG: Secure default configuration" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220961 (CAT II)" -Status "Error" `
        -Message "Failed to check WDigest: $_" `
        -Severity "Medium"
}

# ============================================================================
# STIG: Windows Firewall (CAT I)
# ============================================================================
Write-Host "[STIG] Checking Windows Firewall Configuration..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Private", "Public")

foreach ($profileName in $firewallProfiles) {
    try {
        $fwProfile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        
        # V-220729, V-220730, V-220731: Firewall must be enabled (CAT I)
        $stigId = switch ($profileName) {
            "Domain"  { "V-220729" }
            "Private" { "V-220730" }
            "Public"  { "V-220731" }
        }
        
        if ($fwProfile.Enabled) {
            Add-Result -Category "STIG - $stigId (CAT I)" -Status "Pass" `
                -Message "$profileName Firewall: Enabled" `
                -Details "STIG CAT I: Firewall provides essential network protection" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - $stigId (CAT I)" -Status "Fail" `
                -Message "$profileName Firewall: DISABLED" `
                -Details "STIG CAT I: Enable firewall immediately - critical control" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -Enabled True" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220732, V-220733, V-220734: Inbound connections must be blocked (CAT II)
        $stigIdInbound = switch ($profileName) {
            "Domain"  { "V-220732" }
            "Private" { "V-220733" }
            "Public"  { "V-220734" }
        }
        
        if ($fwProfile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "STIG - $stigIdInbound (CAT II)" -Status "Pass" `
                -Message "$profileName Firewall: Default inbound is Block" `
                -Details "STIG: Default deny reduces attack surface" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - $stigIdInbound (CAT II)" -Status "Fail" `
                -Message "$profileName Firewall: Default inbound is Allow" `
                -Details "STIG: Set default inbound action to Block" `
                -Remediation "Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
    } catch {
        Add-Result -Category "STIG - Firewall" -Status "Error" `
            -Message "Failed to check $profileName firewall: $_" `
            -Severity "Medium"
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
            -Details "STIG: RDP is disabled - no remote access risk" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220964 (CAT II)" -Status "Info" `
            -Message "Remote Desktop is enabled" `
            -Details "STIG: Verify RDP security settings are properly configured" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        
        # V-220965: RDP must require secure RPC (CAT II)
        $secureRPC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -ErrorAction SilentlyContinue
        
        if ($secureRPC -and $secureRPC.fEncryptRPCTraffic -eq 1) {
            Add-Result -Category "STIG - V-220965 (CAT II)" -Status "Pass" `
                -Message "RDP: Secure RPC communication is required" `
                -Details "STIG: RDP RPC traffic is encrypted" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220966: RDP must use FIPS-compliant encryption (CAT II)
        $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        
        if ($encLevel -and $encLevel.MinEncryptionLevel -ge 3) {
            Add-Result -Category "STIG - V-220966 (CAT II)" -Status "Pass" `
                -Message "RDP: Encryption level is set to High or FIPS" `
                -Details "STIG: RDP uses strong encryption" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220966 (CAT II)" -Status "Fail" `
                -Message "RDP: Encryption level is not set to High" `
                -Details "STIG: Configure RDP to use High encryption" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # V-220967: NLA must be required (CAT II)
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "STIG - V-220967 (CAT II)" -Status "Pass" `
                -Message "RDP: Network Level Authentication is required" `
                -Details "STIG: NLA provides additional authentication protection" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220967 (CAT II)" -Status "Fail" `
                -Message "RDP: Network Level Authentication is NOT required" `
                -Details "STIG: Enable NLA for RDP" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - Remote Access" -Status "Error" `
        -Message "Failed to check RDP configuration: $_" `
        -Severity "Medium"
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
            -Details "STIG: SMBv1 has critical vulnerabilities and is disabled" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220968 (CAT II)" -Status "Fail" `
            -Message "SMBv1 protocol is ENABLED" `
            -Details "STIG: Disable SMBv1 immediately (WannaCry vulnerability)" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220968 (CAT II)" -Status "Error" `
        -Message "Failed to check SMBv1: $_" `
        -Severity "Medium"
}

# V-220969: SMB server must perform signing (CAT II)
try {
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer) {
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "STIG - V-220969 (CAT II)" -Status "Pass" `
                -Message "SMB server signing is required" `
                -Details "STIG: SMB signing prevents tampering and relay attacks" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220969 (CAT II)" -Status "Fail" `
                -Message "SMB server signing is NOT required" `
                -Details "STIG: Enable required SMB signing" `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - V-220969 (CAT II)" -Status "Error" `
        -Message "Failed to check SMB signing: $_" `
        -Severity "Medium"
}

# V-220970: SMB client must perform signing (CAT II)
try {
    $smbClientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
    
    if ($smbClientSigning -and $smbClientSigning.RequireSecuritySignature -eq 1) {
        Add-Result -Category "STIG - V-220970 (CAT II)" -Status "Pass" `
            -Message "SMB client signing is required" `
            -Details "STIG: Client-side SMB signing is enforced" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220970 (CAT II)" -Status "Fail" `
            -Message "SMB client signing is NOT required" `
            -Details "STIG: Enable required SMB client signing" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220970 (CAT II)" -Status "Error" `
        -Message "Failed to check SMB client signing: $_" `
        -Severity "Medium"
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
                -Details "STIG: Data at rest is protected (Method: $($bitlocker.EncryptionMethod))" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } elseif ($bitlocker.VolumeStatus -eq "EncryptionInProgress") {
            Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Info" `
                -Message "System drive encryption in progress: $($bitlocker.EncryptionPercentage)`%" `
                -Details "STIG: Allow BitLocker encryption to complete" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Fail" `
                -Message "System drive is NOT encrypted (Status: $($bitlocker.VolumeStatus))" `
                -Details "STIG: Enable BitLocker on system drive" `
                -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -TpmProtector" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
} catch {
    $errorMsg = $_.Exception.Message
    if ($errorMsg -like "*not supported*" -or $errorMsg -like "*requires*") {
        Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Info" `
            -Message "BitLocker not available on this edition" `
            -Details "STIG: BitLocker requires Pro/Enterprise editions" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220958 (CAT II)" -Status "Error" `
            -Message "Failed to check BitLocker: $_" `
            -Severity "Medium"
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
                -Details "STIG: PowerShell v2 cannot be used for downgrade attacks" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220971 (CAT II)" -Status "Fail" `
                -Message "PowerShell v2 is ENABLED" `
                -Details "STIG: Remove PowerShell v2 to prevent security bypass" `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - V-220971 (CAT II)" -Status "Info" `
        -Message "Could not check PowerShell v2 status" `
        -Severity "High" `
        -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
}

# V-220972: PowerShell Script Block Logging must be enabled (CAT II)
try {
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Add-Result -Category "STIG - V-220972 (CAT II)" -Status "Pass" `
            -Message "PowerShell Script Block Logging is enabled" `
            -Details "STIG: PowerShell commands are logged for security monitoring" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220972 (CAT II)" -Status "Fail" `
            -Message "PowerShell Script Block Logging is NOT enabled" `
            -Details "STIG: Enable Script Block Logging for audit trail" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220972 (CAT II)" -Status "Error" `
        -Message "Failed to check PowerShell logging: $_" `
        -Severity "Medium"
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
            -Details "STIG: Prevents automatic execution from removable media" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220973 (CAT II)" -Status "Fail" `
            -Message "AutoPlay is not fully disabled" `
            -Details "STIG: Disable AutoPlay for all drives" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220973 (CAT II)" -Status "Error" `
        -Message "Failed to check AutoPlay: $_" `
        -Severity "Medium"
}

# V-220974: Autorun must be disabled (CAT II)
try {
    $noAutorun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ErrorAction SilentlyContinue
    
    if ($noAutorun -and $noAutorun.NoAutorun -eq 1) {
        Add-Result -Category "STIG - V-220974 (CAT II)" -Status "Pass" `
            -Message "Autorun is disabled" `
            -Details "STIG: Prevents autorun.inf from executing" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220974 (CAT II)" -Status "Fail" `
            -Message "Autorun is NOT disabled" `
            -Details "STIG: Disable Autorun to prevent malware execution" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220974 (CAT II)" -Status "Error" `
        -Message "Failed to check Autorun: $_" `
        -Severity "Medium"
}

# V-220975: Enhanced anti-spoofing must be enabled (CAT III)
try {
    $antiSpoofing = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -ErrorAction SilentlyContinue
    
    if ($antiSpoofing -and $antiSpoofing.EnhancedAntiSpoofing -eq 1) {
        Add-Result -Category "STIG - V-220975 (CAT III)" -Status "Pass" `
            -Message "Enhanced anti-spoofing for facial recognition is enabled" `
            -Details "STIG: Biometric authentication has additional protection" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220975 (CAT III)" -Status "Info" `
            -Message "Enhanced anti-spoofing not configured or not applicable" `
            -Details "STIG: Configure if using Windows Hello facial recognition" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220975 (CAT III)" -Status "Info" `
        -Message "Could not check anti-spoofing (may not be applicable)" `
        -Severity "High" `
        -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
}

# V-220976: Camera access from lock screen must be disabled (CAT II)
try {
    $cameraLockScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -ErrorAction SilentlyContinue
    
    if ($cameraLockScreen -and $cameraLockScreen.NoLockScreenCamera -eq 1) {
        Add-Result -Category "STIG - V-220976 (CAT II)" -Status "Pass" `
            -Message "Camera is disabled on lock screen" `
            -Details "STIG: Prevents unauthorized camera access" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220976 (CAT II)" -Status "Warning" `
            -Message "Camera may be accessible from lock screen" `
            -Details "STIG: Disable camera on lock screen" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name NoLockScreenCamera -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220976 (CAT II)" -Status "Error" `
        -Message "Failed to check lock screen camera: $_" `
        -Severity "Medium"
}

# V-220977: Toast notifications on lock screen must be disabled (CAT II)
try {
    $toastNotifications = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -ErrorAction SilentlyContinue
    
    if ($toastNotifications -and $toastNotifications.NoToastApplicationNotificationOnLockScreen -eq 1) {
        Add-Result -Category "STIG - V-220977 (CAT II)" -Status "Pass" `
            -Message "Toast notifications are disabled on lock screen" `
            -Details "STIG: Prevents information disclosure on lock screen" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220977 (CAT II)" -Status "Warning" `
            -Message "Toast notifications may appear on lock screen" `
            -Details "STIG: Disable notifications on lock screen to prevent info disclosure" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name NoToastApplicationNotificationOnLockScreen -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220977 (CAT II)" -Status "Error" `
        -Message "Failed to check lock screen notifications: $_" `
        -Severity "Medium"
}

# V-220978: Windows Update must be configured properly (CAT II)
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($wuService) {
        if ($wuService.Status -eq "Running") {
            Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Pass" `
                -Message "Windows Update service is running" `
                -Details "STIG: System can receive security updates" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Fail" `
                -Message "Windows Update service is not running" `
                -Details "STIG: Enable Windows Update to receive patches" `
                -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
    }
    
    # Check if automatic updates are disabled
    $noAutoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    
    if ($noAutoUpdate -and $noAutoUpdate.NoAutoUpdate -eq 1) {
        Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Fail" `
            -Message "Automatic Windows Updates are disabled" `
            -Details "STIG: Enable automatic updates for timely patching" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220978 (CAT II)" -Status "Error" `
        -Message "Failed to check Windows Update: $_" `
        -Severity "Medium"
}

# V-220979: Secure Boot must be enabled (CAT II)
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Pass" `
            -Message "Secure Boot is enabled" `
            -Details "STIG: Boot integrity is protected against bootkits and rootkits" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Fail" `
            -Message "Secure Boot is disabled" `
            -Details "STIG: Enable Secure Boot in UEFI/BIOS firmware" `
            -Remediation "Enable Secure Boot in system firmware settings" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Info" `
            -Message "Secure Boot status cannot be determined (Legacy BIOS)" `
            -Details "STIG: UEFI with Secure Boot is required for modern systems" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220979 (CAT II)" -Status "Info" `
        -Message "Could not determine Secure Boot status" `
        -Severity "High" `
        -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
}

# V-220980: Virtualization-based security must be enabled (CAT II)
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        if ($deviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
            Add-Result -Category "STIG - V-220980 (CAT II)" -Status "Pass" `
                -Message "Virtualization-based security is running" `
                -Details "STIG: Hardware-based isolation provides enhanced security" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - V-220980 (CAT II)" -Status "Info" `
                -Message "Virtualization-based security is not running" `
                -Details "STIG: Enable VBS on compatible hardware for enhanced protection" `
                -Severity "High" `
                -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
        }
        
        # Check Credential Guard
        if ($deviceGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "STIG - Credential Guard" -Status "Pass" `
                -Message "Credential Guard is running" `
                -Details "STIG: Credentials are protected in isolated environment" `
                -Severity "Medium" `
                -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
        } else {
            Add-Result -Category "STIG - Credential Guard" -Status "Info" `
                -Message "Credential Guard is not running" `
                -Details "STIG: Enable Credential Guard on compatible systems" `
                -Severity "Medium" `
                -CrossReferences @{ STIG='V-220860'; NIST='CM-6' }
        }
    }
} catch {
    Add-Result -Category "STIG - V-220980 (CAT II)" -Status "Info" `
        -Message "Could not check virtualization-based security" `
        -Severity "High" `
        -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
}

# V-220981: Insecure logons to SMB server must be disabled (CAT II)
try {
    $insecureLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
    
    if ($insecureLogon -and $insecureLogon.AllowInsecureGuestAuth -eq 0) {
        Add-Result -Category "STIG - V-220981 (CAT II)" -Status "Pass" `
            -Message "Insecure guest authentication to SMB servers is disabled" `
            -Details "STIG: Prevents insecure SMB connections" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220981 (CAT II)" -Status "Warning" `
            -Message "Insecure guest authentication may be allowed" `
            -Details "STIG: Disable insecure guest authentication" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name AllowInsecureGuestAuth -Value 0" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220981 (CAT II)" -Status "Error" `
        -Message "Failed to check insecure SMB logon: $_" `
        -Severity "Medium"
}

# V-220982: Network selection prompts must be disabled (CAT II)
try {
    $networkPrompts = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
    
    if ($networkPrompts -and $networkPrompts.DontDisplayNetworkSelectionUI -eq 1) {
        Add-Result -Category "STIG - V-220982 (CAT II)" -Status "Pass" `
            -Message "Network selection UI is disabled on logon" `
            -Details "STIG: Prevents information disclosure at logon screen" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220982 (CAT II)" -Status "Warning" `
            -Message "Network selection UI may appear on logon" `
            -Details "STIG: Disable network selection UI" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name DontDisplayNetworkSelectionUI -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220982 (CAT II)" -Status "Error" `
        -Message "Failed to check network selection UI: $_" `
        -Severity "Medium"
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
                    -Details "STIG: Unnecessary service is disabled" `
                    -Severity "High" `
                    -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
            } else {
                Add-Result -Category "STIG - V-220983 (CAT II)" -Status "Warning" `
                    -Message "Xbox service '$($service.DisplayName)' is not disabled" `
                    -Details "STIG: Disable Xbox services if not required" `
                    -Remediation "Set-Service -Name $svcName -StartupType Disabled" `
                    -Severity "Medium" `
                    -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
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
            -Details "STIG: Prevents automatic installation of suggested apps" `
            -Severity "High" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    } else {
        Add-Result -Category "STIG - V-220984 (CAT II)" -Status "Warning" `
            -Message "Windows consumer experiences may be enabled" `
            -Details "STIG: Disable consumer experiences in enterprise environment" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableWindowsConsumerFeatures -Value 1" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='CAT-I'; NIST='CM-6' }
    }
} catch {
    Add-Result -Category "STIG - V-220984 (CAT II)" -Status "Error" `
        -Message "Failed to check consumer experiences: $_" `
        -Severity "Medium"
}

# ============================================================================
# STIG: Credential Protection and LSA Hardening (CAT I, II)
# ============================================================================
Write-Host "[STIG] Checking credential protection and LSA hardening..." -ForegroundColor Yellow

try {
    # V-220929: WDigest authentication must be disabled (CAT I)
    $wdigest = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default 1
    if ($wdigest -eq 0) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220929: WDigest authentication is disabled (plaintext creds not stored)" `
            -Details "CAT I: WDigest disabled prevents cleartext credential storage in memory" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220929'; NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220929: WDigest authentication is ENABLED -- plaintext credentials in memory" `
            -Details "CAT I: Attackers can extract plaintext passwords from LSASS process memory" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220929'; NIST='IA-5(13)'; NSA='Credential Protection'; CIS='18.3.6' }
    }

    # V-220930: Credential Guard must be enabled (CAT I -- if hardware supports)
    $credGuard = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Default 0
    if ($credGuard -ge 1) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220930: Credential Guard is enabled (LsaCfgFlags=$credGuard)" `
            -Details "CAT I: VBS-isolated credential storage prevents pass-the-hash attacks" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220930'; NIST='IA-5(13)'; NSA='Credential Protection' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220930: Credential Guard is NOT enabled" `
            -Details "CAT I: Domain credentials stored without hardware isolation" `
            -Remediation "Enable via Group Policy: Computer Config `> Admin Templates `> System `> Device Guard" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220930'; NIST='IA-5(13)'; NSA='Credential Protection' }
    }

    # V-220931: LSA Protection (RunAsPPL) must be enabled (CAT I)
    $lsaPPL = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RunAsPPL" -Default 0
    if ($lsaPPL -eq 1) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220931: LSA Protection (RunAsPPL) is enabled" `
            -Details "CAT I: LSASS process protected as Protected Process Light against injection" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220931'; NIST='SI-7'; NSA='Credential Protection'; CIS='18.3.5' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220931: LSA Protection (RunAsPPL) is NOT enabled" `
            -Details "CAT I: LSASS process vulnerable to code injection and credential dumping" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name RunAsPPL -Value 1 -Type DWord" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220931'; NIST='SI-7'; NSA='Credential Protection'; CIS='18.3.5' }
    }

    # V-220862: LM hash storage must be disabled (CAT I)
    $noLmHash = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "NoLMHash" -Default 0
    if ($noLmHash -eq 1) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220862: LM hash storage is disabled (NoLMHash=1)" `
            -Details "CAT I: LAN Manager hashes are trivially crackable and not stored" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220862'; NIST='IA-5'; CIS='2.3.11.7' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220862: LM hash storage is ENABLED" `
            -Details "CAT I: LM hashes can be cracked in seconds using rainbow tables" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name NoLMHash -Value 1 -Type DWord" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220862'; NIST='IA-5'; CIS='2.3.11.7' }
    }

    # V-220935: LM authentication level must be set to NTLMv2 only (CAT I)
    $lmLevel = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LmCompatibilityLevel" -Default 0
    if ($lmLevel -ge 5) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220935: LM authentication level is $lmLevel (NTLMv2 only, refuse LM/NTLM)" `
            -Details "CAT I: Only NTLMv2 responses accepted; LM and NTLM are refused" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220935'; NIST='IA-2(8)'; CIS='2.3.11.7'; NSA='Credential Protection' }
    } elseif ($lmLevel -ge 3) {
        Add-Result -Category "STIG - Credential Protection" -Status "Warning" `
            -Message "V-220935: LM authentication level is $lmLevel (NTLMv2 sent but LM/NTLM accepted)" `
            -Details "CAT I: Should be set to 5 to refuse LM and NTLM responses entirely" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220935'; NIST='IA-2(8)'; CIS='2.3.11.7' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220935: LM authentication level is $lmLevel -- weak authentication accepted" `
            -Details "CAT I: LM and NTLM authentication are easily cracked" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220935'; NIST='IA-2(8)'; CIS='2.3.11.7'; NSA='Credential Protection' }
    }

    # V-220936: Anonymous SID/Name translation must be disabled (CAT I)
    $anonSidTranslation = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "TurnOffAnonymousBlock" -Default 0
    $restrictAnon = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Default 0
    $restrictAnonSam = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymousSAM" -Default 0

    # Check SID/Name translation separately (TurnOffAnonymousBlock=1 means anonymous SID translation is blocked)
    if ($anonSidTranslation -eq 1) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220936: Anonymous SID/Name translation is disabled (TurnOffAnonymousBlock=1)" `
            -Details "CAT I: Anonymous users cannot translate SIDs to account names" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220936'; NIST='AC-14'; CIS='2.3.10.1' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220936: Anonymous SID/Name translation is ALLOWED (TurnOffAnonymousBlock=$anonSidTranslation)" `
            -Details "CAT I: Anonymous users can translate SIDs to discover account names for targeted attacks" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name TurnOffAnonymousBlock -Value 1 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220936'; NIST='AC-14'; CIS='2.3.10.1' }
    }

    # Check anonymous enumeration restrictions
    if ($restrictAnon -ge 1 -and $restrictAnonSam -eq 1) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220936: Anonymous enumeration restrictions are enabled (RestrictAnonymous=$restrictAnon, RestrictAnonymousSAM=$restrictAnonSam)" `
            -Details "CAT I: Anonymous users cannot enumerate SAM accounts or shares" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220936'; NIST='AC-14'; CIS='2.3.10.2' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Fail" `
            -Message "V-220936: Anonymous enumeration restrictions not fully configured (RestrictAnonymous=$restrictAnon, RestrictAnonymousSAM=$restrictAnonSam)" `
            -Details "CAT I: Anonymous users may enumerate user accounts, shares, and group memberships" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name RestrictAnonymous -Value 1; Set-ItemProperty ... -Name RestrictAnonymousSAM -Value 1" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220936'; NIST='AC-14'; CIS='2.3.10.2' }
    }

    # Cached logon credentials count (V-220860)
    $cachedLogons = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Default "10"
    if ([int]$cachedLogons -le 4) {
        Add-Result -Category "STIG - Credential Protection" -Status "Pass" `
            -Message "V-220860: Cached logon credentials limited to $cachedLogons" `
            -Details "CAT II: Minimizes cached domain credentials available for offline attacks" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='V-220860'; NIST='IA-5'; CIS='2.3.11.1' }
    } else {
        Add-Result -Category "STIG - Credential Protection" -Status "Warning" `
            -Message "V-220860: Cached logon credentials is $cachedLogons (recommended: 4 or fewer)" `
            -Details "CAT II: High cached credential count increases offline attack surface" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value '4'" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='V-220860'; NIST='IA-5'; CIS='2.3.11.1' }
    }

} catch {
    Add-Result -Category "STIG - Credential Protection" -Status "Error" `
        -Message "Failed to check credential protection: $_" `
        -Severity "Medium"
}

# ============================================================================
# STIG: TLS/SSL Protocol Enforcement (CAT I, II)
# ============================================================================
Write-Host "[STIG] Checking TLS/SSL protocol enforcement..." -ForegroundColor Yellow

try {
    # V-220955: SSL 2.0 must be disabled (CAT I)
    $ssl2Client = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Default $null
    $ssl2Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Default $null
    if (($null -eq $ssl2Client -or $ssl2Client -eq 0) -and ($null -eq $ssl2Server -or $ssl2Server -eq 0)) {
        Add-Result -Category "STIG - TLS/SSL" -Status "Pass" `
            -Message "V-220955: SSL 2.0 is disabled (not available)" `
            -Details "CAT I: Obsolete protocol with known critical vulnerabilities" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220955'; NIST='SC-8'; NSA='Eliminating Obsolete TLS'; CIS='18.9.24' }
    } else {
        Add-Result -Category "STIG - TLS/SSL" -Status "Fail" `
            -Message "V-220955: SSL 2.0 may be enabled -- critical vulnerability" `
            -Details "CAT I: SSL 2.0 has fundamental design flaws allowing protocol downgrade attacks" `
            -Remediation "Disable via registry: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\Enabled = 0" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220955'; NIST='SC-8'; NSA='Eliminating Obsolete TLS' }
    }

    # V-220956: SSL 3.0 must be disabled (CAT I)
    $ssl3Client = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Default $null
    $ssl3Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Default $null
    if (($null -eq $ssl3Client -or $ssl3Client -eq 0) -and ($null -eq $ssl3Server -or $ssl3Server -eq 0)) {
        Add-Result -Category "STIG - TLS/SSL" -Status "Pass" `
            -Message "V-220956: SSL 3.0 is disabled" `
            -Details "CAT I: POODLE vulnerability (CVE-2014-3566) mitigated" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220956'; NIST='SC-8'; NSA='Eliminating Obsolete TLS'; CIS='18.9.24' }
    } else {
        Add-Result -Category "STIG - TLS/SSL" -Status "Fail" `
            -Message "V-220956: SSL 3.0 is ENABLED -- vulnerable to POODLE attack" `
            -Details "CAT I: CVE-2014-3566 allows extraction of encrypted data" `
            -Remediation "New-Item -Path 'HKLM:\SYSTEM\...\SSL 3.0\Server' -Force; Set-ItemProperty ... -Name Enabled -Value 0 -Type DWord; Set-ItemProperty ... -Name DisabledByDefault -Value 1" `
            -Severity "Critical" `
            -CrossReferences @{ STIG='V-220956'; NIST='SC-8'; NSA='Eliminating Obsolete TLS' }
    }

    # V-220957: TLS 1.0 must be disabled (CAT I)
    $tls10Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Default $null
    if ($null -ne $tls10Server -and $tls10Server -eq 0) {
        Add-Result -Category "STIG - TLS/SSL" -Status "Pass" `
            -Message "V-220957: TLS 1.0 is explicitly disabled" `
            -Details "CAT I: BEAST and other vulnerabilities mitigated" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220957'; NIST='SC-8'; NSA='Eliminating Obsolete TLS' }
    } else {
        Add-Result -Category "STIG - TLS/SSL" -Status "Warning" `
            -Message "V-220957: TLS 1.0 is not explicitly disabled (may be available)" `
            -Details "CAT I: TLS 1.0 has known vulnerabilities; disable unless legacy compatibility required" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\...\TLS 1.0\Server' -Name Enabled -Value 0 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220957'; NIST='SC-8'; NSA='Eliminating Obsolete TLS' }
    }

    # V-220958: TLS 1.1 must be disabled (CAT II)
    $tls11Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Default $null
    if ($null -ne $tls11Server -and $tls11Server -eq 0) {
        Add-Result -Category "STIG - TLS/SSL" -Status "Pass" `
            -Message "V-220958: TLS 1.1 is explicitly disabled" `
            -Details "CAT II: Deprecated protocol removed from available ciphers" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='V-220958'; NIST='SC-8'; NSA='Eliminating Obsolete TLS' }
    } else {
        Add-Result -Category "STIG - TLS/SSL" -Status "Warning" `
            -Message "V-220958: TLS 1.1 is not explicitly disabled" `
            -Details "CAT II: TLS 1.1 deprecated -- disable in favor of TLS 1.2+" `
            -Severity "Medium" `
            -CrossReferences @{ STIG='V-220958'; NIST='SC-8'; NSA='Eliminating Obsolete TLS' }
    }

    # TLS 1.2 must be enabled (CAT I)
    $tls12Server = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Default $null
    $tls12Disabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Default 0
    if (($null -eq $tls12Server -or $tls12Server -eq 1) -and $tls12Disabled -eq 0) {
        Add-Result -Category "STIG - TLS/SSL" -Status "Pass" `
            -Message "TLS 1.2 is enabled (default or explicitly configured)" `
            -Details "CAT I: Minimum acceptable TLS version for STIG compliance" `
            -Severity "High" `
            -CrossReferences @{ NIST='SC-8'; NSA='TLS Inspection'; CIS='18.9.24' }
    } else {
        Add-Result -Category "STIG - TLS/SSL" -Status "Fail" `
            -Message "TLS 1.2 may be disabled or set as DisabledByDefault" `
            -Details "CAT I: TLS 1.2 is the minimum required protocol version" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\...\TLS 1.2\Server' -Name Enabled -Value 1; Set-ItemProperty ... -Name DisabledByDefault -Value 0" `
            -Severity "Critical" `
            -CrossReferences @{ NIST='SC-8'; NSA='TLS Inspection' }
    }

    # NULL cipher suites must be disabled
    $nullCiphers = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Default $null
    if ($null -eq $nullCiphers -or $nullCiphers -eq 0) {
        Add-Result -Category "STIG - TLS/SSL" -Status "Pass" `
            -Message "NULL cipher suites are disabled (no unencrypted TLS connections)" `
            -Details "CAT I: NULL ciphers provide no confidentiality protection" `
            -Severity "High" `
            -CrossReferences @{ NIST='SC-13'; NSA='TLS Inspection' }
    } else {
        Add-Result -Category "STIG - TLS/SSL" -Status "Fail" `
            -Message "NULL cipher suites are ENABLED -- TLS without encryption is possible" `
            -Details "CAT I: Connections may negotiate no encryption at all" `
            -Remediation "Disable NULL ciphers via registry or IIS Crypto tool" `
            -Severity "Critical" `
            -CrossReferences @{ NIST='SC-13'; NSA='TLS Inspection' }
    }

} catch {
    Add-Result -Category "STIG - TLS/SSL" -Status "Error" `
        -Message "Failed to check TLS/SSL configuration: $_" `
        -Severity "Medium"
}

# ============================================================================
# STIG: Hardware Security and Secure Boot (CAT I, II)
# ============================================================================
Write-Host "[STIG] Checking hardware security and Secure Boot..." -ForegroundColor Yellow

try {
    # V-220970: Secure Boot must be enabled (CAT I)
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot) {
            Add-Result -Category "STIG - Hardware Security" -Status "Pass" `
                -Message "V-220970: UEFI Secure Boot is enabled" `
                -Details "CAT I: Boot process integrity verified through cryptographic chain of trust" `
                -Severity "High" `
                -CrossReferences @{ STIG='V-220970'; NIST='SI-7'; NSA='Boot Security'; CIS='1.1.1' }
        } else {
            Add-Result -Category "STIG - Hardware Security" -Status "Fail" `
                -Message "V-220970: UEFI Secure Boot is NOT enabled" `
                -Details "CAT I: Boot process vulnerable to rootkits and bootkits" `
                -Remediation "Enable Secure Boot in UEFI firmware settings" `
                -Severity "Critical" `
                -CrossReferences @{ STIG='V-220970'; NIST='SI-7'; NSA='Boot Security' }
        }
    } catch {
        Add-Result -Category "STIG - Hardware Security" -Status "Warning" `
            -Message "V-220970: Could not determine Secure Boot status (may be legacy BIOS)" `
            -Details "CAT I: System may use legacy BIOS without UEFI Secure Boot support" `
            -Severity "High" `
            -CrossReferences @{ STIG='V-220970'; NIST='SI-7'; NSA='Boot Security' }
    }

    # Virtualization-Based Security (VBS) status
    try {
        $vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($vbsStatus -and $vbsStatus.VirtualizationBasedSecurityStatus -eq 2) {
            Add-Result -Category "STIG - Hardware Security" -Status "Pass" `
                -Message "Virtualization-Based Security (VBS) is running" `
                -Details "CAT I: Hardware-enforced security boundaries protect kernel and credentials" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security'; CIS='18.9.5.1' }
        } elseif ($vbsStatus -and $vbsStatus.VirtualizationBasedSecurityStatus -eq 1) {
            Add-Result -Category "STIG - Hardware Security" -Status "Warning" `
                -Message "VBS is enabled but not running (may require reboot)" `
                -Details "CAT I: VBS configured but not yet active" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security' }
        } else {
            Add-Result -Category "STIG - Hardware Security" -Status "Fail" `
                -Message "Virtualization-Based Security (VBS) is NOT enabled" `
                -Details "CAT I: No hardware-enforced isolation for kernel or credential storage" `
                -Remediation "Enable via Group Policy: Computer Config `> Admin Templates `> System `> Device Guard" `
                -Severity "High" `
                -CrossReferences @{ NIST='SC-3'; NSA='Hardware Security'; CIS='18.9.5.1' }
        }
    } catch { }

    # DEP (Data Execution Prevention) enforcement
    try {
        $bcdeditDep = bcdedit /enum "{current}" 2>&1 | Out-String
        if ($bcdeditDep -match "nx\s+OptOut" -or $bcdeditDep -match "nx\s+AlwaysOn") {
            Add-Result -Category "STIG - Hardware Security" -Status "Pass" `
                -Message "DEP is enabled system-wide (OptOut or AlwaysOn)" `
                -Details "CAT II: Hardware-enforced DEP prevents execution from non-executable memory" `
                -Severity "High" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1'; NSA='Exploit Mitigation' }
        } elseif ($bcdeditDep -match "nx\s+OptIn") {
            Add-Result -Category "STIG - Hardware Security" -Status "Warning" `
                -Message "DEP is in OptIn mode (only Windows system binaries protected)" `
                -Details "CAT II: Recommend OptOut for broader protection" `
                -Remediation "bcdedit /set `"{current}`" nx OptOut" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SI-16'; CIS='18.3.1' }
        }
    } catch { }

    # SEHOP (Structured Exception Handler Overwrite Protection)
    $sehop = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Default 0
    if ($sehop -eq 0) {
        Add-Result -Category "STIG - Hardware Security" -Status "Pass" `
            -Message "SEHOP is enabled (exception chain validation active)" `
            -Details "CAT II: SEH overwrite exploit technique is mitigated" `
            -Severity "Medium" `
            -CrossReferences @{ NIST='SI-16'; NSA='Exploit Mitigation' }
    } else {
        Add-Result -Category "STIG - Hardware Security" -Status "Fail" `
            -Message "SEHOP is DISABLED -- SEH overwrite attacks possible" `
            -Details "CAT II: Exception chain validation is not active" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name DisableExceptionChainValidation -Value 0 -Type DWord" `
            -Severity "High" `
            -CrossReferences @{ NIST='SI-16'; NSA='Exploit Mitigation' }
    }

    # TPM availability
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
            Add-Result -Category "STIG - Hardware Security" -Status "Pass" `
                -Message "TPM is present and ready (Version: $($tpm.ManufacturerVersion))" `
                -Details "CAT II: Trusted Platform Module provides hardware root of trust" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
        } elseif ($tpm -and $tpm.TpmPresent) {
            Add-Result -Category "STIG - Hardware Security" -Status "Warning" `
                -Message "TPM is present but not ready" `
                -Details "CAT II: TPM needs initialization for BitLocker and attestation" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
        } else {
            Add-Result -Category "STIG - Hardware Security" -Status "Info" `
                -Message "No TPM detected on this system" `
                -Details "CAT II: Hardware-backed key storage and attestation not available" `
                -Severity "Medium" `
                -CrossReferences @{ NIST='SC-12'; NSA='Hardware Security' }
        }
    } catch { }

} catch {
    Add-Result -Category "STIG - Hardware Security" -Status "Error" `
        -Message "Failed to check hardware security: $_" `
        -Severity "Medium"
}

# ============================================================================
# STIG Summary and Categorization
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

Write-Host "`n[STIG] ======================================================================" -ForegroundColor Cyan
Write-Host "[STIG] MODULE COMPLETED -- v$moduleVersion" -ForegroundColor Cyan
Write-Host "[STIG] ======================================================================" -ForegroundColor Cyan
Write-Host "[STIG] Total Checks Executed: $totalChecks" -ForegroundColor White
Write-Host "[STIG]" -ForegroundColor Cyan
Write-Host "[STIG] Results Summary:" -ForegroundColor Cyan
$pctPass = if ($totalChecks -gt 0) { [Math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }
Write-Host "[STIG]   Passed:   $($passCount.ToString().PadLeft(3)) ($pctPass`%)" -ForegroundColor Green
Write-Host "[STIG]   Failed:   $($failCount.ToString().PadLeft(3))" -ForegroundColor Red
Write-Host "[STIG]   Warnings: $($warnCount.ToString().PadLeft(3))" -ForegroundColor Yellow
Write-Host "[STIG]   Info:     $($infoCount.ToString().PadLeft(3))" -ForegroundColor Cyan
Write-Host "[STIG]   Errors:   $($errorCount.ToString().PadLeft(3))" -ForegroundColor Magenta
Write-Host "[STIG]" -ForegroundColor Cyan
Write-Host "[STIG] Check Categories:" -ForegroundColor Cyan
foreach ($cat in ($categoryStats.Keys | Sort-Object)) {
    Write-Host "[STIG]   $($cat.PadRight(45)): $($categoryStats[$cat].ToString().PadLeft(3)) checks" -ForegroundColor Gray
}
if ($failCount -gt 0) {
    Write-Host "[STIG]" -ForegroundColor Cyan
    Write-Host "[STIG] Failed Check Severity:" -ForegroundColor Cyan
    foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
        if ($severityStats[$sev] -gt 0) {
            $sevColor = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; 'Low' { 'Cyan' }; default { 'Gray' } }
            Write-Host "[STIG]   $($sev.PadRight(15)): $($severityStats[$sev])" -ForegroundColor $sevColor
        }
    }
}
Write-Host "[STIG] ======================================================================`n" -ForegroundColor Cyan

return $results

# ============================================================================
# Standalone Execution Support
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host "  DISA STIG Compliance Module -- Standalone Test Mode v$moduleVersion" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor White
    Write-Host ""

    $standaloneData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion    = ''
        IPAddresses  = @()
        ScanDate     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        IsAdmin      = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath   = $PSScriptRoot
        Cache        = $null
    }

    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $standaloneData.OSVersion = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
    } catch {
        $standaloneData.OSVersion = "Windows (version detection failed)"
    }

    try {
        $standaloneData.IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress)
    } catch {
        $standaloneData.IPAddresses = @("N/A")
    }

    $commonLibPath = Join-Path (Split-Path $PSScriptRoot -Parent) "shared_components\audit-common.ps1"
    if (Test-Path $commonLibPath) {
        try {
            . $commonLibPath
            $osInfoObj = Get-OSInfo
            $standaloneCache = New-SharedDataCache -OSInfo $osInfoObj
            Invoke-CacheWarmUp -Cache $standaloneCache
            $standaloneData.Cache = $standaloneCache
            $summary = Get-CacheSummary -Cache $standaloneCache
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
    Write-Host "  STIG module standalone test complete" -ForegroundColor Cyan
    Write-Host "  All $($results.Count) checks executed" -ForegroundColor Cyan
    Write-Host "$("=" * 80)`n" -ForegroundColor White
}

# ============================================================================
# End of DISA STIG Compliance Module (Module-STIG.ps1)
# ============================================================================
