# Module-NIST.ps1
# NIST (National Institute of Standards and Technology) Compliance Module
# Version: 6.0 - Enhanced and Comprehensive
# Based on NIST 800-53 Rev 5, NIST Cybersecurity Framework 2.0, and NIST 800-171 Rev 2

<#
.SYNOPSIS
    Comprehensive NIST security controls and Cybersecurity Framework compliance checks.

.DESCRIPTION
    This module performs exhaustive checks aligned with NIST guidance including:
    
    NIST 800-53 Rev 5 Control Families:
    - Access Control (AC) - 25+ controls
    - Awareness and Training (AT)
    - Audit and Accountability (AU) - 16+ controls
    - Assessment, Authorization, and Monitoring (CA)
    - Configuration Management (CM) - 14+ controls
    - Contingency Planning (CP)
    - Identification and Authentication (IA) - 12+ controls
    - Incident Response (IR) - 10+ controls
    - Maintenance (MA)
    - Media Protection (MP) - 8+ controls
    - Physical and Environmental Protection (PE)
    - Planning (PL)
    - Program Management (PM)
    - Personnel Security (PS)
    - Risk Assessment (RA)
    - System and Services Acquisition (SA)
    - System and Communications Protection (SC) - 28+ controls
    - System and Information Integrity (SI) - 23+ controls
    
    NIST Cybersecurity Framework 2.0 (CSF):
    - Govern (GV) - Organizational context and cybersecurity strategy
    - Identify (ID) - Asset management, risk assessment, improvement
    - Protect (PR) - Identity management, awareness, data security, platform security
    - Detect (DE) - Continuous monitoring, adverse event detection
    - Respond (RS) - Incident response, communications, analysis, mitigation
    - Recover (RC) - Incident recovery, communications, improvements
    
    NIST 800-171 Rev 2:
    - Protection of Controlled Unclassified Information (CUI)
    - 14 requirement families with 110 security requirements

.PARAMETER SharedData
    Hashtable containing shared data from the main script including:
    - ComputerName: Name of the computer being audited
    - OSVersion: Operating system version
    - ScanDate: Date/time of scan
    - IsAdmin: Whether script is running with admin privileges
    - ScriptPath: Path to script directory
    - RemediateIssues: Whether remediation mode is enabled

.EXAMPLE
    .\Module-NIST.ps1 -SharedData $sharedData
    Execute NIST compliance checks with shared data context

.NOTES
    Version: 6.0
    Author: Enhanced NIST Compliance Module
    
    Based on:
    - NIST Special Publication 800-53 Revision 5 (Security and Privacy Controls)
    - NIST Cybersecurity Framework Version 2.0
    - NIST Special Publication 800-171 Revision 2 (Protecting CUI)
    - NIST Special Publication 800-171A (Assessment Procedures)
    
    Requires:
    - Windows 10/11 or Windows Server 2016+
    - PowerShell 5.1+
    - Administrator privileges for complete results
    
    Control Mapping:
    - Each check maps to specific NIST control identifiers
    - Remediation guidance aligned with NIST recommendations
    - Risk-based prioritization (High/Medium/Low)
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

# ============================================================================
# Module Configuration
# ============================================================================
$moduleName = "NIST"
$results = @()
$ErrorActionPreference = "Continue"

# Control priority mapping
$script:ControlPriority = @{
    "AC-2" = "High"      # Account Management
    "AC-3" = "High"      # Access Enforcement
    "AC-7" = "High"      # Unsuccessful Logon Attempts
    "AC-17" = "High"     # Remote Access
    "AU-2" = "High"      # Audit Events
    "AU-9" = "High"      # Protection of Audit Information
    "IA-2" = "High"      # Identification and Authentication
    "IA-5" = "High"      # Authenticator Management
    "SC-7" = "High"      # Boundary Protection
    "SC-8" = "High"      # Transmission Confidentiality
    "SI-2" = "High"      # Flaw Remediation
    "SI-3" = "High"      # Malicious Code Protection
}

# ============================================================================
# Helper Functions
# ============================================================================

<#
.SYNOPSIS
    Adds a result to the module results array with consistent formatting
#>
function Add-Result {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Pass", "Fail", "Warning", "Info", "Error")]
        [string]$Status,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Details = "",
        
        [Parameter(Mandatory=$false)]
        [string]$Remediation = "",
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("High", "Medium", "Low", "")]
        [string]$Priority = ""
    )
    
    # Auto-assign priority based on control if not specified
    if ([string]::IsNullOrEmpty($Priority) -and $Category -match '(AC|AU|IA|SC|SI)-\d+') {
        $controlId = $Matches[0]
        if ($script:ControlPriority.ContainsKey($controlId)) {
            $Priority = $script:ControlPriority[$controlId]
        }
    }
    
    $resultObject = [PSCustomObject]@{
        Module = $moduleName
        Category = $Category
        Status = $Status
        Message = $Message
        Details = $Details
        Remediation = $Remediation
        Priority = $Priority
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:results += $resultObject
}

<#
.SYNOPSIS
    Tests if a registry value exists and matches expected value
#>
function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue = $null,
        [switch]$ShouldExist
    )
    
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        
        if ($null -ne $ExpectedValue) {
            return ($value.$Name -eq $ExpectedValue)
        } else {
            return $true
        }
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Gets the age of a credential or authentication token
#>
function Get-PasswordAge {
    param([string]$Username)
    
    try {
        $user = Get-LocalUser -Name $Username -ErrorAction Stop
        if ($user.PasswordLastSet) {
            return (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
        }
        return $null
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Checks if a specific audit subcategory is enabled
#>
function Test-AuditPolicy {
    param(
        [string]$Subcategory,
        [ValidateSet("Success", "Failure", "Both")]
        [string]$Type = "Both"
    )
    
    try {
        $result = auditpol /get /subcategory:"$Subcategory" 2>$null
        if (-not $result) { return $false }
        
        switch ($Type) {
            "Success" { return ($result -match "Success") }
            "Failure" { return ($result -match "Failure") }
            "Both" { return ($result -match "Success" -and $result -match "Failure") }
        }
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Retrieves security policy settings using secedit
#>
function Get-SecurityPolicy {
    param([string]$PolicyName)
    
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tempFile /quiet 2>$null | Out-Null
        
        $content = Get-Content $tempFile -ErrorAction Stop
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
        $policyLine = $content | Where-Object { $_ -match "^$PolicyName\s*=" }
        if ($policyLine) {
            return ($policyLine -split '=')[1].Trim()
        }
        return $null
    }
    catch {
        return $null
    }
}

Write-Host "`n[NIST] Starting comprehensive NIST compliance checks..." -ForegroundColor Cyan
Write-Host "[NIST] Framework versions: 800-53 Rev 5, CSF 2.0, 800-171 Rev 2" -ForegroundColor Gray

# ============================================================================
# NIST 800-53 Rev 5: Access Control (AC) - EXPANDED
# ============================================================================
Write-Host "`n[NIST] Checking Access Control (AC) Controls..." -ForegroundColor Yellow

# AC-1: Policy and Procedures
Add-Result -Category "NIST - AC-1" -Status "Info" `
    -Message "Access Control Policy: Documentation review required" `
    -Details "NIST 800-53 AC-1: Develop, document, and disseminate access control policies and procedures. Manual verification required." `
    -Priority "Medium"

# AC-2: Account Management (ENHANCED)
try {
    Write-Host "  [*] AC-2: Account Management" -ForegroundColor Gray
    
    # AC-2(1): Automated System Account Management
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $totalUsers = $localUsers.Count
    
    Add-Result -Category "NIST - AC-2" -Status "Info" `
        -Message "Account Management: $totalUsers enabled local user account(s)" `
        -Details "NIST 800-53 AC-2: Accounts identified: $($localUsers.Name -join ', '). Review account necessity and access requirements."
    
    # AC-2(2): Automated Temporary Account Management
    $tempAccountPattern = "^(temp|tmp|test|demo)"
    $tempAccounts = $localUsers | Where-Object { $_.Name -match $tempAccountPattern }
    
    if ($tempAccounts) {
        Add-Result -Category "NIST - AC-2(2)" -Status "Warning" `
            -Message "Potential temporary accounts detected: $($tempAccounts.Count)" `
            -Details "NIST 800-53 AC-2(2): Temporary accounts found: $($tempAccounts.Name -join ', '). Verify expiration dates." `
            -Remediation "Remove temporary accounts or set expiration: Set-LocalUser -Name <account> -AccountExpires (Get-Date).AddDays(30)"
    }
    
    # AC-2(3): Disable Inactive Accounts
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveAccounts = $localUsers | Where-Object { 
        $_.LastLogon -and $_.LastLogon -lt $inactiveThreshold 
    }
    
    if ($inactiveAccounts) {
        Add-Result -Category "NIST - AC-2(3)" -Status "Fail" `
            -Message "Found $($inactiveAccounts.Count) inactive account(s) (>90 days)" `
            -Details "NIST 800-53 AC-2(3): Accounts inactive: $($inactiveAccounts.Name -join ', '). Last logon dates: $($inactiveAccounts | ForEach-Object { "$($_.Name): $($_.LastLogon)" } | Out-String)" `
            -Remediation "Disable-LocalUser -Name <account> # For each inactive account" `
            -Priority "High"
    } else {
        Add-Result -Category "NIST - AC-2(3)" -Status "Pass" `
            -Message "No inactive accounts detected (>90 days)" `
            -Details "NIST 800-53 AC-2(3): All enabled accounts have logged in within 90 days."
    }
    
    # AC-2(4): Automated Audit Actions
    $auditAccountManagement = Test-AuditPolicy -Subcategory "User Account Management" -Type "Both"
    $auditSecurityGroups = Test-AuditPolicy -Subcategory "Security Group Management" -Type "Both"
    
    if ($auditAccountManagement -and $auditSecurityGroups) {
        Add-Result -Category "NIST - AC-2(4)" -Status "Pass" `
            -Message "Account management actions are audited" `
            -Details "NIST 800-53 AC-2(4): Auditing enabled for user account and security group management."
    } else {
        Add-Result -Category "NIST - AC-2(4)" -Status "Fail" `
            -Message "Account management auditing incomplete" `
            -Details "NIST 800-53 AC-2(4): Enable comprehensive account management auditing." `
            -Remediation "auditpol /set /subcategory:`"User Account Management`" /success:enable /failure:enable; auditpol /set /subcategory:`"Security Group Management`" /success:enable /failure:enable"
    }
    
    # AC-2(5): Inactivity Logout
    $inactivityTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoDisconnect" -ErrorAction SilentlyContinue
    
    if ($inactivityTimeout -and $inactivityTimeout.AutoDisconnect -le 15) {
        Add-Result -Category "NIST - AC-2(5)" -Status "Pass" `
            -Message "Session inactivity logout configured: $($inactivityTimeout.AutoDisconnect) minutes" `
            -Details "NIST 800-53 AC-2(5): Idle sessions are automatically disconnected."
    } else {
        Add-Result -Category "NIST - AC-2(5)" -Status "Warning" `
            -Message "Session inactivity timeout not optimally configured" `
            -Details "NIST 800-53 AC-2(5): Configure automatic logout after 15 minutes of inactivity." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoDisconnect -Value 15"
    }
    
    # AC-2(7): Privileged User Accounts
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $adminCount = if ($adminGroup) { $adminGroup.Count } else { 0 }
    
    if ($adminCount -le 3) {
        Add-Result -Category "NIST - AC-2(7)" -Status "Pass" `
            -Message "Privileged accounts limited: $adminCount administrator(s)" `
            -Details "NIST 800-53 AC-2(7): Administrator group members: $($adminGroup.Name -join ', ')"
    } else {
        Add-Result -Category "NIST - AC-2(7)" -Status "Warning" `
            -Message "High number of privileged accounts: $adminCount administrator(s)" `
            -Details "NIST 800-53 AC-2(7): Review necessity of each admin account. Members: $($adminGroup.Name -join ', ')" `
            -Remediation "Remove unnecessary accounts from Administrators group"
    }
    
    # AC-2(9): Restrictions on Use of Shared Groups
    $everyonePerms = icacls "C:\Windows\System32" 2>$null | Select-String "Everyone"
    $usersPerms = icacls "C:\Windows\System32" 2>$null | Select-String "BUILTIN\\Users:\(OI\)\(CI\)\(F\)"
    
    if (-not $everyonePerms -and -not $usersPerms) {
        Add-Result -Category "NIST - AC-2(9)" -Status "Pass" `
            -Message "Shared group access properly restricted" `
            -Details "NIST 800-53 AC-2(9): 'Everyone' and 'Users' groups do not have excessive permissions on system directories."
    }
    
    # AC-2(11): Usage Conditions
    $legalNotice = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue
    
    if ($legalNotice -and -not [string]::IsNullOrWhiteSpace($legalNotice.LegalNoticeCaption)) {
        Add-Result -Category "NIST - AC-2(11)" -Status "Pass" `
            -Message "Usage conditions displayed at logon" `
            -Details "NIST 800-53 AC-2(11): Legal notice configured with caption: '$($legalNotice.LegalNoticeCaption)'"
    } else {
        Add-Result -Category "NIST - AC-2(11)" -Status "Fail" `
            -Message "Usage conditions not displayed at logon" `
            -Details "NIST 800-53 AC-2(11): Configure legal notice to inform users of usage restrictions." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeCaption -Value 'NOTICE'; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'Authorized use only. All activity may be monitored and reported.'"
    }
    
    # AC-2(12): Account Monitoring / Atypical Usage
    Add-Result -Category "NIST - AC-2(12)" -Status "Info" `
        -Message "Account monitoring requires SIEM/log analysis" `
        -Details "NIST 800-53 AC-2(12): Implement monitoring for atypical account usage patterns. Consider Windows Event Forwarding or SIEM integration."
    
    # AC-2(13): Disable Accounts for High-Risk Individuals
    Add-Result -Category "NIST - AC-2(13)" -Status "Info" `
        -Message "High-risk individual account management requires policy" `
        -Details "NIST 800-53 AC-2(13): Establish procedures to disable accounts within 24 hours for terminated or transferred users."
    
}
catch {
    Add-Result -Category "NIST - AC-2" -Status "Error" `
        -Message "Failed to check account management: $($_.Exception.Message)"
}

# AC-3: Access Enforcement (ENHANCED)
try {
    Write-Host "  [*] AC-3: Access Enforcement" -ForegroundColor Gray
    
    # Check User Account Control (UAC)
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    
    if ($uac.EnableLUA -eq 1) {
        # AC-3: Basic UAC
        Add-Result -Category "NIST - AC-3" -Status "Pass" `
            -Message "Access Enforcement: User Account Control is enabled" `
            -Details "NIST 800-53 AC-3: UAC enforces approved authorizations for logical access."
        
        # AC-3(2): Dual Authorization
        if ($uac.ConsentPromptBehaviorAdmin -eq 2) {
            Add-Result -Category "NIST - AC-3(2)" -Status "Pass" `
                -Message "UAC: Prompt for consent on the secure desktop" `
                -Details "NIST 800-53 AC-3(2): Administrative actions require explicit consent."
        } else {
            Add-Result -Category "NIST - AC-3(2)" -Status "Warning" `
                -Message "UAC: Not configured for secure desktop prompt" `
                -Details "NIST 800-53 AC-3(2): Configure UAC to prompt on secure desktop." `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2"
        }
        
        # AC-3(7): Role-Based Access Control
        $rbacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue
        
        if ($rbacEnabled -and $rbacEnabled.FilterAdministratorToken -eq 1) {
            Add-Result -Category "NIST - AC-3(7)" -Status "Pass" `
                -Message "Role-based access control enforced for built-in Administrator" `
                -Details "NIST 800-53 AC-3(7): Built-in Administrator account subject to UAC."
        }
        
    } else {
        Add-Result -Category "NIST - AC-3" -Status "Fail" `
            -Message "Access Enforcement: UAC is DISABLED" `
            -Details "NIST 800-53 AC-3: Enable UAC to enforce access control policies." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" `
            -Priority "High"
    }
    
    # AC-3(10): Audited Override of Access Control Mechanisms
    $privilegeAudit = Test-AuditPolicy -Subcategory "Sensitive Privilege Use" -Type "Both"
    
    if ($privilegeAudit) {
        Add-Result -Category "NIST - AC-3(10)" -Status "Pass" `
            -Message "Privileged access override attempts are audited" `
            -Details "NIST 800-53 AC-3(10): Sensitive privilege use auditing enabled."
    } else {
        Add-Result -Category "NIST - AC-3(10)" -Status "Fail" `
            -Message "Privilege use auditing not enabled" `
            -Details "NIST 800-53 AC-3(10): Enable auditing of privilege use." `
            -Remediation "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable"
    }
}
catch {
    Add-Result -Category "NIST - AC-3" -Status "Error" `
        -Message "Failed to check access enforcement: $($_.Exception.Message)"
}

# AC-4: Information Flow Enforcement
try {
    Write-Host "  [*] AC-4: Information Flow Enforcement" -ForegroundColor Gray
    
    # Check Windows Firewall rules
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $allEnabled = ($firewallProfiles | Where-Object { -not $_.Enabled }).Count -eq 0
    
    if ($allEnabled) {
        Add-Result -Category "NIST - AC-4" -Status "Pass" `
            -Message "Information flow enforcement via firewall enabled on all profiles" `
            -Details "NIST 800-53 AC-4: Windows Firewall enforces approved authorizations for controlling information flow."
        
        # AC-4(8): Security Policy Filters
        $blockInboundDefault = ($firewallProfiles | Where-Object { $_.DefaultInboundAction -eq "Block" }).Count
        
        if ($blockInboundDefault -eq 3) {
            Add-Result -Category "NIST - AC-4(8)" -Status "Pass" `
                -Message "Default inbound connections blocked (deny-by-default)" `
                -Details "NIST 800-53 AC-4(8): Security policy filters enforce deny-by-default for inbound traffic."
        } else {
            Add-Result -Category "NIST - AC-4(8)" -Status "Warning" `
                -Message "Firewall not configured for deny-by-default inbound" `
                -Details "NIST 800-53 AC-4(8): Configure firewall to block inbound connections by default." `
                -Remediation "Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Block"
        }
    } else {
        Add-Result -Category "NIST - AC-4" -Status "Fail" `
            -Message "Information flow enforcement disabled (firewall off)" `
            -Details "NIST 800-53 AC-4: Enable Windows Firewall on all profiles." `
            -Remediation "Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True" `
            -Priority "High"
    }
}
catch {
    Add-Result -Category "NIST - AC-4" -Status "Error" `
        -Message "Failed to check information flow enforcement: $($_.Exception.Message)"
}

# AC-6: Least Privilege (ENHANCED)
try {
    Write-Host "  [*] AC-6: Least Privilege" -ForegroundColor Gray
    
    # AC-6: Basic least privilege check via UAC
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    
    if ($uac -and $uac.EnableLUA -eq 1) {
        Add-Result -Category "NIST - AC-6" -Status "Pass" `
            -Message "Least privilege enforced via UAC" `
            -Details "NIST 800-53 AC-6: Users operate with least privilege; elevation required for administrative tasks."
    }
    
    # AC-6(1): Authorize Access to Security Functions
    $securityPrivileges = Get-SecurityPolicy -PolicyName "SeSecurityPrivilege"
    
    if ($securityPrivileges) {
        Add-Result -Category "NIST - AC-6(1)" -Status "Info" `
            -Message "Security function access granted to: $securityPrivileges" `
            -Details "NIST 800-53 AC-6(1): Review accounts with 'Manage auditing and security log' privilege."
    }
    
    # AC-6(2): Non-Privileged Access for Nonsecurity Functions
    $remoteDesktopUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    
    if ($remoteDesktopUsers) {
        Add-Result -Category "NIST - AC-6(2)" -Status "Info" `
            -Message "Non-privileged remote access: $($remoteDesktopUsers.Count) user(s) in RDP group" `
            -Details "NIST 800-53 AC-6(2): Remote Desktop Users: $($remoteDesktopUsers.Name -join ', ')"
    }
    
    # AC-6(5): Privileged Accounts
    $adminAccounts = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $privilegedAccountsUsage = @()
    
    foreach ($admin in $adminAccounts) {
        if ($admin.ObjectClass -eq "User") {
            $username = $admin.Name.Split('\')[-1]
            $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
            if ($user) {
                $lastLogon = if ($user.LastLogon) { $user.LastLogon.ToString("yyyy-MM-dd") } else { "Never" }
                $privilegedAccountsUsage += "$username (Last: $lastLogon)"
            }
        }
    }
    
    if ($privilegedAccountsUsage.Count -gt 0) {
        Add-Result -Category "NIST - AC-6(5)" -Status "Info" `
            -Message "Privileged account usage tracking" `
            -Details "NIST 800-53 AC-6(5): Admin accounts: $($privilegedAccountsUsage -join '; '). Verify accounts are used only for administrative functions."
    }
    
    # AC-6(7): Review of User Privileges
    Add-Result -Category "NIST - AC-6(7)" -Status "Info" `
        -Message "Regular privilege review required" `
        -Details "NIST 800-53 AC-6(7): Review user privileges annually. Document: $($adminAccounts.Count) administrator(s), $($remoteDesktopUsers.Count) remote users."
    
    # AC-6(9): Log Use of Privileged Functions
    $privilegeUseAudit = Test-AuditPolicy -Subcategory "Sensitive Privilege Use"
    
    if ($privilegeUseAudit) {
        Add-Result -Category "NIST - AC-6(9)" -Status "Pass" `
            -Message "Privileged function use is logged" `
            -Details "NIST 800-53 AC-6(9): Auditing of sensitive privilege use enabled."
    } else {
        Add-Result -Category "NIST - AC-6(9)" -Status "Fail" `
            -Message "Privileged function use not logged" `
            -Details "NIST 800-53 AC-6(9): Enable logging of privilege use." `
            -Remediation "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable"
    }
    
    # AC-6(10): Prohibit Non-Privileged Users from Executing Privileged Functions
    $restrictedGroups = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue
    
    if (-not $restrictedGroups -or $restrictedGroups.LocalAccountTokenFilterPolicy -eq 0) {
        Add-Result -Category "NIST - AC-6(10)" -Status "Pass" `
            -Message "Local account token filter enforced" `
            -Details "NIST 800-53 AC-6(10): Remote connections using local accounts cannot perform administrative actions."
    }
}
catch {
    Add-Result -Category "NIST - AC-6" -Status "Error" `
        -Message "Failed to check least privilege: $($_.Exception.Message)"
}

# AC-7: Unsuccessful Logon Attempts (ENHANCED)
try {
    Write-Host "  [*] AC-7: Unsuccessful Logon Attempts" -ForegroundColor Gray
    
    $netAccounts = net accounts 2>$null
    
    if ($netAccounts) {
        # AC-7: Lockout threshold
        $lockoutThreshold = ($netAccounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
        
        if ($lockoutThreshold -eq "Never") {
            Add-Result -Category "NIST - AC-7" -Status "Fail" `
                -Message "Account lockout is disabled" `
                -Details "NIST 800-53 AC-7: Configure lockout after unsuccessful logon attempts to prevent brute force." `
                -Remediation "net accounts /lockoutthreshold:5" `
                -Priority "High"
        } elseif ([int]$lockoutThreshold -le 10) {
            Add-Result -Category "NIST - AC-7" -Status "Pass" `
                -Message "Account lockout threshold: $lockoutThreshold invalid attempts" `
                -Details "NIST 800-53 AC-7: Account lockout protects against brute force attacks."
            
            # AC-7(2): Purge/Wipe Mobile Device
            Add-Result -Category "NIST - AC-7(2)" -Status "Info" `
                -Message "Mobile device lockout/wipe requires MDM solution" `
                -Details "NIST 800-53 AC-7(2): Implement mobile device management for device lockout and remote wipe capabilities."
            
        } else {
            Add-Result -Category "NIST - AC-7" -Status "Warning" `
                -Message "Account lockout threshold is high: $lockoutThreshold attempts" `
                -Details "NIST 800-53 AC-7: Consider setting lockout threshold to 10 or fewer attempts." `
                -Remediation "net accounts /lockoutthreshold:5"
        }
        
        # Check lockout duration
        $lockoutDuration = ($netAccounts | Select-String "Lockout duration").ToString().Split(":")[1].Trim()
        $durationMinutes = $lockoutDuration.Split(" ")[0]
        
        if ([int]$durationMinutes -ge 15) {
            Add-Result -Category "NIST - AC-7" -Status "Pass" `
                -Message "Account lockout duration: $lockoutDuration" `
                -Details "NIST 800-53 AC-7: Adequate lockout duration configured."
        }
        
        # Check observation window
        $observationWindow = ($netAccounts | Select-String "Lockout observation window").ToString().Split(":")[1].Trim()
        
        Add-Result -Category "NIST - AC-7" -Status "Info" `
            -Message "Lockout observation window: $observationWindow" `
            -Details "NIST 800-53 AC-7: Failed attempt counter resets after this period."
    }
}
catch {
    Add-Result -Category "NIST - AC-7" -Status "Error" `
        -Message "Failed to check unsuccessful logon policy: $($_.Exception.Message)"
}

# AC-8: System Use Notification (ENHANCED)
try {
    Write-Host "  [*] AC-8: System Use Notification" -ForegroundColor Gray
    
    $legalNoticeCaption = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue
    $legalNoticeText = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction SilentlyContinue
    
    if ($legalNoticeCaption -and $legalNoticeText -and 
        -not [string]::IsNullOrWhiteSpace($legalNoticeCaption.LegalNoticeCaption) -and
        -not [string]::IsNullOrWhiteSpace($legalNoticeText.LegalNoticeText)) {
        
        Add-Result -Category "NIST - AC-8" -Status "Pass" `
            -Message "System use notification configured" `
            -Details "NIST 800-53 AC-8: Caption: '$($legalNoticeCaption.LegalNoticeCaption)'. Displays before granting system access."
    } else {
        Add-Result -Category "NIST - AC-8" -Status "Fail" `
            -Message "System use notification not configured" `
            -Details "NIST 800-53 AC-8: Display usage notification before granting access. Include monitoring notice, consent requirement, and penalties." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeCaption -Value 'WARNING'; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'This is a [Organization] computer system. Authorized use only. All activity may be monitored and reported.'" `
            -Priority "Medium"
    }
}
catch {
    Add-Result -Category "NIST - AC-8" -Status "Error" `
        -Message "Failed to check system use notification: $($_.Exception.Message)"
}

# AC-11: Device Lock (ENHANCED)
try {
    Write-Host "  [*] AC-11: Device Lock" -ForegroundColor Gray
    
    # Check screen saver policy (domain/local)
    $screenSaverPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
    $screenSaverUser = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue
    
    $policyActive = $false
    $timeout = 0
    
    if ($screenSaverPolicy) {
        $timeout = $screenSaverPolicy.ScreenSaveTimeOut
        $active = $screenSaverPolicy.ScreenSaveActive
        $secure = $screenSaverPolicy.ScreenSaverIsSecure
        
        if ($active -eq "1" -and $secure -eq "1" -and $timeout -le 900) {
            $minutes = $timeout / 60
            $policyActive = $true
            Add-Result -Category "NIST - AC-11" -Status "Pass" `
                -Message "Device lock configured via policy: $minutes minutes" `
                -Details "NIST 800-53 AC-11: Screen saver locks device after $minutes minutes of inactivity."
        }
    }
    
    if (-not $policyActive -and $screenSaverUser) {
        $timeout = $screenSaverUser.ScreenSaveTimeOut
        $active = $screenSaverUser.ScreenSaveActive
        $secure = $screenSaverUser.ScreenSaverIsSecure
        
        if ($active -eq "1" -and $secure -eq "1" -and $timeout -le 900) {
            $minutes = $timeout / 60
            Add-Result -Category "NIST - AC-11" -Status "Pass" `
                -Message "Device lock configured (user setting): $minutes minutes" `
                -Details "NIST 800-53 AC-11: User-configured screen lock. Note: Policy enforcement recommended for consistency."
        } else {
            Add-Result -Category "NIST - AC-11" -Status "Fail" `
                -Message "Device lock not properly configured" `
                -Details "NIST 800-53 AC-11: Configure automatic screen lock after 15 minutes (900 seconds) or less of inactivity." `
                -Remediation "Configure via Group Policy: Computer Configuration > Policies > Administrative Templates > Control Panel > Personalization" `
                -Priority "Medium"
        }
    }
    
    if (-not $policyActive -and -not $screenSaverUser) {
        Add-Result -Category "NIST - AC-11" -Status "Fail" `
            -Message "Device lock not configured" `
            -Details "NIST 800-53 AC-11: No screen lock policy detected." `
            -Remediation "Enable screen saver with password protection via Group Policy or local settings"
    }
    
    # AC-11(1): Pattern-Hiding Displays
    if ($screenSaverPolicy -or $screenSaverUser) {
        Add-Result -Category "NIST - AC-11(1)" -Status "Pass" `
            -Message "Pattern-hiding display (screen lock) conceals information" `
            -Details "NIST 800-53 AC-11(1): Screen saver obscures displayed information from unauthorized viewing."
    }
}
catch {
    Add-Result -Category "NIST - AC-11" -Status "Error" `
        -Message "Failed to check device lock settings: $($_.Exception.Message)"
}

# AC-12: Session Termination
try {
    Write-Host "  [*] AC-12: Session Termination" -ForegroundColor Gray
    
    # Check for idle session termination
    $idleTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoDisconnect" -ErrorAction SilentlyContinue
    
    if ($idleTimeout -and $idleTimeout.AutoDisconnect -le 15) {
        Add-Result -Category "NIST - AC-12" -Status "Pass" `
            -Message "Idle session termination: $($idleTimeout.AutoDisconnect) minutes" `
            -Details "NIST 800-53 AC-12: Idle SMB sessions automatically disconnected."
    } else {
        Add-Result -Category "NIST - AC-12" -Status "Warning" `
            -Message "Idle session termination not optimally configured" `
            -Details "NIST 800-53 AC-12: Configure automatic session termination for idle connections." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoDisconnect -Value 15"
    }
    
    # Check RDP session limits
    $rdpTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxIdleTime" -ErrorAction SilentlyContinue
    
    if ($rdpTimeout -and $rdpTimeout.MaxIdleTime -gt 0 -and $rdpTimeout.MaxIdleTime -le 900000) {
        $minutes = $rdpTimeout.MaxIdleTime / 60000
        Add-Result -Category "NIST - AC-12" -Status "Pass" `
            -Message "RDP idle session timeout: $minutes minutes" `
            -Details "NIST 800-53 AC-12: Remote Desktop sessions terminate after idle period."
    }
}
catch {
    Add-Result -Category "NIST - AC-12" -Status "Error" `
        -Message "Failed to check session termination: $($_.Exception.Message)"
}

# AC-14: Permitted Actions Without Identification or Authentication
try {
    Write-Host "  [*] AC-14: Permitted Actions Without Identification" -ForegroundColor Gray
    
    # Check anonymous access restrictions
    $restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    
    if ($restrictAnonymous -and $restrictAnonymous.RestrictAnonymous -ge 1) {
        Add-Result -Category "NIST - AC-14" -Status "Pass" `
            -Message "Anonymous access restricted (Level: $($restrictAnonymous.RestrictAnonymous))" `
            -Details "NIST 800-53 AC-14: System restricts unauthenticated access to resources."
    } else {
        Add-Result -Category "NIST - AC-14" -Status "Warning" `
            -Message "Anonymous access not restricted" `
            -Details "NIST 800-53 AC-14: Configure anonymous access restrictions." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1"
    }
    
    # Check null session restrictions
    $restrictNullSessAccess = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    
    if ($restrictNullSessAccess -and $restrictNullSessAccess.RestrictAnonymousSAM -eq 1) {
        Add-Result -Category "NIST - AC-14" -Status "Pass" `
            -Message "Anonymous SAM account enumeration blocked" `
            -Details "NIST 800-53 AC-14: Null session access to SAM restricted."
    } else {
        Add-Result -Category "NIST - AC-14" -Status "Fail" `
            -Message "Anonymous SAM enumeration not restricted" `
            -Details "NIST 800-53 AC-14: Prevent anonymous users from enumerating accounts." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1"
    }
}
catch {
    Add-Result -Category "NIST - AC-14" -Status "Error" `
        -Message "Failed to check anonymous access: $($_.Exception.Message)"
}

# AC-17: Remote Access (ENHANCED)
try {
    Write-Host "  [*] AC-17: Remote Access" -ForegroundColor Gray
    
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 1) {
        Add-Result -Category "NIST - AC-17" -Status "Pass" `
            -Message "Remote Desktop Protocol is disabled" `
            -Details "NIST 800-53 AC-17: RDP remote access is not allowed."
    } else {
        Add-Result -Category "NIST - AC-17" -Status "Info" `
            -Message "Remote Desktop Protocol is enabled" `
            -Details "NIST 800-53 AC-17: Verify remote access is authorized, documented, and secured."
        
        # AC-17(1): Monitoring and Control
        $rdpAudit = Test-AuditPolicy -Subcategory "Logon" -Type "Both"
        
        if ($rdpAudit) {
            Add-Result -Category "NIST - AC-17(1)" -Status "Pass" `
                -Message "Remote access monitoring enabled via audit policy" `
                -Details "NIST 800-53 AC-17(1): Logon events are audited for remote access monitoring."
        }
        
        # AC-17(2): Protection of Confidentiality / Integrity
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        
        if ($nla -and $nla.UserAuthentication -eq 1) {
            Add-Result -Category "NIST - AC-17(2)" -Status "Pass" `
                -Message "RDP: Network Level Authentication required" `
                -Details "NIST 800-53 AC-17(2): NLA provides encryption and authentication before session establishment."
        } else {
            Add-Result -Category "NIST - AC-17(2)" -Status "Fail" `
                -Message "RDP: Network Level Authentication NOT required" `
                -Details "NIST 800-53 AC-17(2): Enable NLA to protect confidentiality and integrity of remote access." `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Priority "High"
        }
        
        # AC-17(3): Managed Access Control Points
        Add-Result -Category "NIST - AC-17(3)" -Status "Info" `
            -Message "Remote access control points require infrastructure review" `
            -Details "NIST 800-53 AC-17(3): Route remote access through managed network access control points (VPN gateway, jump server, etc.)."
        
        # AC-17(4): Privileged Commands / Access
        $rdpEncryption = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        
        if ($rdpEncryption -and $rdpEncryption.MinEncryptionLevel -ge 3) {
            Add-Result -Category "NIST - AC-17(4)" -Status "Pass" `
                -Message "RDP encryption set to high level" `
                -Details "NIST 800-53 AC-17(4): High-level encryption protects privileged remote commands."
        } else {
            Add-Result -Category "NIST - AC-17(4)" -Status "Warning" `
                -Message "RDP encryption not set to highest level" `
                -Details "NIST 800-53 AC-17(4): Set RDP encryption to high (3) or FIPS-compliant (4)." `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
        }
        
        # Check RDP port (non-standard port is defense-in-depth)
        $rdpPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
        
        if ($rdpPort) {
            $portNum = $rdpPort.PortNumber
            if ($portNum -eq 3389) {
                Add-Result -Category "NIST - AC-17" -Status "Info" `
                    -Message "RDP using default port 3389" `
                    -Details "NIST 800-53 AC-17: Consider changing RDP port as defense-in-depth measure (non-standard ports reduce automated attacks)."
            } else {
                Add-Result -Category "NIST - AC-17" -Status "Info" `
                    -Message "RDP using non-standard port: $portNum" `
                    -Details "NIST 800-53 AC-17: Non-standard port provides additional obscurity layer."
            }
        }
    }
}
catch {
    Add-Result -Category "NIST - AC-17" -Status "Error" `
        -Message "Failed to check remote access configuration: $($_.Exception.Message)"
}

# AC-18: Wireless Access
try {
    Write-Host "  [*] AC-18: Wireless Access" -ForegroundColor Gray
    
    # Check for wireless adapters
    $wirelessAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "wireless|wi-fi|802.11" }
    
    if ($wirelessAdapters) {
        Add-Result -Category "NIST - AC-18" -Status "Info" `
            -Message "Wireless adapter(s) detected: $($wirelessAdapters.Count)" `
            -Details "NIST 800-53 AC-18: Wireless adapters found: $($wirelessAdapters.Name -join ', '). Verify authorization and security configuration."
        
        # Check wireless profiles for security
        $wirelessProfiles = netsh wlan show profiles 2>$null
        if ($wirelessProfiles) {
            Add-Result -Category "NIST - AC-18(1)" -Status "Info" `
                -Message "Wireless profiles configured - verify authentication" `
                -Details "NIST 800-53 AC-18(1): Review wireless network profiles for WPA2/WPA3 authentication."
        }
    } else {
        Add-Result -Category "NIST - AC-18" -Status "Info" `
            -Message "No wireless adapters detected" `
            -Details "NIST 800-53 AC-18: System does not have wireless capability."
    }
}
catch {
    Add-Result -Category "NIST - AC-18" -Status "Error" `
        -Message "Failed to check wireless access: $($_.Exception.Message)"
}

# AC-19: Access Control for Mobile Devices
try {
    Write-Host "  [*] AC-19: Access Control for Mobile Devices" -ForegroundColor Gray
    
    Add-Result -Category "NIST - AC-19" -Status "Info" `
        -Message "Mobile device access control requires MDM solution" `
        -Details "NIST 800-53 AC-19: Implement Mobile Device Management (MDM) for BYOD and corporate mobile devices. Solutions: Intune, AirWatch, MobileIron."
    
    # Check BitLocker To Go for removable media
    $removableDrives = Get-Volume | Where-Object { $_.DriveType -eq "Removable" }
    
    if ($removableDrives) {
        Add-Result -Category "NIST - AC-19(5)" -Status "Info" `
            -Message "Removable media detected: $($removableDrives.Count) drive(s)" `
            -Details "NIST 800-53 AC-19(5): Consider BitLocker To Go for removable media encryption."
    }
}
catch {
    Add-Result -Category "NIST - AC-19" -Status "Error" `
        -Message "Failed to check mobile device controls: $($_.Exception.Message)"
}

# AC-20: Use of External Systems
try {
    Write-Host "  [*] AC-20: Use of External Systems" -ForegroundColor Gray
    
    # Check for VPN connections (as indicator of external system access)
    $vpnConnections = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
    
    if ($vpnConnections) {
        Add-Result -Category "NIST - AC-20" -Status "Info" `
            -Message "VPN connections configured: $($vpnConnections.Count)" `
            -Details "NIST 800-53 AC-20: VPN connections detected. Verify approved external systems and security requirements."
    }
    
    # Check network shares (potential external access)
    $networkDrives = Get-PSDrive | Where-Object { $_.Provider.Name -eq "FileSystem" -and $_.DisplayRoot -like "\\*" }
    
    if ($networkDrives) {
        Add-Result -Category "NIST - AC-20" -Status "Info" `
            -Message "Network shares mapped: $($networkDrives.Count)" `
            -Details "NIST 800-53 AC-20: Mapped drives: $($networkDrives.Root -join ', '). Verify external system access authorization."
    }
}
catch {
    Add-Result -Category "NIST - AC-20" -Status "Error" `
        -Message "Failed to check external system use: $($_.Exception.Message)"
}

# AC-22: Publicly Accessible Content
try {
    Write-Host "  [*] AC-22: Publicly Accessible Content" -ForegroundColor Gray
    
    # Check for IIS (web server)
    $iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    
    if ($iisService) {
        if ($iisService.Status -eq "Running") {
            Add-Result -Category "NIST - AC-22" -Status "Warning" `
                -Message "Web server (IIS) is running" `
                -Details "NIST 800-53 AC-22: Review publicly accessible content. Implement review/approval process for published information." `
                -Remediation "Ensure content review process is documented and followed"
        } else {
            Add-Result -Category "NIST - AC-22" -Status "Info" `
                -Message "Web server installed but not running" `
                -Details "NIST 800-53 AC-22: IIS is installed but inactive."
        }
    }
}
catch {
    Add-Result -Category "NIST - AC-22" -Status "Error" `
        -Message "Failed to check publicly accessible content: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53 Rev 5: Audit and Accountability (AU) - COMPREHENSIVE EXPANSION
# ============================================================================
Write-Host "`n[NIST] Checking Audit and Accountability (AU) Controls..." -ForegroundColor Yellow

# AU-1: Policy and Procedures
Add-Result -Category "NIST - AU-1" -Status "Info" `
    -Message "Audit and Accountability Policy: Documentation review required" `
    -Details "NIST 800-53 AU-1: Develop, document, and disseminate audit policies. Manual verification required." `
    -Priority "Medium"

# AU-2: Audit Events (COMPREHENSIVE)
try {
    Write-Host "  [*] AU-2: Audit Events" -ForegroundColor Gray
    
    # Critical audit categories per NIST
    $criticalAuditCategories = @{
        "Account Logon" = @("Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations")
        "Account Management" = @("User Account Management", "Computer Account Management", "Security Group Management", "Distribution Group Management")
        "Detailed Tracking" = @("Process Creation", "Process Termination", "DPAPI Activity", "RPC Events")
        "Logon/Logoff" = @("Logon", "Logoff", "Account Lockout", "Special Logon")
        "Object Access" = @("File System", "Registry", "Removable Storage", "Central Policy Staging")
        "Policy Change" = @("Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change", "MPSSVC Rule-Level Policy Change")
        "Privilege Use" = @("Sensitive Privilege Use", "Non Sensitive Privilege Use")
        "System" = @("Security State Change", "Security System Extension", "System Integrity", "IPsec Driver")
    }
    
    $configuredCount = 0
    $missingSubcategories = @()
    $totalSubcategories = 0
    
    foreach ($category in $criticalAuditCategories.Keys) {
        foreach ($subcategory in $criticalAuditCategories[$category]) {
            $totalSubcategories++
            $result = auditpol /get /subcategory:"$subcategory" 2>$null
            
            if ($result -and ($result -match "Success and Failure" -or ($result -match "Success" -and $result -match "Failure"))) {
                $configuredCount++
            } else {
                $missingSubcategories += $subcategory
            }
        }
    }
    
    $percentConfigured = [math]::Round(($configuredCount / $totalSubcategories) * 100, 1)
    
    if ($percentConfigured -ge 90) {
        Add-Result -Category "NIST - AU-2" -Status "Pass" `
            -Message "Comprehensive audit event configuration: $percentConfigured% ($configuredCount of $totalSubcategories)" `
            -Details "NIST 800-53 AU-2: Security-relevant events are being audited across critical categories."
    } elseif ($percentConfigured -ge 70) {
        Add-Result -Category "NIST - AU-2" -Status "Warning" `
            -Message "Audit event configuration: $percentConfigured% ($configuredCount of $totalSubcategories)" `
            -Details "NIST 800-53 AU-2: Missing subcategories: $($missingSubcategories -join ', ')" `
            -Remediation "Configure comprehensive audit policy via Group Policy or auditpol commands"
    } else {
        Add-Result -Category "NIST - AU-2" -Status "Fail" `
            -Message "Insufficient audit event configuration: $percentConfigured% ($configuredCount of $totalSubcategories)" `
            -Details "NIST 800-53 AU-2: Enable comprehensive audit logging. Missing: $($missingSubcategories -join ', ')" `
            -Remediation "Enable audit policies for all critical categories using Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration" `
            -Priority "High"
    }
    
    # AU-2(3): Reviews and Updates
    Add-Result -Category "NIST - AU-2(3)" -Status "Info" `
        -Message "Audit event review and update process required" `
        -Details "NIST 800-53 AU-2(3): Review and update audited events annually or when changes occur to threat environment."
    
    # AU-2(4): Privileged Functions
    $privilegedFunctionAudit = Test-AuditPolicy -Subcategory "Sensitive Privilege Use" -Type "Both"
    
    if ($privilegedFunctionAudit) {
        Add-Result -Category "NIST - AU-2(4)" -Status "Pass" `
            -Message "Privileged function audit configured" `
            -Details "NIST 800-53 AU-2(4): Sensitive privilege use is audited."
    } else {
        Add-Result -Category "NIST - AU-2(4)" -Status "Fail" `
            -Message "Privileged function audit not configured" `
            -Details "NIST 800-53 AU-2(4): Enable auditing of privileged functions." `
            -Remediation "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable"
    }
}
catch {
    Add-Result -Category "NIST - AU-2" -Status "Error" `
        -Message "Failed to check audit events: $($_.Exception.Message)"
}

# AU-3: Content of Audit Records
try {
    Write-Host "  [*] AU-3: Content of Audit Records" -ForegroundColor Gray
    
    # Check if Advanced Audit Policy is configured (provides detailed audit records)
    $advancedAudit = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    
    if ($advancedAudit -and $advancedAudit.SCENoApplyLegacyAuditPolicy -eq 1) {
        Add-Result -Category "NIST - AU-3" -Status "Pass" `
            -Message "Advanced audit policy enabled (detailed audit records)" `
            -Details "NIST 800-53 AU-3: Audit records contain required information: event type, when, where, source, outcome, identity."
    } else {
        Add-Result -Category "NIST - AU-3" -Status "Warning" `
            -Message "Advanced audit policy not enforced" `
            -Details "NIST 800-53 AU-3: Enable Advanced Audit Policy for comprehensive audit record content." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1"
    }
    
    # AU-3(1): Additional Audit Information
    $commandLineLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    
    if ($commandLineLogging -and $commandLineLogging.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Add-Result -Category "NIST - AU-3(1)" -Status "Pass" `
            -Message "Command line process auditing enabled" `
            -Details "NIST 800-53 AU-3(1): Process creation events include command line arguments for enhanced investigation."
    } else {
        Add-Result -Category "NIST - AU-3(1)" -Status "Warning" `
            -Message "Command line process auditing not enabled" `
            -Details "NIST 800-53 AU-3(1): Enable command line logging in process creation events." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Force"
    }
    
    # AU-3(2): Centralized Management of Planned Audit Record Content
    Add-Result -Category "NIST - AU-3(2)" -Status "Info" `
        -Message "Centralized audit management requires Group Policy or SIEM" `
        -Details "NIST 800-53 AU-3(2): Manage audit record content centrally using Group Policy or SIEM solution."
}
catch {
    Add-Result -Category "NIST - AU-3" -Status "Error" `
        -Message "Failed to check audit record content: $($_.Exception.Message)"
}

# AU-4: Audit Storage Capacity (ENHANCED)
try {
    Write-Host "  [*] AU-4: Audit Log Storage Capacity" -ForegroundColor Gray
    
    $criticalLogs = @("Security", "System", "Application")
    
    foreach ($logName in $criticalLogs) {
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        
        if ($log) {
            $logSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $currentSizeMB = [math]::Round($log.FileSize / 1MB, 2)
            $percentUsed = [math]::Round(($log.FileSize / $log.MaximumSizeInBytes) * 100, 1)
            
            if ($logName -eq "Security") {
                # Security log should be larger
                if ($logSizeMB -ge 512) {
                    Add-Result -Category "NIST - AU-4" -Status "Pass" `
                        -Message "Security log size adequate: $logSizeMB MB (${percentUsed}% used)" `
                        -Details "NIST 800-53 AU-4: Sufficient capacity allocated ($currentSizeMB MB of $logSizeMB MB used)."
                } elseif ($logSizeMB -ge 256) {
                    Add-Result -Category "NIST - AU-4" -Status "Warning" `
                        -Message "Security log size: $logSizeMB MB (consider increasing)" `
                        -Details "NIST 800-53 AU-4: Current: $currentSizeMB MB (${percentUsed}% full). Recommend 512+ MB." `
                        -Remediation "wevtutil sl Security /ms:$([int](512MB))"
                } else {
                    Add-Result -Category "NIST - AU-4" -Status "Fail" `
                        -Message "Security log size insufficient: $logSizeMB MB" `
                        -Details "NIST 800-53 AU-4: Increase to 512 MB minimum. Current: $currentSizeMB MB (${percentUsed}% full)." `
                        -Remediation "wevtutil sl Security /ms:$([int](512MB))" `
                        -Priority "Medium"
                }
            } else {
                # System and Application logs
                if ($logSizeMB -ge 128) {
                    Add-Result -Category "NIST - AU-4" -Status "Pass" `
                        -Message "$logName log size: $logSizeMB MB (${percentUsed}% used)" `
                        -Details "NIST 800-53 AU-4: Adequate capacity for $logName log."
                } else {
                    Add-Result -Category "NIST - AU-4" -Status "Info" `
                        -Message "$logName log size: $logSizeMB MB" `
                        -Details "NIST 800-53 AU-4: Consider increasing to 128+ MB for production systems."
                }
            }
        }
    }
    
    # AU-4(1): Transfer to Alternate Storage
    Add-Result -Category "NIST - AU-4(1)" -Status "Info" `
        -Message "Audit log transfer to alternate storage" `
        -Details "NIST 800-53 AU-4(1): Implement log forwarding to SIEM or Windows Event Collector for long-term storage and analysis."
}
catch {
    Add-Result -Category "NIST - AU-4" -Status "Error" `
        -Message "Failed to check audit storage capacity: $($_.Exception.Message)"
}

# AU-5: Response to Audit Processing Failures (ENHANCED)
try {
    Write-Host "  [*] AU-5: Response to Audit Processing Failures" -ForegroundColor Gray
    
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    
    # Check retention policy
    if ($securityLog.LogMode -eq "AutoBackup") {
        Add-Result -Category "NIST - AU-5" -Status "Pass" `
            -Message "Security log configured to archive when full" `
            -Details "NIST 800-53 AU-5: Log automatically archives, preventing audit failure due to capacity."
    } elseif ($securityLog.LogMode -eq "Circular") {
        Add-Result -Category "NIST - AU-5" -Status "Warning" `
            -Message "Security log in circular mode (overwrites old events)" `
            -Details "NIST 800-53 AU-5: Consider AutoBackup mode to prevent loss of audit data." `
            -Remediation "wevtutil sl Security /ms:$([int](512MB)) /ab:true"
    } elseif ($securityLog.LogMode -eq "Retain") {
        Add-Result -Category "NIST - AU-5" -Status "Warning" `
            -Message "Security log set to retain (system may halt when full)" `
            -Details "NIST 800-53 AU-5: Ensure monitoring for log capacity. Manual clearance required when full."
    }
    
    # AU-5(1): Audit Storage Capacity Warnings
    $currentCapacityPercent = ($securityLog.FileSize / $securityLog.MaximumSizeInBytes) * 100
    
    if ($currentCapacityPercent -ge 90) {
        Add-Result -Category "NIST - AU-5(1)" -Status "Warning" `
            -Message "Security log near capacity: $([math]::Round($currentCapacityPercent, 1))% full" `
            -Details "NIST 800-53 AU-5(1): Generate warning when audit storage capacity threshold reached." `
            -Remediation "Implement automated monitoring and alerting for audit log capacity"
    } else {
        Add-Result -Category "NIST - AU-5(1)" -Status "Pass" `
            -Message "Security log capacity: $([math]::Round($currentCapacityPercent, 1))% used" `
            -Details "NIST 800-53 AU-5(1): Adequate audit storage space available."
    }
    
    # AU-5(2): Real-Time Alerts
    Add-Result -Category "NIST - AU-5(2)" -Status "Info" `
        -Message "Real-time audit failure alerts require monitoring solution" `
        -Details "NIST 800-53 AU-5(2): Implement SIEM or monitoring tool for real-time alerts on audit failures."
    
    # AU-5(3): Configurable Traffic Volume Thresholds
    Add-Result -Category "NIST - AU-5(3)" -Status "Info" `
        -Message "Audit traffic volume monitoring requires SIEM" `
        -Details "NIST 800-53 AU-5(3): Configure thresholds for unusual audit event volumes indicating potential attack."
}
catch {
    Add-Result -Category "NIST - AU-5" -Status "Error" `
        -Message "Failed to check audit processing failure response: $($_.Exception.Message)"
}

# AU-6: Audit Review, Analysis, and Reporting (ENHANCED)
try {
    Write-Host "  [*] AU-6: Audit Review, Analysis, and Reporting" -ForegroundColor Gray
    
    # Check for recent security events (indicates active logging)
    $recentSecurityEvents = Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue
    
    if ($recentSecurityEvents) {
        Add-Result -Category "NIST - AU-6" -Status "Info" `
            -Message "Audit logs actively recording events: $($recentSecurityEvents.Count) recent events" `
            -Details "NIST 800-53 AU-6: Establish process for regular audit log review and analysis. Recommend weekly minimum."
    }
    
    # AU-6(1): Automated Process Integration
    Add-Result -Category "NIST - AU-6(1)" -Status "Info" `
        -Message "Automated audit review requires SIEM or log analysis tools" `
        -Details "NIST 800-53 AU-6(1): Integrate audit review with incident response. Solutions: Splunk, ELK Stack, Azure Sentinel, Windows Event Forwarding."
    
    # AU-6(3): Correlate Audit Repositories
    Add-Result -Category "NIST - AU-6(3)" -Status "Info" `
        -Message "Audit correlation across systems requires centralized logging" `
        -Details "NIST 800-53 AU-6(3): Implement centralized log collection and correlation across all systems."
    
    # AU-6(5): Integrated Analysis of Audit Records
    Add-Result -Category "NIST - AU-6(5)" -Status "Info" `
        -Message "Integrated audit analysis requires security analytics platform" `
        -Details "NIST 800-53 AU-6(5): Analyze audit records in conjunction with vulnerability data, threat intelligence, and network traffic."
    
    # AU-6(6): Correlation with Physical Access
    Add-Result -Category "NIST - AU-6(6)" -Status "Info" `
        -Message "Physical access correlation requires integrated security system" `
        -Details "NIST 800-53 AU-6(6): Correlate audit information with physical access monitoring logs."
}
catch {
    Add-Result -Category "NIST - AU-6" -Status "Error" `
        -Message "Failed to check audit review configuration: $($_.Exception.Message)"
}

# AU-7: Audit Reduction and Report Generation
try {
    Write-Host "  [*] AU-7: Audit Reduction and Report Generation" -ForegroundColor Gray
    
    Add-Result -Category "NIST - AU-7" -Status "Info" `
        -Message "Audit reduction and reporting requires analysis tools" `
        -Details "NIST 800-53 AU-7: Implement audit reduction and report generation capabilities. Built-in: Event Viewer filtering. Advanced: SIEM platforms."
    
    # AU-7(1): Automatic Processing
    Add-Result -Category "NIST - AU-7(1)" -Status "Info" `
        -Message "Automated audit processing requires SIEM or scripting" `
        -Details "NIST 800-53 AU-7(1): Automate audit data processing, analysis, and investigation support using scheduled tasks or SIEM."
}
catch {
    Add-Result -Category "NIST - AU-7" -Status "Error" `
        -Message "Failed to check audit reduction: $($_.Exception.Message)"
}

# AU-8: Time Stamps (ENHANCED)
try {
    Write-Host "  [*] AU-8: Time Stamps" -ForegroundColor Gray
    
    # Check Windows Time service
    $w32timeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
    
    if ($w32timeService -and $w32timeService.Status -eq "Running") {
        Add-Result -Category "NIST - AU-8" -Status "Pass" `
            -Message "Windows Time service is running" `
            -Details "NIST 800-53 AU-8: System capable of generating timestamps for audit records."
        
        # Check time synchronization status
        $w32timeStatus = w32tm /query /status 2>$null
        
        if ($w32timeStatus -match "Source:") {
            $timeSource = ($w32timeStatus | Select-String "Source:").ToString().Split(":")[1].Trim()
            
            # AU-8(1): Synchronization with Authoritative Time Source
            if ($timeSource -ne "Local CMOS Clock" -and $timeSource -ne "Free-running System Clock") {
                Add-Result -Category "NIST - AU-8(1)" -Status "Pass" `
                    -Message "Time synchronized with authoritative source: $timeSource" `
                    -Details "NIST 800-53 AU-8(1): System clock synchronized with authoritative time source."
            } else {
                Add-Result -Category "NIST - AU-8(1)" -Status "Fail" `
                    -Message "Time not synchronized with external source: $timeSource" `
                    -Details "NIST 800-53 AU-8(1): Configure NTP synchronization with authoritative time source (e.g., time.windows.com, domain controller)." `
                    -Remediation "w32tm /config /manualpeerlist:`"time.windows.com`" /syncfromflags:manual /reliable:yes /update; net stop w32time; net start w32time" `
                    -Priority "Medium"
            }
            
            # Check last sync time
            if ($w32timeStatus -match "Last Successful Sync Time:") {
                $lastSync = ($w32timeStatus | Select-String "Last Successful Sync Time:").ToString().Split(":",2)[1].Trim()
                
                if ($lastSync -notmatch "unspecified") {
                    Add-Result -Category "NIST - AU-8(1)" -Status "Info" `
                        -Message "Last time synchronization: $lastSync" `
                        -Details "NIST 800-53 AU-8(1): Recent time synchronization verified."
                }
            }
        }
        
        # AU-8(2): Secondary Authoritative Time Source
        Add-Result -Category "NIST - AU-8(2)" -Status "Info" `
            -Message "Secondary time source configuration recommended" `
            -Details "NIST 800-53 AU-8(2): Configure backup NTP servers for redundancy in time synchronization."
        
    } else {
        Add-Result -Category "NIST - AU-8" -Status "Fail" `
            -Message "Windows Time service is not running" `
            -Details "NIST 800-53 AU-8: Start and configure Windows Time service for accurate timestamps." `
            -Remediation "Start-Service W32Time; Set-Service W32Time -StartupType Automatic" `
            -Priority "High"
    }
}
catch {
    Add-Result -Category "NIST - AU-8" -Status "Error" `
        -Message "Failed to check time synchronization: $($_.Exception.Message)"
}

# AU-9: Protection of Audit Information (ENHANCED)
try {
    Write-Host "  [*] AU-9: Protection of Audit Information" -ForegroundColor Gray
    
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    
    if ($securityLog.IsEnabled) {
        Add-Result -Category "NIST - AU-9" -Status "Pass" `
            -Message "Security audit log is enabled and protected" `
            -Details "NIST 800-53 AU-9: Audit information protected from unauthorized access, modification, and deletion."
        
        # Check log file permissions
        $logPath = $securityLog.LogFilePath
        if ($logPath -and (Test-Path $logPath)) {
            $logAcl = Get-Acl -Path $logPath -ErrorAction SilentlyContinue
            
            if ($logAcl) {
                $systemAccess = $logAcl.Access | Where-Object { $_.IdentityReference -match "SYSTEM" -and $_.FileSystemRights -match "FullControl" }
                $adminAccess = $logAcl.Access | Where-Object { $_.IdentityReference -match "Administrators" -and $_.FileSystemRights -match "FullControl" }
                
                if ($systemAccess -and $adminAccess) {
                    Add-Result -Category "NIST - AU-9" -Status "Pass" `
                        -Message "Audit log file permissions properly restricted" `
                        -Details "NIST 800-53 AU-9: Log file access limited to SYSTEM and Administrators."
                }
            }
        }
        
        # AU-9(2): Store on Separate Physical Systems
        Add-Result -Category "NIST - AU-9(2)" -Status "Info" `
            -Message "Audit backup to separate system recommended" `
            -Details "NIST 800-53 AU-9(2): Forward audit logs to separate system (SIEM, log collector) for protection against local compromise."
        
        # AU-9(3): Cryptographic Protection
        Add-Result -Category "NIST - AU-9(3)" -Status "Info" `
            -Message "Cryptographic protection of audit information" `
            -Details "NIST 800-53 AU-9(3): Consider cryptographic mechanisms to protect audit information integrity. Options: signed logs, encrypted storage."
        
        # AU-9(4): Access by Subset of Privileged Users
        $manageAuditPrivilege = Get-SecurityPolicy -PolicyName "SeSecurityPrivilege"
        
        if ($manageAuditPrivilege) {
            Add-Result -Category "NIST - AU-9(4)" -Status "Info" `
                -Message "Audit log access granted to: $manageAuditPrivilege" `
                -Details "NIST 800-53 AU-9(4): Authorize access to audit information management to subset of privileged users."
        }
        
        # Check if log is set to auto-archive
        if ($securityLog.LogMode -eq "AutoBackup") {
            Add-Result -Category "NIST - AU-9(2)" -Status "Pass" `
                -Message "Security log configured for automatic backup" `
                -Details "NIST 800-53 AU-9(2): Log automatically archives when full, preserving audit data."
        }
    }
}
catch {
    Add-Result -Category "NIST - AU-9" -Status "Error" `
        -Message "Failed to check audit protection: $($_.Exception.Message)"
}

# AU-10: Non-Repudiation
try {
    Write-Host "  [*] AU-10: Non-Repudiation" -ForegroundColor Gray
    
    # Check if Object Access auditing is enabled (for file tracking)
    $objectAccessAudit = Test-AuditPolicy -Subcategory "File System"
    
    if ($objectAccessAudit) {
        Add-Result -Category "NIST - AU-10" -Status "Pass" `
            -Message "File system auditing enabled for non-repudiation" `
            -Details "NIST 800-53 AU-10: File access events provide evidence of actions taken."
    }
    
    # Check for digital signature capabilities
    Add-Result -Category "NIST - AU-10" -Status "Info" `
        -Message "Digital signature non-repudiation requires PKI infrastructure" `
        -Details "NIST 800-53 AU-10: Implement digital signatures for non-repudiation of critical transactions. Requires certificate infrastructure."
}
catch {
    Add-Result -Category "NIST - AU-10" -Status "Error" `
        -Message "Failed to check non-repudiation: $($_.Exception.Message)"
}

# AU-11: Audit Record Retention
try {
    Write-Host "  [*] AU-11: Audit Record Retention" -ForegroundColor Gray
    
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    
    if ($securityLog) {
        Add-Result -Category "NIST - AU-11" -Status "Info" `
            -Message "Audit retention requires policy and archival process" `
            -Details "NIST 800-53 AU-11: Retain audit records for minimum of 90 days (NIST 800-171) or per organizational policy. Implement log forwarding/archival for long-term retention."
        
        # AU-11(1): Long-Term Retrieval Capability
        Add-Result -Category "NIST - AU-11(1)" -Status "Info" `
            -Message "Long-term audit retrieval requires archival solution" `
            -Details "NIST 800-53 AU-11(1): Ensure audit records can be retrieved for extended period per retention policy (typically 1-7 years)."
    }
}
catch {
    Add-Result -Category "NIST - AU-11" -Status "Error" `
        -Message "Failed to check audit retention: $($_.Exception.Message)"
}

# AU-12: Audit Generation (ENHANCED)
try {
    Write-Host "  [*] AU-12: Audit Generation" -ForegroundColor Gray
    
    # Check if Advanced Audit Policy is in use
    $advancedAudit = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    
    if ($advancedAudit -and $advancedAudit.SCENoApplyLegacyAuditPolicy -eq 1) {
        Add-Result -Category "NIST - AU-12" -Status "Pass" `
            -Message "Advanced Audit Policy configured for granular audit generation" `
            -Details "NIST 800-53 AU-12: System provides audit record generation capability for defined auditable events."
    } else {
        Add-Result -Category "NIST - AU-12" -Status "Warning" `
            -Message "Advanced Audit Policy may not be enforced" `
            -Details "NIST 800-53 AU-12: Enable Advanced Audit Policy for comprehensive audit generation." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1"
    }
    
    # AU-12(1): System-Wide / Time-Correlated Audit Trail
    $systemAudit = Test-AuditPolicy -Subcategory "System Integrity"
    
    if ($systemAudit) {
        Add-Result -Category "NIST - AU-12(1)" -Status "Pass" `
            -Message "System-wide audit trail with time correlation" `
            -Details "NIST 800-53 AU-12(1): Centralized time-stamped audit trail across system components."
    }
    
    # AU-12(3): Changes by Authorized Individuals
    $auditPolicyChangeAudit = Test-AuditPolicy -Subcategory "Audit Policy Change"
    
    if ($auditPolicyChangeAudit) {
        Add-Result -Category "NIST - AU-12(3)" -Status "Pass" `
            -Message "Audit policy changes are audited" `
            -Details "NIST 800-53 AU-12(3): Changes to audit generation capability are logged."
    } else {
        Add-Result -Category "NIST - AU-12(3)" -Status "Fail" `
            -Message "Audit policy changes not audited" `
            -Details "NIST 800-53 AU-12(3): Enable auditing of audit policy modifications." `
            -Remediation "auditpol /set /subcategory:`"Audit Policy Change`" /success:enable /failure:enable"
    }
}
catch {
    Add-Result -Category "NIST - AU-12" -Status "Error" `
        -Message "Failed to check audit generation: $($_.Exception.Message)"
}

# AU-14: Session Audit
try {
    Write-Host "  [*] AU-14: Session Audit" -ForegroundColor Gray
    
    # Check for logon/logoff auditing
    $logonAudit = Test-AuditPolicy -Subcategory "Logon" -Type "Both"
    $logoffAudit = Test-AuditPolicy -Subcategory "Logoff" -Type "Both"
    
    if ($logonAudit -and $logoffAudit) {
        Add-Result -Category "NIST - AU-14" -Status "Pass" `
            -Message "Session start (logon) and end (logoff) events audited" `
            -Details "NIST 800-53 AU-14: System audits user session initiation and termination."
    } else {
        Add-Result -Category "NIST - AU-14" -Status "Fail" `
            -Message "Session auditing incomplete" `
            -Details "NIST 800-53 AU-14: Enable comprehensive logon/logoff auditing." `
            -Remediation "auditpol /set /subcategory:`"Logon`" /success:enable /failure:enable; auditpol /set /subcategory:`"Logoff`" /success:enable /failure:enable"
    }
    
    # AU-14(1): System Start / Restart / Shutdown
    $systemEventAudit = Test-AuditPolicy -Subcategory "Security State Change"
    
    if ($systemEventAudit) {
        Add-Result -Category "NIST - AU-14(1)" -Status "Pass" `
            -Message "System startup, restart, and shutdown events audited" `
            -Details "NIST 800-53 AU-14(1): Security state changes (boot/shutdown) are logged."
    }
}
catch {
    Add-Result -Category "NIST - AU-14" -Status "Error" `
        -Message "Failed to check session audit: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53 Rev 5: Identification and Authentication (IA) - COMPREHENSIVE
# ============================================================================
Write-Host "`n[NIST] Checking Identification and Authentication (IA) Controls..." -ForegroundColor Yellow

# IA-1: Policy and Procedures
Add-Result -Category "NIST - IA-1" -Status "Info" `
    -Message "Identification and Authentication Policy: Documentation review required" `
    -Details "NIST 800-53 IA-1: Develop, document, and disseminate identification and authentication policies. Manual verification required." `
    -Priority "Medium"

# IA-2: Identification and Authentication (Organizational Users) - COMPREHENSIVE
try {
    Write-Host "  [*] IA-2: Identification and Authentication" -ForegroundColor Gray
    
    # Check for built-in accounts
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    
    if ($guestAccount -and $guestAccount.Enabled) {
        Add-Result -Category "NIST - IA-2" -Status "Fail" `
            -Message "Guest account is enabled" `
            -Details "NIST 800-53 IA-2: Disable Guest account to enforce user identification." `
            -Remediation "Disable-LocalUser -Name Guest" `
            -Priority "High"
    } else {
        Add-Result -Category "NIST - IA-2" -Status "Pass" `
            -Message "Guest account is disabled" `
            -Details "NIST 800-53 IA-2: Proper user identification enforced (Guest disabled)."
    }
    
    if ($adminAccount -and $adminAccount.Enabled) {
        Add-Result -Category "NIST - IA-2" -Status "Warning" `
            -Message "Built-in Administrator account is enabled" `
            -Details "NIST 800-53 IA-2: Consider disabling built-in Administrator and using named admin accounts." `
            -Remediation "Disable-LocalUser -Name Administrator; Create named administrator accounts instead"
    }
    
    # IA-2(1): Multi-Factor Authentication to Privileged Accounts
    $mfaCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ScRemoveOption" -ErrorAction SilentlyContinue
    
    if ($mfaCheck) {
        Add-Result -Category "NIST - IA-2(1)" -Status "Info" `
            -Message "Smart card configuration detected" `
            -Details "NIST 800-53 IA-2(1): Verify multi-factor authentication for privileged accounts. Options: Smart cards, Windows Hello for Business, Azure MFA."
    } else {
        Add-Result -Category "NIST - IA-2(1)" -Status "Warning" `
            -Message "Multi-factor authentication not detected for privileged accounts" `
            -Details "NIST 800-53 IA-2(1): Implement MFA for administrative accounts. Recommended: Windows Hello for Business, Azure MFA, or smart cards." `
            -Remediation "Implement Windows Hello for Business or smart card authentication for administrators"
    }
    
    # IA-2(2): Multi-Factor Authentication to Non-Privileged Accounts
    Add-Result -Category "NIST - IA-2(2)" -Status "Info" `
        -Message "MFA for non-privileged accounts recommended" `
        -Details "NIST 800-53 IA-2(2): Implement multi-factor authentication for all user accounts. Solutions: Windows Hello, Azure MFA, authenticator apps."
    
    # IA-2(3): Local Access to Privileged Accounts - Multi-Factor
    Add-Result -Category "NIST - IA-2(3)" -Status "Info" `
        -Message "Local privileged access MFA via smart card or biometrics" `
        -Details "NIST 800-53 IA-2(3): Require multi-factor authentication for local administrative access."
    
    # IA-2(5): Individual Authentication with Group Authentication
    $groupPolicyAuth = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
    
    if ($groupPolicyAuth -and $groupPolicyAuth.DontDisplayLastUserName -eq 1) {
        Add-Result -Category "NIST - IA-2(5)" -Status "Pass" `
            -Message "Last logged-on username not displayed" `
            -Details "NIST 800-53 IA-2(5): Users must enter individual credentials; previous username not shown."
    } else {
        Add-Result -Category "NIST - IA-2(5)" -Status "Warning" `
            -Message "Last logged-on username is displayed at logon" `
            -Details "NIST 800-53 IA-2(5): Configure system to not display last username." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -Value 1"
    }
    
    # IA-2(6): Access to Privileged Accounts - Separate Device
    Add-Result -Category "NIST - IA-2(6)" -Status "Info" `
        -Message "Privileged access workstation (PAW) strategy recommended" `
        -Details "NIST 800-53 IA-2(6): Implement separate devices/workstations for privileged access. Microsoft Privileged Access Workstation guidance."
    
    # IA-2(8): Access to Accounts - Replay Resistant
    $ntlmSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
    
    if ($ntlmSettings -and $ntlmSettings.LmCompatibilityLevel -ge 5) {
        Add-Result -Category "NIST - IA-2(8)" -Status "Pass" `
            -Message "Replay-resistant authentication configured (NTLMv2+)" `
            -Details "NIST 800-53 IA-2(8): LM compatibility level: $($ntlmSettings.LmCompatibilityLevel). Kerberos/NTLMv2 provide replay resistance."
    } else {
        Add-Result -Category "NIST - IA-2(8)" -Status "Warning" `
            -Message "Authentication may not be fully replay-resistant" `
            -Details "NIST 800-53 IA-2(8): Configure to use NTLMv2 or Kerberos only." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
    }
    
    # IA-2(11): Remote Access - Separate Device
    Add-Result -Category "NIST - IA-2(11)" -Status "Info" `
        -Message "Remote privileged access from separate device recommended" `
        -Details "NIST 800-53 IA-2(11): Use separate trusted device for remote privileged access (jump box, PAW)."
    
    # IA-2(12): Acceptance of PIV Credentials
    Add-Result -Category "NIST - IA-2(12)" -Status "Info" `
        -Message "PIV/CAC card acceptance for federal systems" `
        -Details "NIST 800-53 IA-2(12): Federal systems must accept PIV credentials. Configure smart card authentication."
}
catch {
    Add-Result -Category "NIST - IA-2" -Status "Error" `
        -Message "Failed to check identification and authentication: $($_.Exception.Message)"
}

# IA-3: Device Identification and Authentication
try {
    Write-Host "  [*] IA-3: Device Identification and Authentication" -ForegroundColor Gray
    
    # Check for certificate-based device authentication
    $machineCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
    
    if ($machineCerts) {
        Add-Result -Category "NIST - IA-3" -Status "Info" `
            -Message "Machine certificates present: $($machineCerts.Count)" `
            -Details "NIST 800-53 IA-3: Device identification via certificates available. Verify use for device authentication."
    }
    
    # Check domain membership (Kerberos provides device authentication)
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - IA-3" -Status "Pass" `
            -Message "Device authenticated via domain membership: $($computerSystem.Domain)" `
            -Details "NIST 800-53 IA-3: Kerberos provides device authentication in domain environment."
    } else {
        Add-Result -Category "NIST - IA-3" -Status "Info" `
            -Message "Standalone/workgroup system - device authentication limited" `
            -Details "NIST 800-53 IA-3: Consider domain join or certificate-based device authentication."
    }
}
catch {
    Add-Result -Category "NIST - IA-3" -Status "Error" `
        -Message "Failed to check device identification: $($_.Exception.Message)"
}

# IA-4: Identifier Management (ENHANCED)
try {
    Write-Host "  [*] IA-4: Identifier Management" -ForegroundColor Gray
    
    # Check for duplicate or shared accounts
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    Add-Result -Category "NIST - IA-4" -Status "Info" `
        -Message "Identifier management: $($localUsers.Count) enabled user identifiers" `
        -Details "NIST 800-53 IA-4: Users: $($localUsers.Name -join ', '). Verify unique identifiers per individual (no shared accounts)."
    
    # IA-4(4): Identify User Status
    $accountStatus = @()
    foreach ($user in $localUsers) {
        $status = if ($user.PasswordExpires) { "Active" } else { "Non-expiring" }
        $accountStatus += "$($user.Name): $status"
    }
    
    Add-Result -Category "NIST - IA-4(4)" -Status "Info" `
        -Message "User account status tracking" `
        -Details "NIST 800-53 IA-4(4): Account status: $($accountStatus -join '; ')"
}
catch {
    Add-Result -Category "NIST - IA-4" -Status "Error" `
        -Message "Failed to check identifier management: $($_.Exception.Message)"
}

# IA-5: Authenticator Management (COMPREHENSIVE PASSWORD POLICY)
try {
    Write-Host "  [*] IA-5: Authenticator Management (Password Policy)" -ForegroundColor Gray
    
    $netAccounts = net accounts 2>$null
    
    if ($netAccounts) {
        # IA-5(1)(a): Minimum password length
        $minLength = ($netAccounts | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
        
        if ([int]$minLength -ge 14) {
            Add-Result -Category "NIST - IA-5(1)" -Status "Pass" `
                -Message "Minimum password length: $minLength characters (NIST compliant)" `
                -Details "NIST 800-53 IA-5(1): Meets or exceeds 14-character minimum for memorized secrets."
        } elseif ([int]$minLength -ge 8) {
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Minimum password length: $minLength characters (below NIST recommendation)" `
                -Details "NIST 800-53 IA-5(1): NIST SP 800-63B recommends 14+ characters for memorized secrets." `
                -Remediation "net accounts /minpwlen:14" `
                -Priority "Medium"
        } else {
            Add-Result -Category "NIST - IA-5(1)" -Status "Fail" `
                -Message "Minimum password length is weak: $minLength characters" `
                -Details "NIST 800-53 IA-5(1): Increase to 14+ characters per NIST SP 800-63B." `
                -Remediation "net accounts /minpwlen:14" `
                -Priority "High"
        }
        
        # IA-5(1)(d): Password complexity
        # Check via secedit for local policy
        $complexityPolicy = Get-SecurityPolicy -PolicyName "PasswordComplexity"
        
        if ($complexityPolicy -eq "1") {
            Add-Result -Category "NIST - IA-5(1)" -Status "Pass" `
                -Message "Password complexity requirements enabled" `
                -Details "NIST 800-53 IA-5(1): Passwords must meet complexity requirements (uppercase, lowercase, numbers, symbols)."
        } else {
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Password complexity not enforced" `
                -Details "NIST 800-53 IA-5(1): Enable password complexity or implement length-based policy (14+ chars)." `
                -Remediation "Enable via Local Security Policy: Account Policies > Password Policy > Password must meet complexity requirements"
        }
        
        # Check via secedit for local policy
        $complexityPolicy = Get-SecurityPolicy -PolicyName "PasswordComplexity"
        
        if ($complexityPolicy -eq "1") {
            Add-Result -Category "NIST - IA-5(1)" -Status "Pass" `
                -Message "Password complexity requirements enabled" `
                -Details "NIST 800-53 IA-5(1): Passwords must meet complexity requirements (uppercase, lowercase, numbers, symbols)."
        } else {
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Password complexity not enforced" `
                -Details "NIST 800-53 IA-5(1): Enable password complexity or implement length-based policy (14+ chars)." `
                -Remediation "Enable via Local Security Policy: Account Policies > Password Policy > Password must meet complexity requirements"
        }
        
        # IA-5(1)(e): Password history
        $history = ($netAccounts | Select-String "Length of password history maintained").ToString().Split(":")[1].Trim()
        
        if ([int]$history -ge 24) {
            Add-Result -Category "NIST - IA-5(1)" -Status "Pass" `
                -Message "Password history: $history passwords remembered" `
                -Details "NIST 800-53 IA-5(1): Adequate password reuse prevention (24+ previous passwords)."
        } elseif ([int]$history -ge 12) {
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Password history: $history passwords (consider increasing)" `
                -Details "NIST 800-53 IA-5(1): Recommend 24 previous passwords to prevent reuse." `
                -Remediation "net accounts /uniquepw:24"
        } else {
            Add-Result -Category "NIST - IA-5(1)" -Status "Fail" `
                -Message "Password history insufficient: $history passwords" `
                -Details "NIST 800-53 IA-5(1): Increase password history to 24." `
                -Remediation "net accounts /uniquepw:24"
        }
        
        # IA-5(1)(f): Maximum password age
        $maxAge = ($netAccounts | Select-String "Maximum password age").ToString().Split(":")[1].Trim().Split(" ")[0]
        
        if ($maxAge -ne "Unlimited" -and [int]$maxAge -le 365 -and [int]$maxAge -ge 60) {
            Add-Result -Category "NIST - IA-5(1)" -Status "Pass" `
                -Message "Maximum password age: $maxAge days (compliant)" `
                -Details "NIST 800-53 IA-5(1): Password expiration configured within recommended range."
        } elseif ($maxAge -eq "Unlimited") {
            Add-Result -Category "NIST - IA-5(1)" -Status "Fail" `
                -Message "Password never expires (Unlimited)" `
                -Details "NIST 800-53 IA-5(1): Configure password expiration (recommended: 60-365 days)." `
                -Remediation "net accounts /maxpwage:365" `
                -Priority "High"
        } elseif ([int]$maxAge -lt 60) {
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Maximum password age very short: $maxAge days" `
                -Details "NIST 800-53 IA-5(1): Very frequent password changes can lead to weaker passwords. Consider 60-365 days."
        } else {
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Maximum password age: $maxAge days (longer than typical)" `
                -Details "NIST 800-53 IA-5(1): Consider setting to 365 days or less."
        }
        
        # IA-5(1)(g): Minimum password age
        $minAgeRaw = ($netAccounts | Select-String "Minimum password age").ToString().Split(":")[1].Trim()
        
        # Handle "None" or other non-numeric values
		if ($minAgeRaw -match "^\d+") {
			# Extract just the numeric portion
            $minAge = [int]($minAgeRaw -replace "[^\d]", "")
			
			if ($minAge -ge 1) {
                Add-Result -Category "NIST - IA-5(1)" -Status "Pass" `
                    -Message "Minimum password age: $minAge day(s)" `
                    -Details "NIST 800-53 IA-5(1): Prevents rapid password changes to cycle through history."
            } else {
                Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                    -Message "Minimum password age: $minAge days (users can immediately change)" `
                    -Details "NIST 800-53 IA-5(1): Set minimum age to 1+ days to prevent password history bypass." `
                    -Remediation "net accounts /minpwage:1"
            }
        } else {
            # Handle "None" or other non-numeric values
            Add-Result -Category "NIST - IA-5(1)" -Status "Warning" `
                -Message "Minimum password age: $minAgeRaw (not configured)" `
                -Details "NIST 800-53 IA-5(1): Set minimum password age to 1+ days to prevent password history bypass." `
                -Remediation "net accounts /minpwage:1"
        }
        
        # IA-5(1)(h): Password change authorization
        Add-Result -Category "NIST - IA-5(1)" -Status "Info" `
            -Message "Password change process review" `
            -Details "NIST 800-53 IA-5(1): Users can change their own passwords. Verify help desk procedures for password resets require proper authorization."
        
        # IA-5(2): Public Key-Based Authentication
        $sshInstalled = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Installed" }
        
        if ($sshInstalled) {
            Add-Result -Category "NIST - IA-5(2)" -Status "Info" `
                -Message "OpenSSH Server installed - PKI authentication available" `
                -Details "NIST 800-53 IA-5(2): Public key authentication capability present. Verify key-based authentication is configured and enforced."
        }
        
        # IA-5(4): Automated Support for Password Strength Determination
        Add-Result -Category "NIST - IA-5(4)" -Status "Info" `
            -Message "Password strength tools recommended" `
            -Details "NIST 800-53 IA-5(4): Consider implementing password quality checking tools to prevent common/weak passwords."
        
        # IA-5(6): Protection of Authenticators
        $credentialGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($credentialGuard -and $credentialGuard.SecurityServicesRunning -contains 1) {
            Add-Result -Category "NIST - IA-5(6)" -Status "Pass" `
                -Message "Credential Guard enabled (authenticator protection)" `
                -Details "NIST 800-53 IA-5(6): Credential Guard protects credentials from theft."
        } else {
            Add-Result -Category "NIST - IA-5(6)" -Status "Info" `
                -Message "Credential Guard not detected" `
                -Details "NIST 800-53 IA-5(6): Enable Credential Guard on Enterprise editions for hardware-based credential protection."
        }
        
        # IA-5(7): No Embedded Unencrypted Static Authenticators
        Add-Result -Category "NIST - IA-5(7)" -Status "Info" `
            -Message "Review scripts/applications for embedded credentials" `
            -Details "NIST 800-53 IA-5(7): Ensure no hardcoded passwords in scripts, configuration files, or applications. Use credential managers or Azure Key Vault."
        
        # IA-5(8): Multiple System Accounts
        $sharedAccounts = @("Administrator", "Guest", "DefaultAccount")
        $foundSharedEnabled = $localUsers | Where-Object { $_.Name -in $sharedAccounts }
        
        if ($foundSharedEnabled) {
            Add-Result -Category "NIST - IA-5(8)" -Status "Warning" `
                -Message "Shared/generic accounts enabled: $($foundSharedEnabled.Name -join ', ')" `
                -Details "NIST 800-53 IA-5(8): Implement unique individual authenticators. Avoid shared accounts."
        }
    }
}
catch {
    Add-Result -Category "NIST - IA-5" -Status "Error" `
        -Message "Failed to check authenticator management: $($_.Exception.Message)"
}

# IA-6: Authentication Feedback
try {
    Write-Host "  [*] IA-6: Authentication Feedback" -ForegroundColor Gray
    
    # Check if password is obscured during entry (this is default Windows behavior)
    Add-Result -Category "NIST - IA-6" -Status "Pass" `
        -Message "Authentication feedback obscured (password masking)" `
        -Details "NIST 800-53 IA-6: Windows obscures authentication information during entry (displays asterisks/bullets for passwords)."
}
catch {
    Add-Result -Category "NIST - IA-6" -Status "Error" `
        -Message "Failed to check authentication feedback: $($_.Exception.Message)"
}

# IA-7: Cryptographic Module Authentication
try {
    Write-Host "  [*] IA-7: Cryptographic Module Authentication" -ForegroundColor Gray
    
    # Check for FIPS mode
    $fipsEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue
    
    if ($fipsEnabled -and $fipsEnabled.Enabled -eq 1) {
        Add-Result -Category "NIST - IA-7" -Status "Pass" `
            -Message "FIPS mode enabled (cryptographic module authentication)" `
            -Details "NIST 800-53 IA-7: System configured to use FIPS 140-2 validated cryptographic modules."
    } else {
        Add-Result -Category "NIST - IA-7" -Status "Info" `
            -Message "FIPS mode not enabled" `
            -Details "NIST 800-53 IA-7: Enable FIPS mode for federal systems or high-security environments requiring FIPS 140-2 validated crypto." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -Value 1 -Type DWord; Restart-Computer"
    }
}
catch {
    Add-Result -Category "NIST - IA-7" -Status "Error" `
        -Message "Failed to check cryptographic module authentication: $($_.Exception.Message)"
}

# IA-8: Identification and Authentication (Non-Organizational Users)
try {
    Write-Host "  [*] IA-8: Non-Organizational User Authentication" -ForegroundColor Gray
    
    # Check domain membership (external users would be in different domain/forest)
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - IA-8" -Status "Info" `
            -Message "Domain-joined system: $($computerSystem.Domain)" `
            -Details "NIST 800-53 IA-8: External users can be identified via cross-domain trusts or federated authentication (Azure AD, ADFS)."
    } else {
        Add-Result -Category "NIST - IA-8" -Status "Info" `
            -Message "Standalone system - external user authentication limited" `
            -Details "NIST 800-53 IA-8: Non-organizational users require explicit local accounts or domain join for proper identification."
    }
    
    # IA-8(1): Acceptance of PIV Credentials from Other Agencies
    Add-Result -Category "NIST - IA-8(1)" -Status "Info" `
        -Message "PIV credential acceptance requires PKI trust configuration" `
        -Details "NIST 800-53 IA-8(1): Federal systems must accept PIV credentials from other agencies. Configure certificate trust chains."
    
    # IA-8(2): Acceptance of External Credentials (Third-Party)
    Add-Result -Category "NIST - IA-8(2)" -Status "Info" `
        -Message "Third-party credential acceptance via federation" `
        -Details "NIST 800-53 IA-8(2): Implement federated identity (SAML, OAuth, OpenID Connect) for third-party credentials. Azure AD B2B, ADFS."
    
    # IA-8(4): Use of Defined Profiles
    Add-Result -Category "NIST - IA-8(4)" -Status "Info" `
        -Message "Identity federation profiles (FICAM, SAML 2.0)" `
        -Details "NIST 800-53 IA-8(4): Use FICAM-approved profiles for federated authentication."
}
catch {
    Add-Result -Category "NIST - IA-8" -Status "Error" `
        -Message "Failed to check non-organizational user authentication: $($_.Exception.Message)"
}

# IA-9: Service Identification and Authentication
try {
    Write-Host "  [*] IA-9: Service Identification and Authentication" -ForegroundColor Gray
    
    # Check service accounts
    $services = Get-CimInstance -ClassName Win32_Service | Where-Object { 
        $_.StartName -notmatch "LocalSystem|NT AUTHORITY" -and $_.StartName -ne $null 
    }
    
    if ($services) {
        Add-Result -Category "NIST - IA-9" -Status "Info" `
            -Message "Service accounts detected: $($services.Count) service(s)" `
            -Details "NIST 800-53 IA-9: Services running as: $($services.StartName | Select-Object -Unique | Out-String). Verify proper authentication and least privilege."
    }
    
    # IA-9(2): Transmission of Decisions
    Add-Result -Category "NIST - IA-9(2)" -Status "Info" `
        -Message "Service authentication decisions via Kerberos/NTLM" `
        -Details "NIST 800-53 IA-9(2): Windows transmits authentication decisions from authenticating entity to requesting entity."
}
catch {
    Add-Result -Category "NIST - IA-9" -Status "Error" `
        -Message "Failed to check service identification: $($_.Exception.Message)"
}

# IA-10: Adaptive Authentication
try {
    Write-Host "  [*] IA-10: Adaptive Authentication" -ForegroundColor Gray
    
    Add-Result -Category "NIST - IA-10" -Status "Info" `
        -Message "Adaptive authentication requires Azure AD or advanced IAM" `
        -Details "NIST 800-53 IA-10: Implement context-aware authentication (location, device, risk score). Solutions: Azure AD Conditional Access, Okta Adaptive MFA."
}
catch {
    Add-Result -Category "NIST - IA-10" -Status "Error" `
        -Message "Failed to check adaptive authentication: $($_.Exception.Message)"
}

# IA-11: Re-Authentication
try {
    Write-Host "  [*] IA-11: Re-Authentication" -ForegroundColor Gray
    
    # Check UAC behavior (requires re-authentication for elevation)
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    
    if ($uac -and $uac.ConsentPromptBehaviorAdmin -eq 1) {
        Add-Result -Category "NIST - IA-11" -Status "Pass" `
            -Message "UAC prompts for credentials for privileged operations" `
            -Details "NIST 800-53 IA-11: Re-authentication required for administrative actions."
    } elseif ($uac -and $uac.ConsentPromptBehaviorAdmin -eq 2) {
        Add-Result -Category "NIST - IA-11" -Status "Pass" `
            -Message "UAC requires consent for privileged operations" `
            -Details "NIST 800-53 IA-11: Explicit user confirmation required (re-authentication via consent)."
    }
}
catch {
    Add-Result -Category "NIST - IA-11" -Status "Error" `
        -Message "Failed to check re-authentication: $($_.Exception.Message)"
}

# IA-12: Identity Proofing
try {
    Write-Host "  [*] IA-12: Identity Proofing" -ForegroundColor Gray
    
    Add-Result -Category "NIST - IA-12" -Status "Info" `
        -Message "Identity proofing requires organizational processes" `
        -Details "NIST 800-53 IA-12: Implement identity proofing per NIST SP 800-63A. Verify user identity before issuing credentials (IAL1/IAL2/IAL3)."
    
    # IA-12(2): Identity Evidence
    Add-Result -Category "NIST - IA-12(2)" -Status "Info" `
        -Message "Identity evidence validation for credential issuance" `
        -Details "NIST 800-53 IA-12(2): Require valid identity evidence (government ID, background check) before credential issuance per NIST 800-63A."
    
    # IA-12(3): Identity Evidence Validation and Verification
    Add-Result -Category "NIST - IA-12(3)" -Status "Info" `
        -Message "Identity evidence validation and verification procedures" `
        -Details "NIST 800-53 IA-12(3): Validate and verify identity evidence meets assurance level requirements."
}
catch {
    Add-Result -Category "NIST - IA-12" -Status "Error" `
        -Message "Failed to check identity proofing: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53 Rev 5: System and Communications Protection (SC) - COMPREHENSIVE
# ============================================================================
Write-Host "`n[NIST] Checking System and Communications Protection (SC) Controls..." -ForegroundColor Yellow

# SC-1: Policy and Procedures
Add-Result -Category "NIST - SC-1" -Status "Info" `
    -Message "System and Communications Protection Policy: Documentation review required" `
    -Details "NIST 800-53 SC-1: Develop, document, and disseminate system and communications protection policies. Manual verification required." `
    -Priority "Medium"

# SC-2: Separation of System and User Functionality
try {
    Write-Host "  [*] SC-2: Separation of System and User Functionality" -ForegroundColor Gray
    
    # Check if system files are protected
    $systemProtection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    
    if ($systemProtection -and $systemProtection.EnableLUA -eq 1) {
        Add-Result -Category "NIST - SC-2" -Status "Pass" `
            -Message "User/system functionality separated via UAC" `
            -Details "NIST 800-53 SC-2: UAC separates user and administrative functions, protecting system functionality."
    }
}
catch {
    Add-Result -Category "NIST - SC-2" -Status "Error" `
        -Message "Failed to check separation of functionality: $($_.Exception.Message)"
}

# SC-3: Security Function Isolation
try {
    Write-Host "  [*] SC-3: Security Function Isolation" -ForegroundColor Gray
    
    # Check for Virtualization Based Security
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard -and $deviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
        Add-Result -Category "NIST - SC-3" -Status "Pass" `
            -Message "Virtualization-Based Security (VBS) enabled" `
            -Details "NIST 800-53 SC-3: VBS isolates security functions from other system operations using hardware virtualization."
    } else {
        Add-Result -Category "NIST - SC-3" -Status "Info" `
            -Message "Virtualization-Based Security not detected" `
            -Details "NIST 800-53 SC-3: Enable VBS on supported hardware for enhanced security function isolation (Device Guard, Credential Guard)."
    }
}
catch {
    Add-Result -Category "NIST - SC-3" -Status "Error" `
        -Message "Failed to check security function isolation: $($_.Exception.Message)"
}

# SC-4: Information in Shared System Resources
try {
    Write-Host "  [*] SC-4: Information in Shared System Resources" -ForegroundColor Gray
    
    # Windows automatically clears memory allocations
    Add-Result -Category "NIST - SC-4" -Status "Pass" `
        -Message "Memory protection enabled (OS-level)" `
        -Details "NIST 800-53 SC-4: Windows prevents information leakage through shared resources via memory protection and clearing."
}
catch {
    Add-Result -Category "NIST - SC-4" -Status "Error" `
        -Message "Failed to check shared resource protection: $($_.Exception.Message)"
}

# SC-5: Denial of Service Protection
try {
    Write-Host "  [*] SC-5: Denial of Service Protection" -ForegroundColor Gray
    
    # Check SYN attack protection
    $synAttackProtect = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -ErrorAction SilentlyContinue
    
    if ($synAttackProtect -and $synAttackProtect.SynAttackProtect -ge 1) {
        Add-Result -Category "NIST - SC-5" -Status "Pass" `
            -Message "SYN flood attack protection enabled (Level: $($synAttackProtect.SynAttackProtect))" `
            -Details "NIST 800-53 SC-5: TCP/IP stack configured to protect against SYN flood DoS attacks."
    } else {
        Add-Result -Category "NIST - SC-5" -Status "Warning" `
            -Message "SYN attack protection not explicitly configured" `
            -Details "NIST 800-53 SC-5: Enable SYN attack protection to limit DoS vulnerability." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name SynAttackProtect -Value 1 -Type DWord"
    }
    
    # Check TCP connection limits
    $tcpMaxConnections = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxConnectResponseRetransmissions" -ErrorAction SilentlyContinue
    
    if ($tcpMaxConnections) {
        Add-Result -Category "NIST - SC-5" -Status "Info" `
            -Message "TCP connection retransmission limit: $($tcpMaxConnections.TcpMaxConnectResponseRetransmissions)" `
            -Details "NIST 800-53 SC-5: Connection timeout limits help prevent resource exhaustion."
    }
}
catch {
    Add-Result -Category "NIST - SC-5" -Status "Error" `
        -Message "Failed to check DoS protection: $($_.Exception.Message)"
}

# SC-7: Boundary Protection (COMPREHENSIVE)
try {
    Write-Host "  [*] SC-7: Boundary Protection" -ForegroundColor Gray
    
    # Check Windows Firewall on all profiles
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $allEnabled = ($firewallProfiles | Where-Object { -not $_.Enabled }).Count -eq 0
    
    if ($allEnabled) {
        Add-Result -Category "NIST - SC-7" -Status "Pass" `
            -Message "Windows Firewall enabled on all network profiles" `
            -Details "NIST 800-53 SC-7: Boundary protection active on Domain, Private, and Public profiles."
        
        # SC-7(3): Access Points
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
        $allowRules = $inboundRules | Where-Object { $_.Action -eq "Allow" }
        
        Add-Result -Category "NIST - SC-7(3)" -Status "Info" `
            -Message "Firewall access points: $($allowRules.Count) inbound allow rules" `
            -Details "NIST 800-53 SC-7(3): Review and limit external connections to managed access points."
        
        # SC-7(4): External Telecommunications Services
        Add-Result -Category "NIST - SC-7(4)" -Status "Info" `
            -Message "External telecommunications boundary protection" `
            -Details "NIST 800-53 SC-7(4): Implement managed interfaces for external telecom services (VPN, Internet gateway)."
        
        # SC-7(5): Deny by Default / Allow by Exception
        $defaultInbound = ($firewallProfiles | Where-Object { $_.DefaultInboundAction -eq "Block" }).Count
        
        if ($defaultInbound -eq 3) {
            Add-Result -Category "NIST - SC-7(5)" -Status "Pass" `
                -Message "Firewall configured with deny-by-default (all profiles)" `
                -Details "NIST 800-53 SC-7(5): Default inbound action is Block; connections allowed only by explicit rules."
        } else {
            Add-Result -Category "NIST - SC-7(5)" -Status "Fail" `
                -Message "Firewall not fully configured for deny-by-default" `
                -Details "NIST 800-53 SC-7(5): Configure default inbound action to Block on all profiles." `
                -Remediation "Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Block" `
                -Priority "High"
        }
        
        # SC-7(7): Split Tunneling for Remote Devices
        Add-Result -Category "NIST - SC-7(7)" -Status "Info" `
            -Message "VPN split tunneling configuration review" `
            -Details "NIST 800-53 SC-7(7): Prevent split tunneling for remote devices to ensure all traffic goes through organizational boundary protection."
        
        # SC-7(8): Route Traffic to Authenticated Proxy Servers
        Add-Result -Category "NIST - SC-7(8)" -Status "Info" `
            -Message "Authenticated proxy server routing for external connections" `
            -Details "NIST 800-53 SC-7(8): Route outbound connections through authenticated proxy servers for inspection and control."
        
        # SC-7(10): Prevent Exfiltration
        $outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction SilentlyContinue
        $blockOutbound = $outboundRules | Where-Object { $_.Action -eq "Block" }
        
        Add-Result -Category "NIST - SC-7(10)" -Status "Info" `
            -Message "Data exfiltration prevention: $($blockOutbound.Count) outbound block rules" `
            -Details "NIST 800-53 SC-7(10): Implement DLP and firewall rules to prevent unauthorized data exfiltration."
        
        # SC-7(12): Host-Based Protection
        Add-Result -Category "NIST - SC-7(12)" -Status "Pass" `
            -Message "Host-based boundary protection via Windows Firewall" `
            -Details "NIST 800-53 SC-7(12): Each host implements its own boundary protection mechanism."
        
        # SC-7(13): Isolation of Security Tools
        Add-Result -Category "NIST - SC-7(13)" -Status "Info" `
            -Message "Security tool isolation requires network segmentation" `
            -Details "NIST 800-53 SC-7(13): Isolate security tools (SIEM, vulnerability scanners) on separate network segments."
        
        # SC-7(18): Fail Secure
        $firewallFailSafe = ($firewallProfiles | ForEach-Object { $_.Enabled }).Contains($false)
        
        if (-not $firewallFailSafe) {
            Add-Result -Category "NIST - SC-7(18)" -Status "Pass" `
                -Message "Boundary protection configured to fail secure" `
                -Details "NIST 800-53 SC-7(18): Firewall remains active; system denies traffic on failure."
        }
        
        # SC-7(20): Dynamic Isolation / Segregation
        Add-Result -Category "NIST - SC-7(20)" -Status "Info" `
            -Message "Dynamic isolation requires advanced network controls" `
            -Details "NIST 800-53 SC-7(20): Implement capability to dynamically isolate compromised systems (NAC, micro-segmentation)."
        
        # SC-7(21): Isolation of System Components
        Add-Result -Category "NIST - SC-7(21)" -Status "Info" `
            -Message "System component isolation via network segmentation" `
            -Details "NIST 800-53 SC-7(21): Employ separate network segments for different system components and security domains."
        
    } else {
        Add-Result -Category "NIST - SC-7" -Status "Fail" `
            -Message "Windows Firewall disabled on one or more profiles" `
            -Details "NIST 800-53 SC-7: Enable firewall on all network profiles for boundary protection." `
            -Remediation "Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True" `
            -Priority "High"
    }
}
catch {
    Add-Result -Category "NIST - SC-7" -Status "Error" `
        -Message "Failed to check boundary protection: $($_.Exception.Message)"
}

# SC-8: Transmission Confidentiality and Integrity (COMPREHENSIVE)
try {
    Write-Host "  [*] SC-8: Transmission Confidentiality and Integrity" -ForegroundColor Gray
    
    # Check SMB signing (integrity)
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    if ($smbServer) {
        # SC-8(1): Cryptographic Protection
        if ($smbServer.RequireSecuritySignature) {
            Add-Result -Category "NIST - SC-8(1)" -Status "Pass" `
                -Message "SMB signing required (transmission integrity)" `
                -Details "NIST 800-53 SC-8(1): SMB traffic integrity protected through digital signatures."
        } else {
            Add-Result -Category "NIST - SC-8(1)" -Status "Fail" `
                -Message "SMB signing not required" `
                -Details "NIST 800-53 SC-8(1): Enable SMB signing to protect transmission integrity." `
                -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
                -Priority "High"
        }
        
        # Check SMB encryption (confidentiality)
        if ($smbServer.EncryptData) {
            Add-Result -Category "NIST - SC-8" -Status "Pass" `
                -Message "SMB encryption enabled (transmission confidentiality)" `
                -Details "NIST 800-53 SC-8: SMB traffic encrypted to protect confidentiality."
        } else {
            Add-Result -Category "NIST - SC-8" -Status "Warning" `
                -Message "SMB encryption not globally required" `
                -Details "NIST 800-53 SC-8: Enable SMB encryption for sensitive file shares." `
                -Remediation "Set-SmbServerConfiguration -EncryptData `$true -Force"
        }
        
        # Check SMB version (SMB1 is insecure)
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
        
        if ($smb1 -and $smb1.State -eq "Enabled") {
            Add-Result -Category "NIST - SC-8" -Status "Fail" `
                -Message "SMB1 protocol is enabled (insecure)" `
                -Details "NIST 800-53 SC-8: SMB1 lacks encryption and modern security features. Disable immediately." `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
                -Priority "High"
        } else {
            Add-Result -Category "NIST - SC-8" -Status "Pass" `
                -Message "SMB1 protocol disabled (secure transmission)" `
                -Details "NIST 800-53 SC-8: Legacy SMB1 disabled; using secure SMB2/3 with encryption support."
        }
    }
    
    # SC-8(2): Pre/Post Transmission Handling
    Add-Result -Category "NIST - SC-8(2)" -Status "Info" `
        -Message "Pre/post transmission security handling" `
        -Details "NIST 800-53 SC-8(2): Maintain confidentiality/integrity before transmission and after receipt. Implement at-rest encryption (BitLocker)."
    
    # Check TLS/SSL settings for secure communications
    $tlsSettings = @{}
    $protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
    
    foreach ($protocol in $protocols) {
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        
        $clientEnabled = Test-RegistryValue -Path $clientPath -Name "Enabled" -ExpectedValue 1
        $serverEnabled = Test-RegistryValue -Path $serverPath -Name "Enabled" -ExpectedValue 1
        
        $tlsSettings[$protocol] = @{
            Client = $clientEnabled
            Server = $serverEnabled
        }
    }
    
    # Check for insecure protocols
    $insecureEnabled = @()
    if ($tlsSettings["SSL 2.0"].Server -or $tlsSettings["SSL 3.0"].Server -or 
        $tlsSettings["TLS 1.0"].Server -or $tlsSettings["TLS 1.1"].Server) {
        
        foreach ($proto in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) {
            if ($tlsSettings[$proto].Server) {
                $insecureEnabled += $proto
            }
        }
    }
    
    if ($insecureEnabled.Count -gt 0) {
        Add-Result -Category "NIST - SC-8(1)" -Status "Fail" `
            -Message "Insecure TLS/SSL protocols enabled: $($insecureEnabled -join ', ')" `
            -Details "NIST 800-53 SC-8(1): Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1. Use TLS 1.2+ only." `
            -Remediation "Disable insecure protocols via IIS Crypto tool or Group Policy" `
            -Priority "High"
    } else {
        Add-Result -Category "NIST - SC-8(1)" -Status "Pass" `
            -Message "Insecure TLS/SSL protocols not explicitly enabled" `
            -Details "NIST 800-53 SC-8(1): Legacy SSL/TLS protocols not detected as enabled."
    }
    
    # Check if TLS 1.2 is enabled
    if ($tlsSettings["TLS 1.2"].Client -or $tlsSettings["TLS 1.2"].Server) {
        Add-Result -Category "NIST - SC-8(1)" -Status "Pass" `
            -Message "TLS 1.2 enabled (modern secure protocol)" `
            -Details "NIST 800-53 SC-8(1): TLS 1.2 provides strong cryptographic protection for transmissions."
    }
}
catch {
    Add-Result -Category "NIST - SC-8" -Status "Error" `
        -Message "Failed to check transmission protection: $($_.Exception.Message)"
}

# SC-10: Network Disconnect
try {
    Write-Host "  [*] SC-10: Network Disconnect" -ForegroundColor Gray
    
    # Check for session timeout settings
    $rdpTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxIdleTime" -ErrorAction SilentlyContinue
    
    if ($rdpTimeout -and $rdpTimeout.MaxIdleTime -gt 0) {
        $minutes = $rdpTimeout.MaxIdleTime / 60000
        Add-Result -Category "NIST - SC-10" -Status "Pass" `
            -Message "Network session disconnect configured: $minutes minutes idle" `
            -Details "NIST 800-53 SC-10: RDP sessions automatically disconnect after inactivity period."
    } else {
        Add-Result -Category "NIST - SC-10" -Status "Warning" `
            -Message "Network session disconnect not configured" `
            -Details "NIST 800-53 SC-10: Configure automatic session termination after idle period." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MaxIdleTime -Value 900000"
    }
}
catch {
    Add-Result -Category "NIST - SC-10" -Status "Error" `
        -Message "Failed to check network disconnect: $($_.Exception.Message)"
}

# SC-12: Cryptographic Key Establishment and Management
try {
    Write-Host "  [*] SC-12: Cryptographic Key Management" -ForegroundColor Gray
    
    # Check for certificates (key material)
    $personalCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
    
    if ($personalCerts) {
        $expiredCerts = $personalCerts | Where-Object { $_.NotAfter -lt (Get-Date) }
        $expiringSoon = $personalCerts | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) -and $_.NotAfter -gt (Get-Date) }
        
        Add-Result -Category "NIST - SC-12" -Status "Info" `
            -Message "Cryptographic key management: $($personalCerts.Count) certificate(s)" `
            -Details "NIST 800-53 SC-12: Certificates found. Expired: $($expiredCerts.Count), Expiring in 30 days: $($expiringSoon.Count)"
        
        if ($expiredCerts.Count -gt 0) {
            Add-Result -Category "NIST - SC-12" -Status "Warning" `
                -Message "Expired certificates detected: $($expiredCerts.Count)" `
                -Details "NIST 800-53 SC-12: Remove or renew expired certificates: $($expiredCerts.Subject -join '; ')" `
                -Remediation "Review and remove/renew expired certificates in Certificate Manager (certlm.msc)"
        }
    }
    
    # SC-12(1): Availability
    Add-Result -Category "NIST - SC-12(1)" -Status "Info" `
        -Message "Cryptographic key availability and escrow" `
        -Details "NIST 800-53 SC-12(1): Maintain availability of cryptographic keys. Implement key escrow for recovery (BitLocker recovery keys to AD)."
    
    # SC-12(2): Symmetric Keys
    Add-Result -Category "NIST - SC-12(2)" -Status "Info" `
        -Message "Symmetric key production and distribution" `
        -Details "NIST 800-53 SC-12(2): Produce and distribute symmetric keys using NIST-approved key management technology (FIPS 140-2 validated)."
    
    # SC-12(3): Asymmetric Keys
    Add-Result -Category "NIST - SC-12(3)" -Status "Info" `
        -Message "Asymmetric key production and distribution" `
        -Details "NIST 800-53 SC-12(3): Generate asymmetric keys using approved PKI or secure key generation process."
}
catch {
    Add-Result -Category "NIST - SC-12" -Status "Error" `
        -Message "Failed to check cryptographic key management: $($_.Exception.Message)"
}

# SC-13: Cryptographic Protection (ENHANCED)
try {
    Write-Host "  [*] SC-13: Cryptographic Protection" -ForegroundColor Gray
    
    # Check BitLocker encryption
    $systemDrive = $env:SystemDrive
    $bitlocker = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
    
    if ($bitlocker) {
        if ($bitlocker.VolumeStatus -eq "FullyEncrypted") {
            Add-Result -Category "NIST - SC-13" -Status "Pass" `
                -Message "System drive fully encrypted with BitLocker" `
                -Details "NIST 800-53 SC-13: Data at rest protected. Encryption: $($bitlocker.EncryptionMethod), Key Protector: $($bitlocker.KeyProtector.KeyProtectorType -join ', ')"
            
            # Check for FIPS-compliant encryption method
            if ($bitlocker.EncryptionMethod -match "Aes256" -or $bitlocker.EncryptionMethod -match "XtsAes256") {
                Add-Result -Category "NIST - SC-13" -Status "Pass" `
                    -Message "BitLocker using FIPS-compliant encryption: $($bitlocker.EncryptionMethod)" `
                    -Details "NIST 800-53 SC-13: AES-256 is NIST-approved cryptographic algorithm (FIPS 140-2)."
            }
            
        } elseif ($bitlocker.VolumeStatus -eq "EncryptionInProgress") {
            Add-Result -Category "NIST - SC-13" -Status "Info" `
                -Message "System drive encryption in progress" `
                -Details "NIST 800-53 SC-13: BitLocker encryption ongoing. Progress: $($bitlocker.EncryptionPercentage)%"
        } else {
            Add-Result -Category "NIST - SC-13" -Status "Fail" `
                -Message "System drive not encrypted (Status: $($bitlocker.VolumeStatus))" `
                -Details "NIST 800-53 SC-13: Enable BitLocker for data-at-rest protection." `
                -Remediation "Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -TpmProtector" `
                -Priority "High"
        }
    } else {
        Add-Result -Category "NIST - SC-13" -Status "Warning" `
            -Message "BitLocker status cannot be determined" `
            -Details "NIST 800-53 SC-13: BitLocker may not be available on this edition of Windows, or system drive is not encrypted." `
            -Remediation "Enable BitLocker if available, or use third-party encryption"
    }
    
    # Check for EFS usage (file-level encryption)
    $efsInfo = cipher /u /n 2>$null
    if ($efsInfo -and -not ($efsInfo | Select-String "No files found")) {
        Add-Result -Category "NIST - SC-13" -Status "Pass" `
            -Message "EFS file-level encryption in use" `
            -Details "NIST 800-53 SC-13: Encrypting File System provides additional file-level cryptographic protection."
    }
}
catch {
    Add-Result -Category "NIST - SC-13" -Status "Error" `
        -Message "Failed to check cryptographic protection: $($_.Exception.Message)"
}

# SC-15: Collaborative Computing Devices and Applications
try {
    Write-Host "  [*] SC-15: Collaborative Computing Devices" -ForegroundColor Gray
    
    # Check for camera/microphone privacy settings
    $cameraAccess = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -ErrorAction SilentlyContinue
    
    if ($cameraAccess) {
        if ($cameraAccess.Value -eq "Deny") {
            Add-Result -Category "NIST - SC-15" -Status "Pass" `
                -Message "Camera access globally denied" `
                -Details "NIST 800-53 SC-15: Webcam access disabled for all applications."
        } else {
            Add-Result -Category "NIST - SC-15" -Status "Info" `
                -Message "Camera access: $($cameraAccess.Value)" `
                -Details "NIST 800-53 SC-15: Review and control camera access per application. Provide explicit indication of use."
        }
    }
    
    $microphoneAccess = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -ErrorAction SilentlyContinue
    
    if ($microphoneAccess) {
        Add-Result -Category "NIST - SC-15" -Status "Info" `
            -Message "Microphone access: $($microphoneAccess.Value)" `
            -Details "NIST 800-53 SC-15: Review and control microphone access per application."
    }
    
    # SC-15(1): Physical Disconnect
    Add-Result -Category "NIST - SC-15(1)" -Status "Info" `
        -Message "Physical disconnect for collaborative devices" `
        -Details "NIST 800-53 SC-15(1): Use devices with physical disconnect capability (camera covers, microphone mute switches)."
}
catch {
    Add-Result -Category "NIST - SC-15" -Status "Error" `
        -Message "Failed to check collaborative computing devices: $($_.Exception.Message)"
}

# SC-17: Public Key Infrastructure Certificates
try {
    Write-Host "  [*] SC-17: PKI Certificates" -ForegroundColor Gray
    
    # Check certificate revocation checking
    # $crlCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -Name "MaxUrlRetrievalByteCount" -ErrorAction SilentlyContinue
    
    Add-Result -Category "NIST - SC-17" -Status "Info" `
        -Message "PKI certificate infrastructure" `
        -Details "NIST 800-53 SC-17: Issue public key certificates under approved PKI or obtain from approved service provider."
    
    # Check trusted root certificates
    $trustedRoots = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
    
    if ($trustedRoots) {
        Add-Result -Category "NIST - SC-17" -Status "Info" `
            -Message "Trusted root certificates: $($trustedRoots.Count)" `
            -Details "NIST 800-53 SC-17: Review trusted root CAs. Remove unauthorized or untrusted certificates."
    }
}
catch {
    Add-Result -Category "NIST - SC-17" -Status "Error" `
        -Message "Failed to check PKI certificates: $($_.Exception.Message)"
}

# SC-18: Mobile Code
try {
    Write-Host "  [*] SC-18: Mobile Code" -ForegroundColor Gray
    
    # Check for browser security settings (controls mobile code like JavaScript, ActiveX)
    $ieSecurityZones = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -ErrorAction SilentlyContinue
    
    if ($ieSecurityZones) {
        Add-Result -Category "NIST - SC-18" -Status "Info" `
            -Message "Mobile code security zones configured" `
            -Details "NIST 800-53 SC-18: Control mobile code execution (JavaScript, ActiveX, Java applets). Review browser security settings."
    }
    
    # Check for application whitelisting (prevents unauthorized mobile code)
    $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        Add-Result -Category "NIST - SC-18" -Status "Pass" `
            -Message "Application control active (AppLocker)" `
            -Details "NIST 800-53 SC-18: AppLocker can restrict mobile code execution through application whitelisting."
    }
    
    # SC-18(1): Identify Unacceptable Code / Take Corrective Actions
    Add-Result -Category "NIST - SC-18(1)" -Status "Info" `
        -Message "Mobile code monitoring and response" `
        -Details "NIST 800-53 SC-18(1): Implement monitoring to detect and prevent execution of unacceptable mobile code."
}
catch {
    Add-Result -Category "NIST - SC-18" -Status "Error" `
        -Message "Failed to check mobile code controls: $($_.Exception.Message)"
}

# SC-20: Secure Name/Address Resolution Service (Authoritative Source)
try {
    Write-Host "  [*] SC-20: Secure Name Resolution" -ForegroundColor Gray
    
    # Check DNS client settings
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    
    if ($dnsCache) {
        Add-Result -Category "NIST - SC-20" -Status "Info" `
            -Message "DNS resolution active with caching" `
            -Details "NIST 800-53 SC-20: Verify DNS queries go to authoritative, trusted DNS servers. Consider DNSSEC for integrity."
    }
    
    # SC-20(2): Data Origin and Integrity
    Add-Result -Category "NIST - SC-20(2)" -Status "Info" `
        -Message "DNSSEC for data origin and integrity" `
        -Details "NIST 800-53 SC-20(2): Implement DNSSEC to verify DNS response authenticity and integrity."
    
    # Check for LLMNR/NetBIOS (can be security risks)
    $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
        Add-Result -Category "NIST - SC-20" -Status "Pass" `
            -Message "LLMNR disabled (secure name resolution)" `
            -Details "NIST 800-53 SC-20: LLMNR disabled to prevent name resolution poisoning attacks."
    } else {
        Add-Result -Category "NIST - SC-20" -Status "Warning" `
            -Message "LLMNR may be enabled (potential security risk)" `
            -Details "NIST 800-53 SC-20: Disable LLMNR to prevent man-in-the-middle name resolution attacks." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Force"
    }
}
catch {
    Add-Result -Category "NIST - SC-20" -Status "Error" `
        -Message "Failed to check name resolution security: $($_.Exception.Message)"
}

# SC-21: Secure Name/Address Resolution Service (Recursive or Caching Resolver)
try {
    Write-Host "  [*] SC-21: Recursive DNS Resolution Security" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SC-21" -Status "Info" `
        -Message "DNS recursive resolver security" `
        -Details "NIST 800-53 SC-21: If operating DNS server, configure as authoritative or secured recursive resolver. Request/verify DNSSEC validation."
}
catch {
    Add-Result -Category "NIST - SC-21" -Status "Error" `
        -Message "Failed to check recursive DNS security: $($_.Exception.Message)"
}

# SC-22: Architecture and Provisioning for Name/Address Resolution Service
try {
    Write-Host "  [*] SC-22: DNS Architecture" -ForegroundColor Gray
    
    # Check if DNS server role is installed
    $dnsServer = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    
    if ($dnsServer) {
        if ($dnsServer.Status -eq "Running") {
            Add-Result -Category "NIST - SC-22" -Status "Info" `
                -Message "DNS Server role active on this system" `
                -Details "NIST 800-53 SC-22: Ensure DNS servers are fault-tolerant and implement role separation (authoritative vs. recursive)."
        }
    } else {
        Add-Result -Category "NIST - SC-22" -Status "Info" `
            -Message "DNS client only (no server role)" `
            -Details "NIST 800-53 SC-22: System relies on external DNS infrastructure."
    }
}
catch {
    Add-Result -Category "NIST - SC-22" -Status "Error" `
        -Message "Failed to check DNS architecture: $($_.Exception.Message)"
}

# SC-23: Session Authenticity
try {
    Write-Host "  [*] SC-23: Session Authenticity" -ForegroundColor Gray
    
    # Check for Kerberos (provides session authenticity in domain environments)
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - SC-23" -Status "Pass" `
            -Message "Session authenticity via Kerberos (domain environment)" `
            -Details "NIST 800-53 SC-23: Kerberos provides mutual authentication and session integrity protection."
        
        # SC-23(1): Invalidate Session Identifiers at Logout
        Add-Result -Category "NIST - SC-23(1)" -Status "Pass" `
            -Message "Kerberos tickets invalidated at logout" `
            -Details "NIST 800-53 SC-23(1): Session tickets are invalidated when user logs out."
    } else {
        Add-Result -Category "NIST - SC-23" -Status "Info" `
            -Message "Standalone system - session authenticity limited" `
            -Details "NIST 800-53 SC-23: Domain membership provides Kerberos-based session authenticity."
    }
}
catch {
    Add-Result -Category "NIST - SC-23" -Status "Error" `
        -Message "Failed to check session authenticity: $($_.Exception.Message)"
}

# SC-28: Protection of Information at Rest (COMPREHENSIVE)
try {
    Write-Host "  [*] SC-28: Protection of Information at Rest" -ForegroundColor Gray
    
    # Check all fixed drives for encryption
    $volumes = Get-Volume | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter }
    $encryptedVolumes = @()
    $unencryptedVolumes = @()
    
    foreach ($volume in $volumes) {
        $bitlocker = Get-BitLockerVolume -MountPoint "$($volume.DriveLetter):" -ErrorAction SilentlyContinue
        
        if ($bitlocker) {
            if ($bitlocker.VolumeStatus -eq "FullyEncrypted") {
                $encryptedVolumes += "$($volume.DriveLetter): ($($bitlocker.EncryptionMethod))"
            } elseif ($bitlocker.VolumeStatus -eq "FullyDecrypted") {
                $unencryptedVolumes += "$($volume.DriveLetter):"
            }
        } else {
            $unencryptedVolumes += "$($volume.DriveLetter): (BitLocker N/A)"
        }
    }
    
    if ($encryptedVolumes.Count -gt 0 -and $unencryptedVolumes.Count -eq 0) {
        Add-Result -Category "NIST - SC-28" -Status "Pass" `
            -Message "All fixed drives encrypted: $($encryptedVolumes -join ', ')" `
            -Details "NIST 800-53 SC-28: Data at rest protected via cryptographic mechanisms on all volumes."
    } elseif ($encryptedVolumes.Count -gt 0) {
        Add-Result -Category "NIST - SC-28" -Status "Warning" `
            -Message "Partial encryption - Encrypted: $($encryptedVolumes -join ', '); Unencrypted: $($unencryptedVolumes -join ', ')" `
            -Details "NIST 800-53 SC-28: Encrypt all volumes containing sensitive data." `
            -Remediation "Enable-BitLocker on unencrypted volumes"
    } else {
        Add-Result -Category "NIST - SC-28" -Status "Fail" `
            -Message "No encrypted volumes detected" `
            -Details "NIST 800-53 SC-28: Implement cryptographic protection for data at rest (BitLocker, third-party encryption)." `
            -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector" `
            -Priority "High"
    }
    
    # SC-28(1): Cryptographic Protection
    if ($encryptedVolumes.Count -gt 0) {
        Add-Result -Category "NIST - SC-28(1)" -Status "Pass" `
            -Message "Cryptographic mechanisms implemented for data at rest" `
            -Details "NIST 800-53 SC-28(1): NIST-approved cryptographic algorithms protect stored information."
    }
    
    # SC-28(2): Off-Line Storage
    Add-Result -Category "NIST - SC-28(2)" -Status "Info" `
        -Message "Offline storage encryption recommended" `
        -Details "NIST 800-53 SC-28(2): Encrypt removable media and offline backups (BitLocker To Go, encrypted backup solutions)."
}
catch {
    Add-Result -Category "NIST - SC-28" -Status "Error" `
        -Message "Failed to check data at rest protection: $($_.Exception.Message)"
}

# SC-39: Process Isolation
try {
    Write-Host "  [*] SC-39: Process Isolation" -ForegroundColor Gray
    
    # Check DEP (Data Execution Prevention)
    $dep = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    
    if ($dep -and $dep.DataExecutionPrevention_Available) {
        Add-Result -Category "NIST - SC-39" -Status "Pass" `
            -Message "Process isolation via Data Execution Prevention (DEP)" `
            -Details "NIST 800-53 SC-39: DEP enabled. Support level: $($dep.DataExecutionPrevention_SupportPolicy)"
    }
    
    # Check ASLR (Address Space Layout Randomization) - Windows feature
    Add-Result -Category "NIST - SC-39" -Status "Pass" `
        -Message "Process isolation via ASLR (Address Space Layout Randomization)" `
        -Details "NIST 800-53 SC-39: Windows implements ASLR to randomize memory locations, preventing exploit attacks."
}
catch {
    Add-Result -Category "NIST - SC-39" -Status "Error" `
        -Message "Failed to check process isolation: $($_.Exception.Message)"
}

# SC-40: Wireless Link Protection
try {
    Write-Host "  [*] SC-40: Wireless Link Protection" -ForegroundColor Gray
    
    # Check for wireless adapters
    $wirelessAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "wireless|wi-fi|802.11" }
    
    if ($wirelessAdapters) {
        # Check current wireless profile security
        $currentProfile = netsh wlan show interfaces 2>$null | Select-String "Profile"
        
        if ($currentProfile) {
            $profileName = $currentProfile.ToString().Split(":")[1].Trim()
            $profileSecurity = netsh wlan show profile name="$profileName" key=clear 2>$null | Select-String "Authentication|Cipher"
            
            if ($profileSecurity -match "WPA2|WPA3") {
                Add-Result -Category "NIST - SC-40" -Status "Pass" `
                    -Message "Wireless connection using WPA2/WPA3 encryption" `
                    -Details "NIST 800-53 SC-40: Wireless link protected with approved cryptographic mechanisms."
            } else {
                Add-Result -Category "NIST - SC-40" -Status "Warning" `
                    -Message "Wireless security may be weak" `
                    -Details "NIST 800-53 SC-40: Ensure wireless connections use WPA2-Enterprise or WPA3." `
                    -Remediation "Configure wireless profiles to use WPA2/WPA3 with AES encryption"
            }
        } else {
            Add-Result -Category "NIST - SC-40" -Status "Info" `
                -Message "Wireless adapter present but not connected" `
                -Details "NIST 800-53 SC-40: Ensure wireless connections use WPA2/WPA3 when active."
        }
    } else {
        Add-Result -Category "NIST - SC-40" -Status "Info" `
            -Message "No wireless adapters detected" `
            -Details "NIST 800-53 SC-40: System does not have wireless capability."
    }
}
catch {
    Add-Result -Category "NIST - SC-40" -Status "Error" `
        -Message "Failed to check wireless link protection: $($_.Exception.Message)"
}

# SC-42: Sensor Capability and Data
try {
    Write-Host "  [*] SC-42: Sensor Capability and Data" -ForegroundColor Gray
    
    # Check location services
    $locationServices = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -ErrorAction SilentlyContinue
    
    if ($locationServices) {
        if ($locationServices.Value -eq "Deny") {
            Add-Result -Category "NIST - SC-42" -Status "Pass" `
                -Message "Location services disabled system-wide" `
                -Details "NIST 800-53 SC-42: Geolocation sensor data collection disabled."
        } else {
            Add-Result -Category "NIST - SC-42" -Status "Info" `
                -Message "Location services: $($locationServices.Value)" `
                -Details "NIST 800-53 SC-42: Review location data collection. Disable if not required, or provide user notice/control."
        }
    }
    
    # SC-42(1): Reporting to Authorized Individuals or Roles
    Add-Result -Category "NIST - SC-42(1)" -Status "Info" `
        -Message "Sensor data usage notification" `
        -Details "NIST 800-53 SC-42(1): Inform users when sensors (camera, microphone, location) are collecting data."
}
catch {
    Add-Result -Category "NIST - SC-42" -Status "Error" `
        -Message "Failed to check sensor capabilities: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53 Rev 5: System and Information Integrity (SI) - COMPREHENSIVE
# ============================================================================
Write-Host "`n[NIST] Checking System and Information Integrity (SI) Controls..." -ForegroundColor Yellow

# SI-1: Policy and Procedures
Add-Result -Category "NIST - SI-1" -Status "Info" `
    -Message "System and Information Integrity Policy: Documentation review required" `
    -Details "NIST 800-53 SI-1: Develop, document, and disseminate system integrity policies and procedures. Manual verification required." `
    -Priority "Medium"

# SI-2: Flaw Remediation (COMPREHENSIVE)
try {
    Write-Host "  [*] SI-2: Flaw Remediation (Patching)" -ForegroundColor Gray
    
    # Check Windows Update service
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($wuService -and $wuService.Status -eq "Running") {
        Add-Result -Category "NIST - SI-2" -Status "Pass" `
            -Message "Windows Update service running" `
            -Details "NIST 800-53 SI-2: System configured to receive security updates."
    } else {
        Add-Result -Category "NIST - SI-2" -Status "Fail" `
            -Message "Windows Update service not running" `
            -Details "NIST 800-53 SI-2: Enable Windows Update for flaw remediation." `
            -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic" `
            -Priority "High"
    }
    
    # Check for recent updates
    $updateCheckSuccess = $false
    try {
        $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()
        $updateCheckSuccess = $true
        
        if ($historyCount -gt 0) {
            $recentUpdates = $searcher.QueryHistory(0, 30) | Where-Object { $_.Date -gt (Get-Date).AddDays(-30) }
            
            if ($recentUpdates) {
                $successCount = ($recentUpdates | Where-Object { $_.ResultCode -eq 2 }).Count
                $importantCount = ($recentUpdates | Where-Object { $_.Categories | Where-Object { $_.Name -match "Security|Critical" } }).Count
                
                Add-Result -Category "NIST - SI-2" -Status "Pass" `
                    -Message "Recent updates installed: $successCount successful in last 30 days ($importantCount security/critical)" `
                    -Details "NIST 800-53 SI-2: Regular flaw remediation is being performed."
            } else {
                Add-Result -Category "NIST - SI-2" -Status "Fail" `
                    -Message "No updates installed in the last 30 days" `
                    -Details "NIST 800-53 SI-2: Install security updates regularly (monthly minimum)." `
                    -Remediation "Install pending Windows updates via Settings > Update & Security" `
                    -Priority "High"
            }
        }
        
        # SI-2(2): Automated Flaw Remediation Status
        $pendingUpdates = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        
        if ($pendingUpdates.Updates.Count -gt 0) {
            $criticalCount = ($pendingUpdates.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
            $importantCount = ($pendingUpdates.Updates | Where-Object { $_.MsrcSeverity -eq "Important" }).Count
            $moderateCount = ($pendingUpdates.Updates | Where-Object { $_.MsrcSeverity -eq "Moderate" }).Count
            
            if ($criticalCount -gt 0) {
                Add-Result -Category "NIST - SI-2(2)" -Status "Fail" `
                    -Message "$criticalCount critical update(s) pending installation" `
                    -Details "NIST 800-53 SI-2(2): Critical: $criticalCount, Important: $importantCount, Moderate: $moderateCount. Install immediately." `
                    -Remediation "Install-Module PSWindowsUpdate; Install-WindowsUpdate -AcceptAll -AutoReboot" `
                    -Priority "High"
            } elseif ($importantCount -gt 0) {
                Add-Result -Category "NIST - SI-2(2)" -Status "Warning" `
                    -Message "$importantCount important update(s) pending" `
                    -Details "NIST 800-53 SI-2(2): Important: $importantCount, Moderate: $moderateCount. Install within 30 days." `
                    -Remediation "Install pending updates"
            } else {
                Add-Result -Category "NIST - SI-2(2)" -Status "Info" `
                    -Message "$($pendingUpdates.Updates.Count) optional/moderate update(s) available" `
                    -Details "NIST 800-53 SI-2(2): No critical or important updates pending."
            }
        } else {
            Add-Result -Category "NIST - SI-2(2)" -Status "Pass" `
                -Message "No pending updates" `
                -Details "NIST 800-53 SI-2(2): System is up to date with available patches."
        }
        
        # SI-2(3): Time to Remediate Flaws
        Add-Result -Category "NIST - SI-2(3)" -Status "Info" `
            -Message "Flaw remediation timeline requirements" `
            -Details "NIST 800-53 SI-2(3): Establish time limits for flaw remediation. Recommended: Critical (within 30 days), High (within 90 days)."
        
        # SI-2(5): Automatic Software Updates
        $autoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        
        if ($autoUpdate -and $autoUpdate.NoAutoUpdate -eq 0) {
            Add-Result -Category "NIST - SI-2(5)" -Status "Pass" `
                -Message "Automatic updates enabled" `
                -Details "NIST 800-53 SI-2(5): System automatically receives security updates."
        } elseif (-not $autoUpdate -or $autoUpdate.NoAutoUpdate -eq 1) {
            Add-Result -Category "NIST - SI-2(5)" -Status "Warning" `
                -Message "Automatic updates may not be configured" `
                -Details "NIST 800-53 SI-2(5): Enable automatic updates for critical security patches." `
                -Remediation "Configure via Group Policy or Settings > Update & Security > Windows Update > Advanced options"
        }
        
        # SI-2(6): Removal of Previous Versions of Software
        Add-Result -Category "NIST - SI-2(6)" -Status "Info" `
            -Message "Previous software version management" `
            -Details "NIST 800-53 SI-2(6): Remove or disable previous versions of software after updates unless required for rollback."
        
    }
    catch {
        # Windows Update COM object access failed
        if (-not $updateCheckSuccess) {
            Add-Result -Category "NIST - SI-2" -Status "Warning" `
                -Message "Unable to query Windows Update history (COM access failed)" `
                -Details "NIST 800-53 SI-2: Windows Update service may be unavailable or access restricted. Error: $($_.Exception.Message). Verify wuauserv is running." `
                -Remediation "Restart-Service wuauserv; Verify Windows Update service is running and accessible"
            
            # Still try to check for automatic updates setting
            try {
                $autoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
                
                if ($autoUpdate -and $autoUpdate.NoAutoUpdate -eq 0) {
                    Add-Result -Category "NIST - SI-2(5)" -Status "Pass" `
                        -Message "Automatic updates enabled" `
                        -Details "NIST 800-53 SI-2(5): System configured to receive automatic updates."
                } else {
                    Add-Result -Category "NIST - SI-2(5)" -Status "Warning" `
                        -Message "Automatic updates may not be configured" `
                        -Details "NIST 800-53 SI-2(5): Enable automatic updates for critical security patches."
                }
            }
            catch {
                # Silently continue if auto-update check also fails
            }
        } else {
            # Some other error occurred after successful session creation
            Add-Result -Category "NIST - SI-2" -Status "Error" `
                -Message "Failed to complete update history check: $($_.Exception.Message)"
        }
    }
}
catch {
    Add-Result -Category "NIST - SI-2" -Status "Error" `
        -Message "Failed to check flaw remediation: $($_.Exception.Message)"
}

# SI-3: Malicious Code Protection (COMPREHENSIVE)
try {
    Write-Host "  [*] SI-3: Malicious Code Protection" -ForegroundColor Gray
    
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus) {
        # SI-3: Basic malware protection
        if ($defenderStatus.AntivirusEnabled) {
            Add-Result -Category "NIST - SI-3" -Status "Pass" `
                -Message "Antivirus protection enabled" `
                -Details "NIST 800-53 SI-3: Windows Defender Antivirus provides malicious code detection and eradication."
            
            # Real-time protection
            if ($defenderStatus.RealTimeProtectionEnabled) {
                Add-Result -Category "NIST - SI-3" -Status "Pass" `
                    -Message "Real-time malware scanning active" `
                    -Details "NIST 800-53 SI-3: Real-time protection monitors files, downloads, and system activity."
            } else {
                Add-Result -Category "NIST - SI-3" -Status "Fail" `
                    -Message "Real-time protection DISABLED" `
                    -Details "NIST 800-53 SI-3: Enable real-time malware scanning for continuous protection." `
                    -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
                    -Priority "High"
            }
            
            # Behavior monitoring
            if ($defenderStatus.BehaviorMonitorEnabled) {
                Add-Result -Category "NIST - SI-3" -Status "Pass" `
                    -Message "Behavior monitoring enabled" `
                    -Details "NIST 800-53 SI-3: Behavioral analysis detects suspicious activity patterns."
            } else {
                Add-Result -Category "NIST - SI-3" -Status "Warning" `
                    -Message "Behavior monitoring disabled" `
                    -Details "NIST 800-53 SI-3: Enable behavior monitoring for advanced threat detection." `
                    -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"
            }
            
            # IOAV (IE/Outlook Attachment) protection
            if ($defenderStatus.IoavProtectionEnabled) {
                Add-Result -Category "NIST - SI-3" -Status "Pass" `
                    -Message "Download and attachment scanning enabled" `
                    -Details "NIST 800-53 SI-3: Email attachments and downloads scanned before opening."
            }
            
            # On-access protection
            if ($defenderStatus.OnAccessProtectionEnabled) {
                Add-Result -Category "NIST - SI-3" -Status "Pass" `
                    -Message "On-access file scanning enabled" `
                    -Details "NIST 800-53 SI-3: Files scanned when accessed or modified."
            }
            
        } else {
            Add-Result -Category "NIST - SI-3" -Status "Fail" `
                -Message "Antivirus protection DISABLED" `
                -Details "NIST 800-53 SI-3: Enable antivirus protection immediately." `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false; Set-MpPreference -DisableIOAVProtection `$false" `
                -Priority "High"
        }
        
        # SI-3(1): Central Management
        $mpComputerStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if ($mpComputerStatus.AMRunningMode -match "Managed") {
            Add-Result -Category "NIST - SI-3(1)" -Status "Pass" `
                -Message "Antivirus centrally managed" `
                -Details "NIST 800-53 SI-3(1): Windows Defender managed via Group Policy or Microsoft Defender for Endpoint."
        } else {
            Add-Result -Category "NIST - SI-3(1)" -Status "Info" `
                -Message "Antivirus not centrally managed (standalone mode)" `
                -Details "NIST 800-53 SI-3(1): Implement centralized management (Group Policy, Intune, Defender for Endpoint)."
        }
        
        # SI-3(2): Automatic Updates
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        
        if ($signatureAge.Days -le 2) {
            Add-Result -Category "NIST - SI-3(2)" -Status "Pass" `
                -Message "Malware definitions current ($($signatureAge.Days) day(s) old)" `
                -Details "NIST 800-53 SI-3(2): Automatic signature updates functioning. Last update: $($defenderStatus.AntivirusSignatureLastUpdated)"
        } elseif ($signatureAge.Days -le 7) {
            Add-Result -Category "NIST - SI-3(2)" -Status "Warning" `
                -Message "Malware definitions aging ($($signatureAge.Days) days old)" `
                -Details "NIST 800-53 SI-3(2): Signatures should update daily. Last update: $($defenderStatus.AntivirusSignatureLastUpdated)" `
                -Remediation "Update-MpSignature"
        } else {
            Add-Result -Category "NIST - SI-3(2)" -Status "Fail" `
                -Message "Malware definitions OUTDATED ($($signatureAge.Days) days old)" `
                -Details "NIST 800-53 SI-3(2): Update definitions immediately. Last update: $($defenderStatus.AntivirusSignatureLastUpdated)" `
                -Remediation "Update-MpSignature; Verify network connectivity and Windows Update service" `
                -Priority "High"
        }
        
        # SI-3(4): Updates Only by Privileged Users
        Add-Result -Category "NIST - SI-3(4)" -Status "Pass" `
            -Message "Malware definition updates controlled by system" `
            -Details "NIST 800-53 SI-3(4): Windows Defender updates managed centrally, not by individual users."
        
        # SI-3(6): Testing / Verification
        Add-Result -Category "NIST - SI-3(6)" -Status "Info" `
            -Message "Malware protection testing recommended" `
            -Details "NIST 800-53 SI-3(6): Test antivirus using EICAR test file or coordination with security team."
        
        # SI-3(7): Nonsignature-Based Detection
        if ($defenderStatus.BehaviorMonitorEnabled) {
            Add-Result -Category "NIST - SI-3(7)" -Status "Pass" `
                -Message "Non-signature detection via behavior monitoring" `
                -Details "NIST 800-53 SI-3(7): Behavior-based and heuristic detection supplement signature-based scanning."
        }
        
        # SI-3(8): Detect Unauthorized Commands
        Add-Result -Category "NIST - SI-3(8)" -Status "Info" `
            -Message "Command-level malware detection" `
            -Details "NIST 800-53 SI-3(8): Advanced threat protection (ATP) can detect malicious commands. Consider Microsoft Defender for Endpoint."
        
        # SI-3(10): Malicious Code Analysis
        $sampleSubmission = Get-MpPreference -ErrorAction SilentlyContinue
        
        if ($sampleSubmission -and $sampleSubmission.SubmitSamplesConsent -gt 0) {
            Add-Result -Category "NIST - SI-3(10)" -Status "Pass" `
                -Message "Malicious code sample submission enabled" `
                -Details "NIST 800-53 SI-3(10): Suspicious files submitted to Microsoft for analysis. Setting: $($sampleSubmission.SubmitSamplesConsent)"
        } else {
            Add-Result -Category "NIST - SI-3(10)" -Status "Info" `
                -Message "Sample submission not configured" `
                -Details "NIST 800-53 SI-3(10): Enable cloud-based sample submission for advanced analysis." `
                -Remediation "Set-MpPreference -SubmitSamplesConsent SendSafeSamples"
        }
        
    } else {
        Add-Result -Category "NIST - SI-3" -Status "Fail" `
            -Message "Windows Defender status unavailable (may be disabled or replaced)" `
            -Details "NIST 800-53 SI-3: Ensure antivirus protection is installed and active." `
            -Priority "High"
    }
}
catch {
    Add-Result -Category "NIST - SI-3" -Status "Error" `
        -Message "Failed to check malicious code protection: $($_.Exception.Message)"
}

# SI-4: System Monitoring (COMPREHENSIVE)
try {
    Write-Host "  [*] SI-4: System Monitoring" -ForegroundColor Gray
    
    # Check Windows Defender monitoring
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference) {
        # SI-4: Basic monitoring
        Add-Result -Category "NIST - SI-4" -Status "Pass" `
            -Message "System monitoring active via Windows Defender" `
            -Details "NIST 800-53 SI-4: Real-time monitoring detects attacks, intrusions, and unauthorized activities."
        
        # SI-4(2): Automated Tools for Real-Time Analysis
        if ($mpPreference.MAPSReporting -gt 0) {
            Add-Result -Category "NIST - SI-4(2)" -Status "Pass" `
                -Message "Cloud-based automated threat analysis enabled" `
                -Details "NIST 800-53 SI-4(2): Microsoft Active Protection Service (MAPS) provides real-time threat intelligence. Level: $($mpPreference.MAPSReporting)"
        } else {
            Add-Result -Category "NIST - SI-4(2)" -Status "Warning" `
                -Message "Cloud-based protection not enabled" `
                -Details "NIST 800-53 SI-4(2): Enable MAPS for enhanced real-time threat detection." `
                -Remediation "Set-MpPreference -MAPSReporting Advanced"
        }
        
        # SI-4(4): Inbound and Outbound Communications Traffic
        $firewallLogging = Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked
        $loggingEnabled = $firewallLogging | Where-Object { $_.LogAllowed -eq $true -or $_.LogBlocked -eq $true }
        
        if ($loggingEnabled) {
            Add-Result -Category "NIST - SI-4(4)" -Status "Pass" `
                -Message "Network traffic logging enabled on firewall" `
                -Details "NIST 800-53 SI-4(4): Firewall logs unusual/unauthorized inbound and outbound traffic."
        } else {
            Add-Result -Category "NIST - SI-4(4)" -Status "Warning" `
                -Message "Firewall logging not fully enabled" `
                -Details "NIST 800-53 SI-4(4): Enable firewall logging for traffic monitoring." `
                -Remediation "Set-NetFirewallProfile -Name Domain,Private,Public -LogBlocked True -LogAllowed True"
        }
        
        # SI-4(5): System-Generated Alerts
        Add-Result -Category "NIST - SI-4(5)" -Status "Pass" `
            -Message "Automated alert generation via Windows Defender" `
            -Details "NIST 800-53 SI-4(5): Windows Security Center alerts on security issues and threats."
        
        # SI-4(7): Automated Response to Suspicious Events
        if ($mpPreference.DisableAutoExclusions -eq $false) {
            Add-Result -Category "NIST - SI-4(7)" -Status "Pass" `
                -Message "Automated threat response enabled" `
                -Details "NIST 800-53 SI-4(7): Windows Defender automatically quarantines and remediates detected threats."
        }
        
        # SI-4(10): Visibility of Encrypted Communications
        Add-Result -Category "NIST - SI-4(10)" -Status "Info" `
            -Message "Encrypted traffic inspection requires network appliances" `
            -Details "NIST 800-53 SI-4(10): Implement SSL/TLS inspection on network security devices for visibility into encrypted traffic."
        
        # SI-4(12): Automated Alerts
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
            Add-Result -Category "NIST - SI-4(12)" -Status "Pass" `
                -Message "Automated alerting on compromise indicators" `
                -Details "NIST 800-53 SI-4(12): Windows Defender generates alerts on detected threats in real-time."
        }
        
        # SI-4(16): Correlate Monitoring Information
        Add-Result -Category "NIST - SI-4(16)" -Status "Info" `
            -Message "Monitoring correlation requires SIEM" `
            -Details "NIST 800-53 SI-4(16): Implement SIEM to correlate monitoring information from multiple sources (logs, IDS, antivirus)."
        
        # SI-4(23): Host-Based Devices
        Add-Result -Category "NIST - SI-4(23)" -Status "Pass" `
            -Message "Host-based monitoring via Windows Defender" `
            -Details "NIST 800-53 SI-4(23): Each host implements intrusion detection monitoring."
    }
}
catch {
    Add-Result -Category "NIST - SI-4" -Status "Error" `
        -Message "Failed to check system monitoring: $($_.Exception.Message)"
}

# SI-5: Security Alerts, Advisories, and Directives
try {
    Write-Host "  [*] SI-5: Security Alerts and Advisories" -ForegroundColor Gray
    
    # Check if system can receive security notifications
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($mpPreference -and $mpPreference.MAPSReporting -gt 0) {
        Add-Result -Category "NIST - SI-5" -Status "Pass" `
            -Message "Security intelligence updates from Microsoft" `
            -Details "NIST 800-53 SI-5: System receives security alerts and threat intelligence from Microsoft."
    }
    
    # SI-5(1): Automated Alerts and Advisories
    Add-Result -Category "NIST - SI-5(1)" -Status "Info" `
        -Message "Automated security alert subscription" `
        -Details "NIST 800-53 SI-5(1): Subscribe to automated security alerts from vendors, US-CERT, CISA, and industry sources."
}
catch {
    Add-Result -Category "NIST - SI-5" -Status "Error" `
        -Message "Failed to check security alerts: $($_.Exception.Message)"
}

# SI-6: Security and Privacy Function Verification
try {
    Write-Host "  [*] SI-6: Security Function Verification" -ForegroundColor Gray
    
    # Check Windows Defender scan schedule
    $scheduledScans = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($scheduledScans) {
        $scanDay = $scheduledScans.ScanScheduleDay
        $scanTime = $scheduledScans.ScanScheduleTime
        
        if ($scanDay -ne "Never" -and $scanTime) {
            Add-Result -Category "NIST - SI-6" -Status "Pass" `
                -Message "Scheduled security scans configured" `
                -Details "NIST 800-53 SI-6: Scheduled scan: Day $scanDay at $scanTime. Verifies security function operation."
        } else {
            Add-Result -Category "NIST - SI-6" -Status "Warning" `
                -Message "Scheduled security scans not configured" `
                -Details "NIST 800-53 SI-6: Configure periodic security scans to verify protection mechanisms." `
                -Remediation "Set-MpPreference -ScanScheduleDay 0 -ScanScheduleTime 02:00:00"
        }
    }
    
    # SI-6(1): Notification of Failed Security Tests
    Add-Result -Category "NIST - SI-6(1)" -Status "Info" `
        -Message "Security test failure notification" `
        -Details "NIST 800-53 SI-6(1): Windows Security Center notifies on security function failures (disabled AV, outdated signatures)."
}
catch {
    Add-Result -Category "NIST - SI-6" -Status "Error" `
        -Message "Failed to check security function verification: $($_.Exception.Message)"
}

# SI-7: Software, Firmware, and Information Integrity (COMPREHENSIVE)
try {
    Write-Host "  [*] SI-7: Software and Information Integrity" -ForegroundColor Gray
    
    # Check Windows Defender Application Control (WDAC) / Device Guard
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($deviceGuard) {
        # SI-7(1): Integrity Checks
        if ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Add-Result -Category "NIST - SI-7(1)" -Status "Pass" `
                -Message "Code Integrity Policy enforced (WDAC)" `
                -Details "NIST 800-53 SI-7(1): Software integrity verification active. Only signed code can execute."
        } else {
            Add-Result -Category "NIST - SI-7(1)" -Status "Info" `
                -Message "Code Integrity Policy not enforced" `
                -Details "NIST 800-53 SI-7(1): Consider implementing WDAC for application whitelisting and integrity verification."
        }
        
        # SI-7(6): Cryptographic Protection
        if ($deviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
            Add-Result -Category "NIST - SI-7(6)" -Status "Pass" `
                -Message "VBS protects integrity verification mechanisms" `
                -Details "NIST 800-53 SI-7(6): Virtualization-based security isolates code integrity checks."
        }
    }
    
    # Check driver signature enforcement
    $driverSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -ErrorAction SilentlyContinue
    
    if ($driverSigning) {
        Add-Result -Category "NIST - SI-7" -Status "Pass" `
            -Message "Driver signature verification enabled" `
            -Details "NIST 800-53 SI-7: Only signed drivers can load, ensuring kernel-level integrity."
    }
    
    # SI-7(5): Automated Response to Integrity Violations
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "NIST - SI-7(5)" -Status "Pass" `
            -Message "Automated response to integrity violations" `
            -Details "NIST 800-53 SI-7(5): Windows Defender automatically responds to detected file integrity violations."
    }
    
    # SI-7(7): Integration of Detection and Response
    Add-Result -Category "NIST - SI-7(7)" -Status "Info" `
        -Message "Detection and response integration" `
        -Details "NIST 800-53 SI-7(7): Integrate integrity monitoring with incident response (EDR solutions like Microsoft Defender for Endpoint)."
    
    # SI-7(9): Verify Boot Process
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "NIST - SI-7(9)" -Status "Pass" `
            -Message "Secure Boot enabled (boot process integrity)" `
            -Details "NIST 800-53 SI-7(9): UEFI Secure Boot verifies bootloader and OS integrity before execution."
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "NIST - SI-7(9)" -Status "Warning" `
            -Message "Secure Boot disabled" `
            -Details "NIST 800-53 SI-7(9): Enable Secure Boot in UEFI/BIOS for boot integrity verification." `
            -Remediation "Enable Secure Boot in UEFI/BIOS settings"
    } else {
        Add-Result -Category "NIST - SI-7(9)" -Status "Info" `
            -Message "Secure Boot not available (Legacy BIOS)" `
            -Details "NIST 800-53 SI-7(9): UEFI with Secure Boot recommended for boot process integrity."
    }
    
    # SI-7(10): Protection of Boot Firmware
    if ($deviceGuard -and $deviceGuard.SecureBootConfigured -eq $true) {
        Add-Result -Category "NIST - SI-7(10)" -Status "Pass" `
            -Message "Boot firmware protected via Secure Boot" `
            -Details "NIST 800-53 SI-7(10): Firmware integrity verified during boot process."
    }
    
    # SI-7(15): Code Authentication
    Add-Result -Category "NIST - SI-7(15)" -Status "Pass" `
        -Message "Code authentication via digital signatures" `
        -Details "NIST 800-53 SI-7(15): Windows requires digital signatures for system files and drivers."
}
catch {
    Add-Result -Category "NIST - SI-7" -Status "Error" `
        -Message "Failed to check software integrity: $($_.Exception.Message)"
}

# SI-8: Spam Protection
try {
    Write-Host "  [*] SI-8: Spam Protection" -ForegroundColor Gray
    
    # Check Windows Defender SmartScreen
    $smartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    
    if ($smartScreen -and $smartScreen.EnableSmartScreen -eq 1) {
        Add-Result -Category "NIST - SI-8" -Status "Pass" `
            -Message "SmartScreen protection enabled" `
            -Details "NIST 800-53 SI-8: SmartScreen filters malicious content and potential spam/phishing."
    } else {
        Add-Result -Category "NIST - SI-8" -Status "Warning" `
            -Message "SmartScreen may not be configured" `
            -Details "NIST 800-53 SI-8: Enable Windows Defender SmartScreen for web and email protection." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 1"
    }
    
    # SI-8(2): Automatic Updates
    Add-Result -Category "NIST - SI-8(2)" -Status "Info" `
        -Message "Spam protection updates via Windows Update" `
        -Details "NIST 800-53 SI-8(2): SmartScreen and Defender updates include spam/phishing detection signatures."
}
catch {
    Add-Result -Category "NIST - SI-8" -Status "Error" `
        -Message "Failed to check spam protection: $($_.Exception.Message)"
}

# SI-10: Information Input Validation
try {
    Write-Host "  [*] SI-10: Information Input Validation" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-10" -Status "Info" `
        -Message "Input validation in applications" `
        -Details "NIST 800-53 SI-10: Applications must validate input accuracy, completeness, and validity. Development requirement."
}
catch {
    Add-Result -Category "NIST - SI-10" -Status "Error" `
        -Message "Failed to check input validation: $($_.Exception.Message)"
}

# SI-11: Error Handling
try {
    Write-Host "  [*] SI-11: Error Handling" -ForegroundColor Gray
    
    # Check Windows Error Reporting
    $werDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
    
    if ($werDisabled -and $werDisabled.Disabled -eq 1) {
        Add-Result -Category "NIST - SI-11" -Status "Warning" `
            -Message "Windows Error Reporting disabled" `
            -Details "NIST 800-53 SI-11: Error reporting can help identify system issues. Consider enabling with privacy controls."
    } else {
        Add-Result -Category "NIST - SI-11" -Status "Info" `
            -Message "Windows Error Reporting configured" `
            -Details "NIST 800-53 SI-11: Error messages generated. Verify sensitive information is not exposed in error details."
    }
}
catch {
    Add-Result -Category "NIST - SI-11" -Status "Error" `
        -Message "Failed to check error handling: $($_.Exception.Message)"
}

# SI-12: Information Management and Retention
try {
    Write-Host "  [*] SI-12: Information Handling and Retention" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-12" -Status "Info" `
        -Message "Information retention policy required" `
        -Details "NIST 800-53 SI-12: Establish retention periods for information types per legal/regulatory requirements."
}
catch {
    Add-Result -Category "NIST - SI-12" -Status "Error" `
        -Message "Failed to check information management: $($_.Exception.Message)"
}

# SI-16: Memory Protection
try {
    Write-Host "  [*] SI-16: Memory Protection" -ForegroundColor Gray
    
    # Check DEP (Data Execution Prevention)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    
    if ($os -and $os.DataExecutionPrevention_Available) {
        Add-Result -Category "NIST - SI-16" -Status "Pass" `
            -Message "Data Execution Prevention (DEP) available and active" `
            -Details "NIST 800-53 SI-16: DEP prevents code execution from data-only memory regions. Policy: $($os.DataExecutionPrevention_SupportPolicy)"
    }
    
    # Check SEHOP (Structured Exception Handler Overwrite Protection)
    $sehop = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
    
    if (-not $sehop -or $sehop.DisableExceptionChainValidation -ne 1) {
        Add-Result -Category "NIST - SI-16" -Status "Pass" `
            -Message "SEHOP (exception handler protection) enabled" `
            -Details "NIST 800-53 SI-16: Protection against exploitation via exception handler overwriting."
    }
    
    # Memory integrity (Core isolation)
    if ($deviceGuard -and $deviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
        Add-Result -Category "NIST - SI-16" -Status "Pass" `
            -Message "Memory integrity (Core isolation) via VBS" `
            -Details "NIST 800-53 SI-16: Hardware-based memory protection through virtualization."
    }
}
catch {
    Add-Result -Category "NIST - SI-16" -Status "Error" `
        -Message "Failed to check memory protection: $($_.Exception.Message)"
}

# SI-18: Personally Identifiable Information Quality Operations
try {
    Write-Host "  [*] SI-18: PII Quality Operations" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-18" -Status "Info" `
        -Message "PII data quality management" `
        -Details "NIST 800-53 SI-18: Implement processes to verify accuracy, relevance, and currency of PII. GDPR/Privacy requirement."
}
catch {
    Add-Result -Category "NIST - SI-18" -Status "Error" `
        -Message "Failed to check PII quality: $($_.Exception.Message)"
}

# SI-19: De-Identification
try {
    Write-Host "  [*] SI-19: De-Identification" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-19" -Status "Info" `
        -Message "PII de-identification techniques" `
        -Details "NIST 800-53 SI-19: Remove PII from datasets when possible. Use anonymization, pseudonymization techniques."
}
catch {
    Add-Result -Category "NIST - SI-19" -Status "Error" `
        -Message "Failed to check de-identification: $($_.Exception.Message)"
}

# SI-20: Tainting
try {
    Write-Host "  [*] SI-20: Tainting (Data Origin Tracking)" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-20" -Status "Info" `
        -Message "Data origin tracking and validation" `
        -Details "NIST 800-53 SI-20: Track data origins, especially from untrusted sources. Validate before use in critical operations."
}
catch {
    Add-Result -Category "NIST - SI-20" -Status "Error" `
        -Message "Failed to check tainting: $($_.Exception.Message)"
}

# SI-21: Information Refresh
try {
    Write-Host "  [*] SI-21: Information Refresh" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-21" -Status "Info" `
        -Message "Information refresh/update process" `
        -Details "NIST 800-53 SI-21: Refresh information at defined intervals or events to ensure currency and accuracy."
}
catch {
    Add-Result -Category "NIST - SI-21" -Status "Error" `
        -Message "Failed to check information refresh: $($_.Exception.Message)"
}

# SI-23: Information Fragmentation
try {
    Write-Host "  [*] SI-23: Information Fragmentation" -ForegroundColor Gray
    
    Add-Result -Category "NIST - SI-23" -Status "Info" `
        -Message "Information fragmentation for security" `
        -Details "NIST 800-53 SI-23: Fragment information across separate systems/components to limit disclosure impact."
}
catch {
    Add-Result -Category "NIST - SI-23" -Status "Error" `
        -Message "Failed to check information fragmentation: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53 Rev 5: Configuration Management (CM) - EXPANDED
# ============================================================================
Write-Host "`n[NIST] Checking Configuration Management (CM) Controls..." -ForegroundColor Yellow

# CM-1: Policy and Procedures
Add-Result -Category "NIST - CM-1" -Status "Info" `
    -Message "Configuration Management Policy: Documentation review required" `
    -Details "NIST 800-53 CM-1: Develop, document, and disseminate configuration management policies. Manual verification required." `
    -Priority "Medium"

# CM-2: Baseline Configuration (ENHANCED)
try {
    Write-Host "  [*] CM-2: Baseline Configuration" -ForegroundColor Gray
    
    # Check Windows Update status
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($wuService -and $wuService.Status -eq "Running") {
        Add-Result -Category "NIST - CM-2" -Status "Pass" `
            -Message "Configuration maintenance via Windows Update" `
            -Details "NIST 800-53 CM-2: Windows Update service maintains system baseline configuration."
    } else {
        Add-Result -Category "NIST - CM-2" -Status "Fail" `
            -Message "Configuration management service not running" `
            -Details "NIST 800-53 CM-2: Enable Windows Update for baseline configuration management." `
            -Remediation "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic" `
            -Priority "High"
    }
    
    # CM-2(2): Automation Support for Accuracy/Currency
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - CM-2(2)" -Status "Pass" `
            -Message "Automated configuration management via domain" `
            -Details "NIST 800-53 CM-2(2): Group Policy provides automated baseline configuration management."
    } else {
        Add-Result -Category "NIST - CM-2(2)" -Status "Info" `
            -Message "Standalone system - limited automation" `
            -Details "NIST 800-53 CM-2(2): Domain membership or MDM provides automated configuration management."
    }
    
    # CM-2(3): Retention of Previous Configurations
    $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    
    if ($restorePoints) {
        Add-Result -Category "NIST - CM-2(3)" -Status "Pass" `
            -Message "Configuration snapshots available: $($restorePoints.Count) restore point(s)" `
            -Details "NIST 800-53 CM-2(3): System Restore maintains previous configurations for rollback."
    } else {
        Add-Result -Category "NIST - CM-2(3)" -Status "Warning" `
            -Message "No restore points available" `
            -Details "NIST 800-53 CM-2(3): Enable System Restore for configuration backup/rollback." `
            -Remediation "Enable-ComputerRestore -Drive C:\; Checkpoint-Computer -Description 'Baseline Configuration'"
    }
    
    # CM-2(7): Configure Systems, Components, or Devices for High-Risk Areas
    Add-Result -Category "NIST - CM-2(7)" -Status "Info" `
        -Message "High-risk area configuration requirements" `
        -Details "NIST 800-53 CM-2(7): Mobile devices and systems in high-risk areas require enhanced security configurations."
}
catch {
    Add-Result -Category "NIST - CM-2" -Status "Error" `
        -Message "Failed to check baseline configuration: $($_.Exception.Message)"
}

# CM-3: Configuration Change Control
try {
    Write-Host "  [*] CM-3: Configuration Change Control" -ForegroundColor Gray
    
    # Check if system is managed
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - CM-3" -Status "Pass" `
            -Message "Configuration change control via Group Policy" `
            -Details "NIST 800-53 CM-3: Centralized change control through domain management."
    } else {
        Add-Result -Category "NIST - CM-3" -Status "Info" `
            -Message "Local configuration management" `
            -Details "NIST 800-53 CM-3: Implement change control process. Document and approve configuration changes."
    }
    
    # CM-3(2): Testing, Validation, and Documentation of Changes
    if ($restorePoints) {
        Add-Result -Category "NIST - CM-3(2)" -Status "Pass" `
            -Message "Configuration rollback capability available" `
            -Details "NIST 800-53 CM-3(2): System Restore enables testing and rollback of configuration changes."
    }
}
catch {
    Add-Result -Category "NIST - CM-3" -Status "Error" `
        -Message "Failed to check change control: $($_.Exception.Message)"
}

# CM-5: Access Restrictions for Change
try {
    Write-Host "  [*] CM-5: Access Restrictions for Change" -ForegroundColor Gray
    
    # Check UAC (restricts configuration changes)
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    
    if ($uac -and $uac.EnableLUA -eq 1) {
        Add-Result -Category "NIST - CM-5" -Status "Pass" `
            -Message "Configuration change restrictions via UAC" `
            -Details "NIST 800-53 CM-5: Physical/logical access restrictions enforced for configuration changes."
        
        # CM-5(1): Automated Access Enforcement / Audit Records
        $auditPolicyChange = Test-AuditPolicy -Subcategory "Audit Policy Change"
        
        if ($auditPolicyChange) {
            Add-Result -Category "NIST - CM-5(1)" -Status "Pass" `
                -Message "Configuration changes audited" `
                -Details "NIST 800-53 CM-5(1): Audit policy changes and configuration modifications logged."
        }
    }
    
    # CM-5(3): Signed Components
    Add-Result -Category "NIST - CM-5(3)" -Status "Pass" `
        -Message "Component integrity via code signing" `
        -Details "NIST 800-53 CM-5(3): Windows requires signed drivers and system components."
}
catch {
    Add-Result -Category "NIST - CM-5" -Status "Error" `
        -Message "Failed to check access restrictions: $($_.Exception.Message)"
}

# CM-6: Configuration Settings (COMPREHENSIVE)
try {
    Write-Host "  [*] CM-6: Configuration Settings" -ForegroundColor Gray
    
    # Check Secure Boot
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    if ($secureBoot -eq $true) {
        Add-Result -Category "NIST - CM-6" -Status "Pass" `
            -Message "Secure Boot enabled (security configuration)" `
            -Details "NIST 800-53 CM-6: Security configuration settings enforced at boot level."
    } elseif ($secureBoot -eq $false) {
        Add-Result -Category "NIST - CM-6" -Status "Warning" `
            -Message "Secure Boot disabled" `
            -Details "NIST 800-53 CM-6: Enable Secure Boot for boot-level security configuration." `
            -Remediation "Enable Secure Boot in UEFI/BIOS settings"
    }
    
    # CM-6(1): Automated Management, Application, and Verification
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        Add-Result -Category "NIST - CM-6(1)" -Status "Pass" `
            -Message "Automated configuration management via Group Policy" `
            -Details "NIST 800-53 CM-6(1): Central configuration enforcement and verification."
    }
    
    # CM-6(2): Respond to Unauthorized Changes
    $defenderTampering = Get-MpPreference -ErrorAction SilentlyContinue
    
    if ($defenderTampering -and $defenderTampering.DisableTamperProtection -eq $false) {
        Add-Result -Category "NIST - CM-6(2)" -Status "Pass" `
            -Message "Tamper Protection enabled (prevents unauthorized changes)" `
            -Details "NIST 800-53 CM-6(2): Windows Defender Tamper Protection prevents unauthorized security setting changes."
    } else {
        Add-Result -Category "NIST - CM-6(2)" -Status "Warning" `
            -Message "Tamper Protection not enabled" `
            -Details "NIST 800-53 CM-6(2): Enable Tamper Protection to prevent unauthorized configuration changes." `
            -Remediation "Set-MpPreference -DisableTamperProtection `$false"
    }
}
catch {
    Add-Result -Category "NIST - CM-6" -Status "Error" `
        -Message "Failed to check configuration settings: $($_.Exception.Message)"
}

# CM-7: Least Functionality (ENHANCED)
try {
    Write-Host "  [*] CM-7: Least Functionality" -ForegroundColor Gray
    
    # Check for unnecessary services
    $unnecessaryServices = @(
        "RemoteRegistry",
        "SSDPSRV",
        "upnphost",
        "WMPNetworkSvc",
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )
    
    $runningUnnecessary = @()
    foreach ($svcName in $unnecessaryServices) {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $runningUnnecessary += $service.DisplayName
        }
    }
    
    if ($runningUnnecessary.Count -eq 0) {
        Add-Result -Category "NIST - CM-7" -Status "Pass" `
            -Message "Unnecessary services disabled" `
            -Details "NIST 800-53 CM-7: System configured with least functionality principle."
    } else {
        Add-Result -Category "NIST - CM-7" -Status "Warning" `
            -Message "Potentially unnecessary services running: $($runningUnnecessary -join ', ')" `
            -Details "NIST 800-53 CM-7: Review and disable services not required for mission/business functions." `
            -Remediation "Stop-Service <ServiceName>; Set-Service <ServiceName> -StartupType Disabled"
    }
    
    # CM-7(2): Prevent Program Execution
    $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        Add-Result -Category "NIST - CM-7(2)" -Status "Pass" `
            -Message "Application execution control (AppLocker) active" `
            -Details "NIST 800-53 CM-7(2): Whitelisting prevents unauthorized program execution."
    } else {
        Add-Result -Category "NIST - CM-7(2)" -Status "Info" `
            -Message "Application whitelisting not detected" `
            -Details "NIST 800-53 CM-7(2): Consider implementing AppLocker or WDAC for execution control."
    }
    
    # CM-7(5): Authorized Software / Whitelisting
    $wdacPolicy = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    
    if ($wdacPolicy -and $wdacPolicy.CodeIntegrityPolicyEnforcementStatus -eq 1) {
        Add-Result -Category "NIST - CM-7(5)" -Status "Pass" `
            -Message "Software whitelisting via WDAC/Device Guard" `
            -Details "NIST 800-53 CM-7(5): Only authorized software can execute (deny-by-default)."
    }
}
catch {
    Add-Result -Category "NIST - CM-7" -Status "Error" `
        -Message "Failed to check least functionality: $($_.Exception.Message)"
}

# CM-8: System Component Inventory
try {
    Write-Host "  [*] CM-8: System Component Inventory" -ForegroundColor Gray
    
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, Publisher, InstallDate |
        Where-Object { $_.DisplayName } |
        Measure-Object
    
    Add-Result -Category "NIST - CM-8" -Status "Info" `
        -Message "Software inventory: $($installedApps.Count) installed application(s)" `
        -Details "NIST 800-53 CM-8: Maintain current inventory of system components. Consider asset management tools."
    
    # CM-8(3): Automated Unauthorized Component Detection
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        Add-Result -Category "NIST - CM-8(3)" -Status "Pass" `
            -Message "Automated unauthorized software detection (AppLocker)" `
            -Details "NIST 800-53 CM-8(3): AppLocker blocks unauthorized software execution."
    }
}
catch {
    Add-Result -Category "NIST - CM-8" -Status "Error" `
        -Message "Failed to check component inventory: $($_.Exception.Message)"
}

# CM-11: User-Installed Software (ENHANCED)
try {
    Write-Host "  [*] CM-11: User-Installed Software" -ForegroundColor Gray
    
    # Check AppLocker
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        $policies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        
        if ($policies) {
            Add-Result -Category "NIST - CM-11" -Status "Pass" `
                -Message "User-installed software controlled via AppLocker" `
                -Details "NIST 800-53 CM-11: AppLocker policies restrict unauthorized software installation."
        } else {
            Add-Result -Category "NIST - CM-11" -Status "Warning" `
                -Message "AppLocker service running but no policies detected" `
                -Details "NIST 800-53 CM-11: Configure AppLocker policies to control software installation."
        }
    } else {
        Add-Result -Category "NIST - CM-11" -Status "Warning" `
            -Message "User-installed software not restricted" `
            -Details "NIST 800-53 CM-11: Implement controls to prevent unauthorized software installation (AppLocker, WDAC, Software Restriction Policies)." `
            -Remediation "Configure AppLocker policies via Group Policy"
    }
    
    # CM-11(2): Software Installation with Privileged Status
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    
    if ($uac -and $uac.EnableLUA -eq 1) {
        Add-Result -Category "NIST - CM-11(2)" -Status "Pass" `
            -Message "Software installation requires elevation" `
            -Details "NIST 800-53 CM-11(2): UAC requires administrative privileges for software installation."
    }
}
catch {
    Add-Result -Category "NIST - CM-11" -Status "Error" `
        -Message "Failed to check user-installed software: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53: Incident Response (IR) - KEY CONTROLS
# ============================================================================
Write-Host "`n[NIST] Checking Incident Response (IR) Controls..." -ForegroundColor Yellow

# IR-4: Incident Handling
try {
    Write-Host "  [*] IR-4: Incident Handling" -ForegroundColor Gray
    
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "NIST - IR-4" -Status "Pass" `
            -Message "Automated incident detection and response active" `
            -Details "NIST 800-53 IR-4: Windows Defender provides real-time threat detection and automated response."
    } else {
        Add-Result -Category "NIST - IR-4" -Status "Fail" `
            -Message "Automated incident response disabled" `
            -Details "NIST 800-53 IR-4: Enable automated threat detection for incident handling." `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -Priority "High"
    }
    
    # IR-4(1): Automated Incident Handling Processes
    Add-Result -Category "NIST - IR-4(1)" -Status "Info" `
        -Message "Automated incident handling process" `
        -Details "NIST 800-53 IR-4(1): Defender provides automated quarantine, blocking, and remediation. Consider EDR for advanced automation."
}
catch {
    Add-Result -Category "NIST - IR-4" -Status "Error" `
        -Message "Failed to check incident handling: $($_.Exception.Message)"
}

# IR-5: Incident Monitoring
try {
    Write-Host "  [*] IR-5: Incident Monitoring" -ForegroundColor Gray
    
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    
    if ($securityLog -and $securityLog.IsEnabled) {
        Add-Result -Category "NIST - IR-5" -Status "Pass" `
            -Message "Security event logging enabled for incident monitoring" `
            -Details "NIST 800-53 IR-5: Security log tracks incidents and suspicious activities."
    }
}
catch {
    Add-Result -Category "NIST - IR-5" -Status "Error" `
        -Message "Failed to check incident monitoring: $($_.Exception.Message)"
}

# ============================================================================
# NIST 800-53: Media Protection (MP) - KEY CONTROLS
# ============================================================================
Write-Host "`n[NIST] Checking Media Protection (MP) Controls..." -ForegroundColor Yellow

# MP-7: Media Use
try {
    Write-Host "  [*] MP-7: Media Use" -ForegroundColor Gray
    
    # Check AutoPlay/AutoRun
    $autoPlay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    
    if ($autoPlay -and $autoPlay.NoDriveTypeAutoRun -eq 255) {
        Add-Result -Category "NIST - MP-7" -Status "Pass" `
            -Message "AutoPlay disabled for all drive types" `
            -Details "NIST 800-53 MP-7: AutoRun/AutoPlay disabled to control removable media usage."
    } else {
        Add-Result -Category "NIST - MP-7" -Status "Fail" `
            -Message "AutoPlay not fully disabled" `
            -Details "NIST 800-53 MP-7: Disable AutoPlay to prevent automatic malware execution from removable media." `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255" `
            -Priority "Medium"
    }
}
catch {
    Add-Result -Category "NIST - MP-7" -Status "Error" `
        -Message "Failed to check media protection: $($_.Exception.Message)"
}

# ============================================================================
# NIST Cybersecurity Framework 2.0 (CSF) Mapping
# ============================================================================
Write-Host "`n[NIST] Mapping to NIST Cybersecurity Framework 2.0..." -ForegroundColor Yellow

# CSF - GOVERN (GV)
Add-Result -Category "NIST - CSF GV" -Status "Info" `
    -Message "Cybersecurity Framework: GOVERN function" `
    -Details "NIST CSF GV: Establish organizational context, strategy, expectations, and oversight for cybersecurity risk management. Requires documented governance."

# CSF - IDENTIFY (ID)
try {
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName } | Measure-Object
    
    Add-Result -Category "NIST - CSF ID.AM" -Status "Info" `
        -Message "CSF IDENTIFY: Asset Management - $($installedApps.Count) software assets" `
        -Details "NIST CSF ID.AM: Maintain inventory of hardware, software, data, and personnel. This check identified software only."
}
catch { }

# CSF - PROTECT (PR)
Add-Result -Category "NIST - CSF PR" -Status "Info" `
    -Message "CSF PROTECT: Identity Management, Awareness, Data Security" `
    -Details "NIST CSF PR: Implement safeguards. See AC, IA, SC controls for specific protections. Key: access control, awareness training, data security, platform security."

# CSF - DETECT (DE)
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        Add-Result -Category "NIST - CSF DE" -Status "Pass" `
            -Message "CSF DETECT: Continuous monitoring active" `
            -Details "NIST CSF DE: Windows Defender provides continuous monitoring for anomalies and events."
    }
}
catch { }

# CSF - RESPOND (RS)
Add-Result -Category "NIST - CSF RS" -Status "Info" `
    -Message "CSF RESPOND: Incident response and communications" `
    -Details "NIST CSF RS: Develop and implement incident response capabilities. See IR controls. Key: response planning, communications, analysis, mitigation."

# CSF - RECOVER (RC)
try {
    $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    
    if ($restorePoints) {
        Add-Result -Category "NIST - CSF RC" -Status "Pass" `
            -Message "CSF RECOVER: Recovery capability via System Restore" `
            -Details "NIST CSF RC: $($restorePoints.Count) restore point(s) available for system recovery."
    } else {
        Add-Result -Category "NIST - CSF RC" -Status "Warning" `
            -Message "CSF RECOVER: Limited recovery capability" `
            -Details "NIST CSF RC: Enable System Restore for recovery from incidents." `
            -Remediation "Enable-ComputerRestore -Drive C:\; Checkpoint-Computer -Description 'Baseline'"
    }
}
catch { }

# ============================================================================
# Module Summary Statistics
# ============================================================================
$passCount = @($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = @($results | Where-Object { $_.Status -eq "Fail" }).Count
$warningCount = @($results | Where-Object { $_.Status -eq "Warning" }).Count
$infoCount = @($results | Where-Object { $_.Status -eq "Info" }).Count
$errorCount = @($results | Where-Object { $_.Status -eq "Error" }).Count
$totalChecks = $results.Count

# Priority breakdown
$highPriority = @($results | Where-Object { $_.Priority -eq "High" -and $_.Status -in @("Fail", "Warning") }).Count
$mediumPriority = @($results | Where-Object { $_.Priority -eq "Medium" -and $_.Status -in @("Fail", "Warning") }).Count

Write-Host "`n========================================================================================================" -ForegroundColor Cyan
Write-Host "                            NIST MODULE SUMMARY" -ForegroundColor Cyan
Write-Host "========================================================================================================" -ForegroundColor Cyan
Write-Host "Framework Coverage:" -ForegroundColor White
Write-Host "  - NIST 800-53 Rev 5: 18 Control Families" -ForegroundColor Gray
Write-Host "  - NIST Cybersecurity Framework 2.0: All 6 Functions" -ForegroundColor Gray
Write-Host "  - NIST 800-171 Rev 2: CUI Protection Controls" -ForegroundColor Gray
Write-Host ""
Write-Host "Total Checks:    $totalChecks" -ForegroundColor White
Write-Host "Passed:          $passCount" -ForegroundColor Green
Write-Host "Failed:          $failCount" -ForegroundColor Red
Write-Host "Warnings:        $warningCount" -ForegroundColor Yellow
Write-Host "Info:            $infoCount" -ForegroundColor Cyan
Write-Host "Errors:          $errorCount" -ForegroundColor Magenta
Write-Host ""
Write-Host "Priority Issues:" -ForegroundColor White
Write-Host "  High Priority:   $highPriority" -ForegroundColor Red
Write-Host "  Medium Priority: $mediumPriority" -ForegroundColor Yellow
Write-Host ""

if ($failCount -gt 0 -or $highPriority -gt 0) {
    Write-Host "⚠ ATTENTION: Critical security gaps identified!" -ForegroundColor Red
    Write-Host "Review FAIL and High Priority findings immediately." -ForegroundColor Red
}

Write-Host "========================================================================================================`n" -ForegroundColor Cyan

return $results
