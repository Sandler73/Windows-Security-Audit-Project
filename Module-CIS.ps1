<#
.SYNOPSIS
    CIS Benchmark Module - CIS Windows 10/11 Enterprise v2.0.0
    
.DESCRIPTION
    Contains checks specific to CIS Benchmark recommendations beyond core checks.
    Includes audit policies, user rights assignments, security options, and advanced settings.
#>
# Module-CIS.ps1
# CIS Benchmarks Compliance Module
# Checks alignment with CIS Microsoft Windows Server/Desktop Benchmarks

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

Write-Host "`n[CIS] Starting CIS Benchmarks compliance checks..." -ForegroundColor Cyan

# ============================================================================
# 1. Account Policies
# ============================================================================
Write-Host "[CIS] Checking Account Policies..." -ForegroundColor Yellow

# 1.1 Password Policy
try {
    $passwordPolicy = net accounts | Out-String
    
    # Minimum password length (CIS: 14 or more)
    if ($passwordPolicy -match "Minimum password length\s+(\d+)") {
        $minLength = [int]$Matches[1]
        if ($minLength -ge 14) {
            Add-Result -Category "CIS - Password Policy" -Status "Pass" `
                -Message "Minimum password length is $minLength (meets CIS requirement of 14+)" `
                -Details "CIS Benchmark 1.1.1"
        } else {
            Add-Result -Category "CIS - Password Policy" -Status "Fail" `
                -Message "Minimum password length is $minLength (should be 14+)" `
                -Details "CIS Benchmark 1.1.1" `
                -Remediation "Set via Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length = 14"
        }
    }
    
    # Maximum password age (CIS: 365 or fewer, but not 0)
    if ($passwordPolicy -match "Maximum password age \(days\):\s+(\d+)") {
        $maxAge = [int]$Matches[1]
        if ($maxAge -gt 0 -and $maxAge -le 365) {
            Add-Result -Category "CIS - Password Policy" -Status "Pass" `
                -Message "Maximum password age is $maxAge days (meets CIS requirement)" `
                -Details "CIS Benchmark 1.1.2"
        } else {
            Add-Result -Category "CIS - Password Policy" -Status "Fail" `
                -Message "Maximum password age is $maxAge days (should be 1-365)" `
                -Details "CIS Benchmark 1.1.2" `
                -Remediation "Set via Group Policy: Password Policy > Maximum password age = 365 or fewer days"
        }
    }
    
    # Password history (CIS: 24 or more)
    if ($passwordPolicy -match "Length of password history maintained:\s+(\d+)") {
        $history = [int]$Matches[1]
        if ($history -ge 24) {
            Add-Result -Category "CIS - Password Policy" -Status "Pass" `
                -Message "Password history is $history passwords (meets CIS requirement)" `
                -Details "CIS Benchmark 1.1.4"
        } else {
            Add-Result -Category "CIS - Password Policy" -Status "Fail" `
                -Message "Password history is $history passwords (should be 24+)" `
                -Details "CIS Benchmark 1.1.4" `
                -Remediation "Set via Group Policy: Password Policy > Enforce password history = 24"
        }
    }
    
} catch {
    Add-Result -Category "CIS - Password Policy" -Status "Error" `
        -Message "Failed to check password policy: $_"
}

# 1.2 Account Lockout Policy
try {
    $lockoutPolicy = net accounts | Out-String
    
    # Lockout threshold (CIS: 5 or fewer invalid logon attempts, but not 0)
    if ($lockoutPolicy -match "Lockout threshold:\s+(\d+)") {
        $threshold = [int]$Matches[1]
        if ($threshold -gt 0 -and $threshold -le 5) {
            Add-Result -Category "CIS - Account Lockout" -Status "Pass" `
                -Message "Account lockout threshold is $threshold attempts (meets CIS requirement)" `
                -Details "CIS Benchmark 1.2.1"
        } elseif ($threshold -eq 0) {
            Add-Result -Category "CIS - Account Lockout" -Status "Fail" `
                -Message "Account lockout is disabled (should be 5 or fewer attempts)" `
                -Details "CIS Benchmark 1.2.1" `
                -Remediation "Set via Group Policy: Account Lockout Policy > Account lockout threshold = 5"
        } else {
            Add-Result -Category "CIS - Account Lockout" -Status "Warning" `
                -Message "Account lockout threshold is $threshold (CIS recommends 5 or fewer)" `
                -Details "CIS Benchmark 1.2.1"
        }
    }
    
    # Lockout duration (CIS: 15 or more minutes)
    if ($lockoutPolicy -match "Lockout duration \(minutes\):\s+(\d+)") {
        $duration = [int]$Matches[1]
        if ($duration -ge 15) {
            Add-Result -Category "CIS - Account Lockout" -Status "Pass" `
                -Message "Account lockout duration is $duration minutes (meets CIS requirement)" `
                -Details "CIS Benchmark 1.2.2"
        } else {
            Add-Result -Category "CIS - Account Lockout" -Status "Fail" `
                -Message "Account lockout duration is $duration minutes (should be 15+)" `
                -Details "CIS Benchmark 1.2.2" `
                -Remediation "Set via Group Policy: Account Lockout Policy > Account lockout duration = 15 minutes"
        }
    }
    
} catch {
    Add-Result -Category "CIS - Account Lockout" -Status "Error" `
        -Message "Failed to check account lockout policy: $_"
}

# ============================================================================
# 2. Local Policies - Audit Policy
# ============================================================================
Write-Host "[CIS] Checking Audit Policies..." -ForegroundColor Yellow

$auditChecks = @(
    @{Name="Credential Validation"; Setting="Success and Failure"; Benchmark="17.1.1"}
    @{Name="Security Group Management"; Setting="Success"; Benchmark="17.5.4"}
    @{Name="User Account Management"; Setting="Success and Failure"; Benchmark="17.5.5"}
    @{Name="Process Creation"; Setting="Success"; Benchmark="17.3.1"}
    @{Name="Account Lockout"; Setting="Failure"; Benchmark="17.1.2"}
    @{Name="Logoff"; Setting="Success"; Benchmark="17.5.2"}
    @{Name="Logon"; Setting="Success and Failure"; Benchmark="17.5.3"}
    @{Name="Special Logon"; Setting="Success"; Benchmark="17.5.6"}
)

foreach ($check in $auditChecks) {
    try {
        $auditSetting = auditpol /get /subcategory:"$($check.Name)" 2>$null
        if ($auditSetting -match "$($check.Name)\s+(.+)") {
            $currentSetting = $Matches[1].Trim()
            
            $expectedSettings = $check.Setting -split " and "
            $meetsRequirement = $true
            foreach ($expected in $expectedSettings) {
                if ($currentSetting -notmatch $expected) {
                    $meetsRequirement = $false
                    break
                }
            }
            
            if ($meetsRequirement) {
                Add-Result -Category "CIS - Audit Policy" -Status "Pass" `
                    -Message "$($check.Name): $currentSetting (meets CIS requirement)" `
                    -Details "CIS Benchmark $($check.Benchmark)"
            } else {
                # Build the actual auditpol command
                $remediationCmd = "auditpol /set /subcategory:'$($check.Name)'"
                if ($check.Setting -match "Success") {
                    $remediationCmd += " /success:enable"
                }
                if ($check.Setting -match "Failure") {
                    $remediationCmd += " /failure:enable"
                }
                
                Add-Result -Category "CIS - Audit Policy" -Status "Fail" `
                    -Message "$($check.Name): $currentSetting (should be $($check.Setting))" `
                    -Details "CIS Benchmark $($check.Benchmark)" `
                    -Remediation $remediationCmd
            }
        }
    } catch {
        Add-Result -Category "CIS - Audit Policy" -Status "Error" `
            -Message "Failed to check $($check.Name) audit policy: $_"
    }
}

# ============================================================================
# 3. Local Policies - User Rights Assignment
# ============================================================================
Write-Host "[CIS] Checking User Rights Assignment..." -ForegroundColor Yellow

$userRightsChecks = @(
    @{Right="SeNetworkLogonRight"; Name="Access this computer from the network"; 
      AllowedGroups=@("Administrators", "Authenticated Users"); Benchmark="2.2.1"}
    @{Right="SeTrustedCredManAccessPrivilege"; Name="Access Credential Manager as a trusted caller"; 
      AllowedGroups=@(); Benchmark="2.2.2"}
    @{Right="SeInteractiveLogonRight"; Name="Allow log on locally"; 
      AllowedGroups=@("Administrators", "Users"); Benchmark="2.2.6"}
    @{Right="SeRemoteInteractiveLogonRight"; Name="Allow log on through Remote Desktop Services"; 
      AllowedGroups=@("Administrators", "Remote Desktop Users"); Benchmark="2.2.9"}
    @{Right="SeBackupPrivilege"; Name="Back up files and directories"; 
      AllowedGroups=@("Administrators"); Benchmark="2.2.10"}
    @{Right="SeDenyNetworkLogonRight"; Name="Deny access to this computer from the network"; 
      AllowedGroups=@("Guests"); Benchmark="2.2.16"}
    @{Right="SeDenyRemoteInteractiveLogonRight"; Name="Deny log on through Remote Desktop Services"; 
      AllowedGroups=@("Guests", "Local account"); Benchmark="2.2.19"}
    @{Right="SeDebugPrivilege"; Name="Debug programs"; 
      AllowedGroups=@("Administrators"); Benchmark="2.2.21"}
)

foreach ($check in $userRightsChecks) {
    try {
        # Use secedit to export current settings
        $tempFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tempFile /areas USER_RIGHTS 2>&1 | Out-Null
        
        $content = Get-Content $tempFile -ErrorAction SilentlyContinue
        $rightLine = $content | Where-Object { $_ -match "^$($check.Right)\s*=" }
        
        if ($rightLine) {
            $assignedTo = ($rightLine -split '=')[1].Trim()
            Add-Result -Category "CIS - User Rights" -Status "Info" `
                -Message "$($check.Name): Currently assigned to: $assignedTo" `
                -Details "CIS Benchmark $($check.Benchmark) - Recommended: $($check.AllowedGroups -join ', ')"
        }
        
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    } catch {
        Add-Result -Category "CIS - User Rights" -Status "Error" `
            -Message "Failed to check $($check.Name): $_"
    }
}

# ============================================================================
# 4. Security Options
# ============================================================================
Write-Host "[CIS] Checking Security Options..." -ForegroundColor Yellow

# 4.1 Accounts
try {
    # Administrator account status (CIS: Should be disabled)
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount) {
        if ($adminAccount.Enabled -eq $false) {
            Add-Result -Category "CIS - Security Options" -Status "Pass" `
                -Message "Built-in Administrator account is disabled" `
                -Details "CIS Benchmark 2.3.1.1"
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Fail" `
                -Message "Built-in Administrator account is enabled (should be disabled)" `
                -Details "CIS Benchmark 2.3.1.1" `
                -Remediation "Disable via: net user administrator /active:no"
        }
    }
    
    # Guest account status (CIS: Should be disabled)
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Enabled -eq $false) {
            Add-Result -Category "CIS - Security Options" -Status "Pass" `
                -Message "Guest account is disabled" `
                -Details "CIS Benchmark 2.3.1.2"
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Fail" `
                -Message "Guest account is enabled (should be disabled)" `
                -Details "CIS Benchmark 2.3.1.2" `
                -Remediation "Disable via Group Policy: Security Options > Accounts: Guest account status = Disabled"
        }
    }
    
} catch {
    Add-Result -Category "CIS - Security Options" -Status "Error" `
        -Message "Failed to check account security options: $_"
}

# 4.2 Network Access and Security
$securityOptionsChecks = @(
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; 
      Value=1; Description="Accounts: Limit local account use of blank passwords to console logon only"; Benchmark="2.3.1.4"}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; 
      Value=1; Description="Network security: Do not store LAN Manager hash value on next password change"; Benchmark="2.3.11.7"}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; 
      Value=1; Description="Microsoft network client: Digitally sign communications (always)"; Benchmark="2.3.8.2"}
    @{Key="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; 
      Value=1; Description="Microsoft network server: Digitally sign communications (always)"; Benchmark="2.3.9.2"}
    @{Key="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; 
      Value=1; Description="User Account Control: Run all administrators in Admin Approval Mode"; Benchmark="2.3.17.1"}
    @{Key="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; 
      Value=2; Description="User Account Control: Behavior of elevation prompt for administrators"; Benchmark="2.3.17.2"}
    @{Key="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; 
      Value=1; Description="User Account Control: Switch to secure desktop when prompting for elevation"; Benchmark="2.3.17.9"}
)

foreach ($check in $securityOptionsChecks) {
    try {
        $regValue = Get-ItemProperty -Path $check.Key -Name $check.Name -ErrorAction SilentlyContinue
        if ($regValue) {
            $currentValue = $regValue.($check.Name)
            if ($currentValue -eq $check.Value) {
                Add-Result -Category "CIS - Security Options" -Status "Pass" `
                    -Message "$($check.Description): Configured correctly ($currentValue)" `
                    -Details "CIS Benchmark $($check.Benchmark)"
            } else {
                Add-Result -Category "CIS - Security Options" -Status "Fail" `
                    -Message "$($check.Description): Currently $currentValue (should be $($check.Value))" `
                    -Details "CIS Benchmark $($check.Benchmark)" `
                    -Remediation "Set via Group Policy: Security Options > $($check.Description)"
            }
        } else {
            Add-Result -Category "CIS - Security Options" -Status "Warning" `
                -Message "$($check.Description): Registry value not found" `
                -Details "CIS Benchmark $($check.Benchmark)"
        }
    } catch {
        Add-Result -Category "CIS - Security Options" -Status "Error" `
            -Message "Failed to check $($check.Description): $_"
    }
}

# ============================================================================
# 5. Windows Firewall Settings
# ============================================================================
Write-Host "[CIS] Checking Windows Firewall..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Private", "Public")
foreach ($profile in $firewallProfiles) {
    try {
        $fwProfile = Get-NetFirewallProfile -Name $profile
        
        # Firewall state (CIS: Should be enabled)
        if ($fwProfile.Enabled -eq $true) {
            Add-Result -Category "CIS - Windows Firewall" -Status "Pass" `
                -Message "$profile Profile: Firewall is enabled" `
                -Details "CIS Benchmark 9.1.1/9.2.1/9.3.1"
        } else {
            Add-Result -Category "CIS - Windows Firewall" -Status "Fail" `
                -Message "$profile Profile: Firewall is disabled (should be enabled)" `
                -Details "CIS Benchmark 9.1.1/9.2.1/9.3.1" `
                -Remediation "Enable via Group Policy: Windows Firewall > $profile Profile > Firewall state = On"
        }
        
        # Inbound connections (CIS: Should be Block)
        if ($fwProfile.DefaultInboundAction -eq "Block") {
            Add-Result -Category "CIS - Windows Firewall" -Status "Pass" `
                -Message "$profile Profile: Default inbound action is Block" `
                -Details "CIS Benchmark 9.1.2/9.2.2/9.3.2"
        } else {
            Add-Result -Category "CIS - Windows Firewall" -Status "Fail" `
                -Message "$profile Profile: Default inbound action is $($fwProfile.DefaultInboundAction) (should be Block)" `
                -Details "CIS Benchmark 9.1.2/9.2.2/9.3.2" `
                -Remediation "Set via Group Policy: Windows Firewall > $profile Profile > Inbound connections = Block"
        }
        
        # Logging (CIS: Should log dropped packets)
        if ($fwProfile.LogBlocked -eq $true) {
            Add-Result -Category "CIS - Windows Firewall" -Status "Pass" `
                -Message "$profile Profile: Logging of dropped packets is enabled" `
                -Details "CIS Benchmark 9.1.7/9.2.6/9.3.8"
        } else {
            Add-Result -Category "CIS - Windows Firewall" -Status "Fail" `
                -Message "$profile Profile: Logging of dropped packets is disabled" `
                -Details "CIS Benchmark 9.1.7/9.2.6/9.3.8" `
                -Remediation "Enable via Group Policy: Windows Firewall > $profile Profile > Log dropped packets = Yes"
        }
        
    } catch {
        Add-Result -Category "CIS - Windows Firewall" -Status "Error" `
            -Message "Failed to check $profile firewall profile: $_"
    }
}

# ============================================================================
# 6. Advanced Audit Policy Configuration
# ============================================================================
Write-Host "[CIS] Checking Advanced Audit Policy..." -ForegroundColor Yellow

# Check if advanced audit policy is being used
try {
    $auditPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    if ($auditPolicy -and $auditPolicy.SCENoApplyLegacyAuditPolicy -eq 1) {
        Add-Result -Category "CIS - Advanced Audit" -Status "Pass" `
            -Message "Advanced Audit Policy is configured to override legacy audit policy" `
            -Details "CIS Benchmark 17.1"
    } else {
        Add-Result -Category "CIS - Advanced Audit" -Status "Warning" `
            -Message "Advanced Audit Policy may not be overriding legacy policy" `
            -Details "CIS Benchmark 17.1" `
            -Remediation "Set via Group Policy: Security Settings > Local Policies > Security Options > Audit: Force audit policy subcategory settings"
    }
} catch {
    Add-Result -Category "CIS - Advanced Audit" -Status "Error" `
        -Message "Failed to check advanced audit policy configuration: $_"
}

# ============================================================================
# 7. Windows Services
# ============================================================================
Write-Host "[CIS] Checking Windows Services..." -ForegroundColor Yellow

$serviceChecks = @(
    @{Name="XblAuthManager"; ExpectedStatus="Disabled"; Description="Xbox Live Auth Manager"; Benchmark="5.1"}
    @{Name="XblGameSave"; ExpectedStatus="Disabled"; Description="Xbox Live Game Save"; Benchmark="5.2"}
    @{Name="XboxNetApiSvc"; ExpectedStatus="Disabled"; Description="Xbox Live Networking Service"; Benchmark="5.3"}
    @{Name="RemoteRegistry"; ExpectedStatus="Disabled"; Description="Remote Registry"; Benchmark="5.32"}
    @{Name="SSDPSRV"; ExpectedStatus="Disabled"; Description="SSDP Discovery"; Benchmark="5.35"}
    @{Name="upnphost"; ExpectedStatus="Disabled"; Description="UPnP Device Host"; Benchmark="5.36"}
    @{Name="WMPNetworkSvc"; ExpectedStatus="Disabled"; Description="Windows Media Player Network Sharing Service"; Benchmark="5.40"}
)

foreach ($check in $serviceChecks) {
    try {
        $service = Get-Service -Name $check.Name -ErrorAction SilentlyContinue
        if ($service) {
            $startType = (Get-Service -Name $check.Name).StartType
            if ($startType -eq $check.ExpectedStatus) {
                Add-Result -Category "CIS - Windows Services" -Status "Pass" `
                    -Message "$($check.Description): $startType (meets CIS requirement)" `
                    -Details "CIS Benchmark $($check.Benchmark)"
            } else {
                Add-Result -Category "CIS - Windows Services" -Status "Fail" `
                    -Message "$($check.Description): $startType (should be $($check.ExpectedStatus))" `
                    -Details "CIS Benchmark $($check.Benchmark)" `
                    -Remediation "Set via Group Policy or: Set-Service -Name $($check.Name) -StartupType Disabled"
            }
        } else {
            Add-Result -Category "CIS - Windows Services" -Status "Info" `
                -Message "$($check.Description): Service not found (may not be applicable)" `
                -Details "CIS Benchmark $($check.Benchmark)"
        }
    } catch {
        Add-Result -Category "CIS - Windows Services" -Status "Error" `
            -Message "Failed to check $($check.Description) service: $_"
    }
}

# ============================================================================
# 8. Registry Settings
# ============================================================================
Write-Host "[CIS] Checking Registry Settings..." -ForegroundColor Yellow

$registryChecks = @(
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"; 
      Value=0; Description="Configure Automatic Updates"; Benchmark="18.9.102.1.1"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="AUOptions"; 
      Value=4; Description="Configure Automatic Updates to auto-download and schedule install"; Benchmark="18.9.102.1.2"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; 
      Value=1; Description="Do not allow drive redirection in RDP"; Benchmark="18.9.65.3.2"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; 
      Value=1; Description="Always prompt for password upon connection"; Benchmark="18.9.65.3.9.1"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; 
      Value=3; Description="Require high encryption level for RDP"; Benchmark="18.9.65.3.9.3"}
)

foreach ($check in $registryChecks) {
    try {
        if (Test-Path $check.Path) {
            $regValue = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
            if ($regValue) {
                $currentValue = $regValue.($check.Name)
                if ($currentValue -eq $check.Value) {
                    Add-Result -Category "CIS - Registry Settings" -Status "Pass" `
                        -Message "$($check.Description): Configured correctly" `
                        -Details "CIS Benchmark $($check.Benchmark)"
                } else {
                    Add-Result -Category "CIS - Registry Settings" -Status "Fail" `
                        -Message "$($check.Description): Currently $currentValue (should be $($check.Value))" `
                        -Details "CIS Benchmark $($check.Benchmark)" `
                        -Remediation "Set via Group Policy or registry: $($check.Path)\$($check.Name) = $($check.Value)"
                }
            } else {
                Add-Result -Category "CIS - Registry Settings" -Status "Warning" `
                    -Message "$($check.Description): Registry value not found" `
                    -Details "CIS Benchmark $($check.Benchmark)"
            }
        } else {
            Add-Result -Category "CIS - Registry Settings" -Status "Warning" `
                -Message "$($check.Description): Registry path not found" `
                -Details "CIS Benchmark $($check.Benchmark)"
        }
    } catch {
        Add-Result -Category "CIS - Registry Settings" -Status "Error" `
            -Message "Failed to check $($check.Description): $_"
    }
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
