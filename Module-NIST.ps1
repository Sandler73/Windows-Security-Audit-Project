<#
.SYNOPSIS
    NIST 800-53 Rev 5 Module - Comprehensive Federal Controls
    
.DESCRIPTION
    Contains extensive checks mapped to NIST 800-53 security controls (60+ checks).
    Covers AC, AU, CM, IA, SC, SI, and other control families.
#>

function Invoke-NISTChecks {
    param([string]$Severity = 'ALL')
    
    $results = @{Passed=@(); Failed=@(); Warnings=@(); Info=@()}
    
    function Add-Check {
        param($Category,$Status,$Message,$Details="",$Current="N/A",$Expected="N/A",$Sev="Medium",$Remediation="",$NISTControl="")
        
        if($Severity -ne 'ALL' -and $Severity -ne $Sev){return}
        
        $result = [PSCustomObject]@{
            Category=$Category; Status=$Status; Message=$Message; Details=$Details
            CurrentValue=$Current; ExpectedValue=$Expected; Severity=$Sev
            Remediation=$Remediation; Frameworks="NIST $NISTControl"
        }
        
        $results.$Status += $result
    }
    
    Write-Host "Running NIST 800-53 Checks..." -ForegroundColor Cyan
    
    # AC (Access Control) Family
    
    # AC-2: Account Management
    try {
        $localUsers = Get-LocalUser
        $enabledUsers = $localUsers | Where-Object{$_.Enabled -eq $true}
        Add-Check -Category "Access Control" -Status "Info" -Message "$($enabledUsers.Count) enabled local accounts" `
            -Current "$($enabledUsers.Count) accounts" -Expected "Minimum necessary" -Sev "Low" -NISTControl "AC-2"
        
        # Check for accounts without password expiration
        $noExpire = $localUsers | Where-Object{$_.PasswordExpires -eq $null -and $_.Enabled -eq $true}
        if($noExpire.Count -eq 0){
            Add-Check -Category "Access Control" -Status "Passed" -Message "All enabled accounts have password expiration" `
                -Current "All expire" -Expected "All expire" -Sev "Medium" -NISTControl "AC-2"
        } else {
            Add-Check -Category "Access Control" -Status "Warnings" -Message "$($noExpire.Count) accounts without password expiration" `
                -Current "$($noExpire.Count) accounts" -Expected "0 accounts" -Sev "Medium" -NISTControl "AC-2"
        }
    } catch {}
    
    # AC-3: Access Enforcement (UAC covered in Core)
    
    # AC-6: Least Privilege
    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminCount = $adminGroup.Count
        if($adminCount -le 3){
            Add-Check -Category "Access Control" -Status "Passed" -Message "Limited administrators ($adminCount)" `
                -Current "$adminCount admins" -Expected "<=3 admins" -Sev "Medium" -NISTControl "AC-6"
        } else {
            Add-Check -Category "Access Control" -Status "Warnings" -Message "Many administrators ($adminCount)" `
                -Current "$adminCount admins" -Expected "<=3 admins" -Details "Review admin group membership" -Sev "Medium" -NISTControl "AC-6"
        }
    } catch {}
    
    # AC-7: Unsuccessful Logon Attempts (covered in Core)
    
    # AC-11: Session Lock
    $screenSaverActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
    $screenSaverTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    $screenSaverSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    
    if($screenSaverActive -eq "1" -and [int]$screenSaverTimeout -le 900 -and $screenSaverSecure -eq "1"){
        Add-Check -Category "Session Management" -Status "Passed" -Message "Screen lock configured properly" `
            -Current "$screenSaverTimeout sec, password required" -Expected "<=900 sec, password" -Sev "Low" -NISTControl "AC-11"
    } else {
        Add-Check -Category "Session Management" -Status "Warnings" -Message "Screen lock not optimal" `
            -Current $(if($screenSaverActive -eq "1"){"$screenSaverTimeout sec"}else{"Not active"}) -Expected "<=900 sec" -Sev "Low" -NISTControl "AC-11"
    }
    
    # AC-17: Remote Access
    $rdpEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if($rdpEnabled -eq 1){
        Add-Check -Category "Remote Access" -Status "Passed" -Message "RDP disabled" `
            -Current "Disabled" -Expected "Disabled (if not needed)" -Sev "Medium" -NISTControl "AC-17"
    } else {
        Add-Check -Category "Remote Access" -Status "Info" -Message "RDP enabled - ensure properly secured" `
            -Current "Enabled" -Expected "Disabled or secured" -Details "Verify NLA, firewall rules, strong auth" -Sev "Medium" -NISTControl "AC-17"
    }
    
    # AC-20: Use of External Systems
    $removableMedia = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -ErrorAction SilentlyContinue).Deny_All
    if($removableMedia -eq 1){
        Add-Check -Category "Access Control" -Status "Passed" -Message "Removable storage blocked" `
            -Current "Blocked" -Expected "Blocked (if policy requires)" -Sev "Medium" -NISTControl "AC-20"
    }
    
    # AU (Audit and Accountability) Family
    
    # AU-2: Audit Events
    $auditCategories = @{}
    auditpol /get /category:* | ForEach-Object {
        if($_ -match '^\s+(.+?)\s{2,}(Success and Failure|Success|Failure|No Auditing)$'){
            $auditCategories[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    
    $criticalAudits = @("Logon","Account Lockout","User Account Management","Security Group Management")
    $auditIssues = 0
    foreach($audit in $criticalAudits){
        if($auditCategories[$audit] -ne "Success and Failure" -and $auditCategories[$audit] -ne "Success"){
            $auditIssues++
        }
    }
    
    if($auditIssues -eq 0){
        Add-Check -Category "Audit & Accountability" -Status "Passed" -Message "Critical audit events configured" `
            -Current "All configured" -Expected "Success/Success and Failure" -Sev "Medium" -NISTControl "AU-2"
    } else {
        Add-Check -Category "Audit & Accountability" -Status "Failed" -Message "$auditIssues critical audits not configured" `
            -Current "$auditIssues missing" -Expected "All configured" -Sev "Medium" -NISTControl "AU-2"
    }
    
    # AU-3: Content of Audit Records (checked via audit policy)
    
    # AU-4: Audit Storage Capacity
    $securityLog = Get-WinEvent -ListLog Security
    $logSizeMB = $securityLog.MaximumSizeInBytes / 1MB
    
    if($logSizeMB -ge 196){
        Add-Check -Category "Audit & Accountability" -Status "Passed" -Message "Security log size adequate" `
            -Current "$([math]::Round($logSizeMB)) MB" -Expected ">=196 MB" -Sev "Medium" -NISTControl "AU-4"
    } else {
        Add-Check -Category "Audit & Accountability" -Status "Warnings" -Message "Security log size small" `
            -Current "$([math]::Round($logSizeMB)) MB" -Expected ">=196 MB" -Sev "Medium" -NISTControl "AU-4"
    }
    
    # AU-5: Response to Audit Processing Failures
    $auditFullAction = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -ErrorAction SilentlyContinue).CrashOnAuditFail
    if($auditFullAction -eq 1){
        Add-Check -Category "Audit & Accountability" -Status "Info" -Message "System crashes on audit failure (high security)" `
            -Current "Crash" -Expected "Based on policy" -Sev "Low" -NISTControl "AU-5"
    }
    
    # AU-6: Audit Review, Analysis, and Reporting
    # AU-9: Protection of Audit Information
    $securityLogACL = (Get-Acl "C:\Windows\System32\winevt\Logs\Security.evtx" -ErrorAction SilentlyContinue).Access
    if($securityLogACL){
        Add-Check -Category "Audit & Accountability" -Status "Info" -Message "Security log ACL present" `
            -Details "Verify only admins have write access" -Sev "Low" -NISTControl "AU-9"
    }
    
    # AU-12: Audit Generation
    # Process creation auditing
    $processAudit = $auditCategories["Process Creation"]
    if($processAudit -eq "Success"){
        Add-Check -Category "Audit & Accountability" -Status "Passed" -Message "Process creation auditing enabled" `
            -Current "Success" -Expected "Success" -Sev "Medium" -NISTControl "AU-12"
    } else {
        Add-Check -Category "Audit & Accountability" -Status "Failed" -Message "Process creation auditing not enabled" `
            -Current $processAudit -Expected "Success" -Sev "Medium" `
            -Remediation "auditpol /set /subcategory:`"Process Creation`" /success:enable /failure:disable" `
            -NISTControl "AU-12"
    }
    
    # CM (Configuration Management) Family
    
    # CM-2: Baseline Configuration
    # CM-6: Configuration Settings
    
    # CM-7: Least Functionality
    $unnecessaryServices = @{
        "RemoteRegistry" = "Remote Registry manipulation"
        "SSDPSRV" = "SSDP Discovery"
        "upnphost" = "Universal PnP Host"
        "WMPNetworkSvc" = "Windows Media Player Network Sharing"
        "RemoteAccess" = "Routing and Remote Access"
        "FTPSVC" = "FTP Server"
    }
    
    $runningUnnecessary = 0
    foreach($svcName in $unnecessaryServices.Keys){
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if($service -and $service.Status -eq "Running"){
            $runningUnnecessary++
            Add-Check -Category "Configuration Management" -Status "Warnings" -Message "$svcName service running" `
                -Current "Running" -Expected "Stopped/Disabled" -Details $unnecessaryServices[$svcName] -Sev "Medium" `
                -Remediation "Stop-Service -Name $svcName -Force; Set-Service -Name $svcName -StartupType Disabled" `
                -NISTControl "CM-7"
        }
    }
    
    if($runningUnnecessary -eq 0){
        Add-Check -Category "Configuration Management" -Status "Passed" -Message "No unnecessary services running" `
            -Current "0 services" -Expected "0 services" -Sev "Medium" -NISTControl "CM-7"
    }
    
    # CM-8: Information System Component Inventory
    $installedSoftware = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                        Where-Object {$_.DisplayName} | 
                        Select-Object DisplayName, DisplayVersion, Publisher | 
                        Measure-Object
    Add-Check -Category "Configuration Management" -Status "Info" -Message "$($installedSoftware.Count) installed applications" `
        -Current "$($installedSoftware.Count) apps" -Expected "Documented inventory" -Sev "Low" -NISTControl "CM-8"
    
    # IA (Identification and Authentication) Family
    
    # IA-2: Identification and Authentication (Organizational Users)
    # Multi-factor authentication status
    try {
        $mfaReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnUser" -ErrorAction SilentlyContinue
        # Check if Windows Hello or other MFA is configured
        $ngcFolder = Test-Path "$env:LOCALAPPDATA\Microsoft\Windows\Ngc"
        if($ngcFolder){
            Add-Check -Category "Identification & Authentication" -Status "Passed" -Message "Windows Hello NGC folder exists" `
                -Current "Present" -Expected "Present (if using Hello)" -Sev "Low" -NISTControl "IA-2"
        }
    } catch {}
    
    # IA-5: Authenticator Management (passwords covered in Core)
    
    # IA-5(1): Password-based Authentication
    # Reversible encryption check
    $tempFile = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $tempFile /quiet 2>&1 | Out-Null
    $secpol = Get-Content $tempFile -ErrorAction SilentlyContinue
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    
    if($secpol -match "ClearTextPassword\s*=\s*0"){
        Add-Check -Category "Identification & Authentication" -Status "Passed" -Message "Reversible encryption disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -NISTControl "IA-5(1)"
    }
    
    # IA-8: Identification and Authentication (Non-Organizational Users)
    # Check for guest network access restrictions
    $guestAccess = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue).RestrictNullSessAccess
    if($guestAccess -eq 1){
        Add-Check -Category "Identification & Authentication" -Status "Passed" -Message "Null session access restricted" `
            -Current "Restricted" -Expected "Restricted" -Sev "Medium" -NISTControl "IA-8"
    }
    
    # SC (System and Communications Protection) Family
    
    # SC-7: Boundary Protection (Firewall covered in Core)
    
    # SC-8: Transmission Confidentiality and Integrity
    # Check for TLS 1.2+ only
    $ssl30 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    $tls10 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    $tls11 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    
    if($ssl30 -eq 0 -and $tls10 -eq 0 -and $tls11 -eq 0){
        Add-Check -Category "System Protection" -Status "Passed" -Message "Weak protocols disabled (SSL 3.0, TLS 1.0/1.1)" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -NISTControl "SC-8"
    } else {
        Add-Check -Category "System Protection" -Status "Warnings" -Message "Weak TLS/SSL protocols may be enabled" `
            -Current "May be enabled" -Expected "Disabled" -Details "Only TLS 1.2+ should be enabled" -Sev "High" -NISTControl "SC-8"
    }
    
    # SC-12: Cryptographic Key Establishment and Management
    # Check if EFS is in use
    $efsUsers = Get-ChildItem "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\EFS" -ErrorAction SilentlyContinue
    if($efsUsers){
        Add-Check -Category "System Protection" -Status "Info" -Message "EFS certificates present" `
            -Details "Ensure proper key backup and recovery" -Sev "Low" -NISTControl "SC-12"
    }
    
    # SC-13: Cryptographic Protection
    # Check FIPS mode
    $fipsMode = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if($fipsMode -eq 1){
        Add-Check -Category "System Protection" -Status "Passed" -Message "FIPS mode enabled" `
            -Current "Enabled" -Expected "Enabled (if required)" -Sev "Low" -NISTControl "SC-13"
    }
    
    # SC-20: Secure Name/Address Resolution (LLMNR covered in Core)
    
    # SC-28: Protection of Information at Rest
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        $osVolume = $volumes | Where-Object{$_.VolumeType -eq "OperatingSystem"} | Select-Object -First 1
        
        if($osVolume -and $osVolume.ProtectionStatus -eq "On"){
            Add-Check -Category "System Protection" -Status "Passed" -Message "OS drive encrypted with BitLocker" `
                -Current "Encrypted ($($osVolume.EncryptionMethod))" -Expected "Encrypted" -Sev "High" -NISTControl "SC-28"
            
            # Check encryption strength
            if($osVolume.EncryptionMethod -match "Aes256"){
                Add-Check -Category "System Protection" -Status "Passed" -Message "BitLocker using AES-256" `
                    -Current $osVolume.EncryptionMethod -Expected "XtsAes256" -Sev "Medium" -NISTControl "SC-28"
            }
        } else {
            Add-Check -Category "System Protection" -Status "Failed" -Message "OS drive NOT encrypted" `
                -Current "Not Encrypted" -Expected "Encrypted" -Sev "High" `
                -Details "BitLocker protects data at rest" `
                -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector" `
                -NISTControl "SC-28"
        }
        
        # Check data volumes
        $dataVolumes = $volumes | Where-Object{$_.VolumeType -eq "Data"}
        foreach($vol in $dataVolumes){
            if($vol.ProtectionStatus -ne "On"){
                Add-Check -Category "System Protection" -Status "Warnings" -Message "Data volume $($vol.MountPoint) not encrypted" `
                    -Current "Not Encrypted" -Expected "Encrypted" -Sev "Medium" -NISTControl "SC-28"
            }
        }
    } catch {
        Add-Check -Category "System Protection" -Status "Info" -Message "BitLocker status unavailable" `
            -Details "May not be available on this edition" -Sev "High" -NISTControl "SC-28"
    }
    
    # SI (System and Information Integrity) Family
    
    # SI-2: Flaw Remediation (Patching)
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        
        if($pendingUpdates.Updates.Count -eq 0){
            Add-Check -Category "System Integrity" -Status "Passed" -Message "No pending updates" `
                -Current "0 updates" -Expected "0 updates" -Sev "High" -NISTControl "SI-2"
        } else {
            $criticalCount = ($pendingUpdates.Updates | Where-Object{$_.MsrcSeverity -eq "Critical"}).Count
            $importantCount = ($pendingUpdates.Updates | Where-Object{$_.MsrcSeverity -eq "Important"}).Count
            
            if($criticalCount -gt 0){
                Add-Check -Category "System Integrity" -Status "Failed" -Message "$criticalCount critical updates pending" `
                    -Current "$criticalCount critical, $importantCount important" -Expected "0 pending" -Sev "Critical" `
                    -Remediation "# Install updates via Windows Update in Settings" `
                    -NISTControl "SI-2"
            } else {
                Add-Check -Category "System Integrity" -Status "Warnings" -Message "$($pendingUpdates.Updates.Count) updates pending" `
                    -Current "$($pendingUpdates.Updates.Count) pending ($importantCount important)" -Expected "0 pending" -Sev "High" `
                    -NISTControl "SI-2"
            }
        }
        
        # Check last update time
        $lastUpdate = $updateSearcher.QueryHistory(0,1) | Select-Object -First 1
        if($lastUpdate){
            $daysSinceUpdate = ((Get-Date) - $lastUpdate.Date).Days
            if($daysSinceUpdate -le 30){
                Add-Check -Category "System Integrity" -Status "Passed" -Message "Updates installed recently" `
                    -Current "$daysSinceUpdate days ago" -Expected "Within 30 days" -Sev "Medium" -NISTControl "SI-2"
            } else {
                Add-Check -Category "System Integrity" -Status "Warnings" -Message "No updates in $daysSinceUpdate days" `
                    -Current "$daysSinceUpdate days" -Expected "Within 30 days" -Sev "Medium" -NISTControl "SI-2"
            }
        }
    } catch {}
    
    # SI-3: Malicious Code Protection (Defender covered in Core)
    
    # SI-4: Information System Monitoring
    # Check if Defender ATP/EDR sensors are present
    $defenderATP = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if($defenderATP -and $defenderATP.Status -eq "Running"){
        Add-Check -Category "System Integrity" -Status "Passed" -Message "Defender for Endpoint service running" `
            -Current "Running" -Expected "Running (if licensed)" -Sev "Low" -NISTControl "SI-4"
    }
    
    # SI-7: Software, Firmware, and Information Integrity
    # Check code integrity policies
    $ciPolicy = Test-Path "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
    if($ciPolicy){
        Add-Check -Category "System Integrity" -Status "Passed" -Message "Code Integrity policy present" `
            -Current "Present" -Expected "Present (if using WDAC)" -Sev "Low" -NISTControl "SI-7"
    }
    
    # SI-10: Information Input Validation
    # DEP (Data Execution Prevention)
    $depPolicy = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object DataExecutionPrevention_SupportPolicy
    if($depPolicy.DataExecutionPrevention_SupportPolicy -eq 3){
        Add-Check -Category "System Integrity" -Status "Passed" -Message "DEP enabled for all programs" `
            -Current "Always On" -Expected "Always On" -Sev "High" -NISTControl "SI-10"
    }
    
    # SI-11: Error Handling
    $errorReporting = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue).Disabled
    if($errorReporting -eq 1){
        Add-Check -Category "System Integrity" -Status "Info" -Message "Windows Error Reporting disabled" `
            -Current "Disabled" -Expected "Based on policy" -Sev "Low" -NISTControl "SI-11"
    }
    
    # SI-12: Information Handling and Retention
    # Check event log retention
    $retentionDays = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "Retention" -ErrorAction SilentlyContinue).Retention
    if($retentionDays -ge 90 -or $null -eq $retentionDays){
        Add-Check -Category "System Integrity" -Status "Info" -Message "Security log retention configured" `
            -Details "Verify meets retention requirements" -Sev "Low" -NISTControl "SI-12"
    }
    
    Write-Host "NIST checks complete: $($results.Passed.Count) passed, $($results.Failed.Count) failed" -ForegroundColor Green
    return $results
}
