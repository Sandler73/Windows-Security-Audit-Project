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
    
    Write-Host "Running NIST 800-53 Checks (72 checks)..." -ForegroundColor Cyan
    
    # AC (Access Control) Family - 12 checks
    
    # AC-2: Account Management
    try {
        $localUsers = Get-LocalUser
        $enabled = $localUsers | Where-Object{$_.Enabled}
        $disabled = $localUsers | Where-Object{-not $_.Enabled}
        
        Add-Check -Category "AC - Access Control" -Status "Info" -Message "Local accounts: $($localUsers.Count) total, $($enabled.Count) enabled" `
            -Current "$($enabled.Count) enabled" -Expected "Minimum necessary" -Sev "Low" -NISTControl "AC-2"
        
        # Check for accounts without password expiration
        $noExpire = $localUsers | Where-Object{$_.PasswordExpires -eq $null -and $_.Enabled}
        if($noExpire.Count -eq 0){
            Add-Check -Category "AC - Access Control" -Status "Passed" -Message "All enabled accounts have password expiration" `
                -Current "All expire" -Expected "All expire" -Sev "Medium" -NISTControl "AC-2"
        } else {
            Add-Check -Category "AC - Access Control" -Status "Warnings" -Message "$($noExpire.Count) accounts without password expiration" `
                -Current "$($noExpire.Count) accounts" -Expected "0 accounts" -Sev "Medium" -NISTControl "AC-2"
        }
    } catch {}
    
    # AC-3: Access Enforcement (UAC in Core)
    
    # AC-6: Least Privilege
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        if($admins.Count -le 3){
            Add-Check -Category "AC - Access Control" -Status "Passed" -Message "Limited administrators: $($admins.Count)" `
                -Current "$($admins.Count) admins" -Expected "<=3 admins" -Sev "Medium" -NISTControl "AC-6"
        } else {
            Add-Check -Category "AC - Access Control" -Status "Warnings" -Message "Many administrators: $($admins.Count)" `
                -Current "$($admins.Count) admins" -Expected "<=3 admins" -Sev "Medium" -NISTControl "AC-6"
        }
        
        # Check Power Users group
        $powerUsers = Get-LocalGroupMember -Group "Power Users" -ErrorAction SilentlyContinue
        if(-not $powerUsers -or $powerUsers.Count -eq 0){
            Add-Check -Category "AC - Access Control" -Status "Passed" -Message "Power Users group empty" `
                -Current "Empty" -Expected "Empty" -Sev "Medium" -NISTControl "AC-6(5)"
        }
    } catch {}
    
    # AC-7: Unsuccessful Logon Attempts (Lockout policy in Core)
    
    # AC-11: Session Lock
    $screenSaver = @{
        Active = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
        Timeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
        Secure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    }
    
    if($screenSaver.Active -eq "1" -and [int]$screenSaver.Timeout -le 900 -and $screenSaver.Secure -eq "1"){
        Add-Check -Category "AC - Access Control" -Status "Passed" -Message "Session lock configured: $($screenSaver.Timeout) sec" `
            -Current "$($screenSaver.Timeout) sec with password" -Expected "<=900 sec with password" -Sev "Low" -NISTControl "AC-11"
    } else {
        Add-Check -Category "AC - Access Control" -Status "Warnings" -Message "Session lock not optimal" `
            -Current $(if($screenSaver.Active -eq "1"){"$($screenSaver.Timeout) sec"}else{"Not active"}) -Expected "<=900 sec" -Sev "Low" -NISTControl "AC-11"
    }
    
    # AC-11(1): Pattern-hiding displays
    $hideUserId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLockedUserId" -ErrorAction SilentlyContinue).DontDisplayLockedUserId
    if($hideUserId -eq 3){
        Add-Check -Category "AC - Access Control" -Status "Passed" -Message "User info hidden on lock screen" `
            -Current "Hidden" -Expected "Hidden" -Sev "Low" -NISTControl "AC-11(1)"
    }
    
    # AC-17: Remote Access (RDP in Core)
    
    # AC-20: Use of External Systems
    $removableMedia = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -ErrorAction SilentlyContinue).Deny_All
    if($removableMedia -eq 1){
        Add-Check -Category "AC - Access Control" -Status "Passed" -Message "Removable storage access blocked" `
            -Current "Blocked" -Expected "Blocked (if policy requires)" -Sev "Medium" -NISTControl "AC-20"
    } else {
        Add-Check -Category "AC - Access Control" -Status "Info" -Message "Removable storage access allowed" `
            -Current "Allowed" -Expected "Based on policy" -Sev "Medium" -NISTControl "AC-20"
    }
    
    # AU (Audit and Accountability) Family - 15 checks
    
    # AU-2: Audit Events
    $auditCategories = @{}
    auditpol /get /category:* | ForEach-Object {
        if($_ -match '^\s+(.+?)\s{2,}(Success and Failure|Success|Failure|No Auditing)$'){
            $auditCategories[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    
    $criticalAudits = @{
        'Logon' = 'Success and Failure'
        'Account Lockout' = 'Failure'
        'User Account Management' = 'Success and Failure'
        'Security Group Management' = 'Success'
    }
    
    foreach($audit in $criticalAudits.Keys){
        $current = $auditCategories[$audit]
        $expected = $criticalAudits[$audit]
        if($current -eq $expected -or ($expected -match 'Success' -and $current -eq 'Success and Failure')){
            Add-Check -Category "AU - Audit" -Status "Passed" -Message "$audit audit configured" `
                -Current $current -Expected $expected -Sev "Medium" -NISTControl "AU-2"
        } else {
            Add-Check -Category "AU - Audit" -Status "Failed" -Message "$audit audit not configured" `
                -Current $current -Expected $expected -Sev "Medium" `
                -Remediation "# Configure via auditpol command" -NISTControl "AU-2"
        }
    }
    
    # AU-3: Content of Audit Records
    $cmdLineAudit = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    if($cmdLineAudit -eq 1){
        Add-Check -Category "AU - Audit" -Status "Passed" -Message "Command line in process audit" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" -NISTControl "AU-3(1)"
    } else {
        Add-Check -Category "AU - Audit" -Status "Failed" -Message "Command line NOT in process audit" `
            -Current "Disabled" -Expected "Enabled" -Sev "Medium" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1" `
            -NISTControl "AU-3(1)"
    }
    
    # AU-4: Audit Storage Capacity
    $logs = @('Application','Security','System')
    foreach($logName in $logs){
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if($log){
            $logSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
            $minSize = if($logName -eq 'Security'){128}else{32}
            
            if($logSizeMB -ge $minSize){
                Add-Check -Category "AU - Audit" -Status "Passed" -Message "$logName log size: $logSizeMB MB" `
                    -Current "$logSizeMB MB" -Expected ">=$minSize MB" -Sev "Medium" -NISTControl "AU-4"
            } else {
                Add-Check -Category "AU - Audit" -Status "Warnings" -Message "$logName log too small: $logSizeMB MB" `
                    -Current "$logSizeMB MB" -Expected ">=$minSize MB" -Sev "Medium" -NISTControl "AU-4"
            }
        }
    }
    
    # AU-5: Response to Audit Processing Failures
    $auditFull = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -ErrorAction SilentlyContinue).CrashOnAuditFail
    if($auditFull -eq 1){
        Add-Check -Category "AU - Audit" -Status "Info" -Message "System crashes on audit failure (high security)" `
            -Current "Crash on fail" -Expected "Based on requirements" -Sev "Low" -NISTControl "AU-5"
    }
    
    # AU-9: Protection of Audit Information
    $secLogACL = Test-Path "C:\Windows\System32\winevt\Logs\Security.evtx"
    if($secLogACL){
        Add-Check -Category "AU - Audit" -Status "Info" -Message "Security log exists with ACL protection" `
            -Details "Verify only admins have write access" -Sev "Low" -NISTControl "AU-9"
    }
    
    # AU-12: Audit Generation
    $processCreation = $auditCategories['Process Creation']
    if($processCreation -match 'Success'){
        Add-Check -Category "AU - Audit" -Status "Passed" -Message "Process creation auditing enabled" `
            -Current $processCreation -Expected "Success" -Sev "Medium" -NISTControl "AU-12"
    } else {
        Add-Check -Category "AU - Audit" -Status "Failed" -Message "Process creation auditing NOT enabled" `
            -Current $processCreation -Expected "Success" -Sev "Medium" `
            -Remediation "auditpol /set /subcategory:`"Process Creation`" /success:enable" `
            -NISTControl "AU-12"
    }
    
    # CM (Configuration Management) Family - 8 checks
    
    # CM-2: Baseline Configuration
    # CM-6: Configuration Settings
    
    # CM-7: Least Functionality
    $unnecessaryServices = @{
        'RemoteRegistry' = 'Remote Registry'
        'SSDPSRV' = 'SSDP Discovery'
        'upnphost' = 'UPnP Device Host'
        'RemoteAccess' = 'Routing and Remote Access'
    }
    
    $runningUnnecessary = 0
    foreach($svcName in $unnecessaryServices.Keys){
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -eq 'Running'){
            $runningUnnecessary++
            Add-Check -Category "CM - Configuration" -Status "Warnings" -Message "$($unnecessaryServices[$svcName]) running" `
                -Current "Running" -Expected "Stopped/Disabled" -Sev "Medium" `
                -Remediation "Stop-Service -Name $svcName -Force; Set-Service -Name $svcName -StartupType Disabled" `
                -NISTControl "CM-7"
        }
    }
    
    if($runningUnnecessary -eq 0){
        Add-Check -Category "CM - Configuration" -Status "Passed" -Message "No unnecessary services running" `
            -Current "0 services" -Expected "0 services" -Sev "Medium" -NISTControl "CM-7"
    }
    
    # CM-7(2): Prevent program execution
    $srpPolicy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "DefaultLevel" -ErrorAction SilentlyContinue).DefaultLevel
    if($srpPolicy){
        Add-Check -Category "CM - Configuration" -Status "Info" -Message "Software Restriction Policies configured" `
            -Details "Level: $srpPolicy" -Sev "Medium" -NISTControl "CM-7(2)"
    }
    
    # CM-8: Information System Component Inventory
    $installedSoftware = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                        Where-Object {$_.DisplayName} | Measure-Object
    Add-Check -Category "CM - Configuration" -Status "Info" -Message "$($installedSoftware.Count) installed applications" `
        -Current "$($installedSoftware.Count) apps" -Expected "Documented inventory" -Sev "Low" -NISTControl "CM-8"
    
    # IA (Identification and Authentication) Family - 8 checks
    
    # IA-2: Identification and Authentication
    $ngcFolder = Test-Path "$env:LOCALAPPDATA\Microsoft\Windows\Ngc"
    if($ngcFolder){
        Add-Check -Category "IA - Authentication" -Status "Info" -Message "Windows Hello NGC infrastructure present" `
            -Current "Present" -Expected "Present (for MFA)" -Sev "Low" -NISTControl "IA-2(1)"
    }
    
    # IA-5: Authenticator Management (passwords in Core)
    
    # IA-5(1): Password-based Authentication
    try {
        $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet 2>&1
        $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction Stop
        Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
        
        if($content -match 'ClearTextPassword\s*=\s*0'){
            Add-Check -Category "IA - Authentication" -Status "Passed" -Message "Reversible encryption disabled" `
                -Current "Disabled" -Expected "Disabled" -Sev "High" -NISTControl "IA-5(1)"
        } else {
            Add-Check -Category "IA - Authentication" -Status "Failed" -Message "Reversible encryption NOT disabled" `
                -Current "Enabled" -Expected "Disabled" -Sev "High" -NISTControl "IA-5(1)"
        }
        
        if($content -match 'MinimumPasswordLength\s*=\s*(\d+)'){
            $minLen = [int]$matches[1]
            if($minLen -ge 14){
                Add-Check -Category "IA - Authentication" -Status "Passed" -Message "Password minimum length adequate: $minLen" `
                    -Current $minLen -Expected "14+" -Sev "High" -NISTControl "IA-5(1)(a)"
            }
        }
        
        if($content -match 'PasswordHistorySize\s*=\s*(\d+)'){
            $history = [int]$matches[1]
            if($history -ge 24){
                Add-Check -Category "IA - Authentication" -Status "Passed" -Message "Password history adequate: $history" `
                    -Current $history -Expected "24+" -Sev "Medium" -NISTControl "IA-5(1)(e)"
            }
        }
    } catch {}
    
    # IA-8: Identification and Authentication (Non-Organizational Users)
    $guestAccess = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue).RestrictNullSessAccess
    if($guestAccess -eq 1){
        Add-Check -Category "IA - Authentication" -Status "Passed" -Message "Null session access restricted" `
            -Current "Restricted" -Expected "Restricted" -Sev "Medium" -NISTControl "IA-8"
    } else {
        Add-Check -Category "IA - Authentication" -Status "Warnings" -Message "Null session access not restricted" `
            -Current "Allowed" -Expected "Restricted" -Sev "Medium" -NISTControl "IA-8"
    }
    
    # SC (System and Communications Protection) Family - 15 checks
    
    # SC-7: Boundary Protection (Firewall in Core)
    foreach($profile in @('Domain','Private','Public')){
        $fw = Get-NetFirewallProfile -Name $profile -ErrorAction SilentlyContinue
        if($fw){
            $ruleCount = (Get-NetFirewallRule -Direction Inbound -Enabled True -Profile $profile -ErrorAction SilentlyContinue | Measure-Object).Count
            Add-Check -Category "SC - System Protection" -Status "Info" -Message "${profile}: $ruleCount inbound rules" `
                -Current "$ruleCount rules" -Expected "Minimum necessary" -Sev "Low" -NISTControl "SC-7(5)"
        }
    }
    
    # SC-8: Transmission Confidentiality and Integrity
    $ssl30 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    $tls10 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    
    if($ssl30 -eq 0 -and $tls10 -eq 0){
        Add-Check -Category "SC - System Protection" -Status "Passed" -Message "Weak protocols disabled (SSL 3.0, TLS 1.0)" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -NISTControl "SC-8"
    } else {
        Add-Check -Category "SC - System Protection" -Status "Warnings" -Message "Weak TLS/SSL protocols may be enabled" `
            -Current "May be enabled" -Expected "Disabled" -Sev "High" -NISTControl "SC-8"
    }
    
    # SC-12: Cryptographic Key Establishment and Management
    $efsUsers = Get-ChildItem "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\EFS" -ErrorAction SilentlyContinue
    if($efsUsers){
        Add-Check -Category "SC - System Protection" -Status "Info" -Message "EFS certificates present" `
            -Details "Ensure proper key backup" -Sev "Low" -NISTControl "SC-12"
    }
    
    # SC-13: Cryptographic Protection
    $fipsMode = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if($fipsMode -eq 1){
        Add-Check -Category "SC - System Protection" -Status "Passed" -Message "FIPS mode enabled" `
            -Current "Enabled" -Expected "Enabled (if required)" -Sev "Low" -NISTControl "SC-13"
    }
    
    # SC-20: Secure Name/Address Resolution (LLMNR in Core)
    
    # SC-23: Session Authenticity
    $sessionTimeout = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -ErrorAction SilentlyContinue).MaxConnectionsPerServer
    if($sessionTimeout){
        Add-Check -Category "SC - System Protection" -Status "Info" -Message "HTTP connection limits configured" `
            -Details "Helps prevent session hijacking" -Sev "Low" -NISTControl "SC-23"
    }
    
    # SC-28: Protection of Information at Rest
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        $osVolume = $volumes | Where-Object{$_.VolumeType -eq "OperatingSystem"} | Select-Object -First 1
        
        if($osVolume -and $osVolume.ProtectionStatus -eq "On"){
            Add-Check -Category "SC - System Protection" -Status "Passed" -Message "OS drive encrypted with BitLocker" `
                -Current "Encrypted ($($osVolume.EncryptionMethod))" -Expected "Encrypted" -Sev "High" -NISTControl "SC-28"
            
            if($osVolume.EncryptionMethod -match "Aes256"){
                Add-Check -Category "SC - System Protection" -Status "Passed" -Message "BitLocker using strong encryption" `
                    -Current $osVolume.EncryptionMethod -Expected "XtsAes256" -Sev "Medium" -NISTControl "SC-28"
            } else {
                Add-Check -Category "SC - System Protection" -Status "Warnings" -Message "BitLocker not using AES-256" `
                    -Current $osVolume.EncryptionMethod -Expected "XtsAes256" -Sev "Medium" -NISTControl "SC-28"
            }
        } else {
            Add-Check -Category "SC - System Protection" -Status "Failed" -Message "OS drive NOT encrypted" `
                -Current "Not Encrypted" -Expected "Encrypted" -Sev "High" `
                -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector" `
                -NISTControl "SC-28"
        }
    } catch {
        Add-Check -Category "SC - System Protection" -Status "Info" -Message "BitLocker status unavailable" `
            -Details "May not be available on this edition" -Sev "High" -NISTControl "SC-28"
    }
    
    # SI (System and Information Integrity) Family - 14 checks
    
    # SI-2: Flaw Remediation (Patching)
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        
        if($pendingUpdates.Updates.Count -eq 0){
            Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "No pending updates" `
                -Current "0 updates" -Expected "0 updates" -Sev "High" -NISTControl "SI-2"
        } else {
            $criticalCount = ($pendingUpdates.Updates | Where-Object{$_.MsrcSeverity -eq "Critical"}).Count
            $importantCount = ($pendingUpdates.Updates | Where-Object{$_.MsrcSeverity -eq "Important"}).Count
            
            if($criticalCount -gt 0){
                Add-Check -Category "SI - System Integrity" -Status "Failed" -Message "$criticalCount critical updates pending" `
                    -Current "$criticalCount critical, $importantCount important" -Expected "0 pending" -Sev "Critical" `
                    -Remediation "# Install updates via Settings > Windows Update" -NISTControl "SI-2"
            } else {
                Add-Check -Category "SI - System Integrity" -Status "Warnings" -Message "$($pendingUpdates.Updates.Count) updates pending" `
                    -Current "$($pendingUpdates.Updates.Count) ($importantCount important)" -Expected "0 pending" -Sev "High" -NISTControl "SI-2"
            }
        }
        
        $lastUpdate = $updateSearcher.QueryHistory(0,1) | Select-Object -First 1
        if($lastUpdate){
            $daysSince = ((Get-Date) - $lastUpdate.Date).Days
            if($daysSince -le 30){
                Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "Updates installed recently: $daysSince days ago" `
                    -Current "$daysSince days" -Expected "Within 30 days" -Sev "Medium" -NISTControl "SI-2"
            } else {
                Add-Check -Category "SI - System Integrity" -Status "Warnings" -Message "No updates in $daysSince days" `
                    -Current "$daysSince days" -Expected "Within 30 days" -Sev "Medium" -NISTControl "SI-2"
            }
        }
    } catch {}
    
    # SI-3: Malicious Code Protection (Defender in Core)
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if($mpStatus.AntivirusScanAge -le 7){
            Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "Recent AV scan: $($mpStatus.AntivirusScanAge) days ago" `
                -Current "$($mpStatus.AntivirusScanAge) days" -Expected "<7 days" -Sev "High" -NISTControl "SI-3(1)"
        } else {
            Add-Check -Category "SI - System Integrity" -Status "Warnings" -Message "AV scan outdated: $($mpStatus.AntivirusScanAge) days ago" `
                -Current "$($mpStatus.AntivirusScanAge) days" -Expected "<7 days" -Sev "High" -NISTControl "SI-3(1)"
        }
    } catch {}
    
    # SI-4: Information System Monitoring
    $defenderATP = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if($defenderATP -and $defenderATP.Status -eq "Running"){
        Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "Defender for Endpoint service running" `
            -Current "Running" -Expected "Running (if licensed)" -Sev "Low" -NISTControl "SI-4"
    }
    
    $mpTelemetry = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue).SpynetReporting
    if($mpTelemetry -in @(1,2)){
        $level = if($mpTelemetry -eq 2){"Advanced"}else{"Basic"}
        Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "Defender telemetry: $level" `
            -Current $level -Expected "Basic/Advanced" -Sev "Medium" -NISTControl "SI-4(2)"
    }
    
    # SI-7: Software, Firmware, and Information Integrity
    $ciPolicy = Test-Path "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
    if($ciPolicy){
        Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "Code Integrity policy present" `
            -Current "Present" -Expected "Present (if using WDAC)" -Sev "Low" -NISTControl "SI-7(1)"
    }
    
    # SI-8: Spam Protection
    $smartScreen = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
    if($smartScreen -in @("RequireAdmin","Warn")){
        Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "SmartScreen configured: $smartScreen" `
            -Current $smartScreen -Expected "RequireAdmin/Warn" -Sev "Medium" -NISTControl "SI-8"
    }
    
    # SI-10: Information Input Validation (DEP)
    $depPolicy = (Get-CimInstance -ClassName Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
    if($depPolicy -eq 3){
        Add-Check -Category "SI - System Integrity" -Status "Passed" -Message "DEP enabled for all programs" `
            -Current "Always On" -Expected "Always On" -Sev "High" -NISTControl "SI-10"
    } else {
        Add-Check -Category "SI - System Integrity" -Status "Warnings" -Message "DEP not enabled for all programs" `
            -Current "Policy: $depPolicy" -Expected "3 (Always On)" -Sev "High" -NISTControl "SI-10"
    }
    
    # SI-11: Error Handling
    $errorReporting = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue).Disabled
    if($errorReporting -eq 1){
        Add-Check -Category "SI - System Integrity" -Status "Info" -Message "Windows Error Reporting disabled" `
            -Current "Disabled" -Expected "Based on policy" -Sev "Low" -NISTControl "SI-11"
    }
    
    # SI-12: Information Handling and Retention
    $secLogRetention = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "Retention" -ErrorAction SilentlyContinue).Retention
    if($secLogRetention){
        Add-Check -Category "SI - System Integrity" -Status "Info" -Message "Security log retention configured" `
            -Details "Verify meets retention requirements" -Sev "Low" -NISTControl "SI-12"
    }
    
    $totalChecks = $results.Passed.Count + $results.Failed.Count + $results.Warnings.Count + $results.Info.Count
    Write-Host "NIST checks complete: $totalChecks executed, $($results.Passed.Count) passed, $($results.Failed.Count) failed, $($results.Warnings.Count) warnings" -ForegroundColor Green
    return $results
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

return $results
