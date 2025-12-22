<#
.SYNOPSIS
    Core Security Checks Module - Essential Security Configuration
    
.DESCRIPTION
    Contains fundamental security checks that should always be performed.
    This module always runs regardless of framework selection (75+ checks).
#>

function Invoke-CoreChecks {
    param([string]$Severity = 'ALL')
    
    $results = @{Passed=@(); Failed=@(); Warnings=@(); Info=@()}
    
    function Add-Check {
        param($Category,$Status,$Message,$Details="",$Current="N/A",$Expected="N/A",$Sev="Medium",$Remediation="",$Frameworks=@{})
        
        if($Severity -ne 'ALL' -and $Severity -ne $Sev){return}
        
        $fwList = ($Frameworks.GetEnumerator() | ForEach-Object{"$($_.Key) $($_.Value)"}) -join " | "
        
        $result = [PSCustomObject]@{
            Category=$Category; Status=$Status; Message=$Message; Details=$Details
            CurrentValue=$Current; ExpectedValue=$Expected; Severity=$Sev
            Remediation=$Remediation; Frameworks=$fwList
        }
        
        $results.$Status += $result
    }
    
    Write-Host "Running Core Security Checks..." -ForegroundColor Cyan
    
    # Windows Defender
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $mpPref = Get-MpPreference -ErrorAction Stop
        
        if($mpStatus.RealTimeProtectionEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Real-time protection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Critical" -Frameworks @{'CIS'='18.9.45.4.1';'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Real-time protection DISABLED" `
                -Current "Disabled" -Expected "Enabled" -Sev "Critical" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
                -Frameworks @{'CIS'='18.9.45.4.1';'NIST'='SI-3'}
        }
        
        if($mpStatus.BehaviorMonitorEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Behavior monitoring enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='18.9.45.4.2';'NIST'='SI-3'}
        }
        
        $cloudProtection = switch($mpPref.MAPSReporting){0{"Disabled"}1{"Basic"}2{"Advanced"}default{"Unknown"}}
        if($mpPref.MAPSReporting -gt 0){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Cloud protection enabled ($cloudProtection)" `
                -Current $cloudProtection -Expected "Basic/Advanced" -Sev "High" -Frameworks @{'CIS'='18.9.45.11';'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Cloud protection disabled" `
                -Current "Disabled" -Expected "Basic/Advanced" -Sev "High" `
                -Remediation "Set-MpPreference -MAPSReporting 2" -Frameworks @{'CIS'='18.9.45.11';'NIST'='SI-3'}
        }
        
        $sigAge = $mpStatus.AntivirusSignatureAge
        if($sigAge -le 7){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Signatures up to date ($sigAge days)" `
                -Current "$sigAge days" -Expected "<7 days" -Sev "High" -Frameworks @{'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Signatures outdated ($sigAge days)" `
                -Current "$sigAge days" -Expected "<7 days" -Sev "High" `
                -Remediation "Update-MpSignature" -Frameworks @{'NIST'='SI-3'}
        }
        
        if($mpPref.DisableScriptScanning -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Script scanning enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender'}
        }
        
        if($mpPref.DisableIOAVProtection -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "IOAV protection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
        $sampleSubmission = switch($mpPref.SubmitSamplesConsent){0{"Always prompt"}1{"Safe"}2{"Never"}3{"All"}default{"Unknown"}}
        if($mpPref.SubmitSamplesConsent -ne 2){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Sample submission configured ($sampleSubmission)" `
                -Current $sampleSubmission -Expected "Not 'Never'" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
        $puaProtection = switch($mpPref.PUAProtection){0{"Disabled"}1{"Enabled"}2{"Audit"}default{"Unknown"}}
        if($mpPref.PUAProtection -eq 1){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "PUA protection enabled" `
                -Current $puaProtection -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
    } catch {
        Add-Check -Category "Windows Defender" -Status "Failed" -Message "Cannot query Defender status" `
            -Details $_.Exception.Message -Sev "Critical" -Frameworks @{'NIST'='SI-3'}
    }
    
    # Windows Firewall
    foreach($profile in @("Domain","Private","Public")){
        $fw = Get-NetFirewallProfile -Name $profile -ErrorAction SilentlyContinue
        if($fw -and $fw.Enabled -eq "True"){
            Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile firewall enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Critical" -Frameworks @{'CIS'='9.1';'NIST'='SC-7'}
        } else {
            Add-Check -Category "Windows Firewall" -Status "Failed" -Message "$profile firewall DISABLED" `
                -Current "Disabled" -Expected "Enabled" -Sev "Critical" `
                -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True" `
                -Frameworks @{'CIS'='9.1';'NIST'='SC-7'}
        }
        
        if($fw -and $fw.DefaultInboundAction -eq "Block"){
            Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile default inbound: Block" `
                -Current "Block" -Expected "Block" -Sev "High" -Frameworks @{'CIS'='9.1';'NIST'='SC-7'}
        }
    }
    
    # UAC Settings
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $enableLUA = (Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    
    if($enableLUA -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "UAC enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Critical" -Frameworks @{'CIS'='2.3.17.1';'NIST'='AC-6'}
    } else {
        Add-Check -Category "UAC" -Status "Failed" -Message "UAC DISABLED" `
            -Current "Disabled" -Expected "Enabled" -Sev "Critical" `
            -Remediation "Set-ItemProperty -Path '$uacPath' -Name 'EnableLUA' -Value 1" `
            -Frameworks @{'CIS'='2.3.17.1';'NIST'='AC-6'}
    }
    
    $promptSecureDesktop = (Get-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    if($promptSecureDesktop -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "UAC prompts on secure desktop" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='2.3.17.6';'NIST'='AC-6'}
    }
    
    $consentPrompt = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    if($consentPrompt -ge 2){
        Add-Check -Category "UAC" -Status "Passed" -Message "Admin consent prompt configured" `
            -Current $consentPrompt -Expected "2+ (Prompt)" -Sev "High" -Frameworks @{'CIS'='2.3.17.2';'NIST'='AC-6'}
    }
    
    # UAC Additional Settings
    $uacChecks = @{
        'EnableSecureUIAPaths' = @{Expected=1; Desc='Secure UIAccess applications paths'; Sev='Medium'}
        'EnableVirtualization' = @{Expected=1; Desc='Virtualize file and registry failures'; Sev='Medium'}
        'FilterAdministratorToken' = @{Expected=1; Desc='Built-in Admin approval mode'; Sev='High'}
    }
    
    foreach($setting in $uacChecks.Keys){
        $current = (Get-ItemProperty -Path $uacPath -Name $setting -ErrorAction SilentlyContinue).$setting
        if($current -eq $uacChecks[$setting].Expected){
            Add-Check -Category "UAC" -Status "Passed" -Message $uacChecks[$setting].Desc `
                -Current $current -Expected $uacChecks[$setting].Expected -Sev $uacChecks[$setting].Sev `
                -Frameworks @{'CIS'='2.3.17';'NIST'='AC-6'}
        } else {
            Add-Check -Category "UAC" -Status "Failed" -Message "$($uacChecks[$setting].Desc) not configured" `
                -Current $(if($null -eq $current){"Not Set"}else{$current}) -Expected $uacChecks[$setting].Expected `
                -Sev $uacChecks[$setting].Sev `
                -Remediation "Set-ItemProperty -Path '$uacPath' -Name '$setting' -Value $($uacChecks[$setting].Expected)" `
                -Frameworks @{'CIS'='2.3.17';'NIST'='AC-6'}
        }
    }
    
    # Password Policy
    $netAccounts = net accounts
    $minPwdLength = ($netAccounts | Select-String "Minimum password length" | Out-String).Split(':')[1].Trim()
    if([int]$minPwdLength -ge 14){
        Add-Check -Category "Password Policy" -Status "Passed" -Message "Minimum password length adequate" `
            -Current $minPwdLength -Expected "14+" -Sev "High" -Frameworks @{'CIS'='1.1.1';'NIST'='IA-5(1)'}
    } else {
        Add-Check -Category "Password Policy" -Status "Failed" -Message "Minimum password length too short" `
            -Current $minPwdLength -Expected "14+" -Sev "High" `
            -Frameworks @{'CIS'='1.1.1';'NIST'='IA-5(1)'}
    }
    
    $pwdHistory = ($netAccounts | Select-String "Length of password history" | Out-String).Split(':')[1].Trim()
    if([int]$pwdHistory -ge 24){
        Add-Check -Category "Password Policy" -Status "Passed" -Message "Password history adequate" `
            -Current $pwdHistory -Expected "24+" -Sev "Medium" -Frameworks @{'CIS'='1.1.2';'NIST'='IA-5(1)'}
    }
    
    $maxPwdAge = ($netAccounts | Select-String "Maximum password age" | Out-String).Split(':')[1].Trim().Split(' ')[0]
    if([int]$maxPwdAge -le 60 -and [int]$maxPwdAge -gt 0){
        Add-Check -Category "Password Policy" -Status "Passed" -Message "Maximum password age appropriate" `
            -Current "$maxPwdAge days" -Expected "1-60 days" -Sev "Medium" -Frameworks @{'CIS'='1.1.3';'NIST'='IA-5(1)'}
    }
    
    # Account Lockout
    $lockoutThreshold = ($netAccounts | Select-String "Lockout threshold" | Out-String).Split(':')[1].Trim()
    if([int]$lockoutThreshold -ge 5 -and [int]$lockoutThreshold -le 10){
        Add-Check -Category "Account Lockout" -Status "Passed" -Message "Lockout threshold configured" `
            -Current $lockoutThreshold -Expected "5-10 attempts" -Sev "High" -Frameworks @{'CIS'='1.2.1';'NIST'='AC-7'}
    } else {
        Add-Check -Category "Account Lockout" -Status "Failed" -Message "Lockout threshold not optimal" `
            -Current $lockoutThreshold -Expected "5-10 attempts" -Sev "High" -Frameworks @{'CIS'='1.2.1';'NIST'='AC-7'}
    }
    
    # Windows Update
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $noAutoUpdate = (Get-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
    if($noAutoUpdate -eq 0 -or $null -eq $noAutoUpdate){
        Add-Check -Category "Windows Update" -Status "Passed" -Message "Automatic updates enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'NIST'='SI-2'}
    } else {
        Add-Check -Category "Windows Update" -Status "Failed" -Message "Automatic updates DISABLED" `
            -Current "Disabled" -Expected "Enabled" -Sev "High" `
            -Remediation "Remove-ItemProperty -Path '$wuPath' -Name 'NoAutoUpdate' -Force" `
            -Frameworks @{'NIST'='SI-2'}
    }
    
    # Guest Account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if($guest -and -not $guest.Enabled){
        Add-Check -Category "User Accounts" -Status "Passed" -Message "Guest account disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -Frameworks @{'CIS'='2.3.1.1';'NIST'='AC-2'}
    } else {
        Add-Check -Category "User Accounts" -Status "Failed" -Message "Guest account ENABLED" `
            -Current "Enabled" -Expected "Disabled" -Sev "High" `
            -Remediation "Disable-LocalUser -Name 'Guest'" -Frameworks @{'CIS'='2.3.1.1';'NIST'='AC-2'}
    }
    
    # SMB
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if($smbv1 -and $smbv1.State -eq "Disabled"){
        Add-Check -Category "SMB" -Status "Passed" -Message "SMBv1 disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "Critical" -Frameworks @{'CIS'='18.3.1';'MS'='Baseline'}
    } else {
        Add-Check -Category "SMB" -Status "Failed" -Message "SMBv1 NOT disabled" `
            -Current $(if($smbv1){"$($smbv1.State)"}else{"Unknown"}) -Expected "Disabled" -Sev "Critical" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -Frameworks @{'CIS'='18.3.1';'MS'='Baseline'}
    }
    
    $smbSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if($smbSigning -eq 1){
        Add-Check -Category "SMB" -Status "Passed" -Message "SMB signing required" `
            -Current "Required" -Expected "Required" -Sev "High" -Frameworks @{'CIS'='2.3.8.3';'NIST'='SC-8'}
    }
    
    # PowerShell
    $execPolicy = Get-ExecutionPolicy -Scope LocalMachine
    if($execPolicy -in @('AllSigned','RemoteSigned','Restricted')){
        Add-Check -Category "PowerShell" -Status "Passed" -Message "Execution policy secure" `
            -Current $execPolicy -Expected "AllSigned/RemoteSigned/Restricted" -Sev "Medium" -Frameworks @{'CIS'='18.9.95';'MS'='Baseline'}
    } else {
        Add-Check -Category "PowerShell" -Status "Warnings" -Message "PowerShell execution policy permissive" `
            -Current $execPolicy -Expected "AllSigned/RemoteSigned" -Sev "Medium" -Frameworks @{'CIS'='18.9.95';'MS'='Baseline'}
    }
    
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
    if($psv2 -and $psv2.State -eq "Disabled"){
        Add-Check -Category "PowerShell" -Status "Passed" -Message "PowerShell v2 disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -Frameworks @{'CIS'='18.9.95.1';'STIG'='V-220719'}
    }
    
    # RDP
    $rdpDeny = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if($rdpDeny -eq 1){
        Add-Check -Category "RDP" -Status "Passed" -Message "RDP disabled" `
            -Current "Disabled" -Expected "Disabled (if not needed)" -Sev "Medium" -Frameworks @{'NIST'='AC-17'}
    } else {
        $nla = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        if($nla -eq 1){
            Add-Check -Category "RDP" -Status "Passed" -Message "RDP enabled with NLA" `
                -Current "Enabled with NLA" -Expected "NLA required" -Sev "Medium" -Frameworks @{'CIS'='18.9.62.3.9.1';'NIST'='AC-17'}
        } else {
            Add-Check -Category "RDP" -Status "Failed" -Message "RDP enabled WITHOUT NLA" `
                -Current "Enabled without NLA" -Expected "NLA required" -Sev "High" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1" `
                -Frameworks @{'CIS'='18.9.62.3.9.1';'NIST'='AC-17'}
        }
    }
    
    # LSA Protection
    $lsaProtection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    if($lsaProtection -eq 1){
        Add-Check -Category "Credential Protection" -Status "Passed" -Message "LSA Protection enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Baseline'}
    }
    
    # WDigest
    $wdigest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    if($wdigest -eq 0){
        Add-Check -Category "Credential Protection" -Status "Passed" -Message "WDigest disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -Frameworks @{'MS'='Baseline'}
    } else {
        Add-Check -Category "Credential Protection" -Status "Failed" -Message "WDigest NOT disabled" `
            -Current "Enabled" -Expected "Disabled" -Sev "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0" `
            -Frameworks @{'MS'='Baseline'}
    }
    
    # LLMNR
    $llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    if($llmnr -eq 0){
        Add-Check -Category "Network Security" -Status "Passed" -Message "LLMNR disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "Medium" -Frameworks @{'CIS'='18.5.10.2';'NIST'='SC-20'}
    } else {
        Add-Check -Category "Network Security" -Status "Failed" -Message "LLMNR NOT disabled" `
            -Current "Enabled" -Expected "Disabled" -Sev "Medium" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0" `
            -Frameworks @{'CIS'='18.5.10.2';'NIST'='SC-20'}
    }
    
    # AutoRun
    $autoRun = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    if($autoRun -eq 255){
        Add-Check -Category "AutoRun" -Status "Passed" -Message "AutoRun disabled for all drives" `
            -Current "255 (all drives)" -Expected "255" -Sev "High" -Frameworks @{'CIS'='18.9.8';'NIST'='CM-7'}
    } else {
        Add-Check -Category "AutoRun" -Status "Failed" -Message "AutoRun not fully disabled" `
            -Current $(if($autoRun){"$autoRun"}else{"Not Set"}) -Expected "255" -Sev "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255" `
            -Frameworks @{'CIS'='18.9.8';'NIST'='CM-7'}
    }
    
    # Screen Saver Settings
    $ssTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    $ssActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
    $ssSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    
    if($ssActive -eq "1" -and [int]$ssTimeout -le 900 -and $ssSecure -eq "1"){
        Add-Check -Category "Screen Lock" -Status "Passed" -Message "Screen saver lock configured" `
            -Current "$ssTimeout sec with password" -Expected "<=900 sec with password" -Sev "Low" `
            -Frameworks @{'CIS'='2.3.7.7';'NIST'='AC-11'}
    } else {
        Add-Check -Category "Screen Lock" -Status "Warnings" -Message "Screen saver lock not optimal" `
            -Current $(if($ssActive -eq "1"){"$ssTimeout sec"}else{"Not active"}) -Expected "<=900 sec with password" -Sev "Low" `
            -Frameworks @{'CIS'='2.3.7.7';'NIST'='AC-11'}
    }
    
    # Interactive Logon Settings
    $legalNotice = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue).LegalNoticeCaption
    if($legalNotice){
        Add-Check -Category "Logon Security" -Status "Passed" -Message "Legal notice configured" `
            -Current "Present" -Expected "Present" -Sev "Low" `
            -Frameworks @{'CIS'='2.3.7.4';'STIG'='V-220929'}
    } else {
        Add-Check -Category "Logon Security" -Status "Warnings" -Message "Legal notice not configured" `
            -Current "Not Set" -Expected "Present" -Sev "Low" `
            -Frameworks @{'CIS'='2.3.7.4';'STIG'='V-220929'}
    }
    
    $lastUserName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue).DontDisplayLastUserName
    if($lastUserName -eq 1){
        Add-Check -Category "Logon Security" -Status "Passed" -Message "Last username not displayed" `
            -Current "Hidden" -Expected "Hidden" -Sev "Low" `
            -Frameworks @{'CIS'='2.3.7.3';'STIG'='V-220930'}
    } else {
        Add-Check -Category "Logon Security" -Status "Failed" -Message "Last username displayed at logon" `
            -Current "Displayed" -Expected "Hidden" -Sev "Low" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1" `
            -Frameworks @{'CIS'='2.3.7.3';'STIG'='V-220930'}
    }
    
    # Network Security Settings
    $netSecChecks = @{
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @(
            @{Name='EnableICMPRedirect'; Expected=0; Sev='Medium'; Desc='ICMP redirects disabled'}
            @{Name='DisableIPSourceRouting'; Expected=2; Sev='Low'; Desc='IP source routing disabled'}
            @{Name='TcpMaxDataRetransmissions'; Expected=3; Sev='Low'; Desc='TCP retransmissions limited'}
        )
    }
    
    foreach($path in $netSecChecks.Keys){
        foreach($check in $netSecChecks[$path]){
            $current = (Get-ItemProperty -Path $path -Name $check.Name -ErrorAction SilentlyContinue).($check.Name)
            if($current -eq $check.Expected){
                Add-Check -Category "Network Security" -Status "Passed" -Message $check.Desc `
                    -Current $current -Expected $check.Expected -Sev $check.Sev `
                    -Frameworks @{'CIS'='18.3';'NIST'='SC-7'}
            } else {
                Add-Check -Category "Network Security" -Status "Failed" -Message "$($check.Desc) not configured" `
                    -Current $(if($null -eq $current){"Not Set"}else{$current}) -Expected $check.Expected -Sev $check.Sev `
                    -Remediation "Set-ItemProperty -Path '$path' -Name '$($check.Name)' -Value $($check.Expected)" `
                    -Frameworks @{'CIS'='18.3';'NIST'='SC-7'}
            }
        }
    }
    
    # Windows Services Security
    $criticalServices = @{
        'EventLog' = @{Desc='Windows Event Log service'; Expected='Running'; Sev='Critical'}
        'MpsSvc' = @{Desc='Windows Firewall service'; Expected='Running'; Sev='Critical'}
        'WinDefend' = @{Desc='Windows Defender service'; Expected='Running'; Sev='Critical'}
    }
    
    foreach($svcName in $criticalServices.Keys){
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -eq $criticalServices[$svcName].Expected){
            Add-Check -Category "Services" -Status "Passed" -Message "$($criticalServices[$svcName].Desc) running" `
                -Current $svc.Status -Expected $criticalServices[$svcName].Expected -Sev $criticalServices[$svcName].Sev `
                -Frameworks @{'NIST'='CM-7'}
        } elseif($svc){
            Add-Check -Category "Services" -Status "Failed" -Message "$($criticalServices[$svcName].Desc) not running" `
                -Current $svc.Status -Expected $criticalServices[$svcName].Expected -Sev $criticalServices[$svcName].Sev `
                -Remediation "Start-Service -Name $svcName; Set-Service -Name $svcName -StartupType Automatic" `
                -Frameworks @{'NIST'='CM-7'}
        }
    }
    
    Write-Host "Core checks complete: $($results.Passed.Count) passed, $($results.Failed.Count) failed" -ForegroundColor Green
    return $results
}
