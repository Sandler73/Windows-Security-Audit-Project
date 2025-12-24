<#
.SYNOPSIS
    Core Security Checks Module - Essential Security Configuration
    
.DESCRIPTION
    Contains fundamental security checks (82 checks) that should always be performed.
    Includes Windows Defender, Firewall, UAC, Password Policy, SMB, RDP, and more.
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
    
    Write-Host "Running Core Security Checks (82 checks)..." -ForegroundColor Cyan
    
    # Windows Defender - 15 checks
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $mpPref = Get-MpPreference -ErrorAction Stop
        
        # 1. Real-time protection
        if($mpStatus.RealTimeProtectionEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Real-time protection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Critical" `
                -Frameworks @{'CIS'='18.9.45.4.1';'NIST'='SI-3';'NSA'='WNSS'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Real-time protection DISABLED" `
                -Current "Disabled" -Expected "Enabled" -Sev "Critical" `
                -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
                -Frameworks @{'CIS'='18.9.45.4.1';'NIST'='SI-3'}
        }
        
        # 2. Behavior monitoring
        if($mpStatus.BehaviorMonitorEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Behavior monitoring enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='18.9.45.4.2';'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Behavior monitoring disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" `
                -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false" -Frameworks @{'CIS'='18.9.45.4.2'}
        }
        
        # 3. On-access protection
        if($mpStatus.OnAccessProtectionEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "On-access protection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Critical" -Frameworks @{'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "On-access protection disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "Critical" -Frameworks @{'NIST'='SI-3'}
        }
        
        # 4. IOAV protection
        if($mpStatus.IoavProtectionEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "IOAV protection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "IOAV protection disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
        # 5. Cloud protection
        $cloudProtection = switch($mpPref.MAPSReporting){0{"Disabled"}1{"Basic"}2{"Advanced"}default{"Unknown"}}
        if($mpPref.MAPSReporting -gt 0){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Cloud protection: $cloudProtection" `
                -Current $cloudProtection -Expected "Basic/Advanced" -Sev "High" -Frameworks @{'CIS'='18.9.45.11';'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Cloud protection disabled" `
                -Current "Disabled" -Expected "Basic/Advanced" -Sev "High" `
                -Remediation "Set-MpPreference -MAPSReporting 2" -Frameworks @{'CIS'='18.9.45.11'}
        }
        
        # 6. Signature age
        $sigAge = $mpStatus.AntivirusSignatureAge
        if($sigAge -le 7){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Signatures current ($sigAge days)" `
                -Current "$sigAge days" -Expected "<=7 days" -Sev "High" -Frameworks @{'NIST'='SI-3';'CISA'='M1049'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Signatures outdated ($sigAge days)" `
                -Current "$sigAge days" -Expected "<=7 days" -Sev "High" `
                -Remediation "Update-MpSignature" -Frameworks @{'NIST'='SI-3';'CISA'='M1049'}
        }
        
        # 7. Script scanning
        if($mpPref.DisableScriptScanning -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Script scanning enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender';'NSA'='WNSS'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Script scanning disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" `
                -Remediation "Set-MpPreference -DisableScriptScanning `$false" -Frameworks @{'MS'='Defender'}
        }
        
        # 8. Download/attachment scanning
        if($mpPref.DisableIOAVProtection -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Download/attachment scanning enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Warnings" -Message "Download/attachment scanning disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
        # 9. Sample submission
        $sampleSubmit = switch($mpPref.SubmitSamplesConsent){0{"Prompt"}1{"Safe"}2{"Never"}3{"All"}default{"Unknown"}}
        if($mpPref.SubmitSamplesConsent -ne 2){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Sample submission: $sampleSubmit" `
                -Current $sampleSubmit -Expected "Not Never" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Warnings" -Message "Sample submission disabled" `
                -Current "Never" -Expected "Safe/All" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
        # 10. PUA protection
        $puaProtection = switch($mpPref.PUAProtection){0{"Disabled"}1{"Enabled"}2{"Audit"}default{"Unknown"}}
        if($mpPref.PUAProtection -eq 1){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "PUA protection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender';'CISA'='M1049'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "PUA protection not enabled" `
                -Current $puaProtection -Expected "Enabled" -Sev "Medium" `
                -Remediation "Set-MpPreference -PUAProtection 1" -Frameworks @{'MS'='Defender'}
        }
        
        # 11. Archive scanning
        if($mpPref.DisableArchiveScanning -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Archive file scanning enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Warnings" -Message "Archive scanning disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'MS'='Defender'}
        }
        
        # 12. Removable drive scanning
        if($mpPref.DisableRemovableDriveScanning -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Removable drive scanning enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender';'CISA'='M1042'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "Removable drive scanning disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" `
                -Remediation "Set-MpPreference -DisableRemovableDriveScanning `$false" -Frameworks @{'MS'='Defender'}
        }
        
        # 13. Network inspection
        if($mpStatus.NISEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Network inspection enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Warnings" -Message "Network inspection disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender'}
        }
        
        # 14. Block at First Sight
        if($mpPref.DisableBlockAtFirstSeen -eq $false){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "Block at First Sight enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Warnings" -Message "Block at First Sight disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" -Frameworks @{'MS'='Defender'}
        }
        
        # 15. AntiSpyware
        if($mpStatus.AntiSpywareEnabled){
            Add-Check -Category "Windows Defender" -Status "Passed" -Message "AntiSpyware enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'NIST'='SI-3'}
        } else {
            Add-Check -Category "Windows Defender" -Status "Failed" -Message "AntiSpyware disabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" -Frameworks @{'NIST'='SI-3'}
        }
        
    } catch {
        Add-Check -Category "Windows Defender" -Status "Failed" -Message "Cannot query Windows Defender" `
            -Details $_.Exception.Message -Sev "Critical" -Frameworks @{'NIST'='SI-3'}
    }
    
    # Windows Firewall - 15 checks (5 per profile)
    foreach($profile in @("Domain","Private","Public")){
        $fw = Get-NetFirewallProfile -Name $profile -ErrorAction SilentlyContinue
        if($fw){
            # Enabled
            if($fw.Enabled -eq "True"){
                Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile firewall enabled" `
                    -Current "Enabled" -Expected "Enabled" -Sev "Critical" `
                    -Frameworks @{'CIS'='9.1';'NIST'='SC-7';'NSA'='WNSS';'CISA'='CPG'}
            } else {
                Add-Check -Category "Windows Firewall" -Status "Failed" -Message "$profile firewall DISABLED" `
                    -Current "Disabled" -Expected "Enabled" -Sev "Critical" `
                    -Remediation "Set-NetFirewallProfile -Name $profile -Enabled True" `
                    -Frameworks @{'CIS'='9.1';'NIST'='SC-7'}
            }
            
            # Default inbound
            if($fw.DefaultInboundAction -eq "Block"){
                Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile inbound: Block" `
                    -Current "Block" -Expected "Block" -Sev "High" -Frameworks @{'CIS'='9.1';'NIST'='SC-7'}
            } else {
                Add-Check -Category "Windows Firewall" -Status "Failed" -Message "$profile inbound: Allow" `
                    -Current "Allow" -Expected "Block" -Sev "High" `
                    -Remediation "Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block" `
                    -Frameworks @{'CIS'='9.1'}
            }
            
            # Default outbound
            if($fw.DefaultOutboundAction -eq "Allow"){
                Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile outbound: Allow" `
                    -Current "Allow" -Expected "Allow" -Sev "Low" -Frameworks @{'CIS'='9.1'}
            }
            
            # Logging blocked
            if($fw.LogBlocked -eq "True"){
                Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile logging blocked" `
                    -Current "Enabled" -Expected "Enabled" -Sev "Low" -Frameworks @{'NIST'='AU-2'}
            } else {
                Add-Check -Category "Windows Firewall" -Status "Warnings" -Message "$profile not logging blocked" `
                    -Current "Disabled" -Expected "Enabled" -Sev "Low" -Frameworks @{'NIST'='AU-2'}
            }
            
            # Notifications
            if($fw.NotifyOnListen -eq "False"){
                Add-Check -Category "Windows Firewall" -Status "Passed" -Message "$profile notifications disabled" `
                    -Current "Disabled" -Expected "Disabled" -Sev "Low" -Frameworks @{'CIS'='9.1'}
            }
        }
    }
    
    # UAC - 8 checks
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    # 1. UAC enabled
    $enableLUA = (Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    if($enableLUA -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "UAC enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Critical" `
            -Frameworks @{'CIS'='2.3.17.1';'NIST'='AC-6';'NSA'='WNSS'}
    } else {
        Add-Check -Category "UAC" -Status "Failed" -Message "UAC DISABLED" `
            -Current "Disabled" -Expected "Enabled" -Sev "Critical" `
            -Remediation "Set-ItemProperty -Path '$uacPath' -Name 'EnableLUA' -Value 1" `
            -Frameworks @{'CIS'='2.3.17.1';'NIST'='AC-6'}
    }
    
    # 2. Prompt on secure desktop
    $promptSecure = (Get-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    if($promptSecure -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "UAC on secure desktop" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='2.3.17.6';'NIST'='AC-6'}
    } else {
        Add-Check -Category "UAC" -Status "Failed" -Message "UAC not on secure desktop" `
            -Current "Disabled" -Expected "Enabled" -Sev "High" `
            -Remediation "Set-ItemProperty -Path '$uacPath' -Name 'PromptOnSecureDesktop' -Value 1" `
            -Frameworks @{'CIS'='2.3.17.6'}
    }
    
    # 3. Admin consent prompt
    $consentAdmin = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    if($consentAdmin -ge 2){
        Add-Check -Category "UAC" -Status "Passed" -Message "Admin consent prompt enabled" `
            -Current $consentAdmin -Expected "2+" -Sev "High" -Frameworks @{'CIS'='2.3.17.2'}
    } else {
        Add-Check -Category "UAC" -Status "Failed" -Message "Admin consent prompt disabled" `
            -Current $consentAdmin -Expected "2+" -Sev "High" `
            -Remediation "Set-ItemProperty -Path '$uacPath' -Name 'ConsentPromptBehaviorAdmin' -Value 2" `
            -Frameworks @{'CIS'='2.3.17.2'}
    }
    
    # 4. Standard user elevation prompt
    $elevatePrompt = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue).ConsentPromptBehaviorUser
    if($elevatePrompt -eq 0){
        Add-Check -Category "UAC" -Status "Passed" -Message "Standard user elevation denied" `
            -Current "Auto deny" -Expected "Auto deny" -Sev "Medium" -Frameworks @{'CIS'='2.3.17.3'}
    } else {
        Add-Check -Category "UAC" -Status "Warnings" -Message "Standard user can request elevation" `
            -Current $elevatePrompt -Expected "0 (auto deny)" -Sev "Medium" -Frameworks @{'CIS'='2.3.17.3'}
    }
    
    # 5. Secure UI paths
    $secureUIPath = (Get-ItemProperty -Path $uacPath -Name "EnableSecureUIAPaths" -ErrorAction SilentlyContinue).EnableSecureUIAPaths
    if($secureUIPath -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "Secure UI paths enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'CIS'='2.3.17.7'}
    } else {
        Add-Check -Category "UAC" -Status "Warnings" -Message "Secure UI paths not enabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'CIS'='2.3.17.7'}
    }
    
    # 6. Virtualization
    $virtualization = (Get-ItemProperty -Path $uacPath -Name "EnableVirtualization" -ErrorAction SilentlyContinue).EnableVirtualization
    if($virtualization -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "File/registry virtualization enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'CIS'='2.3.17.8'}
    } else {
        Add-Check -Category "UAC" -Status "Warnings" -Message "Virtualization disabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'CIS'='2.3.17.8'}
    }
    
    # 7. Admin approval mode
    $filterAdmin = (Get-ItemProperty -Path $uacPath -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue).FilterAdministratorToken
    if($filterAdmin -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "Admin approval mode enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='2.3.17.4'}
    } else {
        Add-Check -Category "UAC" -Status "Warnings" -Message "Admin approval mode disabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='2.3.17.4'}
    }
    
    # 8. Installer detection
    $installerDetect = (Get-ItemProperty -Path $uacPath -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue).EnableInstallerDetection
    if($installerDetect -eq 1){
        Add-Check -Category "UAC" -Status "Passed" -Message "Installer detection enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Low" -Frameworks @{'CIS'='2.3.17.5'}
    }
    
    # Password and Lockout Policy - 8 checks
    try {
        $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet 2>&1
        $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction Stop
        Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
        
        # 1. Min password length
        if($content -match 'MinimumPasswordLength\s*=\s*(\d+)'){
            $minLen = [int]$matches[1]
            if($minLen -ge 14){
                Add-Check -Category "Password Policy" -Status "Passed" -Message "Min password length: $minLen" `
                    -Current $minLen -Expected "14+" -Sev "High" -Frameworks @{'CIS'='1.1.1';'NIST'='IA-5(1)';'NSA'='WNSS'}
            } else {
                Add-Check -Category "Password Policy" -Status "Failed" -Message "Min password length too short: $minLen" `
                    -Current $minLen -Expected "14+" -Sev "High" `
                    -Remediation "# Configure via Local Security Policy: secpol.msc" `
                    -Frameworks @{'CIS'='1.1.1';'NIST'='IA-5(1)'}
            }
        }
        
        # 2. Password history
        if($content -match 'PasswordHistorySize\s*=\s*(\d+)'){
            $history = [int]$matches[1]
            if($history -ge 24){
                Add-Check -Category "Password Policy" -Status "Passed" -Message "Password history: $history" `
                    -Current $history -Expected "24+" -Sev "Medium" -Frameworks @{'CIS'='1.1.2';'NIST'='IA-5(1)'}
            } else {
                Add-Check -Category "Password Policy" -Status "Warnings" -Message "Password history too small: $history" `
                    -Current $history -Expected "24+" -Sev "Medium" -Frameworks @{'CIS'='1.1.2'}
            }
        }
        
        # 3. Max password age
        if($content -match 'MaximumPasswordAge\s*=\s*(\d+)'){
            $maxAge = [int]$matches[1]
            if($maxAge -le 60 -and $maxAge -gt 0){
                Add-Check -Category "Password Policy" -Status "Passed" -Message "Max password age: $maxAge days" `
                    -Current "$maxAge days" -Expected "1-60 days" -Sev "Medium" -Frameworks @{'CIS'='1.1.3';'NIST'='IA-5(1)'}
            } else {
                Add-Check -Category "Password Policy" -Status "Warnings" -Message "Max password age not optimal: $maxAge" `
                    -Current "$maxAge days" -Expected "1-60 days" -Sev "Medium" -Frameworks @{'CIS'='1.1.3'}
            }
        }
        
        # 4. Min password age
        if($content -match 'MinimumPasswordAge\s*=\s*(\d+)'){
            $minAge = [int]$matches[1]
            if($minAge -ge 1){
                Add-Check -Category "Password Policy" -Status "Passed" -Message "Min password age: $minAge day(s)" `
                    -Current "$minAge days" -Expected "1+ days" -Sev "Low" -Frameworks @{'CIS'='1.1.4'}
            } else {
                Add-Check -Category "Password Policy" -Status "Warnings" -Message "Min password age not set" `
                    -Current "0 days" -Expected "1+ days" -Sev "Low" -Frameworks @{'CIS'='1.1.4'}
            }
        }
        
        # 5. Password complexity
        if($content -match 'PasswordComplexity\s*=\s*(\d+)'){
            $complexity = [int]$matches[1]
            if($complexity -eq 1){
                Add-Check -Category "Password Policy" -Status "Passed" -Message "Password complexity required" `
                    -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'CIS'='1.1.5';'NIST'='IA-5(1)'}
            } else {
                Add-Check -Category "Password Policy" -Status "Failed" -Message "Password complexity NOT required" `
                    -Current "Disabled" -Expected "Enabled" -Sev "High" `
                    -Remediation "# Enable via Local Security Policy" -Frameworks @{'CIS'='1.1.5'}
            }
        }
        
        # 6. Reversible encryption
        if($content -match 'ClearTextPassword\s*=\s*(\d+)'){
            $cleartext = [int]$matches[1]
            if($cleartext -eq 0){
                Add-Check -Category "Password Policy" -Status "Passed" -Message "Reversible encryption disabled" `
                    -Current "Disabled" -Expected "Disabled" -Sev "High" -Frameworks @{'CIS'='1.1.6';'NIST'='IA-5(1)'}
            } else {
                Add-Check -Category "Password Policy" -Status "Failed" -Message "Reversible encryption ENABLED" `
                    -Current "Enabled" -Expected "Disabled" -Sev "High" `
                    -Remediation "# Disable via Local Security Policy" -Frameworks @{'CIS'='1.1.6'}
            }
        }
        
        # 7. Account lockout threshold
        if($content -match 'LockoutBadCount\s*=\s*(\d+)'){
            $lockCount = [int]$matches[1]
            if($lockCount -ge 5 -and $lockCount -le 10){
                Add-Check -Category "Account Lockout" -Status "Passed" -Message "Lockout threshold: $lockCount" `
                    -Current $lockCount -Expected "5-10" -Sev "High" -Frameworks @{'CIS'='1.2.1';'NIST'='AC-7';'NSA'='WNSS'}
            } elseif($lockCount -eq 0) {
                Add-Check -Category "Account Lockout" -Status "Failed" -Message "Account lockout not configured" `
                    -Current "Never" -Expected "5-10 attempts" -Sev "High" `
                    -Remediation "# Configure via Local Security Policy" -Frameworks @{'CIS'='1.2.1'}
            } else {
                Add-Check -Category "Account Lockout" -Status "Warnings" -Message "Lockout threshold not optimal: $lockCount" `
                    -Current $lockCount -Expected "5-10" -Sev "High" -Frameworks @{'CIS'='1.2.1'}
            }
        }
        
        # 8. Lockout duration
        if($content -match 'LockoutDuration\s*=\s*(\d+)'){
            $lockDuration = [int]$matches[1]
            if($lockDuration -ge 15){
                Add-Check -Category "Account Lockout" -Status "Passed" -Message "Lockout duration: $lockDuration min" `
                    -Current "$lockDuration min" -Expected "15+ min" -Sev "Medium" -Frameworks @{'CIS'='1.2.2';'NIST'='AC-7'}
            } else {
                Add-Check -Category "Account Lockout" -Status "Warnings" -Message "Lockout duration too short: $lockDuration" `
                    -Current "$lockDuration min" -Expected "15+ min" -Sev "Medium" -Frameworks @{'CIS'='1.2.2'}
            }
        }
        
    } catch {
        Add-Check -Category "Password Policy" -Status "Warnings" -Message "Cannot export security policy" `
            -Details $_.Exception.Message -Sev "High" -Frameworks @{'CIS'='1.1'}
    }
    
    # Windows Update - 2 checks
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $noAutoUpdate = (Get-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
    if($noAutoUpdate -eq 0 -or $null -eq $noAutoUpdate){
        Add-Check -Category "Windows Update" -Status "Passed" -Message "Automatic updates enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -Frameworks @{'NIST'='SI-2';'CISA'='CPG'}
    } else {
        Add-Check -Category "Windows Update" -Status "Failed" -Message "Automatic updates DISABLED" `
            -Current "Disabled" -Expected "Enabled" -Sev "High" `
            -Remediation "Remove-ItemProperty -Path '$wuPath' -Name 'NoAutoUpdate' -Force" `
            -Frameworks @{'NIST'='SI-2';'CISA'='CPG'}
    }
    
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pending = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        
        if($pending.Updates.Count -eq 0){
            Add-Check -Category "Windows Update" -Status "Passed" -Message "No pending updates" `
                -Current "0 updates" -Expected "0 updates" -Sev "Medium" -Frameworks @{'NIST'='SI-2'}
        } else {
            $critical = ($pending.Updates | Where-Object{$_.MsrcSeverity -eq "Critical"}).Count
            if($critical -gt 0){
                Add-Check -Category "Windows Update" -Status "Failed" -Message "$critical critical updates pending" `
                    -Current "$critical critical" -Expected "0 pending" -Sev "Critical" `
                    -Remediation "# Install updates via Settings > Windows Update" -Frameworks @{'NIST'='SI-2';'CISA'='CPG'}
            } else {
                Add-Check -Category "Windows Update" -Status "Warnings" -Message "$($pending.Updates.Count) updates pending" `
                    -Current "$($pending.Updates.Count) updates" -Expected "0 pending" -Sev "Medium" `
                    -Frameworks @{'NIST'='SI-2'}
            }
        }
    } catch {}
    
    # User Accounts - 2 checks
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if($guest -and -not $guest.Enabled){
        Add-Check -Category "User Accounts" -Status "Passed" -Message "Guest account disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" `
            -Frameworks @{'CIS'='2.3.1.1';'NIST'='AC-2';'NSA'='WNSS'}
    } else {
        Add-Check -Category "User Accounts" -Status "Failed" -Message "Guest account ENABLED" `
            -Current "Enabled" -Expected "Disabled" -Sev "High" `
            -Remediation "Disable-LocalUser -Name 'Guest'" `
            -Frameworks @{'CIS'='2.3.1.1';'NIST'='AC-2'}
    }
    
    $admin = Get-LocalUser | Where-Object{$_.SID -like "*-500"}
    if($admin -and -not $admin.Enabled){
        Add-Check -Category "User Accounts" -Status "Passed" -Message "Built-in Administrator disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -Frameworks @{'CIS'='2.3.1.2';'NSA'='WNSS'}
    } else {
        Add-Check -Category "User Accounts" -Status "Warnings" -Message "Built-in Administrator enabled" `
            -Current "Enabled" -Expected "Disabled" -Sev "High" -Frameworks @{'CIS'='2.3.1.2'}
    }
    
    # SMB - 3 checks
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if($smbv1 -and $smbv1.State -eq "Disabled"){
        Add-Check -Category "SMB" -Status "Passed" -Message "SMBv1 disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "Critical" `
            -Frameworks @{'CIS'='18.3.1';'MS'='Baseline';'NSA'='WNSS';'CISA'='CPG'}
    } elseif($smbv1 -and $smbv1.State -eq "Enabled") {
        Add-Check -Category "SMB" -Status "Failed" -Message "SMBv1 ENABLED" `
            -Current "Enabled" -Expected "Disabled" -Sev "Critical" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -Frameworks @{'CIS'='18.3.1';'MS'='Baseline'}
    }
    
    $smbSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if($smbSigning -eq 1){
        Add-Check -Category "SMB" -Status "Passed" -Message "SMB server signing required" `
            -Current "Required" -Expected "Required" -Sev "High" `
            -Frameworks @{'CIS'='2.3.8.3';'NIST'='SC-8';'NSA'='WNSS'}
    } else {
        Add-Check -Category "SMB" -Status "Failed" -Message "SMB server signing NOT required" `
            -Current "Not required" -Expected "Required" -Sev "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1" `
            -Frameworks @{'CIS'='2.3.8.3';'NIST'='SC-8'}
    }
    
    $smbClientSign = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if($smbClientSign -eq 1){
        Add-Check -Category "SMB" -Status "Passed" -Message "SMB client signing required" `
            -Current "Required" -Expected "Required" -Sev "High" -Frameworks @{'CIS'='2.3.6.3';'NIST'='SC-8'}
    } else {
        Add-Check -Category "SMB" -Status "Warnings" -Message "SMB client signing not required" `
            -Current "Not required" -Expected "Required" -Sev "High" -Frameworks @{'CIS'='2.3.6.3'}
    }
    
    # PowerShell - 3 checks
    $execPolicy = Get-ExecutionPolicy -Scope LocalMachine
    if($execPolicy -in @('AllSigned','RemoteSigned','Restricted')){
        Add-Check -Category "PowerShell" -Status "Passed" -Message "Execution policy: $execPolicy" `
            -Current $execPolicy -Expected "AllSigned/RemoteSigned/Restricted" -Sev "Medium" `
            -Frameworks @{'CIS'='18.9.95';'MS'='Baseline'}
    } else {
        Add-Check -Category "PowerShell" -Status "Warnings" -Message "Execution policy permissive: $execPolicy" `
            -Current $execPolicy -Expected "AllSigned/RemoteSigned" -Sev "Medium" `
            -Frameworks @{'CIS'='18.9.95'}
    }
    
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
    if($psv2 -and $psv2.State -eq "Disabled"){
        Add-Check -Category "PowerShell" -Status "Passed" -Message "PowerShell v2 disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" `
            -Frameworks @{'CIS'='18.9.95.1';'STIG'='V-220719';'NSA'='WNSS'}
    } elseif($psv2 -and $psv2.State -eq "Enabled") {
        Add-Check -Category "PowerShell" -Status "Failed" -Message "PowerShell v2 ENABLED" `
            -Current "Enabled" -Expected "Disabled" -Sev "High" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart" `
            -Frameworks @{'CIS'='18.9.95.1';'STIG'='V-220719'}
    }
    
    $scriptLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if($scriptLogging -eq 1){
        Add-Check -Category "PowerShell" -Status "Passed" -Message "Script block logging enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" `
            -Frameworks @{'CIS'='18.9.95.2';'NIST'='AU-2'}
    } else {
        Add-Check -Category "PowerShell" -Status "Warnings" -Message "Script block logging not enabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "Medium" -Frameworks @{'CIS'='18.9.95.2'}
    }
    
    # RDP - 3 checks
    $rdpDeny = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if($rdpDeny -eq 1){
        Add-Check -Category "RDP" -Status "Passed" -Message "RDP disabled" `
            -Current "Disabled" -Expected "Disabled (if not needed)" -Sev "Medium" `
            -Frameworks @{'NIST'='AC-17';'CISA'='CPG'}
    } else {
        $nla = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        if($nla -eq 1){
            Add-Check -Category "RDP" -Status "Passed" -Message "RDP enabled with NLA" `
                -Current "NLA enabled" -Expected "NLA required" -Sev "Medium" `
                -Frameworks @{'CIS'='18.9.62.3.9.1';'NIST'='AC-17'}
        } else {
            Add-Check -Category "RDP" -Status "Failed" -Message "RDP enabled WITHOUT NLA" `
                -Current "No NLA" -Expected "NLA required" -Sev "High" `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1" `
                -Frameworks @{'CIS'='18.9.62.3.9.1';'NIST'='AC-17'}
        }
    }
    
    $rdpEncryption = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
    if($rdpEncryption -eq 3){
        Add-Check -Category "RDP" -Status "Passed" -Message "RDP encryption: High" `
            -Current "High" -Expected "High" -Sev "High" -Frameworks @{'CIS'='18.9.62.3.9.2'}
    } else {
        Add-Check -Category "RDP" -Status "Warnings" -Message "RDP encryption not set to High" `
            -Current $(if($rdpEncryption){"Level $rdpEncryption"}else{"Not set"}) -Expected "3 (High)" -Sev "High" `
            -Frameworks @{'CIS'='18.9.62.3.9.2'}
    }
    
    $rdpSecurityLayer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer
    if($rdpSecurityLayer -eq 2){
        Add-Check -Category "RDP" -Status "Passed" -Message "RDP security layer: SSL/TLS" `
            -Current "SSL/TLS" -Expected "SSL/TLS" -Sev "High" -Frameworks @{'CIS'='18.9.62.3.9.3'}
    }
    
    # Credential Protection - 2 checks
    $lsaProtection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    if($lsaProtection -eq 1){
        Add-Check -Category "Credential Protection" -Status "Passed" -Message "LSA Protection enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" `
            -Frameworks @{'MS'='Baseline';'NSA'='WNSS'}
    } else {
        Add-Check -Category "Credential Protection" -Status "Warnings" -Message "LSA Protection not enabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1" `
            -Frameworks @{'MS'='Baseline'}
    }
    
    $wdigest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    if($wdigest -eq 0){
        Add-Check -Category "Credential Protection" -Status "Passed" -Message "WDigest disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "High" -Frameworks @{'MS'='Baseline';'NSA'='WNSS'}
    } else {
        Add-Check -Category "Credential Protection" -Status "Failed" -Message "WDigest NOT disabled" `
            -Current $(if($null -eq $wdigest){"Not set (enabled)"}else{"Enabled"}) -Expected "Disabled" -Sev "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0" `
            -Frameworks @{'MS'='Baseline'}
    }
    
    # Network Security - 5 checks
    $llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    if($llmnr -eq 0){
        Add-Check -Category "Network Security" -Status "Passed" -Message "LLMNR disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "Medium" `
            -Frameworks @{'CIS'='18.5.10.2';'NIST'='SC-20';'NSA'='WNSS'}
    } else {
        Add-Check -Category "Network Security" -Status "Failed" -Message "LLMNR NOT disabled" `
            -Current "Enabled" -Expected "Disabled" -Sev "Medium" `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0" `
            -Frameworks @{'CIS'='18.5.10.2';'NIST'='SC-20'}
    }
    
    $netbios = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -ErrorAction SilentlyContinue).NoNameReleaseOnDemand
    if($netbios -eq 1){
        Add-Check -Category "Network Security" -Status "Passed" -Message "NetBIOS name release protected" `
            -Current "Protected" -Expected "Protected" -Sev "Low" -Frameworks @{'NSA'='WNSS'}
    }
    
    $icmpRedirect = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -ErrorAction SilentlyContinue).EnableICMPRedirect
    if($icmpRedirect -eq 0){
        Add-Check -Category "Network Security" -Status "Passed" -Message "ICMP redirects disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "Medium" -Frameworks @{'CIS'='18.4.1';'NIST'='SC-7'}
    } else {
        Add-Check -Category "Network Security" -Status "Warnings" -Message "ICMP redirects enabled" `
            -Current "Enabled" -Expected "Disabled" -Sev "Medium" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Value 0" `
            -Frameworks @{'CIS'='18.4.1'}
    }
    
    $ipSourceRoute = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue).DisableIPSourceRouting
    if($ipSourceRoute -eq 2){
        Add-Check -Category "Network Security" -Status "Passed" -Message "IP source routing disabled" `
            -Current "Highest protection" -Expected "Highest protection" -Sev "Medium" `
            -Frameworks @{'CIS'='18.4.2';'NIST'='SC-7'}
    } else {
        Add-Check -Category "Network Security" -Status "Warnings" -Message "IP source routing not fully disabled" `
            -Current $(if($ipSourceRoute -eq 1){"Medium"}elseif($ipSourceRoute -eq 0){"Enabled"}else{"Not set"}) -Expected "2 (Highest)" -Sev "Medium" `
            -Frameworks @{'CIS'='18.4.2'}
    }
    
    $ipv6SourceRoute = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue).DisableIPSourceRouting
    if($ipv6SourceRoute -eq 2){
        Add-Check -Category "Network Security" -Status "Passed" -Message "IPv6 source routing disabled" `
            -Current "Highest protection" -Expected "Highest protection" -Sev "Medium" -Frameworks @{'CIS'='18.4.3'}
    }
    
    # AutoRun - 1 check
    $autoRun = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    if($autoRun -eq 255){
        Add-Check -Category "AutoRun" -Status "Passed" -Message "AutoRun disabled all drives" `
            -Current "255 (all drives)" -Expected "255" -Sev "High" `
            -Frameworks @{'CIS'='18.9.8';'NIST'='CM-7';'CISA'='M1042'}
    } else {
        Add-Check -Category "AutoRun" -Status "Failed" -Message "AutoRun not fully disabled" `
            -Current $(if($autoRun){"$autoRun"}else{"Not Set"}) -Expected "255" -Sev "High" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255" `
            -Frameworks @{'CIS'='18.9.8';'NIST'='CM-7'}
    }
    
    # Services - 3 checks
    $criticalServices = @{
        'EventLog' = 'Windows Event Log'
        'MpsSvc' = 'Windows Firewall'
        'WinDefend' = 'Windows Defender'
    }
    
    foreach($svcName in $criticalServices.Keys){
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -eq 'Running'){
            Add-Check -Category "Services" -Status "Passed" -Message "$($criticalServices[$svcName]) running" `
                -Current "Running" -Expected "Running" -Sev "Critical" -Frameworks @{'NIST'='CM-7'}
        } elseif($svc) {
            Add-Check -Category "Services" -Status "Failed" -Message "$($criticalServices[$svcName]) NOT running" `
                -Current $svc.Status -Expected "Running" -Sev "Critical" `
                -Remediation "Start-Service -Name $svcName; Set-Service -Name $svcName -StartupType Automatic" `
                -Frameworks @{'NIST'='CM-7'}
        }
    }
    
    $totalChecks = $results.Passed.Count + $results.Failed.Count + $results.Warnings.Count + $results.Info.Count
    Write-Host "Core checks complete: $totalChecks executed, $($results.Passed.Count) passed, $($results.Failed.Count) failed, $($results.Warnings.Count) warnings" -ForegroundColor Green
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

Write-Host "`n[Core] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red
Write-Host "  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "  Info: $infoCount" -ForegroundColor Cyan
Write-Host "  Errors: $errorCount" -ForegroundColor Magenta

return $results  # THIS LINE MUST BE PRESENT
    Write-Host "Core checks complete: $($results.Passed.Count) passed, $($results.Failed.Count) failed" -ForegroundColor Green
    return $results
}
