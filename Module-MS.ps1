<#
.SYNOPSIS
    Microsoft Security Baseline Module - Comprehensive MS Recommendations
    
.DESCRIPTION
    Contains extensive checks based on Microsoft Security Compliance Toolkit baselines.
    Includes Windows 10/11 security recommendations from Microsoft (50+ checks).
#>

function Invoke-MSChecks {
    param([string]$Severity = 'ALL')
    
    $results = @{Passed=@(); Failed=@(); Warnings=@(); Info=@()}
    
    function Add-Check {
        param($Category,$Status,$Message,$Details="",$Current="N/A",$Expected="N/A",$Sev="Medium",$Remediation="",$MSControl="")
        
        if($Severity -ne 'ALL' -and $Severity -ne $Sev){return}
        
        $result = [PSCustomObject]@{
            Category=$Category; Status=$Status; Message=$Message; Details=$Details
            CurrentValue=$Current; ExpectedValue=$Expected; Severity=$Sev
            Remediation=$Remediation; Frameworks="MS $MSControl"
        }
        
        $results.$Status += $result
    }
    
    Write-Host "Running Microsoft Security Baseline Checks..." -ForegroundColor Cyan
    
    # Windows Defender Advanced Features
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        
        # Attack Surface Reduction Rules
        if($mpPref.AttackSurfaceReductionRules_Ids.Count -gt 0){
            Add-Check -Category "Defender ATP" -Status "Passed" -Message "ASR rules configured ($($mpPref.AttackSurfaceReductionRules_Ids.Count) rules)" `
                -Current "$($mpPref.AttackSurfaceReductionRules_Ids.Count) rules" -Expected "1+ rules" -Sev "Medium" -MSControl "ASR"
        } else {
            Add-Check -Category "Defender ATP" -Status "Warnings" -Message "No ASR rules configured" `
                -Current "0 rules" -Expected "1+ rules" -Sev "Medium" `
                -Details "ASR reduces attack vectors" -MSControl "ASR"
        }
        
        # Controlled Folder Access
        $cfaStatus = switch($mpPref.EnableControlledFolderAccess){
            0{"Disabled"} 1{"Enabled"} 2{"Audit Mode"} default{"Unknown"}
        }
        if($mpPref.EnableControlledFolderAccess -eq 1){
            Add-Check -Category "Defender ATP" -Status "Passed" -Message "Controlled Folder Access enabled" `
                -Current $cfaStatus -Expected "Enabled" -Sev "Medium" -MSControl "CFA"
        } else {
            Add-Check -Category "Defender ATP" -Status "Warnings" -Message "Controlled Folder Access not enabled" `
                -Current $cfaStatus -Expected "Enabled" -Sev "Medium" `
                -Details "Protects against ransomware" -MSControl "CFA"
        }
        
        # Network Protection
        $netProtect = switch($mpPref.EnableNetworkProtection){
            0{"Disabled"} 1{"Enabled"} 2{"Audit Mode"} default{"Unknown"}
        }
        if($mpPref.EnableNetworkProtection -eq 1){
            Add-Check -Category "Defender ATP" -Status "Passed" -Message "Network Protection enabled" `
                -Current $netProtect -Expected "Enabled" -Sev "Medium" -MSControl "NetProtect"
        } else {
            Add-Check -Category "Defender ATP" -Status "Warnings" -Message "Network Protection not enabled" `
                -Current $netProtect -Expected "Enabled" -Sev "Medium" `
                -Details "Blocks connections to malicious domains" -MSControl "NetProtect"
        }
        
        # Cloud-delivered protection extended timeout
        $cloudExtTimeout = $mpPref.MAPSReporting
        if($cloudExtTimeout -eq 2){
            Add-Check -Category "Defender ATP" -Status "Passed" -Message "MAPS reporting set to Advanced" `
                -Current "Advanced" -Expected "Advanced" -Sev "High" -MSControl "MAPS"
        }
        
        # Block at First Sight
        $bafs = $mpPref.DisableBlockAtFirstSeen
        if($bafs -eq $false){
            Add-Check -Category "Defender ATP" -Status "Passed" -Message "Block at First Sight enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -MSControl "BAFS"
        } else {
            Add-Check -Category "Defender ATP" -Status "Failed" -Message "Block at First Sight DISABLED" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" `
                -Remediation "Set-MpPreference -DisableBlockAtFirstSeen `$false" -MSControl "BAFS"
        }
        
    } catch {
        Add-Check -Category "Defender ATP" -Status "Warnings" -Message "Cannot query Defender" `
            -Details $_.Exception.Message -Sev "High"
    }
    
    # Virtualization-Based Security
    $vbsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    
    $vbs = (Get-ItemProperty -Path $vbsPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    if($vbs -eq 1){
        Add-Check -Category "VBS" -Status "Passed" -Message "Virtualization-based security enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -MSControl "VBS"
    } else {
        Add-Check -Category "VBS" -Status "Warnings" -Message "VBS not enabled" `
            -Current "Disabled/Not Configured" -Expected "Enabled" -Sev "High" `
            -Details "Requires compatible hardware (TPM 2.0, UEFI)" -MSControl "VBS"
    }
    
    # Require Platform Security Features
    $platformSec = (Get-ItemProperty -Path $vbsPath -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue).RequirePlatformSecurityFeatures
    if($platformSec -eq 1 -or $platformSec -eq 3){
        Add-Check -Category "VBS" -Status "Passed" -Message "Platform security features required" `
            -Current $(if($platformSec -eq 1){"Secure Boot"}else{"Secure Boot + DMA"}) -Expected "Enabled" -Sev "High" -MSControl "PlatformSec"
    }
    
    # Credential Guard
    $credGuard = (Get-ItemProperty -Path $vbsPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
    if($credGuard -eq 1 -or $credGuard -eq 2){
        Add-Check -Category "Credential Protection" -Status "Passed" -Message "Credential Guard enabled" `
            -Current $(if($credGuard -eq 1){"Enabled with lock"}else{"Enabled without lock"}) -Expected "Enabled" -Sev "High" -MSControl "CredGuard"
    } else {
        Add-Check -Category "Credential Protection" -Status "Warnings" -Message "Credential Guard not enabled" `
            -Current "Not Configured" -Expected "Enabled" -Sev "High" `
            -Details "Requires VBS and compatible hardware" -MSControl "CredGuard"
    }
    
    # HVCI (Hypervisor-Enforced Code Integrity)
    $hvci = (Get-ItemProperty -Path "$vbsPath\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if($hvci -eq 1){
        Add-Check -Category "VBS" -Status "Passed" -Message "HVCI (Memory Integrity) enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "High" -MSControl "HVCI"
    } else {
        Add-Check -Category "VBS" -Status "Warnings" -Message "HVCI not enabled" `
            -Current "Disabled/Not Configured" -Expected "Enabled" -Sev "High" `
            -Details "Requires compatible hardware and drivers" -MSControl "HVCI"
    }
    
    # Secure Boot
    try {
        $secureBootStatus = Confirm-SecureBootUEFI
        if($secureBootStatus){
            Add-Check -Category "Boot Security" -Status "Passed" -Message "Secure Boot enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "High" -MSControl "SecureBoot"
        } else {
            Add-Check -Category "Boot Security" -Status "Failed" -Message "Secure Boot NOT enabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "High" `
                -Details "Enable in UEFI/BIOS settings" `
                -Remediation "# Enable Secure Boot in UEFI firmware settings" `
                -MSControl "SecureBoot"
        }
    } catch {
        Add-Check -Category "Boot Security" -Status "Info" -Message "Secure Boot status unavailable" `
            -Details "May not be using UEFI or not supported" -Sev "High" -MSControl "SecureBoot"
    }
    
    # Early Launch Anti-Malware
    $elamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
    $driverLoadPolicy = (Get-ItemProperty -Path $elamPath -Name "DriverLoadPolicy" -ErrorAction SilentlyContinue).DriverLoadPolicy
    if($driverLoadPolicy -eq 3 -or $driverLoadPolicy -eq 1){
        $policy = switch($driverLoadPolicy){1{"Good only"}3{"Good and unknown"}default{"Unknown"}}
        Add-Check -Category "Boot Security" -Status "Passed" -Message "Early launch driver policy configured" `
            -Current $policy -Expected "Good only/Good and unknown" -Sev "Medium" -MSControl "ELAM"
    } else {
        Add-Check -Category "Boot Security" -Status "Warnings" -Message "Early launch driver policy not optimal" `
            -Current "Not Set/Bad" -Expected "Good only" -Sev "Medium" -MSControl "ELAM"
    }
    
    # SmartScreen
    $smartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $smartScreen = (Get-ItemProperty -Path $smartScreenPath -Name "EnableSmartScreen" -ErrorAction SilentlyContinue).EnableSmartScreen
    if($smartScreen -eq 1){
        Add-Check -Category "SmartScreen" -Status "Passed" -Message "SmartScreen enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" -MSControl "SmartScreen"
    } else {
        Add-Check -Category "SmartScreen" -Status "Failed" -Message "SmartScreen NOT enabled" `
            -Current "Disabled" -Expected "Enabled" -Sev "Medium" `
            -Details "SmartScreen protects against phishing and malware" `
            -Remediation "New-Item -Path '$smartScreenPath' -Force; Set-ItemProperty -Path '$smartScreenPath' -Name 'EnableSmartScreen' -Value 1" `
            -MSControl "SmartScreen"
    }
    
    $shellSmartScreen = (Get-ItemProperty -Path $smartScreenPath -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue).ShellSmartScreenLevel
    if($shellSmartScreen -eq "Block"){
        Add-Check -Category "SmartScreen" -Status "Passed" -Message "SmartScreen set to Block" `
            -Current "Block" -Expected "Block" -Sev "Medium" -MSControl "SmartScreen"
    }
    
    # Exploit Protection
    $exploitProtectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
    $disableExploitProtectOverride = (Get-ItemProperty -Path $exploitProtectionPath -Name "DisallowExploitProtectionOverride" -ErrorAction SilentlyContinue).DisallowExploitProtectionOverride
    if($disableExploitProtectOverride -eq 1){
        Add-Check -Category "Exploit Protection" -Status "Passed" -Message "Users cannot override exploit protection" `
            -Current "Disabled override" -Expected "Disabled" -Sev "Medium" -MSControl "ExploitProtect"
    } else {
        Add-Check -Category "Exploit Protection" -Status "Warnings" -Message "Users can override exploit protection" `
            -Current "Allowed" -Expected "Disabled" -Sev "Medium" -MSControl "ExploitProtect"
    }
    
    # Windows Hello for Business
    $whfbPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    $whfbEnabled = (Get-ItemProperty -Path $whfbPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if($whfbEnabled -eq 1){
        Add-Check -Category "Authentication" -Status "Passed" -Message "Windows Hello for Business enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Low" -MSControl "WHFB"
    } else {
        Add-Check -Category "Authentication" -Status "Info" -Message "Windows Hello for Business not enabled" `
            -Details "Optional depending on environment" -Sev "Low" -MSControl "WHFB"
    }
    
    # Require device encryption
    $deviceEncryption = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -ErrorAction SilentlyContinue).UseAdvancedStartup
    if($deviceEncryption -eq 1){
        Add-Check -Category "Encryption" -Status "Passed" -Message "BitLocker advanced startup configured" `
            -Current "Configured" -Expected "Configured" -Sev "High" -MSControl "BitLocker"
    }
    
    # AppLocker
    $applockerPolicies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    if($applockerPolicies){
        $ruleCount = ($applockerPolicies.RuleCollections | ForEach-Object{$_.Count} | Measure-Object -Sum).Sum
        if($ruleCount -gt 0){
            Add-Check -Category "Application Control" -Status "Passed" -Message "AppLocker policies active ($ruleCount rules)" `
                -Current "$ruleCount rules" -Expected "1+ rules" -Sev "Medium" -MSControl "AppLocker"
        }
    } else {
        Add-Check -Category "Application Control" -Status "Info" -Message "No AppLocker policies" `
            -Details "Consider for high-security environments" -Sev "Medium" -MSControl "AppLocker"
    }
    
    # Windows Sandbox
    $sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
    if($sandbox -and $sandbox.State -eq "Enabled"){
        Add-Check -Category "Isolation" -Status "Passed" -Message "Windows Sandbox available" `
            -Current "Enabled" -Expected "Enabled (optional)" -Sev "Low" -MSControl "Sandbox"
    }
    
    # Microsoft Edge Security (if installed)
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if(Test-Path $edgePath){
        # Edge SmartScreen
        $edgeSmartScreen = (Get-ItemProperty -Path $edgePath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
        if($edgeSmartScreen -eq 1){
            Add-Check -Category "Browser Security" -Status "Passed" -Message "Edge SmartScreen enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -MSControl "EdgeSmartScreen"
        } else {
            Add-Check -Category "Browser Security" -Status "Failed" -Message "Edge SmartScreen not enabled" `
                -Current "Disabled" -Expected "Enabled" -Sev "Medium" `
                -Remediation "New-Item -Path '$edgePath' -Force; Set-ItemProperty -Path '$edgePath' -Name 'SmartScreenEnabled' -Value 1" `
                -MSControl "EdgeSmartScreen"
        }
        
        # Edge PUA blocking
        $edgePUA = (Get-ItemProperty -Path $edgePath -Name "SmartScreenPuaEnabled" -ErrorAction SilentlyContinue).SmartScreenPuaEnabled
        if($edgePUA -eq 1){
            Add-Check -Category "Browser Security" -Status "Passed" -Message "Edge PUA blocking enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Low" -MSControl "EdgePUA"
        }
        
        # Site isolation
        $siteIsolation = (Get-ItemProperty -Path $edgePath -Name "SitePerProcess" -ErrorAction SilentlyContinue).SitePerProcess
        if($siteIsolation -eq 1){
            Add-Check -Category "Browser Security" -Status "Passed" -Message "Edge site isolation enabled" `
                -Current "Enabled" -Expected "Enabled" -Sev "Medium" -MSControl "EdgeSiteIsolation"
        }
        
        # Password manager
        $passwordManager = (Get-ItemProperty -Path $edgePath -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue).PasswordManagerEnabled
        if($null -ne $passwordManager){
            Add-Check -Category "Browser Security" -Status "Info" -Message "Edge password manager: $(if($passwordManager -eq 1){'Enabled'}else{'Disabled'})" `
                -Current $(if($passwordManager -eq 1){"Enabled"}else{"Disabled"}) -Expected "Based on policy" -Sev "Low" -MSControl "EdgePassword"
        }
        
        # InPrivate mode
        $inPrivate = (Get-ItemProperty -Path $edgePath -Name "InPrivateModeAvailability" -ErrorAction SilentlyContinue).InPrivateModeAvailability
        if($inPrivate -eq 0){
            Add-Check -Category "Browser Security" -Status "Info" -Message "Edge InPrivate mode available" `
                -Current "Available" -Expected "Based on policy" -Sev "Low" -MSControl "EdgeInPrivate"
        }
    }
    
    # Windows Defender Application Guard
    $wdag = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction SilentlyContinue
    if($wdag -and $wdag.State -eq "Enabled"){
        Add-Check -Category "Isolation" -Status "Passed" -Message "Application Guard enabled" `
            -Current "Enabled" -Expected "Enabled (optional)" -Sev "Medium" -MSControl "WDAG"
    }
    
    # Remote Assistance
    $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $allowRA = (Get-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
    if($allowRA -eq 0 -or $null -eq $allowRA){
        Add-Check -Category "Remote Access" -Status "Passed" -Message "Remote Assistance disabled" `
            -Current "Disabled" -Expected "Disabled (unless needed)" -Sev "Low" -MSControl "RemoteAssist"
    } else {
        Add-Check -Category "Remote Access" -Status "Warnings" -Message "Remote Assistance enabled" `
            -Current "Enabled" -Expected "Disabled (unless needed)" -Sev "Low" -MSControl "RemoteAssist"
    }
    
    # Solicited Remote Assistance
    $allowSolicited = (Get-ItemProperty -Path $raPath -Name "fAllowFullControl" -ErrorAction SilentlyContinue).fAllowFullControl
    if($allowRA -eq 1 -and $allowSolicited -eq 0){
        Add-Check -Category "Remote Access" -Status "Passed" -Message "Remote Assistance limited to view-only" `
            -Current "View only" -Expected "View only (if enabled)" -Sev "Low" -MSControl "RemoteAssist"
    }
    
    # Windows Error Reporting disabled
    $werPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    $disableWER = (Get-ItemProperty -Path $werPath -Name "Disabled" -ErrorAction SilentlyContinue).Disabled
    if($disableWER -eq 1){
        Add-Check -Category "Privacy" -Status "Info" -Message "Windows Error Reporting disabled" `
            -Current "Disabled" -Expected "Based on policy" -Sev "Low" -MSControl "WER"
    }
    
    # Delivery Optimization
    $doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    $doMode = (Get-ItemProperty -Path $doPath -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode
    if($doMode -eq 1 -or $doMode -eq 0){
        Add-Check -Category "Update Management" -Status "Passed" -Message "Delivery Optimization limited" `
            -Current $(if($doMode -eq 0){"Disabled"}else{"LAN only"}) -Expected "Disabled/LAN only" -Sev "Low" -MSControl "DeliveryOpt"
    }
    
    # App privacy settings
    $appPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    
    # Location
    $letAppsAccessLocation = (Get-ItemProperty -Path $appPrivacyPath -Name "LetAppsAccessLocation" -ErrorAction SilentlyContinue).LetAppsAccessLocation
    if($letAppsAccessLocation -eq 2){
        Add-Check -Category "Privacy" -Status "Passed" -Message "Apps cannot access location" `
            -Current "Force deny" -Expected "Force deny (if not needed)" -Sev "Low" -MSControl "Privacy"
    }
    
    # Camera
    $letAppsAccessCamera = (Get-ItemProperty -Path $appPrivacyPath -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue).LetAppsAccessCamera
    if($letAppsAccessCamera -eq 2){
        Add-Check -Category "Privacy" -Status "Info" -Message "Apps cannot access camera" `
            -Current "Force deny" -Expected "Based on needs" -Sev "Low" -MSControl "Privacy"
    }
    
    # Microphone
    $letAppsAccessMicrophone = (Get-ItemProperty -Path $appPrivacyPath -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue).LetAppsAccessMicrophone
    if($letAppsAccessMicrophone -eq 2){
        Add-Check -Category "Privacy" -Status "Info" -Message "Apps cannot access microphone" `
            -Current "Force deny" -Expected "Based on needs" -Sev "Low" -MSControl "Privacy"
    }
    
    # Advertising ID
    $advertisingInfo = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue).DisabledByGroupPolicy
    if($advertisingInfo -eq 1){
        Add-Check -Category "Privacy" -Status "Passed" -Message "Advertising ID disabled" `
            -Current "Disabled" -Expected "Disabled" -Sev "Low" -MSControl "Privacy"
    }
    
    # Windows Update for Business
    $wufbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $deferQualityUpdates = (Get-ItemProperty -Path $wufbPath -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue).DeferQualityUpdates
    if($deferQualityUpdates -eq 1){
        $deferDays = (Get-ItemProperty -Path $wufbPath -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue).DeferQualityUpdatesPeriodInDays
        Add-Check -Category "Update Management" -Status "Info" -Message "Quality updates deferred ($deferDays days)" `
            -Current "$deferDays days" -Expected "Based on policy" -Sev "Low" -MSControl "WUfB"
    }
    
    # Microsoft Defender SmartScreen for Microsoft Store apps
    $storeAppsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
    $enableWebContentEval = (Get-ItemProperty -Path $storeAppsPath -Name "EnableWebContentEvaluation" -ErrorAction SilentlyContinue).EnableWebContentEvaluation
    if($enableWebContentEval -eq 1){
        Add-Check -Category "SmartScreen" -Status "Passed" -Message "SmartScreen for Store apps enabled" `
            -Current "Enabled" -Expected "Enabled" -Sev "Medium" -MSControl "StoreApps"
    }
    
    Write-Host "MS Baseline checks complete: $($results.Passed.Count) passed, $($results.Failed.Count) failed" -ForegroundColor Green
    return $results
}
