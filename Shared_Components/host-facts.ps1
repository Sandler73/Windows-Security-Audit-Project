# host-facts.ps1
# Derived host-facts registry for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Canonical derived host-facts registry computed once per audit run.

.DESCRIPTION
    Builds a single source-of-truth hashtable of derived host facts that
    multiple audit modules consume, instead of each module re-deriving the
    same state. Mirrors the Linux project's host_facts.py architecture
    (GAP-4 of the parity program).

    Facts are derived from the SharedDataCache (populated by Invoke-CacheWarmUp
    in audit-common.ps1) where available, with guarded direct queries as
    fallback. Every fact is best-effort: on failure the fact is $null (or a
    documented default) and a Reason entry is recorded in the Errors list, so
    consuming modules can distinguish "false" from "unknown".

    Fact groups:
    - Identity/role: domain membership, domain-controller role, server vs
      workstation, Server Core, OS build/version identity
    - Protection stack: Defender AV state, tamper protection, Defender for
      Endpoint (Sense) presence, third-party AV indicator
    - Platform security: TPM, Secure Boot, VBS/HVCI, Credential Guard,
      LSA protection (RunAsPPL), BitLocker system-drive state
    - Exposure: RDP enabled/NLA, SMB1 state, SMB signing, firewall profile
      states, listening TCP port inventory, WinRM service state
    - Identity hygiene: local Administrators membership count, Guest account
      state, LAPS presence (modern and legacy)
    - Execution control: AppLocker service state, WDAC policy indicator,
      PowerShell v2 engine availability, script block logging, execution policy
    - Servicing: Windows Update service state, pending reboot indicator

    The orchestrator computes this once (after cache warm-up, before module
    dispatch) and publishes it as $SharedData.HostFacts. Modules consume the
    hashtable directly; runspaces need no access to this file because they
    receive the computed data, not the functions.

.PARAMETER Cache
    The SharedDataCache hashtable from New-SharedDataCache (optional). When
    present, cached registry/CIM/service data is preferred over direct queries.

.PARAMETER OSInfo
    The OS information hashtable from Get-OSInfo (optional). When absent it is
    derived (via cache when possible).

.EXAMPLE
    . .\shared_components\host-facts.ps1
    $facts = New-HostFactsRegistry -Cache $cache -OSInfo $osInfo
    if ($facts.SMB1Enabled) { ... }

.NOTES
    Requires: PowerShell 5.1+; Administrator privileges improve completeness
    Dependencies: audit-common.ps1 (optional, for Get-CachedRegistryValue and
    Get-OSInfo); all dependencies are availability-guarded via Get-Command
    Security: read-only; no state is modified; no network calls
    Registry paths: all paths herein already appear in the audited v6.2.0
    module set (verified in the v6.1.2 principal audit); no new paths invented
    Version: 6.6.0
#>

# ============================================================================
# Internal guarded read helpers (availability-checked, cache-aware)
# ============================================================================
function Get-HFRegValue {
    <#
    .SYNOPSIS
        Cache-aware guarded registry read returning $Default on any failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [hashtable]$Cache = $null,
        $Default = $null
    )
    if ($Cache -and (Get-Command 'Get-CachedRegistryValue' -ErrorAction SilentlyContinue)) {
        return Get-CachedRegistryValue -Path $Path -Name $Name -Cache $Cache -DefaultValue $Default
    }
    try {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if ($null -ne $prop) { return $prop.$Name }
    } catch { }
    return $Default
}

function Get-HFServiceState {
    <#
    .SYNOPSIS
        Guarded service query returning a small state object or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        return @{ Present = $true; Status = "$($svc.Status)"; StartType = "$($svc.StartType)" }
    } catch {
        return $null
    }
}

# ============================================================================
# Registry builder
# ============================================================================
function New-HostFactsRegistry {
    <#
    .SYNOPSIS
        Compute the derived host-facts registry.
    .DESCRIPTION
        Returns a hashtable of derived facts plus a Meta section (timestamp,
        elapsed, error list). Safe to call without Cache/OSInfo; completeness
        degrades gracefully.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Cache = $null,
        [hashtable]$OSInfo = $null
    )

    $started = Get-Date
    $errors = [System.Collections.Generic.List[string]]::new()
    $facts = @{}

    # ---- Identity / role -------------------------------------------------
    try {
        if (-not $OSInfo -and (Get-Command 'Get-OSInfo' -ErrorAction SilentlyContinue)) {
            $OSInfo = Get-OSInfo -Cache $Cache
        }
    } catch { $errors.Add("OSInfo: $($_.Exception.Message)") }

    $facts.ComputerName   = $env:COMPUTERNAME
    $facts.OSCaption      = if ($OSInfo) { $OSInfo.OSCaption } else { $null }
    $facts.OSBuild        = if ($OSInfo) { $OSInfo.BuildNumber } else { $null }
    $facts.IsServer       = if ($OSInfo) { [bool]$OSInfo.IsServer } else { $null }
    $facts.IsDomainJoined = if ($OSInfo) { [bool]$OSInfo.IsDomainJoined } else { $null }
    $facts.DomainName     = if ($OSInfo) { $OSInfo.DomainName } else { $null }
    $facts.IsServerCore   = if ($OSInfo -and $OSInfo.InstallType) { $OSInfo.InstallType -eq 'Server Core' } else { $null }
    $facts.PSVersion      = $PSVersionTable.PSVersion.ToString()

    # v6.5.0 (HostFacts phase 2): retain the raw Win32_OperatingSystem instance.
    # Modules read Caption, BuildNumber and ProductType from it; the derived
    # scalar facts above do not carry ProductType, so the raw object is kept
    # rather than expanding the fact list property by property.
    $facts.RawOSCim = $null
    try {
        $facts.RawOSCim = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch { $errors.Add("RawOSCim: $($_.Exception.Message)") }

    # Domain controller: ProductType 2 (Win32_OperatingSystem)
    $facts.IsDomainController = $null
    try {
        $os = $null
        if ($Cache -and $Cache.OSInfo -and $null -ne $Cache.OSInfo.ProductType) {
            $facts.IsDomainController = ($Cache.OSInfo.ProductType -eq 2)
        } else {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            if ($os) { $facts.IsDomainController = ($os.ProductType -eq 2) }
        }
    } catch { $errors.Add("DomainController: $($_.Exception.Message)") }

    # ---- Protection stack ------------------------------------------------
    $facts.DefenderPresent = $null
    $facts.DefenderRealTimeProtection = $null
    $facts.DefenderTamperProtection = $null
    try {
        if (Get-Command 'Get-MpComputerStatus' -ErrorAction SilentlyContinue) {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            if ($mp) {
                $facts.DefenderPresent = $true
                $facts.DefenderRealTimeProtection = [bool]$mp.RealTimeProtectionEnabled
                # v6.5.0 (HostFacts phase 2): retain the raw status object so
                # modules can satisfy every property they read from one run-wide
                # query instead of one query per module. Field-level facts above
                # cover only a subset of the properties call sites use.
                $facts.RawDefenderStatus = $mp
                if ($null -ne $mp.IsTamperProtected) { $facts.DefenderTamperProtection = [bool]$mp.IsTamperProtected }
            }
        } else {
            $winDefend = Get-HFServiceState -Name 'WinDefend'
            $facts.DefenderPresent = ($null -ne $winDefend)
        }
    } catch { $errors.Add("Defender: $($_.Exception.Message)") }

    $sense = Get-HFServiceState -Name 'Sense'
    $facts.DefenderATPPresent = ($null -ne $sense)
    $facts.DefenderATPRunning = if ($sense) { $sense.Status -eq 'Running' } else { $false }

    # ---- Platform security ----------------------------------------------
    $facts.TPMPresent = $null
    try {
        if (Get-Command 'Get-Tpm' -ErrorAction SilentlyContinue) {
            $tpm = Get-Tpm -ErrorAction Stop
            if ($tpm) { $facts.TPMPresent = [bool]$tpm.TpmPresent }
        }
    } catch { $errors.Add("TPM: $($_.Exception.Message)") }

    $facts.SecureBootEnabled = $null
    try {
        if (Get-Command 'Confirm-SecureBootUEFI' -ErrorAction SilentlyContinue) {
            $facts.SecureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        }
    } catch { $errors.Add("SecureBoot: $($_.Exception.Message)") }

    $vbs = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Cache $Cache
    $facts.VBSEnabled = if ($null -ne $vbs) { $vbs -eq 1 } else { $null }
    $hvci = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Cache $Cache
    $facts.HVCIEnabled = if ($null -ne $hvci) { $hvci -eq 1 } else { $null }
    $lsaCfg = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Cache $Cache
    $facts.CredentialGuardConfigured = if ($null -ne $lsaCfg) { $lsaCfg -ge 1 } else { $null }
    $runAsPPL = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Cache $Cache
    $facts.LSAProtection = if ($null -ne $runAsPPL) { $runAsPPL -ge 1 } else { $null }

    $facts.BitLockerSystemDrive = $null
    try {
        if (Get-Command 'Get-BitLockerVolume' -ErrorAction SilentlyContinue) {
            $sysDrive = $env:SystemDrive
            $blv = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
            if ($blv) { $facts.BitLockerSystemDrive = ($blv.ProtectionStatus -eq 'On') }
        }
    } catch { $errors.Add("BitLocker: $($_.Exception.Message)") }

    # ---- Exposure --------------------------------------------------------
    $rdpDeny = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Cache $Cache
    $facts.RDPEnabled = if ($null -ne $rdpDeny) { $rdpDeny -eq 0 } else { $null }
    $nla = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Cache $Cache
    $facts.RDPNLARequired = if ($null -ne $nla) { $nla -eq 1 } else { $null }

    $smb1 = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Cache $Cache
    # Absent value means OS default: disabled on modern builds
    $facts.SMB1Enabled = if ($null -ne $smb1) { $smb1 -eq 1 } else { $false }
    $smbSign = Get-HFRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Cache $Cache
    $facts.SMBSigningRequired = if ($null -ne $smbSign) { $smbSign -eq 1 } else { $null }

    $facts.FirewallProfiles = $null
    try {
        if (Get-Command 'Get-NetFirewallProfile' -ErrorAction SilentlyContinue) {
            $profiles = Get-NetFirewallProfile -ErrorAction Stop
            $facts.FirewallProfiles = @{}
            foreach ($p in $profiles) { $facts.FirewallProfiles[$p.Name] = [bool]$p.Enabled }
            $facts.RawFirewallProfiles = @($profiles)   # v6.5.0 phase 2
        }
    } catch { $errors.Add("Firewall: $($_.Exception.Message)") }

    $facts.ListeningTcpPorts = $null
    try {
        if (Get-Command 'Get-NetTCPConnection' -ErrorAction SilentlyContinue) {
            $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
            $facts.ListeningTcpPorts = @($listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
            $facts.ListeningTcpPortCount = $facts.ListeningTcpPorts.Count
        }
    } catch { $errors.Add("ListeningPorts: $($_.Exception.Message)") }

    $winrm = Get-HFServiceState -Name 'WinRM'
    $facts.WinRMPresent = ($null -ne $winrm)
    $facts.WinRMRunning = if ($winrm) { $winrm.Status -eq 'Running' } else { $false }

    # ---- Identity hygiene ------------------------------------------------
    $facts.LocalAdminCount = $null
    try {
        if (Get-Command 'Get-LocalGroupMember' -ErrorAction SilentlyContinue) {
            $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
            $facts.LocalAdminCount = $admins.Count
        }
    } catch { $errors.Add("LocalAdmins: $($_.Exception.Message)") }

    $facts.GuestAccountEnabled = $null
    try {
        if (Get-Command 'Get-LocalUser' -ErrorAction SilentlyContinue) {
            $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
            if ($guest) { $facts.GuestAccountEnabled = [bool]$guest.Enabled }
        }
    } catch { $errors.Add("Guest: $($_.Exception.Message)") }

    # LAPS: modern (Windows LAPS policy) and legacy (AdmPwd) indicators
    $lapsModern = Get-HFRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory' -Cache $Cache
    $lapsLegacy = Get-HFRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -Name 'AdmPwdEnabled' -Cache $Cache
    $facts.LAPSConfigured = (($null -ne $lapsModern) -or ($lapsLegacy -eq 1))

    # ---- Execution control ----------------------------------------------
    $appid = Get-HFServiceState -Name 'AppIDSvc'
    $facts.AppLockerServicePresent = ($null -ne $appid)
    $facts.AppLockerServiceRunning = if ($appid) { $appid.Status -eq 'Running' } else { $false }

    $sbl = Get-HFRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Cache $Cache
    $facts.PSScriptBlockLogging = if ($null -ne $sbl) { $sbl -eq 1 } else { $false }
    try {
        $facts.PSExecutionPolicy = "$(Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop)"
    } catch {
        $facts.PSExecutionPolicy = $null
        $errors.Add("ExecutionPolicy: $($_.Exception.Message)")
    }

    $facts.PSv2EngineAvailable = $null
    try {
        if (Get-Command 'Get-WindowsOptionalFeature' -ErrorAction SilentlyContinue) {
            $v2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop
            if ($v2) { $facts.PSv2EngineAvailable = ($v2.State -eq 'Enabled') }
        }
    } catch { $errors.Add("PSv2: $($_.Exception.Message)") }

    # ---- Servicing -------------------------------------------------------
    $wu = Get-HFServiceState -Name 'wuauserv'
    $facts.WindowsUpdateServicePresent = ($null -ne $wu)
    $facts.WindowsUpdateServiceDisabled = if ($wu) { $wu.StartType -eq 'Disabled' } else { $null }

    $facts.PendingReboot = $null
    try {
        $cbsPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop
        $wuPending  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop
        $facts.PendingReboot = ($cbsPending -or $wuPending)
    } catch { $errors.Add("PendingReboot: $($_.Exception.Message)") }

    # ---- Meta ------------------------------------------------------------
    $facts.Meta = @{
        GeneratedAt    = $started.ToString('yyyy-MM-dd HH:mm:ss')
        ElapsedSeconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 3)
        FactCount      = ($facts.Keys | Where-Object { $_ -ne 'Meta' }).Count
        Errors         = $errors
        Version        = '6.6.0'
    }

    return $facts
}
