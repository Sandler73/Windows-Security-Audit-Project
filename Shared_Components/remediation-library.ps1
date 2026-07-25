# remediation-library.ps1
# Remediation library for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Per-topic remediation entries: apply command, verification, impact
    profile, and rollback-capture specification.

.DESCRIPTION
    Parity equivalent of the Linux remediation_library component (single OS
    family, so far smaller than the 3,229-line multi-family original). Builds
    on canonical-remediations.ps1: every canonical topic gains a library entry
    with:

    - Apply           the canonical command (sourced from the topic table --
                      the library never defines a second fix form)
    - Verify          a guarded scriptblock that reads the setting back and
                      returns $true (applied), $false (not applied), or $null
                      (unverifiable on this host)
    - Impact          one of the impact profiles (see below)
    - RequiresReboot  whether full effect needs a restart
    - RollbackCapture array of capture specs consumed by the rollback
                      generator (v6.4 item 4): registry_value, service_state,
                      security_policy, audit_policy, mp_preference,
                      smb_server_config, windows_feature, manual
    - Prerequisite    operator note that MUST be satisfied before applying
                      (e.g. BitLocker recovery-key backup)

    Impact profiles (ascending disruption, mirroring the Linux tiers):
        None, RestartService, RequireReboot, BreakSessions, BreakNetwork,
        BreakBoot

    EXECUTION BOUNDARY (deliberate): this component contains NO execution
    path. New-RemediationPlan produces an ordered, impact-annotated plan;
    applying it is reserved for the orchestrator's gated remediation flow
    once the rollback generator exists, because capture-before-apply is a
    hard rule of this framework. Verification (read-only) is the only thing
    this component runs.

.EXAMPLE
    . .\shared_components\canonical-remediations.ps1
    . .\shared_components\remediation-library.ps1
    (Get-RemediationEntry -Topic SmbSigningServer).Impact     # BreakSessions
    Test-RemediationApplied -Topic GuestAccount               # $true/$false/$null

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: canonical-remediations.ps1 (topic table); degrades to an
    empty library with a warning if absent
    Security: read-only verification only; no state modification
    Version: 6.6.0
#>

# Impact profile constants and severity ranking
$script:IMPACT_NONE            = 'None'
$script:IMPACT_RESTART_SERVICE = 'RestartService'
$script:IMPACT_REQUIRE_REBOOT  = 'RequireReboot'
$script:IMPACT_BREAK_SESSIONS  = 'BreakSessions'
$script:IMPACT_BREAK_NETWORK   = 'BreakNetwork'
$script:IMPACT_BREAK_BOOT      = 'BreakBoot'
$script:ImpactRank = @{
    'None' = 0; 'RestartService' = 1; 'RequireReboot' = 2
    'BreakSessions' = 3; 'BreakNetwork' = 4; 'BreakBoot' = 5
}

# ============================================================================
# Verification helpers (guarded, read-only)
# ============================================================================
function Test-RegValueEquals {
    param([string]$Path, [string]$Name, $Expected)
    try {
        $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return ($v -eq $Expected)
    } catch { return $false }
}

function Test-ServiceRunningAuto {
    param([string]$Name)
    try {
        $s = Get-Service -Name $Name -ErrorAction Stop
        if (-not $s) { return $false }
        $auto = $true
        try { $auto = ("$($s.StartType)" -eq 'Automatic') } catch { $auto = $null }
        if ($s.Status -eq 'Running' -and $auto) { return $true }
        return $false
    } catch { return $false }
}

# ============================================================================
# Library entries. Keys MUST be canonical topic ids; Apply text is resolved
# from the canonical table at load time (single source of truth).
# ============================================================================
$script:RemediationEntries = [ordered]@{
    'SmbV1Protocol' = @{
        Impact = 'RequireReboot'; RequiresReboot = $true; Prerequisite = $null
        RollbackCapture = @(@{ Type='windows_feature'; Name='SMB1Protocol' })
        Verify = { try { $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop; return ("$($f.State)" -ne 'Enabled') } catch { return $null } }
    }
    'SmbSigningServer' = @{
        Impact = 'BreakSessions'; RequiresReboot = $false
        Prerequisite = 'Confirm no legacy SMB clients require unsigned sessions'
        RollbackCapture = @(@{ Type='smb_server_config'; Name='RequireSecuritySignature' })
        Verify = { try { return [bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch { return $null } }
    }
    'NtlmCompatibility' = @{
        Impact = 'BreakSessions'; RequiresReboot = $false
        Prerequisite = 'Inventory NTLMv1/LM dependencies via the NTLM Operational log first'
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Expected 5 }
    }
    'NtlmV1SsoBlock' = @{
        Impact = 'BreakSessions'; RequiresReboot = $false
        Prerequisite = 'Review Event ID 4024 audit hits before enforcing'
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='BlockNtlmv1SSO' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'BlockNtlmv1SSO' -Expected 1 }
    }
    'WDigestCredentialCaching' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Expected 0 }
    }
    'LsaProtection' = @{
        Impact = 'RequireReboot'; RequiresReboot = $true
        Prerequisite = 'Verify third-party LSA plugins are signed/compatible before enabling PPL'
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RunAsPPL' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Expected 1 }
    }
    'RestrictAnonymous' = @{
        Impact = 'BreakSessions'; RequiresReboot = $false
        Prerequisite = 'Confirm no legacy applications depend on anonymous enumeration'
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Expected 1 }
    }
    'RdpNetworkLevelAuth' = @{
        Impact = 'BreakSessions'; RequiresReboot = $false
        Prerequisite = 'Confirm all RDP clients support NLA (CredSSP)'
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name='UserAuthentication' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Expected 1 }
    }
    'UacEnableLua' = @{
        Impact = 'RequireReboot'; RequiresReboot = $true; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Expected 1 }
    }
    'UacAdminConsentPrompt' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Expected 2 }
    }
    'GuestAccount' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='local_user_enabled'; Name='Guest' })
        Verify = { try { $g = Get-LocalUser -Name Guest -ErrorAction Stop; return (-not $g.Enabled) } catch { return $null } }
    }
    'PasswordMinLength' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='security_policy'; Area='SECURITYPOLICY' })
        Verify = { try { $out = & net accounts 2>$null; foreach ($l in $out) { if ($l -match 'Minimum password length\s*:?\s*(\d+)') { return ([int]$Matches[1] -ge 14) } }; return $null } catch { return $null } }
    }
    'PasswordHistory' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='security_policy'; Area='SECURITYPOLICY' })
        Verify = { try { $out = & net accounts 2>$null; foreach ($l in $out) { if ($l -match 'password history\s*:?\s*(\d+)') { return ([int]$Matches[1] -ge 24) } }; return $null } catch { return $null } }
    }
    'AccountLockoutThreshold' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='security_policy'; Area='SECURITYPOLICY' })
        Verify = { try { $out = & net accounts 2>$null; foreach ($l in $out) { if ($l -match 'Lockout threshold\s*:?\s*(\d+|Never)') { if ($Matches[1] -eq 'Never') { return $false }; return ([int]$Matches[1] -le 5 -and [int]$Matches[1] -ge 1) } }; return $null } catch { return $null } }
    }
    'SecurityEventLogSize' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='MaxSize' }, @{ Type='eventlog_size'; LogName='Security' })
        Verify = { try { $l = Get-WinEvent -ListLog 'Security' -ErrorAction Stop; return ($l.MaximumSizeInBytes -ge 1GB) } catch { return $null } }
    }
    'PowerShellScriptBlockLogging' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Expected 1 }
    }
    'DefenderRealTimeProtection' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='mp_preference'; Name='DisableRealtimeMonitoring' })
        Verify = { try { return (-not (Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring) } catch { return $null } }
    }
    'DefenderSignatures' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @()  # signature updates are not rolled back
        Verify = { try { return ((Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureAge -le 3) } catch { return $null } }
    }
    'DefenderNetworkProtection' = @{
        Impact = 'None'; RequiresReboot = $false
        Prerequisite = 'Network Protection may block flagged destinations; review exclusion process'
        RollbackCapture = @(@{ Type='mp_preference'; Name='EnableNetworkProtection' })
        Verify = { try { return ((Get-MpPreference -ErrorAction Stop).EnableNetworkProtection -eq 1) } catch { return $null } }
    }
    'DefenderControlledFolderAccess' = @{
        Impact = 'BreakSessions'; RequiresReboot = $false
        Prerequisite = 'CFA can block legitimate apps writing to protected folders; stage in Audit first'
        RollbackCapture = @(@{ Type='mp_preference'; Name='EnableControlledFolderAccess' })
        Verify = { try { return ((Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess -eq 1) } catch { return $null } }
    }
    'AutorunDisable' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Expected 255 }
    }
    'InactivityLock' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='InactivityTimeoutSecs' })
        Verify = { try { $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction Stop).InactivityTimeoutSecs; return ($v -ge 1 -and $v -le 900) } catch { return $false } }
    }
    'BitLockerSystemDrive' = @{
        Impact = 'BreakBoot'; RequiresReboot = $true
        Prerequisite = 'MANDATORY: back up the recovery key BEFORE enabling; loss of key after enablement means permanent data loss on boot failure'
        RollbackCapture = @(@{ Type='manual'; Note='Rollback is Disable-BitLocker (decryption); capture recovery key and encryption status before applying' })
        Verify = { try { if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { return $null }; $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; return ("$($v.ProtectionStatus)" -eq 'On') } catch { return $null } }
    }
    'AuditPolicyLogon' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='audit_policy' })
        Verify = { try { $out = & auditpol /get /subcategory:Logon 2>$null; foreach ($l in $out) { if ($l -match 'Logon\s+Success and Failure') { return $true } }; return $false } catch { return $null } }
    }
    'AuditPolicyChange' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='audit_policy' })
        Verify = { try { $out = & auditpol /get /subcategory:"Audit Policy Change" 2>$null; foreach ($l in $out) { if ($l -match 'Audit Policy Change\s+Success and Failure') { return $true } }; return $false } catch { return $null } }
    }
    'TimeService' = @{
        Impact = 'RestartService'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='service_state'; Name='W32Time' })
        Verify = { Test-ServiceRunningAuto -Name 'W32Time' }
    }
    'EventLogService' = @{
        Impact = 'RestartService'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='service_state'; Name='EventLog' })
        Verify = { Test-ServiceRunningAuto -Name 'EventLog' }
    }
    'AutomaticUpdates' = @{
        Impact = 'None'; RequiresReboot = $false; Prerequisite = $null
        RollbackCapture = @(@{ Type='registry_value'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoUpdate' })
        Verify = { Test-RegValueEquals -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Expected 0 }
    }
}

# Resolve Apply text from the canonical table at load (single source of truth)
if (Get-Command 'Get-CanonicalRemediation' -ErrorAction SilentlyContinue) {
    foreach ($topicKey in @($script:RemediationEntries.Keys)) {
        $script:RemediationEntries[$topicKey]['Apply'] = Get-CanonicalRemediation -Topic $topicKey
        $script:RemediationEntries[$topicKey]['Topic'] = $topicKey
    }
} else {
    Write-Warning "canonical-remediations.ps1 not loaded; remediation library has no Apply commands"
    foreach ($topicKey in @($script:RemediationEntries.Keys)) {
        $script:RemediationEntries[$topicKey]['Apply'] = $null
        $script:RemediationEntries[$topicKey]['Topic'] = $topicKey
    }
}

# ============================================================================
# API
# ============================================================================
function Get-RemediationEntry {
    <#
    .SYNOPSIS
        One library entry by topic id, or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Topic)
    if ($script:RemediationEntries.Contains($Topic)) { return $script:RemediationEntries[$Topic] }
    return $null
}

function Get-RemediationEntries {
    <#
    .SYNOPSIS
        The full entry table (topic id -> entry).
    #>
    return $script:RemediationEntries
}

function Get-ImpactRank {
    <#
    .SYNOPSIS
        Numeric severity rank of an impact profile (unknown -> highest,
        conservative).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Impact)
    if ($script:ImpactRank.ContainsKey($Impact)) { return $script:ImpactRank[$Impact] }
    return 5
}

function Test-RemediationApplied {
    <#
    .SYNOPSIS
        Run a topic's read-only verification. Returns $true / $false / $null
        (unverifiable). Never throws.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Topic)
    $entry = Get-RemediationEntry -Topic $Topic
    if (-not $entry -or -not $entry.Verify) { return $null }
    try { return (& $entry.Verify) } catch { return $null }
}

function New-RemediationPlan {
    <#
    .SYNOPSIS
        Build an ordered, impact-annotated plan for a topic set. The plan is
        DATA for the gated execution flow (post-rollback-generator); nothing
        is applied here. Topics are ordered lowest-impact first so an operator
        aborting mid-plan has taken the least disruptive steps.
    .OUTPUTS
        PSCustomObject: Steps (ordered), MaxImpact, RequiresReboot,
        Prerequisites, UnknownTopics.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]]$Topics)
    $steps = [System.Collections.Generic.List[object]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    foreach ($topic in ($Topics | Select-Object -Unique)) {
        $entry = Get-RemediationEntry -Topic $topic
        if (-not $entry) { $unknown.Add($topic); continue }
        $steps.Add([PSCustomObject]@{
            Topic           = $topic
            Apply           = $entry.Apply
            Impact          = $entry.Impact
            ImpactRank      = (Get-ImpactRank -Impact $entry.Impact)
            RequiresReboot  = [bool]$entry.RequiresReboot
            Prerequisite    = $entry.Prerequisite
            RollbackCapture = @($entry.RollbackCapture)
        })
    }
    $ordered = @($steps | Sort-Object ImpactRank, Topic)
    $maxImpact = 'None'
    foreach ($s in $ordered) { if ($s.ImpactRank -gt (Get-ImpactRank -Impact $maxImpact)) { $maxImpact = $s.Impact } }
    return [PSCustomObject]@{
        Steps          = $ordered
        MaxImpact      = $maxImpact
        RequiresReboot = [bool](@($ordered | Where-Object { $_.RequiresReboot }).Count -gt 0)
        Prerequisites  = @($ordered | Where-Object { $_.Prerequisite } | ForEach-Object { "$($_.Topic): $($_.Prerequisite)" })
        UnknownTopics  = @($unknown)
    }
}

# Backwards-compatible alias (see note in attack-surface.ps1).
Set-Alias -Name Build-RemediationPlan -Value New-RemediationPlan -Scope Script -Force
