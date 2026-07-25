# remediation-bundles.ps1
# Named remediation bundles with impact-tiered confirmation for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Named bundles of remediation topics with aggregate impact and
    confirmation-tier requirements.

.DESCRIPTION
    Parity equivalent of the Linux remediation_bundles component. A bundle
    groups related topics into an operator-facing hardening unit (e.g.
    'CredentialHardening'). Each bundle derives its aggregate impact from the
    library entries (maximum member impact) and maps to a confirmation tier
    that the gated execution flow must enforce ON TOP of the framework's
    existing dual-confirmation remediation gate -- tiers add requirements,
    they never relax the base gate:

        Tier 1 (Standard)  impact None/RestartService: base dual confirmation
        Tier 2 (Elevated)  RequireReboot/BreakSessions: base gate + explicit
                           per-bundle acknowledgment listing the disruption
        Tier 3 (Critical)  BreakNetwork/BreakBoot: base gate + typed
                           confirmation phrase + prerequisite checklist
                           acknowledgment (e.g. BitLocker recovery-key backup)

    EXECUTION BOUNDARY: like the library, this component is data + plan
    building only. Nothing here applies changes; execution arrives with the
    rollback generator (capture-before-apply rule).

.EXAMPLE
    . .\shared_components\canonical-remediations.ps1
    . .\shared_components\remediation-library.ps1
    . .\shared_components\remediation-bundles.ps1
    Get-RemediationBundleNames
    (Get-BundlePlan -Name CredentialHardening).ConfirmationTier

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: remediation-library.ps1 (impact resolution); bundles degrade
    to topic lists with conservative Tier 3 if the library is absent
    Security: read-only; no state modification
    Version: 6.6.0
#>

$script:RemediationBundles = [ordered]@{
    'CredentialHardening' = @{
        Description = 'Credential theft resistance: LSASS protection, WDigest plaintext caching off, NTLMv1 refusal and SSO blocking, anonymous enumeration off'
        Topics      = @('LsaProtection','WDigestCredentialCaching','NtlmCompatibility','NtlmV1SsoBlock','RestrictAnonymous')
    }
    'SmbHardening' = @{
        Description = 'SMB attack-surface reduction: SMBv1 removal and mandatory server signing'
        Topics      = @('SmbV1Protocol','SmbSigningServer')
    }
    'DefenderBaseline' = @{
        Description = 'Microsoft Defender operating baseline: real-time protection, current signatures, network protection, controlled folder access'
        Topics      = @('DefenderRealTimeProtection','DefenderSignatures','DefenderNetworkProtection','DefenderControlledFolderAccess')
    }
    'AuditVisibility' = @{
        Description = 'Detection and evidence: script block logging, logon and policy-change auditing, adequate security log sizing, event log service health'
        Topics      = @('PowerShellScriptBlockLogging','AuditPolicyLogon','AuditPolicyChange','SecurityEventLogSize','EventLogService')
    }
    'AccountPolicy' = @{
        Description = 'Account and session policy: password length and history, lockout threshold, Guest disablement, inactivity lock'
        Topics      = @('PasswordMinLength','PasswordHistory','AccountLockoutThreshold','GuestAccount','InactivityLock')
    }
    'UacBaseline' = @{
        Description = 'Elevation boundary: UAC enabled with secure-desktop admin consent prompting'
        Topics      = @('UacEnableLua','UacAdminConsentPrompt')
    }
    'RemoteAccessHardening' = @{
        Description = 'Remote access: RDP Network Level Authentication'
        Topics      = @('RdpNetworkLevelAuth')
    }
    'PatchAndTime' = @{
        Description = 'Update and time hygiene: automatic updates on, time service healthy'
        Topics      = @('AutomaticUpdates','TimeService')
    }
    'MediaAndAutorun' = @{
        Description = 'Removable-media execution: AutoRun/AutoPlay disabled on all drive types'
        Topics      = @('AutorunDisable')
    }
    'EncryptionAtRest' = @{
        Description = 'Data at rest: BitLocker system-drive encryption (RECOVERY KEY BACKUP IS MANDATORY FIRST)'
        Topics      = @('BitLockerSystemDrive')
    }
}

# ============================================================================
# API
# ============================================================================

# ============================================================================
# Deprecated v6.1 bundle-name aliases (option B migration). The v6.1
# -RemediationBundle ValidateSet shipped five pattern-based bundle names.
# They now map onto the v6.4 topic-based bundles so existing command lines
# keep working while emitting a deprecation notice. Where a v6.1 bundle spans
# multiple v6.4 bundles, the alias resolves to the ordered union of their
# topics via a synthetic bundle.
# ============================================================================
$script:V61BundleAliases = [ordered]@{
    'DisableLegacyProtocols' = @('SmbHardening')
    'HardenAuthentication'   = @('CredentialHardening','UacBaseline')
    'EnableAuditLogging'     = @('AuditVisibility')
    'LockDownRDP'            = @('RemoteAccessHardening')
    'EssentialEightLevel1'   = @('PatchAndTime','EncryptionAtRest','DefenderBaseline','MediaAndAutorun')
}

function Test-IsV61BundleAlias {
    <#
    .SYNOPSIS
        $true when the name is a deprecated v6.1 bundle alias.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    return [bool]($script:V61BundleAliases.Keys | Where-Object { $_ -ieq $Name })
}

function Resolve-BundleName {
    <#
    .SYNOPSIS
        Resolve a bundle name (v6.4 canonical OR v6.1 alias) to the set of
        v6.4 bundle names it maps to. Returns @() for unknown names.
        Emits a one-time deprecation warning for aliases unless -Quiet.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name, [switch]$Quiet)
    $canonical = $script:RemediationBundles.Keys | Where-Object { $_ -ieq $Name } | Select-Object -First 1
    if ($canonical) { return @($canonical) }
    $aliasKey = $script:V61BundleAliases.Keys | Where-Object { $_ -ieq $Name } | Select-Object -First 1
    if ($aliasKey) {
        if (-not $Quiet) {
            Write-Warning "Bundle name '$aliasKey' is a deprecated v6.1 alias; it now maps to the v6.4 bundle(s): $($script:V61BundleAliases[$aliasKey] -join ', '). Prefer the v6.4 name(s) going forward."
        }
        return @($script:V61BundleAliases[$aliasKey])
    }
    return @()
}

function Get-ResolvedBundleTopics {
    <#
    .SYNOPSIS
        Ordered, de-duplicated union of topics for a bundle name (canonical or
        alias). Empty for unknown names.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name, [switch]$Quiet)
    $bundleNames = Resolve-BundleName -Name $Name -Quiet:$Quiet
    $topics = [System.Collections.Generic.List[string]]::new()
    foreach ($bn in $bundleNames) {
        $b = Get-RemediationBundle -Name $bn
        if ($b) { foreach ($tp in $b.Topics) { if (-not $topics.Contains($tp)) { $topics.Add($tp) } } }
    }
    return @($topics)
}

function Get-AllBundleNames {
    <#
    .SYNOPSIS
        All accepted -RemediationBundle values: v6.4 canonical names plus
        deprecated v6.1 aliases (for the parameter's dynamic validation and
        help text).
    #>
    return @(@($script:RemediationBundles.Keys) + @($script:V61BundleAliases.Keys))
}

function Get-RemediationBundleNames {
    <#
    .SYNOPSIS
        Bundle names in declaration order.
    #>
    return @($script:RemediationBundles.Keys)
}

function Get-RemediationBundle {
    <#
    .SYNOPSIS
        One bundle definition (Description + Topics) or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    $match = $script:RemediationBundles.Keys | Where-Object { $_ -ieq $Name } | Select-Object -First 1
    if ($match) { return $script:RemediationBundles[$match] }
    return $null
}

function Get-ConfirmationTier {
    <#
    .SYNOPSIS
        Map an impact profile to its confirmation tier (1..3). Unknown
        impacts map to Tier 3 (conservative).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Impact)
    switch ($Impact) {
        'None'            { return 1 }
        'RestartService'  { return 1 }
        'RequireReboot'   { return 2 }
        'BreakSessions'   { return 2 }
        'BreakNetwork'    { return 3 }
        'BreakBoot'       { return 3 }
        default           { return 3 }
    }
}

function Get-BundlePlan {
    <#
    .SYNOPSIS
        Build the ordered remediation plan for a bundle, annotated with the
        bundle's aggregate impact and required confirmation tier. Data only;
        nothing is applied.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    $bundle = Get-RemediationBundle -Name $Name
    if (-not $bundle) { return $null }
    if (-not (Get-Command 'Build-RemediationPlan' -ErrorAction SilentlyContinue)) {
        # Library absent: degrade to a topic list at the most conservative tier
        return [PSCustomObject]@{
            Name             = $Name
            Description      = $bundle.Description
            Steps            = @($bundle.Topics | ForEach-Object { [PSCustomObject]@{ Topic = $_; Apply = $null; Impact = 'Unknown'; ImpactRank = 5; RequiresReboot = $null; Prerequisite = $null; RollbackCapture = @() } })
            MaxImpact        = 'Unknown'
            RequiresReboot   = $null
            Prerequisites    = @()
            UnknownTopics    = @()
            ConfirmationTier = 3
            LibraryAvailable = $false
        }
    }
    $plan = Build-RemediationPlan -Topics $bundle.Topics
    return [PSCustomObject]@{
        Name             = $Name
        Description      = $bundle.Description
        Steps            = $plan.Steps
        MaxImpact        = $plan.MaxImpact
        RequiresReboot   = $plan.RequiresReboot
        Prerequisites    = $plan.Prerequisites
        UnknownTopics    = $plan.UnknownTopics
        ConfirmationTier = (Get-ConfirmationTier -Impact $plan.MaxImpact)
        LibraryAvailable = $true
    }
}

function Show-RemediationBundles {
    <#
    .SYNOPSIS
        Print the bundle catalog with impact and tier annotations (for a
        future -ListBundles orchestrator switch).
    #>
    Write-Host ""
    Write-Host "Available remediation bundles:" -ForegroundColor Cyan
    foreach ($name in $script:RemediationBundles.Keys) {
        $plan = Get-BundlePlan -Name $name
        $tierLbl = switch ($plan.ConfirmationTier) { 1 { 'Standard' } 2 { 'Elevated' } 3 { 'CRITICAL' } }
        Write-Host ("  {0,-24} impact: {1,-14} tier: {2,-8} topics: {3}" -f $name, $plan.MaxImpact, $tierLbl, $plan.Steps.Count) -ForegroundColor White
        Write-Host ("  {0,-24} {1}" -f '', $script:RemediationBundles[$name].Description) -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Bundles are plan units; application requires the gated remediation flow with rollback capture." -ForegroundColor Cyan
}
