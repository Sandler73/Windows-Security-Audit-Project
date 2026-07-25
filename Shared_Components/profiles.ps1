# profiles.ps1
# Audit profiles for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Role-based audit profiles: named module sets keyed to host role.

.DESCRIPTION
    Implements parity (Linux profiles.py equivalent). A profile names a
    curated module set for a host role so operators run the right frameworks
    without hand-listing modules. Six built-in profiles:

    - Workstation       : end-user client posture (baselines, EDR, platform)
    - MemberServer      : domain-joined server posture
    - DomainController  : DC-focused posture (identity/AD-heavy frameworks)
    - ServerCore        : reduced-surface Server Core posture
    - Minimal           : fastest meaningful pass (core + primary baseline)
    - Full              : all 16 modules (equivalent to -Modules All)

    Resolution rules (enforced by the orchestrator):
    - Explicit -Modules always wins over -Profile (operator override).
    - -Profile selects that profile's module set.
    - With neither, HostFacts can suggest a profile; the suggestion is
      informational only and never changes behavior silently.

.EXAMPLE
    . .\shared_components\profiles.ps1
    Get-AuditProfileNames
    (Get-AuditProfile -Name DomainController).Modules

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: none; Get-SuggestedProfile consumes a HostFacts hashtable if
    provided (shared_components/host-facts.ps1) but degrades without it
    Security: read-only; no state modification
    Version: 6.6.0
#>

$script:AuditProfiles = [ordered]@{
    'Workstation' = @{
        Description = 'End-user client posture: platform security, baselines, endpoint protection, primary compliance frameworks for client fleets'
        Modules     = @('Core','MS','MS-DefenderATP','CIS','NIST','STIG','ACSC','CISA','NSA')
    }
    'MemberServer' = @{
        Description = 'Domain-joined server posture: server baselines plus the frameworks auditors most commonly scope to member servers'
        Modules     = @('Core','MS','MS-DefenderATP','CIS','NIST','STIG','CISA','NSA','ISO27001','SOC2')
    }
    'DomainController' = @{
        Description = 'Domain controller posture: identity-critical hardening and the frameworks with DC-specific requirements'
        Modules     = @('Core','MS','MS-DefenderATP','CIS','NIST','STIG','NSA','CISA')
    }
    'ServerCore' = @{
        Description = 'Server Core reduced-surface posture: platform and baseline coverage appropriate to headless servers'
        Modules     = @('Core','MS','CIS','NIST','STIG','NSA')
    }
    'Minimal' = @{
        Description = 'Fastest meaningful pass: core baseline plus the Microsoft baseline only'
        Modules     = @('Core','MS')
    }
    'Full' = @{
        Description = 'Every module (equivalent to -Modules All)'
        Modules     = @('ACSC','CIS','CISA','CMMC','Core','ENISA','GDPR','HIPAA','ISO27001','MS','MS-DefenderATP','NIST','NSA','PCI-DSS','SOC2','STIG')
    }
}

function Get-AuditProfileNames {
    <#
    .SYNOPSIS
        Return the built-in profile names in declaration order.
    #>
    return @($script:AuditProfiles.Keys)
}

function Get-AuditProfile {
    <#
    .SYNOPSIS
        Return one profile definition (Description + Modules) or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Name)
    $match = $script:AuditProfiles.Keys | Where-Object { $_ -ieq $Name } | Select-Object -First 1
    if ($match) { return $script:AuditProfiles[$match] }
    return $null
}

function Show-AuditProfiles {
    <#
    .SYNOPSIS
        Print the profile catalog for -ListProfiles.
    #>
    Write-Host ""
    Write-Host "Available audit profiles:" -ForegroundColor Cyan
    foreach ($name in $script:AuditProfiles.Keys) {
        $p = $script:AuditProfiles[$name]
        Write-Host ("  {0,-18} {1}" -f $name, $p.Description) -ForegroundColor White
        Write-Host ("  {0,-18} Modules: {1}" -f '', ($p.Modules -join ', ')) -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Usage: -Profile <name>   (explicit -Modules overrides a profile)" -ForegroundColor Cyan
}

function Get-SuggestedProfile {
    <#
    .SYNOPSIS
        Suggest a profile from HostFacts. Informational only; never applied
        silently.
    #>
    [CmdletBinding()]
    param([hashtable]$HostFacts = $null)
    if (-not $HostFacts) { return $null }
    if ($HostFacts.IsDomainController -eq $true) { return 'DomainController' }
    if ($HostFacts.IsServerCore -eq $true)       { return 'ServerCore' }
    if ($HostFacts.IsServer -eq $true)           { return 'MemberServer' }
    if ($HostFacts.IsServer -eq $false)          { return 'Workstation' }
    return $null
}
