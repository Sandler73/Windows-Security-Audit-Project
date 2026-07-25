# shared-assessments.ps1
# Shared host-wide assessments for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Expensive host-wide collections computed once per run and shared with all
    modules.

.DESCRIPTION
    Implements the parity equivalent of the Linux project's shared_assessments
    component, with the assessment set grounded in this codebase's MEASURED
    duplication rather than the Unix-specific originals:

    - LocalUsers           (duplicated across 13 modules)
    - LocalAdministrators  (duplicated across 11 modules)
    - InstalledHotfixes    (duplicated across 5 modules; includes derived
                            latest-hotfix age in days)
    - ListeningTcpPorts    (duplicated across 3 modules; port + owning PID)

    Each assessment returns a uniform record:
        Name        assessment identifier
        Items       collected items, capped at 25 (see Truncated)
        Count       full count before capping
        Truncated   $true when Items was capped
        CollectedAt timestamp
        Error       $null on success, otherwise the failure message
        Source      the cmdlet/API used

    Execution model: the orchestrator pre-warms all assessments once after the
    HostFacts warmup (Initialize-SharedAssessments), so parallel module
    execution reads a fully-populated $SharedData.Assessments with no
    concurrent-write hazard. When a module runs standalone (no SharedData),
    Get-SharedAssessment memoizes at component scope instead. Call-site
    migration across modules follows in a later pass (memoize-first, L-A27).

.EXAMPLE
    . .\shared_components\shared-assessments.ps1
    $sd = @{}
    Initialize-SharedAssessments -SharedData $sd
    (Get-SharedAssessment -Name LocalAdministrators -SharedData $sd).Count

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: none (standalone-safe; all collectors availability-guarded)
    Security: read-only collection; no state modification
    Version: 6.6.0
#>

$script:AssessmentItemCap = 25
$script:AssessmentMemo = @{}

# ============================================================================
# Assessment definitions (collector scriptblocks; each returns an item array
# or throws -- the wrapper converts failures into Error records)
# ============================================================================
$script:AssessmentDefinitions = [ordered]@{
    'LocalUsers' = @{
        Source    = 'Get-LocalUser'
        Collector = {
            if (-not (Get-Command 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
                throw "Get-LocalUser unavailable on this host"
            }
            @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name                 = $_.Name
                    Enabled              = $_.Enabled
                    PasswordRequired     = $_.PasswordRequired
                    PasswordNeverExpires = ($null -eq $_.PasswordExpires -and $_.Enabled)
                    LastLogon            = $_.LastLogon
                    SID                  = "$($_.SID)"
                }
            })
        }
    }
    'LocalAdministrators' = @{
        Source    = 'Get-LocalGroupMember'
        Collector = {
            if (-not (Get-Command 'Get-LocalGroupMember' -ErrorAction SilentlyContinue)) {
                throw "Get-LocalGroupMember unavailable on this host"
            }
            @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name            = $_.Name
                    ObjectClass     = $_.ObjectClass
                    PrincipalSource = "$($_.PrincipalSource)"
                    SID             = "$($_.SID)"
                }
            })
        }
    }
    'InstalledHotfixes' = @{
        Source    = 'Get-HotFix'
        Collector = {
            if (-not (Get-Command 'Get-HotFix' -ErrorAction SilentlyContinue)) {
                throw "Get-HotFix unavailable on this host"
            }
            @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | ForEach-Object {
                [PSCustomObject]@{
                    HotFixID    = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = $_.InstalledOn
                }
            })
        }
    }
    'ListeningTcpPorts' = @{
        Source    = 'Get-NetTCPConnection'
        Collector = {
            if (-not (Get-Command 'Get-NetTCPConnection' -ErrorAction SilentlyContinue)) {
                throw "Get-NetTCPConnection unavailable on this host"
            }
            @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Sort-Object LocalPort -Unique | ForEach-Object {
                [PSCustomObject]@{
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    OwningProcess = $_.OwningProcess
                }
            })
        }
    }
}

# ============================================================================
# Core API
# ============================================================================
function New-AssessmentRecord {
    <#
    .SYNOPSIS
        Build the uniform assessment record from a collector outcome.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [array]$Items = @(),
        [string]$Source = '',
        [string]$ErrorMessage = $null
    )
    $count = @($Items).Count
    $truncated = $count -gt $script:AssessmentItemCap
    $kept = if ($truncated) { @($Items | Select-Object -First $script:AssessmentItemCap) } else { @($Items) }
    return [PSCustomObject]@{
        Name        = $Name
        Items       = $kept
        Count       = $count
        Truncated   = $truncated
        CollectedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Error       = $ErrorMessage
        Source      = $Source
    }
}

function Invoke-AssessmentCollection {
    <#
    .SYNOPSIS
        Run one assessment definition; failures become Error records, never
        throws (WSA-F1 discipline: no silent loss, no crash propagation).
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    $def = $script:AssessmentDefinitions[$Name]
    if (-not $def) {
        return New-AssessmentRecord -Name $Name -ErrorMessage "Unknown assessment '$Name'"
    }
    try {
        $items = & $def.Collector
        return New-AssessmentRecord -Name $Name -Items @($items) -Source $def.Source
    } catch {
        return New-AssessmentRecord -Name $Name -Source $def.Source -ErrorMessage "$($_.Exception.Message)"
    }
}

function Initialize-SharedAssessments {
    <#
    .SYNOPSIS
        Pre-warm every assessment into $SharedData.Assessments (orchestrator
        call site: once, after HostFacts warmup, before module dispatch).
    .OUTPUTS
        Hashtable of assessment records (also attached to SharedData).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$SharedData)
    $bag = @{}
    foreach ($name in $script:AssessmentDefinitions.Keys) {
        $bag[$name] = Invoke-AssessmentCollection -Name $name
    }
    $SharedData['Assessments'] = $bag
    return $bag
}

function Get-SharedAssessment {
    <#
    .SYNOPSIS
        Retrieve one assessment: SharedData first, component memo fallback
        (standalone mode). Never returns $null; unknown names yield an Error
        record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [hashtable]$SharedData = $null
    )
    if ($SharedData -and $SharedData.ContainsKey('Assessments') -and $SharedData.Assessments.ContainsKey($Name)) {
        return $SharedData.Assessments[$Name]
    }
    if (-not $script:AssessmentMemo.ContainsKey($Name)) {
        $script:AssessmentMemo[$Name] = Invoke-AssessmentCollection -Name $Name
    }
    return $script:AssessmentMemo[$Name]
}

function Get-SharedAssessmentNames {
    <#
    .SYNOPSIS
        Registered assessment names in declaration order.
    #>
    return @($script:AssessmentDefinitions.Keys)
}

function Get-LatestHotfixAgeDays {
    <#
    .SYNOPSIS
        Derived signal: age in days of the most recent installed hotfix, or
        $null when unknowable (collection error or no dated entries).
    #>
    [CmdletBinding()]
    param([hashtable]$SharedData = $null)
    $hf = Get-SharedAssessment -Name 'InstalledHotfixes' -SharedData $SharedData
    if ($hf.Error -or $hf.Count -eq 0) { return $null }
    $dated = @($hf.Items | Where-Object { $_.InstalledOn }) | Sort-Object InstalledOn -Descending
    if ($dated.Count -eq 0) { return $null }
    return [Math]::Round(((Get-Date) - [datetime]$dated[0].InstalledOn).TotalDays, 1)
}
