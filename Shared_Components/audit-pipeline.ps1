# audit-pipeline.ps1
# Composed post-execution pipeline for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Runs the post-execution phases as one composed pass and returns a single
    pipeline-result object with per-phase timing and run metadata.

.DESCRIPTION
    Parity equivalent of the Linux v3_pipeline component. The Windows
    orchestrator already implemented every individual phase as a discrete
    function (result validation at collection time, compliance scoring, risk
    priority, cross-framework correlation, compensating controls, baseline
    drift). What it lacked was composition: the phases ran as separate gated
    blocks that stashed their output into script-scope variables, with no
    single result object, no per-phase timing, and no machine-readable run
    summary.

    This component COMPOSES those existing functions; it does not reimplement
    any of them. Each phase is invoked through the same function the
    orchestrator called before, is guarded by the same availability check, and
    honours the same switch, so behaviour is unchanged. What is added is the
    surrounding structure:

      - a single PipelineResult carrying results, scores, enrichment output,
        drift, timings, timestamp and metadata
      - per-phase elapsed timing, so a slow phase is attributable
      - Get-PipelineSummary: a machine-readable payload suitable for CI, log
        shipping, or an automation gate
      - Show-PipelineSummary: the console rendering

    Phase order (mirrors the reference):
      1. Compliance scoring (per-module and overall)
      2. Risk priority enrichment
      3. Cross-framework correlation
      4. Compensating controls
      5. Baseline drift

    The run timestamp is fixed BEFORE the baseline phase, because the drift
    comparison embeds it. The reference component carries a comment recording
    that assigning it afterwards left every drift report with an empty
    timestamp; the same ordering is preserved here deliberately.

    Any phase whose underlying function is unavailable is skipped and recorded
    as skipped rather than failing the run. A phase that throws is recorded as
    errored and the pipeline continues, so one enrichment failure cannot cost
    an operator the entire audit.

.EXAMPLE
    . .\shared_components\audit-pipeline.ps1
    $outcome = Invoke-AuditPipeline -Results $allResults -ComplianceThreshold 80 `
                   -IncludeRiskPriority -AssetCriticality 9
    $outcome.PhaseTimings
    Get-PipelineSummary -Outcome $outcome | ConvertTo-Json -Depth 6

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: composes functions from audit-common.ps1 and the orchestrator
    (Get-ComplianceScore). Every call is availability-guarded, so the component
    degrades to recorded skips rather than failing.
    Security: read-only composition over existing results; no state modification
    Version: 6.6.0
#>

function New-PhaseRecord {
    <#
    .SYNOPSIS
        Build a uniform per-phase execution record.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Status,   # Completed | Skipped | Error
        [double]$ElapsedMs = 0.0,
        [string]$Detail = '',
        [string]$ErrorMessage = $null
    )
    return [PSCustomObject]@{
        Name         = $Name
        Status       = $Status
        ElapsedMs    = [Math]::Round($ElapsedMs, 1)
        Detail       = $Detail
        Error        = $ErrorMessage
    }
}

function Invoke-AuditPipeline {
    <#
    .SYNOPSIS
        Run the composed post-execution pipeline over collected results.
    .OUTPUTS
        PSCustomObject: Results, ComplianceScores, RiskScoredCount, Correlations,
        CompensatingControls, BaselineComparison, PhaseTimings, Timestamp,
        ElapsedSeconds, Metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][array]$Results,
        [double]$ComplianceThreshold = 70.0,
        [hashtable]$ComplianceScores = $null,
        [switch]$IncludeRiskPriority,
        [switch]$IncludeCorrelations,
        [switch]$IncludeCompensatingControls,
        [int]$AssetCriticality = 0,
        [string]$BaselinePath = '',
        [hashtable]$ExecutionInfo = @{},
        [hashtable]$HostFacts = $null
    )

    $pipelineStart = [System.Diagnostics.Stopwatch]::StartNew()
    $phases = [System.Collections.Generic.List[object]]::new()

    $outcome = [PSCustomObject]@{
        Results              = @($Results)
        ComplianceScores     = @{}
        RiskScoredCount      = 0
        Correlations         = @()
        CompensatingControls = @()
        BaselineComparison   = $null
        PhaseTimings         = @()
        Timestamp            = ''
        ElapsedSeconds       = 0.0
        Metadata             = @{}
    }

    # ---- Phase 1: Compliance scoring (per-module and overall) ----
    # If the caller already computed scores (the orchestrator does, upstream of
    # this call), reuse them rather than recomputing: recomputation would be
    # wasted work and could diverge from what the reports already display.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($ComplianceScores -and $ComplianceScores.Keys.Count -gt 0) {
        $outcome.ComplianceScores = $ComplianceScores
        $sw.Stop()
        $phases.Add((New-PhaseRecord -Name 'ComplianceScoring' -Status 'Completed' -ElapsedMs $sw.Elapsed.TotalMilliseconds -Detail "reused $($ComplianceScores.Keys.Count) upstream score set(s)"))
    }
    elseif (Get-Command 'Get-ComplianceScore' -ErrorAction SilentlyContinue) {
        try {
            $scores = @{}
            $groups = @{}
            foreach ($r in $Results) {
                $m = "$($r.Module)"
                if (-not $m) { $m = 'Unknown' }
                if (-not $groups.ContainsKey($m)) { $groups[$m] = [System.Collections.Generic.List[object]]::new() }
                $groups[$m].Add($r)
            }
            foreach ($m in $groups.Keys) {
                $scores[$m] = Get-ComplianceScore -ModuleName $m -Results @($groups[$m]) -Threshold $ComplianceThreshold
            }
            $scores['overall'] = Get-ComplianceScore -ModuleName 'overall' -Results @($Results) -Threshold $ComplianceThreshold
            $outcome.ComplianceScores = $scores
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'ComplianceScoring' -Status 'Completed' -ElapsedMs $sw.Elapsed.TotalMilliseconds -Detail "$($groups.Keys.Count) module(s) scored at threshold $ComplianceThreshold"))
        } catch {
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'ComplianceScoring' -Status 'Error' -ElapsedMs $sw.Elapsed.TotalMilliseconds -ErrorMessage "$($_.Exception.Message)"))
        }
    } else {
        $sw.Stop()
        $phases.Add((New-PhaseRecord -Name 'ComplianceScoring' -Status 'Skipped' -Detail 'Get-ComplianceScore unavailable'))
    }

    # ---- Phase 2: Risk priority enrichment ----
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($IncludeRiskPriority) {
        if (Get-Command 'Get-RiskPriorityScore' -ErrorAction SilentlyContinue) {
            try {
                $exposureCtx = @{
                    IsDomainController   = if (Get-Command Test-DomainControllerHost -ErrorAction SilentlyContinue) { Test-DomainControllerHost } else { $false }
                    IsInternetFacing     = if (Get-Command Test-InternetFacingHost -ErrorAction SilentlyContinue) { Test-InternetFacingHost } else { $false }
                    HasListeningServices = $true
                }
                if ($AssetCriticality -ge 1 -and $AssetCriticality -le 10) {
                    $exposureCtx['AssetCriticality'] = $AssetCriticality
                }
                $scored = 0
                foreach ($r in $Results) {
                    if (-not $r.PSObject.Properties['RiskPriority']) {
                        $score = Get-RiskPriorityScore -Result $r -ExposureContext $exposureCtx
                        Add-Member -InputObject $r -MemberType NoteProperty -Name 'RiskPriority' -Value $score -Force
                        $scored++
                    }
                }
                $outcome.RiskScoredCount = $scored
                $sw.Stop()
                $critLbl = if ($exposureCtx.ContainsKey('AssetCriticality')) { "asset criticality $AssetCriticality (operator-supplied)" } else { 'role-derived criticality' }
                $phases.Add((New-PhaseRecord -Name 'RiskPriority' -Status 'Completed' -ElapsedMs $sw.Elapsed.TotalMilliseconds -Detail "$scored finding(s) scored using $critLbl"))
            } catch {
                $sw.Stop()
                $phases.Add((New-PhaseRecord -Name 'RiskPriority' -Status 'Error' -ElapsedMs $sw.Elapsed.TotalMilliseconds -ErrorMessage "$($_.Exception.Message)"))
            }
        } else {
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'RiskPriority' -Status 'Skipped' -Detail 'Get-RiskPriorityScore unavailable'))
        }
    } else {
        $sw.Stop()
        $phases.Add((New-PhaseRecord -Name 'RiskPriority' -Status 'Skipped' -Detail 'not requested'))
    }

    # ---- Phase 3: Cross-framework correlation ----
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($IncludeCorrelations -and (Get-Command 'Find-CrossFrameworkCorrelations' -ErrorAction SilentlyContinue)) {
        try {
            $outcome.Correlations = @(Find-CrossFrameworkCorrelations -Results $Results)
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'Correlations' -Status 'Completed' -ElapsedMs $sw.Elapsed.TotalMilliseconds -Detail "$($outcome.Correlations.Count) correlation group(s)"))
        } catch {
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'Correlations' -Status 'Error' -ElapsedMs $sw.Elapsed.TotalMilliseconds -ErrorMessage "$($_.Exception.Message)"))
        }
    } else {
        $sw.Stop()
        $reason = if (-not $IncludeCorrelations) { 'not requested' } else { 'Find-CrossFrameworkCorrelations unavailable' }
        $phases.Add((New-PhaseRecord -Name 'Correlations' -Status 'Skipped' -Detail $reason))
    }

    # ---- Phase 4: Compensating controls ----
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($IncludeCompensatingControls -and (Get-Command 'Find-CompensatingControls' -ErrorAction SilentlyContinue)) {
        try {
            $outcome.CompensatingControls = @(Find-CompensatingControls -Results $Results)
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'CompensatingControls' -Status 'Completed' -ElapsedMs $sw.Elapsed.TotalMilliseconds -Detail "$($outcome.CompensatingControls.Count) mitigation(s)"))
        } catch {
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'CompensatingControls' -Status 'Error' -ElapsedMs $sw.Elapsed.TotalMilliseconds -ErrorMessage "$($_.Exception.Message)"))
        }
    } else {
        $sw.Stop()
        $reason = if (-not $IncludeCompensatingControls) { 'not requested' } else { 'Find-CompensatingControls unavailable' }
        $phases.Add((New-PhaseRecord -Name 'CompensatingControls' -Status 'Skipped' -Detail $reason))
    }

    # The run timestamp is fixed HERE, before the baseline phase, because the
    # drift comparison embeds it. Assigning it after that call leaves the drift
    # report with an empty timestamp (a defect the reference implementation hit
    # and documented); the ordering is deliberate.
    $outcome.Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

    # ---- Phase 5: Baseline drift ----
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($BaselinePath -and (Get-Command 'Compare-ToBaseline' -ErrorAction SilentlyContinue)) {
        try {
            $outcome.BaselineComparison = Compare-ToBaseline -CurrentResults $Results -BaselinePath $BaselinePath
            $sw.Stop()
            $bc = $outcome.BaselineComparison
            $phases.Add((New-PhaseRecord -Name 'BaselineDrift' -Status 'Completed' -ElapsedMs $sw.Elapsed.TotalMilliseconds -Detail "$(@($bc.NewFailures).Count) new, $(@($bc.Resolved).Count) resolved, $(@($bc.Regressions).Count) regression(s)"))
        } catch {
            $sw.Stop()
            $phases.Add((New-PhaseRecord -Name 'BaselineDrift' -Status 'Error' -ElapsedMs $sw.Elapsed.TotalMilliseconds -ErrorMessage "$($_.Exception.Message)"))
        }
    } else {
        $sw.Stop()
        $reason = if (-not $BaselinePath) { 'no baseline supplied' } else { 'Compare-ToBaseline unavailable' }
        $phases.Add((New-PhaseRecord -Name 'BaselineDrift' -Status 'Skipped' -Detail $reason))
    }

    $pipelineStart.Stop()
    $outcome.PhaseTimings   = @($phases)
    $outcome.ElapsedSeconds = [Math]::Round($pipelineStart.Elapsed.TotalSeconds, 4)
    $outcome.Metadata       = Build-PipelineMetadata -ExecutionInfo $ExecutionInfo -HostFacts $HostFacts -ResultCount @($Results).Count -Threshold $ComplianceThreshold -AssetCriticality $AssetCriticality
    return $outcome
}

function Build-PipelineMetadata {
    <#
    .SYNOPSIS
        Assemble run metadata for the pipeline summary payload.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ExecutionInfo = @{},
        [hashtable]$HostFacts = $null,
        [int]$ResultCount = 0,
        [double]$Threshold = 70.0,
        [int]$AssetCriticality = 0
    )
    $meta = [ordered]@{
        ComputerName        = if ($ExecutionInfo.ComputerName) { "$($ExecutionInfo.ComputerName)" } else { "$env:COMPUTERNAME" }
        OSVersion           = if ($ExecutionInfo.OSVersion) { "$($ExecutionInfo.OSVersion)" } else { '' }
        ScriptVersion       = if ($ExecutionInfo.ScriptVersion) { "$($ExecutionInfo.ScriptVersion)" } else { '' }
        StartTime           = if ($ExecutionInfo.StartTime) { "$($ExecutionInfo.StartTime)" } else { '' }
        ResultCount         = $ResultCount
        ComplianceThreshold = $Threshold
        AssetCriticality    = if ($AssetCriticality -ge 1 -and $AssetCriticality -le 10) { $AssetCriticality } else { 'role-derived' }
        PowerShellVersion   = "$($PSVersionTable.PSVersion)"
    }
    if ($HostFacts) {
        foreach ($k in @('IsDomainController','IsServer','IsServerCore')) {
            if ($HostFacts.Contains($k)) { $meta[$k] = $HostFacts[$k] }
        }
    }
    return $meta
}

function Get-PipelineSummary {
    <#
    .SYNOPSIS
        Machine-readable summary of a pipeline run, suitable for CI gating,
        log shipping, or JSON export.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Outcome)

    $overall = $null
    if ($Outcome.ComplianceScores -and $Outcome.ComplianceScores.ContainsKey('overall')) {
        $overall = $Outcome.ComplianceScores['overall']
    }
    $statusCounts = [ordered]@{ Pass=0; Fail=0; Warning=0; Info=0; Error=0 }
    foreach ($r in $Outcome.Results) {
        $s = "$($r.Status)"
        if ($statusCounts.Contains($s)) { $statusCounts[$s]++ }
    }
    return [ordered]@{
        timestamp        = $Outcome.Timestamp
        elapsedSeconds   = $Outcome.ElapsedSeconds
        resultCount      = @($Outcome.Results).Count
        statusCounts     = $statusCounts
        compliance       = if ($overall) {
            [ordered]@{
                weightedPct         = $overall.WeightedPct
                simplePct           = $overall.SimplePct
                severityWeightedPct = $overall.SeverityWeightedPct
                threshold           = $overall.Threshold
                verdict             = $overall.ThresholdResult
            }
        } else { $null }
        riskScoredCount  = $Outcome.RiskScoredCount
        correlationCount = @($Outcome.Correlations).Count
        compensatingCount= @($Outcome.CompensatingControls).Count
        drift            = if ($Outcome.BaselineComparison) {
            [ordered]@{
                newFailures = @($Outcome.BaselineComparison.NewFailures).Count
                resolved    = @($Outcome.BaselineComparison.Resolved).Count
                regressions = @($Outcome.BaselineComparison.Regressions).Count
            }
        } else { $null }
        phases           = @($Outcome.PhaseTimings | ForEach-Object {
            [ordered]@{ name=$_.Name; status=$_.Status; elapsedMs=$_.ElapsedMs; detail=$_.Detail; error=$_.Error }
        })
        metadata         = $Outcome.Metadata
    }
}

function Show-PipelineSummary {
    <#
    .SYNOPSIS
        Console rendering of the pipeline phases and outcome.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Outcome, [switch]$IncludeTimings)

    foreach ($p in $Outcome.PhaseTimings) {
        if ($p.Status -eq 'Completed') {
            Write-Host "[*] $($p.Name): $($p.Detail)" -ForegroundColor Cyan
        } elseif ($p.Status -eq 'Error') {
            Write-Host "[!] $($p.Name) failed: $($p.Error)" -ForegroundColor Red
        }
    }
    if ($IncludeTimings) {
        Write-Host ""
        Write-Host "  Pipeline phase timings:" -ForegroundColor Cyan
        foreach ($p in $Outcome.PhaseTimings) {
            $col = switch ($p.Status) { 'Completed' { 'Green' } 'Error' { 'Red' } default { 'DarkGray' } }
            Write-Host ("    {0,-22} {1,-10} {2,8} ms" -f $p.Name, $p.Status, $p.ElapsedMs) -ForegroundColor $col
        }
        Write-Host ("    {0,-22} {1,-10} {2,8} s" -f 'TOTAL', '', $Outcome.ElapsedSeconds) -ForegroundColor Cyan
    }
}
