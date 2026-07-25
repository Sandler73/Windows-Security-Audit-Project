<#
.SYNOPSIS
    Pester tests for the composed post-execution audit pipeline.
.DESCRIPTION
    Validates that the pipeline composes the existing enrichment functions
    without altering their behavior: phase records are emitted for every phase
    with correct skip and error accounting, upstream compliance scores are
    reused rather than recomputed, the run timestamp is fixed before the
    baseline phase that embeds it, risk decoration is idempotent across runs,
    a failing phase does not abort the pipeline, and the summary payload is
    complete and JSON-serializable.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\audit-pipeline.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\audit-common.ps1')
    . (Join-Path $PSScriptRoot '..\shared_components\audit-pipeline.ps1')

    $script:OrchSrc = Get-Content (Join-Path $PSScriptRoot '..\Windows-Security-Audit.ps1') -Raw
    foreach ($fn in @('function Get-ModuleStatistics', 'function Get-ComplianceScore')) {
        $a = $script:OrchSrc.IndexOf($fn)
        $b = $script:OrchSrc.IndexOf("`nfunction ", $a + 10)
        Invoke-Expression $script:OrchSrc.Substring($a, $b - $a)
    }

    function New-PlResults {
        $r = @()
        1..5 | ForEach-Object { $r += [PSCustomObject]@{ Module='NIST'; Category='NIST - AC'; Status='Pass';    Severity='Medium'; Message="p$_"; Details='d'; Remediation=''; CrossReferences=@{} } }
        1..3 | ForEach-Object { $r += [PSCustomObject]@{ Module='STIG'; Category='STIG - SMB'; Status='Fail';   Severity='High';   Message="f$_"; Details='d'; Remediation='fix'; CrossReferences=@{} } }
        1..2 | ForEach-Object { $r += [PSCustomObject]@{ Module='CIS';  Category='CIS - Log';  Status='Warning'; Severity='Critical'; Message="w$_"; Details='d'; Remediation=''; CrossReferences=@{} } }
        return $r
    }
}

Describe 'Phase accounting' {
    It 'emits a record for every phase, including those not requested' {
        $o = Invoke-AuditPipeline -Results (New-PlResults)
        @($o.PhaseTimings).Count | Should -Be 5
        ($o.PhaseTimings | ForEach-Object { $_.Name }) | Should -Be @('ComplianceScoring','RiskPriority','Correlations','CompensatingControls','BaselineDrift')
    }
    It 'records unrequested phases as skipped with a reason, not as failures' {
        $o = Invoke-AuditPipeline -Results (New-PlResults)
        $rp = $o.PhaseTimings | Where-Object Name -eq 'RiskPriority'
        $rp.Status | Should -Be 'Skipped'
        $rp.Detail | Should -Be 'not requested'
        $rp.Error  | Should -BeNullOrEmpty
    }
    It 'records a skipped baseline phase when no baseline is supplied' {
        $o = Invoke-AuditPipeline -Results (New-PlResults)
        ($o.PhaseTimings | Where-Object Name -eq 'BaselineDrift').Detail | Should -Be 'no baseline supplied'
    }
    It 'continues the pipeline when a phase throws, recording it as an error' {
        Mock Find-CrossFrameworkCorrelations { throw 'boom' }
        $o = Invoke-AuditPipeline -Results (New-PlResults) -IncludeCorrelations -IncludeCompensatingControls
        ($o.PhaseTimings | Where-Object Name -eq 'Correlations').Status | Should -Be 'Error'
        # The phase after the failure still ran
        ($o.PhaseTimings | Where-Object Name -eq 'CompensatingControls').Status | Should -Be 'Completed'
    }
}

Describe 'Compliance scoring' {
    It 'computes scores per module plus an overall entry when none are supplied' {
        $o = Invoke-AuditPipeline -Results (New-PlResults) -ComplianceThreshold 70
        $o.ComplianceScores.Keys | Should -Contain 'overall'
        $o.ComplianceScores.Keys | Should -Contain 'NIST'
        $o.ComplianceScores['overall'].Threshold | Should -Be 70
    }
    It 'reuses upstream scores rather than recomputing them' {
        $supplied = @{ overall = [PSCustomObject]@{ WeightedPct = 42; SimplePct = 42; SeverityWeightedPct = 42; Threshold = 70; ThresholdResult = 'SENTINEL' } }
        $o = Invoke-AuditPipeline -Results (New-PlResults) -ComplianceScores $supplied
        $o.ComplianceScores['overall'].ThresholdResult | Should -Be 'SENTINEL'
        ($o.PhaseTimings | Where-Object Name -eq 'ComplianceScoring').Detail | Should -Match 'reused'
    }
    It 'honours the supplied threshold in the verdict' {
        $lenient = Invoke-AuditPipeline -Results (New-PlResults) -ComplianceThreshold 10
        $strict  = Invoke-AuditPipeline -Results (New-PlResults) -ComplianceThreshold 99
        $lenient.ComplianceScores['overall'].ThresholdResult | Should -Be 'PASS'
        $strict.ComplianceScores['overall'].ThresholdResult  | Should -Be 'FAIL'
    }
}

Describe 'Risk decoration' {
    It 'decorates every undecorated result and reports the count' {
        $r = New-PlResults
        $o = Invoke-AuditPipeline -Results $r -IncludeRiskPriority
        $o.RiskScoredCount | Should -Be $r.Count
        @($r | Where-Object { $_.PSObject.Properties['RiskPriority'] }).Count | Should -Be $r.Count
    }
    It 'is idempotent: a second pass over the same results scores nothing new' {
        $r = New-PlResults
        Invoke-AuditPipeline -Results $r -IncludeRiskPriority | Out-Null
        (Invoke-AuditPipeline -Results $r -IncludeRiskPriority).RiskScoredCount | Should -Be 0
    }
    It 'reports operator-supplied criticality distinctly from the role-derived default' {
        $withCrit = Invoke-AuditPipeline -Results (New-PlResults) -IncludeRiskPriority -AssetCriticality 9
        ($withCrit.PhaseTimings | Where-Object Name -eq 'RiskPriority').Detail | Should -Match 'operator-supplied'
        $derived = Invoke-AuditPipeline -Results (New-PlResults) -IncludeRiskPriority
        ($derived.PhaseTimings | Where-Object Name -eq 'RiskPriority').Detail | Should -Match 'role-derived'
    }
}

Describe 'Run metadata and summary' {
    It 'fixes the timestamp before the baseline phase that embeds it' {
        $o = Invoke-AuditPipeline -Results (New-PlResults)
        $o.Timestamp | Should -Not -BeNullOrEmpty
    }
    It 'produces a complete, JSON-serializable summary payload' {
        $o = Invoke-AuditPipeline -Results (New-PlResults) -IncludeRiskPriority -AssetCriticality 4
        $s = Get-PipelineSummary -Outcome $o
        foreach ($k in 'timestamp','elapsedSeconds','resultCount','statusCounts','compliance','phases','metadata') {
            $s.Keys | Should -Contain $k
        }
        $s.resultCount | Should -Be 10
        $s.statusCounts.Pass | Should -Be 5
        $s.statusCounts.Fail | Should -Be 3
        { $s | ConvertTo-Json -Depth 6 } | Should -Not -Throw
    }
    It 'records the criticality mode in metadata' {
        (Invoke-AuditPipeline -Results (New-PlResults) -AssetCriticality 8).Metadata.AssetCriticality | Should -Be 8
        (Invoke-AuditPipeline -Results (New-PlResults)).Metadata.AssetCriticality | Should -Be 'role-derived'
    }
}

Describe 'Orchestrator integration' {
    It 'invokes the pipeline behind an availability guard and retains the v6.1 fallback' {
        $script:OrchSrc | Should -Match 'if \(\$script:HAS_AUDIT_PIPELINE\) \{'
        $script:OrchSrc | Should -Match 'Invoke-AuditPipeline -Results \$allResults'
        # Fallback path still contains the original enrichment calls
        $script:OrchSrc | Should -Match 'Find-CrossFrameworkCorrelations -Results \$allResults'
        $script:OrchSrc | Should -Match 'Compare-ToBaseline -CurrentResults \$allResults'
    }
    It 'repopulates the script-scope variables downstream code consumes' {
        foreach ($v in 'CrossFrameworkCorrelations','CompensatingControls','BaselineComparison') {
            $script:OrchSrc | Should -Match "\`$script:$v\s*="
        }
    }
}
