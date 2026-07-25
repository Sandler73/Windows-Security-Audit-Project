<#
.SYNOPSIS
    Pester tests for operator-settable asset criticality and compliance threshold.
.DESCRIPTION
    Validates the v6.5.0 additions that make two previously hardcoded values
    operator-settable: asset criticality feeding the risk-priority score, and
    the weighted-compliance threshold driving the PASS/FAIL verdict. Asserts
    that omitting either parameter preserves the prior derived behavior, that
    supplied values take effect and are bounded, and that an out-of-range or
    non-numeric criticality is ignored rather than corrupting the score.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\risk-and-threshold.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\audit-common.ps1')

    # Get-ComplianceScore and its dependency live in the orchestrator
    $script:OrchSrc = Get-Content (Join-Path $PSScriptRoot '..\Windows-Security-Audit.ps1') -Raw
    foreach ($fn in @('function Get-ModuleStatistics', 'function Get-ComplianceScore')) {
        $a = $script:OrchSrc.IndexOf($fn)
        if ($a -lt 0) { throw "Unable to locate $fn in the orchestrator" }
        $b = $script:OrchSrc.IndexOf("`nfunction ", $a + 10)
        Invoke-Expression $script:OrchSrc.Substring($a, $b - $a)
    }

    function New-RtResult {
        param([string]$Status = 'Fail', [string]$Severity = 'High')
        [PSCustomObject]@{ Status = $Status; Severity = $Severity; Module = 'M'; Category = 'C'; Message = 'm' }
    }
}

Describe 'Asset criticality' {
    It 'preserves the derived default when no criticality is supplied' {
        $r = New-RtResult
        $general = Get-RiskPriorityScore -Result $r
        $dc = Get-RiskPriorityScore -Result $r -ExposureContext @{ IsDomainController = $true }
        $dc | Should -BeGreaterThan $general -Because 'a domain controller derives a higher criticality'
    }
    It 'lowers the score for a low-criticality asset and raises it for a high-criticality asset' {
        $r = New-RtResult
        $default = Get-RiskPriorityScore -Result $r
        $low  = Get-RiskPriorityScore -Result $r -ExposureContext @{ AssetCriticality = 1 }
        $high = Get-RiskPriorityScore -Result $r -ExposureContext @{ AssetCriticality = 10 }
        $low  | Should -BeLessThan $default
        $high | Should -BeGreaterThan $default
    }
    It 'lets an explicit criticality override the role-derived value' {
        $r = New-RtResult
        $dcDerived  = Get-RiskPriorityScore -Result $r -ExposureContext @{ IsDomainController = $true }
        $dcOverride = Get-RiskPriorityScore -Result $r -ExposureContext @{ IsDomainController = $true; AssetCriticality = 1 }
        $dcOverride | Should -BeLessThan $dcDerived
    }
    It 'ignores out-of-range and non-numeric criticality rather than corrupting the score' {
        $r = New-RtResult
        $default = Get-RiskPriorityScore -Result $r
        Get-RiskPriorityScore -Result $r -ExposureContext @{ AssetCriticality = 99 }      | Should -Be $default
        Get-RiskPriorityScore -Result $r -ExposureContext @{ AssetCriticality = 0 }       | Should -Be $default
        Get-RiskPriorityScore -Result $r -ExposureContext @{ AssetCriticality = 'high' }  | Should -Be $default
    }
    It 'keeps every score within the documented 1-100 bound' {
        foreach ($sev in 'Critical','High','Medium','Low','Informational') {
            foreach ($crit in 1..10) {
                $s = Get-RiskPriorityScore -Result (New-RtResult -Severity $sev) -ExposureContext @{ AssetCriticality = $crit }
                $s | Should -BeGreaterOrEqual 1
                $s | Should -BeLessOrEqual 100
            }
        }
    }
}

Describe 'Compliance threshold' {
    BeforeAll {
        $script:Mixed = @()
        1..8 | ForEach-Object { $script:Mixed += New-RtResult -Status 'Pass' -Severity 'Medium' }
        1..2 | ForEach-Object { $script:Mixed += New-RtResult -Status 'Fail' -Severity 'High' }
    }
    It 'defaults to 70 and reports PASS above it' {
        $d = Get-ComplianceScore -ModuleName 'M' -Results $script:Mixed
        $d.Threshold | Should -Be 70
        $d.ThresholdResult | Should -Be 'PASS'
    }
    It 'reports FAIL when the weighted score falls below a stricter threshold' {
        $d = Get-ComplianceScore -ModuleName 'M' -Results $script:Mixed -Threshold 85
        $d.ThresholdResult | Should -Be 'FAIL'
    }
    It 'echoes the supplied threshold in the payload so reports can display it' {
        (Get-ComplianceScore -ModuleName 'M' -Results $script:Mixed -Threshold 42).Threshold | Should -Be 42
    }
    It 'does not alter the computed percentages' {
        $a = Get-ComplianceScore -ModuleName 'M' -Results $script:Mixed
        $b = Get-ComplianceScore -ModuleName 'M' -Results $script:Mixed -Threshold 95
        $b.WeightedPct | Should -Be $a.WeightedPct
        $b.SimplePct   | Should -Be $a.SimplePct
    }
}

Describe 'Orchestrator wiring' {
    It 'declares both parameters with validation ranges' {
        $script:OrchSrc | Should -Match '\[ValidateRange\(1,10\)\]\s*\r?\n\s*\[int\]\$AssetCriticality'
        $script:OrchSrc | Should -Match '\[ValidateRange\(0,100\)\]\s*\r?\n\s*\[double\]\$ComplianceThreshold'
    }
    It 'threads the threshold into both compliance score call sites' {
        ([regex]::Matches($script:OrchSrc, 'Get-ComplianceScore -Results [^\r\n]*-Threshold \$ComplianceThreshold')).Count | Should -Be 2
    }
    It 'passes criticality through the exposure context only when in range' {
        $script:OrchSrc | Should -Match "AssetCriticality -ge 1 -and \`$AssetCriticality -le 10"
        $script:OrchSrc | Should -Match "\`$exposureCtx\['AssetCriticality'\] = \`$AssetCriticality"
    }
}
