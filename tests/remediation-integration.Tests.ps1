<#
.SYNOPSIS
    Pester tests for the remediation flow integration.
.DESCRIPTION
    Source-level contract tests guarding the integration between the v6.4 components
    and the pre-existing remediation flow: state capture strictly precedes apply,
    verification follows apply, impact tiers add to rather than replace the existing
    confirmation gate, every new call is availability-guarded, and the earlier
    fallbacks remain intact so the flow degrades to prior behavior.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\remediation-integration.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:OrchestratorSource = Get-Content (Join-Path $PSScriptRoot '..\Windows-Security-Audit.ps1') -Raw
    $start = $script:OrchestratorSource.IndexOf('function Invoke-Remediation')
    $end   = $script:OrchestratorSource.IndexOf("`n# ====", $start + 100)
    $script:RemediationFn = $script:OrchestratorSource.Substring($start, $end - $start)
}

Describe 'Capture-before-apply ordering' {
    It 'captures state before the remediation command executes' {
        $iCapture = $RemediationFn.IndexOf('Invoke-RollbackCapture')
        $iApply   = $RemediationFn.IndexOf('$null = & $remedScript')
        $iCapture | Should -BeGreaterThan 0
        $iCapture | Should -BeLessThan $iApply
    }
    It 'verifies the setting after applying it' {
        $iApply  = $RemediationFn.IndexOf('$null = & $remedScript')
        $iVerify = $RemediationFn.IndexOf('Test-RemediationApplied')
        $iVerify | Should -BeGreaterThan $iApply
    }
    It 'runs exactly one apply loop (no parallel remediation path introduced)' {
        ([regex]::Matches($RemediationFn, [regex]::Escape('$null = & $remedScript'))).Count | Should -Be 1
    }
}

Describe 'Confirmation gating' {
    It 'evaluates impact tiers before the existing YES gate' {
        $iTier = $RemediationFn.IndexOf('Get-ConfirmationTier')
        $iYes  = $RemediationFn.IndexOf("Type 'YES' to confirm")
        $iTier | Should -BeGreaterThan 0
        $iTier | Should -BeLessThan $iYes
    }
    It 'retains the original YES gate (tiers add requirements, never relax them)' {
        $RemediationFn | Should -Match "Type 'YES' to confirm"
    }
    It 'requires case-sensitive typed confirmations for elevated and critical tiers' {
        $RemediationFn | Should -Match "-cne 'ACKNOWLEDGE'"
        $RemediationFn | Should -Match "-cne 'I ACCEPT THE RISK'"
    }
}

Describe 'Availability guarding and degradation' {
    It 'guards every v6.4 call behind its component availability flag' {
        $pairs = @(
            @{ Call = 'Get-RemediationTopic';    Guard = 'HAS_CANONICAL_REMEDIATIONS' },
            @{ Call = 'Invoke-RollbackCapture';  Guard = 'HAS_ROLLBACK_GENERATOR' },
            @{ Call = 'Test-RemediationApplied'; Guard = 'HAS_REMEDIATION_LIBRARY' },
            @{ Call = 'New-RollbackScript';      Guard = 'HAS_ROLLBACK_GENERATOR' }
        )
        foreach ($p in $pairs) {
            $idx = $RemediationFn.IndexOf($p.Call)
            $idx | Should -BeGreaterThan 0
            $window = $RemediationFn.Substring([Math]::Max(0, $idx - 700), [Math]::Min(700, $idx))
            $window | Should -Match $p.Guard -Because "$($p.Call) must be availability-guarded"
        }
    }
    It 'preserves the v6.1 command-derived rollback as the fallback path' {
        $RemediationFn | Should -Match 'ConvertTo-RegistryRollback -ForwardCommand'
        $RemediationFn | Should -Match 'elseif \(\$RollbackPath -and \$rollbackEntries\.Count -gt 0\)'
    }
}

Describe 'Honest reporting' {
    It 'no longer claims success solely because the command did not throw' {
        $RemediationFn | Should -Not -Match '\[\+\] Remediation applied successfully'
    }
    It 'reports a distinct outcome when verification fails' {
        $RemediationFn | Should -Match 'verification FAILED'
    }
    It 'surfaces verification counts in the summary' {
        $RemediationFn | Should -Match 'Verification: \$verifiedCount verified'
    }
}
