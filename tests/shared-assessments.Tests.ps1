<#
.SYNOPSIS
    Pester tests for the shared host-wide assessments component.
.DESCRIPTION
    Validates the assessment registry, the uniform record contract including item
    capping and truncation flags, error-record discipline in place of exceptions,
    the SharedData pre-warm and standalone memoization paths, and the derived
    latest-hotfix-age signal.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\shared-assessments.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\shared-assessments.ps1')
}

Describe 'Assessment registry' {
    It 'declares the four measured-duplication assessments' {
        Get-SharedAssessmentNames | Should -Be @('LocalUsers','LocalAdministrators','InstalledHotfixes','ListeningTcpPorts')
    }
}

Describe 'Record contract' {
    It 'caps Items at 25 and sets Truncated with the full Count' {
        $rec = New-AssessmentRecord -Name 'X' -Items @(1..40) -Source 's'
        $rec.Count | Should -Be 40
        @($rec.Items).Count | Should -Be 25
        $rec.Truncated | Should -BeTrue
    }
    It 'returns an Error record for unknown assessments instead of throwing' {
        $rec = Invoke-AssessmentCollection -Name 'DoesNotExist'
        $rec.Error | Should -Not -BeNullOrEmpty
        $rec.Count | Should -Be 0
    }
    It 'converts collector failures into Error records (no throw propagation)' {
        Mock Get-LocalUser { throw 'boom' }
        $rec = Invoke-AssessmentCollection -Name 'LocalUsers'
        $rec.Error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Pre-warm and retrieval' {
    It 'Initialize-SharedAssessments populates SharedData.Assessments for every name' {
        $sd = @{}
        $bag = Initialize-SharedAssessments -SharedData $sd
        foreach ($n in Get-SharedAssessmentNames) {
            $sd.Assessments.ContainsKey($n) | Should -BeTrue
            $sd.Assessments[$n].Name | Should -Be $n
        }
    }
    It 'Get-SharedAssessment prefers SharedData over recollection' {
        $sd = @{ Assessments = @{ LocalUsers = (New-AssessmentRecord -Name 'LocalUsers' -Items @('sentinel') -Source 'test') } }
        (Get-SharedAssessment -Name LocalUsers -SharedData $sd).Items[0] | Should -Be 'sentinel'
    }
}

Describe 'Derived signals' {
    It 'Get-LatestHotfixAgeDays returns $null on collection error' {
        $sd = @{ Assessments = @{ InstalledHotfixes = (New-AssessmentRecord -Name 'InstalledHotfixes' -ErrorMessage 'x') } }
        Get-LatestHotfixAgeDays -SharedData $sd | Should -BeNullOrEmpty
    }
    It 'computes age from the newest dated hotfix' {
        $items = @([PSCustomObject]@{ HotFixID='KB1'; Description='d'; InstalledOn=(Get-Date).AddDays(-10) })
        $sd = @{ Assessments = @{ InstalledHotfixes = (New-AssessmentRecord -Name 'InstalledHotfixes' -Items $items -Source 't') } }
        [double](Get-LatestHotfixAgeDays -SharedData $sd) | Should -BeGreaterThan 9
    }
}
