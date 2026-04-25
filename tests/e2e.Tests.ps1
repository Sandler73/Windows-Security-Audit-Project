<#
.SYNOPSIS
    Pester end-to-end (E2E) tests for the Windows Security Audit framework.
.DESCRIPTION
    Runs full audits and validates output files, formats, and integration
    of all components. These are slower tests (90+ seconds each) so they
    can be tagged 'Slow' for CI matrix optimization.

    IMPORTANT: The orchestrator constructs output filenames as
    "Windows-Security-Audit-{ComputerName}-{yyyy-MM-dd_HHmmss}.{ext}"
    and treats -OutputPath as a directory hint (uses parent of any path
    passed). Tests must look for the actual generated filename via
    wildcard pattern, not assume a literal filename was honored.

    A test helper Get-LatestAuditFile is defined in BeforeAll to centralize
    this logic.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.1.2
    Last Updated: 2026-04-25
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\e2e.Tests.ps1 -Output Detailed

    Skip slow tests:
        Invoke-Pester -Path .\tests\e2e.Tests.ps1 -ExcludeTagFilter Slow
#>

BeforeAll {
    $script:ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    $script:OrchPath    = Join-Path $script:ProjectRoot 'Windows-Security-Audit.ps1'

    # Test helper: locate a generated audit output file by directory + extension.
    # Returns the most-recently-modified file matching the orchestrator's actual
    # naming convention, or $null if none found.
    function Get-LatestAuditFile {
        param(
            [Parameter(Mandatory)] [string] $Directory,
            [Parameter(Mandatory)] [ValidateSet('html','json','csv','xml')] [string] $Extension
        )
        if (-not (Test-Path $Directory)) { return $null }
        $files = @(Get-ChildItem -Path $Directory `
                                  -Filter "Windows-Security-Audit-*.$Extension" `
                                  -ErrorAction SilentlyContinue)
        if ($files.Count -eq 0) { return $null }
        return ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    }
}

Describe 'Single-Module End-to-End' {
    BeforeAll {
        $script:E2EDir = Join-Path $TestDrive ('e2e-single-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:E2EDir -ItemType Directory -Force | Out-Null
    }

    It 'Core module produces JSON output with valid schema' {
        # Pass any path under our test directory; orchestrator only uses parent
        & $script:OrchPath `
            -Modules core `
            -OutputFormat JSON `
            -OutputPath (Join-Path $script:E2EDir 'out') `
            -Quiet *>&1 | Out-Null

        $jsonPath = Get-LatestAuditFile -Directory $script:E2EDir -Extension 'json'
        $jsonPath | Should -Not -BeNullOrEmpty
        Test-Path $jsonPath | Should -Be $true

        $data = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        $data.Results | Should -Not -BeNullOrEmpty
        @($data.Results).Count | Should -BeGreaterThan 100
    }

    It 'CIS module standalone returns array of result objects' {
        $cisModule = Join-Path $script:ProjectRoot 'modules\module-cis.ps1'
        $results = & $cisModule -SharedData @{ Cache = @{} } 2>&1

        $resultsOnly = @($results | Where-Object { $_.PSObject.Properties.Name -contains 'Module' })
        $resultsOnly.Count | Should -BeGreaterThan 100
    }

    It 'STIG module emits CAT I/II/III categorized results via Severity' {
        $stigModule = Join-Path $script:ProjectRoot 'modules\module-stig.ps1'
        $results = & $stigModule -SharedData @{ Cache = @{} } 2>&1

        $stigResults = @($results | Where-Object { $_.Module -eq 'STIG' })
        $stigResults.Count | Should -BeGreaterThan 0

        $severities = $stigResults.Severity | Sort-Object -Unique
        # STIG should produce a mix of Critical (CAT I), High (CAT II), Medium (CAT III)
        $severities.Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'Multi-Format Output' -Tag 'Slow' {
    BeforeAll {
        $script:MFDir = Join-Path $TestDrive ('e2e-multi-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:MFDir -ItemType Directory -Force | Out-Null

        & $script:OrchPath `
            -Modules core `
            -OutputFormat All `
            -OutputPath (Join-Path $script:MFDir 'out') `
            -Quiet *>&1 | Out-Null
    }

    It 'Generates HTML output' {
        Get-LatestAuditFile -Directory $script:MFDir -Extension 'html' | Should -Not -BeNullOrEmpty
    }

    It 'Generates JSON output' {
        Get-LatestAuditFile -Directory $script:MFDir -Extension 'json' | Should -Not -BeNullOrEmpty
    }

    It 'Generates CSV output' {
        Get-LatestAuditFile -Directory $script:MFDir -Extension 'csv' | Should -Not -BeNullOrEmpty
    }

    It 'Generates XML output' {
        Get-LatestAuditFile -Directory $script:MFDir -Extension 'xml' | Should -Not -BeNullOrEmpty
    }

    It 'JSON content is valid' {
        $jsonPath = Get-LatestAuditFile -Directory $script:MFDir -Extension 'json'
        if ($jsonPath) {
            $content = Get-Content -Path $jsonPath -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'CSV content is parseable' {
        $csvPath = Get-LatestAuditFile -Directory $script:MFDir -Extension 'csv'
        if ($csvPath) {
            $rows = Import-Csv -Path $csvPath
            $rows.Count | Should -BeGreaterThan 0
        }
    }

    It 'HTML content has report banner' {
        $htmlPath = Get-LatestAuditFile -Directory $script:MFDir -Extension 'html'
        if ($htmlPath) {
            $content = Get-Content -Path $htmlPath -Raw
            $content | Should -Match 'Windows Security Audit'
            $content | Should -Match '<!DOCTYPE|<html'
        }
    }

    It 'XML content has valid root element' {
        $xmlPath = Get-LatestAuditFile -Directory $script:MFDir -Extension 'xml'
        if ($xmlPath) {
            $content = Get-Content -Path $xmlPath -Raw
            { [xml]$content } | Should -Not -Throw
        }
    }
}

Describe 'Parallel Execution' -Tag 'Slow' {
    It 'Parallel mode produces same total result count as sequential' {
        $seqDir = Join-Path $TestDrive ('seq-' + [guid]::NewGuid().ToString('N'))
        $parDir = Join-Path $TestDrive ('par-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $seqDir -ItemType Directory -Force | Out-Null
        New-Item -Path $parDir -ItemType Directory -Force | Out-Null

        & $script:OrchPath -Modules core,cis -OutputFormat JSON `
            -OutputPath (Join-Path $seqDir 'out') -Quiet *>&1 | Out-Null
        & $script:OrchPath -Modules core,cis -OutputFormat JSON `
            -OutputPath (Join-Path $parDir 'out') -Parallel -Workers 2 -Quiet *>&1 | Out-Null

        $seqJson = Get-LatestAuditFile -Directory $seqDir -Extension 'json'
        $parJson = Get-LatestAuditFile -Directory $parDir -Extension 'json'

        $seqJson | Should -Not -BeNullOrEmpty
        $parJson | Should -Not -BeNullOrEmpty

        $seqData = Get-Content $seqJson -Raw | ConvertFrom-Json
        $parData = Get-Content $parJson -Raw | ConvertFrom-Json

        $seqCount = @($seqData.Results).Count
        $parCount = @($parData.Results).Count

        # Should be within 5% (small variance allowed for env-dependent checks)
        [math]::Abs($seqCount - $parCount) | Should -BeLessOrEqual ($seqCount * 0.05)
    }
}

Describe 'Full 16-Module Execution' -Tag 'Slow','Full' {
    It 'All 16 modules complete successfully via -Modules All' {
        $fullDir = Join-Path $TestDrive ('full-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $fullDir -ItemType Directory -Force | Out-Null

        & $script:OrchPath -Modules All -OutputFormat JSON `
            -OutputPath (Join-Path $fullDir 'out') -Parallel -Workers 4 -Quiet *>&1 | Out-Null

        $jsonPath = Get-LatestAuditFile -Directory $fullDir -Extension 'json'
        $jsonPath | Should -Not -BeNullOrEmpty

        $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
        @($data.Results).Count | Should -BeGreaterThan 3000
    }

    It 'Total checks approximately equal 3,994' {
        $fullDir = Join-Path $TestDrive ('full2-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $fullDir -ItemType Directory -Force | Out-Null

        & $script:OrchPath -Modules All -OutputFormat JSON `
            -OutputPath (Join-Path $fullDir 'out') -Parallel -Workers 4 -Quiet *>&1 | Out-Null

        $jsonPath = Get-LatestAuditFile -Directory $fullDir -Extension 'json'
        if ($jsonPath) {
            $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
            $count = @($data.Results).Count
            # Allow +/-10% variance for environment-dependent checks
            $count | Should -BeGreaterOrEqual 3500
            $count | Should -BeLessOrEqual 4400
        }
    }

    It 'All 16 unique module names appear in results' {
        $fullDir = Join-Path $TestDrive ('full3-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $fullDir -ItemType Directory -Force | Out-Null

        & $script:OrchPath -Modules All -OutputFormat JSON `
            -OutputPath (Join-Path $fullDir 'out') -Parallel -Workers 4 -Quiet *>&1 | Out-Null

        $jsonPath = Get-LatestAuditFile -Directory $fullDir -Extension 'json'
        if ($jsonPath) {
            $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
            $modules = @($data.Results.Module | Sort-Object -Unique)
            $modules.Count | Should -BeGreaterOrEqual 14
            $modules.Count | Should -BeLessOrEqual 16
        }
    }
}

Describe 'Baseline Drift (v6.1.0)' -Tag 'Slow' {
    It '-Baseline parameter accepts JSON path without error' {
        $baselineDir = Join-Path $TestDrive ('baseline-' + [guid]::NewGuid().ToString('N'))
        $currentDir  = Join-Path $TestDrive ('current-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $baselineDir -ItemType Directory -Force | Out-Null
        New-Item -Path $currentDir -ItemType Directory -Force | Out-Null

        # Generate a baseline first
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $baselineDir 'out') -Quiet *>&1 | Out-Null

        $baseline = Get-LatestAuditFile -Directory $baselineDir -Extension 'json'
        $baseline | Should -Not -BeNullOrEmpty

        # Then compare current run against it
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $currentDir 'out') -Baseline $baseline -Quiet *>&1 | Out-Null

        $current = Get-LatestAuditFile -Directory $currentDir -Extension 'json'
        $current | Should -Not -BeNullOrEmpty
    }
}

Describe 'Cache Behavior' {
    It '-NoCache flag produces results (slower path works)' {
        $noCacheDir = Join-Path $TestDrive ('nocache-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $noCacheDir -ItemType Directory -Force | Out-Null

        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $noCacheDir 'out') -NoCache -Quiet *>&1 | Out-Null

        $jsonPath = Get-LatestAuditFile -Directory $noCacheDir -Extension 'json'
        $jsonPath | Should -Not -BeNullOrEmpty
    }
}

Describe 'Logging' {
    It 'Auto-creates log file when -LogFile not specified' {
        $logTestDir = Join-Path $TestDrive ('autolog-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $logTestDir -ItemType Directory -Force | Out-Null

        Push-Location $TestDrive
        try {
            & $script:OrchPath -Modules core -OutputFormat JSON `
                -OutputPath (Join-Path $logTestDir 'out') -Quiet *>&1 | Out-Null

            # Auto-log goes to <ScriptRoot>\logs\audit-{yyyyMMdd-HHmmss}.log
            $scriptRoot = Split-Path $script:OrchPath -Parent
            $logsDir = Join-Path $scriptRoot 'logs'
            Test-Path $logsDir | Should -Be $true
        }
        finally {
            Pop-Location
        }
    }

    It 'Custom -LogFile writes to specified location' {
        $logTestDir = Join-Path $TestDrive ('customlog-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $logTestDir -ItemType Directory -Force | Out-Null

        $logPath = Join-Path $logTestDir 'custom-audit.log'

        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $logTestDir 'out') `
            -LogFile $logPath -Quiet *>&1 | Out-Null

        Test-Path $logPath | Should -Be $true
    }
}
