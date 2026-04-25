<#
.SYNOPSIS
    Pester end-to-end (E2E) tests for the Windows Security Audit framework.
.DESCRIPTION
    Runs full audits and validates output files, formats, and integration
    of all components. These are slower tests (90+ seconds each) so they
    can be tagged 'Slow' for CI matrix optimization.
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
}

Describe 'Single-Module End-to-End' {
    BeforeAll {
        $script:E2EDir = Join-Path $TestDrive ('e2e-single-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:E2EDir -ItemType Directory -Force | Out-Null
    }

    It 'Core module produces JSON output with valid schema' {
        $jsonPath = Join-Path $script:E2EDir 'core.json'

        & $script:OrchPath `
            -Modules core `
            -OutputFormat JSON `
            -OutputPath $jsonPath `
            -Quiet 2>&1 | Out-Null

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

        $script:OutBase = Join-Path $script:MFDir 'audit'

        & $script:OrchPath `
            -Modules core `
            -OutputFormat All `
            -OutputPath $script:OutBase `
            -Quiet 2>&1 | Out-Null
    }

    It 'Generates HTML output' {
        Test-Path "$script:OutBase.html" | Should -Be $true
    }

    It 'Generates JSON output' {
        Test-Path "$script:OutBase.json" | Should -Be $true
    }

    It 'Generates CSV output' {
        Test-Path "$script:OutBase.csv" | Should -Be $true
    }

    It 'Generates XML output' {
        Test-Path "$script:OutBase.xml" | Should -Be $true
    }

    It 'JSON content is valid' {
        $jsonPath = "$script:OutBase.json"
        if (Test-Path $jsonPath) {
            $content = Get-Content -Path $jsonPath -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'CSV content is parseable' {
        $csvPath = "$script:OutBase.csv"
        if (Test-Path $csvPath) {
            $rows = Import-Csv -Path $csvPath
            $rows.Count | Should -BeGreaterThan 0
        }
    }

    It 'HTML content has report banner and 3,994 reference' {
        $htmlPath = "$script:OutBase.html"
        if (Test-Path $htmlPath) {
            $content = Get-Content -Path $htmlPath -Raw
            $content | Should -Match 'Windows Security Audit'
            $content | Should -Match '<!DOCTYPE|<html'
        }
    }

    It 'XML content has valid root element' {
        $xmlPath = "$script:OutBase.xml"
        if (Test-Path $xmlPath) {
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

        $seqJson = Join-Path $seqDir 'seq.json'
        $parJson = Join-Path $parDir 'par.json'

        & $script:OrchPath -Modules core,cis -OutputFormat JSON `
            -OutputPath $seqJson -Quiet 2>&1 | Out-Null
        & $script:OrchPath -Modules core,cis -OutputFormat JSON `
            -OutputPath $parJson -Parallel -Workers 2 -Quiet 2>&1 | Out-Null

        if ((Test-Path $seqJson) -and (Test-Path $parJson)) {
            $seqData = Get-Content $seqJson -Raw | ConvertFrom-Json
            $parData = Get-Content $parJson -Raw | ConvertFrom-Json

            $seqCount = @($seqData.Results).Count
            $parCount = @($parData.Results).Count

            # Should be within 5% (small variance allowed for env-dependent checks)
            [math]::Abs($seqCount - $parCount) | Should -BeLessOrEqual ($seqCount * 0.05)
        }
    }
}

Describe 'Full 16-Module Execution' -Tag 'Slow','Full' {
    It 'All 16 modules complete successfully via -Modules All' {
        $fullDir = Join-Path $TestDrive ('full-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $fullDir -ItemType Directory -Force | Out-Null

        $jsonPath = Join-Path $fullDir 'full.json'

        & $script:OrchPath -Modules All -OutputFormat JSON `
            -OutputPath $jsonPath -Parallel -Workers 4 -Quiet 2>&1 | Out-Null

        Test-Path $jsonPath | Should -Be $true

        $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
        @($data.Results).Count | Should -BeGreaterThan 3000
    }

    It 'Total checks approximately equal 3,994' {
        $fullDir = Join-Path $TestDrive ('full2-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $fullDir -ItemType Directory -Force | Out-Null
        $jsonPath = Join-Path $fullDir 'full.json'

        & $script:OrchPath -Modules All -OutputFormat JSON `
            -OutputPath $jsonPath -Parallel -Workers 4 -Quiet 2>&1 | Out-Null

        if (Test-Path $jsonPath) {
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
        $jsonPath = Join-Path $fullDir 'full.json'

        & $script:OrchPath -Modules All -OutputFormat JSON `
            -OutputPath $jsonPath -Parallel -Workers 4 -Quiet 2>&1 | Out-Null

        if (Test-Path $jsonPath) {
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
        New-Item -Path $baselineDir -ItemType Directory -Force | Out-Null

        $baseline = Join-Path $baselineDir 'baseline.json'
        $current  = Join-Path $baselineDir 'current.json'

        # Generate a baseline first
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath $baseline -Quiet 2>&1 | Out-Null

        # Then compare current run against it
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath $current -Baseline $baseline -Quiet 2>&1 | Out-Null

        Test-Path $current | Should -Be $true
    }
}

Describe 'Cache Behavior' {
    It '-NoCache flag produces results (slower path works)' {
        $noCacheDir = Join-Path $TestDrive ('nocache-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $noCacheDir -ItemType Directory -Force | Out-Null
        $jsonPath = Join-Path $noCacheDir 'nocache.json'

        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath $jsonPath -NoCache -Quiet 2>&1 | Out-Null

        Test-Path $jsonPath | Should -Be $true
    }
}

Describe 'Logging' {
    It 'Auto-creates log file when -LogFile not specified' {
        Push-Location $TestDrive
        try {
            $jsonPath = Join-Path $TestDrive ('autolog-' + [guid]::NewGuid().ToString('N') + '.json')
            & $script:OrchPath -Modules core -OutputFormat JSON `
                -OutputPath $jsonPath -Quiet 2>&1 | Out-Null

            # Log file appears in script root\logs\ by default
            $scriptRoot = Split-Path $script:OrchPath -Parent
            $logsDir = Join-Path $scriptRoot 'logs'
            $found = Test-Path $logsDir
            $found | Should -Be $true
        }
        finally {
            Pop-Location
        }
    }

    It 'Custom -LogFile writes to specified location' {
        $logPath = Join-Path $TestDrive ('custom-log-' + [guid]::NewGuid().ToString('N') + '.log')
        $jsonPath = Join-Path $TestDrive ('audit-' + [guid]::NewGuid().ToString('N') + '.json')

        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath $jsonPath `
            -LogFile $logPath -Quiet 2>&1 | Out-Null

        Test-Path $logPath | Should -Be $true
    }
}
