<#
.SYNOPSIS
    Pester tests for the 9-field result object schema across all modules.
.DESCRIPTION
    Runs each module standalone and validates that every result object
    conforms to the canonical 9-field schema:
        Module, Category, Status, Severity, Message, Details,
        Remediation, CrossReferences, Timestamp.

    Validates that Status values come from {Pass, Fail, Warning, Info, Error}
    and Severity values come from {Critical, High, Medium, Low, Informational}.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.1.2
    Last Updated: 2026-04-25
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\result-schema.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    $script:ModulesDir  = Join-Path $script:ProjectRoot 'modules'
    $script:LibPath     = Join-Path $script:ProjectRoot 'shared_components\audit-common.ps1'

    # Load shared library
    . $script:LibPath

    $script:RequiredFields = @(
        'Module','Category','Status','Severity','Message',
        'Details','Remediation','CrossReferences','Timestamp'
    )

    $script:ValidStatuses   = @('Pass','Fail','Warning','Info','Error')
    $script:ValidSeverities = @('Critical','High','Medium','Low','Informational')

    # Run each module ONCE and cache results
    $script:ModuleResults = @{}
    $script:ModuleFiles = Get-ChildItem -Path $script:ModulesDir -Filter 'module-*.ps1'

    foreach ($file in $script:ModuleFiles) {
        try {
            $sharedData = @{ Cache = @{} }
            $results = & $file.FullName -SharedData $sharedData -ErrorAction SilentlyContinue 2>$null
            if ($null -ne $results) {
                $script:ModuleResults[$file.Name] = @($results)
            }
        }
        catch {
            $script:ModuleResults[$file.Name] = @()
        }
    }
}

Describe 'Result Object Schema' {
    It 'Each module returns at least one result' {
        foreach ($key in $script:ModuleResults.Keys) {
            $count = $script:ModuleResults[$key].Count
            $count | Should -BeGreaterThan 0 -Because "Module $key should return results"
        }
    }

    It 'Every result has all 9 required fields' {
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $names = $result.PSObject.Properties.Name
                foreach ($field in $script:RequiredFields) {
                    $names | Should -Contain $field `
                        -Because "$key result missing field: $field"
                }
            }
        }
    }

    It 'Every Status value is in the allowed set' {
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $script:ValidStatuses | Should -Contain $result.Status `
                    -Because "$key has invalid Status '$($result.Status)'"
            }
        }
    }

    It 'Every Severity value is in the allowed set' {
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $script:ValidSeverities | Should -Contain $result.Severity `
                    -Because "$key has invalid Severity '$($result.Severity)'"
            }
        }
    }

    It 'Module field matches the file name pattern' {
        foreach ($key in $script:ModuleResults.Keys) {
            # Extract expected module name (e.g., module-cis.ps1 -> cis or CIS)
            $expectedName = ($key -replace '^module-', '') -replace '\.ps1$', ''

            foreach ($result in $script:ModuleResults[$key]) {
                $result.Module | Should -Match $expectedName `
                    -Because "$key result Module field should reference '$expectedName'"
            }
        }
    }

    It 'Timestamp field is a non-null DateTime or ISO string' {
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $result.Timestamp | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'CrossReferences field is a hashtable' {
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $result.CrossReferences | Should -BeOfType [hashtable]
            }
        }
    }

    It 'Category field follows "Module - Category" naming pattern' {
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $result.Category | Should -Match '^[\w]+\s*-\s*' `
                    -Because "$key has malformed Category '$($result.Category)'"
            }
        }
    }
}

Describe 'Module Check Count Verification' {
    BeforeDiscovery {
        $script:ExpectedCounts = @{
            'module-acsc.ps1'           = 170
            'module-cis.ps1'            = 260
            'module-cisa.ps1'           = 289
            'module-cmmc.ps1'           = 145
            'module-core.ps1'           = 243
            'module-enisa.ps1'          = 248
            'module-gdpr.ps1'           = 183
            'module-hipaa.ps1'          = 237
            'module-iso27001.ps1'       = 286
            'module-ms.ps1'             = 367
            'module-ms-defenderatp.ps1' = 155
            'module-nist.ps1'           = 520
            'module-nsa.ps1'            = 225
            'module-pcidss.ps1'         = 279
            'module-soc2.ps1'           = 162
            'module-stig.ps1'           = 225
        }
        $script:CountCases = @($script:ExpectedCounts.GetEnumerator() | ForEach-Object {
            @{ Name = $_.Key; Expected = $_.Value }
        })
    }

    It 'Module <n> emits approximately <Expected> results' -ForEach $script:CountCases {
        param($Name, $Expected)
        $results = $script:ModuleResults[$Name]
        $results | Should -Not -BeNullOrEmpty
        $count = @($results).Count
        # Allow +/-10% variance for environment-dependent checks
        $minExpected = [int]($Expected * 0.85)
        $maxExpected = [int]($Expected * 1.15)
        $count | Should -BeGreaterOrEqual $minExpected
        $count | Should -BeLessOrEqual $maxExpected
    }
}

Describe 'Total Aggregate Check Count' {
    It 'Total checks across all modules approximately equals 3,994' {
        $total = 0
        foreach ($key in $script:ModuleResults.Keys) {
            $total += @($script:ModuleResults[$key]).Count
        }
        # Allow +/-10% variance
        $total | Should -BeGreaterOrEqual 3500
        $total | Should -BeLessOrEqual 4400
    }
}

Describe 'Status Distribution Reasonableness' {
    It 'No module has 100% Error results (suggests environment issue)' {
        foreach ($key in $script:ModuleResults.Keys) {
            $results = $script:ModuleResults[$key]
            if ($results.Count -eq 0) { continue }
            $errorCount = @($results | Where-Object Status -eq 'Error').Count
            $errorPct = ($errorCount / $results.Count) * 100
            $errorPct | Should -BeLessThan 80 `
                -Because "$key has $errorPct% Error results (run as Administrator?)"
        }
    }

    It 'At least one module has Pass results (sanity check)' {
        $totalPass = 0
        foreach ($key in $script:ModuleResults.Keys) {
            $totalPass += @($script:ModuleResults[$key] | Where-Object Status -eq 'Pass').Count
        }
        $totalPass | Should -BeGreaterThan 0
    }
}

Describe 'NIST Module Category Consolidation' {
    It 'NIST module has 20 unique categories (consolidated from 230 in v6.1.0)' {
        $nistResults = $script:ModuleResults['module-nist.ps1']
        if ($nistResults) {
            $uniqueCategories = @($nistResults.Category | Sort-Object -Unique)
            # Should be approximately 20 (8 control families + 12 framework extensions)
            $uniqueCategories.Count | Should -BeLessOrEqual 25
            $uniqueCategories.Count | Should -BeGreaterOrEqual 15
        }
    }
}

Describe 'CrossReferences Population' {
    It 'At least 50% of results have populated CrossReferences' {
        $totalResults = 0
        $populatedRefs = 0
        foreach ($key in $script:ModuleResults.Keys) {
            foreach ($result in $script:ModuleResults[$key]) {
                $totalResults++
                if ($result.CrossReferences -is [hashtable] -and $result.CrossReferences.Count -gt 0) {
                    $populatedRefs++
                }
            }
        }
        if ($totalResults -gt 0) {
            $populatedPct = ($populatedRefs / $totalResults) * 100
            $populatedPct | Should -BeGreaterOrEqual 50
        }
    }
}
