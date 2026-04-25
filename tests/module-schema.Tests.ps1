<#
.SYNOPSIS
    Pester structural tests for all 16 audit modules.
.DESCRIPTION
    Validates that every module file conforms to project conventions:
    comment-based help, brace balance, ASCII-only, BOM-free, exactly one
    return statement, version sync, $moduleName declaration.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.1.2
    Last Updated: 2026-04-25
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\module-schema.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:ModulesDir = Join-Path $PSScriptRoot '..\modules'
    $script:ExpectedVersion = '6.1.2'
    $script:ExpectedModuleCount = 16
    $script:ExpectedTotalChecks = 3994

    if (-not (Test-Path $script:ModulesDir)) {
        throw "Modules directory not found at: $script:ModulesDir"
    }

    $script:ModuleFiles = Get-ChildItem -Path $script:ModulesDir -Filter 'module-*.ps1'
}

Describe 'Module Inventory' {
    It "Has exactly $script:ExpectedModuleCount module files" {
        $script:ModuleFiles.Count | Should -Be $script:ExpectedModuleCount
    }

    It 'Includes all 16 expected modules' {
        $expected = @(
            'module-acsc.ps1','module-cis.ps1','module-cisa.ps1','module-cmmc.ps1',
            'module-core.ps1','module-enisa.ps1','module-gdpr.ps1','module-hipaa.ps1',
            'module-iso27001.ps1','module-ms.ps1','module-ms-defenderatp.ps1',
            'module-nist.ps1','module-nsa.ps1','module-pcidss.ps1','module-soc2.ps1',
            'module-stig.ps1'
        )
        $actual = $script:ModuleFiles | ForEach-Object { $_.Name }
        foreach ($e in $expected) {
            $actual | Should -Contain $e
        }
    }
}

Describe 'Module File Encoding and Structure' {
    BeforeDiscovery {
        $modules = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\modules') -Filter 'module-*.ps1'
        $script:ModuleTestCases = @($modules | ForEach-Object {
            @{ Path = $_.FullName; Name = $_.Name }
        })
    }

    It 'Module <Name> contains no BOM bytes' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 3) {
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -Be $false
        }
    }

    It 'Module <Name> contains only ASCII characters' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $nonAscii = @($bytes | Where-Object { $_ -gt 127 })
        $nonAscii.Count | Should -Be 0
    }

    It 'Module <Name> has balanced braces' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $open = ([regex]::Matches($content, '\{')).Count
        $close = ([regex]::Matches($content, '\}')).Count
        ($open - $close) | Should -Be 0
    }

    It 'Module <Name> has comment-based help block' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match '<#'
        $content | Should -Match '\.SYNOPSIS'
        $content | Should -Match '#>'
    }

    It 'Module <Name> declares Version 6.1.2' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match '\$moduleVersion\s*=\s*[''"]6\.1\.2[''"]'
    }

    It 'Module <Name> declares $moduleName variable' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match '\$moduleName\s*=\s*[''"]'
    }

    It 'Module <Name> has exactly one return $results statement' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $retMatches = [regex]::Matches($content, 'return\s+\$results\b')
        $retMatches.Count | Should -Be 1
    }

    It 'Module <Name> declares param block' -ForEach $script:ModuleTestCases {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match 'param\s*\('
    }
}

Describe 'Module Code Quality' {
    BeforeDiscovery {
        $modules = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\modules') -Filter 'module-*.ps1'
        $script:ModuleTestCases2 = @($modules | ForEach-Object {
            @{ Path = $_.FullName; Name = $_.Name }
        })
    }

    It 'Module <Name> contains Add-Result helper' -ForEach $script:ModuleTestCases2 {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match 'function\s+Add-Result|Add-Result\s+'
    }

    It 'Module <Name> has try/catch error handling' -ForEach $script:ModuleTestCases2 {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match '\btry\s*\{'
        $content | Should -Match '\bcatch\s*\{'
    }

    It 'Module <Name> uses left-side $null comparisons' -ForEach $script:ModuleTestCases2 {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $rightSideNull = [regex]::Matches($content, '-(?:eq|ne)\s+\$null\b')
        $rightSideNull.Count | Should -Be 0
    }

    It 'Module <Name> contains check categories with hyphenated naming' -ForEach $script:ModuleTestCases2 {
        param($Path, $Name)
        $content = Get-Content -Path $Path -Raw
        $content | Should -Match '-Category\s+["''][\w]+\s*-\s*'
    }
}

Describe 'Module Check Counts (v6.1.2 baseline)' {
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
        $script:CountTestCases = @($script:ExpectedCounts.GetEnumerator() | ForEach-Object {
            @{
                Name = $_.Key
                Path = Join-Path $PSScriptRoot '..\modules' $_.Key
                ExpectedCount = $_.Value
            }
        })
    }

    It '<Name> has expected number of Add-Result calls (~<ExpectedCount>)' -ForEach $script:CountTestCases {
        param($Name, $Path, $ExpectedCount)
        $content = Get-Content -Path $Path -Raw
        $addResultMatches = [regex]::Matches($content, '\bAdd-Result\b')
        # Allow slight variance for auxiliary helper-function references
        $addResultMatches.Count | Should -BeGreaterOrEqual ($ExpectedCount - 5)
        $addResultMatches.Count | Should -BeLessOrEqual ($ExpectedCount + 5)
    }
}

Describe 'Project-Wide Aggregate Counts' {
    It "All modules collectively have $script:ExpectedTotalChecks Add-Result calls" {
        $total = 0
        foreach ($file in $script:ModuleFiles) {
            $content = Get-Content -Path $file.FullName -Raw
            $addResultMatches = [regex]::Matches($content, '\bAdd-Result\b')
            $total += $addResultMatches.Count
        }
        # Allow for +/-20 variance to accommodate small refactors
        $total | Should -BeGreaterOrEqual ($script:ExpectedTotalChecks - 20)
        $total | Should -BeLessOrEqual ($script:ExpectedTotalChecks + 20)
    }
}

Describe 'Orchestrator and Shared Library Schema' {
    It 'Windows-Security-Audit.ps1 exists and matches v6.1.2' {
        $orchPath = Join-Path $PSScriptRoot '..\Windows-Security-Audit.ps1'
        Test-Path $orchPath | Should -Be $true
        $content = Get-Content -Path $orchPath -Raw
        $content | Should -Match '\$script:ScriptVersion\s*=\s*[''"]6\.1\.2[''"]'
    }

    It 'shared_components/audit-common.ps1 exists and matches v6.1.2' {
        $libPath = Join-Path $PSScriptRoot '..\shared_components\audit-common.ps1'
        Test-Path $libPath | Should -Be $true
        $content = Get-Content -Path $libPath -Raw
        $content | Should -Match 'COMMON_LIB_VERSION\s*=\s*[''"]6\.1\.2[''"]'
    }

    It 'Orchestrator declares Show-DetailedHelp function' {
        $orchPath = Join-Path $PSScriptRoot '..\Windows-Security-Audit.ps1'
        $content = Get-Content -Path $orchPath -Raw
        $content | Should -Match 'function\s+Show-DetailedHelp'
    }

    It 'Orchestrator supports help aliases' {
        $orchPath = Join-Path $PSScriptRoot '..\Windows-Security-Audit.ps1'
        $content = Get-Content -Path $orchPath -Raw
        $content | Should -Match 'ValueFromRemainingArguments'
    }
}
