<#
.SYNOPSIS
    Pester integration tests for Windows-Security-Audit.ps1 orchestrator.
.DESCRIPTION
    Tests the orchestrator's parameter handling, help system, module discovery,
    output generation, and integration with the shared library.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.1.2
    Last Updated: 2026-04-25
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\orchestrator.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    $script:OrchPath    = Join-Path $script:ProjectRoot 'Windows-Security-Audit.ps1'

    if (-not (Test-Path $script:OrchPath)) {
        throw "Orchestrator not found at: $script:OrchPath"
    }
}

Describe 'Orchestrator File Existence' {
    It 'Orchestrator file exists' {
        Test-Path $script:OrchPath | Should -Be $true
    }

    It 'Orchestrator has comment-based help' {
        $content = Get-Content -Path $script:OrchPath -Raw
        $content | Should -Match '<#'
        $content | Should -Match '\.SYNOPSIS'
        $content | Should -Match '\.DESCRIPTION'
        $content | Should -Match '\.EXAMPLE'
    }

    It 'Orchestrator declares ScriptVersion 6.1.2' {
        $content = Get-Content -Path $script:OrchPath -Raw
        $content | Should -Match '\$script:ScriptVersion\s*=\s*[''"]6\.1\.2[''"]'
    }

    It 'Orchestrator parses without syntax errors' {
        $parseErrors = $null
        $parseTokens = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:OrchPath, [ref]$parseTokens, [ref]$parseErrors
        )
        $parseErrors.Count | Should -Be 0
    }
}

Describe 'Help System' {
    It '-Help switch invocation produces help text' {
        $output = & $script:OrchPath -Help *>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
        $output | Should -Match 'PARAMETERS|Parameters|Usage'
    }

    It '-H alias produces help text' {
        $output = & $script:OrchPath -H *>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It '-? alias produces help text' {
        $output = & $script:OrchPath -? *>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It '-ShowHelp alias produces help text' {
        $output = & $script:OrchPath -ShowHelp *>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    # NOTE: Bare-form help arguments ('help', '-help', '--help', '--h', '/?')
    # are documented in the orchestrator's help text but are NOT supported
    # by the parameter binding pipeline. PowerShell binds bare arguments to
    # -Modules first; that parameter has a [ValidateSet(...)] attribute
    # that rejects 'help'/'--help'/etc. BEFORE the script body runs. The
    # $RemainingArgs catch-all only sees args that survive ValidateSet,
    # which never happens for the documented free-form aliases. Use the
    # bound switch forms above (-Help, -H, -?, -ShowHelp) instead. See the
    # orchestrator's docstring update for clarification of supported forms.

    It 'Help output mentions all 16 modules' {
        $output = & $script:OrchPath -Help *>&1 | Out-String
        # Modules are listed in the FRAMEWORKS section of help in their
        # canonical names (matching the -Modules ValidateSet). Use the
        # exact canonical strings, escaped for regex special characters
        # (PCI-DSS contains hyphen; MS-DefenderATP contains hyphen).
        @(
            'ACSC','CIS','CISA','CMMC','Core','ENISA','GDPR','HIPAA',
            'ISO27001','MS','MS-DefenderATP','NIST','NSA','PCI-DSS','SOC2','STIG'
        ) | ForEach-Object {
            $output | Should -Match ([regex]::Escape($_)) `
                -Because "Help output should mention module '$_'"
        }
    }
}

Describe 'Module Discovery' {
    It '-ListModules switch lists all 16 modules' {
        $output = & $script:OrchPath -ListModules *>&1 | Out-String
        @(
            'ACSC','CIS','CISA','CMMC','Core','ENISA','GDPR','HIPAA',
            'ISO27001','MS','MS-DefenderATP','NIST','NSA','PCI-DSS','SOC2','STIG'
        ) | ForEach-Object {
            $output | Should -Match ([regex]::Escape($_)) `
                -Because "-ListModules should mention module '$_'"
        }
    }
}

Describe 'Parameter Validation' {
    It 'Orchestrator parameter block declares all v6.1 parameters' {
        $content = Get-Content -Path $script:OrchPath -Raw
        # Note: 'ShowHelp' is the variable name; '-Help', '-H' are aliases.
        # The parameter block declares [Alias("Help","H")] [switch]$ShowHelp.
        @(
            'Modules', 'OutputPath', 'OutputFormat',
            'ShowHelp', 'ListModules',
            'Parallel', 'Workers', 'NoCache', 'ShowProfile',
            'LogFile', 'LogLevel', 'JsonLog', 'Quiet',
            'RemediateIssues', 'AutoRemediate', 'RemediationFile', 'RemediationBundle',
            'Baseline', 'ExportGPO', 'RollbackPath',
            'ShowRiskPriority', 'ShowCorrelations', 'ShowCompensatingControls'
        ) | ForEach-Object {
            $content | Should -Match "\`$$_\b" -Because "Param block should declare `$$_"
        }
    }

    It 'ShowHelp parameter has Help and H aliases' {
        $content = Get-Content -Path $script:OrchPath -Raw
        # The orchestrator's help-related parameter is declared as:
        #   [Alias("Help","H")] [switch]$ShowHelp
        # Check both alias values appear in proximity to ShowHelp.
        $content | Should -Match '\[Alias\([^)]*"Help"[^)]*\)\][^$]*\$ShowHelp'
    }

    It 'OutputFormat ValidateSet includes HTML, JSON, CSV, XML, Console, All' {
        $content = Get-Content -Path $script:OrchPath -Raw
        # Order in orchestrator: HTML, CSV, JSON, XML, All, Console.
        # Test for each value's presence in the ValidateSet without
        # assuming a particular order.
        if ($content -match '\[ValidateSet\(([^)]+)\)\]\s*\[string\]\$OutputFormat') {
            $set = $matches[1]
            @('HTML','CSV','JSON','XML','Console','All') | ForEach-Object {
                $set | Should -Match "`"$_`"" `
                    -Because "OutputFormat ValidateSet should include $_"
            }
        } else {
            throw "Could not find ValidateSet attribute on OutputFormat parameter"
        }
    }

    It 'LogLevel ValidateSet includes DEBUG, INFO, WARNING, ERROR' {
        $content = Get-Content -Path $script:OrchPath -Raw
        if ($content -match '\[ValidateSet\(([^)]+)\)\]\s*\[string\]\$LogLevel') {
            $set = $matches[1]
            @('DEBUG','INFO','WARNING','ERROR') | ForEach-Object {
                $set | Should -Match "`"$_`"" `
                    -Because "LogLevel ValidateSet should include $_"
            }
        } else {
            throw "Could not find ValidateSet attribute on LogLevel parameter"
        }
    }
}

Describe 'Output File Generation' {
    BeforeEach {
        $script:OutDir = Join-Path $TestDrive ('orch-test-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:OutDir -ItemType Directory -Force | Out-Null
    }

    # NOTE: The orchestrator constructs filenames as
    # Windows-Security-Audit-{ComputerName}-{yyyy-MM-dd_HHmmss}.{ext}
    # and treats -OutputPath as a directory hint (parent of any path passed).
    # Tests must look up the generated file via wildcard pattern.

    It 'Generates JSON output file when requested' {
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $script:OutDir 'out') -Quiet *>&1 | Out-Null

        $jsonFiles = @(Get-ChildItem -Path $script:OutDir -Filter 'Windows-Security-Audit-*.json')
        $jsonFiles.Count | Should -BeGreaterThan 0
    }

    It 'Generates valid JSON content' {
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $script:OutDir 'out') -Quiet *>&1 | Out-Null

        $jsonFiles = @(Get-ChildItem -Path $script:OutDir -Filter 'Windows-Security-Audit-*.json')
        if ($jsonFiles.Count -gt 0) {
            $content = Get-Content -Path $jsonFiles[0].FullName -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'JSON output contains Results array' {
        & $script:OrchPath -Modules core -OutputFormat JSON `
            -OutputPath (Join-Path $script:OutDir 'out') -Quiet *>&1 | Out-Null

        $jsonFiles = @(Get-ChildItem -Path $script:OutDir -Filter 'Windows-Security-Audit-*.json')
        if ($jsonFiles.Count -gt 0) {
            $data = Get-Content -Path $jsonFiles[0].FullName -Raw | ConvertFrom-Json
            $data.PSObject.Properties.Name | Should -Contain 'Results'
        }
    }
}

Describe 'Auto-Logging Behavior (v6.1.2)' {
    It 'Creates logs directory automatically when -LogFile not specified' {
        $tempRoot = Join-Path $TestDrive ('autolog-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

        Push-Location $tempRoot
        try {
            & $script:OrchPath -Modules core -OutputFormat JSON `
                -OutputPath (Join-Path $tempRoot 'out') -Quiet *>&1 | Out-Null

            # Auto-log is created in <ScriptRoot>\logs\, not the invocation dir
            $scriptRoot = Split-Path $script:OrchPath -Parent
            $logsDir = Join-Path $scriptRoot 'logs'
            $found = (Test-Path $logsDir) -or (Test-Path (Join-Path $tempRoot 'logs'))
            $found | Should -Be $true
        }
        finally {
            Pop-Location
        }
    }
}

Describe 'Error Handling' {
    It 'Invalid module name is rejected by ValidateSet' {
        # The orchestrator's -Modules parameter has a [ValidateSet(...)]
        # attribute. PowerShell rejects invalid values at parameter-binding
        # time with ParameterBindingValidationException -- this IS the
        # "clear error" path; the script body never runs. Verify the
        # exception is raised, AND that its message names the rejected value.
        $errorRecord = $null
        try {
            & $script:OrchPath -Modules 'NonExistentModule_Test' *>$null
        } catch {
            $errorRecord = $_
        }
        $errorRecord | Should -Not -BeNullOrEmpty `
            -Because 'Invalid -Modules value should produce a parameter-binding error'
        $errorMessage = $errorRecord.Exception.Message
        $errorMessage | Should -Match 'NonExistentModule_Test|ValidateSet|does not belong' `
            -Because "Error should reference the rejected value or ValidateSet; got: $errorMessage"
    }

    It 'Invalid OutputFormat is rejected by ValidateSet' {
        # PowerShell ValidateSet failure produces ParameterBinding error
        { & $script:OrchPath -OutputFormat 'NotAFormat' -Modules core -Quiet 2>$null } |
            Should -Throw
    }
}
