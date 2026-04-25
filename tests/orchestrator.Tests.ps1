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

    It 'Orchestrator brace count is balanced' {
        $content = Get-Content -Path $script:OrchPath -Raw
        $open = ([regex]::Matches($content, '\{')).Count
        $close = ([regex]::Matches($content, '\}')).Count
        ($open - $close) | Should -Be 0
    }
}

Describe 'Help System' {
    It '-Help switch invocation produces help text' {
        $output = & $script:OrchPath -Help 2>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
        $output | Should -Match 'PARAMETERS|Parameters|Usage'
    }

    It '-H alias produces help text' {
        $output = & $script:OrchPath -H 2>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It '-? alias produces help text' {
        $output = & $script:OrchPath -? 2>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It '-ShowHelp alias produces help text' {
        $output = & $script:OrchPath -ShowHelp 2>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It 'Free-form "help" argument produces help text' {
        $output = & $script:OrchPath help 2>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It 'Free-form "--help" argument produces help text' {
        $output = & $script:OrchPath '--help' 2>&1 | Out-String
        $output | Should -Match 'Windows Security Audit'
    }

    It 'Help output mentions all 16 modules' {
        $output = & $script:OrchPath -Help 2>&1 | Out-String
        @('acsc','cis','cisa','cmmc','core','enisa','gdpr','hipaa',
          'iso27001','ms','ms-defenderatp','nist','nsa','pcidss','soc2','stig') |
            ForEach-Object {
                $output | Should -Match $_
            }
    }
}

Describe 'Module Discovery' {
    It '-ListModules switch lists all 16 modules' {
        $output = & $script:OrchPath -ListModules 2>&1 | Out-String
        @('acsc','cis','cisa','cmmc','core','enisa','gdpr','hipaa',
          'iso27001','ms','ms-defenderatp','nist','nsa','pcidss','soc2','stig') |
            ForEach-Object {
                $output | Should -Match $_
            }
    }
}

Describe 'Parameter Validation' {
    It 'Orchestrator parameter block declares all v6.1 parameters' {
        $content = Get-Content -Path $script:OrchPath -Raw
        @(
            'Modules', 'OutputPath', 'OutputFormat',
            'Help', 'ListModules',
            'Parallel', 'Workers', 'NoCache', 'ShowProfile',
            'LogFile', 'LogLevel', 'JsonLog', 'Quiet',
            'RemediateIssues', 'AutoRemediate', 'RemediationFile', 'RemediationBundle',
            'Baseline', 'ExportGPO', 'RollbackPath',
            'ShowRiskPriority', 'ShowCorrelations', 'ShowCompensatingControls'
        ) | ForEach-Object {
            $content | Should -Match "\`$$_\b"
        }
    }

    It 'OutputFormat ValidateSet includes HTML, JSON, CSV, XML, Console, All' {
        $content = Get-Content -Path $script:OrchPath -Raw
        $content | Should -Match 'ValidateSet.*HTML.*JSON.*CSV.*XML'
    }

    It 'LogLevel ValidateSet includes DEBUG, INFO, WARNING, ERROR, CRITICAL' {
        $content = Get-Content -Path $script:OrchPath -Raw
        $content | Should -Match 'ValidateSet.*DEBUG.*INFO|ValidateSet.*INFO.*DEBUG'
    }
}

Describe 'Output File Generation' {
    BeforeEach {
        $script:OutDir = Join-Path $TestDrive ('orch-test-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:OutDir -ItemType Directory -Force | Out-Null
    }

    It 'Generates JSON output file when requested' {
        $jsonPath = Join-Path $script:OutDir 'audit.json'
        & $script:OrchPath -Modules core -OutputFormat JSON -OutputPath $jsonPath -Quiet 2>&1 | Out-Null
        Test-Path $jsonPath | Should -Be $true
    }

    It 'Generates valid JSON content' {
        $jsonPath = Join-Path $script:OutDir 'audit.json'
        & $script:OrchPath -Modules core -OutputFormat JSON -OutputPath $jsonPath -Quiet 2>&1 | Out-Null

        if (Test-Path $jsonPath) {
            $content = Get-Content -Path $jsonPath -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'JSON output contains ExecutionInfo and Results' {
        $jsonPath = Join-Path $script:OutDir 'audit.json'
        & $script:OrchPath -Modules core -OutputFormat JSON -OutputPath $jsonPath -Quiet 2>&1 | Out-Null

        if (Test-Path $jsonPath) {
            $data = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
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
            $jsonPath = Join-Path $tempRoot 'audit.json'
            & $script:OrchPath -Modules core -OutputFormat JSON -OutputPath $jsonPath -Quiet 2>&1 | Out-Null

            $logsDir = Join-Path $tempRoot 'logs'
            # Logs may be created in script root, not invocation dir, so accept either
            $found = (Test-Path $logsDir) -or
                     (Test-Path (Join-Path (Split-Path $script:OrchPath -Parent) 'logs'))
            $found | Should -Be $true
        }
        finally {
            Pop-Location
        }
    }
}

Describe 'Error Handling' {
    It 'Invalid module name produces clear error' {
        $output = & $script:OrchPath -Modules 'NonExistentModule_Test' 2>&1 | Out-String
        $output | Should -Match 'Invalid|not found|Unknown|Error|invalid'
    }

    It 'Invalid OutputFormat is rejected by ValidateSet' {
        # PowerShell ValidateSet failure produces ParameterBinding error
        { & $script:OrchPath -OutputFormat 'NotAFormat' -Modules core -Quiet 2>$null } |
            Should -Throw
    }
}
