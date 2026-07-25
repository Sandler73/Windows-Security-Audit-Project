<#
.SYNOPSIS
    Pester tests for the rollback generator component.
.DESCRIPTION
    Validates read-only capture with error-record discipline, safe-path refusal,
    absent-value semantics, plan capture, and the generated rollback script:
    reverse restore order, typed confirmation, per-record guards, failure
    aggregation, and that the generated script itself parses cleanly.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\rollback-generator.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\canonical-remediations.ps1')
    . (Join-Path $PSScriptRoot '..\shared_components\remediation-library.ps1')
    . (Join-Path $PSScriptRoot '..\shared_components\rollback-generator.ps1')
}

Describe 'Capture is read-only and never throws' {
    It 'captures a present registry value with its kind' {
        Mock Get-ItemProperty { [PSCustomObject]@{ RunAsPPL = 1 } }
        Mock Get-Item { $o = [PSCustomObject]@{}; $o | Add-Member ScriptMethod GetValueKind { param($n) 'DWord' } -PassThru }
        $r = Invoke-RollbackCapture -Spec @{ Type='registry_value'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RunAsPPL' }
        $r.State.Value | Should -Be 1
        $r.Error | Should -BeNullOrEmpty
    }
    It 'records absent registry values as absent (not an error)' {
        Mock Get-ItemProperty { throw [System.Management.Automation.ItemNotFoundException]::new('x') }
        $r = Invoke-RollbackCapture -Spec @{ Type='registry_value'; Path='HKLM:\X'; Name='Y' }
        $r.State | Should -Be 'absent'
        $r.Error | Should -BeNullOrEmpty
    }
    It 'converts collector failures into error records instead of throwing' {
        Mock Get-Service { throw 'no such service' }
        $r = Invoke-RollbackCapture -Spec @{ Type='service_state'; Name='Nope' }
        $r.Error | Should -Not -BeNullOrEmpty
    }
    It 'refuses unsafe file paths' {
        $r = Invoke-RollbackCapture -Spec @{ Type='file_content'; Path='..\..\etc\passwd' }
        $r.Error | Should -Match 'safe-path'
    }
    It 'flags unknown capture types as errors' {
        (Invoke-RollbackCapture -Spec @{ Type='bogus'; Name='x' }).Error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Plan capture' {
    It 'produces a record per capture spec and a none-record for capture-less steps' {
        Mock Get-LocalUser { [PSCustomObject]@{ Name='Guest'; Enabled=$true } }
        $plan = New-RemediationPlan -Topics @('GuestAccount','DefenderSignatures')
        $records = Invoke-PlanCapture -Plan $plan
        @($records | Where-Object { $_.Topic -eq 'DefenderSignatures' -and $_.Type -eq 'none' }).Count | Should -Be 1
    }
}

Describe 'Generated rollback script' {
    BeforeAll {
        $regPresent = New-CaptureRecord -Type 'registry_value' -Target 'HKLM:\SW\K::V' -State @{ Value = 5; Kind = 'DWord' }
        $regAbsent  = New-CaptureRecord -Type 'registry_value' -Target 'HKLM:\SW\K::Gone' -State 'absent'
        $svc        = New-CaptureRecord -Type 'service_state' -Target 'W32Time' -State @{ Status='Running'; StartType='Automatic' }
        $manual     = New-CaptureRecord -Type 'manual' -Target 'MANUAL' -State 'note' -Note 'Back up recovery key first'
        $script:OutFile = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-rbk-" + [guid]::NewGuid().ToString('N') + ".ps1")
        New-RollbackScript -CaptureRecords @($regPresent,$regAbsent,$svc,$manual) -OutputPath $OutFile | Out-Null
        $script:Gen = Get-Content $OutFile -Raw
    }
    AfterAll { if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue } }

    It 'requires a typed confirmation before restoring' {
        $Gen | Should -Match 'Read-Host'
        $Gen | Should -Match 'ROLLBACK'
    }
    It 'restores in reverse capture order (LIFO): manual step precedes the first captured value' {
        $Gen.IndexOf('MANUAL STEP') | Should -BeLessThan $Gen.IndexOf('::V'.Replace('::V','V ='))
    }
    It 'removes values that were absent before remediation' {
        $Gen | Should -Match "Remove-ItemProperty .*-Name 'Gone'"
    }
    It 'restores present values with their registry kind' {
        $Gen | Should -Match '-Value 5 -Type DWord'
    }
    It 'guards every restore and aggregates failures with a nonzero exit' {
        ([regex]::Matches($Gen,'\} catch \{')).Count | Should -BeGreaterOrEqual 3
        $Gen | Should -Match 'exit 2'
    }
    It 'parses clean as a standalone script' {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($OutFile, [ref]$tokens, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0
    }
}
