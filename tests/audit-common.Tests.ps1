<#
.SYNOPSIS
    Pester unit tests for the shared foundation library (audit-common.ps1).
.DESCRIPTION
    Tests the 39 helper functions in shared_components/audit-common.ps1
    covering type-safety helpers, registry/service/policy queries, OS info,
    BitLocker, Defender, firewall, network, user, software, and v6.1.0+
    cross-cutting helpers (rollback, impact, correlation, baseline).
.NOTES
    Author: Windows Security Audit Project
    Version: 6.1.2
    Last Updated: 2026-04-25
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\audit-common.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:LibPath = Join-Path $PSScriptRoot '..\shared_components\audit-common.ps1'
    if (-not (Test-Path $script:LibPath)) {
        throw "Foundation library not found at: $script:LibPath"
    }
    . $script:LibPath
}

Describe 'Foundation Library Loading' {
    It 'Library file exists at expected path' {
        Test-Path $script:LibPath | Should -Be $true
    }

    It 'COMMON_LIB_VERSION variable is set' {
        $script:COMMON_LIB_VERSION | Should -Not -BeNullOrEmpty
    }

    It 'COMMON_LIB_VERSION matches v6.1.2' {
        $script:COMMON_LIB_VERSION | Should -Be '6.1.2'
    }

    It 'Library has no syntax errors when dot-sourced' {
        { . $script:LibPath } | Should -Not -Throw
    }
}

Describe 'ConvertTo-SafeInt' {
    It 'Converts numeric string to integer' {
        ConvertTo-SafeInt '42' | Should -Be 42
    }

    It 'Returns 0 for "None"' {
        ConvertTo-SafeInt 'None' | Should -Be 0
    }

    It 'Returns 0 for "Never"' {
        ConvertTo-SafeInt 'Never' | Should -Be 0
    }

    It 'Returns 0 for null' {
        ConvertTo-SafeInt $null | Should -Be 0
    }

    It 'Returns 0 for empty string' {
        ConvertTo-SafeInt '' | Should -Be 0
    }

    It 'Returns custom default for non-numeric' {
        ConvertTo-SafeInt -Value 'abc' -Default 99 | Should -Be 99
    }

    It 'Trims whitespace before parsing' {
        ConvertTo-SafeInt '  42  ' | Should -Be 42
    }

    It 'Handles negative numbers' {
        ConvertTo-SafeInt '-5' | Should -Be -5
    }

    It 'Handles zero correctly' {
        ConvertTo-SafeInt '0' | Should -Be 0
    }
}

Describe 'New-AuditResult' {
    It 'Creates result with all required fields' {
        $result = New-AuditResult -Module 'Test' `
            -Category 'Test - Category' `
            -Status 'Pass' -Severity 'Medium' `
            -Message 'Test passes' -Details 'Working'

        $result.Module | Should -Be 'Test'
        $result.Category | Should -Be 'Test - Category'
        $result.Status | Should -Be 'Pass'
        $result.Severity | Should -Be 'Medium'
        $result.Message | Should -Be 'Test passes'
    }

    It 'Includes Timestamp field' {
        $result = New-AuditResult -Module 'X' -Category 'X' `
            -Status 'Pass' -Severity 'Low' -Message 'OK' -Details ''
        $result.Timestamp | Should -Not -BeNullOrEmpty
    }

    It 'Defaults CrossReferences to empty hashtable' {
        $result = New-AuditResult -Module 'X' -Category 'X' `
            -Status 'Pass' -Severity 'Low' -Message 'OK' -Details ''
        $result.CrossReferences | Should -BeOfType [hashtable]
    }
}

Describe 'New-CheckId' {
    It 'Generates non-empty string identifier' {
        $id = New-CheckId -Framework 'CIS' -Category 'AccountPolicy' -Number 1
        $id | Should -Not -BeNullOrEmpty
        $id | Should -BeOfType [string]
    }

    It 'Generates same ID for same inputs' {
        $id1 = New-CheckId -Framework 'CIS' -Category 'AccountPolicy' -Number 1
        $id2 = New-CheckId -Framework 'CIS' -Category 'AccountPolicy' -Number 1
        $id1 | Should -Be $id2
    }

    It 'Generates different IDs for different inputs' {
        $id1 = New-CheckId -Framework 'CIS' -Category 'AccountPolicy' -Number 1
        $id2 = New-CheckId -Framework 'CIS' -Category 'AccountPolicy' -Number 2
        $id1 | Should -Not -Be $id2
    }

    It 'Embeds framework prefix in generated ID' {
        $id = New-CheckId -Framework 'STIG' -Category 'Logon' -Number 42
        $id | Should -Match '^STIG-'
    }

    It 'Pads number to 4 digits' {
        $id = New-CheckId -Framework 'NIST' -Category 'AC' -Number 7
        $id | Should -Match '0007$'
    }
}

Describe 'Get-OSInfo' {
    It 'Accepts -Cache parameter without error' {
        $cache = @{}
        { Get-OSInfo -Cache $cache } | Should -Not -Throw
    }

    It 'Returns object with OS version properties' {
        $os = Get-OSInfo
        $os | Should -Not -BeNullOrEmpty
    }

    It 'Returns cached value when Cache.OSInfo is pre-populated' {
        # Get-OSInfo is cache-aware: it READS from $Cache.OSInfo if populated
        # (e.g., by Invoke-CacheWarmUp). It does not write back to the cache
        # itself; cache population is the warm-up function's responsibility.
        # This test verifies the read path: pre-populate the cache and confirm
        # Get-OSInfo returns the cached value verbatim.
        $cache = @{
            OSInfo = @{
                ComputerName = 'TEST_HOST_FIXTURE'
                OSCaption    = 'Windows Test Edition'
                BuildNumber  = '99999'
            }
        }
        $result = Get-OSInfo -Cache $cache
        $result.ComputerName | Should -Be 'TEST_HOST_FIXTURE'
        $result.OSCaption    | Should -Be 'Windows Test Edition'
        $result.BuildNumber  | Should -Be '99999'
    }
}

Describe 'Get-BitLockerStatus' {
    It 'Accepts -Cache parameter without error' {
        $cache = @{}
        { Get-BitLockerStatus -Cache $cache } | Should -Not -Throw
    }

    It 'Returns hashtable with SystemDriveProtected key' {
        # Get-BitLockerStatus returns a [hashtable], not a [PSCustomObject].
        # Use .ContainsKey() (or .Keys) for membership checks; PSObject.Properties
        # on a hashtable returns [hashtable]'s intrinsic properties (Keys, Values,
        # Count, etc.), not the user-defined keys.
        $result = Get-BitLockerStatus
        $result | Should -BeOfType [hashtable]
        $result.ContainsKey('SystemDriveProtected') | Should -Be $true
    }

    It 'SystemDriveProtected is boolean-like (True/False/Unknown)' {
        $result = Get-BitLockerStatus
        $result.SystemDriveProtected | Should -BeIn @($true, $false, 'Unknown', $null)
    }

    It 'Returns expected hashtable schema (all standard keys present)' {
        $result = Get-BitLockerStatus
        $expectedKeys = @('IsEncrypted','SystemDriveProtected','ProtectionStatus',
                          'EncryptionMethod','VolumeStatus','KeyProtectors')
        foreach ($key in $expectedKeys) {
            $result.ContainsKey($key) | Should -Be $true -Because "expected key '$key' present"
        }
    }
}

Describe 'Get-CachedAuditPolicy' {
    It 'Returns parsed objects when Subcategory not specified' {
        $result = Get-CachedAuditPolicy
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Returns string when Subcategory specified' {
        $result = Get-CachedAuditPolicy -Subcategory 'Logon'
        if ($null -ne $result) {
            $result | Should -BeOfType [string]
        }
    }

    It 'Subcategory parameter is optional (no Mandatory prompt)' {
        $cmdInfo = Get-Command Get-CachedAuditPolicy
        $param = $cmdInfo.Parameters['Subcategory']
        $param.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.Mandatory | Should -Be $false }
    }
}

Describe 'Get-CachedRegistryValue' {
    It 'Returns null for non-existent registry path' {
        $result = Get-CachedRegistryValue `
            -Path 'HKLM:\SOFTWARE\NonExistent_Audit_Test_Key' `
            -Name 'X'
        $result | Should -BeNullOrEmpty
    }

    It 'Returns value for known existing registry path' {
        $result = Get-CachedRegistryValue `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -Name 'ProductName'
        $result | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-RegistryValue' {
    It 'Returns boolean for existing path/value' {
        $result = Test-RegistryValue `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -Name 'ProductName'
        $result | Should -BeOfType [bool]
    }

    It 'Returns false for non-existent path' {
        $result = Test-RegistryValue `
            -Path 'HKLM:\SOFTWARE\NonExistent_Audit_Test' `
            -Name 'X'
        $result | Should -Be $false
    }
}

Describe 'Get-CachedService' {
    It 'Returns service object for known service' {
        $svc = Get-CachedService -ServiceName 'wuauserv'
        $svc | Should -Not -BeNullOrEmpty
    }

    It 'Returns null for non-existent service' {
        $svc = Get-CachedService -ServiceName 'NonExistentService_Audit_Test'
        $svc | Should -BeNullOrEmpty
    }
}

Describe 'Test-ServiceEnabled and Test-ServiceRunning' {
    It 'Test-ServiceEnabled returns boolean' {
        $result = Test-ServiceEnabled -ServiceName 'wuauserv'
        $result | Should -BeOfType [bool]
    }

    It 'Test-ServiceRunning returns boolean' {
        $result = Test-ServiceRunning -ServiceName 'wuauserv'
        $result | Should -BeOfType [bool]
    }
}

Describe 'Initialize-AuditLogging' {
    It 'Creates log file with timestamp when LogFile not provided' {
        $tempRoot = Join-Path $TestDrive 'audit-test'
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

        Initialize-AuditLogging -ScriptRoot $tempRoot -Quiet

        $logsDir = Join-Path $tempRoot 'logs'
        Test-Path $logsDir | Should -Be $true

        $logFiles = Get-ChildItem -Path $logsDir -Filter 'audit-*.log'
        $logFiles.Count | Should -BeGreaterThan 0
    }

    It 'Uses specified LogFile path when provided' {
        $tempLog = Join-Path $TestDrive 'custom-audit.log'
        Initialize-AuditLogging -LogFile $tempLog -Quiet
        Test-Path $tempLog | Should -Be $true
    }
}

Describe 'Write-AuditLog' {
    BeforeEach {
        $script:logPath = Join-Path $TestDrive ('write-test-' + [guid]::NewGuid().ToString() + '.log')
        Initialize-AuditLogging -LogFile $script:logPath -Quiet
    }

    It 'Writes message to log file' {
        Write-AuditLog -Message 'Test message' -Level INFO
        $content = Get-Content $script:logPath -Raw
        $content | Should -Match 'Test message'
    }

    It 'Includes timestamp in log entry' {
        Write-AuditLog -Message 'Timestamp test' -Level INFO
        $content = Get-Content $script:logPath -Raw
        $content | Should -Match '\d{4}-\d{2}-\d{2}'
    }

    It 'Filters by log level (DEBUG below INFO not written)' {
        Initialize-AuditLogging -LogFile $script:logPath -LogLevel INFO -Quiet
        Write-AuditLog -Message 'Should not appear' -Level DEBUG
        $content = Get-Content $script:logPath -Raw
        $content | Should -Not -Match 'Should not appear'
    }
}

Describe 'v6.1.0 Cross-Cutting Helpers' {
    It 'ConvertTo-RegistryRollback function exists' {
        Get-Command ConvertTo-RegistryRollback -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'ConvertTo-ServiceRollback function exists' {
        Get-Command ConvertTo-ServiceRollback -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Get-RemediationImpact function exists' {
        Get-Command Get-RemediationImpact -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Get-RiskPriorityScore function exists' {
        Get-Command Get-RiskPriorityScore -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Find-CompensatingControls function exists' {
        Get-Command Find-CompensatingControls -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Find-CrossFrameworkCorrelations function exists' {
        Get-Command Find-CrossFrameworkCorrelations -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Compare-ToBaseline function exists' {
        Get-Command Compare-ToBaseline -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Export-RegistryPolicyFile function exists' {
        Get-Command Export-RegistryPolicyFile -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Test-InternetFacingHost function exists' {
        Get-Command Test-InternetFacingHost -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'Test-DomainControllerHost function exists' {
        Get-Command Test-DomainControllerHost -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-RiskPriorityScore' {
    It 'Returns integer in 1-100 range for Critical Fail' {
        $result = [PSCustomObject]@{
            Status = 'Fail'; Severity = 'Critical'
            Category = 'Core - Credential Protection'
            Message = 'LSA Protection disabled'
        }
        $score = Get-RiskPriorityScore -Result $result
        $score | Should -BeGreaterOrEqual 1
        $score | Should -BeLessOrEqual 100
    }

    It 'Returns lower score for Pass than Fail' {
        $passResult = [PSCustomObject]@{
            Status = 'Pass'; Severity = 'High'; Category = 'X'; Message = 'Y'
        }
        $failResult = [PSCustomObject]@{
            Status = 'Fail'; Severity = 'High'; Category = 'X'; Message = 'Y'
        }
        $passScore = Get-RiskPriorityScore -Result $passResult
        $failScore = Get-RiskPriorityScore -Result $failResult
        $passScore | Should -BeLessThan $failScore
    }
}

Describe 'Get-AuditCommonInfo' {
    It 'Returns library metadata object' {
        $info = Get-AuditCommonInfo
        $info | Should -Not -BeNullOrEmpty
    }

    It 'Includes Version field matching expected version' {
        $info = Get-AuditCommonInfo
        $info.Version | Should -Be '6.1.2'
    }

    It 'Includes HelperFunctions list' {
        $info = Get-AuditCommonInfo
        $info.HelperFunctions | Should -Not -BeNullOrEmpty
        # 38 helper functions in v6.1.2: 29 originals + 9 v6.1 additions
        # (ConvertTo-RegistryRollback, ConvertTo-ServiceRollback, Get-RemediationImpact,
        #  Get-RiskPriorityScore, Find-CompensatingControls, Find-CrossFrameworkCorrelations,
        #  Compare-ToBaseline, Export-RegistryPolicyFile, Test-InternetFacingHost,
        #  Test-DomainControllerHost) -- adjust this floor when adding new helpers.
        $info.HelperFunctions.Count | Should -BeGreaterOrEqual 38
    }
}
