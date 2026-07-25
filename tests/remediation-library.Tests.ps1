<#
.SYNOPSIS
    Pester tests for the remediation library and bundles components.
.DESCRIPTION
    Validates topic-to-entry coverage in both directions, single-source resolution of
    apply commands from the canonical table, rollback-capture typing, the three-state
    verification contract, remediation plan ordering and aggregation, bundle
    integrity, impact-to-confirmation-tier mapping, and the deprecated v6.1 bundle
    name aliases.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\remediation-library.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\canonical-remediations.ps1')
    . (Join-Path $PSScriptRoot '..\shared_components\remediation-library.ps1')
    . (Join-Path $PSScriptRoot '..\shared_components\remediation-bundles.ps1')
    $script:KnownCaptureTypes = @('registry_value','service_state','security_policy','audit_policy',
        'mp_preference','smb_server_config','windows_feature','manual','local_user_enabled','eventlog_size')
}

Describe 'Topic and entry coverage' {
    It 'every canonical topic has a library entry and no entry is orphaned' {
        $topics = @(Get-CanonicalTopics)
        $entries = Get-RemediationEntries
        foreach ($t in $topics) { $entries.Contains($t) | Should -BeTrue -Because "topic '$t' needs a library entry" }
        foreach ($k in $entries.Keys) { $topics | Should -Contain $k }
    }
    It 'resolves every Apply command from the canonical table (single source of truth)' {
        $entries = Get-RemediationEntries
        foreach ($k in $entries.Keys) {
            $entries[$k].Apply | Should -Be (Get-CanonicalRemediation -Topic $k)
        }
    }
    It 'declares only known rollback capture types' {
        $entries = Get-RemediationEntries
        foreach ($k in $entries.Keys) {
            foreach ($c in $entries[$k].RollbackCapture) { $KnownCaptureTypes | Should -Contain $c.Type }
        }
    }
    It 'declares a valid impact profile on every entry' {
        $entries = Get-RemediationEntries
        foreach ($k in $entries.Keys) {
            @('None','RestartService','RequireReboot','BreakSessions','BreakNetwork','BreakBoot') | Should -Contain $entries[$k].Impact
        }
    }
}

Describe 'Verification contract' {
    It 'returns $true when the setting is applied' {
        Mock Get-ItemProperty { [PSCustomObject]@{ RunAsPPL = 1 } }
        Test-RemediationApplied -Topic 'LsaProtection' | Should -BeTrue
    }
    It 'returns $false when the setting is absent or wrong' {
        Mock Get-ItemProperty { throw 'absent' }
        Test-RemediationApplied -Topic 'LsaProtection' | Should -BeFalse
    }
    It 'returns $null for unknown topics and never throws' {
        Test-RemediationApplied -Topic 'DoesNotExist' | Should -BeNullOrEmpty
    }
}

Describe 'Plan building' {
    It 'orders steps lowest-impact first and aggregates correctly' {
        $plan = Build-RemediationPlan -Topics @('BitLockerSystemDrive','GuestAccount','SmbSigningServer')
        $plan.Steps[0].Topic | Should -Be 'GuestAccount'
        $plan.Steps[-1].Topic | Should -Be 'BitLockerSystemDrive'
        $plan.MaxImpact | Should -Be 'BreakBoot'
        $plan.RequiresReboot | Should -BeTrue
    }
    It 'segregates unknown topics instead of failing or inventing steps' {
        $plan = Build-RemediationPlan -Topics @('GuestAccount','FakeTopic')
        $plan.Steps.Count | Should -Be 1
        $plan.UnknownTopics | Should -Contain 'FakeTopic'
    }
    It 'contains no execution machinery (data only)' {
        $plan = Build-RemediationPlan -Topics @('GuestAccount')
        $plan.PSObject.Properties.Name | Should -Not -Contain 'Execute'
    }
}

Describe 'Bundles' {
    It 'declares ten bundles whose topic references all resolve' {
        $entries = Get-RemediationEntries
        $names = Get-RemediationBundleNames
        $names.Count | Should -Be 10
        foreach ($n in $names) {
            foreach ($t in (Get-RemediationBundle -Name $n).Topics) { $entries.Contains($t) | Should -BeTrue }
        }
    }
    It 'covers every canonical topic in at least one bundle' {
        $bundled = @(Get-RemediationBundleNames | ForEach-Object { (Get-RemediationBundle -Name $_).Topics }) | Select-Object -Unique
        foreach ($t in (Get-CanonicalTopics)) { $bundled | Should -Contain $t }
    }
    It 'maps impacts to confirmation tiers conservatively' {
        Get-ConfirmationTier -Impact 'None' | Should -Be 1
        Get-ConfirmationTier -Impact 'BreakSessions' | Should -Be 2
        Get-ConfirmationTier -Impact 'BreakBoot' | Should -Be 3
        Get-ConfirmationTier -Impact 'SomethingNew' | Should -Be 3
    }
    It 'EncryptionAtRest is Tier 3 with the recovery-key prerequisite' {
        $p = Get-BundlePlan -Name 'EncryptionAtRest'
        $p.ConfirmationTier | Should -Be 3
        ($p.Prerequisites -join ' ') | Should -Match 'recovery key'
    }
    It 'resolves bundle names case-insensitively' {
        (Get-BundlePlan -Name 'credentialhardening').Name | Should -Be 'credentialhardening'
    }
}

Describe 'v6.1 bundle-name aliases (option B migration)' {
    It 'identifies v6.1 aliases and not v6.4 canonical names' {
        Test-IsV61BundleAlias -Name 'LockDownRDP'  | Should -BeTrue
        Test-IsV61BundleAlias -Name 'SmbHardening' | Should -BeFalse
    }
    It 'passes canonical names through unchanged' {
        Resolve-BundleName -Name 'CredentialHardening' -Quiet | Should -Be @('CredentialHardening')
    }
    It 'maps single-bundle aliases correctly' {
        Resolve-BundleName -Name 'DisableLegacyProtocols' -Quiet | Should -Be @('SmbHardening')
        Resolve-BundleName -Name 'LockDownRDP' -Quiet | Should -Be @('RemoteAccessHardening')
    }
    It 'maps multi-bundle aliases to the ordered union of their topics (deduped)' {
        $topics = @(Get-ResolvedBundleTopics -Name 'HardenAuthentication' -Quiet)
        $topics | Should -Contain 'LsaProtection'
        $topics | Should -Contain 'UacEnableLua'
        $topics | Should -Not -Contain 'SmbSigningServer'
        ($topics | Select-Object -Unique).Count | Should -Be $topics.Count
    }
    It 'resolves EssentialEightLevel1 across four bundles without duplicates' {
        $topics = @(Get-ResolvedBundleTopics -Name 'EssentialEightLevel1' -Quiet)
        $topics.Count | Should -Be 8
        ($topics | Select-Object -Unique).Count | Should -Be 8
    }
    It 'returns empty for unknown names' {
        Resolve-BundleName -Name 'NotARealBundle' -Quiet | Should -BeNullOrEmpty
    }
    It 'emits a deprecation warning for aliases but not canonical names' {
        $w = $null
        Resolve-BundleName -Name 'LockDownRDP' -WarningVariable w -WarningAction SilentlyContinue | Out-Null
        @($w).Count | Should -BeGreaterOrEqual 1
        $w2 = $null
        Resolve-BundleName -Name 'RemoteAccessHardening' -WarningVariable w2 -WarningAction SilentlyContinue | Out-Null
        @($w2).Count | Should -Be 0
    }
    It 'accepts every v6.1 alias and v6.4 canonical name via Get-AllBundleNames' {
        $all = Get-AllBundleNames
        foreach ($n in @('CredentialHardening','SmbHardening','DisableLegacyProtocols','EssentialEightLevel1')) {
            $all | Should -Contain $n
        }
        $all.Count | Should -Be 15
    }
}
