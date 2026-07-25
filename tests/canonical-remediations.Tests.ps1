<#
.SYNOPSIS
    Pester tests for the canonical remediations component.
.DESCRIPTION
    Validates topic-table integrity, classifier accuracy across realistic finding
    phrasings including compressed forms, normalization behavior (variants unify to
    the canonical form; unclassified findings are preserved verbatim), and the
    value-independence flags.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\canonical-remediations.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\canonical-remediations.ps1')
}

Describe 'Topic table integrity' {
    It 'every topic declares Canonical, Rationale, ValueIndependent, and Match patterns' {
        $idx = Get-CanonicalTopicIndex
        foreach ($k in $idx.Keys) {
            $idx[$k].Canonical | Should -Not -BeNullOrEmpty
            $idx[$k].Rationale | Should -Not -BeNullOrEmpty
            $idx[$k].ContainsKey('ValueIndependent') | Should -BeTrue
            @($idx[$k].Match).Count | Should -BeGreaterThan 0
        }
    }
    It 'declares at least 25 topics' {
        (Get-CanonicalTopics).Count | Should -BeGreaterOrEqual 25
    }
}

Describe 'Classifier' {
    It 'classifies representative findings to the expected topics' {
        Get-RemediationTopic -Message 'SMB signing is not required' -Category 'NIST - SC' | Should -Be 'SmbSigningServer'
        Get-RemediationTopic -Message 'SMBv1 protocol is enabled' -Category 'CIS' | Should -Be 'SmbV1Protocol'
        Get-RemediationTopic -Message 'PowerShell script block logging disabled' -Category 'CIS' | Should -Be 'PowerShellScriptBlockLogging'
        Get-RemediationTopic -Message 'Security event log wraps in 3 days at current volume' -Category 'STIG - V2R8' | Should -Be 'SecurityEventLogSize'
        Get-RemediationTopic -Message 'Guest account is enabled' -Category 'HIPAA' | Should -Be 'GuestAccount'
    }
    It 'returns $null for findings outside the topic set' {
        Get-RemediationTopic -Message 'Kernel module xyz loaded' -Category 'Weird' | Should -BeNullOrEmpty
    }
    It 'classifies audit-logging phrasings surfaced by the 4a/4b audit' {
        # These missed before the audit fix (one-word ScriptBlockLogging; natural
        # 'Audit Policy logon' / 'Logon auditing' phrasings)
        Get-RemediationTopic -Message 'PowerShell ScriptBlockLogging disabled' -Category '' | Should -Be 'PowerShellScriptBlockLogging'
        Get-RemediationTopic -Message 'Audit Policy logon not configured' -Category '' | Should -Be 'AuditPolicyLogon'
        Get-RemediationTopic -Message 'Logon auditing not enabled' -Category '' | Should -Be 'AuditPolicyLogon'
    }
    It 'still distinguishes Audit Policy Change from Logon (order precedence holds)' {
        Get-RemediationTopic -Message 'Audit Policy Change not configured' -Category '' | Should -Be 'AuditPolicyChange'
    }
}

Describe 'Normalization' {
    It 'unifies variant fixes to the canonical form' {
        $norm = ConvertTo-CanonicalRemediation -Message 'PowerShell script block logging disabled' -Category 'NIST' -Remediation 'variant-form'
        $norm | Should -Match '-Type DWord'
    }
    It 'preserves unclassified remediation text verbatim and never invents fixes' {
        ConvertTo-CanonicalRemediation -Message 'Kernel module xyz loaded' -Category 'W' -Remediation 'original-fix' | Should -Be 'original-fix'
        ConvertTo-CanonicalRemediation -Message 'Kernel module xyz loaded' -Category 'W' -Remediation '' | Should -Be ''
    }
}

Describe 'Value independence' {
    It 'flags complete-as-is topics true and operator-value topics false' {
        Test-ValueIndependentTopic -Topic 'SmbSigningServer' | Should -BeTrue
        Test-ValueIndependentTopic -Topic 'PasswordMinLength' | Should -BeFalse
        Test-ValueIndependentTopic -Topic 'NoSuchTopic' | Should -BeFalse
    }
}
