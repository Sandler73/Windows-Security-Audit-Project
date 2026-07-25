<#
.SYNOPSIS
    Pester tests for the role-based audit profiles component.
.DESCRIPTION
    Validates the profile catalog and declaration order, case-insensitive name
    resolution, HostFacts-driven profile suggestion precedence, and that every
    module referenced by a profile resolves to a module file on disk.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\profiles.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\profiles.ps1')
}

Describe 'Profile catalog' {
    It 'declares exactly the six built-in profiles in order' {
        Get-AuditProfileNames | Should -Be @('Workstation','MemberServer','DomainController','ServerCore','Minimal','Full')
    }
    It 'gives every profile a description and a non-empty module set' {
        foreach ($n in Get-AuditProfileNames) {
            $p = Get-AuditProfile -Name $n
            $p.Description | Should -Not -BeNullOrEmpty
            @($p.Modules).Count | Should -BeGreaterThan 0
        }
    }
    It 'Full covers all 16 modules' {
        @((Get-AuditProfile -Name Full).Modules).Count | Should -Be 16
    }
}

Describe 'Resolution behavior' {
    It 'resolves names case-insensitively' {
        (Get-AuditProfile -Name 'domaincontroller') | Should -Not -BeNullOrEmpty
    }
    It 'returns $null for unknown profiles' {
        Get-AuditProfile -Name 'DoesNotExist' | Should -BeNullOrEmpty
    }
    It 'every profile module reference resolves to a module file on disk' {
        $moduleDir = Join-Path $PSScriptRoot '..\modules'
        $onDisk = Get-ChildItem $moduleDir -Filter 'module-*.ps1' | ForEach-Object { $_.BaseName -replace '^module-','' }
        $nameMap = @{ 'ms-defenderatp'='MS-DefenderATP'; 'pcidss'='PCI-DSS' }
        foreach ($n in Get-AuditProfileNames) {
            foreach ($m in (Get-AuditProfile -Name $n).Modules) {
                $hit = $onDisk | Where-Object {
                    $canon = if ($nameMap.ContainsKey($_)) { $nameMap[$_] } else { $_ }
                    $canon -ieq $m
                } | Select-Object -First 1
                $hit | Should -Not -BeNullOrEmpty -Because "profile '$n' references module '$m'"
            }
        }
    }
}

Describe 'HostFacts suggestion' {
    It 'suggests DomainController when IsDomainController' {
        Get-SuggestedProfile -HostFacts @{ IsDomainController = $true; IsServer = $true } | Should -Be 'DomainController'
    }
    It 'suggests ServerCore before MemberServer' {
        Get-SuggestedProfile -HostFacts @{ IsDomainController = $false; IsServerCore = $true; IsServer = $true } | Should -Be 'ServerCore'
    }
    It 'suggests MemberServer for a plain server' {
        Get-SuggestedProfile -HostFacts @{ IsDomainController = $false; IsServerCore = $false; IsServer = $true } | Should -Be 'MemberServer'
    }
    It 'suggests Workstation for a client' {
        Get-SuggestedProfile -HostFacts @{ IsServer = $false } | Should -Be 'Workstation'
    }
    It 'returns $null with no facts' {
        Get-SuggestedProfile | Should -BeNullOrEmpty
    }
}
