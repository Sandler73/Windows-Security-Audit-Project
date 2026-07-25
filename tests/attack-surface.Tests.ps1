<#
.SYNOPSIS
    Pester tests for the attack-surface assessment component.
.DESCRIPTION
    Validates the domain model and priority permutation, deterministic
    single-primary domain resolution with word-boundary matching and
    category-over-message precedence, false-positive resistance, reference-faithful
    exposure scoring and rating thresholds, and report rendering with encoded
    output.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\attack-surface.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\report-templates.ps1')
    . (Join-Path $PSScriptRoot '..\shared_components\attack-surface.ps1')
    function New-ASResult {
        param([string]$Module='M',[string]$Category,[string]$Status='Fail',[string]$Message,[string]$Severity='Medium',[string]$Remediation='')
        [PSCustomObject]@{ Module=$Module; Category=$Category; Status=$Status; Message=$Message; Details='d'; Remediation=$Remediation; Severity=$Severity; CrossReferences=@{}; Timestamp='t' }
    }
}

Describe 'Domain model integrity' {
    It 'declares ten domains with a valid priority permutation' {
        $script:AS_Domains.Count | Should -Be 10
        ($script:AS_DomainPriority | Sort-Object) | Should -Be (0..9)
    }
    It 'compiled one pattern per domain' {
        $script:AS_DomainPatterns.Count | Should -Be $script:AS_Domains.Count
    }
}

Describe 'Deterministic domain resolution' {
    It 'maps representative findings to their primary domain' {
        (Resolve-PrimaryDomain -Result (New-ASResult -Category 'STIG - Remote Desktop' -Message 'RDP requires no NLA')) |
            ForEach-Object { $script:AS_Domains[$_].Name } | Should -Be 'Remote Access'
        (Resolve-PrimaryDomain -Result (New-ASResult -Category 'Core - Credential' -Message 'WDigest caches plaintext')) |
            ForEach-Object { $script:AS_Domains[$_].Name } | Should -Be 'Credential Exposure'
    }
    It 'returns exactly one primary domain (no double-counting)' {
        # A finding whose text hits multiple domains still yields a single index
        $idx = Resolve-PrimaryDomain -Result (New-ASResult -Category 'X' -Message 'SMB signing and firewall port exposure')
        $idx | Should -BeGreaterOrEqual 0
        @($idx).Count | Should -Be 1
    }
    It 'returns -1 for findings with no domain keywords' {
        Resolve-PrimaryDomain -Result (New-ASResult -Category 'Totally Unrelated' -Message 'zzz nothing here') | Should -Be -1
    }
    It 'resists substring false positives via word boundaries' {
        # "SMBGhost" must not match \bsmb\b; the message has no other whole-word hit
        Resolve-PrimaryDomain -Result (New-ASResult -Category 'Commentary' -Message 'The SMBGhostiness writeup') | Should -Be -1
    }
    It 'prefers category over message' {
        # message mentions RDP, category mentions Defender; category wins
        $idx = Resolve-PrimaryDomain -Result (New-ASResult -Category 'Core - Defender realtime' -Message 'note: also affects rdp')
        $script:AS_Domains[$idx].Name | Should -Be 'Endpoint Protection'
    }
}

Describe 'Exposure scoring (reference-faithful)' {
    It 'gives a domain with a single Critical Fail a score of 100' {
        $s = Build-AttackSurface -AllResults @(New-ASResult -Category 'Remote Desktop' -Message 'RDP open' -Status 'Fail' -Severity 'Critical')
        ($s.Domains | Where-Object Name -eq 'Remote Access').ExposureScore | Should -Be 100
    }
    It 'counts a Pass in considered but contributes zero exposure' {
        $s = Build-AttackSurface -AllResults @(New-ASResult -Category 'Password Policy' -Message 'password length ok' -Status 'Pass')
        $s.TotalFindingsConsidered | Should -Be 1
        ($s.Domains | Where-Object Name -eq 'Authentication & Access').ExposureScore | Should -Be 0
    }
    It 'excludes unmapped findings from consideration entirely' {
        $s = Build-AttackSurface -AllResults @(New-ASResult -Category 'Unrelated' -Message 'zzz')
        $s.TotalFindingsConsidered | Should -Be 0
    }
    It 'assigns ratings by the reference thresholds' {
        Get-AttackSurfaceRating -Score 5   | Should -Be 'Minimal'
        Get-AttackSurfaceRating -Score 20  | Should -Be 'Low'
        Get-AttackSurfaceRating -Score 40  | Should -Be 'Moderate'
        Get-AttackSurfaceRating -Score 60  | Should -Be 'Elevated'
        Get-AttackSurfaceRating -Score 90  | Should -Be 'High'
    }
}

Describe 'Report rendering' {
    BeforeAll {
        $s = Build-AttackSurface -AllResults @(
            New-ASResult -Category 'Remote Desktop' -Message 'RDP open' -Status 'Fail' -Severity 'High' -Remediation 'fix'
            New-ASResult -Category 'Network' -Message 'firewall port exposed' -Status 'Warning' -Severity 'Medium'
        )
        $script:AsOut = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-as-" + [guid]::NewGuid().ToString('N') + ".html")
        Export-AttackSurfaceReport -Surface $s -OutputPath $AsOut -ExecutionInfo @{ ComputerName='H'; ScriptVersion='6.6.0' } | Out-Null
        $script:AsHtml = Get-Content $AsOut -Raw
    }
    AfterAll { if (Test-Path $AsOut) { Remove-Item $AsOut -Force -ErrorAction SilentlyContinue } }

    It 'renders the executive summary and collapsible domain sections' {
        $AsHtml | Should -Match 'Executive Summary: .* exposure \('
        ($AsHtml -split "id='asdomRemoteAccess'")[1].Substring(0,200) | Should -Match 'toggleModule'
    }
    It 'renders host identification cards instead of a header host line' {
        foreach ($card in 'Computer Name','Operating System','IP Address\(es\)','Scan Date') {
            $AsHtml | Should -Match ">$card<"
        }
        $AsHtml | Should -Not -Match 'Host: .*\|.*IP:'
    }
    It 'includes a table of contents linking the summary and each domain' {
        $AsHtml | Should -Match "class='toc'"
        $AsHtml | Should -Match "href='#asoverall'"
        $AsHtml | Should -Match "href='#asdom"
    }
    It 'leads with visuals: radial gauge, rating scale, and per-domain bar chart' {
        $AsHtml | Should -Match 'as-gauge'
        $AsHtml | Should -Match 'as-scale'
        $AsHtml | Should -Match 'as-bar-fill'
    }
    It 'spans the page rather than sitting inset' {
        $AsHtml | Should -Match 'main\{max-width:none'
    }
    It 'gives the summary cards coloured edges' {
        $AsHtml | Should -Match 'edge-total'
        $AsHtml | Should -Match 'edge-fail'
    }
    It 'sizes Status and Severity columns and keeps tables resizable' {
        $AsHtml | Should -Match 'col-status'
        $AsHtml | Should -Match 'col-severity'
        $AsHtml | Should -Match "<table class='findings'><thead>"
    }
    It 'uses the shared spine (theme toggle) and stamps the build' {
        $AsHtml | Should -Match 'toggleTheme'
        $AsHtml | Should -Match 'attack-surface report build'
    }
    It 'HTML-encodes finding content' {
        $s2 = Build-AttackSurface -AllResults @(New-ASResult -Category 'Remote Desktop' -Message '<script>alert(1)</script>' -Status 'Fail')
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-as2-" + [guid]::NewGuid().ToString('N') + ".html")
        try {
            Export-AttackSurfaceReport -Surface $s2 -OutputPath $tmp -ExecutionInfo @{} | Out-Null
            $g = Get-Content $tmp -Raw
            $g | Should -Not -Match '<script>alert'
            $g | Should -Match '&lt;script&gt;'
        } finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
    }
}
