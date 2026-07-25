<#
.SYNOPSIS
    Pester tests for the per-framework tailored split-report renderers.
.DESCRIPTION
    Validates the framework specification table, per-framework tailoring contracts
    (native scoring, framework panels, HIPAA current-versus-proposed separation),
    the shared interactive spine (theme toggle, centered header, collapsibility,
    search and export controls), HTML encoding safety, and the format-aware
    export driver.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\report-templates.Tests.ps1 -Output Detailed
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\shared_components\report-templates.ps1')

    function New-TestResult {
        param([string]$Module,[string]$Category,[string]$Status,[string]$Message,
              [string]$Severity='Medium',[hashtable]$CrossReferences=@{},
              [string]$Remediation='',[string]$Details='ctx')
        [PSCustomObject]@{
            Module=$Module; Category=$Category; Status=$Status; Message=$Message
            Details=$Details; Remediation=$Remediation; Severity=$Severity
            CrossReferences=$CrossReferences; Timestamp='2026-01-01 00:00:00'
        }
    }
    $script:ExecInfo = @{ ComputerName='PESTERHOST'; OSVersion='Windows'; StartTime='2026-01-01'; ScriptVersion='6.6.0' }
}

Describe 'Framework report specifications' {
    It 'registers a spec for all 16 frameworks' {
        $script:FrameworkReportSpecs.Keys.Count | Should -Be 16
    }
    It 'every spec declares DisplayName, Authority, GroupLabel, Scoring' {
        foreach ($k in $script:FrameworkReportSpecs.Keys) {
            $s = $script:FrameworkReportSpecs[$k]
            $s.DisplayName | Should -Not -BeNullOrEmpty
            $s.Authority   | Should -Not -BeNullOrEmpty
            $s.GroupLabel  | Should -Not -BeNullOrEmpty
            $s.Scoring     | Should -BeIn @('passfail','stig')
        }
    }
}

Describe 'STIG renderer tailoring' {
    BeforeAll {
        $r = @(
            New-TestResult 'STIG' 'STIG - Account Policies (CAT II)' 'Pass' 'ok' 'Medium' @{ STIG='V-253298' }
            New-TestResult 'STIG' 'STIG - UAC (CAT I)' 'Fail' 'bad' 'Critical' @{ STIG='V-253451' } 'Fix-It'
        )
        $script:StigHtml = New-FrameworkReportHtml -ModuleName 'STIG' -Results $r -ExecutionInfo $ExecInfo
    }
    It 'scores as Open / Not a Finding' {
        $StigHtml | Should -Match 'Not a Finding'
        $StigHtml | Should -Match '>Open<'
    }
    It 'renders the CAT distribution panel' {
        $StigHtml | Should -Match 'Severity Category Distribution'
    }
    It 'includes a populated V-ID column' {
        $StigHtml | Should -Match 'V-253451'
    }
}

Describe 'CMMC renderer tailoring' {
    It 'renders the SPRS panel with the extracted score' {
        $r = @(New-TestResult 'CMMC' 'CMMC - SPRS Scoring' 'Info' 'SPRS Score: 95 / 110 (High)' 'Informational')
        $html = New-FrameworkReportHtml -ModuleName 'CMMC' -Results $r -ExecutionInfo $ExecInfo
        $html | Should -Match 'SPRS Score \(DoD Methodology\)'
        $html | Should -Match '>95 <'
    }
}

Describe 'PCI renderer tailoring' {
    It 'renders the mandatory-since-2025 panel' {
        $r = @(New-TestResult 'PCI-DSS' 'PCI-DSS - Mandatory v4.0.1 Reqs' 'Warning' '8.4.2 unverified' 'High')
        $html = New-FrameworkReportHtml -ModuleName 'PCI-DSS' -Results $r -ExecutionInfo $ExecInfo
        $html | Should -Match 'Mandatory Since 2025-03-31'
    }
}

Describe 'HIPAA renderer tailoring' {
    BeforeAll {
        $r = @(
            New-TestResult 'HIPAA' 'HIPAA - Technical Safeguards' 'Pass' 'current ok'
            New-TestResult 'HIPAA' 'HIPAA - Technical Safeguards' 'Fail' 'current gap'
            New-TestResult 'HIPAA' 'HIPAA - Proposed Rule (NPRM)' 'Info' 'PROPOSED: MFA' 'Informational'
        )
        $script:HipHtml = New-FrameworkReportHtml -ModuleName 'HIPAA' -Results $r -ExecutionInfo $ExecInfo
    }
    It 'renders proposed indicators in a separate, explicitly-labeled section' {
        $HipHtml | Should -Match 'NOT Current Requirements'
    }
    It 'excludes proposed indicators from the compliance denominator' {
        # 1 pass / 2 scored = 50%; would be a different figure if the Info
        # proposed row leaked into scoring or grouping
        $HipHtml | Should -Match '50(\.0)?`?% compliant'
    }
}

Describe 'Spine styling and interaction contract (all frameworks)' {
    BeforeAll {
        $r = @(New-TestResult 'NIST' 'NIST - AC Access Control' 'Pass' 'ok')
        $script:SpineHtml = New-FrameworkReportHtml -ModuleName 'NIST' -Results $r -ExecutionInfo $ExecInfo
    }
    It 'ships the light/dark toggle with dark as the default state (operator direction 2026-07)' {
        $SpineHtml | Should -Match "data-theme='dark'"
        $SpineHtml | Should -Match 'toggleTheme'
        $SpineHtml | Should -Match 'theme-slider'
        $SpineHtml | Should -Match ':root\{--bg-primary:#ffffff'
    }
    It 'centers the report header' {
        $SpineHtml | Should -Match 'header\{[^}]*text-align:center'
    }
    It 'uses Garamond and the shared CSS variable scheme' {
        $SpineHtml | Should -Match 'Garamond'
        $SpineHtml | Should -Match '--bg-primary'
        $SpineHtml | Should -Match '--accent'
    }
    It 'makes the executive summary, TOC, and remediation index collapsible' {
        foreach ($id in 'exec','toc','remediation') {
            ($SpineHtml -split "id='$id'")[1].Substring(0, 260) | Should -Match 'toggleModule'
        }
    }
    It 'ships the full interaction set: donut filter, include/exclude search, per-column filters, resize, column visibility, selection, export modal' {
        $SpineHtml | Should -Match 'dashboardFilter'
        $SpineHtml | Should -Match 'Exclude matches'
        $SpineHtml | Should -Match 'filterColumn'
        $SpineHtml | Should -Match 'initResizeHandles'
        $SpineHtml | Should -Match 'toggleColumnVisibility'
        $SpineHtml | Should -Match 'toggleSelectAll'
        $SpineHtml | Should -Match "executeExport\('xls'\)"
    }
    It 'includes a print stylesheet that hides interactive controls' {
        $SpineHtml | Should -Match '@media print'
        $SpineHtml | Should -Match 'theme-toggle,\.global-controls'
    }
}

Describe 'Regulatory and Framework Context sub-section' {
    It 'nests framework panels under the collapsible framework-context sub-section' {
        $r = @(New-TestResult 'CMMC' 'CMMC - SPRS Scoring' 'Info' 'SPRS Score: 95 / 110 (High)' 'Informational')
        $html = New-FrameworkReportHtml -ModuleName 'CMMC' -Results $r -ExecutionInfo $ExecInfo
        $html | Should -Match ($script:FrameworkSectionTitle)
        $html | Should -Match "id='fwsection'"
        $html | Should -Match "id='fwpanel1'"
    }
}

Describe 'HTML encoding safety' {
    It 'encodes hostile content in messages' {
        $r = @(New-TestResult 'NIST' 'NIST - AC Access Control' 'Fail' '<script>alert(1)</script>')
        $html = New-FrameworkReportHtml -ModuleName 'NIST' -Results $r -ExecutionInfo $ExecInfo
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
    }
}

Describe 'Round 2 spine additions (operator parity feedback 2026-07-21)' {
    BeforeAll {
        $r = @(
            New-TestResult 'NIST' 'NIST - AC Access Control' 'Fail' 'lockout gap' 'Critical' @{} 'Fix-AC7'
            New-TestResult 'NIST' 'NIST - SI System Integrity' 'Pass' 'ok'
        )
        $ei = @{ ComputerName='PESTERHOST'; OSVersion='Windows'; StartTime='2026-01-01'; ScriptVersion='6.6.0'; IPAddresses=@('10.0.0.5'); ScanDate='2026-01-01' }
        $script:R2Html = New-FrameworkReportHtml -ModuleName 'NIST' -Results $r -ExecutionInfo $ei
    }
    It 'renders host identification as composite-style info cards, not a collapsible section' {
        foreach ($card in 'Computer Name','Operating System','IP Address\(es\)','Scan Date','Module') {
            $R2Html | Should -Match ">$card<"
        }
        $R2Html | Should -Match '10\.0\.0\.5'
        $R2Html | Should -Match "class='info-grid'"
        $R2Html | Should -Not -Match "id='hostinfo'"
    }
    It 'does not restate host detail in the header (the cards carry it)' {
        $R2Html | Should -Not -Match "class='hostline'"
    }
    It 'places the result cards beside the donut' {
        $R2Html | Should -Match "class='donut-row'"
    }
    It 'colours the Overall Compliance cards by band' {
        $R2Html | Should -Match 'verdict-(pass|warn|fail)'
    }
    It 'sizes Status and Severity columns to their vocabularies' {
        $R2Html | Should -Match 'col-status'
        $R2Html | Should -Match 'col-severity'
        $R2Html | Should -Match 'th\.col-status\{width:104px\}'
    }
    It 'makes every table resizable, including the mini tables' {
        $R2Html | Should -Match 'table\.findings th, table\.mini th'
    }
    It 'renders the Result Distribution six-card panel' {
        $R2Html | Should -Match 'Result Distribution'
        foreach ($card in 'Total','Passed','Failed','Warnings','Info','Errors') { $R2Html | Should -Match ">$card<" }
    }
    It 'renders Overall Compliance with the weighted, rating, simple, and severity-adjusted cards' {
        $R2Html | Should -Match '>Overall Compliance<'
        foreach ($card in 'Weighted Score','Overall Rating','Simple Score','Severity-Adjusted Score') {
            $R2Html | Should -Match ([regex]::Escape($card))
        }
    }
    It 'derives the Overall Rating verdict from the weighted score' {
        $low = @(New-TestResult 'NIST' 'NIST - AC' 'Fail' 'bad' 'High')
        (New-FrameworkReportHtml -ModuleName 'NIST' -Results $low -ExecutionInfo $ExecInfo) | Should -Match "verdict-fail'><h3>Overall Rating"
        $high = @(1..9 | ForEach-Object { New-TestResult 'NIST' 'NIST - AC' 'Pass' "ok$_" }) + @(New-TestResult 'NIST' 'NIST - AC' 'Fail' 'one' 'Low')
        (New-FrameworkReportHtml -ModuleName 'NIST' -Results $high -ExecutionInfo $ExecInfo) | Should -Match "verdict-pass'><h3>Overall Rating"
    }
    It 'gives the executive summary cards the same coloured edges as the compliance cards' {
        foreach ($edge in 'edge-pass','edge-fail','edge-warning','edge-info','edge-sev-critical') {
            $R2Html | Should -Match $edge
        }
    }
    It 'spans the page rather than sitting inset, matching the composite report' {
        $R2Html | Should -Match 'main\{max-width:none'
        $R2Html | Should -Not -Match 'main\{max-width:1320px'
    }
    It 'renders Top Priority Findings ranked Fail-first' {
        $R2Html | Should -Match 'Top Priority Findings \(1\)'
    }
    It 'prefers an orchestrator-provided compliance score over the fallback' {
        $r = @(New-TestResult 'NIST' 'NIST - AC Access Control' 'Pass' 'ok')
        $score = @{ SimplePct=11.11; WeightedPct=22.22; SeverityWeightedPct=33.33; TotalChecks=1; Passed=1; Failed=0; Warnings=0; Info=0; Errors=0 }
        $html = New-FrameworkReportHtml -ModuleName 'NIST' -Results $r -ExecutionInfo $ExecInfo -ComplianceScore $score
        $html | Should -Match '33\.33'
    }
    It 'stamps renderer build provenance into the artifact' {
        $R2Html | Should -Match 'WSA report-templates build'
        $R2Html | Should -Match 'Renderer build:'
    }
}

Describe 'Export driver' {
    It 'is format-aware: writes HTML/CSV/JSON/XML per framework when requested' {
        $r = @(
            New-TestResult 'NIST' 'NIST - AC Access Control' 'Pass' 'ok'
            New-TestResult 'CIS'  'CIS - Account Policy' 'Pass' 'ok'
        )
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-rt-" + [guid]::NewGuid().ToString('N'))
        try {
            $files = @(Export-FrameworkReports -AllResults $r -OutputDirectory $dir -ExecutionInfo $ExecInfo -Formats @('HTML','JSON','CSV','XML') -HostName 'TESTHOST')
            $files.Count | Should -Be 8
            foreach ($f in $files) { (Split-Path $f -Leaf) | Should -Match '-Report-TESTHOST-\d{4}-\d{2}-\d{2}_\d{6}\.' }
            foreach ($ext in '.html','.json','.csv','.xml') {
                @($files | Where-Object { $_ -like "*$ext" }).Count | Should -Be 2
            }
        } finally {
            if (Test-Path $dir) { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'defaults to HTML plus JSON companions' {
        $r = @(New-TestResult 'NIST' 'NIST - AC Access Control' 'Pass' 'ok')
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-rt-" + [guid]::NewGuid().ToString('N'))
        try {
            $files = @(Export-FrameworkReports -AllResults $r -OutputDirectory $dir -ExecutionInfo $ExecInfo)
            $files.Count | Should -Be 2
        } finally {
            if (Test-Path $dir) { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}
