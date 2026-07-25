<#
.SYNOPSIS
    Pester tests asserting that code comments carry no development bookkeeping.
.DESCRIPTION
    Comments should describe purpose and function. Version markers and
    phase, sprint or work-item identifiers duplicate the changelog, add bulk to
    the source, and go stale without anyone noticing. This suite fails the build
    if any reappear.

    Framework and product versions named in comments (PCI DSS v4.0.1, CIS
    Controls v8.1, CSF 2.0, STIG V2R8, Windows 25H2) are subject matter, not
    bookkeeping, and are deliberately permitted. So are the CMMC rollout
    phases, which are part of the standard.
.NOTES
    Author: Windows Security Audit Project
    Version: 6.6.0
    Pester Version: 5.x

    Run via:
        Invoke-Pester -Path .\tests\comment-hygiene.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:SourceFiles = @(
        Get-ChildItem -Path $script:Root -Filter '*.ps1' -File
        Get-ChildItem -Path (Join-Path $script:Root 'shared_components') -Filter '*.ps1' -File
        Get-ChildItem -Path (Join-Path $script:Root 'modules') -Filter '*.ps1' -File
        Get-ChildItem -Path (Join-Path $script:Root 'tests') -Filter '*.ps1' -File
    )

    function Get-CommentOffences {
        param([Parameter(Mandatory)][string]$Pattern, [string]$Allow)
        $found = @()
        foreach ($f in $script:SourceFiles) {
            $n = 0
            foreach ($line in (Get-Content $f.FullName)) {
                $n++
                $hash = $line.IndexOf('#')
                if ($hash -lt 0) { continue }
                $comment = $line.Substring($hash)
                if ($comment -notmatch $Pattern) { continue }
                if ($Allow -and $comment -match $Allow) { continue }
                $found += "$($f.Name):$n  $($comment.Trim())"
            }
        }
        return $found
    }
}

Describe 'Comment hygiene' {
    It 'carries no project version markers in comments' {
        # Framework versions are subject matter and are allowed.
        $allow = 'PCI|DSS|CIS|CSF|NIST|STIG|ISO|SOC|Benchmark|Controls|Essential Eight|Amd|TSC|Rev\s*\d|2[0-9]H2|v2602'
        $hits = Get-CommentOffences -Pattern '[Vv]6\.\d' -Allow $allow
        $hits | Should -BeNullOrEmpty -Because "comments must not record the version an element was introduced in:`n$($hits -join ""`n"")"
    }

    It 'carries no phase, sprint or work-item identifiers in comments' {
        # CMMC rollout phases are part of the standard, not development phases.
        $allow = 'CMMC|rollout|solicitation|C3PAO|self-assessment'
        $hits = Get-CommentOffences -Pattern 'GAP-\d|\bPR-\d|WSA-[A-Z]+\d|\b[Pp]hase \d|\b[Rr]ound \d|\boption [AB]\b|\bL-A\d+' -Allow $allow
        $hits | Should -BeNullOrEmpty -Because "comments must not record development phases or work items:`n$($hits -join ""`n"")"
    }

    It 'carries no process bookkeeping in comments' {
        $hits = Get-CommentOffences -Pattern 'operator (feedback|decision|direction)|parity program'
        $hits | Should -BeNullOrEmpty -Because "comments must describe the code, not the process that produced it:`n$($hits -join ""`n"")"
    }
}
