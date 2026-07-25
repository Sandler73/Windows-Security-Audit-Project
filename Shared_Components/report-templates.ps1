# report-templates.ps1
# Per-framework tailored split-report renderers for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Renders one tailored HTML report per framework module for -SplitReports.

.DESCRIPTION
    Implements the per-framework split-report design (parity program GAP-2 as
    expanded by the tailored-report specification): each framework's report is
    a purpose-built document over a shared spine, NOT the combined report
    filtered by module.

    Shared spine (all frameworks), at feature parity with the Linux project's
    report engine: framework identity header with authoritative version line,
    host/scope block, executive posture summary with an interactive SVG status
    donut (clickable segments and legend filter the findings), severity badge
    distribution, table of contents with anchor links, global search with
    include/exclude modes, per-column filter row, sortable and resizable
    columns, per-table column visibility toggles, row selection with
    select-all, export modal (CSV / JSON / XML / TXT / Excel) at global,
    per-table, and selected-rows scope, per-group category statistics,
    collapsible group sections, word-wrapped cells, remediation index, print
    stylesheet, evidence/timestamp footer.

    Framework-specific tailoring (spec-driven):
    - Native grouping: findings grouped by the framework's own construct,
      derived from the module's category taxonomy (STIG requirement areas,
      NIST control families, CIS domains, CMMC practice families, PCI
      requirement areas, HIPAA safeguard categories, ISO Annex A themes, ...).
    - Native scoring: STIG reports score as Open / Not a Finding / Not
      Reviewed with a CAT severity distribution; CMMC reports carry the SPRS
      score panel extracted from module results; other frameworks score as
      compliance percentage.
    - Framework panels: CMMC SPRS + Conditional/Final context; STIG CAT
      distribution; PCI mandatory-since-2025 requirement panel; HIPAA renders
      current-rule findings separate from clearly-labeled proposed-rule (NPRM)
      indicators; CIS renders the v8.1 Governance signal prominently.

    Styling: Garamond over the shared CSS variable scheme (--bg-primary,
    --text-primary, --accent, ...) with a light/dark theme toggle matching the
    combined report's mechanism (documentElement data-theme attribute; dark is
    the default state). Report headers are centered. Every sub-section is
    collapsible: executive summary, table of contents, the
    'Framework-Specific Compliance Analysis' sub-section and each panel within
    it, every findings group, the proposed-rule block, and the remediation
    index. (Theme toggle added per operator direction 2026-07, superseding the
    earlier dark-only standard for these reports.)

.PARAMETER (component)
    Dot-source this file, then call Export-FrameworkReports.

.EXAMPLE
    . .\shared_components\report-templates.ps1
    $files = Export-FrameworkReports -AllResults $allResults -OutputDirectory .\reports\by-framework -ExecutionInfo $execInfo

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: none (standalone; consumes the standard result object schema)
    Security: writes HTML files only; all dynamic content is HTML-encoded
    Version: 6.6.0
#>

# ============================================================================
# Framework report specifications
# ============================================================================
$script:FrameworkReportSpecs = @{
    'STIG' = @{
        DisplayName = 'DISA STIG'
        Authority   = 'DISA STIG library: Windows 11 STIG V2R8 (Jul 2026), Windows 10 STIG V3R6 (Jan 2026)'
        GroupLabel  = 'Requirement Area'
        Scoring     = 'stig'
        Panels      = @('CatDistribution')
    }
    'CMMC' = @{
        DisplayName = 'CMMC 2.0'
        Authority   = 'CMMC 2.0 under 32 CFR Part 170 and the 48 CFR acquisition rule (binding since 2025-11-10; Phase 2 from 2026-11-10)'
        GroupLabel  = 'Practice Family'
        Scoring     = 'passfail'
        Panels      = @('SprsScore')
    }
    'PCI-DSS' = @{
        DisplayName = 'PCI DSS v4.0.1'
        Authority   = 'PCI DSS v4.0.1 (sole active version; formerly future-dated requirements mandatory since 2025-03-31)'
        GroupLabel  = 'Requirement Area'
        Scoring     = 'passfail'
        Panels      = @('PciMandatory')
    }
    'NIST' = @{
        DisplayName = 'NIST 800-53 / CSF 2.0'
        Authority   = 'NIST SP 800-53 Rev 5 Release 5.2.0 (Aug 2025), CSF 2.0, SP 800-171 Rev 2'
        GroupLabel  = 'Control Family'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'HIPAA' = @{
        DisplayName = 'HIPAA Security Rule'
        Authority   = 'HIPAA Security Rule (45 CFR Part 164 Subpart C -- current rule; Jan 2025 NPRM pending, final action projected July 2027)'
        GroupLabel  = 'Safeguard Area'
        Scoring     = 'passfail'
        Panels      = @('HipaaProposed')
    }
    'CIS' = @{
        DisplayName = 'CIS Benchmarks / Controls v8.1'
        Authority   = 'CIS Windows Benchmarks (current releases) and CIS Controls v8.1 (Governance function, CSF 2.0 alignment)'
        GroupLabel  = 'Benchmark Domain'
        Scoring     = 'passfail'
        Panels      = @('CisGovernance')
    }
    'ACSC' = @{
        DisplayName = 'ACSC Essential Eight'
        Authority   = 'ACSC Essential Eight Maturity Model (November 2023 update) and ISM'
        GroupLabel  = 'Strategy / Control Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'CISA' = @{
        DisplayName = 'CISA Directives and Guidance'
        Authority   = 'CISA KEV (living catalog), BOD 22-01/23-01/23-02, CPGs, Zero Trust Maturity Model'
        GroupLabel  = 'Directive / Guidance Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'NSA' = @{
        DisplayName = 'NSA Cybersecurity Guidance'
        Authority   = 'NSA CSI guidance including BlackLotus (CVE-2023-24932) mitigation'
        GroupLabel  = 'Guidance Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'ENISA' = @{
        DisplayName = 'ENISA / EU Instruments'
        Authority   = 'ENISA guidance; NIS2 (2022/2555); CRA (2024/2847: Art. 14 reporting from 2026-09-11); DORA (2022/2554, applies since 2025-01-17)'
        GroupLabel  = 'Guideline / Instrument Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'ISO27001' = @{
        DisplayName = 'ISO/IEC 27001:2022'
        Authority   = 'ISO/IEC 27001:2022 (incl. Amd 1:2024) with 27002:2022 guidance'
        GroupLabel  = 'Annex A Theme / Control Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'GDPR' = @{
        DisplayName = 'GDPR Technical Measures'
        Authority   = 'GDPR (2016/679) Art. 32 technical and organisational measures'
        GroupLabel  = 'Article / Measure Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'SOC2' = @{
        DisplayName = 'SOC 2 Trust Services Criteria'
        Authority   = 'AICPA 2017 TSC (With Revised Points of Focus - 2022)'
        GroupLabel  = 'Trust Services Criterion Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'MS' = @{
        DisplayName = 'Microsoft Security Baseline'
        Authority   = 'Microsoft Security Baselines: Windows 11 25H2 (Sep 2025), Windows Server 2025 v2602 (Feb 2026)'
        GroupLabel  = 'Baseline Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'MS-DefenderATP' = @{
        DisplayName = 'Microsoft Defender for Endpoint'
        Authority   = 'Microsoft Defender for Endpoint configuration guidance (per-rule ASR inventory current)'
        GroupLabel  = 'Capability Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
    'Core' = @{
        DisplayName = 'Core Security Baseline'
        Authority   = 'Framework core baseline: platform security, credential protection, modern Windows security features'
        GroupLabel  = 'Baseline Area'
        Scoring     = 'passfail'
        Panels      = @()
    }
}

# ============================================================================
# Helpers
# ============================================================================
function ConvertTo-SafeHtml {
    <#
    .SYNOPSIS
        HTML-encode a string for safe embedding (XSS mitigation).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-NativeGroupName {
    <#
    .SYNOPSIS
        Derive the framework-native group for a result from its category,
        stripping the module prefix (e.g. 'NIST - AC Access Control' -> 'AC
        Access Control').
    #>
    param([Parameter(Mandatory=$true)]$Result, [Parameter(Mandatory=$true)][string]$ModuleName)
    $cat = "$($Result.Category)"
    $prefixes = @("$ModuleName - ", "$ModuleName -", "ATP - ")
    foreach ($pre in $prefixes) {
        if ($cat.StartsWith($pre)) { return $cat.Substring($pre.Length).Trim() }
    }
    if ($cat) { return $cat }
    return 'General'
}

function Get-FrameworkPosture {
    <#
    .SYNOPSIS
        Compute the framework-native posture summary for a result set.
    #>
    param([Parameter(Mandatory=$true)][array]$Results, [Parameter(Mandatory=$true)][string]$Scoring)
    $counts = @{ Pass = 0; Fail = 0; Warning = 0; Info = 0; Error = 0 }
    foreach ($r in $Results) {
        $s = "$($r.Status)"
        if ($counts.ContainsKey($s)) { $counts[$s]++ }
    }
    $scored = $counts.Pass + $counts.Fail + $counts.Warning
    $pct = if ($scored -gt 0) { [Math]::Round(($counts.Pass / $scored) * 100, 1) } else { 0 }
    if ($Scoring -eq 'stig') {
        return @{
            Mode = 'stig'
            Cells = [ordered]@{
                'Open'            = $counts.Fail + $counts.Warning
                'Not a Finding'   = $counts.Pass
                'Not Reviewed'    = $counts.Info + $counts.Error
                'Total Checks'    = $Results.Count
            }
            Headline = "$($counts.Fail + $counts.Warning) Open / $($counts.Pass) Not a Finding"
        }
    }
    return @{
        Mode = 'passfail'
        Cells = [ordered]@{
            'Compliance' = "$pct`%"
            'Pass'       = $counts.Pass
            'Fail'       = $counts.Fail
            'Warning'    = $counts.Warning
            'Info'       = $counts.Info
            'Error'      = $counts.Error
        }
        Headline = "$pct`% compliant ($scored scored checks)"
    }
}

# ============================================================================
# Framework panels
# ============================================================================
# Sub-section title for framework-native panels. Operator-adjustable single
# constant (operator decision 2026-07-21: 'Regulatory & Framework Context').
$script:FrameworkSectionTitle = 'Regulatory & Framework Context'
# Build provenance: stamped into every generated report (HTML comment + footer)
# so a tested artifact is always traceable to the renderer that produced it.
$script:ReportTemplatesBuild = '6.6.0'

function New-CollapsibleSection {
    <#
    .SYNOPSIS
        Generic collapsible section: clickable header toggles the body.
    #>
    param([string]$Id, [string]$Title, [string]$BodyHtml, [string]$CssClass = 'panel', [switch]$StartCollapsed)
    $collapsedCls = if ($StartCollapsed) { ' collapsed' } else { '' }
    return "<div class='$CssClass$collapsedCls' id='$Id'>" +
           "<div class='group-header' onclick='toggleModule(""$Id"")'><h2><span class='collapse-icon'>&#9660;</span>$Title</h2></div>" +
           "<div class='group-body'>$BodyHtml</div></div>"
}

$script:PanelSeq = 0
function New-PanelHtml {
    param([string]$Title, [string]$BodyHtml)
    $script:PanelSeq++
    return New-CollapsibleSection -Id "fwpanel$($script:PanelSeq)" -Title (ConvertTo-SafeHtml $Title) -BodyHtml $BodyHtml
}

function New-SprsScorePanel {
    param([array]$Results)
    $sprs = $Results | Where-Object { "$($_.Category)" -like '*SPRS*' -and "$($_.Message)" -match 'SPRS Score:\s*(-?\d+)\s*/\s*110' } | Select-Object -First 1
    if ($sprs -and "$($sprs.Message)" -match 'SPRS Score:\s*(-?\d+)\s*/\s*110') {
        $score = $Matches[1]
        $body = "<div class='big-metric'>$score <span class='metric-denom'>/ 110</span></div>" +
                "<p>NIST SP 800-171 DoD Assessment Methodology self-assessment estimate from this run. " +
                "DFARS 252.204-7019 requires a current score posted in SPRS at time of award; a Conditional CMMC status requires POA&amp;M closeout within 180 days to reach Final status.</p>"
        return New-PanelHtml -Title 'SPRS Score (DoD Methodology)' -BodyHtml $body
    }
    return New-PanelHtml -Title 'SPRS Score (DoD Methodology)' -BodyHtml '<p>No SPRS score result present in this run.</p>'
}

function New-CatDistributionPanel {
    param([array]$Results)
    $cat1 = 0; $cat2 = 0; $cat3 = 0; $uncat = 0
    foreach ($r in $Results) {
        $blob = "$($r.Category) $((@($r.CrossReferences.Values) -join ' '))"
        if ($blob -match 'CAT\s*I\b' -and $blob -notmatch 'CAT\s*II') { $cat1++ }
        elseif ($blob -match 'CAT\s*III\b') { $cat3++ }
        elseif ($blob -match 'CAT\s*II\b') { $cat2++ }
        else { $uncat++ }
    }
    $body = "<table class='mini'><tr><th>CAT I</th><th>CAT II</th><th>CAT III</th><th>Unmapped</th></tr>" +
            "<tr><td>$cat1</td><td>$cat2</td><td>$cat3</td><td>$uncat</td></tr></table>" +
            "<p>CAT membership parsed from requirement categories and cross-references where the module recorded it; unmapped checks carry framework severity instead.</p>"
    return New-PanelHtml -Title 'STIG Severity Category Distribution' -BodyHtml $body
}

function New-PciMandatoryPanel {
    param([array]$Results)
    $mand = @($Results | Where-Object { "$($_.Category)" -like '*Mandatory v4.0.1*' })
    if ($mand.Count -eq 0) {
        return New-PanelHtml -Title 'Mandatory Since 2025-03-31' -BodyHtml '<p>No formerly-future-dated requirement results present in this run.</p>'
    }
    $rows = foreach ($m in $mand) {
        "<tr><td class='st-$(("$($m.Status)").ToLower())'>$(ConvertTo-SafeHtml $m.Status)</td><td>$(ConvertTo-SafeHtml $m.Message)</td></tr>"
    }
    $body = "<p>PCI DSS v4.0.1 requirements that were future-dated under v4.0 have been mandatory since 31 March 2025. This run assessed $($mand.Count) of them:</p>" +
            "<table class='mini'><tr><th>Status</th><th>Requirement Assessment</th></tr>$($rows -join '')</table>"
    return New-PanelHtml -Title 'Mandatory Since 2025-03-31 (Formerly Future-Dated)' -BodyHtml $body
}

function New-CisGovernancePanel {
    param([array]$Results)
    $gv = @($Results | Where-Object { "$($_.Category)" -like '*v8.1 Governance*' })
    if ($gv.Count -eq 0) {
        return New-PanelHtml -Title 'Controls v8.1 Governance (GV)' -BodyHtml '<p>No Governance-function results present in this run.</p>'
    }
    $rows = foreach ($g in $gv) {
        "<tr><td class='st-$(("$($g.Status)").ToLower())'>$(ConvertTo-SafeHtml $g.Status)</td><td>$(ConvertTo-SafeHtml $g.Message)</td></tr>"
    }
    $body = "<table class='mini'><tr><th>Status</th><th>Governance Signal</th></tr>$($rows -join '')</table>"
    return New-PanelHtml -Title 'Controls v8.1 Governance (GV)' -BodyHtml $body
}

function Split-HipaaProposed {
    <#
    .SYNOPSIS
        Separate HIPAA current-rule results from labeled proposed-rule (NPRM)
        indicators so the report cannot conflate proposed text with law.
    #>
    param([array]$Results)
    $proposed = @($Results | Where-Object { "$($_.Category)" -like '*Proposed Rule*' })
    $current  = @($Results | Where-Object { "$($_.Category)" -notlike '*Proposed Rule*' })
    return @{ Current = $current; Proposed = $proposed }
}

# ============================================================================
# Spine renderer (v2: full feature parity with the Linux report engine, minus
# the theme toggle, which is deliberately replaced by dark-only styling per
# the project's HTML standard)
# ============================================================================

$script:ReportCss = @'
:root{--bg-primary:#ffffff;--bg-secondary:#f8f9fa;--bg-tertiary:#e9ecef;--text-primary:#333333;--text-secondary:#666666;--border-color:#dee2e6;--card-shadow:rgba(0,0,0,.08);--row-hover:#f1f3f5;--accent:#1565c0;--accent-light:#e3f2fd;--header-bg:linear-gradient(135deg,#0d1b2a,#1b2838);--pass:#1a7f37;--fail:#cf222e;--warning:#9a6700;--info:#1565c0;--error:#8250df}
[data-theme="dark"]{--bg-primary:#0b0e14;--bg-secondary:#111822;--bg-tertiary:#1a2332;--text-primary:#c9d1d9;--text-secondary:#8b949e;--border-color:#21262d;--card-shadow:rgba(0,0,0,.4);--row-hover:#161b22;--accent:#58a6ff;--accent-light:#0d1117;--header-bg:linear-gradient(135deg,#060a10,#0d1520);--pass:#3fb950;--fail:#f85149;--warning:#d29922;--info:#58a6ff;--error:#bc8cff}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Garamond,'Times New Roman',serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;padding:0 0 40px 0}
header{background:var(--header-bg);padding:28px 36px;border-bottom:2px solid var(--accent);text-align:center;position:relative}
header h1{font-size:1.7em;color:#e6edf3}
.theme-toggle{position:absolute;top:20px;right:30px;display:flex;align-items:center;gap:8px;cursor:pointer;color:#fff;font-size:.9em}
.theme-slider{width:44px;height:22px;background:rgba(255,255,255,.25);border-radius:11px;position:relative}
.theme-slider::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;background:#fff;border-radius:50%;transition:transform .2s}
[data-theme="dark"] .theme-slider::after{transform:translateX(22px)}
header .authority{color:var(--text-secondary);font-size:.95em;margin-top:4px}
.hostline{color:var(--text-secondary);font-size:.9em;margin-top:8px}
main{max-width:none;margin:0;padding:24px 36px}
.metric-row{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0;align-items:center}
/* Host identification grid, matching the composite report's info cards. */
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:18px 0}
.info-card{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:12px 16px;box-shadow:0 2px 8px var(--card-shadow)}
.info-card h3{font-size:.75em;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.info-card p{color:var(--text-primary);font-size:1.02em;word-wrap:break-word}
.metric-card{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:12px 18px;min-width:110px;box-shadow:0 2px 8px var(--card-shadow)}
.metric-card h3{font-size:.75em;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px}
.metric-value{font-size:1.5em;color:var(--accent)}
.big-metric{font-size:2.6em;color:var(--accent)}
.metric-denom{font-size:.5em;color:var(--text-secondary)}
.panel,.group-section{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:18px;margin:18px 0;box-shadow:0 2px 8px var(--card-shadow)}
.panel h2,.group-section h2{font-size:1.15em;color:var(--text-primary);margin-bottom:10px}
.group-header{cursor:pointer;user-select:none}
.group-count{color:var(--text-secondary);font-size:.8em}
.group-stats{color:var(--text-secondary);font-size:.85em;margin:4px 0 8px 0}
.collapse-icon{display:inline-block;transition:transform .15s;margin-right:6px;color:var(--accent)}
.collapsed .collapse-icon{transform:rotate(-90deg)}
.collapsed .group-body{display:none}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.92em;table-layout:fixed}
/* Status/Severity carry short fixed vocabularies; sizing them to their longest
   value reclaims width for Check/Details and cuts wrapping. */
table.findings th.col-status{width:104px}
table.findings th.col-severity{width:92px}
table.findings th.col-vid{width:104px}
table.findings th.col-select{width:34px}
table.mini th.col-status{width:104px}
table.mini th.col-severity{width:92px}
table.mini{table-layout:fixed}
th{background:var(--bg-tertiary);color:var(--text-primary);text-align:left;padding:8px;border-bottom:2px solid var(--accent);position:relative}
th.sortable{cursor:pointer}
td{padding:7px 8px;border-bottom:1px solid var(--border-color);vertical-align:top;word-wrap:break-word;overflow-wrap:break-word;white-space:normal}
tr:hover td{background:var(--row-hover)}
tr.hidden-row{display:none}
.filter-row th{background:var(--bg-secondary);padding:4px;border-bottom:1px solid var(--border-color)}
.filter-row input{width:100%;padding:4px 6px;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:4px;color:var(--text-primary);font-family:inherit;font-size:.88em}
.resizer{position:absolute;right:0;top:0;height:100%;width:5px;cursor:col-resize;user-select:none}
.resizer:hover{background:var(--accent)}
code{font-family:Consolas,monospace;font-size:.85em;color:#9ecbff;word-wrap:break-word}
.badge{display:inline-block;padding:1px 9px;border-radius:10px;font-size:.82em;border:1px solid}
.st-pass{color:var(--pass);border-color:var(--pass)}
.st-fail{color:var(--fail);border-color:var(--fail)}
.st-warning{color:var(--warning);border-color:var(--warning)}
.st-info{color:var(--info);border-color:var(--info)}
.st-error{color:var(--error);border-color:var(--error)}
.sev-critical{color:#f85149}.sev-high{color:#db6d28}.sev-medium{color:#d29922}.sev-low{color:#58a6ff}.sev-informational{color:#8b949e}
.proposed-note{border-left:3px solid #d29922;padding-left:10px;color:var(--text-secondary)}
.global-controls{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:14px 18px;margin:18px 0;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.global-controls input[type=text]{flex:1;min-width:220px;padding:8px;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:inherit;font-size:1em}
.global-controls select,.global-controls button,.tbl-controls button,.tbl-controls select,.colvis-box label{background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:inherit;padding:7px 12px;font-size:.9em}
.global-controls button,.tbl-controls button{cursor:pointer}
.global-controls button:hover,.tbl-controls button:hover{border-color:var(--accent);color:var(--accent)}
.tbl-controls{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0;align-items:center}
.colvis-box{display:none;position:absolute;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:6px;padding:8px;z-index:30}
.colvis-box.open{display:block}
.colvis-box label{display:block;border:none;padding:2px 6px;cursor:pointer}
.colvis-wrap{position:relative;display:inline-block}
.toc{columns:2;column-gap:28px}
.toc a{color:var(--accent);text-decoration:none}
.toc a:hover{text-decoration:underline}
.toc li{margin:2px 0;break-inside:avoid}
.donut-wrap{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
/* Result cards sit to the right of the donut rather than beneath it, so the
   dashboard reads as one band instead of two stacked rows. */
.donut-row{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
.donut-row .metric-row{flex:1;min-width:280px;margin:0}
.compliance-verdict-pass{color:var(--pass)}
.compliance-verdict-fail{color:var(--fail)}
.metric-card.verdict-pass{border-left:4px solid var(--pass)}
.metric-card.verdict-warn{border-left:4px solid var(--warning)}
.metric-card.verdict-fail{border-left:4px solid var(--fail)}
/* Executive-summary card edges, matching the compliance-card treatment. */
.metric-card.edge-total{border-left:4px solid var(--accent)}
.metric-card.edge-pass{border-left:4px solid var(--pass)}
.metric-card.edge-fail{border-left:4px solid var(--fail)}
.metric-card.edge-warning{border-left:4px solid var(--warning)}
.metric-card.edge-info{border-left:4px solid var(--info)}
.metric-card.edge-error{border-left:4px solid var(--error)}
.metric-card.edge-sev-critical{border-left:4px solid #f85149}
.metric-card.edge-sev-high{border-left:4px solid #db6d28}
.metric-card.edge-sev-medium{border-left:4px solid #d29922}
.metric-card.edge-sev-low{border-left:4px solid #58a6ff}
.metric-card.edge-sev-informational{border-left:4px solid var(--text-secondary)}
.donut-legend{list-style:none}
.donut-legend li{cursor:pointer;margin:3px 0}
.donut-legend li.active{text-decoration:underline}
.donut-legend .sw{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:7px}
.donut-svg circle.seg{cursor:pointer;transition:stroke-width .12s}
.donut-svg circle.seg:hover{stroke-width:30}
.donut-total{fill:var(--text-primary)}
.export-modal-back{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:90}
.export-modal-back.open{display:flex;align-items:center;justify-content:center}
.export-modal{background:var(--bg-secondary);border:1px solid var(--accent);border-radius:10px;padding:22px 26px;min-width:340px}
.export-modal h3{color:var(--text-primary);margin-bottom:10px}
.export-modal .fmt-row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.export-modal .scope-note{color:var(--text-secondary);font-size:.85em}
footer{max-width:none;margin:24px 0 0;padding:12px 36px 0;color:var(--text-secondary);font-size:.85em;border-top:1px solid var(--border-color)}
@media print{
 .theme-toggle,.global-controls,.tbl-controls,.filter-row,.export-modal-back,.colvis-box,.resizer,input[type=checkbox]{display:none !important}
 .collapsed .group-body{display:block !important}
 body{background:#ffffff;color:#000000}
 .panel,.group-section{box-shadow:none;border:1px solid #999}
 th{background:#eeeeee;color:#000}
 td{color:#000;border-bottom:1px solid #ccc}
 header{background:#ffffff;border-bottom:2px solid #000}
 header h1{color:#000}
}
'@

$script:ReportJs = @'
var colFilters={};var statusFilter=null;
function toggleTheme(){var b=document.documentElement;b.setAttribute('data-theme',b.getAttribute('data-theme')==='dark'?'light':'dark');}
function esc(s){return (s==null?'':String(s));}
function getCellText(td){return td?td.textContent.trim():'';}
function rowMatches(tr,tableId){
 var cells=tr.cells;var q=document.getElementById('globalSearch').value.toLowerCase();
 var mode=document.getElementById('globalSearchMode').value;
 var text=tr.textContent.toLowerCase();
 if(q){var hit=text.indexOf(q)>-1;if(mode==='include'&&!hit)return false;if(mode==='exclude'&&hit)return false;}
 if(statusFilter){var st=getCellText(cells[1]).toLowerCase();if(st.indexOf(statusFilter)===-1)return false;}
 var f=colFilters[tableId]||{};
 for(var idx in f){var v=f[idx];if(!v)continue;if(getCellText(cells[idx]).toLowerCase().indexOf(v)===-1)return false;}
 return true;
}
function applyAllFilters(){
 document.querySelectorAll('table.findings').forEach(function(table){
  var id=table.id;
  Array.prototype.forEach.call(table.tBodies[0].rows,function(tr){
   tr.classList.toggle('hidden-row',!rowMatches(tr,id));
  });
 });
 updateGroupCounts();
}
function updateGroupCounts(){
 document.querySelectorAll('.group-section').forEach(function(sec){
  var t=sec.querySelector('table.findings');if(!t)return;
  var vis=t.querySelectorAll('tbody tr:not(.hidden-row)').length;
  var el=sec.querySelector('.visible-count');if(el)el.textContent=vis;
 });
}
function globalFilter(){applyAllFilters();}
function clearGlobalSearch(){document.getElementById('globalSearch').value='';document.getElementById('globalSearchMode').value='include';clearDashboardFilter();applyAllFilters();}
function filterColumn(tableId,colIdx,value){if(!colFilters[tableId])colFilters[tableId]={};colFilters[tableId][colIdx]=value.toLowerCase();applyAllFilters();}
function dashboardFilter(kind,label){statusFilter=(statusFilter===label.toLowerCase())?null:label.toLowerCase();document.querySelectorAll('.donut-legend li').forEach(function(li){li.classList.toggle('active',statusFilter&&li.dataset.label.toLowerCase()===statusFilter);});applyAllFilters();}
function clearDashboardFilter(){statusFilter=null;document.querySelectorAll('.donut-legend li').forEach(function(li){li.classList.remove('active');});}
function sortTable(th){
 var table=th.closest('table');var idx=Array.prototype.indexOf.call(th.parentNode.children,th);
 if(idx===0)return;
 var rows=Array.prototype.slice.call(table.tBodies[0].rows);var asc=th.dataset.asc!=='1';
 rows.sort(function(a,b){var x=getCellText(a.cells[idx]),y=getCellText(b.cells[idx]);var nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny))return (nx-ny)*(asc?1:-1);return x.localeCompare(y)*(asc?1:-1);});
 th.dataset.asc=asc?'1':'0';rows.forEach(function(r){table.tBodies[0].appendChild(r);});
}
function toggleModule(id){document.getElementById(id).classList.toggle('collapsed');}
function toggleSelectAll(tableId,checked){document.querySelectorAll('#'+tableId+' tbody input.row-select').forEach(function(cb){cb.checked=checked;});}
function toggleColVis(btn){btn.parentNode.querySelector('.colvis-box').classList.toggle('open');}
function toggleColumnVisibility(tableId,colIdx,visible){
 var table=document.getElementById(tableId);
 Array.prototype.forEach.call(table.rows,function(tr){if(tr.cells[colIdx])tr.cells[colIdx].style.display=visible?'':'none';});
}
function initResizeHandles(){
 // Every generated table is resizable, including the mini tables used by the
 // priority, remediation and framework panels.
 document.querySelectorAll('table.findings th, table.mini th').forEach(function(th){
  var r=document.createElement('span');r.className='resizer';th.appendChild(r);
  r.addEventListener('mousedown',function(e){
   e.preventDefault();e.stopPropagation();
   var startX=e.pageX,startW=th.offsetWidth;
   function onMove(ev){th.style.width=Math.max(50,startW+(ev.pageX-startX))+'px';}
   function onUp(){document.removeEventListener('mousemove',onMove);document.removeEventListener('mouseup',onUp);}
   document.addEventListener('mousemove',onMove);document.addEventListener('mouseup',onUp);
  });
  r.addEventListener('click',function(e){e.stopPropagation();});
 });
}
function getTableData(table,selectedOnly,visibleOnly){
 var headers=[];Array.prototype.forEach.call(table.tHead.rows[0].cells,function(th,i){if(i>0)headers.push(th.textContent.replace(/\u25B2|\u25BC/g,'').trim());});
 var out=[];
 Array.prototype.forEach.call(table.tBodies[0].rows,function(tr){
  if(visibleOnly&&tr.classList.contains('hidden-row'))return;
  var cb=tr.querySelector('input.row-select');
  if(selectedOnly&&(!cb||!cb.checked))return;
  var o={};Array.prototype.forEach.call(tr.cells,function(td,i){if(i>0)o[headers[i-1]]=getCellText(td);});
  out.push(o);
 });
 return out;
}
function collectData(scope){
 var data=[];
 if(scope.table){var t=document.getElementById(scope.table);data=getTableData(t,scope.selected,true);}
 else{document.querySelectorAll('table.findings').forEach(function(t){data=data.concat(getTableData(t,scope.selected,true));});}
 return data;
}
function toCSV(data){
 if(!data.length)return '';
 var cols=Object.keys(data[0]);
 var lines=[cols.map(function(c){return '"'+c.replace(/"/g,'""')+'"';}).join(',')];
 data.forEach(function(o){lines.push(cols.map(function(c){return '"'+esc(o[c]).replace(/"/g,'""')+'"';}).join(','));});
 return lines.join('\r\n');
}
function escXml(s){return esc(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function toXML(data){
 var out=['<?xml version="1.0" encoding="UTF-8"?>','<findings>'];
 data.forEach(function(o){out.push(' <finding>');for(var k in o){var tag=k.replace(/[^A-Za-z0-9]/g,'');out.push('  <'+tag+'>'+escXml(o[k])+'</'+tag+'>');}out.push(' </finding>');});
 out.push('</findings>');return out.join('\n');
}
function toTXT(data){return data.map(function(o){return Object.keys(o).map(function(k){return k+': '+o[k];}).join('\n');}).join('\n\n---\n\n');}
function toExcel(data){
 var cols=data.length?Object.keys(data[0]):[];
 var rows=data.map(function(o){return '<tr>'+cols.map(function(c){return '<td>'+escXml(o[c])+'</td>';}).join('')+'</tr>';}).join('');
 return '<html><head><meta charset="utf-8"></head><body><table><tr>'+cols.map(function(c){return '<th>'+escXml(c)+'</th>';}).join('')+'</tr>'+rows+'</table></body></html>';
}
function downloadFile(name,mime,content){
 var blob=new Blob([content],{type:mime});var a=document.createElement('a');
 a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();
 setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},400);
}
var exportScope={};
function showExportModal(tableId,selectedOnly){exportScope={table:tableId,selected:!!selectedOnly};var n=document.getElementById('exportScopeNote');n.textContent=(tableId?('Scope: this section'+(selectedOnly?' (selected rows)':'')):('Scope: entire report'+(selectedOnly?' (selected rows)':'')))+' (currently visible rows only)';document.getElementById('exportModalBack').classList.add('open');}
function closeExportModal(){document.getElementById('exportModalBack').classList.remove('open');}
function executeExport(fmt){
 var data=collectData(exportScope);
 var base=document.body.dataset.reportname+'-export';
 if(fmt==='csv')downloadFile(base+'.csv','text/csv',toCSV(data));
 else if(fmt==='json')downloadFile(base+'.json','application/json',JSON.stringify(data,null,2));
 else if(fmt==='xml')downloadFile(base+'.xml','application/xml',toXML(data));
 else if(fmt==='txt')downloadFile(base+'.txt','text/plain',toTXT(data));
 else if(fmt==='xls')downloadFile(base+'.xls','application/vnd.ms-excel',toExcel(data));
 closeExportModal();
}
document.addEventListener('DOMContentLoaded',function(){initResizeHandles();updateGroupCounts();});
'@

function Get-FallbackComplianceScore {
    <#
    .SYNOPSIS
        Compute Simple/Weighted/Severity-Adjusted compliance for a result set.
        Mirrors the orchestrator's Get-ComplianceScore math exactly; used only
        when the orchestrator did not pass its per-module score through.
    #>
    param([array]$Results)
    $c = @{ Pass=0; Fail=0; Warning=0; Info=0; Error=0 }
    $sevDist = @{ Critical=0; High=0; Medium=0; Low=0; Informational=0 }
    foreach ($r in $Results) {
        $s = "$($r.Status)"; if ($c.ContainsKey($s)) { $c[$s]++ }
        $sv = "$($r.Severity)"; if ($sevDist.ContainsKey($sv)) { $sevDist[$sv]++ }
    }
    $total = @($Results).Count
    $applicable = [Math]::Max(1, $total - $c.Info)
    $simplePct = [Math]::Round(($c.Pass / $applicable) * 100, 2)
    $weightedPct = [Math]::Round((($c.Pass * 1.0 + $c.Warning * 0.5) / $applicable) * 100, 2)
    $sevWeights = @{ Critical=5.0; High=3.0; Medium=1.5; Low=0.5; Informational=0.0 }
    $totalWeight = 0.0
    foreach ($s in $sevDist.Keys) { if ($s -ne 'Informational') { $totalWeight += $sevWeights[$s] * $sevDist[$s] } }
    $sevWeightedPct = $weightedPct
    if ($totalWeight -gt 0) {
        $failRate = ($c.Fail + $c.Error) / $applicable
        $critHighW = ($sevWeights['Critical'] * $sevDist['Critical']) + ($sevWeights['High'] * $sevDist['High'])
        $adjFail = [Math]::Min(1.0, $failRate * (1.0 + $critHighW / $totalWeight))
        $sevWeightedPct = [Math]::Round([Math]::Max(0, [Math]::Min(100, (1.0 - $adjFail) * 100)), 2)
    }
    # Threshold/verdict mirror the orchestrator's Get-ComplianceScore contract so
    # the Overall Rating card renders identically whether the score came from
    # upstream or from this fallback.
    $threshold = 70.0
    return @{ SimplePct=$simplePct; WeightedPct=$weightedPct; SeverityWeightedPct=$sevWeightedPct
              TotalChecks=$total; Passed=$c.Pass; Failed=$c.Fail; Warnings=$c.Warning; Info=$c.Info; Errors=$c.Error
              Threshold=$threshold
              ThresholdResult=$(if ($weightedPct -ge $threshold) { 'PASS' } else { 'FAIL' }) }
}

function New-StatusDonutSvg {
    <#
    .SYNOPSIS
        Build a clickable SVG status donut with legend (dashboard filter).
    #>
    param([hashtable]$Counts)
    $order = @(
        @{ Label = 'Pass';    Color = '#3fb950' },
        @{ Label = 'Fail';    Color = '#f85149' },
        @{ Label = 'Warning'; Color = '#d29922' },
        @{ Label = 'Info';    Color = '#58a6ff' },
        @{ Label = 'Error';   Color = '#bc8cff' }
    )
    $total = 0; foreach ($o in $order) { $total += [int]$Counts[$o.Label] }
    if ($total -eq 0) { return '<p>No results to chart.</p>' }
    $r = 70; $circ = [Math]::Round(2 * [Math]::PI * $r, 2)
    $offset = [Math]::Round($circ * 0.25, 2)  # start at 12 o'clock
    $segs = foreach ($o in $order) {
        $c = [int]$Counts[$o.Label]
        if ($c -eq 0) { continue }
        $len = [Math]::Round($circ * $c / $total, 2)
        $gap = [Math]::Round($circ - $len, 2)
        $seg = "<circle class='seg' r='$r' cx='90' cy='90' fill='transparent' stroke='$($o.Color)' stroke-width='26' " +
               "stroke-dasharray='$len $gap' stroke-dashoffset='$offset' " +
               "onclick=`"dashboardFilter('status','$($o.Label)')`"><title>$($o.Label): $c</title></circle>"
        $offset = [Math]::Round($offset - $len, 2)
        $seg
    }
    $legend = foreach ($o in $order) {
        $c = [int]$Counts[$o.Label]
        $pct = [Math]::Round(($c / $total) * 100, 1)
        "<li data-label='$($o.Label)' onclick=`"dashboardFilter('status','$($o.Label)')`"><span class='sw' style='background:$($o.Color)'></span>$($o.Label): $c ($pct`%)</li>"
    }
    return "<div class='donut-wrap'><svg class='donut-svg' width='180' height='180' viewBox='0 0 180 180'>$($segs -join '')" +
           "<text x='90' y='96' text-anchor='middle' fill='currentColor' font-size='26' font-family='Garamond' class='donut-total'>$total</text></svg>" +
           "<ul class='donut-legend'>$($legend -join '')</ul></div>"
}

function New-FrameworkReportHtml {
    <#
    .SYNOPSIS
        Render one framework's tailored report as an HTML string (v2 spine).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ModuleName,
        [Parameter(Mandatory=$true)][array]$Results,
        [hashtable]$ExecutionInfo = @{},
        [hashtable]$ComplianceScore = $null
    )

    $spec = $script:FrameworkReportSpecs[$ModuleName]
    $script:PanelSeq = 0  # deterministic per-report panel ids
    if (-not $spec) {
        $spec = @{ DisplayName = $ModuleName; Authority = 'Framework specification not registered'; GroupLabel = 'Area'; Scoring = 'passfail'; Panels = @() }
    }

    # HIPAA: proposed-rule separation before any scoring.
    $proposedBlock = ''
    $scoredResults = $Results
    if ($spec.Panels -contains 'HipaaProposed') {
        $splitH = Split-HipaaProposed -Results $Results
        $scoredResults = $splitH.Current
        if ($splitH.Proposed.Count -gt 0) {
            $rows = foreach ($p in $splitH.Proposed) {
                "<tr><td><span class='badge st-info'>Info</span></td><td>$(ConvertTo-SafeHtml $p.Message)</td><td>$(ConvertTo-SafeHtml $p.Details)</td></tr>"
            }
            $propBody = "<p class='proposed-note'>The January 2025 Security Rule NPRM is proposed, not law (final action projected July 2027). " +
                "These forward-looking indicators are excluded from the compliance score above; the current Security Rule remains the sole authoritative basis for every scored finding in this report.</p>" +
                "<table class='mini'><tr><th>Status</th><th>Indicator</th><th>Context</th></tr>$($rows -join '')</table>"
            $proposedBlock = New-CollapsibleSection -Id 'proposed' -Title 'Proposed Rule (NPRM) Indicators -- NOT Current Requirements' -BodyHtml $propBody
        }
    }

    $posture = Get-FrameworkPosture -Results $scoredResults -Scoring $spec.Scoring

    # Status + severity distributions (scored results)
    $statusCounts = @{ Pass = 0; Fail = 0; Warning = 0; Info = 0; Error = 0 }
    $sevCounts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    foreach ($r in $scoredResults) {
        $s = "$($r.Status)"; if ($statusCounts.ContainsKey($s)) { $statusCounts[$s]++ }
        $sv = "$($r.Severity)"; if (-not $sv) { $sv = 'Medium' }
        if ($sevCounts.Contains($sv)) { $sevCounts[$sv]++ }
    }

    # Native grouping
    $groups = [ordered]@{}
    foreach ($r in $scoredResults) {
        $g = Get-NativeGroupName -Result $r -ModuleName $ModuleName
        if (-not $groups.Contains($g)) { $groups[$g] = [System.Collections.Generic.List[object]]::new() }
        $groups[$g].Add($r)
    }
    $sortedGroupNames = @($groups.Keys | Sort-Object)

    # Framework panels
    $panelsHtml = foreach ($panel in $spec.Panels) {
        switch ($panel) {
            'SprsScore'       { New-SprsScorePanel -Results $Results }
            'CatDistribution' { New-CatDistributionPanel -Results $Results }
            'PciMandatory'    { New-PciMandatoryPanel -Results $Results }
            'CisGovernance'   { New-CisGovernancePanel -Results $Results }
            'HipaaProposed'   { }
        }
    }

    # TOC (anchors: exec, panels, each group, proposed, remediation)
    $tocItems = [System.Collections.Generic.List[string]]::new()
    $tocItems.Add("<li><a href='#exec'>Executive Summary</a></li>")
    $tocItems.Add("<li><a href='#overallcompliance'>Overall Compliance</a></li>")
    $tocItems.Add("<li><a href='#toppriority'>Top Priority Findings</a></li>")
    if ($spec.Panels.Count -gt 0) {
        $tocItems.Add("<li><a href='#fwsection'>$(ConvertTo-SafeHtml $script:FrameworkSectionTitle)</a></li>")
    }
    $gi = 0
    foreach ($g in $sortedGroupNames) {
        $gi++
        $tocItems.Add("<li><a href='#grp$gi'>$(ConvertTo-SafeHtml $g)</a> <span class='group-count'>($($groups[$g].Count))</span></li>")
    }
    if ($proposedBlock) { $tocItems.Add("<li><a href='#proposed'>Proposed Rule (NPRM) Indicators</a></li>") }
    $tocItems.Add("<li><a href='#remediation'>Remediation Index</a></li>")

    # Grouped findings tables (checkbox col, filter row, badges, controls)
    $isStig = ($spec.Scoring -eq 'stig')
    $gi = 0
    $findingsHtml = foreach ($g in $sortedGroupNames) {
        $gi++
        $tableId = "tbl$gi"
        $grpResults = $groups[$g]
        # Category-level statistics
        $gs = @{ Pass = 0; Fail = 0; Warning = 0; Info = 0; Error = 0 }
        foreach ($r in $grpResults) { $s = "$($r.Status)"; if ($gs.ContainsKey($s)) { $gs[$s]++ } }
        $statsLine = "Pass $($gs.Pass) &nbsp;|&nbsp; Fail $($gs.Fail) &nbsp;|&nbsp; Warning $($gs.Warning) &nbsp;|&nbsp; Info $($gs.Info) &nbsp;|&nbsp; Error $($gs.Error) &nbsp;|&nbsp; Visible: <span class='visible-count'>$($grpResults.Count)</span>/$($grpResults.Count)"

        $rows = foreach ($r in $grpResults) {
            $status = "$($r.Status)"
            $statusLbl = if ($isStig) {
                switch ($status) { 'Pass' { 'Not a Finding' } 'Fail' { 'Open' } 'Warning' { 'Open (partial)' } default { 'Not Reviewed' } }
            } else { $status }
            $vid = ''
            if ($isStig -and $r.CrossReferences) {
                foreach ($v in @($r.CrossReferences.Values)) { if ("$v" -match '^(V-\d{6})') { $vid = $Matches[1]; break } }
            }
            $vidCell = if ($isStig) { "<td>$(ConvertTo-SafeHtml $vid)</td>" } else { '' }
            $xrefs = if ($r.CrossReferences -and @($r.CrossReferences.Keys).Count -gt 0) {
                (@($r.CrossReferences.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join '; ')
            } else { '' }
            $rem = if ($r.Remediation) { "<code>$(ConvertTo-SafeHtml "$($r.Remediation)")</code>" } else { '' }
            $sevClass = "sev-$(("$($r.Severity)").ToLower())"
            "<tr><td><input type='checkbox' class='row-select'></td>" +
            "<td><span class='badge st-$($status.ToLower())'>$(ConvertTo-SafeHtml $statusLbl)</span></td>$vidCell" +
            "<td class='$sevClass'>$(ConvertTo-SafeHtml "$($r.Severity)")</td>" +
            "<td>$(ConvertTo-SafeHtml "$($r.Message)")</td>" +
            "<td>$(ConvertTo-SafeHtml "$($r.Details)")</td>" +
            "<td>$(ConvertTo-SafeHtml $xrefs)</td>" +
            "<td>$rem</td></tr>"
        }
        $vidTh = if ($isStig) { "<th class='sortable col-vid' onclick='sortTable(this)'>V-ID</th>" } else { '' }
        $vidF  = if ($isStig) { "<th><input type='text' oninput='filterColumn(""$tableId"",2,this.value)'></th>" } else { '' }
        $statusTh = if ($isStig) { 'Finding Status' } else { 'Status' }
        $colBase = if ($isStig) { 3 } else { 2 }
        $headerCells = @("<th class='col-select'><input type='checkbox' onchange='toggleSelectAll(""$tableId"",this.checked)'></th>",
                         "<th class='sortable col-status' onclick='sortTable(this)'>$statusTh</th>", $vidTh,
                         "<th class='sortable col-severity' onclick='sortTable(this)'>Severity</th>",
                         "<th class='sortable' onclick='sortTable(this)'>Check</th>",
                         "<th class='sortable' onclick='sortTable(this)'>Details</th>",
                         "<th class='sortable' onclick='sortTable(this)'>Cross-References</th>",
                         "<th class='sortable' onclick='sortTable(this)'>Remediation</th>") -join ''
        $filterCells = @("<th></th>",
                         "<th><input type='text' oninput='filterColumn(""$tableId"",1,this.value)'></th>", $vidF,
                         "<th><input type='text' oninput='filterColumn(""$tableId"",$colBase,this.value)'></th>",
                         "<th><input type='text' oninput='filterColumn(""$tableId"",$($colBase+1),this.value)'></th>",
                         "<th><input type='text' oninput='filterColumn(""$tableId"",$($colBase+2),this.value)'></th>",
                         "<th><input type='text' oninput='filterColumn(""$tableId"",$($colBase+3),this.value)'></th>",
                         "<th><input type='text' oninput='filterColumn(""$tableId"",$($colBase+4),this.value)'></th>") -join ''
        $colNames = if ($isStig) { @('Finding Status','V-ID','Severity','Check','Details','Cross-References','Remediation') }
                    else { @('Status','Severity','Check','Details','Cross-References','Remediation') }
        $ci = 0
        $visChecks = foreach ($cn in $colNames) {
            $ci++
            "<label><input type='checkbox' checked onchange='toggleColumnVisibility(""$tableId"",$ci,this.checked)'> $cn</label>"
        }
        "<div class='group-section' id='grp$gi'>" +
        "<div class='group-header' onclick='toggleModule(""grp$gi"")'><h2><span class='collapse-icon'>&#9660;</span>$(ConvertTo-SafeHtml $g) <span class='group-count'>($($grpResults.Count))</span></h2></div>" +
        "<div class='group-body'>" +
        "<div class='group-stats'>$statsLine</div>" +
        "<div class='tbl-controls'>" +
        "<button onclick='showExportModal(""$tableId"",false)'>Export section</button>" +
        "<button onclick='showExportModal(""$tableId"",true)'>Export selected</button>" +
        "<span class='colvis-wrap'><button onclick='toggleColVis(this)'>Columns</button><span class='colvis-box'>$($visChecks -join '')</span></span>" +
        "</div>" +
        "<table class='findings' id='$tableId'><thead><tr>$headerCells</tr><tr class='filter-row'>$filterCells</tr></thead><tbody>$($rows -join '')</tbody></table>" +
        "</div></div>"
    }

    # Remediation index
    $remItems = @($scoredResults | Where-Object { $_.Status -in @('Fail','Warning') -and $_.Remediation } |
        Sort-Object @{Expression={ switch ("$($_.Severity)") { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} default {4} } }})
    $remHtml = if ($remItems.Count -gt 0) {
        $rrows = foreach ($ri in ($remItems | Select-Object -First 50)) {
            "<tr><td class='sev-$(("$($ri.Severity)").ToLower())'>$(ConvertTo-SafeHtml "$($ri.Severity)")</td><td>$(ConvertTo-SafeHtml "$($ri.Message)")</td><td><code>$(ConvertTo-SafeHtml "$($ri.Remediation)")</code></td></tr>"
        }
        New-CollapsibleSection -Id 'remediation' -Title "Remediation Index ($($remItems.Count) actionable, top 50 shown)" -BodyHtml "<table class='mini'><thead><tr><th class='col-severity'>Severity</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>$($rrows -join '')</tbody></table>"
    } else {
        New-CollapsibleSection -Id 'remediation' -Title 'Remediation Index' -BodyHtml '<p>No actionable remediation items in this run.</p>'
    }

    # Executive summary cells
    $postureCells = foreach ($k in $posture.Cells.Keys) {
        $edge = switch -Wildcard ("$k") {
            'Open*'          { 'edge-fail' }
            'Not a Finding'  { 'edge-pass' }
            'Not Reviewed'   { 'edge-info' }
            default          { 'edge-total' }
        }
        "<div class='metric-card $edge'><h3>$(ConvertTo-SafeHtml $k)</h3><div class='metric-value'>$(ConvertTo-SafeHtml "$($posture.Cells[$k])")</div></div>"
    }
    $sevCells = foreach ($k in $sevCounts.Keys) {
        "<div class='metric-card edge-sev-$($k.ToLower())'><h3>$k</h3><div class='metric-value sev-$($k.ToLower())'>$($sevCounts[$k])</div></div>"
    }
    $donut = New-StatusDonutSvg -Counts $statusCounts

    # ---- Round 2 spine additions (operator-grounded parity 2026-07-21) ----
    # Host/scope cards (Linux split spine: Hostname, IP Address(es), OS, Scan
    # Date, Modules)
    $ipList = if ($ExecutionInfo.IPAddresses) { @($ExecutionInfo.IPAddresses) -join ', ' } else { 'not collected' }
    $scanDate = if ($ExecutionInfo.ScanDate) { $ExecutionInfo.ScanDate } elseif ($ExecutionInfo.StartTime) { $ExecutionInfo.StartTime } else { (Get-Date -Format 'yyyy-MM-dd') }
    # Host identification renders as a plain info-card grid in the same style as
    # the composite report, not as its own collapsible section: it is reference
    # context for everything below, so it should always be visible.
    $hostCards = @(
        "<div class='info-card'><h3>Computer Name</h3><p>$(ConvertTo-SafeHtml ($(if ($ExecutionInfo.ComputerName) { $ExecutionInfo.ComputerName } else { $env:COMPUTERNAME })))</p></div>",
        "<div class='info-card'><h3>Operating System</h3><p>$(ConvertTo-SafeHtml ($(if ($ExecutionInfo.OSVersion) { $ExecutionInfo.OSVersion } else { 'Windows' })))</p></div>",
        "<div class='info-card'><h3>IP Address(es)</h3><p>$(ConvertTo-SafeHtml $ipList)</p></div>",
        "<div class='info-card'><h3>Scan Date</h3><p>$(ConvertTo-SafeHtml "$scanDate")</p></div>",
        "<div class='info-card'><h3>Module</h3><p>$(ConvertTo-SafeHtml $spec.DisplayName)</p></div>"
    ) -join ''
    $hostSection = "<div class='info-grid'>$hostCards</div>"

    # Result Distribution: six color-coded count cards (composite naming/colors)
    $rdTotal = @($scoredResults).Count
    # Executive-summary cards carry the same coloured left edge as the compliance
    # cards, so status and severity are distinguishable at a glance.
    $rdCards = @(
        "<div class='metric-card edge-total'><h3>Total</h3><div class='metric-value'>$rdTotal</div></div>",
        "<div class='metric-card edge-pass'><h3>Passed</h3><div class='metric-value' style='color:var(--pass)'>$($statusCounts.Pass)</div></div>",
        "<div class='metric-card edge-fail'><h3>Failed</h3><div class='metric-value' style='color:var(--fail)'>$($statusCounts.Fail)</div></div>",
        "<div class='metric-card edge-warning'><h3>Warnings</h3><div class='metric-value' style='color:var(--warning)'>$($statusCounts.Warning)</div></div>",
        "<div class='metric-card edge-info'><h3>Info</h3><div class='metric-value' style='color:var(--info)'>$($statusCounts.Info)</div></div>",
        "<div class='metric-card edge-error'><h3>Errors</h3><div class='metric-value' style='color:var(--error)'>$($statusCounts.Error)</div></div>"
    ) -join ''

    # Overall Compliance: Weighted / Simple / Severity-Adjusted cards.
    # Prefer the orchestrator's computed score; fall back to the mirrored math.
    $cscore = if ($ComplianceScore) { $ComplianceScore } else { Get-FallbackComplianceScore -Results $scoredResults }
    # Colour the compliance cards so the outcome is readable at a glance:
    # green at or above 80, amber from 60, red below 60.
    function Get-ComplianceBand {
        param([double]$Pct)
        if ($Pct -ge 80) { return @{ Class='verdict-pass'; Color='var(--pass)' } }
        if ($Pct -ge 60) { return @{ Class='verdict-warn'; Color='var(--warning)' } }
        return @{ Class='verdict-fail'; Color='var(--fail)' }
    }
    $bW = Get-ComplianceBand -Pct ([double]$cscore.WeightedPct)
    $bS = Get-ComplianceBand -Pct ([double]$cscore.SimplePct)
    $bA = Get-ComplianceBand -Pct ([double]$cscore.SeverityWeightedPct)
    # Overall Rating mirrors the composite report: the PASS/FAIL verdict drawn
    # from the weighted score against the compliance threshold.
    $verdict = if ($cscore.ContainsKey('ThresholdResult') -and $cscore.ThresholdResult) { "$($cscore.ThresholdResult)" }
               elseif ([double]$cscore.WeightedPct -ge 70) { 'PASS' } else { 'FAIL' }
    $bV = if ($verdict -eq 'PASS') { @{ Class='verdict-pass'; Color='var(--pass)' } } else { @{ Class='verdict-fail'; Color='var(--fail)' } }
    $ocCards = @(
        "<div class='metric-card $($bW.Class)'><h3>Weighted Score</h3><div class='metric-value' style='color:$($bW.Color)'>$($cscore.WeightedPct)`%</div></div>",
        "<div class='metric-card $($bV.Class)'><h3>Overall Rating</h3><div class='metric-value' style='color:$($bV.Color)'>$verdict</div></div>",
        "<div class='metric-card $($bS.Class)'><h3>Simple Score</h3><div class='metric-value' style='color:$($bS.Color)'>$($cscore.SimplePct)`%</div></div>",
        "<div class='metric-card $($bA.Class)'><h3>Severity-Adjusted Score</h3><div class='metric-value' style='color:$($bA.Color)'>$($cscore.SeverityWeightedPct)`%</div></div>"
    ) -join ''
    $ocSection = New-CollapsibleSection -Id 'overallcompliance' -Title 'Overall Compliance' -BodyHtml "<div class='metric-row'>$ocCards</div><p style='color:var(--text-secondary);font-size:.85em'>Weighted counts warnings at half credit; Simple counts passes only; Severity-Adjusted amplifies the failure rate by the Critical/High share. Informational results are excluded from all three denominators.</p>"

    # Top Priority Findings (top 10 Fail then Warning by severity rank)
    $sevRank = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
    $priority = @($scoredResults | Where-Object { $_.Status -in @('Fail','Warning') } |
        Sort-Object @{Expression={ if ($_.Status -eq 'Fail') { 0 } else { 1 } }}, @{Expression={ $v=$sevRank["$($_.Severity)"]; if ($null -eq $v) { 5 } else { $v } }} |
        Select-Object -First 10)
    $tpSection = ''
    if ($priority.Count -gt 0) {
        $tpRows = foreach ($f in $priority) {
            "<tr><td class='sev-$(("$($f.Severity)").ToLower())'>$(ConvertTo-SafeHtml "$($f.Severity)")</td>" +
            "<td><span class='badge st-$(("$($f.Status)").ToLower())'>$(ConvertTo-SafeHtml "$($f.Status)")</span></td>" +
            "<td>$(ConvertTo-SafeHtml (Get-NativeGroupName -Result $f -ModuleName $ModuleName))</td>" +
            "<td>$(ConvertTo-SafeHtml "$($f.Message)")</td>" +
            "<td>$(if ($f.Remediation) { "<code>$(ConvertTo-SafeHtml "$($f.Remediation)")</code>" })</td></tr>"
        }
        $tpSection = New-CollapsibleSection -Id 'toppriority' -Title "Top Priority Findings ($($priority.Count))" -BodyHtml "<table class='mini'><thead><tr><th class='col-severity'>Severity</th><th class='col-status'>Status</th><th>$(ConvertTo-SafeHtml $spec.GroupLabel)</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>$($tpRows -join '')</tbody></table>"
    }

    # Collapsible top sections (feedback: all sub-sections collapsible)
    $execBody = "<h2 style='margin-top:2px'>Result Distribution</h2><div class='donut-row'>$donut<div class='metric-row'>$rdCards</div></div>" +
                $(if ($posture.Mode -eq 'stig') { "<h2 style='margin-top:14px'>STIG Finding Status</h2><div class='metric-row'>$($postureCells -join '')</div>" } else { '' }) +
                "<h2 style='margin-top:14px'>Severity Distribution</h2><div class='metric-row'>$($sevCells -join '')</div>"
    $execSection = New-CollapsibleSection -Id 'exec' -Title "Executive Summary: $(ConvertTo-SafeHtml $posture.Headline)" -BodyHtml $execBody
    $tocSection  = New-CollapsibleSection -Id 'toc' -Title 'Table of Contents' -BodyHtml "<ul class='toc'>$($tocItems -join '')</ul>"
    $fwSection = ''
    $panelsJoined = ($panelsHtml -join '')
    if ($panelsJoined) {
        $fwSection = New-CollapsibleSection -Id 'fwsection' -Title (ConvertTo-SafeHtml $script:FrameworkSectionTitle) -BodyHtml $panelsJoined
    }

    $hostName = if ($ExecutionInfo.ComputerName) { $ExecutionInfo.ComputerName } else { $env:COMPUTERNAME }
    $osLabel  = if ($ExecutionInfo.OSVersion) { $ExecutionInfo.OSVersion } else { 'Windows' }
    $ranAt    = if ($ExecutionInfo.StartTime) { $ExecutionInfo.StartTime } else { (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
    $fwVer    = if ($ExecutionInfo.ScriptVersion) { $ExecutionInfo.ScriptVersion } else { '6.6.0' }
    $reportName = ($ModuleName -replace '[^\w\-]', '_')

    $html = @"
<!DOCTYPE html>
<html lang='en' data-theme='dark'>
<!-- WSA report-templates build $script:ReportTemplatesBuild | generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -->
<head>
<meta charset='utf-8'>
<title>$(ConvertTo-SafeHtml $spec.DisplayName) Report - $(ConvertTo-SafeHtml $hostName)</title>
<style>$script:ReportCss</style>
</head>
<body data-reportname='$reportName'>
<header>
<div class='theme-toggle' onclick='toggleTheme()' title='Toggle light/dark theme'><span>&#9728;</span><div class='theme-slider'></div><span>&#9790;</span></div>
<h1>$(ConvertTo-SafeHtml $spec.DisplayName) Compliance Report</h1>
<div class='authority'>$(ConvertTo-SafeHtml $spec.Authority)</div>
</header>
<main>
$hostSection
$execSection
$ocSection
$tpSection
$tocSection
$fwSection
<div class='global-controls'>
<h3>Search &amp; Export</h3>
<input type='text' id='globalSearch' placeholder='Search all findings...' oninput='globalFilter()'>
<select id='globalSearchMode' onchange='globalFilter()'><option value='include'>Include matches</option><option value='exclude'>Exclude matches</option></select>
<button onclick='clearGlobalSearch()'>Clear</button>
<button onclick='showExportModal(null,false)'>Export all</button>
<button onclick='showExportModal(null,true)'>Export selected</button>
</div>
$($findingsHtml -join '')
$proposedBlock
$remHtml
</main>
<footer>Generated by Windows Security Audit v$(ConvertTo-SafeHtml $fwVer) &nbsp;|&nbsp; $(ConvertTo-SafeHtml "$ranAt") &nbsp;|&nbsp; Grouping: $(ConvertTo-SafeHtml $spec.GroupLabel) &nbsp;|&nbsp; This per-framework report is generated alongside (not filtered from) the combined report. &nbsp;|&nbsp; Renderer build: $script:ReportTemplatesBuild</footer>
<div class='export-modal-back' id='exportModalBack' onclick='if(event.target===this)closeExportModal()'>
<div class='export-modal'>
<h3>Export Findings</h3>
<div class='scope-note' id='exportScopeNote'></div>
<div class='fmt-row'>
<button onclick="executeExport('csv')">CSV</button>
<button onclick="executeExport('json')">JSON</button>
<button onclick="executeExport('xml')">XML</button>
<button onclick="executeExport('txt')">TXT</button>
<button onclick="executeExport('xls')">Excel</button>
</div>
<div class='fmt-row'><button onclick='closeExportModal()'>Cancel</button></div>
</div>
</div>
<script>$script:ReportJs</script>
</body>
</html>
"@
    return $html
}

# ============================================================================
# Companion data exports (per-framework CSV / JSON / XML)
# ============================================================================
function Export-FrameworkCsv {
    param([array]$Results, [string]$Path)
    $Results | Select-Object Module, Category, Status, Severity, Message, Details, Remediation |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Export-FrameworkJson {
    param([array]$Results, [string]$Path, [hashtable]$ExecutionInfo = @{}, [string]$ModuleName = '')
    $payload = @{
        module        = $ModuleName
        generatedAt   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        executionInfo = $ExecutionInfo
        resultCount   = @($Results).Count
        results       = @($Results | Select-Object Module, Category, Status, Severity, Message, Details, Remediation, CrossReferences, Timestamp)
    }
    $payload | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding UTF8
}

function Export-FrameworkXml {
    param([array]$Results, [string]$Path, [string]$ModuleName = '')
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine("<frameworkReport module=""$([System.Security.SecurityElement]::Escape($ModuleName))"" generated=""$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"">")
    foreach ($r in $Results) {
        [void]$sb.AppendLine('  <finding>')
        foreach ($prop in 'Category','Status','Severity','Message','Details','Remediation') {
            $v = [System.Security.SecurityElement]::Escape("$($r.$prop)")
            [void]$sb.AppendLine("    <$($prop.ToLower())>$v</$($prop.ToLower())>")
        }
        [void]$sb.AppendLine('  </finding>')
    }
    [void]$sb.AppendLine('</frameworkReport>')
    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
}

# ============================================================================
# Export driver
# ============================================================================
function Export-FrameworkReports {
    <#
    .SYNOPSIS
        Write tailored per-framework reports. HTML always; CSV/JSON/XML
        companions per the requested formats (mirrors the Linux project's
        format-aware split exports).
    .OUTPUTS
        Array of file paths written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][array]$AllResults,
        [Parameter(Mandatory=$true)][string]$OutputDirectory,
        [hashtable]$ExecutionInfo = @{},
        [string[]]$Formats = @('HTML','JSON'),
        [hashtable]$ComplianceScores = @{},
        [string]$HostName = ''
    )
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $written = [System.Collections.Generic.List[string]]::new()
    # v6.6.0: file naming is <Module>-Report-<hostname>-<date> so that reports
    # remain identifiable once copied out of their directory.
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    if (-not $HostName) {
        $HostName = if ($ExecutionInfo.ComputerName) { "$($ExecutionInfo.ComputerName)" } else { "$env:COMPUTERNAME" }
    }
    $hostPart = ($HostName -replace '[^\w\-\.]', '_')
    $byModule = $AllResults | Group-Object -Property Module
    foreach ($grp in $byModule) {
        $mod = "$($grp.Name)"
        if (-not $mod) { continue }
        $safeName = ($mod -replace '[^\w\-]', '_')
        $modResults = @($grp.Group)
        try {
            if ($Formats -contains 'HTML') {
                $modScore = $null
                if ($ComplianceScores -and $ComplianceScores.ContainsKey($mod)) { $modScore = $ComplianceScores[$mod] }
                $html = New-FrameworkReportHtml -ModuleName $mod -Results $modResults -ExecutionInfo $ExecutionInfo -ComplianceScore $modScore
                $path = Join-Path $OutputDirectory "$safeName-Report-$hostPart-$stamp.html"
                $html | Out-File -FilePath $path -Encoding UTF8
                $written.Add($path)
            }
            if ($Formats -contains 'CSV') {
                $path = Join-Path $OutputDirectory "$safeName-Report-$hostPart-$stamp.csv"
                Export-FrameworkCsv -Results $modResults -Path $path
                $written.Add($path)
            }
            if ($Formats -contains 'JSON') {
                $path = Join-Path $OutputDirectory "$safeName-Report-$hostPart-$stamp.json"
                Export-FrameworkJson -Results $modResults -Path $path -ExecutionInfo $ExecutionInfo -ModuleName $mod
                $written.Add($path)
            }
            if ($Formats -contains 'XML') {
                $path = Join-Path $OutputDirectory "$safeName-Report-$hostPart-$stamp.xml"
                Export-FrameworkXml -Results $modResults -Path $path -ModuleName $mod
                $written.Add($path)
            }
        } catch {
            Write-Warning "Framework report for '$mod' failed: $($_.Exception.Message)"
        }
    }
    return $written
}
