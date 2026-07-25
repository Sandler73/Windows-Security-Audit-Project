# attack-surface.ps1
# Attack-surface assessment for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Synthesizes an attack-surface assessment from audit results: per-domain
    exposure scoring and cross-domain highlights.

.DESCRIPTION
    Parity equivalent of the Linux attack_surface component, with Windows
    domains and the reference's hard-won design decisions carried over intact:

    DETERMINISTIC DOMAIN RESOLUTION (from the Linux v3.9 P5.3 rework): the
    original substring-over-details matcher produced ~38% unmapped and ~15%
    multi-counted results, plus false positives (a keyword matching inside a
    larger word). This component instead:
      Stage 1: word-boundary regex against the CATEGORY only (categories are
               curated, host-independent identifiers)
      Stage 2: fallback to the MESSAGE only (never Details -- that is where
               host-specific noise lives)
      Tie-break: a priority order selects exactly ONE primary domain, so no
               finding is double-counted.
    Word boundaries prevent substring false positives (e.g. \bSMB\b cannot
    match inside 'SMBGhost' commentary; \bRDP\b is a whole token).

    EXPOSURE SCORING (identical math to the reference): each mapped finding
    contributes severity_weight * status_multiplier; a domain's score is
    100 * accumulated_contribution / max_possible (capped at 100); the overall
    score is a sqrt(finding-count)-weighted mean across domains. Only non-Pass
    statuses contribute. Ratings: Minimal <10, Low <25, Moderate <50,
    Elevated <75, High otherwise.

    Windows domains: Network Exposure; Remote Access (RDP/WinRM/SMB);
    Authentication & Access; Privilege & Escalation (UAC/LSA/tokens);
    Credential Exposure (LSASS/WDigest/cached creds); Service & Daemon Surface;
    Endpoint Protection (Defender/ASR/SmartScreen); Cryptographic Posture
    (TLS/SMB signing/BitLocker); Application & Execution Control
    (AppLocker/WDAC/macros/PowerShell); Detection & Response (auditing/logging).

    The rendered report is produced through report-templates.ps1's shared
    spine (collapsible sections, dark/light toggle, search/export) when that
    component is present, so it matches the framework's other reports; a
    self-contained fallback renderer is used otherwise.

.EXAMPLE
    . .\shared_components\attack-surface.ps1
    $surface = New-AttackSurface -AllResults $results -HostFacts $hf
    Export-AttackSurfaceReport -Surface $surface -OutputPath .\attack-surface.html -ExecutionInfo $exec

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: report-templates.ps1 optional (shared spine + HTML encoding);
    self-contained fallback otherwise
    Security: read-only synthesis over existing results; no host queries here
    Version: 6.6.0
#>

# ============================================================================
# Weights (identical to the reference)
# ============================================================================
$script:AS_SeverityWeight = @{
    'Critical' = 10.0; 'High' = 6.0; 'Medium' = 3.0; 'Low' = 1.0
    'Informational' = 0.5; '' = 2.0
}
$script:AS_StatusMultiplier = @{
    'Fail' = 1.0; 'Warning' = 0.5; 'Info' = 0.15; 'Error' = 0.25; 'Pass' = 0.0
}

# ============================================================================
# Windows attack-surface domains: Name, Keywords, Description.
# Display order here; priority (tie-break) declared separately below.
# ============================================================================
$script:AS_Domains = @(
    @{ Name = 'Network Exposure'
       Keywords = @('listening','open port','firewall','netbios','llmnr','smb','tcp','udp','port','ports','network','ipv6','ipv4','ingress','egress','exposed')
       Description = 'Network-reachable services and perimeter controls. The primary remote attack surface.' }
    @{ Name = 'Remote Access'
       Keywords = @('rdp','remote desktop','winrm','remote management','psremoting','terminal server','nla','wsman')
       Description = 'Interactive and programmatic remote-management entry points. High-value initial-access targets.' }
    @{ Name = 'Authentication & Access'
       Keywords = @('password','logon','lockout','account','mfa','multi-factor','smartcard','kerberos','ntlm','lmcompatibility','anonymous','guest','authentication','credential guard')
       Description = 'How identities prove themselves and how access is gated. Weak authentication is the most-exploited initial-access vector.' }
    @{ Name = 'Privilege & Escalation'
       Keywords = @('uac','enablelua','privilege','elevation','administrator','admin rights','token','runas','lsa protection','runasppl','sudo','consentprompt')
       Description = 'Paths from limited access to elevated control. Determines blast radius once a foothold is gained.' }
    @{ Name = 'Credential Exposure'
       Keywords = @('lsass','wdigest','cached credential','cached logon','credential caching','password in','plaintext','stored credential','dpapi','secret')
       Description = 'Credentials at rest or in memory that, if read, grant access elsewhere. Often the pivot in lateral movement.' }
    @{ Name = 'Service & Daemon Surface'
       Keywords = @('service','daemon','legacy','cleartext','telnet','ftp','tftp','snmp','spooler','unnecessary','running service','startup')
       Description = 'Installed and running services. Each service is code that can be attacked; legacy/cleartext services are especially dangerous.' }
    @{ Name = 'Endpoint Protection'
       Keywords = @('defender','antivirus','anti-malware','realtime','real-time','asr','attack surface reduction','smartscreen','tamper','controlled folder','network protection')
       Description = 'Preventive endpoint controls. Gaps here remove the last line of on-host defense.' }
    @{ Name = 'Cryptographic Posture'
       Keywords = @('tls','ssl','cipher','certificate','encryption','bitlocker','smb signing','signing','sha1','md5','rc4','3des','weak algorithm','at rest','in transit')
       Description = 'Strength and configuration of cryptography. Weak crypto undermines confidentiality and integrity guarantees.' }
    @{ Name = 'Application & Execution Control'
       Keywords = @('applocker','wdac','application control','macro','office macro','script block','powershell','constrained language','execution policy','autorun','autoplay')
       Description = 'Controls over what code may run. Weak execution control lets malicious or unwanted code execute freely.' }
    @{ Name = 'Detection & Response'
       Keywords = @('audit','auditing','auditpol','logging','event log','sysmon','siem','monitoring','alert','detection','forwarding','backup','recovery','incident')
       Description = 'Visibility into attacks. Low coverage does not create an opening but lets intrusions proceed undetected, raising effective risk.' }
)

# Priority order (domain indices, most specific first) for single-primary
# selection. Specific exposure domains precede broad ones; Detection & Response
# last (it overlaps many). Must be a permutation of 0..N-1.
$script:AS_DomainPriority = @(1, 4, 6, 3, 7, 8, 2, 0, 5, 9)

# Precompiled word-boundary pattern per domain (compiled once at load)
$script:AS_DomainPatterns = @()
foreach ($dom in $script:AS_Domains) {
    $escaped = @($dom.Keywords | ForEach-Object { [regex]::Escape($_) } | Sort-Object { $_.Length } -Descending)
    $script:AS_DomainPatterns += [regex]::new('\b(?:' + ($escaped -join '|') + ')\b',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-AttackSurfaceRating {
    param([double]$Score)
    if ($Score -lt 10) { return 'Minimal' }
    if ($Score -lt 25) { return 'Low' }
    if ($Score -lt 50) { return 'Moderate' }
    if ($Score -lt 75) { return 'Elevated' }
    return 'High'
}

function Resolve-PrimaryDomain {
    <#
    .SYNOPSIS
        Return the single primary domain index for a result (or -1). Category
        first, then message; word-boundary matched; priority tie-broken. Never
        reads Details (host-specific noise).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Result)
    $category = "$($Result.Category)"
    $message  = "$($Result.Message)"
    foreach ($text in @($category, $message)) {
        if (-not $text) { continue }
        foreach ($idx in $script:AS_DomainPriority) {
            if ($script:AS_DomainPatterns[$idx].IsMatch($text)) { return $idx }
        }
    }
    return -1
}

function New-AttackSurface {
    <#
    .SYNOPSIS
        Synthesize the attack-surface assessment from audit results.
    .OUTPUTS
        PSCustomObject: OverallScore, OverallRating, Domains[], HighlightFindings[],
        TotalFindingsConsidered, HostSummary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][array]$AllResults,
        [hashtable]$HostFacts = $null
    )
    $n = $script:AS_Domains.Count
    $exposureRaw = New-Object 'double[]' $n
    $maxPossible = New-Object 'double[]' $n
    $totals = New-Object 'int[]' $n
    $fails  = New-Object 'int[]' $n
    $warns  = New-Object 'int[]' $n
    $infos  = New-Object 'int[]' $n
    $domainFindings = @(); for ($i = 0; $i -lt $n; $i++) { $domainFindings += ,([System.Collections.Generic.List[object]]::new()) }
    $allExposure = [System.Collections.Generic.List[object]]::new()
    $considered = 0

    foreach ($r in $AllResults) {
        $d = Resolve-PrimaryDomain -Result $r
        if ($d -lt 0) { continue }
        $considered++
        $sev = "$($r.Severity)".Trim()
        if ($sev) { $sev = $sev.Substring(0,1).ToUpper() + $sev.Substring(1).ToLower() }
        $sevKey = if ($script:AS_SeverityWeight.ContainsKey($sev)) { $sev } elseif ($sev -eq '') { '' } else { 'Medium' }
        $weight = $script:AS_SeverityWeight[$sevKey]
        $status = "$($r.Status)"
        $mult = if ($script:AS_StatusMultiplier.ContainsKey($status)) { $script:AS_StatusMultiplier[$status] } else { 0.0 }
        $contribution = $weight * $mult

        $totals[$d]++
        $maxPossible[$d] += $weight
        $exposureRaw[$d] += $contribution
        if ($status -eq 'Fail') { $fails[$d]++ }
        elseif ($status -eq 'Warning') { $warns[$d]++ }
        elseif ($status -eq 'Info') { $infos[$d]++ }

        if ($mult -gt 0) {
            $finding = [PSCustomObject]@{
                Module = "$($r.Module)"; Category = "$($r.Category)"; Message = "$($r.Message)"
                Status = $status; Severity = $(if ($sevKey) { $sevKey } else { 'Medium' })
                Details = "$($r.Details)"; Remediation = "$($r.Remediation)"; Weight = $contribution
                Domain = $script:AS_Domains[$d].Name
            }
            $domainFindings[$d].Add($finding)
            $allExposure.Add($finding)
        }
    }

    $domainsOut = [System.Collections.Generic.List[object]]::new()
    $weightedSum = 0.0; $weightTotal = 0.0
    for ($d = 0; $d -lt $n; $d++) {
        $score = if ($maxPossible[$d] -gt 0) { [Math]::Min(100.0, 100.0 * $exposureRaw[$d] / $maxPossible[$d]) } else { 0.0 }
        $top = @($domainFindings[$d] | Sort-Object { -$_.Weight })
        $domainsOut.Add([PSCustomObject]@{
            Name = $script:AS_Domains[$d].Name
            Description = $script:AS_Domains[$d].Description
            ExposureScore = [Math]::Round($score, 1)
            Rating = (Get-AttackSurfaceRating -Score $score)
            TotalFindings = $totals[$d]
            FailCount = $fails[$d]; WarningCount = $warns[$d]; InfoCount = $infos[$d]
            TopFindings = $top
        })
        $domainWeight = [Math]::Max(1.0, [Math]::Sqrt($totals[$d]))
        $weightedSum += $score * $domainWeight
        $weightTotal += $domainWeight
    }
    $overall = if ($weightTotal -gt 0) { [Math]::Round($weightedSum / $weightTotal, 1) } else { 0.0 }
    $highlights = @($allExposure | Sort-Object { -$_.Weight } | Select-Object -First 40)

    $hostSummary = [ordered]@{}
    if ($HostFacts) {
        foreach ($k in @('ComputerName','OSVersion','IsDomainController','IsServer','FirewallEnabled','DefenderEnabled')) {
            if ($HostFacts.Contains($k)) { $hostSummary[$k] = "$($HostFacts[$k])" }
        }
    }

    return [PSCustomObject]@{
        OverallScore = $overall
        OverallRating = (Get-AttackSurfaceRating -Score $overall)
        Domains = @($domainsOut)
        HighlightFindings = $highlights
        TotalFindingsConsidered = $considered
        HostSummary = $hostSummary
    }
}

# ============================================================================
# Rendering
# ============================================================================
$script:AttackSurfaceCss = @'
.subtitle{color:var(--text-secondary);font-size:.95em;margin-top:5px}
/* Sections span the page like the composite report rather than sitting inset,
   which reduces wrapping in the wide findings tables. */
main{max-width:none;margin:0}
footer{max-width:none;margin:24px 0 0}
/* Card edges, matching the audit reports. */
.metric-card.edge-total{border-left:4px solid var(--accent)}
.metric-card.edge-fail{border-left:4px solid #f85149}
.metric-card.edge-warning{border-left:4px solid #d29922}
.metric-card.edge-info{border-left:4px solid #58a6ff}
.metric-card.edge-domains{border-left:4px solid #8b949e}
.as-exec-row{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.as-exec-side{flex:1;min-width:300px}
.as-gauge{flex:0 0 auto}
.as-scale{display:flex;gap:4px;margin-bottom:6px}
.as-band{flex:1;text-align:center;padding:5px 4px;border-radius:5px;font-size:.82em}
.as-bars{display:flex;flex-direction:column;gap:6px;margin-top:6px}
.as-bar-row{display:flex;align-items:center;gap:10px}
.as-bar-label{flex:0 0 210px;font-size:.9em;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.as-bar-track{flex:1;background:var(--bg-tertiary);border-radius:5px;height:15px;overflow:hidden}
.as-bar-fill{height:100%;border-radius:5px}
.as-bar-val{flex:0 0 46px;text-align:right;font-size:.9em}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:18px 0}
.info-card{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:12px 16px;box-shadow:0 2px 8px var(--card-shadow)}
.info-card h3{font-size:.75em;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.info-card p{color:var(--text-primary);font-size:1.02em;word-wrap:break-word}
.toc{columns:2;column-gap:28px;list-style:none}
.toc li{margin:2px 0;break-inside:avoid}
.toc a{color:var(--accent);text-decoration:none}
.toc a:hover{text-decoration:underline}
table.findings th.col-status{width:104px}
table.findings th.col-severity{width:92px}
@media print{.theme-toggle{display:none !important}}
'@

function Get-RatingColor {
    param([string]$Rating)
    switch ($Rating) {
        'Minimal'  { '#3fb950' }
        'Low'      { '#57ab5a' }
        'Moderate' { '#d29922' }
        'Elevated' { '#db6d28' }
        'High'     { '#f85149' }
        default    { '#8b949e' }
    }
}

function Export-AttackSurfaceReport {
    <#
    .SYNOPSIS
        Render the attack-surface assessment as an HTML report and write it.
        Uses report-templates.ps1's ConvertTo-SafeHtml and CSS/JS spine when
        available; otherwise a self-contained fallback.
    .OUTPUTS
        The output path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$Surface,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [hashtable]$ExecutionInfo = @{}
    )

    $haveSpine = (Get-Command 'ConvertTo-SafeHtml' -ErrorAction SilentlyContinue) -and (Get-Command 'New-CollapsibleSection' -ErrorAction SilentlyContinue)
    $enc = if ($haveSpine) { { param($s) ConvertTo-SafeHtml $s } } else {
        { param($s) if ($null -eq $s) { '' } else { "$s".Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;') } }
    }

    $hostName = if ($ExecutionInfo.ComputerName) { $ExecutionInfo.ComputerName } else { $env:COMPUTERNAME }
    $osLabel  = if ($ExecutionInfo.OSVersion) { $ExecutionInfo.OSVersion } else { 'Windows' }
    $fwVer    = if ($ExecutionInfo.ScriptVersion) { $ExecutionInfo.ScriptVersion } else { '6.6.0' }
    $ipList   = if ($ExecutionInfo.IPAddresses) { (@($ExecutionInfo.IPAddresses) -join ', ') } else { 'not collected' }

    # Host identification cards, matching the audit reports. The header no
    # longer restates this detail: it would duplicate the cards.
    $scanDate = if ($ExecutionInfo.ScanDate) { $ExecutionInfo.ScanDate }
                elseif ($ExecutionInfo.StartTime) { $ExecutionInfo.StartTime }
                else { (Get-Date -Format 'yyyy-MM-dd') }
    $hostCardsHtml = "<div class='info-grid'>" +
        "<div class='info-card'><h3>Computer Name</h3><p>$(& $enc $hostName)</p></div>" +
        "<div class='info-card'><h3>Operating System</h3><p>$(& $enc $osLabel)</p></div>" +
        "<div class='info-card'><h3>IP Address(es)</h3><p>$(& $enc $ipList)</p></div>" +
        "<div class='info-card'><h3>Scan Date</h3><p>$(& $enc "$scanDate")</p></div>" +
        "</div>"

    # Table of contents: summary, highlights, then each domain in rank order.
    $tocEntries = [System.Collections.Generic.List[string]]::new()
    $tocEntries.Add("<li><a href='#asoverall'>Executive Summary</a></li>")
    $tocEntries.Add("<li><a href='#ashighlights'>Cross-Domain Highlights</a></li>")
    $tocEntries.Add("<li><a href='#asdomains'>Exposure Domains</a></li>")
    foreach ($d in ($Surface.Domains | Sort-Object { -$_.ExposureScore })) {
        $safeId = ($d.Name -replace '[^\w]', '')
        $dc = Get-RatingColor -Rating $d.Rating
        $tocEntries.Add("<li><a href='#asdom$safeId'>$(& $enc $d.Name)</a> <span style='color:$dc'>($($d.ExposureScore))</span></li>")
    }
    $tocHtml = "<div class='panel'><h2>Table of Contents</h2><ul class='toc'>$($tocEntries -join '')</ul></div>"

    $overallColor = Get-RatingColor -Rating $Surface.OverallRating

    # --- Executive summary visuals ----
    # A single headline number was too thin a summary, so the panel now leads
    # with a radial gauge, the position of the score on the rating scale, the
    # contributing-finding mix, and a ranked bar chart of domain exposure. The
    # visuals sit at the top of the report because non-technical readers take
    # the summary from the first screen.
    $pct = [Math]::Max(0, [Math]::Min(100, [double]$Surface.OverallScore))

    # Radial gauge: 270-degree arc, value arc over a track arc.
    $r = 78; $circ = 2 * [Math]::PI * $r
    $arcSpan = 0.75            # three-quarter circle
    $track = [Math]::Round($circ * $arcSpan, 2)
    $gap   = [Math]::Round($circ - $track, 2)
    $val   = [Math]::Round($circ * $arcSpan * ($pct / 100.0), 2)
    $valGap= [Math]::Round($circ - $val, 2)
    $gauge = "<div class='as-gauge'><svg width='210' height='190' viewBox='0 0 200 190'>" +
             "<g transform='rotate(135 100 100)'>" +
             "<circle r='$r' cx='100' cy='100' fill='transparent' stroke='var(--bg-tertiary)' stroke-width='18' stroke-dasharray='$track $gap' stroke-linecap='round'></circle>" +
             "<circle r='$r' cx='100' cy='100' fill='transparent' stroke='$overallColor' stroke-width='18' stroke-dasharray='$val $valGap' stroke-linecap='round'></circle>" +
             "</g>" +
             "<text x='100' y='104' text-anchor='middle' fill='$overallColor' font-size='42' font-family='Garamond'>$($Surface.OverallScore)</text>" +
             "<text x='100' y='128' text-anchor='middle' fill='var(--text-secondary)' font-size='13' font-family='Garamond'>of 100</text>" +
             "</svg><div style='text-align:center;font-size:1.25em;color:$overallColor'>$(& $enc $Surface.OverallRating) exposure</div></div>"

    # Rating scale showing where this host sits.
    $scaleCells = foreach ($band in @(
        @{N='Minimal';  Lo=0;  Hi=10},  @{N='Low';      Lo=10; Hi=25},
        @{N='Moderate'; Lo=25; Hi=50},  @{N='Elevated'; Lo=50; Hi=75},
        @{N='High';     Lo=75; Hi=100})) {
        $bc = Get-RatingColor -Rating $band.N
        $active = ($Surface.OverallRating -eq $band.N)
        $style = if ($active) { "background:$bc;color:#0b0e14;font-weight:bold" } else { "background:var(--bg-tertiary);color:var(--text-secondary)" }
        "<div class='as-band' style='$style' title='$($band.Lo)-$($band.Hi)'>$($band.N)</div>"
    }
    $scaleBar = "<div class='as-scale'>$($scaleCells -join '')</div>" +
                "<div style='color:var(--text-secondary);font-size:.85em;text-align:center'>0 = minimal attack surface, 100 = maximal</div>"

    # Contributing-finding mix across all mapped domains.
    $mixCounts = @{ Fail=0; Warning=0; Info=0; Error=0 }
    foreach ($d in $Surface.Domains) {
        $mixCounts.Fail    += $d.FailCount
        $mixCounts.Warning += $d.WarningCount
        $mixCounts.Info    += $d.InfoCount
    }
    $mixCards = @(
        "<div class='metric-card edge-total'><h3>Findings Mapped</h3><div class='metric-value'>$($Surface.TotalFindingsConsidered)</div></div>",
        "<div class='metric-card edge-domains'><h3>Domains</h3><div class='metric-value'>$($Surface.Domains.Count)</div></div>",
        "<div class='metric-card edge-fail'><h3>Failing</h3><div class='metric-value' style='color:#f85149'>$($mixCounts.Fail)</div></div>",
        "<div class='metric-card edge-warning'><h3>Warnings</h3><div class='metric-value' style='color:#d29922'>$($mixCounts.Warning)</div></div>",
        "<div class='metric-card edge-info'><h3>Informational</h3><div class='metric-value' style='color:#58a6ff'>$($mixCounts.Info)</div></div>"
    ) -join ''

    # Ranked horizontal bar chart of per-domain exposure.
    $barRows = foreach ($d in ($Surface.Domains | Sort-Object { -$_.ExposureScore })) {
        $bc = Get-RatingColor -Rating $d.Rating
        $w = [Math]::Max(1, [double]$d.ExposureScore)
        "<div class='as-bar-row'><div class='as-bar-label' title='$(& $enc $d.Name)'>$(& $enc $d.Name)</div>" +
        "<div class='as-bar-track'><div class='as-bar-fill' style='width:$w%;background:$bc'></div></div>" +
        "<div class='as-bar-val' style='color:$bc'>$($d.ExposureScore)</div></div>"
    }
    $barChart = "<h3 style='margin:14px 0 6px;color:var(--text-primary)'>Exposure by Domain</h3><div class='as-bars'>$($barRows -join '')</div>"

    $execBody = "<div class='as-exec-row'>$gauge<div class='as-exec-side'>$scaleBar<div class='metric-row'>$mixCards</div></div></div>$barChart"

    # Domain sections
    $domainBlocks = foreach ($dom in ($Surface.Domains | Sort-Object { -$_.ExposureScore })) {
        $color = Get-RatingColor -Rating $dom.Rating
        $bar = "<div style='background:var(--bg-tertiary);border-radius:6px;height:16px;overflow:hidden;margin:6px 0'>" +
               "<div style='width:$([Math]::Max(2,$dom.ExposureScore))%;background:$color;height:100%'></div></div>"
        $findingRows = if (@($dom.TopFindings).Count -gt 0) {
            $rows = foreach ($f in $dom.TopFindings) {
                "<tr><td><span class='badge st-$(("$($f.Status)").ToLower())'>$(& $enc $f.Status)</span></td>" +
                "<td class='sev-$(("$($f.Severity)").ToLower())'>$(& $enc $f.Severity)</td>" +
                "<td>$(& $enc $f.Module)</td><td>$(& $enc $f.Message)</td>" +
                "<td>$(if ($f.Remediation) { "<code>$(& $enc $f.Remediation)</code>" })</td></tr>"
            }
            "<table class='findings'><thead><tr><th class='col-status'>Status</th><th class='col-severity'>Severity</th><th>Module</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>$($rows -join '')</tbody></table>"
        } else { "<p style='color:var(--text-secondary)'>No exposure-contributing findings mapped to this domain.</p>" }

        $body = "<p style='color:var(--text-secondary)'>$(& $enc $dom.Description)</p>" +
                "<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap'>" +
                "<div style='font-size:1.8em;color:$color'>$($dom.ExposureScore)</div>" +
                "<div style='color:$color;font-weight:bold'>$(& $enc $dom.Rating)</div>" +
                "<div style='color:var(--text-secondary);font-size:.9em'>$($dom.TotalFindings) findings &nbsp;|&nbsp; $($dom.FailCount) fail, $($dom.WarningCount) warn, $($dom.InfoCount) info</div></div>" +
                $bar + $findingRows
        $title = "$(& $enc $dom.Name) &mdash; <span style='color:$color'>$(& $enc $dom.Rating) ($($dom.ExposureScore))</span>"
        if ($haveSpine) {
            $safeId = ($dom.Name -replace '[^\w]', '')
            New-CollapsibleSection -Id "asdom$safeId" -Title $title -BodyHtml $body
        } else {
            "<div class='panel'><h2>$title</h2>$body</div>"
        }
    }

    # Highlights table
    $hlRows = foreach ($h in $Surface.HighlightFindings) {
        "<tr><td><span class='badge st-$(("$($h.Status)").ToLower())'>$(& $enc $h.Status)</span></td>" +
        "<td class='sev-$(("$($h.Severity)").ToLower())'>$(& $enc $h.Severity)</td>" +
        "<td>$(& $enc $h.Domain)</td><td>$(& $enc $h.Module)</td><td>$(& $enc $h.Message)</td></tr>"
    }
    $hlTable = "<table class='findings'><thead><tr><th class='col-status'>Status</th><th class='col-severity'>Severity</th><th>Domain</th><th>Module</th><th>Finding</th></tr></thead><tbody>$($hlRows -join '')</tbody></table>"

    # Reuse the report-templates CSS/JS spine if present, else a minimal dark sheet
    if ($haveSpine -and $script:ReportCss) {
        $css = $script:ReportCss + $script:AttackSurfaceCss; $js = $script:ReportJs
        $gaugeSection   = New-CollapsibleSection -Id 'asoverall' -Title "Executive Summary: $(& $enc $Surface.OverallRating) exposure ($($Surface.OverallScore)/100)" -BodyHtml $execBody
        $highlightSect  = New-CollapsibleSection -Id 'ashighlights' -Title "Cross-Domain Highlights (top $(@($Surface.HighlightFindings).Count))" -BodyHtml $hlTable
        $domainWrap     = $domainBlocks -join ''
        $themeToggle    = "<div class='theme-toggle' onclick='toggleTheme()' title='Toggle light/dark theme'><span>&#9728;</span><div class='theme-slider'></div><span>&#9790;</span></div>"
        $bodyAttr = "data-theme='dark' data-reportname='attack-surface'"
    } else {
        $css = $script:AttackSurfaceCss + ":root{--bg-primary:#0b0e14;--bg-secondary:#111822;--bg-tertiary:#1a2332;--text-primary:#c9d1d9;--text-secondary:#8b949e;--border-color:#21262d;--accent:#58a6ff}body{font-family:Garamond,serif;background:var(--bg-primary);color:var(--text-primary);margin:0;padding:0 0 40px}header{background:linear-gradient(135deg,#060a10,#0d1520);padding:26px 34px;border-bottom:2px solid var(--accent);text-align:center}main{max-width:none;margin:0;padding:22px 34px}.panel{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:18px;margin:16px 0}table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.92em}th{background:var(--bg-tertiary);text-align:left;padding:8px;border-bottom:2px solid var(--accent)}td{padding:7px 8px;border-bottom:1px solid var(--border-color);word-wrap:break-word}.badge{padding:1px 8px;border-radius:10px;border:1px solid}.st-fail{color:#f85149;border-color:#f85149}.st-warning{color:#d29922;border-color:#d29922}.st-info{color:#58a6ff;border-color:#58a6ff}.st-pass{color:#3fb950;border-color:#3fb950}.st-error{color:#bc8cff;border-color:#bc8cff}.sev-critical{color:#f85149}.sev-high{color:#db6d28}.sev-medium{color:#d29922}.sev-low{color:#58a6ff}code{color:#9ecbff;font-family:Consolas,monospace}"
        $js = ''
        $gaugeSection = "<div class='panel'><h2>Executive Summary: $(& $enc $Surface.OverallRating) exposure ($($Surface.OverallScore)/100)</h2>$execBody</div>"
        $highlightSect = "<div class='panel'><h2>Cross-Domain Highlights</h2>$hlTable</div>"
        $domainWrap = $domainBlocks -join ''
        $themeToggle = ''
        $bodyAttr = "data-reportname='attack-surface'"
    }

    $buildStamp = if ($script:ReportTemplatesBuild) { $script:ReportTemplatesBuild } else { $fwVer }
    $html = @"
<!DOCTYPE html>
<html lang='en' data-theme='dark'>
<!-- WSA attack-surface report build $buildStamp | generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -->
<head>
<meta charset='utf-8'>
<title>Attack Surface Assessment - $(& $enc $hostName)</title>
<style>$css</style>
</head>
<body $bodyAttr>
<header>
$themeToggle
<h1>Attack Surface Assessment</h1>
<div class='subtitle'>Exposure synthesis across $($Surface.Domains.Count) Windows domains</div>
</header>
<main>
$hostCardsHtml
$tocHtml
$gaugeSection
$highlightSect
<h2 id='asdomains' style='margin:20px 0 4px'>Exposure Domains (highest first)</h2>
$domainWrap
</main>
<footer style='margin:20px 0 0;padding:12px 34px 0;color:var(--text-secondary);font-size:.85em;border-top:1px solid var(--border-color)'>Generated by Windows Security Audit v$(& $enc $fwVer) &nbsp;|&nbsp; Attack-surface build: $(& $enc $buildStamp) &nbsp;|&nbsp; Exposure is synthesized from audit findings; it does not run additional host queries.</footer>
$(if ($js) { "<script>$js</script>" })
</body>
</html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    return $OutputPath
}

# Backwards-compatible alias. 'Build' is not an approved PowerShell verb, so the
# function was renamed; the original name remains available to existing callers.
Set-Alias -Name Build-AttackSurface -Value New-AttackSurface -Scope Script -Force
