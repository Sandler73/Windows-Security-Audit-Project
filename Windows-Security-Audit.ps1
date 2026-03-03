# Windows-Security-Audit.ps1
# Comprehensive Windows Security Audit Script
# Version: 6.0
# GitHub: https://github.com/Sandler73/Windows-Security-Audit-Script

<#
.SYNOPSIS
    Comprehensive module-based Windows security audit script supporting multiple
    compliance frameworks with parallel execution, caching, structured logging,
    and compliance scoring.

.DESCRIPTION
    This script audits Windows systems against multiple security frameworks:
    - Core Security Baseline        - ENISA Cybersecurity Recommendations
    - CIS Benchmarks                - ISO 27001 Annex A Technology Controls
    - CISA Best Practices           - Microsoft Security Baseline
    - DISA STIGs                    - Microsoft Defender for Endpoint/EDR
    - NIST Cybersecurity Framework  - NSA Cybersecurity Guidance

    v6.0 Features:
    - SharedDataCache (reads registry/WMI/policies once, shares across modules)
    - Parallel module execution via RunspacePool
    - Structured logging with file + console output (incl. JSON for SIEM)
    - Compliance scoring (simple%, weighted%, severity-weighted%)
    - Severity levels on all results (Critical/High/Medium/Low/Informational)
    - Cross-framework reference mapping
    - Enhanced interactive HTML dashboard with SVG charts
    - Performance profiling and cache statistics

.PARAMETER Modules
    Comma-separated list of modules. Available: Core,CIS,MS,NIST,STIG,NSA,CISA,MS-DefenderATP,ENISA,ISO27001,All
.PARAMETER OutputFormat
    Output format: HTML, CSV, JSON, XML, or Console. Default: HTML
.PARAMETER OutputPath
    Path for output file. Default: .\reports\Windows-Security-Audit-Report-[timestamp].[ext]
.PARAMETER RemediateIssues
    Interactively remediate failed checks
.PARAMETER RemediateIssues_Fail
    Remediate only FAIL status issues
.PARAMETER RemediateIssues_Warning
    Remediate only WARNING status issues
.PARAMETER RemediateIssues_Info
    Remediate only INFO status issues
.PARAMETER AutoRemediate
    Automatically remediate without prompting
.PARAMETER RemediationFile
    JSON file with specific issues to remediate (from HTML report export)
.PARAMETER Parallel
    Execute modules in parallel for faster completion
.PARAMETER Workers
    Number of parallel workers (default: 4, max: 16)
.PARAMETER NoCache
    Disable shared data caching (for debugging)
.PARAMETER ShowProfile
    Show detailed timing/performance breakdown
.PARAMETER LogLevel
    Logging verbosity: DEBUG, INFO, WARNING, ERROR. Default: INFO
.PARAMETER LogFile
    Path to write detailed log file
.PARAMETER JsonLog
    Use JSON format for log file (for SIEM ingestion)
.PARAMETER ListModules
    List all available modules and exit
.PARAMETER Quiet
    Suppress non-essential output including auto-open of HTML report

.EXAMPLE
    .\Windows-Security-Audit.ps1
    Run all modules with default HTML output
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Parallel -Workers 8 -ShowProfile
    Run all modules in parallel with performance breakdown
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Modules Core,NIST -OutputFormat CSV -LogLevel DEBUG
    Run specific modules with CSV output and debug logging

.NOTES
    Requires: Windows 10/11 or Windows Server 2016+, PowerShell 5.1+
    Run as Administrator for complete results
    Version: 6.0
#>

param(
    [ValidateSet("Core","CIS","MS","NIST","STIG","NSA","CISA","MS-DefenderATP","ENISA","ISO27001","All")]
    [string[]]$Modules = @("All"),
    [ValidateSet("HTML","CSV","JSON","XML","All","Console")]
    [string]$OutputFormat = "HTML",
    [string]$OutputPath = "",
    [switch]$RemediateIssues,
    [switch]$RemediateIssues_Fail,
    [switch]$RemediateIssues_Warning,
    [switch]$RemediateIssues_Info,
    [switch]$AutoRemediate,
    [string]$RemediationFile = "",
    [switch]$Parallel,
    [ValidateRange(1,16)][int]$Workers = 4,
    [switch]$NoCache,
    [switch]$ShowProfile,
    [ValidateSet("DEBUG","INFO","WARNING","ERROR")]
    [string]$LogLevel = "INFO",
    [string]$LogFile = "",
    [switch]$JsonLog,
    [switch]$ListModules,
    [switch]$Quiet
)

$ErrorActionPreference = "Continue"
$script:ScriptVersion = "6.0"
$script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:LogDir = Join-Path $script:ScriptPath "logs"
$script:ReportDir = Join-Path $script:ScriptPath "reports"
$script:ValidStatusValues = @("Pass", "Fail", "Warning", "Info", "Error")
$script:ValidSeverityValues = @("Critical", "High", "Medium", "Low", "Informational")
$script:MAX_PARALLEL_WORKERS = 16
$script:StatisticsLog = @{ ValidationIssues = @(); NormalizedResults = 0; ModuleStats = @{} }

# Load Shared Library (audit-common.ps1)
$script:HAS_COMMON_LIB = $false
$script:CommonLibPath = Join-Path $script:ScriptPath "shared_components\audit-common.ps1"
if (Test-Path $script:CommonLibPath) {
    try {
        . $script:CommonLibPath
        $script:HAS_COMMON_LIB = $true
        # Verify critical functions loaded
        $expectedFns = @('Get-OSInfo', 'New-SharedDataCache', 'Invoke-CacheWarmUp',
                         'Initialize-AuditLogging', 'Write-AuditLog', 'New-AuditResult',
                         'Get-CachedRegistryValue', 'Get-CacheSummary')
        $missingFns = @($expectedFns | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
        if ($missingFns.Count -gt 0) {
            Write-Warning "Shared library loaded but missing functions: $($missingFns -join ', ')"
        }
    }
    catch { Write-Warning "Failed to load shared library: $_" }
}

# ============================================================================
# Banner
# ============================================================================
function Show-Banner {
    Write-Host "`n========================================================================================================" -ForegroundColor Cyan
    Write-Host "                        Windows Security Audit Script v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "                   Comprehensive Multi-Framework Security Assessment" -ForegroundColor Cyan
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "`nSupported Frameworks:" -ForegroundColor White
    Write-Host "  - Core Security Baseline          - ENISA Cybersecurity Recommendations" -ForegroundColor Gray
    Write-Host "  - CIS Benchmarks                  - ISO 27001 Annex A Controls" -ForegroundColor Gray
    Write-Host "  - CISA Best Practices             - Microsoft Security Baseline" -ForegroundColor Gray
    Write-Host "  - DISA STIGs                      - Microsoft Defender for Endpoint/EDR" -ForegroundColor Gray
    Write-Host "  - NIST Cybersecurity Framework     - NSA Cybersecurity Guidance" -ForegroundColor Gray
    if ($script:HAS_COMMON_LIB) {
        Write-Host "`n  Shared Library: v$($script:COMMON_LIB_VERSION) (caching, parallel execution enabled)" -ForegroundColor Green
    } else {
        Write-Host "`n  Shared Library: Not found (running without caching)" -ForegroundColor Yellow
    }
    Write-Host "`n========================================================================================================`n" -ForegroundColor Cyan
}

# ============================================================================
# Prerequisites
# ============================================================================
function Test-Prerequisites {
    Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Host "[!] PowerShell 5.1 or higher required. Current: $psVersion" -ForegroundColor Red
        return $false
    }
    Write-Host "[+] PowerShell version: $psVersion" -ForegroundColor Green
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator" -ForegroundColor Yellow
        if ($RemediateIssues -or $AutoRemediate) {
            Write-Host "[!] ERROR: Remediation requires Administrator privileges" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "[+] Running with Administrator privileges" -ForegroundColor Green
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        Write-Host "[+] Operating System: $($os.Caption) (Build $($os.BuildNumber))" -ForegroundColor Green
    } catch { Write-Host "[!] Could not detect OS version" -ForegroundColor Yellow }
    return $true
}

# ============================================================================
# Result Validation & Normalization
# ============================================================================
function Test-ResultObject {
    param([PSCustomObject]$Result, [string]$ModuleName)
    $issues = @()
    if (-not $Result.Module)   { $issues += "Missing Module" }
    if (-not $Result.Category) { $issues += "Missing Category" }
    if (-not $Result.Status)   { $issues += "Missing Status" }
    if (-not $Result.Message)  { $issues += "Missing Message" }
    if ($Result.Status -and $Result.Status -notin $script:ValidStatusValues) { $issues += "Invalid status: $($Result.Status)" }
    if ($issues.Count -gt 0) {
        $script:StatisticsLog.ValidationIssues += @{ Module = $ModuleName; Issues = $issues }
    }
    return ($issues.Count -eq 0)
}

function Repair-ResultObject {
    param([PSCustomObject]$Result, [string]$ModuleName)
    $script:StatisticsLog.NormalizedResults++
    $defaults = @{ Module = $ModuleName; Category = "$ModuleName - Unknown"; Status = "Error"; Message = "Incomplete result"; Details = ""; Remediation = ""; Severity = "Medium"; CrossReferences = @{}; Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
    foreach ($prop in $defaults.Keys) {
        if (-not ($Result.PSObject.Properties[$prop])) { $Result | Add-Member -NotePropertyName $prop -NotePropertyValue $defaults[$prop] -Force }
        elseif ([string]::IsNullOrEmpty($Result.$prop) -and $prop -ne 'Details' -and $prop -ne 'Remediation') { $Result.$prop = $defaults[$prop] }
    }
    # Normalize status value to canonical casing (PowerShell hashtables are case-insensitive)
    if ($Result.Status -notin $script:ValidStatusValues) {
        $Result.Status = switch -Wildcard ($Result.Status.ToUpper()) {
            'PASS'    { 'Pass' }
            'OK'      { 'Pass' }
            'FAIL'    { 'Fail' }
            'WARN'    { 'Warning' }
            'WARNING' { 'Warning' }
            'INFO'    { 'Info' }
            'ERROR'   { 'Error' }
            default   { 'Error' }
        }
    }
    if (-not $Result.PSObject.Properties['Severity'] -or $Result.Severity -notin $script:ValidSeverityValues) {
        $Result | Add-Member -NotePropertyName 'Severity' -NotePropertyValue 'Medium' -Force
    }
    if (-not $Result.PSObject.Properties['CrossReferences']) {
        $Result | Add-Member -NotePropertyName 'CrossReferences' -NotePropertyValue @{} -Force
    }
    return $Result
}

function Get-ValidatedResults {
    param([array]$Results, [string]$ModuleName)
    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host "[!] Module $ModuleName returned no results" -ForegroundColor Yellow
        return @()
    }
    $validated = @()
    foreach ($result in $Results) {
        if (-not (Test-ResultObject -Result $result -ModuleName $ModuleName)) {
            $result = Repair-ResultObject -Result $result -ModuleName $ModuleName
        }
        if (-not $result.PSObject.Properties['Severity']) { $result | Add-Member -NotePropertyName 'Severity' -NotePropertyValue 'Medium' -Force }
        if (-not $result.PSObject.Properties['CrossReferences']) { $result | Add-Member -NotePropertyName 'CrossReferences' -NotePropertyValue @{} -Force }
        $validated += $result
    }
    return $validated
}

function Get-ModuleStatistics {
    param([array]$Results)
    return @{
        Total = $Results.Count
        Pass = @($Results | Where-Object { $_.Status -eq "Pass" }).Count
        Fail = @($Results | Where-Object { $_.Status -eq "Fail" }).Count
        Warning = @($Results | Where-Object { $_.Status -eq "Warning" }).Count
        Info = @($Results | Where-Object { $_.Status -eq "Info" }).Count
        Error = @($Results | Where-Object { $_.Status -eq "Error" }).Count
    }
}

# ============================================================================
# Compliance Scoring (v6.0)
# ============================================================================
function Get-ComplianceScore {
    param([string]$ModuleName, [array]$Results, [double]$Threshold = 70.0)
    $stats = Get-ModuleStatistics -Results $Results
    $sevDist = @{ Critical = @($Results | Where-Object { $_.Severity -eq 'Critical' }).Count; High = @($Results | Where-Object { $_.Severity -eq 'High' }).Count; Medium = @($Results | Where-Object { $_.Severity -eq 'Medium' }).Count; Low = @($Results | Where-Object { $_.Severity -eq 'Low' }).Count; Informational = @($Results | Where-Object { $_.Severity -eq 'Informational' }).Count }
    $applicable = [Math]::Max(1, $stats.Total - $stats.Info)
    $simplePct = [Math]::Round(($stats.Pass / $applicable) * 100, 2)
    $weightedPct = [Math]::Round((($stats.Pass * 1.0 + $stats.Warning * 0.5) / $applicable) * 100, 2)
    $sevWeights = @{ Critical = 5.0; High = 3.0; Medium = 1.5; Low = 0.5; Informational = 0.0 }
    $totalWeight = 0.0
    foreach ($s in $sevDist.Keys) { if ($s -ne 'Informational') { $totalWeight += $sevWeights[$s] * $sevDist[$s] } }
    $sevWeightedPct = $weightedPct
    if ($totalWeight -gt 0) {
        $failRate = ($stats.Fail + $stats.Error) / $applicable
        $critHighW = ($sevWeights['Critical'] * $sevDist['Critical']) + ($sevWeights['High'] * $sevDist['High'])
        $adjFail = [Math]::Min(1.0, $failRate * (1.0 + $critHighW / $totalWeight))
        $sevWeightedPct = [Math]::Round([Math]::Max(0, [Math]::Min(100, (1.0 - $adjFail) * 100)), 2)
    }
    return @{ ModuleName = $ModuleName; TotalChecks = $stats.Total; Passed = $stats.Pass; Failed = $stats.Fail; Warnings = $stats.Warning; Info = $stats.Info; Errors = $stats.Error; SimplePct = $simplePct; WeightedPct = $weightedPct; SeverityWeightedPct = $sevWeightedPct; Threshold = $Threshold; ThresholdResult = $(if ($weightedPct -ge $Threshold) { "PASS" } else { "FAIL" }); SeverityDistribution = $sevDist }
}

# ============================================================================
# Module Discovery & Execution
# ============================================================================
function Get-AvailableModules {
    $modulesDir = Join-Path $script:ScriptPath "modules"
    $modules = @{}
    if (-not (Test-Path $modulesDir)) { $modulesDir = $script:ScriptPath }
    $moduleFiles = Get-ChildItem -Path $modulesDir -Filter "module-*.ps1" -ErrorAction SilentlyContinue
    $nameMap = @{ 'core'='Core'; 'cis'='CIS'; 'cisa'='CISA'; 'ms'='MS'; 'ms-defenderatp'='MS-DefenderATP'; 'nist'='NIST'; 'nsa'='NSA'; 'stig'='STIG'; 'enisa'='ENISA'; 'iso27001'='ISO27001' }
    foreach ($file in $moduleFiles) {
        $rawName = ($file.BaseName -replace '^module-', '').ToLower()
        $displayName = if ($nameMap[$rawName]) { $nameMap[$rawName] } else { $rawName }
        $modules[$displayName] = $file.FullName
    }
    return $modules
}

function Show-AvailableModules {
    $available = Get-AvailableModules
    Write-Host "`n  Available Security Audit Modules:" -ForegroundColor Cyan
    Write-Host "  $('=' * 50)" -ForegroundColor Gray
    foreach ($name in ($available.Keys | Sort-Object)) {
        Write-Host "    $name" -ForegroundColor White -NoNewline
        Write-Host " -> $($available[$name])" -ForegroundColor Gray
    }
    Write-Host "`n  Usage: .\Windows-Security-Audit.ps1 -Modules Core,NIST,CIS`n" -ForegroundColor Cyan
}

function Invoke-SecurityModule {
    param([string]$ModuleName, [hashtable]$SharedData)
    $available = Get-AvailableModules
    if (-not $available.ContainsKey($ModuleName)) {
        Write-Host "[!] Module not found: $ModuleName" -ForegroundColor Red
        return @()
    }
    $modulePath = $available[$ModuleName]
    try {
        Write-Host "`n[*] Executing module: $ModuleName" -ForegroundColor Cyan
        $scriptBlock = [ScriptBlock]::Create("param([hashtable]`$SharedData); & '$modulePath' -SharedData `$SharedData")
        $moduleResults = & $scriptBlock -SharedData $SharedData
        if ($moduleResults) {
            $moduleResults = Get-ValidatedResults -Results $moduleResults -ModuleName $ModuleName
            $moduleStats = Get-ModuleStatistics -Results $moduleResults
            $script:StatisticsLog.ModuleStats[$ModuleName] = $moduleStats
            Write-Host "[+] Module $ModuleName completed: $($moduleStats.Total) checks ($($moduleStats.Pass) pass, $($moduleStats.Fail) fail, $($moduleStats.Warning) warning, $($moduleStats.Info) info, $($moduleStats.Error) error)" -ForegroundColor Green
            return $moduleResults
        } else {
            Write-Host "[!] Module $ModuleName returned no results" -ForegroundColor Yellow
            return @()
        }
    } catch {
        Write-Host "[!] Error executing module ${ModuleName}: $_" -ForegroundColor Red
        return @()
    }
}

# ============================================================================
# Remediation Engine
# ============================================================================
function Invoke-Remediation {
    param([array]$Results)

    $statusFilter = @()
    if ($RemediateIssues)         { $statusFilter = @("Fail", "Warning", "Info") }
    if ($RemediateIssues_Fail)    { $statusFilter += "Fail" }
    if ($RemediateIssues_Warning) { $statusFilter += "Warning" }
    if ($RemediateIssues_Info)    { $statusFilter += "Info" }
    $statusFilter = $statusFilter | Select-Object -Unique

    Write-Host "`n========================================================================================================" -ForegroundColor Yellow
    Write-Host "                                  REMEDIATION MODE" -ForegroundColor Yellow
    Write-Host "========================================================================================================`n" -ForegroundColor Yellow

    # Handle targeted remediation from file
    if ($RemediationFile) {
        if (-not (Test-Path $RemediationFile)) {
            Write-Host "[!] ERROR: Remediation file not found: $RemediationFile" -ForegroundColor Red
            Write-Host "========================================================================================================`n" -ForegroundColor Yellow
            return
        }
        Write-Host "[*] Mode: Targeted remediation from file" -ForegroundColor Cyan
        Write-Host "[*] File: $RemediationFile" -ForegroundColor Gray

        try {
            $remediationData = Get-Content $RemediationFile -Raw | ConvertFrom-Json
            $targetedChecks = @()

            if ($remediationData.modules) {
                # Matches JSON structure from HTML "Export Selected" feature
                foreach ($moduleData in $remediationData.modules) {
                    foreach ($check in $moduleData.checks) {
                        $matchingResult = $Results | Where-Object {
                            $_.Module -eq $moduleData.module -and
                            $_.Category -eq $check.category -and
                            $_.Message -eq $check.message -and
                            -not [string]::IsNullOrWhiteSpace($_.Remediation)
                        } | Select-Object -First 1
                        if ($matchingResult) { $targetedChecks += $matchingResult }
                    }
                }
            } else {
                Write-Host "[!] ERROR: Invalid remediation file format. Expected 'modules' array." -ForegroundColor Red
                return
            }

            if ($targetedChecks.Count -eq 0) {
                Write-Host "[!] No matching remediable issues found in remediation file." -ForegroundColor Yellow
                return
            }
            Write-Host "[*] Found $($targetedChecks.Count) targeted issue(s) to remediate" -ForegroundColor Cyan
            $remediableResults = $targetedChecks
        } catch {
            Write-Host "[!] ERROR: Failed to parse remediation file: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    } else {
        # Standard remediation mode
        $remediableResults = @($Results | Where-Object {
            $_.Status -in $statusFilter -and -not [string]::IsNullOrWhiteSpace($_.Remediation)
        })
        if ($remediableResults.Count -eq 0) {
            Write-Host "[*] No remediable issues found for status filter: $($statusFilter -join ', ')" -ForegroundColor Green
            return
        }
        Write-Host "[*] Found $($remediableResults.Count) remediable issue(s)" -ForegroundColor Cyan
        Write-Host "[*] Status filter: $($statusFilter -join ', ')" -ForegroundColor Gray
    }

    # Confirm auto-remediate
    if ($AutoRemediate -and -not $RemediationFile) {
        Write-Host "`n[!] AUTO-REMEDIATION MODE" -ForegroundColor Red
        Write-Host "    This will automatically apply $($remediableResults.Count) remediation(s)." -ForegroundColor Yellow
        $confirm = Read-Host "    Type 'YES' to confirm"
        if ($confirm -ne "YES") {
            Write-Host "[*] Auto-remediation cancelled" -ForegroundColor Cyan
            return
        }
    }

    # Execute remediations
    $successCount = 0; $failCount = 0; $skipCount = 0
    $skipAll = $false

    foreach ($item in $remediableResults) {
        if ($skipAll) { $skipCount++; continue }

        Write-Host "`n  [$($item.Module)] $($item.Category)" -ForegroundColor Cyan
        Write-Host "    Status:   $($item.Status)" -ForegroundColor $(if ($item.Status -eq 'Fail') { 'Red' } elseif ($item.Status -eq 'Warning') { 'Yellow' } else { 'Cyan' })
        if ($item.PSObject.Properties['Severity']) {
            Write-Host "    Severity: $($item.Severity)" -ForegroundColor Gray
        }
        Write-Host "    Issue:    $($item.Message)" -ForegroundColor White
        Write-Host "    Fix:      $($item.Remediation)" -ForegroundColor Gray

        $shouldApply = $false
        if ($AutoRemediate) {
            $shouldApply = $true
        } else {
            $response = Read-Host "    Apply remediation? (Y/N/S=Skip remaining)"
            if ($response -eq 'S' -or $response -eq 's') {
                Write-Host "    [*] Skipping all remaining remediations" -ForegroundColor Yellow
                $skipAll = $true; $skipCount++; continue
            }
            $shouldApply = ($response -eq 'Y' -or $response -eq 'y')
        }

        if ($shouldApply) {
            try {
                Write-Host "    [*] Applying..." -ForegroundColor Yellow
                $remedScript = [ScriptBlock]::Create($item.Remediation)
                $null = & $remedScript
                Write-Host "    [+] Remediation applied successfully" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "    [!] Remediation failed: $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
            }
        } else {
            Write-Host "    [*] Skipped" -ForegroundColor Gray
            $skipCount++
        }
    }

    Write-Host "`n========================================================================================================" -ForegroundColor Yellow
    Write-Host "  Remediation Summary: $successCount applied, $failCount failed, $skipCount skipped" -ForegroundColor $(if ($failCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "========================================================================================================`n" -ForegroundColor Yellow
}

# ============================================================================
# HTML Report Generation (Enhanced Dashboard - v6.0)
# ============================================================================
function ConvertTo-HTMLReport {
    param(
        [array]$AllResults,
        [hashtable]$ExecutionInfo,
        [hashtable]$ComplianceScores = @{}
    )

    # Pre-compute data for dashboard
    $modulesData = @{}
    foreach ($result in $AllResults) {
        if (-not $modulesData.ContainsKey($result.Module)) {
            $modulesData[$result.Module] = @()
        }
        $modulesData[$result.Module] += $result
    }

    # Per-module compliance scores
    $moduleScores = @{}
    foreach ($modName in $modulesData.Keys) {
        $modResults = $modulesData[$modName]
        $stats = Get-ModuleStatistics -Results $modResults
        $applicable = [Math]::Max(1, $stats.Total - $stats.Info)
        $score = [Math]::Round(($stats.Pass / $applicable) * 100, 1)
        $moduleScores[$modName] = @{ Score = $score; Stats = $stats; Total = $stats.Total }
    }

    # Severity distribution
    $sevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    foreach ($r in $AllResults) {
        $sev = if ($r.PSObject.Properties['Severity'] -and $r.Severity -in $script:ValidSeverityValues) { $r.Severity } else { 'Medium' }
        $sevCounts[$sev]++
    }

    # Category-level statistics per module
    $categoryStats = @{}
    foreach ($modName in $modulesData.Keys) {
        $cats = @{}
        foreach ($r in $modulesData[$modName]) {
            if (-not $cats.ContainsKey($r.Category)) {
                $cats[$r.Category] = @{ total = 0; pass = 0; fail = 0; warning = 0; info = 0; error = 0 }
            }
            $cats[$r.Category].total++
            $cats[$r.Category][$r.Status.ToLower()]++
        }
        $categoryStats[$modName] = $cats
    }

    # Remediation priority list (fail/warning sorted by severity)
    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
    $remediationItems = @($AllResults | Where-Object {
        ($_.Status -eq 'Fail' -or $_.Status -eq 'Warning') -and -not [string]::IsNullOrWhiteSpace($_.Remediation)
    } | Sort-Object @{Expression={ $severityOrder[$_.Severity] }}, @{Expression={ if ($_.Status -eq 'Fail') { 0 } else { 1 } }})

    # SVG Donut chart
    $total = [Math]::Max(1, $ExecutionInfo.TotalChecks)
    $donutSegments = @(
        @{ Label='Pass'; Count=$ExecutionInfo.PassCount; Color='#28a745' },
        @{ Label='Fail'; Count=$ExecutionInfo.FailCount; Color='#dc3545' },
        @{ Label='Warning'; Count=$ExecutionInfo.WarningCount; Color='#fd7e14' },
        @{ Label='Info'; Count=$ExecutionInfo.InfoCount; Color='#17a2b8' },
        @{ Label='Error'; Count=$ExecutionInfo.ErrorCount; Color='#6f42c1' }
    )
    $circumference = 2 * 3.14159 * 45
    $donutParts = @(); $offset = 0
    foreach ($seg in $donutSegments) {
        if ($seg.Count -gt 0) {
            $segLen = ($seg.Count / $total) * $circumference
            $donutParts += "<circle cx='60' cy='60' r='45' fill='none' stroke='$($seg.Color)' stroke-width='20' stroke-dasharray='$([Math]::Round($segLen,2)) $([Math]::Round($circumference,2))' stroke-dashoffset='$([Math]::Round(-$offset,2))' style='cursor:pointer' onclick=""dashboardFilter('status','$($seg.Label)')""><title>$($seg.Label): $($seg.Count)</title></circle>"
            $offset += $segLen
        }
    }
    $donutSvg = $donutParts -join "`n"

    # Module compliance bars
    $moduleBarHtml = ""
    foreach ($modName in ($moduleScores.Keys | Sort-Object)) {
        $sc = $moduleScores[$modName]
        $barColor = if ($sc.Score -ge 80) { '#28a745' } elseif ($sc.Score -ge 60) { '#fd7e14' } else { '#dc3545' }
        $moduleBarHtml += "<div class='module-bar' onclick=""scrollToModule('$modName')"" style='cursor:pointer'><span class='module-bar-label'>$modName</span><div class='module-bar-track'><div class='module-bar-fill' style='width:$($sc.Score)%;background:$barColor'></div></div><span class='module-bar-pct'>$($sc.Score)%</span></div>`n"
    }

    # Severity badges
    $sevBadgeHtml = ""
    foreach ($sev in @('Critical','High','Medium','Low','Informational')) {
        $sevColor = switch ($sev) { 'Critical' { '#dc3545' }; 'High' { '#fd7e14' }; 'Medium' { '#ffc107' }; 'Low' { '#17a2b8' }; 'Informational' { '#6c757d' } }
        $sevBadgeHtml += "<span class='severity-badge' style='background:$sevColor;cursor:pointer' onclick=""dashboardFilter('severity','$sev')"">$sev`: $($sevCounts[$sev])</span> "
    }

    # Compliance score section
    $complianceHtml = ""
    if ($ComplianceScores.Count -gt 0 -and $ComplianceScores.ContainsKey('overall')) {
        $oc = $ComplianceScores['overall']
        $ocColor = if ($oc.WeightedPct -ge 80) { '#28a745' } elseif ($oc.WeightedPct -ge 60) { '#fd7e14' } else { '#dc3545' }
        $complianceHtml = "<div class='compliance-summary'><h3>Compliance Scores</h3><div class='compliance-overall'><span style='color:$ocColor;font-size:2em;font-weight:bold'>$($oc.WeightedPct)%</span><br><small>Overall Weighted [$($oc.ThresholdResult)]</small></div><div class='compliance-details'><div>Simple: $($oc.SimplePct)%</div><div>Severity-Adjusted: $($oc.SeverityWeightedPct)%</div></div></div>"
    }

    # Top remediation priorities table
    $remPriorityHtml = ""
    $remCount = [Math]::Min($remediationItems.Count, 25)
    if ($remCount -gt 0) {
        $remPriorityHtml = "<div class='remediation-priority'><h3>Top Remediation Priorities</h3><table class='rem-table'><tr><th>#</th><th>Severity</th><th>Module</th><th>Category</th><th>Issue</th></tr>"
        for ($i = 0; $i -lt $remCount; $i++) {
            $item = $remediationItems[$i]
            $sc = switch ($item.Severity) { 'Critical' { '#dc3545' }; 'High' { '#fd7e14' }; 'Medium' { '#ffc107' }; 'Low' { '#17a2b8' }; default { '#6c757d' } }
            $remPriorityHtml += "<tr><td>$($i+1)</td><td><span class='severity-badge' style='background:$sc'>$($item.Severity)</span></td><td>$($item.Module)</td><td>$([System.Security.SecurityElement]::Escape($item.Category))</td><td>$([System.Security.SecurityElement]::Escape($item.Message))</td></tr>"
        }
        $remPriorityHtml += "</table></div>"
    }

    # Table of Contents
    $tocHtml = "<div class='toc'><h3>Table of Contents</h3><ul><li><a href='#dashboard'>Executive Dashboard</a></li>"
    foreach ($modName in ($modulesData.Keys | Sort-Object)) {
        $tocHtml += "<li><a href='#module-$modName'>$modName ($($modulesData[$modName].Count) checks)</a></li>"
    }
    $tocHtml += "</ul></div>"

    # Cross-framework summary table
    $crossFrameworkHtml = "<table class='rem-table' style='font-size:0.85em'><tr><th>Framework</th><th>Checks</th><th>Pass</th><th>Fail</th><th>Score</th></tr>"
    foreach ($modName in ($moduleScores.Keys | Sort-Object)) {
        $ms = $moduleScores[$modName]
        $crossFrameworkHtml += "<tr><td>$modName</td><td>$($ms.Total)</td><td>$($ms.Stats.Pass)</td><td>$($ms.Stats.Fail)</td><td>$($ms.Score)%</td></tr>"
    }
    $crossFrameworkHtml += "</table>"

    # Build module result tables
    $moduleTablesHtml = ""
    foreach ($modName in ($modulesData.Keys | Sort-Object)) {
        $modResults = $modulesData[$modName]
        $modScore = $moduleScores[$modName]

        # Category sub-stats badges
        $catBadges = ""
        if ($categoryStats.ContainsKey($modName)) {
            foreach ($catName in ($categoryStats[$modName].Keys | Sort-Object)) {
                $cs = $categoryStats[$modName][$catName]
                $catBadges += "<span class='cat-badge'>$([System.Security.SecurityElement]::Escape($catName)) ($($cs.pass)/$($cs.total))</span>"
            }
        }

        $moduleTablesHtml += @"
<div class='module-section' id='module-$modName'>
<div class='module-header' onclick='toggleModule("$modName")'><h2><span class='collapse-icon' id='icon-$modName'>&#9660;</span> $modName <span class='module-score'>$($modScore.Score)% ($($modScore.Stats.Total) checks)</span></h2></div>
<div class='module-content' id='content-$modName'>
<div class='category-stats'>$catBadges</div>
<div class='table-controls'>
<input type='text' class='module-search' id='search-$modName' placeholder='Filter $modName...' oninput='filterModuleTable("$modName")'>
<div class='export-buttons'>
<button onclick='exportModuleData("$modName","csv")'>CSV</button>
<button onclick='exportModuleData("$modName","json")'>JSON</button>
<button onclick='exportModuleData("$modName","xml")'>XML</button>
<button onclick='exportModuleSelected("$modName")'>Export Selected</button>
</div></div>
<table class='results-table' id='table-$modName'>
<thead><tr>
<th class='col-select'><input type='checkbox' onchange='toggleAllRows("$modName",this.checked)'></th>
<th class='resizable' data-col='category'>Category<div class='resize-handle'></div><input type='text' class='col-filter' placeholder='Filter...' oninput='filterColumn("$modName","category",this.value)'></th>
<th class='resizable' data-col='status'>Status<div class='resize-handle'></div><input type='text' class='col-filter' placeholder='Filter...' oninput='filterColumn("$modName","status",this.value)'></th>
<th class='resizable' data-col='severity'>Severity<div class='resize-handle'></div><input type='text' class='col-filter' placeholder='Filter...' oninput='filterColumn("$modName","severity",this.value)'></th>
<th class='resizable' data-col='message'>Message<div class='resize-handle'></div><input type='text' class='col-filter' placeholder='Filter...' oninput='filterColumn("$modName","message",this.value)'></th>
<th class='resizable' data-col='details'>Details<div class='resize-handle'></div><input type='text' class='col-filter' placeholder='Filter...' oninput='filterColumn("$modName","details",this.value)'></th>
<th class='resizable' data-col='remediation'>Remediation<div class='resize-handle'></div><input type='text' class='col-filter' placeholder='Filter...' oninput='filterColumn("$modName","remediation",this.value)'></th>
</tr></thead><tbody>
"@

        foreach ($r in $modResults) {
            $statusClass = switch ($r.Status) { 'Pass' { 'status-pass' }; 'Fail' { 'status-fail' }; 'Warning' { 'status-warning' }; 'Info' { 'status-info' }; 'Error' { 'status-error' } }
            $sevClass = switch ($r.Severity) { 'Critical' { 'sev-critical' }; 'High' { 'sev-high' }; 'Medium' { 'sev-medium' }; 'Low' { 'sev-low' }; default { 'sev-info' } }
            $ec = [System.Security.SecurityElement]::Escape($r.Category)
            $em = [System.Security.SecurityElement]::Escape($r.Message)
            $ed = [System.Security.SecurityElement]::Escape($r.Details)
            $er = [System.Security.SecurityElement]::Escape($r.Remediation)
            $moduleTablesHtml += "<tr data-status='$($r.Status)' data-severity='$($r.Severity)' data-module='$modName'><td><input type='checkbox' class='row-select'></td><td data-col='category'>$ec</td><td data-col='status' class='$statusClass'>$($r.Status)</td><td data-col='severity' class='$sevClass'>$($r.Severity)</td><td data-col='message'>$em</td><td data-col='details'>$ed</td><td data-col='remediation'>$er</td></tr>`n"
        }

        $moduleTablesHtml += "</tbody></table></div></div>`n"
    }

    # ================================================================
    # Assemble complete HTML document
    # ================================================================
    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>Windows Security Audit Report - $($ExecutionInfo.ComputerName)</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg-primary:#fff;--bg-secondary:#f8f9fa;--bg-tertiary:#e9ecef;--bg-gradient-start:#1a237e;--bg-gradient-end:#283593;--text-primary:#333;--text-secondary:#666;--border-color:#dee2e6;--card-shadow:rgba(0,0,0,.08);--row-hover:#f1f3f5;--accent:#1565c0;--accent-light:#e3f2fd}
[data-theme="dark"]{--bg-primary:#1a1a2e;--bg-secondary:#16213e;--bg-tertiary:#0f3460;--bg-gradient-start:#0a1628;--bg-gradient-end:#1a237e;--text-primary:#e0e0e0;--text-secondary:#b0b0b0;--border-color:#2a3a5c;--card-shadow:rgba(0,0,0,.3);--row-hover:#1e2d4a;--accent:#42a5f5;--accent-light:#0d2137}
body{font-family:Garamond,'Times New Roman',serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6}
.report-header{background:linear-gradient(135deg,var(--bg-gradient-start),var(--bg-gradient-end));color:#fff;padding:30px 40px;width:100%}
.report-header h1{font-size:2em;margin-bottom:5px}.report-header .subtitle{opacity:.9;font-size:1.1em}
.header-controls{display:flex;gap:15px;align-items:center;margin-top:15px}
.theme-toggle{display:flex;align-items:center;gap:8px;cursor:pointer;color:#fff;font-size:.9em}
.theme-slider{width:44px;height:22px;background:rgba(255,255,255,.3);border-radius:11px;position:relative;transition:background .3s}
.theme-slider::after{content:'';position:absolute;width:18px;height:18px;background:#fff;border-radius:50%;top:2px;left:2px;transition:transform .3s}
[data-theme="dark"] .theme-slider::after{transform:translateX(22px)}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;padding:20px 40px}
.info-card{background:var(--bg-secondary);border-radius:8px;padding:15px;box-shadow:0 2px 8px var(--card-shadow)}
.info-card h3{font-size:.85em;color:var(--text-secondary);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.info-card p{font-size:1.1em;font-weight:600}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;padding:0 40px 20px}
.summary-card{text-align:center;border-radius:8px;padding:15px 10px;color:#fff;cursor:pointer;transition:transform .2s,box-shadow .2s}
.summary-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.2)}
.summary-card h3{font-size:2em;margin-bottom:3px}.summary-card p{font-size:.85em;opacity:.9}
.summary-card.total{background:#495057}.summary-card.pass{background:#28a745}.summary-card.fail{background:#dc3545}
.summary-card.warning{background:#fd7e14}.summary-card.info{background:#17a2b8}.summary-card.error{background:#6f42c1}
.dashboard{padding:20px 40px;display:grid;grid-template-columns:1fr 1fr;gap:20px}
.dashboard-panel{background:var(--bg-secondary);border-radius:8px;padding:20px;box-shadow:0 2px 8px var(--card-shadow)}
.dashboard-panel h3{margin-bottom:15px;color:var(--accent);border-bottom:2px solid var(--accent);padding-bottom:8px}
.donut-container{text-align:center}
.donut-legend{display:flex;flex-wrap:wrap;justify-content:center;gap:10px;margin-top:10px}
.donut-legend span{display:flex;align-items:center;gap:5px;font-size:.9em;cursor:pointer}
.donut-legend .dot{width:12px;height:12px;border-radius:50%;display:inline-block}
.module-bar{display:flex;align-items:center;gap:10px;margin-bottom:8px;padding:4px 0}
.module-bar-label{width:130px;font-weight:600;font-size:.9em;text-align:right}
.module-bar-track{flex:1;height:20px;background:var(--bg-tertiary);border-radius:10px;overflow:hidden}
.module-bar-fill{height:100%;border-radius:10px;transition:width .5s ease;min-width:2px}
.module-bar-pct{width:50px;font-weight:600;font-size:.9em}
.severity-badge{display:inline-block;padding:3px 10px;border-radius:12px;color:#fff;font-size:.8em;font-weight:600;margin:2px}
.severity-section{display:flex;flex-wrap:wrap;gap:8px;justify-content:center}
.compliance-summary{text-align:center;padding:15px}
.compliance-overall{margin:10px 0}.compliance-details{display:flex;gap:20px;justify-content:center;color:var(--text-secondary);font-size:.9em}
.remediation-priority{padding:20px 40px}.remediation-priority h3{margin-bottom:10px;color:var(--accent)}
.rem-table{width:100%;border-collapse:collapse;font-size:.9em}
.rem-table th{background:var(--bg-gradient-start);color:#fff;padding:8px 12px;text-align:left}
.rem-table td{padding:8px 12px;border-bottom:1px solid var(--border-color)}.rem-table tr:hover{background:var(--row-hover)}
.toc{padding:20px 40px}.toc h3{color:var(--accent);margin-bottom:10px}.toc ul{list-style:none;padding:0;columns:2}
.toc li{margin-bottom:5px}.toc a{color:var(--accent);text-decoration:none}.toc a:hover{text-decoration:underline}
.module-section{margin:15px 40px;background:var(--bg-secondary);border-radius:8px;overflow:hidden;box-shadow:0 2px 8px var(--card-shadow)}
.module-header{background:linear-gradient(135deg,var(--bg-gradient-start),var(--bg-gradient-end));color:#fff;padding:12px 20px;cursor:pointer}
.module-header h2{font-size:1.2em;display:flex;align-items:center;gap:10px}
.module-score{font-size:.75em;opacity:.8;margin-left:auto}
.collapse-icon{font-size:.8em;transition:transform .3s}
.module-content{padding:15px}.module-content.collapsed{display:none}
.category-stats{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.cat-badge{background:var(--accent-light);color:var(--accent);padding:3px 10px;border-radius:12px;font-size:.8em}
.table-controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
.module-search{padding:6px 12px;border:1px solid var(--border-color);border-radius:4px;font-family:inherit;background:var(--bg-primary);color:var(--text-primary);width:250px}
.export-buttons button{padding:5px 12px;border:1px solid var(--border-color);background:var(--bg-primary);color:var(--text-primary);border-radius:4px;cursor:pointer;font-family:inherit;font-size:.85em}
.export-buttons button:hover{background:var(--accent);color:#fff}
.results-table{width:100%;border-collapse:collapse;font-size:.9em;table-layout:auto}
.results-table th{background:var(--bg-gradient-start);color:#fff;padding:8px 10px;text-align:left;position:relative;white-space:nowrap;user-select:none}
.results-table td{padding:8px 10px;border-bottom:1px solid var(--border-color);word-wrap:break-word;overflow-wrap:break-word;vertical-align:top}
.results-table tr:hover{background:var(--row-hover)}
.col-select{width:30px;text-align:center}
.col-filter{width:90%;padding:3px 6px;font-size:.85em;border:1px solid rgba(255,255,255,.3);border-radius:3px;background:rgba(255,255,255,.15);color:#fff;margin-top:4px;display:block;font-family:inherit}
.col-filter::placeholder{color:rgba(255,255,255,.5)}
.resize-handle{position:absolute;right:0;top:0;bottom:0;width:5px;cursor:col-resize;background:transparent}.resize-handle:hover{background:rgba(255,255,255,.3)}
.status-pass{color:#28a745;font-weight:600}.status-fail{color:#dc3545;font-weight:600}.status-warning{color:#fd7e14;font-weight:600}.status-info{color:#17a2b8;font-weight:600}.status-error{color:#6f42c1;font-weight:600}
.sev-critical{color:#dc3545;font-weight:600}.sev-high{color:#fd7e14;font-weight:600}.sev-medium{color:#ffc107;font-weight:600}.sev-low{color:#17a2b8}.sev-info{color:#6c757d}
.global-controls{padding:15px 40px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;background:var(--bg-secondary);border-bottom:1px solid var(--border-color);position:sticky;top:0;z-index:100}
.global-search{padding:8px 14px;border:1px solid var(--border-color);border-radius:4px;font-family:inherit;background:var(--bg-primary);color:var(--text-primary);width:300px;font-size:.95em}
.filter-mode{padding:5px 10px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-primary);color:var(--text-primary);cursor:pointer;font-family:inherit}
.global-export button{padding:6px 14px;border:1px solid var(--accent);background:var(--accent);color:#fff;border-radius:4px;cursor:pointer;font-family:inherit}
.global-export button:hover{opacity:.9}
.report-footer{text-align:center;padding:20px 40px;color:var(--text-secondary);font-size:.85em;border-top:1px solid var(--border-color);margin-top:30px}
@media print{.header-controls,.theme-toggle,.global-controls,.table-controls,.export-buttons,.col-filter,.resize-handle,.col-select,.report-footer{display:none!important}.module-content{display:block!important}.module-section{break-inside:avoid;margin:10px 0;box-shadow:none}body{font-size:10pt}.results-table th{background:#333!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@media(max-width:768px){.dashboard{grid-template-columns:1fr}.info-grid{grid-template-columns:1fr 1fr}.toc ul{columns:1}.report-header,.info-grid,.summary-grid,.dashboard,.module-section,.global-controls,.remediation-priority,.toc{padding-left:15px;padding-right:15px}}
</style>
</head>
<body>
<div class='report-header'><h1>Windows Security Audit Report</h1><div class='subtitle'>Comprehensive Multi-Framework Assessment &mdash; v$($script:ScriptVersion)</div>
<div class='header-controls'><div class='theme-toggle' onclick='toggleTheme()'><span>&#9728;</span><div class='theme-slider'></div><span>&#9790;</span></div>
<button onclick='window.print()' style='padding:5px 15px;border:1px solid rgba(255,255,255,.4);background:transparent;color:#fff;border-radius:4px;cursor:pointer;font-family:inherit'>Print Report</button></div></div>

<div class='info-grid'>
<div class='info-card'><h3>Computer Name</h3><p>$($ExecutionInfo.ComputerName)</p></div>
<div class='info-card'><h3>Operating System</h3><p>$($ExecutionInfo.OSVersion)</p></div>
<div class='info-card'><h3>IP Address(es)</h3><p>$($ExecutionInfo.IPAddresses -join ', ')</p></div>
<div class='info-card'><h3>Scan Date</h3><p>$($ExecutionInfo.ScanDate)</p></div>
<div class='info-card'><h3>Duration</h3><p>$($ExecutionInfo.Duration)</p></div>
<div class='info-card'><h3>Modules Executed</h3><p>$($ExecutionInfo.ModulesRun -join ', ')</p></div>
</div>

<div class='summary-grid'>
<div class='summary-card total' onclick="dashboardFilter('all','')"><h3>$($ExecutionInfo.TotalChecks)</h3><p>Total Checks</p></div>
<div class='summary-card pass' onclick="dashboardFilter('status','Pass')"><h3>$($ExecutionInfo.PassCount)</h3><p>Passed</p></div>
<div class='summary-card fail' onclick="dashboardFilter('status','Fail')"><h3>$($ExecutionInfo.FailCount)</h3><p>Failed</p></div>
<div class='summary-card warning' onclick="dashboardFilter('status','Warning')"><h3>$($ExecutionInfo.WarningCount)</h3><p>Warnings</p></div>
<div class='summary-card info' onclick="dashboardFilter('status','Info')"><h3>$($ExecutionInfo.InfoCount)</h3><p>Info</p></div>
<div class='summary-card error' onclick="dashboardFilter('status','Error')"><h3>$($ExecutionInfo.ErrorCount)</h3><p>Errors</p></div>
</div>

<div class='dashboard' id='dashboard'>
<div class='dashboard-panel'><h3>Status Distribution</h3><div class='donut-container'>
<svg viewBox='0 0 120 120' width='200' height='200'>$donutSvg</svg>
<div class='donut-legend'>
<span onclick="dashboardFilter('status','Pass')"><span class='dot' style='background:#28a745'></span>Pass ($($ExecutionInfo.PassCount))</span>
<span onclick="dashboardFilter('status','Fail')"><span class='dot' style='background:#dc3545'></span>Fail ($($ExecutionInfo.FailCount))</span>
<span onclick="dashboardFilter('status','Warning')"><span class='dot' style='background:#fd7e14'></span>Warning ($($ExecutionInfo.WarningCount))</span>
<span onclick="dashboardFilter('status','Info')"><span class='dot' style='background:#17a2b8'></span>Info ($($ExecutionInfo.InfoCount))</span>
<span onclick="dashboardFilter('status','Error')"><span class='dot' style='background:#6f42c1'></span>Error ($($ExecutionInfo.ErrorCount))</span>
</div></div></div>
<div class='dashboard-panel'><h3>Module Compliance</h3>$moduleBarHtml</div>
<div class='dashboard-panel'><h3>Severity Distribution</h3><div class='severity-section'>$sevBadgeHtml</div>$complianceHtml</div>
<div class='dashboard-panel'><h3>Cross-Framework Summary</h3>$crossFrameworkHtml</div>
</div>

$remPriorityHtml
$tocHtml

<div class='global-controls'>
<input type='text' class='global-search' id='globalSearch' placeholder='Search all results...' oninput='globalFilter()'>
<select class='filter-mode' id='filterMode' onchange='globalFilter()'><option value='include'>Include matches</option><option value='exclude'>Exclude matches</option></select>
<div class='global-export'>
<button onclick='exportAllData("csv")'>Export All CSV</button>
<button onclick='exportAllData("json")'>Export All JSON</button>
<button onclick='exportAllData("xml")'>Export All XML</button>
</div></div>

$moduleTablesHtml

<div class='report-footer'>Generated by Windows Security Audit Script v$($script:ScriptVersion) | $($ExecutionInfo.ScanDate) | <a href='https://github.com/Sandler73/Windows-Security-Audit-Script'>GitHub</a></div>

<script>
function toggleTheme(){var b=document.documentElement;b.setAttribute('data-theme',b.getAttribute('data-theme')==='dark'?'light':'dark')}
function toggleModule(m){var c=document.getElementById('content-'+m),i=document.getElementById('icon-'+m);if(c.classList.contains('collapsed')){c.classList.remove('collapsed');i.innerHTML='&#9660;'}else{c.classList.add('collapsed');i.innerHTML='&#9654;'}}
function scrollToModule(m){var e=document.getElementById('module-'+m);if(e){e.scrollIntoView({behavior:'smooth',block:'start'});var c=document.getElementById('content-'+m);if(c&&c.classList.contains('collapsed'))toggleModule(m)}}
function dashboardFilter(t,v){document.querySelectorAll('.results-table tbody tr').forEach(function(r){if(t==='all'){r.style.display='';return}r.style.display=r.getAttribute('data-'+t)===v?'':'none'});document.getElementById('globalSearch').value=''}
function globalFilter(){var q=document.getElementById('globalSearch').value.toLowerCase(),m=document.getElementById('filterMode').value;document.querySelectorAll('.results-table tbody tr').forEach(function(r){if(!q){r.style.display='';return}var t=r.textContent.toLowerCase(),h=t.includes(q);r.style.display=(m==='include'?h:!h)?'':'none'})}
function filterModuleTable(mod){var q=document.getElementById('search-'+mod).value.toLowerCase();document.getElementById('table-'+mod).querySelectorAll('tbody tr').forEach(function(r){if(!q){r.style.display='';return}r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}
function filterColumn(mod,col,v){var q=v.toLowerCase();document.getElementById('table-'+mod).querySelectorAll('tbody tr').forEach(function(r){if(!q){r.style.display='';return}var c=r.querySelector('td[data-col="'+col+'"]');if(c)r.style.display=c.textContent.toLowerCase().includes(q)?'':'none'})}
function toggleAllRows(mod,chk){document.getElementById('table-'+mod).querySelectorAll('tbody .row-select').forEach(function(cb){cb.checked=chk})}
function getTableData(mod,selOnly){var t=document.getElementById('table-'+mod),d=[];t.querySelectorAll('tbody tr').forEach(function(r){if(r.style.display==='none')return;if(selOnly&&!r.querySelector('.row-select').checked)return;var c=r.querySelectorAll('td');d.push({module:r.getAttribute('data-module'),category:c[1]?c[1].textContent:'',status:c[2]?c[2].textContent:'',severity:c[3]?c[3].textContent:'',message:c[4]?c[4].textContent:'',details:c[5]?c[5].textContent:'',remediation:c[6]?c[6].textContent:''})});return d}
function dl(c,f,m){var b=new Blob([c],{type:m}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download=f;a.click();URL.revokeObjectURL(u)}
function exportToCSV(d,f){var h='Module,Category,Status,Severity,Message,Details,Remediation';var r=d.map(function(x){return[x.module,x.category,x.status,x.severity,x.message,x.details,x.remediation].map(function(v){return'"'+(v||'').replace(/"/g,'""')+'"'}).join(',')});dl(h+'\n'+r.join('\n'),f,'text/csv')}
function exportToJSON(d,f){dl(JSON.stringify({export_date:new Date().toISOString(),results:d},null,2),f,'application/json')}
function esc(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s||''));return d.innerHTML}
function exportToXML(d,f){var x='<?xml version="1.0" encoding="UTF-8"?>\n<audit_export>\n<metadata><export_date>'+new Date().toISOString()+'</export_date></metadata>\n<results>\n';d.forEach(function(r){x+='<r><module>'+esc(r.module)+'</module><category>'+esc(r.category)+'</category><status>'+esc(r.status)+'</status><severity>'+esc(r.severity)+'</severity><message>'+esc(r.message)+'</message><details>'+esc(r.details)+'</details><remediation>'+esc(r.remediation)+'</remediation></r>\n'});x+='</results>\n</audit_export>';dl(x,f,'application/xml')}
function exportModuleData(m,fmt){var d=getTableData(m,false),fn='Windows-Audit-'+m+'-'+new Date().toISOString().slice(0,10);if(fmt==='csv')exportToCSV(d,fn+'.csv');else if(fmt==='json')exportToJSON(d,fn+'.json');else if(fmt==='xml')exportToXML(d,fn+'.xml')}
function exportModuleSelected(m){var d=getTableData(m,true);if(!d.length){alert('No rows selected');return}var fn='Windows-Audit-'+m+'-Selected-'+new Date().toISOString().slice(0,10);dl(JSON.stringify({modules:[{module:m,checks:d.map(function(r){return{category:r.category,message:r.message,remediation:r.remediation}})}]},null,2),fn+'.json','application/json')}
function exportAllData(fmt){var a=[];document.querySelectorAll('.results-table').forEach(function(t){a=a.concat(getTableData(t.id.replace('table-',''),false))});var fn='Windows-Audit-All-'+new Date().toISOString().slice(0,10);if(fmt==='csv')exportToCSV(a,fn+'.csv');else if(fmt==='json')exportToJSON(a,fn+'.json');else if(fmt==='xml')exportToXML(a,fn+'.xml')}
document.querySelectorAll('.resize-handle').forEach(function(h){h.addEventListener('mousedown',function(e){e.preventDefault();var th=h.parentElement,sx=e.pageX,sw=th.offsetWidth;function mv(e2){th.style.width=(sw+e2.pageX-sx)+'px';th.style.minWidth=th.style.width}function up(){document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up)}document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up)})})
</script>
</body></html>
"@

    return $html
}

# ============================================================================
# Export Functions (CSV, JSON, XML)
# ============================================================================

function Export-CSVResults {
    <#
    .SYNOPSIS
        Exports audit results to a CSV file with all fields including Severity and CrossReferences.
    .PARAMETER Results
        Array of AuditResult objects to export.
    .PARAMETER Path
        Output file path for the CSV.
    #>
    param([array]$Results, [string]$Path)

    try {
        $csvData = @()
        foreach ($r in $Results) {
            # Serialize CrossReferences hashtable to readable string
            $crossRefStr = ""
            if ($r.PSObject.Properties['CrossReferences'] -and $r.CrossReferences -is [hashtable] -and $r.CrossReferences.Count -gt 0) {
                $crossRefParts = @()
                foreach ($key in $r.CrossReferences.Keys) {
                    $crossRefParts += "$key=$($r.CrossReferences[$key])"
                }
                $crossRefStr = $crossRefParts -join "; "
            }

            $csvData += [PSCustomObject]@{
                Module         = $r.Module
                Category       = $r.Category
                Status         = $r.Status
                Severity       = if ($r.PSObject.Properties['Severity']) { $r.Severity } else { 'Medium' }
                Message        = $r.Message
                Details        = $r.Details
                Remediation    = $r.Remediation
                CrossReferences = $crossRefStr
                Timestamp      = if ($r.PSObject.Properties['Timestamp']) { $r.Timestamp } else { '' }
            }
        }

        $csvData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "[+] CSV report exported to: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[!] ERROR: Failed to export CSV: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-JSONResults {
    <#
    .SYNOPSIS
        Exports audit results to a structured JSON file with metadata and compliance scores.
    .PARAMETER Results
        Array of AuditResult objects to export.
    .PARAMETER Path
        Output file path for the JSON.
    .PARAMETER ExecutionInfo
        Hashtable containing execution metadata (ComputerName, OSVersion, etc.).
    .PARAMETER ComplianceScores
        Hashtable containing compliance score calculations.
    #>
    param(
        [array]$Results,
        [string]$Path,
        [hashtable]$ExecutionInfo = @{},
        [hashtable]$ComplianceScores = @{}
    )

    try {
        # Build structured JSON output
        $jsonOutput = @{
            metadata = @{
                script_version     = $script:ScriptVersion
                computer_name      = $ExecutionInfo.ComputerName
                operating_system   = $ExecutionInfo.OSVersion
                ip_addresses       = $ExecutionInfo.IPAddresses
                scan_date          = $ExecutionInfo.ScanDate
                duration           = $ExecutionInfo.Duration
                modules_executed   = $ExecutionInfo.ModulesRun
                total_checks       = $ExecutionInfo.TotalChecks
                export_date        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
            summary = @{
                pass    = $ExecutionInfo.PassCount
                fail    = $ExecutionInfo.FailCount
                warning = $ExecutionInfo.WarningCount
                info    = $ExecutionInfo.InfoCount
                error   = $ExecutionInfo.ErrorCount
            }
            compliance_scores = @{}
            results = @()
        }

        # Add compliance scores if available
        if ($ComplianceScores.Count -gt 0) {
            foreach ($key in $ComplianceScores.Keys) {
                $cs = $ComplianceScores[$key]
                $jsonOutput.compliance_scores[$key] = @{
                    simple_pct           = $cs.SimplePct
                    weighted_pct         = $cs.WeightedPct
                    severity_weighted_pct = $cs.SeverityWeightedPct
                    threshold_result     = $cs.ThresholdResult
                }
            }
        }

        # Serialize results with all fields
        foreach ($r in $Results) {
            $resultObj = @{
                module          = $r.Module
                category        = $r.Category
                status          = $r.Status
                severity        = if ($r.PSObject.Properties['Severity']) { $r.Severity } else { 'Medium' }
                message         = $r.Message
                details         = $r.Details
                remediation     = $r.Remediation
                cross_references = @{}
                timestamp       = if ($r.PSObject.Properties['Timestamp']) { $r.Timestamp } else { '' }
            }
            if ($r.PSObject.Properties['CrossReferences'] -and $r.CrossReferences -is [hashtable]) {
                $resultObj.cross_references = $r.CrossReferences
            }
            $jsonOutput.results += $resultObj
        }

        $jsonOutput | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "[+] JSON report exported to: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[!] ERROR: Failed to export JSON: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-XMLResults {
    <#
    .SYNOPSIS
        Exports audit results to a well-formed XML file with metadata, compliance scores,
        and per-result elements including Severity and CrossReferences.
    .PARAMETER Results
        Array of AuditResult objects to export.
    .PARAMETER Path
        Output file path for the XML.
    .PARAMETER ExecutionInfo
        Hashtable containing execution metadata.
    .PARAMETER ComplianceScores
        Hashtable containing compliance score calculations.
    #>
    param(
        [array]$Results,
        [string]$Path,
        [hashtable]$ExecutionInfo = @{},
        [hashtable]$ComplianceScores = @{}
    )

    try {
        $xmlSettings = New-Object System.Xml.XmlWriterSettings
        $xmlSettings.Indent = $true
        $xmlSettings.IndentChars = "  "
        $xmlSettings.Encoding = [System.Text.Encoding]::UTF8

        $writer = [System.Xml.XmlWriter]::Create($Path, $xmlSettings)
        $writer.WriteStartDocument()

        # Processing instruction for stylesheet
        $writer.WriteProcessingInstruction("xml-stylesheet", "type='text/xsl' href='audit-report.xsl'")

        # Root element
        $writer.WriteStartElement("SecurityAuditReport")
        $writer.WriteAttributeString("version", $script:ScriptVersion)
        $writer.WriteAttributeString("generated", (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'))

        # Metadata section
        $writer.WriteStartElement("Metadata")
        $writer.WriteElementString("ComputerName", [string]$ExecutionInfo.ComputerName)
        $writer.WriteElementString("OperatingSystem", [string]$ExecutionInfo.OSVersion)
        $writer.WriteElementString("ScanDate", [string]$ExecutionInfo.ScanDate)
        $writer.WriteElementString("Duration", [string]$ExecutionInfo.Duration)
        $writer.WriteStartElement("IPAddresses")
        if ($ExecutionInfo.IPAddresses) {
            foreach ($ip in $ExecutionInfo.IPAddresses) {
                $writer.WriteElementString("IP", [string]$ip)
            }
        }
        $writer.WriteEndElement() # IPAddresses
        $writer.WriteStartElement("ModulesExecuted")
        if ($ExecutionInfo.ModulesRun) {
            foreach ($mod in $ExecutionInfo.ModulesRun) {
                $writer.WriteElementString("Module", [string]$mod)
            }
        }
        $writer.WriteEndElement() # ModulesExecuted
        $writer.WriteEndElement() # Metadata

        # Summary section
        $writer.WriteStartElement("Summary")
        $writer.WriteElementString("TotalChecks", [string]$ExecutionInfo.TotalChecks)
        $writer.WriteElementString("Pass", [string]$ExecutionInfo.PassCount)
        $writer.WriteElementString("Fail", [string]$ExecutionInfo.FailCount)
        $writer.WriteElementString("Warning", [string]$ExecutionInfo.WarningCount)
        $writer.WriteElementString("Info", [string]$ExecutionInfo.InfoCount)
        $writer.WriteElementString("Error", [string]$ExecutionInfo.ErrorCount)
        $writer.WriteEndElement() # Summary

        # Compliance Scores section
        if ($ComplianceScores.Count -gt 0) {
            $writer.WriteStartElement("ComplianceScores")
            foreach ($key in $ComplianceScores.Keys) {
                $cs = $ComplianceScores[$key]
                $writer.WriteStartElement("Score")
                $writer.WriteAttributeString("framework", $key)
                $writer.WriteElementString("SimplePct", [string]$cs.SimplePct)
                $writer.WriteElementString("WeightedPct", [string]$cs.WeightedPct)
                $writer.WriteElementString("SeverityWeightedPct", [string]$cs.SeverityWeightedPct)
                $writer.WriteElementString("ThresholdResult", [string]$cs.ThresholdResult)
                $writer.WriteEndElement() # Score
            }
            $writer.WriteEndElement() # ComplianceScores
        }

        # Results section
        $writer.WriteStartElement("Results")
        $writer.WriteAttributeString("count", [string]$Results.Count)
        foreach ($r in $Results) {
            $writer.WriteStartElement("Check")
            $writer.WriteAttributeString("module", [string]$r.Module)
            $writer.WriteAttributeString("status", [string]$r.Status)
            $writer.WriteAttributeString("severity", $(if ($r.PSObject.Properties['Severity']) { $r.Severity } else { 'Medium' }))
            $writer.WriteElementString("Category", [string]$r.Category)
            $writer.WriteElementString("Message", [string]$r.Message)
            $writer.WriteElementString("Details", [string]$r.Details)
            $writer.WriteElementString("Remediation", [string]$r.Remediation)
            # CrossReferences
            if ($r.PSObject.Properties['CrossReferences'] -and $r.CrossReferences -is [hashtable] -and $r.CrossReferences.Count -gt 0) {
                $writer.WriteStartElement("CrossReferences")
                foreach ($crKey in $r.CrossReferences.Keys) {
                    $writer.WriteStartElement("Reference")
                    $writer.WriteAttributeString("framework", $crKey)
                    $writer.WriteString([string]$r.CrossReferences[$crKey])
                    $writer.WriteEndElement() # Reference
                }
                $writer.WriteEndElement() # CrossReferences
            }
            $writer.WriteEndElement() # Check
        }
        $writer.WriteEndElement() # Results

        $writer.WriteEndElement() # SecurityAuditReport
        $writer.WriteEndDocument()
        $writer.Close()

        Write-Host "[+] XML report exported to: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[!] ERROR: Failed to export XML: $($_.Exception.Message)" -ForegroundColor Red
        if ($writer) { try { $writer.Close() } catch {} }
        return $false
    }
}

function Export-Results {
    <#
    .SYNOPSIS
        Dispatcher function that routes export to the appropriate format handler(s).
        Supports HTML, CSV, JSON, and XML output with automatic path generation.
    .PARAMETER Results
        Array of AuditResult objects to export.
    .PARAMETER ExecutionInfo
        Hashtable containing execution metadata.
    .PARAMETER ComplianceScores
        Hashtable containing compliance score calculations.
    #>
    param(
        [array]$Results,
        [hashtable]$ExecutionInfo,
        [hashtable]$ComplianceScores = @{}
    )

    # Build base filename from computer name and date
    $baseName = "Windows-Security-Audit-$($ExecutionInfo.ComputerName)-$(Get-Date -Format 'yyyy-MM-dd_HHmmss')"

    # Determine output directory
    $outputDir = if ($OutputPath -and (Test-Path (Split-Path $OutputPath -Parent))) {
        Split-Path $OutputPath -Parent
    } elseif ($OutputPath) {
        $OutputPath
    } else {
        $PSScriptRoot
    }

    # Ensure output directory exists
    if (-not (Test-Path $outputDir)) {
        try {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        } catch {
            Write-Host "[!] ERROR: Cannot create output directory: $outputDir. Using current directory." -ForegroundColor Red
            $outputDir = $PSScriptRoot
        }
    }

    Write-Host "`n========================================================================================================" -ForegroundColor Cyan
    Write-Host "                                     EXPORT RESULTS" -ForegroundColor Cyan
    Write-Host "========================================================================================================`n" -ForegroundColor Cyan

    $exportedFiles = @()

    # HTML Export (default, always generated unless explicitly disabled)
    $htmlPath = Join-Path $outputDir "$baseName.html"
    try {
        $htmlContent = ConvertTo-HTMLReport -AllResults $Results -ExecutionInfo $ExecutionInfo -ComplianceScores $ComplianceScores
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "[+] HTML report exported to: $htmlPath" -ForegroundColor Green
        $exportedFiles += $htmlPath
    } catch {
        Write-Host "[!] ERROR: Failed to export HTML: $($_.Exception.Message)" -ForegroundColor Red
    }

    # CSV Export
    if ($OutputFormat -eq 'csv' -or $OutputFormat -eq 'all') {
        $csvPath = Join-Path $outputDir "$baseName.csv"
        if (Export-CSVResults -Results $Results -Path $csvPath) {
            $exportedFiles += $csvPath
        }
    }

    # JSON Export
    if ($OutputFormat -eq 'json' -or $OutputFormat -eq 'all') {
        $jsonPath = Join-Path $outputDir "$baseName.json"
        if (Export-JSONResults -Results $Results -Path $jsonPath -ExecutionInfo $ExecutionInfo -ComplianceScores $ComplianceScores) {
            $exportedFiles += $jsonPath
        }
    }

    # XML Export
    if ($OutputFormat -eq 'xml' -or $OutputFormat -eq 'all') {
        $xmlPath = Join-Path $outputDir "$baseName.xml"
        if (Export-XMLResults -Results $Results -Path $xmlPath -ExecutionInfo $ExecutionInfo -ComplianceScores $ComplianceScores) {
            $exportedFiles += $xmlPath
        }
    }

    Write-Host "`n  Total files exported: $($exportedFiles.Count)" -ForegroundColor Cyan

    # Auto-open HTML report if requested
    if ($exportedFiles.Count -gt 0 -and $htmlPath -and (Test-Path $htmlPath)) {
        if (-not $Quiet) {
            Write-Host "  Opening HTML report in default browser..." -ForegroundColor Gray
            try { Start-Process $htmlPath } catch { }
        }
    }

    Write-Host "========================================================================================================`n" -ForegroundColor Cyan

    return $exportedFiles
}

# ============================================================================
# Main Execution Orchestrator
# ============================================================================

function Start-SecurityAudit {
    <#
    .SYNOPSIS
        Main orchestrator function that coordinates the full security audit lifecycle:
        prerequisite checks, cache initialization, module discovery and execution,
        compliance scoring, result aggregation, reporting, and remediation.
    .DESCRIPTION
        Supports both sequential and parallel (RunspacePool) module execution.
        Integrates with SharedDataCache from audit-common.ps1 for performance.
        Calculates compliance scores per-module and overall using three methods.
        Generates HTML, CSV, JSON, and XML reports.
    #>

    # ---- Initialization ----
    $auditStartTime = Get-Date
    $script:StatisticsLog = @{ ModuleStats = @{}; ModuleTimings = @{}; TotalStartTime = $auditStartTime }

    # Initialize logging if shared library is available
    if ($script:HAS_COMMON_LIB) {
        $logParams = @{
            LogLevel = $LogLevel
        }
        if ($LogFile) { $logParams['LogFile'] = $LogFile }
        if ($JsonLog) { $logParams['JsonFormat'] = $true }
        try {
            Initialize-AuditLogging @logParams
            Write-AuditLog -Message "Windows Security Audit v$($script:ScriptVersion) starting" -Level 'INFO'
        } catch {
            Write-Host "[!] Warning: Could not initialize structured logging: $_" -ForegroundColor Yellow
        }
    }

    # Show banner
    Show-Banner

    # ---- Prerequisites ----
    Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Cyan
    $prereqResult = Test-Prerequisites
    if (-not $prereqResult.Success) {
        Write-Host "[!] FATAL: Prerequisites not met. Aborting." -ForegroundColor Red
        foreach ($msg in $prereqResult.Messages) {
            Write-Host "    - $msg" -ForegroundColor Red
        }
        return
    }
    foreach ($msg in $prereqResult.Messages) {
        Write-Host "  [+] $msg" -ForegroundColor Green
    }

    # ---- Module Discovery ----
    Write-Host "`n[*] Discovering available modules..." -ForegroundColor Cyan
    $availableModules = Get-AvailableModules

    if ($availableModules.Count -eq 0) {
        Write-Host "[!] FATAL: No modules found in modules/ directory. Aborting." -ForegroundColor Red
        return
    }

    # Handle -ListModules
    if ($ListModules) {
        Show-AvailableModules
        return
    }

    # Determine which modules to run
    $modulesToRun = @()
    if ($Modules -and $Modules.Count -gt 0 -and $Modules[0] -ne "All") {
        foreach ($requestedMod in $Modules) {
            $normalizedName = $requestedMod.Trim()
            if ($availableModules.ContainsKey($normalizedName)) {
                $modulesToRun += $normalizedName
            } else {
                # Try case-insensitive match
                $matched = $availableModules.Keys | Where-Object { $_ -ieq $normalizedName } | Select-Object -First 1
                if ($matched) {
                    $modulesToRun += $matched
                } else {
                    Write-Host "[!] WARNING: Requested module '$requestedMod' not found. Skipping." -ForegroundColor Yellow
                }
            }
        }
    } else {
        # "All" or no modules specified — run all available modules
        $modulesToRun = @($availableModules.Keys | Sort-Object)
    }

    if ($modulesToRun.Count -eq 0) {
        Write-Host "[!] FATAL: No valid modules selected. Aborting." -ForegroundColor Red
        Show-AvailableModules
        return
    }

    Write-Host "[+] Modules to execute: $($modulesToRun -join ', ')" -ForegroundColor Green

    # ---- SharedData Cache Initialization ----
    $sharedData = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion    = ''
        IPAddresses  = @()
        ScanDate     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        IsAdmin      = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ScriptPath   = $PSScriptRoot
        Cache        = $null
    }

    if ($script:HAS_COMMON_LIB -and -not $NoCache) {
        Write-Host "`n[*] Initializing SharedDataCache..." -ForegroundColor Cyan
        $cacheStartTime = Get-Date

        try {
            # Get OS information from shared library
            $osInfo = Get-OSInfo
            $sharedData.ComputerName = $osInfo.ComputerName
            $sharedData.OSVersion = "$($osInfo.OSCaption) (Build $($osInfo.BuildNumber))"

            # Create and warm up the cache
            $cache = New-SharedDataCache -OSInfo $osInfo
            Invoke-CacheWarmUp -Cache $cache

            $sharedData.Cache = $cache

            # Collect IP addresses from cache
            if ($cache.NetworkConfig -and $cache.NetworkConfig.IPConfiguration) {
                $sharedData.IPAddresses = @($cache.NetworkConfig.IPConfiguration |
                    Where-Object { $_.IPv4Address } |
                    ForEach-Object { $_.IPv4Address.IPAddress } |
                    Where-Object { $_ -ne '127.0.0.1' -and $_ -ne '::1' })
            }
            if ($sharedData.IPAddresses.Count -eq 0) {
                # Fallback: try basic method
                $sharedData.IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress)
            }

            $cacheElapsed = ((Get-Date) - $cacheStartTime).TotalSeconds
            $script:StatisticsLog.ModuleTimings['CacheWarmUp'] = $cacheElapsed

            # Display cache summary
            $cacheSummary = Get-CacheSummary -Cache $cache
            Write-Host "[+] Cache initialized in $([Math]::Round($cacheElapsed, 2))s" -ForegroundColor Green
            Write-Host "    Services: $($cacheSummary.ServicesCount) | Registry keys: $($cacheSummary.RegistryCacheCount) | Hotfixes: $($cacheSummary.HotfixCount)" -ForegroundColor Gray

            if ($script:HAS_COMMON_LIB) {
                Write-AuditLog -Message "Cache initialized: $($cacheSummary.ServicesCount) services, $($cacheSummary.RegistryCacheCount) registry keys" -Level 'INFO'
            }
        } catch {
            Write-Host "[!] WARNING: Cache initialization failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    Continuing without cache (modules will query system directly)" -ForegroundColor Yellow
        }
    } else {
        # No shared library or cache disabled — basic system info
        try {
            $sharedData.OSVersion = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        } catch {
            $sharedData.OSVersion = "Windows (version detection failed)"
        }
        try {
            $sharedData.IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress)
        } catch {
            $sharedData.IPAddresses = @("N/A")
        }
        if ($NoCache) {
            Write-Host "[*] Cache disabled by -NoCache flag" -ForegroundColor Gray
        }
    }

    # ---- Module Execution ----
    $allResults = @()
    $moduleExecutionStart = Get-Date

    if ($Parallel -and $modulesToRun.Count -gt 1) {
        # ============================================================
        # Parallel Execution via RunspacePool
        # ============================================================
        $workerCount = [Math]::Min($Workers, $modulesToRun.Count)
        Write-Host "`n[*] Executing $($modulesToRun.Count) modules in PARALLEL ($workerCount workers)..." -ForegroundColor Cyan

        try {
            $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $workerCount, $sessionState, $Host)
            $runspacePool.Open()

            $jobs = @()

            foreach ($modName in $modulesToRun) {
                $modulePath = $availableModules[$modName]

                # Build script block that loads shared lib + executes module
                $jobScript = {
                    param($ModPath, $SharedDataParam, $CommonLibPath, $ModName)

                    # Load shared library in this runspace if available
                    if ($CommonLibPath -and (Test-Path $CommonLibPath)) {
                        try { . $CommonLibPath } catch { }
                    }

                    # Execute the module
                    try {
                        $results = & $ModPath -SharedData $SharedDataParam
                        return @{ ModuleName = $ModName; Results = $results; Error = $null; StartTime = (Get-Date) }
                    } catch {
                        return @{ ModuleName = $ModName; Results = @(); Error = $_.Exception.Message; StartTime = (Get-Date) }
                    }
                }

                $commonLibPath = Join-Path $PSScriptRoot "shared_components\audit-common.ps1"
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $runspacePool
                $null = $ps.AddScript($jobScript).AddArgument($modulePath).AddArgument($sharedData).AddArgument($commonLibPath).AddArgument($modName)

                $jobs += @{
                    PowerShell = $ps
                    Handle     = $ps.BeginInvoke()
                    ModuleName = $modName
                    StartTime  = Get-Date
                }

                Write-Host "  [>] Queued: $modName" -ForegroundColor Gray
            }

            # Collect results
            foreach ($job in $jobs) {
                try {
                    $jobResult = $job.PowerShell.EndInvoke($job.Handle)
                    $jobElapsed = ((Get-Date) - $job.StartTime).TotalSeconds
                    $script:StatisticsLog.ModuleTimings[$job.ModuleName] = $jobElapsed

                    if ($jobResult -and $jobResult.Count -gt 0) {
                        $result = $jobResult[0]
                        if ($result.Error) {
                            Write-Host "  [!] $($job.ModuleName): ERROR - $($result.Error)" -ForegroundColor Red
                        } elseif ($result.Results -and $result.Results.Count -gt 0) {
                            $validatedResults = Get-ValidatedResults -Results $result.Results -ModuleName $job.ModuleName
                            $moduleStats = Get-ModuleStatistics -Results $validatedResults
                            $script:StatisticsLog.ModuleStats[$job.ModuleName] = $moduleStats
                            $allResults += $validatedResults
                            Write-Host "  [+] $($job.ModuleName): $($moduleStats.Total) checks ($($moduleStats.Pass) pass, $($moduleStats.Fail) fail) [$([Math]::Round($jobElapsed,1))s]" -ForegroundColor Green
                        } else {
                            Write-Host "  [!] $($job.ModuleName): No results returned [$([Math]::Round($jobElapsed,1))s]" -ForegroundColor Yellow
                        }
                    }
                } catch {
                    Write-Host "  [!] $($job.ModuleName): Failed to collect results - $_" -ForegroundColor Red
                } finally {
                    $job.PowerShell.Dispose()
                }
            }

            $runspacePool.Close()
            $runspacePool.Dispose()
        } catch {
            Write-Host "[!] Parallel execution framework failed: $_" -ForegroundColor Red
            Write-Host "[*] Falling back to sequential execution..." -ForegroundColor Yellow
            $Parallel = $false
        }
    }

    if (-not $Parallel -or $modulesToRun.Count -eq 1) {
        # ============================================================
        # Sequential Execution
        # ============================================================
        Write-Host "`n[*] Executing $($modulesToRun.Count) modules sequentially..." -ForegroundColor Cyan

        foreach ($modName in $modulesToRun) {
            $modStartTime = Get-Date
            $moduleResults = Invoke-SecurityModule -ModuleName $modName -SharedData $sharedData
            $modElapsed = ((Get-Date) - $modStartTime).TotalSeconds
            $script:StatisticsLog.ModuleTimings[$modName] = $modElapsed

            if ($moduleResults -and $moduleResults.Count -gt 0) {
                $allResults += $moduleResults
            }
        }
    }

    $moduleExecutionElapsed = ((Get-Date) - $moduleExecutionStart).TotalSeconds
    $script:StatisticsLog.ModuleTimings['_TotalModuleExecution'] = $moduleExecutionElapsed

    # ---- Results Summary ----
    if ($allResults.Count -eq 0) {
        Write-Host "`n[!] WARNING: No audit results collected. Check module configurations." -ForegroundColor Yellow
        return
    }

    # Calculate overall statistics
    $overallStats = Get-ModuleStatistics -Results $allResults

    # Calculate compliance scores
    $complianceScores = @{}

    # Per-module scores
    $moduleGroups = @{}
    foreach ($r in $allResults) {
        if (-not $moduleGroups.ContainsKey($r.Module)) { $moduleGroups[$r.Module] = @() }
        $moduleGroups[$r.Module] += $r
    }
    foreach ($modName in $moduleGroups.Keys) {
        $complianceScores[$modName] = Get-ComplianceScore -Results $moduleGroups[$modName]
    }
    # Overall score
    $complianceScores['overall'] = Get-ComplianceScore -Results $allResults

    # Build ExecutionInfo for reporting
    $totalElapsed = ((Get-Date) - $auditStartTime).TotalSeconds
    $executionInfo = @{
        ComputerName  = $sharedData.ComputerName
        OSVersion     = $sharedData.OSVersion
        IPAddresses   = $sharedData.IPAddresses
        ScanDate      = $sharedData.ScanDate
        Duration      = "$([Math]::Round($totalElapsed, 1))s"
        ModulesRun    = $modulesToRun
        TotalChecks   = $overallStats.Total
        PassCount     = $overallStats.Pass
        FailCount     = $overallStats.Fail
        WarningCount  = $overallStats.Warning
        InfoCount     = $overallStats.Info
        ErrorCount    = $overallStats.Error
    }

    # ---- Display Audit Summary ----
    Write-Host "`n========================================================================================================" -ForegroundColor White
    Write-Host "                              WINDOWS SECURITY AUDIT SUMMARY" -ForegroundColor White
    Write-Host "========================================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "  Computer:    $($executionInfo.ComputerName)" -ForegroundColor Cyan
    Write-Host "  OS:          $($executionInfo.OSVersion)" -ForegroundColor Cyan
    Write-Host "  IP(s):       $($executionInfo.IPAddresses -join ', ')" -ForegroundColor Cyan
    Write-Host "  Scan Date:   $($executionInfo.ScanDate)" -ForegroundColor Cyan
    Write-Host "  Duration:    $($executionInfo.Duration)" -ForegroundColor Cyan
    Write-Host "  Modules:     $($modulesToRun -join ', ')" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────────┐" -ForegroundColor White
    Write-Host "  │  TOTAL: $($overallStats.Total)   │  PASS: $($overallStats.Pass)   │  FAIL: $($overallStats.Fail)   │  WARN: $($overallStats.Warning)   │  INFO: $($overallStats.Info)   │  ERR: $($overallStats.Error)  │" -ForegroundColor White
    Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor White

    # Display compliance scores
    $oc = $complianceScores['overall']
    $ocColor = if ($oc.WeightedPct -ge 80) { 'Green' } elseif ($oc.WeightedPct -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host ""
    Write-Host "  Overall Compliance Score:" -ForegroundColor White
    Write-Host "    Simple:            $($oc.SimplePct)%" -ForegroundColor $ocColor
    Write-Host "    Weighted:          $($oc.WeightedPct)% [$($oc.ThresholdResult)]" -ForegroundColor $ocColor
    Write-Host "    Severity-Adjusted: $($oc.SeverityWeightedPct)%" -ForegroundColor $ocColor
    Write-Host ""

    # Per-module breakdown
    Write-Host "  Per-Module Compliance:" -ForegroundColor White
    foreach ($modName in ($moduleGroups.Keys | Sort-Object)) {
        $mc = $complianceScores[$modName]
        $mcColor = if ($mc.WeightedPct -ge 80) { 'Green' } elseif ($mc.WeightedPct -ge 60) { 'Yellow' } else { 'Red' }
        $ms = $script:StatisticsLog.ModuleStats[$modName]
        $bar = "[" + ("█" * [Math]::Floor($mc.WeightedPct / 5)) + ("░" * (20 - [Math]::Floor($mc.WeightedPct / 5))) + "]"
        Write-Host "    $($modName.PadRight(20)) $bar $($mc.WeightedPct)%  ($($ms.Total) checks, $($ms.Pass) pass, $($ms.Fail) fail)" -ForegroundColor $mcColor
    }

    # ---- Performance Profile ----
    if ($ShowProfile) {
        Write-Host "`n  ──────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  Performance Profile:" -ForegroundColor White
        if ($script:StatisticsLog.ModuleTimings.ContainsKey('CacheWarmUp')) {
            Write-Host "    Cache Warm-Up:         $([Math]::Round($script:StatisticsLog.ModuleTimings['CacheWarmUp'], 2))s" -ForegroundColor Gray
        }
        foreach ($modName in ($modulesToRun | Sort-Object)) {
            if ($script:StatisticsLog.ModuleTimings.ContainsKey($modName)) {
                $timing = $script:StatisticsLog.ModuleTimings[$modName]
                Write-Host "    $($modName.PadRight(25)) $([Math]::Round($timing, 2))s" -ForegroundColor Gray
            }
        }
        Write-Host "    Module Execution:      $([Math]::Round($moduleExecutionElapsed, 2))s" -ForegroundColor Gray
        Write-Host "    Total Audit Duration:  $([Math]::Round($totalElapsed, 2))s" -ForegroundColor Gray
        if ($Parallel) {
            Write-Host "    Execution Mode:        Parallel ($Workers workers)" -ForegroundColor Gray
        } else {
            Write-Host "    Execution Mode:        Sequential" -ForegroundColor Gray
        }
    }

    Write-Host "`n========================================================================================================`n" -ForegroundColor White

    # ---- Severity Distribution ----
    $sevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    foreach ($r in $allResults) {
        $sev = if ($r.PSObject.Properties['Severity'] -and $r.Severity) { $r.Severity } else { 'Medium' }
        if ($sevCounts.ContainsKey($sev)) { $sevCounts[$sev]++ }
    }
    $failResults = @($allResults | Where-Object { $_.Status -eq 'Fail' })
    $failSevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    foreach ($r in $failResults) {
        $sev = if ($r.PSObject.Properties['Severity'] -and $r.Severity) { $r.Severity } else { 'Medium' }
        if ($failSevCounts.ContainsKey($sev)) { $failSevCounts[$sev]++ }
    }

    Write-Host "  Severity Distribution (Failed Checks Only):" -ForegroundColor White
    foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
        $count = $failSevCounts[$sev]
        $sevColor = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; 'Low' { 'Cyan' }; default { 'Gray' } }
        if ($count -gt 0) {
            Write-Host "    $($sev.PadRight(15)) $count" -ForegroundColor $sevColor
        }
    }
    Write-Host ""

    # ---- Remediation ----
    if ($RemediateIssues -or $RemediateIssues_Fail -or $RemediateIssues_Warning -or $RemediateIssues_Info -or $RemediationFile) {
        Invoke-Remediation -Results $allResults
    }

    # ---- Export Results ----
    $exportedFiles = Export-Results -Results $allResults -ExecutionInfo $executionInfo -ComplianceScores $complianceScores

    # ---- Final Logging ----
    if ($script:HAS_COMMON_LIB) {
        try {
            Write-AuditLog -Message "Audit complete: $($overallStats.Total) checks, $($overallStats.Pass) pass, $($overallStats.Fail) fail, compliance=$($oc.WeightedPct)%" -Level 'INFO'
            Write-AuditLog -Message "Duration: $([Math]::Round($totalElapsed, 2))s, Files exported: $($exportedFiles.Count)" -Level 'INFO'
        } catch { }
    }

    Write-Host "[*] Windows Security Audit complete.`n" -ForegroundColor Green
}

# ============================================================================
# Script Entry Point
# ============================================================================
# Shared library loading occurs at script initialization (line ~114).
# Valid status/severity values defined at script initialization (line ~109).
try {
    Start-SecurityAudit
} catch {
    Write-Host "`n========================================================================================================" -ForegroundColor Red
    Write-Host "                               FATAL ERROR - AUDIT ABORTED" -ForegroundColor Red
    Write-Host "========================================================================================================" -ForegroundColor Red
    Write-Host "`n  Error Message : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Error Type    : $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "  Script        : $($_.InvocationInfo.ScriptName)" -ForegroundColor Yellow
    Write-Host "  Line Number   : $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
    Write-Host "  Line Content  : $($_.InvocationInfo.Line.Trim())" -ForegroundColor Yellow
    if ($_.Exception.InnerException) {
        Write-Host "  Inner Error   : $($_.Exception.InnerException.Message)" -ForegroundColor DarkYellow
    }
    Write-Host "`n  Stack Trace:" -ForegroundColor Gray
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor Gray
    Write-Host "`n  Troubleshooting:" -ForegroundColor Cyan
    Write-Host "    1. Ensure script is running as Administrator" -ForegroundColor White
    Write-Host "    2. Verify PowerShell version: `$PSVersionTable.PSVersion (requires 5.1+)" -ForegroundColor White
    Write-Host "    3. Check shared_components\audit-common.ps1 exists and loads without error" -ForegroundColor White
    Write-Host "    4. Check modules\ directory contains valid module scripts" -ForegroundColor White
    Write-Host "    5. Run with -LogLevel DEBUG -LogFile .\debug.log for detailed diagnostics" -ForegroundColor White
    Write-Host "`n========================================================================================================`n" -ForegroundColor Red

    # Attempt to log the fatal error if structured logging is available
    if ($script:HAS_COMMON_LIB) {
        try { Write-AuditLog -Message "FATAL: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" -Level 'CRITICAL' } catch { }
    }

    exit 1
}
# ============================================================================
# End of Main Script (Windows-Security-Audit.ps1)
# ============================================================================
