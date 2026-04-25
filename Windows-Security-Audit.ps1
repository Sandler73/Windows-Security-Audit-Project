# Windows-Security-Audit.ps1
# Windows Security Audit Project
# Version: 6.1.2
# GitHub: https://github.com/Sandler73/Windows-Security-Audit-Project

<#
.SYNOPSIS
    Comprehensive module-based Windows security audit script supporting multiple
    compliance frameworks with parallel execution, caching, structured logging,
    and compliance scoring.

.DESCRIPTION
    This script audits Windows systems against multiple security frameworks:
    - ACSC Essential Eight           - HIPAA Security Rule
    - CIS Benchmarks                 - ISO 27001 Annex A Technology Controls
    - CISA Best Practices            - Microsoft Security Baseline
    - CMMC 2.0 (DoD)                 - Microsoft Defender for Endpoint/EDR
    - Core Security Baseline         - NIST Cybersecurity Framework
    - DISA STIGs                     - NSA Cybersecurity Guidance
    - ENISA Cybersecurity Guidelines - PCI DSS v4.0
    - GDPR Technical Controls        - SOC 2 Type II

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
    Comma-separated list of modules. Available: ACSC, CIS, CISA, CMMC, Core, ENISA, GDPR,
    HIPAA, ISO27001, MS, MS-DefenderATP, NIST, NSA, PCI-DSS, SOC2, STIG, All
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
.PARAMETER Verbose
    Enable verbose output for detailed diagnostic information during execution.
    Inherited from [CmdletBinding()] -- use -Verbose switch.

.PARAMETER Baseline
    Path to a baseline JSON file (typically a previous audit's JSON output).
    When supplied, the report includes a drift section showing new failures,
    resolved findings, and regressions versus the baseline state.

.PARAMETER ExportGPO
    Path for a Group Policy registry.pol file generated from selected
    remediations. Only registry-modifying remediations are included; non-registry
    remediations are skipped and counted in the operation summary.

.PARAMETER RollbackPath
    Path for a generated rollback script. When auto-remediation runs with this
    parameter set, the orchestrator writes a PowerShell script containing the
    inverse of every applied remediation.

.PARAMETER RemediationBundle
    Apply a predefined collection of related remediations as a single batch.
    Recognized bundles: DisableLegacyProtocols, HardenAuthentication,
    EnableAuditLogging, LockDownRDP, EssentialEightLevel1.

.PARAMETER ShowRiskPriority
    Add a Risk Priority column (1-100 scale) to the HTML report and exports.
    The score combines severity, exploitability, exposure, and asset criticality.

.PARAMETER ShowCorrelations
    Add a Cross-Framework Correlations panel to the HTML report identifying
    findings that test the same underlying control across multiple modules.

.PARAMETER ShowCompensatingControls
    Add a Compensating Controls panel to the HTML report flagging failed checks
    where a passing related control may mitigate the risk.

.PARAMETER ShowHelp
    Display the comprehensive help screen and exit. Aliases: -Help, -H, -?
    The script also recognizes the following non-standard invocation forms via
    its remaining-arguments catch-all: 'help', '-help', '--help', '--h'.

.EXAMPLE
    .\Windows-Security-Audit.ps1
    Run all modules with default HTML output
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Parallel -Workers 8 -ShowProfile
    Run all modules in parallel with performance breakdown
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Modules Core,NIST -OutputFormat CSV -LogLevel DEBUG
    Run specific modules with CSV output and debug logging
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Modules CMMC,HIPAA -LogFile .\audit.log -Verbose
    Run CMMC and HIPAA modules with verbose output and explicit log file
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Modules GDPR,SOC2,PCI-DSS -LogLevel DEBUG -JsonLog
    Run privacy/compliance modules with JSON-formatted debug logging
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Baseline .\reports\audit-2026-02-15.json
    Compare current state to a previous audit and highlight drift
.EXAMPLE
    .\Windows-Security-Audit.ps1 -ShowRiskPriority -ShowCorrelations -ShowCompensatingControls
    Generate enriched report with risk priority, correlations, and compensating controls
.EXAMPLE
    .\Windows-Security-Audit.ps1 -RemediateIssues_Fail -RollbackPath .\rollback.ps1
    Apply remediation for failed checks and generate inverse-script for rollback
.EXAMPLE
    .\Windows-Security-Audit.ps1 -Help
    Display comprehensive help. Equivalent forms: -H, -?, help, -help, --help, --h

.NOTES
    Requires: Windows 10/11 or Windows Server 2016+, PowerShell 5.1+
    Run as Administrator for complete results
    Version: 6.1.2
    Logging: Always enabled. Use -LogFile to specify path, -LogLevel to filter.
    Help:    Use -Help (or any of -H, -?, help, -help, --help, --h) for full help.
#>

[CmdletBinding()]
param(
    [ValidateSet("ACSC","CIS","CISA","CMMC","Core","ENISA","GDPR","HIPAA","ISO27001","MS","MS-DefenderATP","NIST","NSA","PCI-DSS","SOC2","STIG","All")]
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
    [switch]$Quiet,
    [string]$Baseline = "",
    [string]$ExportGPO = "",
    [string]$RollbackPath = "",
    [ValidateSet("DisableLegacyProtocols","HardenAuthentication","EnableAuditLogging","LockDownRDP","EssentialEightLevel1","")]
    [string]$RemediationBundle = "",
    [switch]$ShowRiskPriority,
    [switch]$ShowCorrelations,
    [switch]$ShowCompensatingControls,

    # v6.1: Help invocation parameter. Aliases cover '-Help', '-H', '-?'.
    # Additional non-standard forms ('help', '--help', '--h', '-help') are caught
    # via the $RemainingArgs catch-all and detected at the start of Start-SecurityAudit.
    [Alias("Help","H")]
    [switch]$ShowHelp,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = "Continue"
$script:ScriptVersion = "6.1.2"
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
# Built-in Logging Infrastructure (fallback when shared library unavailable)
# ============================================================================
# Log level numeric values for comparison
$script:BuiltInLogLevels = @{ 'DEBUG'=0; 'INFO'=1; 'WARNING'=2; 'ERROR'=3; 'CRITICAL'=4 }
$script:CurrentLogLevelNumeric = $script:BuiltInLogLevels[$LogLevel]
$script:ActiveLogFile = $LogFile
$script:UseJsonLog = $JsonLog.IsPresent

function Initialize-BuiltInLogging {
    # Create log file and directory if -LogFile was specified
    if ($script:ActiveLogFile) {
        $logDir = Split-Path -Parent $script:ActiveLogFile
        if ($logDir -and -not (Test-Path $logDir)) {
            try {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                Write-Verbose "Created log directory: $logDir"
            } catch {
                Write-Warning "Could not create log directory ${logDir}: $_"
                return
            }
        }
        # Create the log file if it does not exist
        if (-not (Test-Path $script:ActiveLogFile)) {
            try {
                $header = "# Windows Security Audit Log - Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                Set-Content -Path $script:ActiveLogFile -Value $header -Encoding UTF8
                Write-Verbose "Created log file: $($script:ActiveLogFile)"
            } catch {
                Write-Warning "Could not create log file: $_"
            }
        }
    } else {
        # Auto-generate log file path in logs/ directory
        if (-not (Test-Path $script:LogDir)) {
            try { New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null } catch { <# Expected: item may not exist #> }
        }
        $script:ActiveLogFile = Join-Path $script:LogDir "audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        try {
            $header = "# Windows Security Audit Log - Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Set-Content -Path $script:ActiveLogFile -Value $header -Encoding UTF8
            Write-Verbose "Auto-created log file: $($script:ActiveLogFile)"
        } catch {
            Write-Warning "Could not create auto log file: $_"
            $script:ActiveLogFile = ""
        }
    }
}

# Only define built-in Write-AuditLog if shared library did NOT provide one
if (-not (Get-Command 'Write-AuditLog' -ErrorAction SilentlyContinue)) {
    function Write-AuditLog {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$Message,
            [ValidateSet('DEBUG','INFO','WARNING','ERROR','CRITICAL')]
            [string]$Level = 'INFO',
            [string]$Module = 'MAIN'
        )
        $numericLevel = $script:BuiltInLogLevels[$Level]
        if ($numericLevel -lt $script:CurrentLogLevelNumeric) { return }

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

        # Console output with color coding
        $color = switch ($Level) {
            'DEBUG'    { 'Gray' }
            'INFO'     { 'White' }
            'WARNING'  { 'Yellow' }
            'ERROR'    { 'Red' }
            'CRITICAL' { 'Red' }
            default    { 'White' }
        }
        if (-not $Quiet) {
            $prefix = switch ($Level) {
                'DEBUG'    { '[DBG]' }
                'INFO'     { '[+]' }
                'WARNING'  { '[!]' }
                'ERROR'    { '[-]' }
                'CRITICAL' { '[!!!]' }
                default    { '[*]' }
            }
            Write-Host "$prefix [$Module] $Message" -ForegroundColor $color
        }

        # Write-Verbose passthrough for -Verbose support
        Write-Verbose "[$Level] [$Module] $Message"

        # File output
        if ($script:ActiveLogFile) {
            try {
                if ($script:UseJsonLog) {
                    $logEntry = @{
                        timestamp = $timestamp
                        level     = $Level
                        module    = $Module
                        message   = $Message
                    } | ConvertTo-Json -Compress
                } else {
                    $logEntry = "[$timestamp] [$Level] [$Module] $Message"
                }
                Add-Content -Path $script:ActiveLogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
            } catch { <# Expected: item may not exist #> }
        }
    }
}

# Also define Initialize-AuditLogging fallback if shared lib didn't provide it
if (-not (Get-Command 'Initialize-AuditLogging' -ErrorAction SilentlyContinue)) {
    function Initialize-AuditLogging {
        param(
            [string]$LogLevel = 'INFO',
            [string]$LogFile = '',
            [switch]$JsonFormat
        )
        if ($LogLevel) { $script:CurrentLogLevelNumeric = $script:BuiltInLogLevels[$LogLevel] }
        if ($LogFile) { $script:ActiveLogFile = $LogFile }
        if ($JsonFormat) { $script:UseJsonLog = $true }
        Initialize-BuiltInLogging
    }
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
    Write-Host "  - ACSC Essential Eight              - HIPAA Security Rule" -ForegroundColor Gray
    Write-Host "  - CIS Benchmarks                    - ISO 27001 Annex A Controls" -ForegroundColor Gray
    Write-Host "  - CISA Best Practices               - Microsoft Security Baseline" -ForegroundColor Gray
    Write-Host "  - CMMC 2.0 (DoD)                    - Microsoft Defender for Endpoint/EDR" -ForegroundColor Gray
    Write-Host "  - Core Security Baseline             - NIST Cybersecurity Framework" -ForegroundColor Gray
    Write-Host "  - DISA STIGs                         - NSA Cybersecurity Guidance" -ForegroundColor Gray
    Write-Host "  - ENISA Cybersecurity Guidelines     - PCI DSS v4.0" -ForegroundColor Gray
    Write-Host "  - GDPR Technical Controls            - SOC 2 Type II" -ForegroundColor Gray
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
    # Validates PowerShell version, admin privileges, and OS compatibility
    # Returns: PSCustomObject with .Success (bool) and .Messages (string[])
    $messages = @()
    $success = $true
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        $messages += "PowerShell 5.1+ required (current: $psVersion)"
        $success = $false
    } else {
        $messages += "PowerShell version: $psVersion"
    }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $messages += "WARNING: Not running as Administrator (some checks may be limited)"
        if ($RemediateIssues -or $AutoRemediate) {
            $messages += "ERROR: Remediation requires Administrator privileges"
            $success = $false
        }
    } else {
        $messages += "Running with Administrator privileges"
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $messages += "Operating System: $($os.Caption) (Build $($os.BuildNumber))"
    } catch {
        $messages += "Could not detect OS version"
    }
    return [PSCustomObject]@{ Success = $success; Messages = $messages }
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
    $nameMap = @{
        'acsc'='ACSC'; 'cis'='CIS'; 'cisa'='CISA'; 'cmmc'='CMMC'; 'core'='Core';
        'enisa'='ENISA'; 'gdpr'='GDPR'; 'hipaa'='HIPAA'; 'iso27001'='ISO27001';
        'ms'='MS'; 'ms-defenderatp'='MS-DefenderATP'; 'nist'='NIST'; 'nsa'='NSA';
        'pcidss'='PCI-DSS'; 'soc2'='SOC2'; 'stig'='STIG'
    }
    foreach ($file in $moduleFiles) {
        $rawName = ($file.BaseName -replace '^module-', '').ToLower()
        $displayName = if ($nameMap[$rawName]) { $nameMap[$rawName] } else { $rawName }
        $modules[$displayName] = $file.FullName
    }
    return $modules
}

function Show-DetailedHelp {
    <#
    .SYNOPSIS
        Display comprehensive interactive help for the Windows Security Audit Script.
    .DESCRIPTION
        Renders a multi-section help screen covering overview, frameworks, parameters
        (grouped by purpose), examples, v6.1 capabilities, and quick reference. This
        is the primary user-facing help and supplements PowerShell's Get-Help cmdlet.
    #>

    $version = if ($script:ScriptVersion) { $script:ScriptVersion } else { "6.1" }
    $w = 88

    function Write-Section { param([string]$Title)
        Write-Host ""
        Write-Host ("=" * $w) -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host ("=" * $w) -ForegroundColor Cyan
    }
    function Write-SubSection { param([string]$Title)
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Yellow
        Write-Host ("  " + ("-" * ($Title.Length))) -ForegroundColor DarkGray
    }
    function Write-Param { param([string]$Name, [string]$Type, [string]$Desc, [string]$Default = "")
        $line = "    {0,-30} {1,-12}" -f $Name, $Type
        Write-Host $line -ForegroundColor White -NoNewline
        Write-Host " $Desc" -ForegroundColor Gray
        if ($Default) {
            Write-Host ("    {0,-30} {1,-12} Default: {2}" -f "", "", $Default) -ForegroundColor DarkGray
        }
    }
    function Write-Example { param([string]$Title, [string]$Cmd, [string]$Desc)
        Write-Host ""
        Write-Host "    $Title" -ForegroundColor Yellow
        Write-Host "      $Cmd" -ForegroundColor White
        Write-Host "      $Desc" -ForegroundColor DarkGray
    }

    # ---- Banner ----
    Write-Host ""
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host "                Windows Security Audit Script - v$version Help" -ForegroundColor Cyan
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host "  PowerShell-based security compliance auditor for Windows systems" -ForegroundColor White
    Write-Host "  16 frameworks, 3,994 automated checks, multi-format reporting" -ForegroundColor Gray

    # ---- Synopsis ----
    Write-Section "SYNOPSIS"
    Write-Host "    .\Windows-Security-Audit.ps1 [-Modules <list>] [-OutputFormat <fmt>]" -ForegroundColor White
    Write-Host "                                 [-OutputPath <path>] [remediation switches]" -ForegroundColor White
    Write-Host "                                 [-Parallel] [-Workers <N>] [-Baseline <path>]" -ForegroundColor White
    Write-Host "                                 [-ExportGPO <path>] [-RollbackPath <path>]" -ForegroundColor White
    Write-Host "                                 [-RemediationBundle <name>]" -ForegroundColor White
    Write-Host "                                 [-ShowRiskPriority] [-ShowCorrelations]" -ForegroundColor White
    Write-Host "                                 [-ShowCompensatingControls] [logging switches]" -ForegroundColor White

    # ---- Description ----
    Write-Section "DESCRIPTION"
    Write-Host "    Comprehensive Windows security compliance audit tool that evaluates the system" -ForegroundColor White
    Write-Host "    against multiple industry-standard frameworks. Each module performs hundreds" -ForegroundColor White
    Write-Host "    of registry, service, audit-policy, and configuration checks, classifies" -ForegroundColor White
    Write-Host "    results by severity, and maps findings to equivalent controls across other" -ForegroundColor White
    Write-Host "    frameworks. Generates HTML, JSON, CSV, and XML reports." -ForegroundColor White

    # ---- Frameworks ----
    Write-Section "SUPPORTED FRAMEWORKS (16 modules)"
    $frameworks = @(
        @('ACSC',           'Australian Cyber Security Centre Essential Eight + Maturity Levels'),
        @('CIS',            'CIS Benchmarks v8 + Cloud/Mobile/ICS-OT Companion Guides'),
        @('CISA',           'CISA Best Practices, KEV catalog, Zero Trust Maturity Model'),
        @('CMMC',           'CMMC 2.0 L1/L2/L3 + NIST SP 800-172 + DFARS 252.204-7012'),
        @('Core',           'Core Security Baseline + Win11 features (VBS, HVCI, Pluton, etc.)'),
        @('ENISA',          'ENISA Cybersecurity + NIS2 + Cyber Resilience Act + DORA'),
        @('GDPR',           'GDPR Articles 5/15-21/28/32/35 + ePrivacy + Schrems II'),
        @('HIPAA',          'HIPAA Security Rule + NIST SP 800-66 R2 + HITECH + 405(d) HICP'),
        @('ISO27001',       'ISO 27001:2022 + 27002:2022 + 27017/27018 + 27701'),
        @('MS',             'Microsoft Security Baseline (Win11 24H2/Server 2025) + Edge + M365'),
        @('MS-DefenderATP', 'Microsoft Defender for Endpoint (ATP/EDR + per-rule ASR + WDAC)'),
        @('NIST',           'NIST SP 800-53 Rev 5 + CSF 2.0 + 800-171 R3 + 800-207 + 800-161'),
        @('NSA',            'NSA Cybersecurity (CSI + AD hardening + Top 10 + BlackLotus)'),
        @('PCI-DSS',        'PCI DSS v4.0/v4.0.1 + PIN Security + 3DS Core + SSF'),
        @('SOC2',           'SOC 2 Trust Service Criteria + AICPA TSP Section 100 PoF'),
        @('STIG',           'DISA STIGs + SRG cross-mapping + Microsoft Defender STIG')
    )
    foreach ($f in $frameworks) {
        Write-Host ("    {0,-16} {1}" -f $f[0], $f[1]) -ForegroundColor White
    }

    # ---- Parameters: Module Selection ----
    Write-Section "PARAMETERS"

    Write-SubSection "Module Selection and Output"
    Write-Param "-Modules <string[]>" "[string[]]" "Modules to run. Comma-separated list or 'All'." "All"
    Write-Host "                                                Valid: ACSC, CIS, CISA, CMMC, Core, ENISA, GDPR," -ForegroundColor DarkGray
    Write-Host "                                                HIPAA, ISO27001, MS, MS-DefenderATP, NIST, NSA," -ForegroundColor DarkGray
    Write-Host "                                                PCI-DSS, SOC2, STIG, All" -ForegroundColor DarkGray
    Write-Param "-OutputFormat <string>" "[string]" "Report format: HTML, CSV, JSON, XML, All, Console" "HTML"
    Write-Param "-OutputPath <string>" "[string]" "Output file path (auto-generated if omitted)" ".\reports\..."
    Write-Param "-ListModules" "[switch]" "List available modules and exit"

    Write-SubSection "Remediation"
    Write-Param "-RemediateIssues" "[switch]" "Interactive remediation of Fail/Warning/Info findings"
    Write-Param "-RemediateIssues_Fail" "[switch]" "Interactive remediation of Fail status only"
    Write-Param "-RemediateIssues_Warning" "[switch]" "Interactive remediation of Warning status only"
    Write-Param "-RemediateIssues_Info" "[switch]" "Interactive remediation of Info status only"
    Write-Param "-AutoRemediate" "[switch]" "Apply remediations without prompting (requires YES confirmation)"
    Write-Param "-RemediationFile <path>" "[string]" "JSON file with selected issues to remediate"
    Write-Param "-RemediationBundle <name>" "[string]" "Apply predefined bundle. Valid: DisableLegacyProtocols,"
    Write-Host "                                                HardenAuthentication, EnableAuditLogging," -ForegroundColor DarkGray
    Write-Host "                                                LockDownRDP, EssentialEightLevel1" -ForegroundColor DarkGray
    Write-Param "-RollbackPath <path>" "[string]" "Generate inverse-script alongside auto-remediation"

    Write-SubSection "v6.1 Cross-Cutting Capabilities"
    Write-Param "-Baseline <path>" "[string]" "Compare to previous audit JSON for drift analysis"
    Write-Param "-ExportGPO <path>" "[string]" "Export remediations to Group Policy .pol file"
    Write-Param "-ShowRiskPriority" "[switch]" "Add 1-100 risk priority score to results"
    Write-Param "-ShowCorrelations" "[switch]" "Group same-control findings across modules"
    Write-Param "-ShowCompensatingControls" "[switch]" "Flag failed checks where related control mitigates"

    Write-SubSection "Performance and Caching"
    Write-Param "-Parallel" "[switch]" "Execute modules in parallel via RunspacePool"
    Write-Param "-Workers <int>" "[int]" "Parallel worker count (1-16)" "4"
    Write-Param "-NoCache" "[switch]" "Disable shared data cache (debugging only)"
    Write-Param "-ShowProfile" "[switch]" "Display per-module timing breakdown"

    Write-SubSection "Logging"
    Write-Param "-LogLevel <string>" "[string]" "Verbosity: DEBUG, INFO, WARNING, ERROR" "INFO"
    Write-Param "-LogFile <path>" "[string]" "Explicit log file path (auto-generated if omitted)"
    Write-Param "-JsonLog" "[switch]" "JSON format for SIEM ingestion"
    Write-Param "-Quiet" "[switch]" "Suppress non-essential output"
    Write-Param "-Verbose" "[switch]" "Detailed diagnostic output"

    Write-SubSection "Help"
    Write-Param "-Help, -H, -?" "[switch]" "Display this help screen"
    Write-Host "    Also accepts:                            help, -help, --help, --h" -ForegroundColor Gray

    # ---- Examples ----
    Write-Section "EXAMPLES"

    Write-Example "Run all modules with default HTML output:" `
        ".\Windows-Security-Audit.ps1" `
        "Generates timestamped HTML report in .\reports\ directory."

    Write-Example "Run specific frameworks in parallel:" `
        ".\Windows-Security-Audit.ps1 -Modules CIS,STIG,NIST -Parallel -Workers 8" `
        "Three modules execute concurrently using 8 worker threads."

    Write-Example "Multi-format output with custom path:" `
        ".\Windows-Security-Audit.ps1 -OutputFormat All -OutputPath .\audits\Q2-baseline" `
        "Generates Q2-baseline.html, .json, .csv, .xml in .\audits\ directory."

    Write-Example "Compare to previous baseline (v6.1):" `
        ".\Windows-Security-Audit.ps1 -Baseline .\audits\Q1-baseline.json" `
        "Report includes drift section: new failures, resolved findings, regressions."

    Write-Example "Apply Essential Eight Level 1 bundle (v6.1):" `
        ".\Windows-Security-Audit.ps1 -RemediationBundle EssentialEightLevel1 -AutoRemediate -RollbackPath .\rollback.ps1" `
        "Auto-applies E8 L1 controls; generates rollback script for reversal."

    Write-Example "Enriched report with priorities and correlations (v6.1):" `
        ".\Windows-Security-Audit.ps1 -ShowRiskPriority -ShowCorrelations -ShowCompensatingControls" `
        "Adds 1-100 priority scores, cross-framework correlations, and compensating control panels."

    Write-Example "Export remediations to Group Policy (v6.1):" `
        ".\Windows-Security-Audit.ps1 -RemediateIssues_Fail -ExportGPO .\policy.pol" `
        "Generates Group Policy .pol file from registry-modifying remediations."

    Write-Example "Selective interactive remediation:" `
        ".\Windows-Security-Audit.ps1 -RemediateIssues_Fail -RemediateIssues_Warning" `
        "Prompt for each Fail or Warning finding individually."

    Write-Example "SIEM-friendly JSON logging:" `
        ".\Windows-Security-Audit.ps1 -OutputFormat JSON -JsonLog -LogFile .\siem.json" `
        "Both audit results and run-time logs in JSON format."

    Write-Example "List available modules:" `
        ".\Windows-Security-Audit.ps1 -ListModules" `
        "Displays all 16 available modules and exits."

    # ---- Bundles ----
    Write-Section "REMEDIATION BUNDLES (v6.1)"
    Write-Host "    Bundles select related remediations from the discovered findings." -ForegroundColor White
    Write-Host ""
    $bundles = @(
        @('DisableLegacyProtocols', 'SMBv1, TLS 1.0/1.1, SSLv2/3, LLMNR, NetBIOS, LM hash, NTLMv1, RC4, 3DES'),
        @('HardenAuthentication',   'UAC, LSA Protection, Credential Guard, NTLM levels, Anonymous, Cached Logons, Password Policy, WDigest'),
        @('EnableAuditLogging',     'Process Creation, ScriptBlockLogging, ModuleLogging, Transcription, Audit Policy, Event Log Size'),
        @('LockDownRDP',            'RDP enable, NLA, MinEncryption, SecurityLayer, IdleTimeout, MaxIdleTime'),
        @('EssentialEightLevel1',   'ACSC E1-E8: AppControl, Patch Apps, Macros, App Hardening, Admin Privs, Patch OS, MFA, Backups')
    )
    foreach ($b in $bundles) {
        Write-Host ("    {0,-26} {1}" -f $b[0], $b[1]) -ForegroundColor Gray
    }

    # ---- Quick Reference ----
    Write-Section "QUICK REFERENCE"
    Write-SubSection "Output Formats"
    Write-Host "    HTML       Interactive report with charts, filters, and remediation panel" -ForegroundColor White
    Write-Host "    JSON       Structured data for programmatic consumption" -ForegroundColor White
    Write-Host "    CSV        Tabular for spreadsheet analysis" -ForegroundColor White
    Write-Host "    XML        XSL-styled workbook (renders in browser)" -ForegroundColor White
    Write-Host "    All        Generate all formats simultaneously" -ForegroundColor White
    Write-Host "    Console    Tabular output to terminal only" -ForegroundColor White

    Write-SubSection "Result Status Values"
    Write-Host "    Pass       Configuration meets the framework requirement" -ForegroundColor Green
    Write-Host "    Fail       Configuration violates the framework requirement" -ForegroundColor Red
    Write-Host "    Warning    Marginal/risky configuration; review recommended" -ForegroundColor Yellow
    Write-Host "    Info       Informational finding; no action required" -ForegroundColor Cyan
    Write-Host "    Error      Check could not be performed (permission/feature issue)" -ForegroundColor Magenta

    Write-SubSection "Severity Levels"
    Write-Host "    Critical       Immediate action required; high-impact vulnerability" -ForegroundColor Red
    Write-Host "    High           Significant risk; remediate within standard cadence" -ForegroundColor DarkYellow
    Write-Host "    Medium         Moderate risk; address per organizational policy" -ForegroundColor Yellow
    Write-Host "    Low            Minor risk; informational hardening" -ForegroundColor Cyan
    Write-Host "    Informational  Reference data; no risk implication" -ForegroundColor Gray

    # ---- Requirements ----
    Write-Section "REQUIREMENTS"
    Write-Host "    OS              Windows 10/11 or Windows Server 2016+" -ForegroundColor White
    Write-Host "    PowerShell      5.1 or later" -ForegroundColor White
    Write-Host "    Privileges      Administrator (run as elevated PowerShell)" -ForegroundColor White
    Write-Host "    Dependencies    None - all checks use built-in cmdlets" -ForegroundColor White

    # ---- Footer ----
    Write-Section "MORE INFORMATION"
    Write-Host "    Documentation:  docs\project\README.md" -ForegroundColor White
    Write-Host "    Wiki:           docs\wiki\Home.md" -ForegroundColor White
    Write-Host "    Changelog:      docs\project\CHANGELOG.md" -ForegroundColor White
    Write-Host "    Release notes:  RELEASE-NOTES-v6.1.md" -ForegroundColor White
    Write-Host "    Module catalog: .\Windows-Security-Audit.ps1 -ListModules" -ForegroundColor White
    Write-Host "    Cmdlet help:    Get-Help .\Windows-Security-Audit.ps1 -Full" -ForegroundColor White
    Write-Host ""
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
}

function Show-AvailableModules {
    $available = Get-AvailableModules
    Write-Host "`n  Available Security Audit Modules:" -ForegroundColor Cyan
    Write-Host "  $('=' * 50)" -ForegroundColor Gray
    foreach ($name in ($available.Keys | Sort-Object)) {
        Write-Host "    $name" -ForegroundColor White -NoNewline
        Write-Host " -`> $($available[$name])" -ForegroundColor Gray
    }
    Write-Host "`n  Usage: .\Windows-Security-Audit.ps1 -Modules Core,NIST,CIS`n" -ForegroundColor Cyan
}

function Invoke-SecurityModule {
    param([string]$ModuleName, [hashtable]$SharedData)
    $available = Get-AvailableModules
    if (-not $available.ContainsKey($ModuleName)) {
        Write-Host "[!] Module not found: $ModuleName" -ForegroundColor Red
        Write-AuditLog -Message "Module not found in registry: $ModuleName" -Level 'ERROR' -Module $ModuleName
        return @()
    }
    $modulePath = $available[$ModuleName]
    $moduleStartTime = Get-Date
    try {
        Write-Host "`n[*] Executing module: $ModuleName" -ForegroundColor Cyan
        Write-AuditLog -Message "Module starting: path=$modulePath" -Level 'DEBUG' -Module $ModuleName
        $scriptBlock = [ScriptBlock]::Create("param([hashtable]`$SharedData); & '$modulePath' -SharedData `$SharedData")
        $moduleResults = & $scriptBlock -SharedData $SharedData
        $moduleElapsed = ((Get-Date) - $moduleStartTime).TotalSeconds
        if ($moduleResults) {
            $moduleResults = Get-ValidatedResults -Results $moduleResults -ModuleName $ModuleName
            $moduleStats = Get-ModuleStatistics -Results $moduleResults
            $script:StatisticsLog.ModuleStats[$ModuleName] = $moduleStats
            $script:StatisticsLog.ModuleTimings[$ModuleName] = $moduleElapsed
            Write-Host "[+] Module $ModuleName completed: $($moduleStats.Total) checks `($($moduleStats.Pass) pass, $($moduleStats.Fail) fail, $($moduleStats.Warning) warning, $($moduleStats.Info) info, $($moduleStats.Error) error`)" -ForegroundColor Green
            Write-AuditLog -Message "Module complete in $([Math]::Round($moduleElapsed, 2))s: $($moduleStats.Total) checks ($($moduleStats.Pass) pass, $($moduleStats.Fail) fail, $($moduleStats.Warning) warning, $($moduleStats.Info) info, $($moduleStats.Error) error)" -Level 'INFO' -Module $ModuleName
            return $moduleResults
        } else {
            Write-Host "[!] Module $ModuleName returned no results" -ForegroundColor Yellow
            Write-AuditLog -Message "Module returned no results after $([Math]::Round($moduleElapsed, 2))s" -Level 'WARNING' -Module $ModuleName
            return @()
        }
    } catch {
        $moduleElapsed = ((Get-Date) - $moduleStartTime).TotalSeconds
        Write-Host "[!] Error executing module ${ModuleName}: $_" -ForegroundColor Red
        Write-AuditLog -Message "Module exception after $([Math]::Round($moduleElapsed, 2))s: $($_.Exception.Message)" -Level 'ERROR' -Module $ModuleName
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

        # v6.1: Apply bundle filter when -RemediationBundle specified
        if ($RemediationBundle) {
            $bundlePatterns = switch ($RemediationBundle) {
                'DisableLegacyProtocols' {
                    @('SMBv1','TLS\s*1\.0','TLS\s*1\.1','SSL\s*[23]\.0','LLMNR','NetBIOS','LM Hash|NoLMHash','NTLMv1|LmCompatibilityLevel','RC4','3DES')
                }
                'HardenAuthentication' {
                    @('UAC|EnableLUA','RunAsPPL|LSA Protection','Credential Guard','LmCompatibilityLevel','Anonymous|RestrictAnonymous','Cached Logons|CachedLogonsCount','Password.*Length|Password.*Complexity','Account Lockout','WDigest')
                }
                'EnableAuditLogging' {
                    @('Audit Process Creation','ScriptBlockLogging','ModuleLogging','Transcription','Audit Policy|auditpol','Event Log Size|MaxSize','Process.*Command Line')
                }
                'LockDownRDP' {
                    @('RDP|Remote Desktop|fDenyTSConnections','UserAuthentication.*NLA|NLA','MinEncryptionLevel','SecurityLayer','TermService','IdleTimeout|MaxIdleTime')
                }
                'EssentialEightLevel1' {
                    @('Application Control|AppLocker|WDAC','Patch Applications|Application.*update','Macros|Office Macros','User Application Hardening|App Hardening','Restrict Administrative Privileges|Admin','Patch Operating System|OS.*update|Windows Update','Multi.?Factor|MFA','Backup|VSS|System Restore')
                }
                default { @() }
            }

            if ($bundlePatterns.Count -gt 0) {
                $bundleFiltered = @($remediableResults | Where-Object {
                    $combined = "$($_.Category) $($_.Message)"
                    $matched = $false
                    foreach ($pattern in $bundlePatterns) {
                        if ($combined -match $pattern) { $matched = $true; break }
                    }
                    $matched
                })
                Write-Host "[*] Bundle '$RemediationBundle' selected $($bundleFiltered.Count) of $($remediableResults.Count) remediable issue(s)" -ForegroundColor Cyan
                $remediableResults = $bundleFiltered
            }
        }

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

        # v6.1: Pre-confirmation impact analysis
        if (Get-Command Get-RemediationImpact -ErrorAction SilentlyContinue) {
            $impacts = $remediableResults | ForEach-Object { Get-RemediationImpact -Remediation $_.Remediation }
            $rebootCount = @($impacts | Where-Object { $_.RequiresReboot }).Count
            $logoffCount = @($impacts | Where-Object { $_.RequiresLogoff }).Count
            $serviceCount = @($impacts | Where-Object { $_.ServiceImpact }).Count
            $networkCount = @($impacts | Where-Object { $_.NetworkImpact }).Count
            $destructiveCount = @($impacts | Where-Object { -not $_.Reversible }).Count

            Write-Host "    Impact summary:" -ForegroundColor Yellow
            if ($rebootCount -gt 0)      { Write-Host "      - $rebootCount remediation(s) will require a system restart" -ForegroundColor Red }
            if ($logoffCount -gt 0)      { Write-Host "      - $logoffCount remediation(s) will require user logoff" -ForegroundColor Yellow }
            if ($serviceCount -gt 0)     { Write-Host "      - $serviceCount remediation(s) will affect service state" -ForegroundColor Yellow }
            if ($networkCount -gt 0)     { Write-Host "      - $networkCount remediation(s) will affect network configuration" -ForegroundColor Yellow }
            if ($destructiveCount -gt 0) { Write-Host "      - $destructiveCount remediation(s) are NOT reversible" -ForegroundColor Red }
            if ($rebootCount + $logoffCount + $serviceCount + $networkCount + $destructiveCount -eq 0) {
                Write-Host "      - All remediations are reversible registry changes with no immediate disruption" -ForegroundColor Green
            }
        }

        $confirm = Read-Host "    Type 'YES' to confirm"
        if ($confirm -ne "YES") {
            Write-Host "[*] Auto-remediation cancelled" -ForegroundColor Cyan
            return
        }
    }

    # Execute remediations
    $successCount = 0; $failCount = 0; $skipCount = 0
    $skipAll = $false
    $rollbackEntries = @()  # v6.1: collect rollback commands as remediations succeed

    foreach ($item in $remediableResults) {
        if ($skipAll) { $skipCount++; continue }

        Write-Host "`n  [$($item.Module)] $($item.Category)" -ForegroundColor Cyan
        Write-Host "    Status:   $($item.Status)" -ForegroundColor $(if ($item.Status -eq 'Fail') { 'Red' } elseif ($item.Status -eq 'Warning') { 'Yellow' } else { 'Cyan' })
        if ($item.PSObject.Properties['Severity']) {
            Write-Host "    Severity: $($item.Severity)" -ForegroundColor Gray
        }
        Write-Host "    Issue:    $($item.Message)" -ForegroundColor White
        Write-Host "    Fix:      $($item.Remediation)" -ForegroundColor Gray

        # v6.1: Per-item impact display in interactive mode
        if (-not $AutoRemediate -and (Get-Command Get-RemediationImpact -ErrorAction SilentlyContinue)) {
            $itemImpact = Get-RemediationImpact -Remediation $item.Remediation
            if ($itemImpact.Category -ne 'None' -and $itemImpact.Category -ne 'Reversible') {
                Write-Host "    Impact:   $($itemImpact.Category)" -ForegroundColor Yellow
            }
        }

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
            # v6.1: Capture rollback BEFORE applying remediation (state must still be original)
            $rollbackCommand = $null
            if ($RollbackPath -and (Get-Command ConvertTo-RegistryRollback -ErrorAction SilentlyContinue)) {
                $rollbackCommand = ConvertTo-RegistryRollback -ForwardCommand $item.Remediation
                if (-not $rollbackCommand -and (Get-Command ConvertTo-ServiceRollback -ErrorAction SilentlyContinue)) {
                    $rollbackCommand = ConvertTo-ServiceRollback -ForwardCommand $item.Remediation
                }
            }

            try {
                Write-Host "    [*] Applying..." -ForegroundColor Yellow
                $remedScript = [ScriptBlock]::Create($item.Remediation)
                $null = & $remedScript
                Write-Host "    [+] Remediation applied successfully" -ForegroundColor Green
                $successCount++

                # v6.1: Record rollback only after successful application
                if ($rollbackCommand) {
                    $rollbackEntries += [PSCustomObject]@{
                        Module      = $item.Module
                        Category    = $item.Category
                        Original    = $item.Remediation
                        Rollback    = $rollbackCommand
                        Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            } catch {
                Write-Host "    [!] Remediation failed: $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
            }
        } else {
            Write-Host "    [*] Skipped" -ForegroundColor Gray
            $skipCount++
        }
    }

    # v6.1: Write rollback script if requested and any rollbacks were captured
    if ($RollbackPath -and $rollbackEntries.Count -gt 0) {
        try {
            $rollbackScriptLines = @()
            $rollbackScriptLines += "# Windows Security Audit - Remediation Rollback Script"
            $rollbackScriptLines += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $rollbackScriptLines += "# Remediations to reverse: $($rollbackEntries.Count)"
            $rollbackScriptLines += "# WARNING: Review each command before execution. Rollback restores prior state."
            $rollbackScriptLines += ""
            $rollbackScriptLines += '$ErrorActionPreference = "Continue"'
            $rollbackScriptLines += '$rollbackSuccess = 0; $rollbackFail = 0'
            $rollbackScriptLines += ""

            foreach ($entry in $rollbackEntries) {
                $rollbackScriptLines += "# [$($entry.Module)] $($entry.Category)"
                $rollbackScriptLines += "# Forward: $($entry.Original)"
                $rollbackScriptLines += "try {"
                $rollbackScriptLines += "    $($entry.Rollback)"
                $rollbackScriptLines += "    Write-Host '  [+] Rolled back: $($entry.Module) - $($entry.Category)' -ForegroundColor Green"
                $rollbackScriptLines += '    $rollbackSuccess++'
                $rollbackScriptLines += "} catch {"
                $rollbackScriptLines += "    Write-Host '  [!] Rollback failed: $($entry.Module) - $($entry.Category)' -ForegroundColor Red"
                $rollbackScriptLines += "    Write-Host ('      ' + `$_.Exception.Message) -ForegroundColor Red"
                $rollbackScriptLines += '    $rollbackFail++'
                $rollbackScriptLines += "}"
                $rollbackScriptLines += ""
            }

            $rollbackScriptLines += "Write-Host ''"
            $rollbackScriptLines += 'Write-Host "Rollback complete: $rollbackSuccess succeeded, $rollbackFail failed" -ForegroundColor Cyan'

            $rollbackScriptLines | Set-Content -Path $RollbackPath -Encoding UTF8
            Write-Host "[+] Rollback script written: $RollbackPath ($($rollbackEntries.Count) commands)" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to write rollback script: $($_.Exception.Message)" -ForegroundColor Red
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

    # Severity distribution (all results)
    $sevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    foreach ($r in $AllResults) {
        $sev = if ($r.PSObject.Properties['Severity'] -and $r.Severity -in $script:ValidSeverityValues) { $r.Severity } else { 'Medium' }
        $sevCounts[$sev]++
    }

    # Failed severity distribution
    $failSevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    foreach ($r in ($AllResults | Where-Object { $_.Status -eq 'Fail' })) {
        $sev = if ($r.PSObject.Properties['Severity'] -and $r.Severity -in $script:ValidSeverityValues) { $r.Severity } else { 'Medium' }
        $failSevCounts[$sev]++
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

    # Remediation priority list (fail/warning sorted by severity) - top 50
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
            $donutParts += "<circle cx='60' cy='60' r='45' fill='none' stroke='$($seg.Color)' stroke-width='20' stroke-dasharray='$([Math]::Round($segLen,2)) $([Math]::Round($circumference,2))' stroke-dashoffset='$([Math]::Round(-$offset,2))' style='cursor:pointer' onclick=`"dashboardFilter('status','$($seg.Label)')`"><title>$($seg.Label): $($seg.Count)</title></circle>"
            $offset += $segLen
        }
    }
    $donutSvg = $donutParts -join "`n"

    # Module compliance bars
    $moduleBarHtml = ""
    foreach ($modName in ($moduleScores.Keys | Sort-Object)) {
        $sc = $moduleScores[$modName]
        $barColor = if ($sc.Score -ge 80) { '#28a745' } elseif ($sc.Score -ge 60) { '#fd7e14' } else { '#dc3545' }
        $moduleBarHtml += "<div class='module-bar' onclick=`"scrollToModule('$modName')`" style='cursor:pointer'><span class='module-bar-label'>$modName</span><div class='module-bar-track'><div class='module-bar-fill' style='width:$($sc.Score)`%;background:$barColor'></div></div><span class='module-bar-pct'>$($sc.Score)`%</span></div>`n"
    }

    # Severity cards HTML (below summary cards)
    $sevCardHtml = ""
    foreach ($sev in @('Critical','High','Medium','Low','Informational')) {
        $sevColor = switch ($sev) { 'Critical' { '#dc3545' }; 'High' { '#fd7e14' }; 'Medium' { '#ffc107' }; 'Low' { '#17a2b8' }; 'Informational' { '#6c757d' } }
        $sevCardHtml += "<div class='summary-card' style='background:$sevColor;cursor:pointer' onclick=`"dashboardFilter('severity','$sev')`"><h3>$($sevCounts[$sev])</h3><p>$sev</p></div>`n"
    }

    # Compliance score section
    $complianceHtml = ""
    if ($ComplianceScores.Count -gt 0 -and $ComplianceScores.ContainsKey('overall')) {
        $oc = $ComplianceScores['overall']
        $ocColor = if ($oc.WeightedPct -ge 80) { '#28a745' } elseif ($oc.WeightedPct -ge 60) { '#fd7e14' } else { '#dc3545' }
        $complianceHtml = @"
<div class='compliance-cards'>
<div class='compliance-card' style='background:$ocColor;color:#fff'>
<div class='compliance-card-value'>$($oc.WeightedPct)`%</div>
<div class='compliance-card-label'>Weighted Score</div>
</div>
<div class='compliance-card' style='background:var(--bg-tertiary)'>
<div class='compliance-card-value' style='color:$ocColor'>$($oc.ThresholdResult)</div>
<div class='compliance-card-label'>Overall Rating</div>
</div>
<div class='compliance-card' style='background:var(--bg-tertiary)'>
<div class='compliance-card-value' style='color:$ocColor'>$($oc.SimplePct)`%</div>
<div class='compliance-card-label'>Simple Score</div>
</div>
<div class='compliance-card' style='background:var(--bg-tertiary)'>
<div class='compliance-card-value' style='color:$ocColor'>$($oc.SeverityWeightedPct)`%</div>
<div class='compliance-card-label'>Severity-Adjusted</div>
</div>
</div>
"@
    }

    # Table of Contents
    $tocHtml = "<div class='toc-section' id='toc'><div class='toc-header' onclick='toggleToc()'><h3><span class='collapse-icon' id='toc-icon'>&#9660;</span> Table of Contents</h3></div><div class='toc-content' id='toc-content'><ul>"
    $tocHtml += "<li><a href='#dashboard'>Executive Dashboard</a></li>"
    foreach ($modName in ($modulesData.Keys | Sort-Object)) {
        $tocHtml += "<li><a href='#module-$modName'>$modName `($($modulesData[$modName].Count) checks`)</a></li>"
    }
    $tocHtml += "<li><a href='#remediation-priority'>Remediation Priority Ranking</a></li>"
    $tocHtml += "</ul></div></div>"

    # Cross-framework summary table
    $crossFrameworkHtml = "<table class='rem-table' style='font-size:0.85em'><tr><th>Framework</th><th>Checks</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th></tr>"
    foreach ($modName in ($moduleScores.Keys | Sort-Object)) {
        $ms = $moduleScores[$modName]
        $scoreColor = if ($ms.Score -ge 80) { '#28a745' } elseif ($ms.Score -ge 60) { '#fd7e14' } else { '#dc3545' }
        $crossFrameworkHtml += "<tr><td><strong>$modName</strong></td><td>$($ms.Total)</td><td style='color:#28a745'>$($ms.Stats.Pass)</td><td style='color:#dc3545'>$($ms.Stats.Fail)</td><td style='color:#fd7e14'>$($ms.Stats.Warning)</td><td style='color:$scoreColor;font-weight:bold'>$($ms.Score)`%</td></tr>"
    }
    $crossFrameworkHtml += "</table>"

    # Remediation Priority Ranking (Top 50) - collapsible panel
    $remCount = [Math]::Min($remediationItems.Count, 50)
    $remPriorityHtml = ""
    if ($remCount -gt 0) {
        $remPriorityHtml = @"
<div class='module-section' id='remediation-priority'>
<div class='module-header' onclick='toggleRemediation()'><h2><span class='collapse-icon' id='icon-remediation'>&#9660;</span> Remediation Priority Ranking (Top 50)</h2></div>
<div class='module-content' id='content-remediation'>
<table class='rem-table'><thead><tr><th>#</th><th>Severity</th><th>Status</th><th>Module</th><th>Category</th><th>Issue</th><th>Remediation</th></tr></thead><tbody>
"@
        for ($i = 0; $i -lt $remCount; $i++) {
            $item = $remediationItems[$i]
            $sc = switch ($item.Severity) { 'Critical' { '#dc3545' }; 'High' { '#fd7e14' }; 'Medium' { '#ffc107' }; 'Low' { '#17a2b8' }; default { '#6c757d' } }
            $stClass = switch ($item.Status) { 'Fail' { 'status-fail' }; 'Warning' { 'status-warning' }; default { '' } }
            $ec = [System.Security.SecurityElement]::Escape($item.Category)
            $em = [System.Security.SecurityElement]::Escape($item.Message)
            $er = [System.Security.SecurityElement]::Escape($item.Remediation)
            $remPriorityHtml += "<tr><td>$($i+1)</td><td><span class='severity-badge' style='background:$sc'>$($item.Severity)</span></td><td class='$stClass'>$($item.Status)</td><td>$($item.Module)</td><td>$ec</td><td>$em</td><td class='rem-cell'>$er</td></tr>`n"
        }
        $remPriorityHtml += "</tbody></table></div></div>"
    }

    # Build module result tables
    $moduleTablesHtml = ""
    foreach ($modName in ($modulesData.Keys | Sort-Object)) {
        $modResults = $modulesData[$modName]
        $modScore = $moduleScores[$modName]

        # Category sub-section: expanded table per category
        $catDetailHtml = ""
        if ($categoryStats.ContainsKey($modName)) {
            $catDetailHtml = "<div class='cat-detail-section'><table class='cat-detail-table'><tr><th>Category</th><th>Total</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Info</th><th>Error</th><th>Score</th></tr>"
            foreach ($catName in ($categoryStats[$modName].Keys | Sort-Object)) {
                $cs = $categoryStats[$modName][$catName]
                $catApplicable = [Math]::Max(1, $cs.total - $cs.info)
                $catScore = [Math]::Round(($cs.pass / $catApplicable) * 100, 1)
                $csColor = if ($catScore -ge 80) { '#28a745' } elseif ($catScore -ge 60) { '#fd7e14' } else { '#dc3545' }
                $ecCat = [System.Security.SecurityElement]::Escape($catName)
                $catDetailHtml += "<tr><td>$ecCat</td><td>$($cs.total)</td><td style='color:#28a745'>$($cs.pass)</td><td style='color:#dc3545'>$($cs.fail)</td><td style='color:#fd7e14'>$($cs.warning)</td><td style='color:#17a2b8'>$($cs.info)</td><td style='color:#6f42c1'>$($cs.error)</td><td style='color:$csColor;font-weight:bold'>$catScore`%</td></tr>"
            }
            $catDetailHtml += "</table></div>"
        }

        $moduleTablesHtml += @"
<div class='module-section' id='module-$modName'>
<div class='module-header' onclick='toggleModule("$modName")'><h2><span class='collapse-icon' id='icon-$modName'>&#9660;</span> $modName <span class='module-score'>$($modScore.Score)`% `($($modScore.Stats.Total) checks`)</span></h2></div>
<div class='module-content' id='content-$modName'>
$catDetailHtml
<div class='table-controls'>
<input type='text' class='module-search' id='search-$modName' placeholder='Filter $modName...' oninput='filterModuleTable("$modName")'>
</div>
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
:root{--bg-primary:#ffffff;--bg-secondary:#f8f9fa;--bg-tertiary:#e9ecef;--bg-gradient-start:#0d1b2a;--bg-gradient-end:#1b2838;--text-primary:#333333;--text-secondary:#666666;--border-color:#dee2e6;--card-shadow:rgba(0,0,0,.08);--row-hover:#f1f3f5;--accent:#1565c0;--accent-light:#e3f2fd;--header-bg:linear-gradient(135deg,#0d1b2a,#1b2838)}
[data-theme="dark"]{--bg-primary:#0b0e14;--bg-secondary:#111822;--bg-tertiary:#1a2332;--bg-gradient-start:#060a10;--bg-gradient-end:#0d1520;--text-primary:#c9d1d9;--text-secondary:#8b949e;--border-color:#21262d;--card-shadow:rgba(0,0,0,.4);--row-hover:#161b22;--accent:#58a6ff;--accent-light:#0d1117;--header-bg:linear-gradient(135deg,#060a10,#0d1520)}
body{font-family:Garamond,'Times New Roman',serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6}
.report-header{background:var(--header-bg);color:#fff;padding:30px 40px;width:100%;position:relative;text-align:center}
.report-header h1{font-size:2em;margin-bottom:5px}
.report-header .subtitle{opacity:.85;font-size:1.1em}
.theme-toggle{position:absolute;top:20px;right:30px;display:flex;align-items:center;gap:8px;cursor:pointer;color:#fff;font-size:.9em}
.theme-slider{width:44px;height:22px;background:rgba(255,255,255,.3);border-radius:11px;position:relative;transition:background .3s}
.theme-slider::after{content:'';position:absolute;width:18px;height:18px;background:#fff;border-radius:50%;top:2px;left:2px;transition:transform .3s}
[data-theme="dark"] .theme-slider::after{transform:translateX(22px)}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;padding:20px 40px}
.info-card{background:var(--bg-secondary);border-radius:8px;padding:15px;box-shadow:0 2px 8px var(--card-shadow)}
.info-card h3{font-size:.85em;color:var(--text-secondary);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.info-card p{font-size:1.1em;font-weight:600}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;padding:0 40px 15px}
.summary-card{text-align:center;border-radius:8px;padding:15px 10px;color:#fff;cursor:pointer;transition:transform .2s,box-shadow .2s}
.summary-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.2)}
.summary-card h3{font-size:2em;margin-bottom:3px}.summary-card p{font-size:.85em;opacity:.9}
.summary-card.total{background:#495057}.summary-card.pass{background:#28a745}.summary-card.fail{background:#dc3545}
.summary-card.warning{background:#fd7e14}.summary-card.info{background:#17a2b8}.summary-card.error{background:#6f42c1}
.severity-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;padding:0 40px 20px}
.severity-grid .summary-card{padding:12px 8px}
.severity-grid .summary-card h3{font-size:1.6em}
.severity-grid .summary-card p{font-size:.8em}
.toc-section{margin:0 40px 15px;background:var(--bg-secondary);border-radius:8px;overflow:hidden;box-shadow:0 2px 8px var(--card-shadow)}
.toc-header{background:linear-gradient(135deg,var(--bg-gradient-start),var(--bg-gradient-end));color:#fff;padding:10px 20px;cursor:pointer}
.toc-header h3{font-size:1.1em;display:flex;align-items:center;gap:10px}
.toc-content{padding:15px 20px}
.toc-content ul{list-style:none;padding:0;columns:3;column-gap:20px}
.toc-content li{margin-bottom:5px}.toc-content a{color:var(--accent);text-decoration:none}.toc-content a:hover{text-decoration:underline}
.dashboard{padding:15px 40px;display:grid;grid-template-columns:1fr 2fr;gap:20px}
.dashboard-panel{background:var(--bg-secondary);border-radius:8px;padding:20px;box-shadow:0 2px 8px var(--card-shadow)}
.dashboard-panel h3{margin-bottom:15px;color:var(--accent);border-bottom:2px solid var(--accent);padding-bottom:8px}
.dashboard-full{grid-column:1/-1}
.donut-container{text-align:center}
.donut-legend{display:flex;flex-direction:column;align-items:flex-start;gap:6px;margin-top:12px;padding-left:15px}
.donut-legend span{display:flex;align-items:center;gap:5px;font-size:.9em;cursor:pointer}
.donut-legend .dot{width:12px;height:12px;border-radius:50%;display:inline-block}
.module-bar{display:flex;align-items:center;gap:10px;margin-bottom:8px;padding:4px 0}
.module-bar-label{width:130px;font-weight:600;font-size:.9em;text-align:right}
.module-bar-track{flex:1;height:20px;background:var(--bg-tertiary);border-radius:10px;overflow:hidden}
.module-bar-fill{height:100%;border-radius:10px;transition:width .5s ease;min-width:2px}
.module-bar-pct{width:50px;font-weight:600;font-size:.9em}
.severity-badge{display:inline-block;padding:3px 10px;border-radius:12px;color:#fff;font-size:.8em;font-weight:600;margin:2px}
.compliance-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;padding:10px 0}
.compliance-card{border-radius:10px;padding:20px 15px;text-align:center;box-shadow:0 2px 8px var(--card-shadow)}
.compliance-card-value{font-size:2em;font-weight:700;margin-bottom:4px}
.compliance-card-label{font-size:.85em;opacity:.85;text-transform:uppercase;letter-spacing:.5px}
.rem-table{width:100%;border-collapse:collapse;font-size:.9em}
.rem-table th{background:var(--bg-gradient-start);color:#fff;padding:8px 12px;text-align:left}
.rem-table td{padding:8px 12px;border-bottom:1px solid var(--border-color);vertical-align:top}.rem-table tr:hover{background:var(--row-hover)}
.rem-cell{max-width:300px;word-wrap:break-word;overflow-wrap:break-word;font-family:monospace;font-size:.85em}
.cat-detail-section{margin-bottom:15px}
.cat-detail-table{width:100%;border-collapse:collapse;font-size:.85em;margin-bottom:10px}
.cat-detail-table th{background:var(--bg-tertiary);color:var(--text-primary);padding:6px 10px;text-align:left;border-bottom:2px solid var(--border-color)}
.cat-detail-table td{padding:6px 10px;border-bottom:1px solid var(--border-color)}
.cat-detail-table tr:hover{background:var(--row-hover)}
.module-section{margin:15px 40px;background:var(--bg-secondary);border-radius:8px;overflow:hidden;box-shadow:0 2px 8px var(--card-shadow)}
.module-header{background:linear-gradient(135deg,var(--bg-gradient-start),var(--bg-gradient-end));color:#fff;padding:12px 20px;cursor:pointer}
.module-header h2{font-size:1.2em;display:flex;align-items:center;gap:10px}
.module-score{font-size:.75em;opacity:.8;margin-left:auto}
.collapse-icon{font-size:.8em;transition:transform .3s}
.module-content{padding:15px}.module-content.collapsed{display:none}
.table-controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
.module-search{padding:6px 12px;border:1px solid var(--border-color);border-radius:4px;font-family:inherit;background:var(--bg-primary);color:var(--text-primary);width:250px}
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
.global-export{margin-left:auto;display:flex;gap:8px}
.global-export button{padding:6px 14px;border:1px solid var(--accent);background:var(--accent);color:#fff;border-radius:4px;cursor:pointer;font-family:inherit}
.global-export button:hover{opacity:.9}
.export-modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:1000;justify-content:center;align-items:center}
.export-modal-overlay.active{display:flex}
.export-modal{background:var(--bg-secondary);border-radius:12px;padding:25px;min-width:350px;box-shadow:0 8px 32px rgba(0,0,0,.3)}
.export-modal h3{margin-bottom:15px;color:var(--accent)}
.export-modal .format-list{display:flex;flex-direction:column;gap:8px}
.export-modal .format-btn{padding:10px 15px;border:1px solid var(--border-color);background:var(--bg-primary);color:var(--text-primary);border-radius:6px;cursor:pointer;font-family:inherit;font-size:.95em;text-align:left;transition:background .2s}
.export-modal .format-btn:hover{background:var(--accent);color:#fff}
.export-modal .close-btn{margin-top:15px;padding:8px 20px;border:1px solid var(--border-color);background:transparent;color:var(--text-primary);border-radius:4px;cursor:pointer;font-family:inherit}
.report-footer{text-align:center;padding:20px 40px;color:var(--text-secondary);font-size:.85em;border-top:1px solid var(--border-color);margin-top:30px}
@media print{.theme-toggle,.global-controls,.table-controls,.col-filter,.resize-handle,.col-select,.report-footer,.export-modal-overlay{display:none!important}.module-content{display:block!important}.module-section{break-inside:avoid;margin:10px 0;box-shadow:none}body{font-size:10pt}.results-table th{background:#333!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@media(max-width:768px){.dashboard{grid-template-columns:1fr}.info-grid{grid-template-columns:1fr 1fr}.toc-content ul{columns:1}.report-header,.info-grid,.summary-grid,.severity-grid,.dashboard,.module-section,.global-controls,.toc-section{padding-left:15px;padding-right:15px}}
</style>
</head>
<body>
<div class='report-header'>
<div class='theme-toggle' onclick='toggleTheme()'><span>&#9728;</span><div class='theme-slider'></div><span>&#9790;</span></div>
<h1>Windows Security Audit Report</h1>
<div class='subtitle'>Comprehensive Multi-Framework Security Assessment</div>

</div>

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

<div class='severity-grid'>
$sevCardHtml
</div>

$tocHtml

<div class='dashboard' id='dashboard'>
<div class='dashboard-panel'><h3>Status Distribution</h3><div class='donut-container'>
<svg viewBox='0 0 120 120' width='180' height='180'>$donutSvg</svg>
<div class='donut-legend'>
<span onclick="dashboardFilter('status','Pass')"><span class='dot' style='background:#28a745'></span>Pass `($($ExecutionInfo.PassCount)`)</span>
<span onclick="dashboardFilter('status','Fail')"><span class='dot' style='background:#dc3545'></span>Fail `($($ExecutionInfo.FailCount)`)</span>
<span onclick="dashboardFilter('status','Warning')"><span class='dot' style='background:#fd7e14'></span>Warning `($($ExecutionInfo.WarningCount)`)</span>
<span onclick="dashboardFilter('status','Info')"><span class='dot' style='background:#17a2b8'></span>Info `($($ExecutionInfo.InfoCount)`)</span>
<span onclick="dashboardFilter('status','Error')"><span class='dot' style='background:#6f42c1'></span>Error `($($ExecutionInfo.ErrorCount)`)</span>
</div></div></div>
<div class='dashboard-panel'><h3>Module Compliance</h3>$moduleBarHtml</div>
<div class='dashboard-panel dashboard-full'><h3>Cross-Framework Compliance Matrix</h3>$crossFrameworkHtml</div>
<div class='dashboard-panel dashboard-full'><h3>Overall Compliance</h3>$complianceHtml</div>
</div>

<div class='global-controls'>
<input type='text' class='global-search' id='globalSearch' placeholder='Search all results...' oninput='globalFilter()'>
<select class='filter-mode' id='filterMode' onchange='globalFilter()'><option value='include'>Include matches</option><option value='exclude'>Exclude matches</option></select>
<div class='global-export'>
<button onclick='showExportModal("all")'>Export All</button>
<button onclick='showExportModal("selected")'>Export Selected</button>
</div></div>

$moduleTablesHtml

$remPriorityHtml

<div class='report-footer'>Generated by Windows Security Audit Script | $($ExecutionInfo.ScanDate) | <a href='https://github.com/Sandler73/Windows-Security-Audit-Project'>GitHub</a></div>

<div class='export-modal-overlay' id='exportModal'>
<div class='export-modal'>
<h3 id='exportModalTitle'>Export Format</h3>
<div class='format-list'>
<button class='format-btn' onclick='doExport("csv")'>CSV Workbook</button>
<button class='format-btn' onclick='doExport("xls")'>Excel (XLS)</button>
<button class='format-btn' onclick='doExport("json")'>JSON (Structured Data)</button>
<button class='format-btn' onclick='doExport("xml")'>XML Workbook</button>
<button class='format-btn' onclick='doExport("siem")'>XML (SIEM-Compatible)</button>
<button class='format-btn' onclick='doExport("txt")'>TXT (Plain Text)</button>
</div>
<button class='close-btn' onclick='closeExportModal()'>Cancel</button>
</div></div>

<script>
var exportMode='all';
function toggleTheme(){var b=document.documentElement;b.setAttribute('data-theme',b.getAttribute('data-theme')==='dark'?'light':'dark')}
function toggleModule(m){var c=document.getElementById('content-'+m),i=document.getElementById('icon-'+m);if(c.classList.contains('collapsed')){c.classList.remove('collapsed');i.innerHTML='&#9660;'}else{c.classList.add('collapsed');i.innerHTML='&#9654;'}}
function toggleRemediation(){toggleModule('remediation')}
function toggleToc(){var c=document.getElementById('toc-content'),i=document.getElementById('toc-icon');if(c.style.display==='none'){c.style.display='';i.innerHTML='&#9660;'}else{c.style.display='none';i.innerHTML='&#9654;'}}
function scrollToModule(m){var e=document.getElementById('module-'+m);if(e){e.scrollIntoView({behavior:'smooth',block:'start'});var c=document.getElementById('content-'+m);if(c&&c.classList.contains('collapsed'))toggleModule(m)}}
function dashboardFilter(t,v){document.querySelectorAll('.results-table tbody tr').forEach(function(r){if(t==='all'){r.style.display='';return}r.style.display=r.getAttribute('data-'+t)===v?'':'none'});document.getElementById('globalSearch').value=''}
function globalFilter(){var q=document.getElementById('globalSearch').value.toLowerCase(),m=document.getElementById('filterMode').value;document.querySelectorAll('.results-table tbody tr').forEach(function(r){if(!q){r.style.display='';return}var t=r.textContent.toLowerCase(),h=t.includes(q);r.style.display=(m==='include'?h:!h)?'':'none'})}
function filterModuleTable(mod){var q=document.getElementById('search-'+mod).value.toLowerCase();document.getElementById('table-'+mod).querySelectorAll('tbody tr').forEach(function(r){if(!q){r.style.display='';return}r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}
function filterColumn(mod,col,v){var q=v.toLowerCase();document.getElementById('table-'+mod).querySelectorAll('tbody tr').forEach(function(r){if(!q){r.style.display='';return}var c=r.querySelector('td[data-col="'+col+'"]');if(c)r.style.display=c.textContent.toLowerCase().includes(q)?'':'none'})}
function toggleAllRows(mod,chk){document.getElementById('table-'+mod).querySelectorAll('tbody .row-select').forEach(function(cb){cb.checked=chk})}
function getTableData(mod,selOnly){var t=document.getElementById('table-'+mod),d=[];if(!t)return d;t.querySelectorAll('tbody tr').forEach(function(r){if(r.style.display==='none')return;if(selOnly&&!r.querySelector('.row-select').checked)return;var c=r.querySelectorAll('td');d.push({module:r.getAttribute('data-module'),category:c[1]?c[1].textContent:'',status:c[2]?c[2].textContent:'',severity:c[3]?c[3].textContent:'',message:c[4]?c[4].textContent:'',details:c[5]?c[5].textContent:'',remediation:c[6]?c[6].textContent:''})});return d}
function getAllData(selOnly){var a=[];document.querySelectorAll('.results-table').forEach(function(t){var mod=t.id.replace('table-','');a=a.concat(getTableData(mod,selOnly))});return a}
function dl(c,f,m){var b=new Blob([c],{type:m}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download=f;a.click();URL.revokeObjectURL(u)}
function esc(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s||''));return d.innerHTML}
function showExportModal(mode){exportMode=mode;document.getElementById('exportModalTitle').textContent=mode==='all'?'Export All - Select Format':'Export Selected - Select Format';document.getElementById('exportModal').classList.add('active')}
function closeExportModal(){document.getElementById('exportModal').classList.remove('active')}
function doExport(fmt){closeExportModal();var d=getAllData(exportMode==='selected');if(exportMode==='selected'&&!d.length){alert('No rows selected. Use checkboxes to select rows first.');return}var fn='Windows-Audit-'+(exportMode==='all'?'All':'Selected')+'-'+new Date().toISOString().slice(0,10);if(fmt==='csv')exportToCSV(d,fn+'.csv');else if(fmt==='xls')exportToXLS(d,fn+'.xls');else if(fmt==='json')exportToJSON(d,fn+'.json');else if(fmt==='xml')exportToXML(d,fn+'.xml');else if(fmt==='siem')exportToSIEM(d,fn+'-siem.xml');else if(fmt==='txt')exportToTXT(d,fn+'.txt')}
function exportToCSV(d,f){var h='Module,Category,Status,Severity,Message,Details,Remediation';var r=d.map(function(x){return[x.module,x.category,x.status,x.severity,x.message,x.details,x.remediation].map(function(v){return'"'+(v||'').replace(/"/g,'""')+'"'}).join(',')});dl(h+'\n'+r.join('\n'),f,'text/csv')}
function exportToJSON(d,f){dl(JSON.stringify({export_date:new Date().toISOString(),host:'$($ExecutionInfo.ComputerName)',total_results:d.length,results:d},null,2),f,'application/json')}
function exportToXML(d,f){var x='<?xml version="1.0" encoding="UTF-8"?>\n';x+='<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:windows-security-audit" exclude-result-prefixes="a">\n';x+='<a:export><a:metadata><a:export_date>'+esc(new Date().toISOString())+'</a:export_date><a:host>'+esc('$($ExecutionInfo.ComputerName)')+'</a:host><a:total>'+d.length+'</a:total></a:metadata>\n<a:results>\n';d.forEach(function(r){x+='<a:r><a:module>'+esc(r.module)+'</a:module><a:category>'+esc(r.category)+'</a:category><a:status>'+esc(r.status)+'</a:status><a:severity>'+esc(r.severity)+'</a:severity><a:message>'+esc(r.message)+'</a:message><a:details>'+esc(r.details)+'</a:details><a:remediation>'+esc(r.remediation)+'</a:remediation></a:r>\n'});x+='</a:results></a:export>\n';var css='*{margin:0;padding:0;box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;color:#1a2332}.hd{background:linear-gradient(135deg,#1a2332,#2d3e50);color:#fff;padding:28px 35px}.hd h1{font-size:1.5em;margin-bottom:4px}.hd p{font-size:.92em;color:#a0aec0}.mt{display:flex;gap:30px;padding:14px 35px;background:#fff;border-bottom:1px solid #e2e8f0;font-size:.9em}.mt b{color:#1a2332}.ss{display:flex;gap:10px;padding:18px 35px;flex-wrap:wrap}.sb{padding:8px 16px;border-radius:6px;font-weight:600;font-size:.9em}.sb-t{background:#e2e8f0;color:#1a2332}.sb-p{background:#c6f6d5;color:#22543d}.sb-f{background:#fed7d7;color:#822727}.sb-w{background:#fefcbf;color:#744210}.sb-i{background:#bee3f8;color:#2a4365}.bd{padding:0 35px 30px}table{width:100%;border-collapse:separate;border-spacing:0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}th{background:#1a2332;color:#fff;padding:11px 13px;text-align:left;font-size:.82em;font-weight:600;text-transform:uppercase;letter-spacing:.4px}td{padding:9px 13px;border-bottom:1px solid #edf2f7;font-size:.87em;vertical-align:top;max-width:320px;word-wrap:break-word}tr:nth-child(even) td{background:#f8fafc}tr:hover td{background:#edf2f7}.p{color:#22543d;font-weight:700}.f{color:#c53030;font-weight:700}.w{color:#b7791f;font-weight:700}.i{color:#2b6cb0;font-weight:600}.e{color:#6b21a8;font-weight:600}.sv{padding:2px 8px;border-radius:3px;font-size:.78em;font-weight:600;color:#fff;white-space:nowrap}.sv-c{background:#c53030}.sv-h{background:#dd6b20}.sv-m{background:#d69e2e}.sv-l{background:#38a169}.sv-i{background:#4299e1}.ft{text-align:center;color:#718096;font-size:.8em;padding:18px 35px;border-top:1px solid #e2e8f0}';x+='<xsl:template match="/"><html><head><title>Windows Security Audit - XML Workbook</title><style>'+css+'</style></head><body>\n';x+='<div class="hd"><h1>Windows Security Audit Report</h1><p>XML Workbook Export &#8212; Comprehensive Multi-Framework Assessment</p></div>\n';x+='<div class="mt"><div><b>Host: </b><xsl:value-of select="//a:host"/></div><div><b>Date: </b><xsl:value-of select="substring(//a:export_date,1,10)"/></div><div><b>Findings: </b><xsl:value-of select="//a:total"/></div></div>\n';var q=String.fromCharCode(39);x+='<div class="ss"><span class="sb sb-t">Total: <xsl:value-of select="count(//a:r)"/></span><span class="sb sb-p">Pass: <xsl:value-of select="count(//a:r[a:status='+q+'Pass'+q+'])"/></span><span class="sb sb-f">Fail: <xsl:value-of select="count(//a:r[a:status='+q+'Fail'+q+'])"/></span><span class="sb sb-w">Warning: <xsl:value-of select="count(//a:r[a:status='+q+'Warning'+q+'])"/></span><span class="sb sb-i">Info: <xsl:value-of select="count(//a:r[a:status='+q+'Info'+q+'])"/></span></div>\n';x+='<div class="bd"><table><tr><th>#</th><th>Module</th><th>Category</th><th>Status</th><th>Severity</th><th>Message</th><th>Details</th><th>Remediation</th></tr>\n';x+='<xsl:for-each select="//a:r"><tr><td><xsl:value-of select="position()"/></td><td><xsl:value-of select="a:module"/></td><td><xsl:value-of select="a:category"/></td>';x+='<td><xsl:attribute name="class"><xsl:choose><xsl:when test="a:status='+q+'Pass'+q+'">p</xsl:when><xsl:when test="a:status='+q+'Fail'+q+'">f</xsl:when><xsl:when test="a:status='+q+'Warning'+q+'">w</xsl:when><xsl:when test="a:status='+q+'Info'+q+'">i</xsl:when><xsl:otherwise>e</xsl:otherwise></xsl:choose></xsl:attribute><xsl:value-of select="a:status"/></td>';x+='<td><span><xsl:attribute name="class"><xsl:choose><xsl:when test="a:severity='+q+'Critical'+q+'">sv sv-c</xsl:when><xsl:when test="a:severity='+q+'High'+q+'">sv sv-h</xsl:when><xsl:when test="a:severity='+q+'Medium'+q+'">sv sv-m</xsl:when><xsl:when test="a:severity='+q+'Low'+q+'">sv sv-l</xsl:when><xsl:otherwise>sv sv-i</xsl:otherwise></xsl:choose></xsl:attribute><xsl:value-of select="a:severity"/></span></td>';x+='<td><xsl:value-of select="a:message"/></td><td><xsl:value-of select="a:details"/></td><td><xsl:value-of select="a:remediation"/></td></tr>\n</xsl:for-each></table></div>\n';x+='<div class="ft">Windows Security Audit &#8212; XML Workbook Export</div></body></html></xsl:template>\n</xsl:stylesheet>';dl(x,f,'application/xml')}
function exportToSIEM(d,f){var x='<?xml version="1.0" encoding="UTF-8"?>\n<SIEM_Events source="WindowsSecurityAudit" host="$($ExecutionInfo.ComputerName)" generated="'+new Date().toISOString()+'">\n';d.forEach(function(r,i){x+='<Event id="'+(i+1)+'" timestamp="'+new Date().toISOString()+'" severity="'+esc(r.severity)+'" status="'+esc(r.status)+'"><Source>'+esc(r.module)+'</Source><Category>'+esc(r.category)+'</Category><Message>'+esc(r.message)+'</Message><Details>'+esc(r.details)+'</Details><Remediation>'+esc(r.remediation)+'</Remediation></Event>\n'});x+='</SIEM_Events>';dl(x,f,'application/xml')}
function exportToXLS(d,f){var t='<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel"><head><meta charset="UTF-8"><!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>Audit Results</x:Name></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]--></head><body><table border="1"><tr><th>Module</th><th>Category</th><th>Status</th><th>Severity</th><th>Message</th><th>Details</th><th>Remediation</th></tr>';d.forEach(function(r){t+='<tr><td>'+esc(r.module)+'</td><td>'+esc(r.category)+'</td><td>'+esc(r.status)+'</td><td>'+esc(r.severity)+'</td><td>'+esc(r.message)+'</td><td>'+esc(r.details)+'</td><td>'+esc(r.remediation)+'</td></tr>'});t+='</table></body></html>';dl(t,f,'application/vnd.ms-excel')}
function exportToTXT(d,f){var t='Windows Security Audit Report - $($ExecutionInfo.ComputerName)\nGenerated: '+new Date().toISOString()+'\nTotal Results: '+d.length+'\n'+('=').repeat(80)+'\n\n';d.forEach(function(r,i){t+='['+(i+1)+'] ['+r.severity+'] ['+r.status+'] '+r.module+'\n    Category: '+r.category+'\n    Message: '+r.message+'\n';if(r.details)t+='    Details: '+r.details+'\n';if(r.remediation)t+='    Remediation: '+r.remediation+'\n';t+='\n'});dl(t,f,'text/plain')}
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

    # JSON Export (always generated as companion to HTML report)
    $jsonPath = Join-Path $outputDir "$baseName.json"
    if (Export-JSONResults -Results $Results -Path $jsonPath -ExecutionInfo $ExecutionInfo -ComplianceScores $ComplianceScores) {
        $exportedFiles += $jsonPath
    }

    # XML Export
    if ($OutputFormat -eq 'xml' -or $OutputFormat -eq 'all') {
        $xmlPath = Join-Path $outputDir "$baseName.xml"
        if (Export-XMLResults -Results $Results -Path $xmlPath -ExecutionInfo $ExecutionInfo -ComplianceScores $ComplianceScores) {
            $exportedFiles += $xmlPath
        }
    }

    Write-Host "`n  Total files exported: $($exportedFiles.Count)" -ForegroundColor Cyan

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

    # ---- v6.1 Help Detection (must run before any initialization) ----
    # Covers all invocation forms: -Help, -H, -?, -ShowHelp (bound aliases) plus
    # 'help', '-help', '--help', '--h' (caught via $RemainingArgs catch-all).
    # PowerShell's built-in -? is intercepted by the engine itself when our param
    # block has no matching parameter; we still catch it through the alias.
    $helpRequested = $ShowHelp
    if (-not $helpRequested -and $RemainingArgs) {
        foreach ($arg in $RemainingArgs) {
            if ($arg -match '^(?:--?h(?:elp)?|help|/\?|/h(?:elp)?)$') {
                $helpRequested = $true
                break
            }
        }
    }
    if ($helpRequested) {
        Show-DetailedHelp
        return
    }

    # ---- Initialization ----
    $auditStartTime = Get-Date
    $script:StatisticsLog = @{ ModuleStats = @{}; ModuleTimings = @{}; TotalStartTime = $auditStartTime }

    # Initialize logging (uses shared library if available, built-in fallback otherwise)
    # v6.1.2: Pass -ScriptRoot so the shared lib auto-creates logs/ next to the
    # script when -LogFile is omitted; pass -Quiet to suppress console emission
    # when the user requested -Quiet mode.
    $logParams = @{
        LogLevel = $LogLevel
    }
    if ($LogFile)        { $logParams['LogFile']    = $LogFile }
    if ($JsonLog)        { $logParams['JsonFormat'] = $true }
    if ($Quiet)          { $logParams['Quiet']      = $true }
    if ($script:ScriptPath) { $logParams['ScriptRoot'] = $script:ScriptPath }
    try {
        Initialize-AuditLogging @logParams
        # After Initialize-AuditLogging, the shared library has either honored
        # the supplied -LogFile or auto-generated one. Mirror it onto the
        # orchestrator-scoped variable so downstream code can reference it.
        if ($script:HAS_COMMON_LIB) {
            $resolvedLogPath = (Get-Variable -Name 'LogFilePath' -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
            if ($resolvedLogPath) { $script:ActiveLogFile = $resolvedLogPath }
        }
        Write-AuditLog -Message "Windows Security Audit v$($script:ScriptVersion) starting" -Level 'INFO'
        Write-AuditLog -Message "Log level: $LogLevel | Log file: $($script:ActiveLogFile) | JSON: $([bool]$JsonLog) | Quiet: $([bool]$Quiet)" -Level 'DEBUG'
        Write-AuditLog -Message "Invocation: PSVersion=$($PSVersionTable.PSVersion) | OS=$([System.Environment]::OSVersion.VersionString) | User=$env:USERNAME | Admin=$(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -Level 'DEBUG'
        Write-AuditLog -Message "Parameters: Modules=$($Modules -join ',') | Parallel=$([bool]$Parallel) | Workers=$Workers | NoCache=$([bool]$NoCache) | OutputFormat=$OutputFormat" -Level 'DEBUG'
    } catch {
        Write-Host "[!] Warning: Could not initialize logging: $_" -ForegroundColor Yellow
    }

    # Show banner
    Show-Banner

    # ---- Prerequisites ----
    Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Cyan
    Write-AuditLog -Message "Checking prerequisites" -Level 'DEBUG'
    $prereqResult = Test-Prerequisites
    if (-not $prereqResult.Success) {
        Write-Host "[!] FATAL: Prerequisites not met. Aborting." -ForegroundColor Red
        Write-AuditLog -Message "FATAL: Prerequisites failed - aborting" -Level 'CRITICAL'
        foreach ($msg in $prereqResult.Messages) {
            Write-Host "    - $msg" -ForegroundColor Red
            Write-AuditLog -Message "Prereq failure: $msg" -Level 'ERROR'
        }
        return
    }
    foreach ($msg in $prereqResult.Messages) {
        Write-Host "  [+] $msg" -ForegroundColor Green
        Write-AuditLog -Message "Prereq OK: $msg" -Level 'DEBUG'
    }

    # ---- Module Discovery ----
    Write-Host "`n[*] Discovering available modules..." -ForegroundColor Cyan
    Write-AuditLog -Message "Module discovery starting" -Level 'DEBUG'
    $availableModules = Get-AvailableModules
    Write-AuditLog -Message "Discovered $($availableModules.Count) modules: $($availableModules.Keys -join ', ')" -Level 'DEBUG'

    if ($availableModules.Count -eq 0) {
        Write-Host "[!] FATAL: No modules found in modules/ directory. Aborting." -ForegroundColor Red
        Write-AuditLog -Message "FATAL: No modules found - aborting" -Level 'CRITICAL'
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
                Write-AuditLog -Message "Selected module (exact match): $normalizedName" -Level 'DEBUG'
            } else {
                # Try case-insensitive match
                $matched = $availableModules.Keys | Where-Object { $_ -ieq $normalizedName } | Select-Object -First 1
                if ($matched) {
                    $modulesToRun += $matched
                    Write-AuditLog -Message "Selected module (case-insensitive): $requestedMod -> $matched" -Level 'DEBUG'
                } else {
                    Write-Host "[!] WARNING: Requested module '$requestedMod' not found. Skipping." -ForegroundColor Yellow
                    Write-AuditLog -Message "Requested module not found: $requestedMod" -Level 'WARNING'
                }
            }
        }
    } else {
        # "All" or no modules specified -- run all available modules
        $modulesToRun = @($availableModules.Keys | Sort-Object)
        Write-AuditLog -Message "Selected all available modules ($($modulesToRun.Count))" -Level 'DEBUG'
    }

    if ($modulesToRun.Count -eq 0) {
        Write-Host "[!] FATAL: No valid modules selected. Aborting." -ForegroundColor Red
        Write-AuditLog -Message "FATAL: No valid modules to run after selection - aborting" -Level 'CRITICAL'
        Show-AvailableModules
        return
    }

    Write-Host "[+] Modules to execute: $($modulesToRun -join ', ')" -ForegroundColor Green
    Write-AuditLog -Message "Final module list: $($modulesToRun -join ', ')" -Level 'INFO'

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
            Write-Host "    Services: $($cacheSummary.ServicesCached) | Registry keys: $($cacheSummary.RegistryCached) | Local users: $($cacheSummary.LocalUsersCached) | Hotfixes: $($cacheSummary.HotFixesCached)" -ForegroundColor Gray

            if ($script:HAS_COMMON_LIB) {
                Write-AuditLog -Message "Cache initialized: $($cacheSummary.ServicesCached) services, $($cacheSummary.RegistryCached) registry keys, $($cacheSummary.HotFixesCached) hotfixes" -Level 'INFO'
            }
        } catch {
            Write-Host "[!] WARNING: Cache initialization failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    Continuing without cache (modules will query system directly)" -ForegroundColor Yellow
        }
    } else {
        # No shared library or cache disabled -- basic system info
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
        Write-Host "`n[*] Executing $($modulesToRun.Count) modules in PARALLEL `($workerCount workers`)..." -ForegroundColor Cyan
        Write-AuditLog -Message "Parallel execution: $($modulesToRun.Count) modules across $workerCount workers" -Level 'INFO'

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
                        try { . $CommonLibPath } catch { <# Expected: item may not exist #> }
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

                Write-Host "  [`>] Queued: $modName" -ForegroundColor Gray
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
                            Write-Host "  [+] $($job.ModuleName): $($moduleStats.Total) checks `($($moduleStats.Pass) pass, $($moduleStats.Fail) fail`) [$([Math]::Round($jobElapsed,1))s]" -ForegroundColor Green
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
        Write-AuditLog -Message "Sequential execution: $($modulesToRun.Count) modules" -Level 'INFO'

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
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor White
    Write-Host "  |  TOTAL: $($overallStats.Total)   |  PASS: $($overallStats.Pass)   |  FAIL: $($overallStats.Fail)   |  WARN: $($overallStats.Warning)   |  INFO: $($overallStats.Info)   |  ERR: $($overallStats.Error)  |" -ForegroundColor White
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor White

    # Display compliance scores
    $oc = $complianceScores['overall']
    $ocColor = if ($oc.WeightedPct -ge 80) { 'Green' } elseif ($oc.WeightedPct -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host ""
    Write-Host "  Overall Compliance Score:" -ForegroundColor White
    Write-Host "    Simple:            $($oc.SimplePct)`%" -ForegroundColor $ocColor
    Write-Host "    Weighted:          $($oc.WeightedPct)`% [$($oc.ThresholdResult)]" -ForegroundColor $ocColor
    Write-Host "    Severity-Adjusted: $($oc.SeverityWeightedPct)`%" -ForegroundColor $ocColor
    Write-Host ""

    # Per-module breakdown
    Write-Host "  Per-Module Compliance:" -ForegroundColor White
    foreach ($modName in ($moduleGroups.Keys | Sort-Object)) {
        $mc = $complianceScores[$modName]
        $mcColor = if ($mc.WeightedPct -ge 80) { 'Green' } elseif ($mc.WeightedPct -ge 60) { 'Yellow' } else { 'Red' }
        $ms = $script:StatisticsLog.ModuleStats[$modName]
        $bar = "[" + ("#" * [Math]::Floor($mc.WeightedPct / 5)) + ("." * (20 - [Math]::Floor($mc.WeightedPct / 5))) + "]"
        Write-Host "    $($modName.PadRight(20)) $bar $($mc.WeightedPct)`%  `($($ms.Total) checks, $($ms.Pass) pass, $($ms.Fail) fail`)" -ForegroundColor $mcColor
    }

    # ---- Performance Profile ----
    if ($ShowProfile) {
        Write-Host "`n  --------------------------------------------------" -ForegroundColor Gray
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
            Write-Host "    Execution Mode:        Parallel `($Workers workers`)" -ForegroundColor Gray
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

    # ---- v6.1: Risk Priority enrichment (additive - decorates existing results) ----
    if ($ShowRiskPriority) {
        $exposureCtx = @{
            IsDomainController   = if (Get-Command Test-DomainControllerHost -ErrorAction SilentlyContinue) { Test-DomainControllerHost } else { $false }
            IsInternetFacing     = if (Get-Command Test-InternetFacingHost -ErrorAction SilentlyContinue) { Test-InternetFacingHost } else { $false }
            HasListeningServices = $true
        }
        foreach ($r in $allResults) {
            if (-not $r.PSObject.Properties['RiskPriority']) {
                $score = if (Get-Command Get-RiskPriorityScore -ErrorAction SilentlyContinue) {
                    Get-RiskPriorityScore -Result $r -ExposureContext $exposureCtx
                } else { 0 }
                Add-Member -InputObject $r -MemberType NoteProperty -Name 'RiskPriority' -Value $score -Force
            }
        }
        Write-Host "[*] Risk Priority scores computed for $($allResults.Count) findings" -ForegroundColor Cyan
    }

    # ---- v6.1: Cross-Framework Correlations ----
    $script:CrossFrameworkCorrelations = @()
    if ($ShowCorrelations -and (Get-Command Find-CrossFrameworkCorrelations -ErrorAction SilentlyContinue)) {
        $script:CrossFrameworkCorrelations = Find-CrossFrameworkCorrelations -Results $allResults
        Write-Host "[*] Identified $($script:CrossFrameworkCorrelations.Count) cross-framework correlation groups" -ForegroundColor Cyan
    }

    # ---- v6.1: Compensating Controls ----
    $script:CompensatingControls = @()
    if ($ShowCompensatingControls -and (Get-Command Find-CompensatingControls -ErrorAction SilentlyContinue)) {
        $script:CompensatingControls = Find-CompensatingControls -Results $allResults
        Write-Host "[*] Identified $($script:CompensatingControls.Count) compensating-control mitigations" -ForegroundColor Cyan
    }

    # ---- v6.1: Baseline Drift Comparison ----
    $script:BaselineComparison = $null
    if ($Baseline -and (Get-Command Compare-ToBaseline -ErrorAction SilentlyContinue)) {
        try {
            $script:BaselineComparison = Compare-ToBaseline -CurrentResults $allResults -BaselinePath $Baseline
            Write-Host "[*] Baseline drift: $($script:BaselineComparison.NewFailures.Count) new, $($script:BaselineComparison.Resolved.Count) resolved, $($script:BaselineComparison.Regressions.Count) regressions" -ForegroundColor Cyan
        }
        catch {
            Write-Host "[!] Baseline comparison failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ---- Remediation ----
    if ($RemediateIssues -or $RemediateIssues_Fail -or $RemediateIssues_Warning -or $RemediateIssues_Info -or $RemediationFile -or $RemediationBundle) {
        Invoke-Remediation -Results $allResults
    }

    # ---- v6.1: Group Policy Export ----
    if ($ExportGPO -and (Get-Command Export-RegistryPolicyFile -ErrorAction SilentlyContinue)) {
        $remediationStrings = @($allResults | Where-Object {
            $_.Status -in @('Fail','Warning') -and -not [string]::IsNullOrWhiteSpace($_.Remediation)
        } | Select-Object -ExpandProperty Remediation)

        if ($remediationStrings.Count -gt 0) {
            try {
                $gpoResult = Export-RegistryPolicyFile -Remediations $remediationStrings -OutputPath $ExportGPO
                Write-Host "[+] Group Policy file written: $($gpoResult.OutputPath) ($($gpoResult.WrittenCount) entries, $($gpoResult.SkippedCount) skipped)" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] GPO export failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "[*] No registry-modifying remediations to export to GPO" -ForegroundColor Yellow
        }
    }

    # ---- Export Results ----
    Write-AuditLog -Message "Export starting: format=$OutputFormat, results=$($allResults.Count)" -Level 'DEBUG'
    $exportStartTime = Get-Date
    $exportedFiles = Export-Results -Results $allResults -ExecutionInfo $executionInfo -ComplianceScores $complianceScores
    $exportElapsed = ((Get-Date) - $exportStartTime).TotalSeconds
    Write-AuditLog -Message "Export complete in $([Math]::Round($exportElapsed, 2))s: $($exportedFiles.Count) files written" -Level 'DEBUG'
    foreach ($ef in $exportedFiles) {
        Write-AuditLog -Message "Exported: $ef" -Level 'DEBUG'
    }

    # ---- Final Logging ----
    if ($script:HAS_COMMON_LIB) {
        try {
            Write-AuditLog -Message "Audit complete: $($overallStats.Total) checks, $($overallStats.Pass) pass, $($overallStats.Fail) fail, compliance=$($oc.WeightedPct)`%" -Level 'INFO'
            Write-AuditLog -Message "Duration: $([Math]::Round($totalElapsed, 2))s, Files exported: $($exportedFiles.Count)" -Level 'INFO'
            # v6.1.2: Per-module timing summary at DEBUG for performance analysis
            if ($script:StatisticsLog.ModuleTimings -and $script:StatisticsLog.ModuleTimings.Count -gt 0) {
                $timingPairs = @()
                foreach ($mod in ($script:StatisticsLog.ModuleTimings.Keys | Sort-Object)) {
                    $t = [Math]::Round($script:StatisticsLog.ModuleTimings[$mod], 2)
                    $timingPairs += "${mod}:${t}s"
                }
                Write-AuditLog -Message "Module timings: $($timingPairs -join ' | ')" -Level 'DEBUG'
            }
        } catch { <# Expected: item may not exist #> }
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
        try { Write-AuditLog -Message "FATAL: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" -Level 'CRITICAL' } catch { <# Expected: item may not exist #> }
    }

    exit 1
}
