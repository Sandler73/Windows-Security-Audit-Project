# Usage Guide

**Windows Security Audit Project — Comprehensive Usage Guide**
**Version:** 6.1.2

This guide walks you through every aspect of running the Windows Security Audit Script — from your first audit to advanced workflows like baseline drift comparison, Group Policy export, and scripted remediation. Every parameter, every workflow, every output format is covered with worked examples.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Your First Audit](#your-first-audit)
4. [Understanding the Output](#understanding-the-output)
5. [Selecting Modules](#selecting-modules)
6. [Output Formats](#output-formats)
7. [Logging](#logging)
8. [Performance and Caching](#performance-and-caching)
9. [Remediation Workflows](#remediation-workflows)
10. [Baseline Drift Comparison](#baseline-drift-comparison)
11. [Group Policy Export](#group-policy-export)
12. [Cross-Cutting v6.1 Capabilities](#cross-cutting-v61-capabilities)
13. [Standalone Module Execution](#standalone-module-execution)
14. [Advanced Workflows](#advanced-workflows)
15. [SIEM and Automation Integration](#siem-and-automation-integration)
16. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Operating System** | Windows 10 21H2 / Server 2016 | Windows 11 24H2 / Server 2025 |
| **PowerShell** | 5.1 | 7.x |
| **Privileges** | Standard user (limited results) | Administrator (full results) |
| **Memory** | 512 MB free | 1 GB+ free |
| **Disk Space** | 100 MB free for reports | 500 MB+ for baselines |
| **CPU** | Any x64 processor | 4+ cores for `-Parallel` |

### Verify Your Environment

Before installation, verify your PowerShell and Windows versions:

```powershell
# PowerShell version
$PSVersionTable.PSVersion

# Windows version
[System.Environment]::OSVersion.Version
(Get-CimInstance Win32_OperatingSystem).Caption

# Check execution policy
Get-ExecutionPolicy

# Verify administrator privileges (for full audit results)
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

If `IsInRole` returns `False`, restart your PowerShell session as Administrator. If `Get-ExecutionPolicy` returns `Restricted`, see the next section.

### Set Execution Policy

The script is unsigned. Choose the appropriate execution policy for your environment:

```powershell
# RECOMMENDED for most users (allow local scripts, require signing for downloaded scripts)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Alternative: bypass for current process only (most secure for one-time runs)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Per-invocation alternative (no policy change required)
powershell.exe -ExecutionPolicy Bypass -File .\Windows-Security-Audit.ps1
```

---

## Installation

### Option 1: Clone from Git

```powershell
git clone https://github.com/Sandler73/Windows-Security-Audit-Project.git
cd Windows-Security-Audit-Project\Windows-Security-Audit
```

### Option 2: Download Release Archive

1. Download `Windows-Security-Audit-v6.1.2.zip` from the Releases page
2. Verify checksum (SHA-256 published with each release):
   ```powershell
   Get-FileHash .\Windows-Security-Audit-v6.1.2.zip -Algorithm SHA256
   ```
3. Extract to your preferred location:
   ```powershell
   Expand-Archive -Path .\Windows-Security-Audit-v6.1.2.zip -DestinationPath .\
   cd .\Windows-Security-Audit
   ```

### Verify Installation

```powershell
# Should display the comprehensive help screen
.\Windows-Security-Audit.ps1 -Help

# Should list all 16 available modules
.\Windows-Security-Audit.ps1 -ListModules
```

---

## Your First Audit

The simplest invocation runs all 16 modules and generates an HTML report:

```powershell
.\Windows-Security-Audit.ps1
```

This is equivalent to:

```powershell
.\Windows-Security-Audit.ps1 -Modules All -OutputFormat HTML
```

When the audit completes, you'll find the following files in `.\reports\`:

| File | Purpose |
|------|---------|
| `audit-yyyyMMdd-HHmmss.html` | Interactive HTML report with filters, exports, and remediation panel |
| `audit-yyyyMMdd-HHmmss.json` | Companion JSON for programmatic access |

And in `.\logs\`:

| File | Purpose |
|------|---------|
| `audit-yyyyMMdd-HHmmss.log` | Auto-generated execution log (color-coded console output mirrored here) |

---

## Understanding the Output

### Console Output

While running, the script prints color-coded progress to the console:

```
================================================================================
              Windows Security Audit Script v6.1.2
================================================================================

[*] Checking prerequisites...
  [+] PowerShell 5.1 or higher detected
  [+] Running as Administrator
  [+] All modules accessible

[*] Discovering available modules...
[+] Modules to execute: acsc, cis, cisa, cmmc, core, enisa, gdpr, hipaa, iso27001, ms, ms-defenderatp, nist, nsa, pcidss, soc2, stig

[*] Initializing shared data cache...
[+] Cache initialized in 5.38s
    Services: 278 | Registry keys: 7 | Local users: 5 | Hotfixes: 5

[*] Executing 16 modules in PARALLEL (4 workers)...

[+] Module acsc completed: 170 checks (98 pass, 22 fail, 31 warning, 17 info, 2 error)
[+] Module cis completed: 260 checks (155 pass, 41 fail, 38 warning, 26 info, 0 error)
... (and so on for each module)

================================================================================
[*] Audit Complete
================================================================================
  Duration:        77.94s
  Total Checks:    3,994
  Pass:            2,547 (63.77%)
  Fail:            687 (17.20%)
  Warning:         521 (13.05%)
  Info:            213 (5.33%)
  Error:           26 (0.65%)
  Compliance:      64.06%
[+] HTML report: .\reports\audit-20260425-152307.html
[+] JSON report: .\reports\audit-20260425-152307.json
[+] Log file:    .\logs\audit-20260425-152307.log
```

### Result Status Values

| Status | Meaning | Color |
|--------|---------|-------|
| **Pass** | Configuration meets framework requirement | Green |
| **Fail** | Configuration violates framework requirement | Red |
| **Warning** | Marginal/risky configuration; review recommended | Yellow |
| **Info** | Informational finding; no action required | Cyan |
| **Error** | Check could not be performed (permission/feature issue) | Magenta |

### Severity Levels

| Severity | Meaning |
|----------|---------|
| **Critical** | Immediate action required; high-impact vulnerability |
| **High** | Significant risk; remediate within standard cadence |
| **Medium** | Moderate risk; address per organizational policy |
| **Low** | Minor risk; informational hardening |
| **Informational** | Reference data; no risk implication |

### Result Object Structure

Every check returns a 9-field PSCustomObject:

```json
{
  "Module":          "CIS",
  "Category":        "CIS - Account Policy",
  "Status":          "Fail",
  "Severity":        "High",
  "Message":         "Maximum password age exceeds policy (current: 0 days)",
  "Details":         "CIS Benchmark recommends 60-365 days for password rotation",
  "Remediation":     "net accounts /maxpwage:90",
  "CrossReferences": { "NIST": "IA-5", "STIG": "V-220903" },
  "Timestamp":       "2026-04-25T15:23:07.123Z"
}
```

---

## Selecting Modules

### Run All Modules

```powershell
.\Windows-Security-Audit.ps1 -Modules All
.\Windows-Security-Audit.ps1                     # Equivalent (default)
```

### Run Specific Modules

```powershell
# Single module
.\Windows-Security-Audit.ps1 -Modules CIS

# Multiple modules
.\Windows-Security-Audit.ps1 -Modules CIS,STIG,NIST

# Mixed compliance focus
.\Windows-Security-Audit.ps1 -Modules HIPAA,GDPR,SOC2,PCI-DSS

# Module names are case-insensitive
.\Windows-Security-Audit.ps1 -Modules cis,stig,nist
```

### List Available Modules

```powershell
.\Windows-Security-Audit.ps1 -ListModules
```

Output:

```
Available Modules (16):

  ACSC            Australian Cyber Security Centre Essential Eight
  CIS             CIS Controls v8 + IG2/IG3 Companion Guides
  CISA            CISA Best Practices, KEV catalog, Zero Trust Maturity
  CMMC            CMMC 2.0 + NIST SP 800-172 + DFARS 252.204-7012
  Core            Foundational Windows Security Baseline
  ENISA           ENISA Cybersecurity + NIS2 + DORA
  GDPR            GDPR Articles 5/15-21/28/32/35
  HIPAA           HIPAA Security Rule + 405(d) HICP
  ISO27001        ISO 27001:2022 + 27002/27017/27018/27701
  MS              Microsoft Security Baseline (Win11 24H2/Server 2025)
  MS-DefenderATP  Microsoft Defender for Endpoint
  NIST            NIST SP 800-53 R5 + CSF 2.0 + 800-171 R3
  NSA             NSA Cybersecurity (CSI + AD hardening)
  PCI-DSS         PCI DSS v4.0/v4.0.1 + PIN Security + 3DS
  SOC2            SOC 2 Trust Service Criteria
  STIG            DISA STIGs + SRG cross-mapping
```

---

## Output Formats

The script supports five native output formats and six browser-based exports.

### Native Formats

| Format | Switch | Use Case |
|--------|--------|----------|
| **HTML** (default) | `-OutputFormat HTML` | Interactive review, executive presentation |
| **JSON** | `-OutputFormat JSON` | Programmatic parsing, automation, SIEM ingestion |
| **CSV** | `-OutputFormat CSV` | Spreadsheet analysis, ticket creation |
| **XML** | `-OutputFormat XML` | XSL-styled workbook (renders in browser); SIEM systems expecting XML |
| **Console** | `-OutputFormat Console` | Terminal-only; no file output |
| **All** | `-OutputFormat All` | Generate every format simultaneously |

### Examples

```powershell
# Default HTML output to .\reports\
.\Windows-Security-Audit.ps1

# JSON only, custom path
.\Windows-Security-Audit.ps1 -OutputFormat JSON -OutputPath .\audits\Q2-baseline.json

# Generate all formats with shared base name
.\Windows-Security-Audit.ps1 -OutputFormat All -OutputPath .\audits\Q2-2026

# Console-only (good for piping or quick review)
.\Windows-Security-Audit.ps1 -Modules Core -OutputFormat Console
```

### Browser-Based Exports (from HTML report)

Once the HTML report opens, the **Export** button in the top toolbar offers six additional export formats:

1. **CSV** — flat tabular export
2. **Excel (.xls)** — opens directly in Microsoft Excel
3. **JSON** — same shape as native JSON
4. **XML Workbook** — XSL-styled XML
5. **SIEM XML** — SIEM-compatible structured XML
6. **Plain Text (.txt)** — human-readable text dump

You can also export selectively by checking individual rows or filtering by module/category before clicking Export.

---

## Logging

### Default Behavior

Without specifying `-LogFile`, the script automatically generates a timestamped log file:

```
.\logs\audit-yyyyMMdd-HHmmss.log
```

Console output is mirrored to this file with the same color-coded format.

### Log Levels

| Level | Numeric | Use |
|-------|---------|-----|
| `DEBUG` | 10 | Deep diagnostic trace (invocation context, module timings, parameter values) |
| `INFO` (default) | 20 | Standard progress messages |
| `WARNING` | 30 | Non-fatal issues |
| `ERROR` | 40 | Module failures or critical errors |
| `CRITICAL` | 50 | Audit-aborting failures |

### Examples

```powershell
# Default INFO level
.\Windows-Security-Audit.ps1

# Deep debugging — captures invocation context, parameters, per-module timing
.\Windows-Security-Audit.ps1 -LogLevel Debug -Verbose

# Custom log file path
.\Windows-Security-Audit.ps1 -LogFile .\diagnostic-2026-04-25.log

# JSON-formatted log for SIEM ingestion
.\Windows-Security-Audit.ps1 -JsonLog -LogFile .\siem-audit.json

# Suppress console output (file logging only)
.\Windows-Security-Audit.ps1 -Quiet
```

### Sample DEBUG Output

```
[2026-04-25 15:23:07.001] [INFO] [MAIN] Windows Security Audit v6.1.2 starting
[2026-04-25 15:23:07.012] [DEBUG] [MAIN] Log level: Debug | Log file: .\logs\audit-20260425-152307.log | JSON: False | Quiet: False
[2026-04-25 15:23:07.014] [DEBUG] [MAIN] Invocation: PSVersion=5.1.22621.3155 | OS=Microsoft Windows NT 10.0.22631.0 | User=Administrator | Admin=True
[2026-04-25 15:23:07.015] [DEBUG] [MAIN] Parameters: Modules=All | Parallel=True | Workers=4 | NoCache=False | OutputFormat=HTML
[2026-04-25 15:23:07.020] [DEBUG] [MAIN] Checking prerequisites
[2026-04-25 15:23:07.034] [DEBUG] [MAIN] Prereq OK: PowerShell 5.1 or higher detected
[2026-04-25 15:23:07.041] [DEBUG] [MAIN] Module discovery starting
[2026-04-25 15:23:07.052] [DEBUG] [MAIN] Discovered 16 modules: acsc, cis, cisa, cmmc, core, enisa, gdpr, hipaa, iso27001, ms, ms-defenderatp, nist, nsa, pcidss, soc2, stig
[2026-04-25 15:23:12.430] [DEBUG] [CIS] Module starting: path=.\modules\module-cis.ps1
[2026-04-25 15:23:18.892] [INFO] [CIS] Module complete in 6.46s: 260 checks (155 pass, 41 fail, 38 warning, 26 info, 0 error)
...
[2026-04-25 15:24:25.001] [DEBUG] [MAIN] Module timings: acsc:5.32s | cis:6.46s | cisa:8.71s | cmmc:4.18s | core:7.93s | ...
```

---

## Performance and Caching

### Default: Sequential Execution with Cache

```powershell
.\Windows-Security-Audit.ps1
```

Modules run one at a time; the shared data cache pre-populates registry, services, audit policy, and password policy queries during warmup, eliminating redundant queries.

### Parallel Execution

For multi-core systems, parallel execution dramatically reduces total runtime:

```powershell
# Default 4 workers
.\Windows-Security-Audit.ps1 -Parallel

# Specify worker count (1-16)
.\Windows-Security-Audit.ps1 -Parallel -Workers 8

# Combined with profiling
.\Windows-Security-Audit.ps1 -Parallel -Workers 8 -ShowProfile
```

### Performance Profiling

The `-ShowProfile` switch reports per-module timing at the end of the audit:

```
=== Module Performance Profile ===
  acsc            5.32s (170 checks)
  cis             6.46s (260 checks)
  cisa            8.71s (289 checks)
  ...
  Total wall time: 77.94s
  CPU time:        232.18s (parallel speedup: 2.98x)
```

### Cache Control

```powershell
# Disable cache (debugging only — adds ~3-5x runtime)
.\Windows-Security-Audit.ps1 -NoCache
```

---

## Remediation Workflows

### Audit-Only Mode (Default — Read-Only)

Without any remediation switches, the script performs **only** read-only checks:

```powershell
.\Windows-Security-Audit.ps1
# No system changes — safe to run on any environment
```

### Interactive Remediation

The script prompts for confirmation before each fix:

```powershell
# Prompt for every Fail/Warning/Info finding
.\Windows-Security-Audit.ps1 -RemediateIssues

# Filter by status
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail        # Failures only
.\Windows-Security-Audit.ps1 -RemediateIssues_Warning     # Warnings only
.\Windows-Security-Audit.ps1 -RemediateIssues_Info        # Info only

# Combine
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -RemediateIssues_Warning
```

For each finding, you'll see:

```
[Issue 1 of 31]
  Module:     CIS
  Category:   CIS - Account Policy
  Severity:   High
  Status:     Fail
  Message:    Maximum password age exceeds policy (current: 0 days)
  Details:    CIS Benchmark recommends 60-365 days for password rotation
  Remediation: net accounts /maxpwage:90

  Apply this remediation? (Y/N/A=All/S=Skip Remaining/Q=Quit):
```

### Automated Remediation

The `-AutoRemediate` switch applies all qualifying remediations without per-item prompting, BUT requires explicit `YES` confirmation upfront:

```powershell
# Apply all Fail remediations after summary confirmation
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -AutoRemediate
```

Pre-confirmation displays the full impact summary:

```
=== Remediation Plan ===
  Total remediations:      31
  Critical:                4
  High:                    18
  Medium:                  9
  Reboot required:         3
  Logoff required:         2
  Service restart:         5
  Network impact:          1
  Destructive:             0

This action will modify system configuration.
Type YES to proceed, or anything else to cancel: 
```

### Targeted Remediation from HTML Report

The HTML report's checkbox-based selection exports a JSON file that can be re-fed:

```powershell
# Step 1: Run audit, open HTML report, check the boxes for issues to fix
.\Windows-Security-Audit.ps1

# Step 2: In the HTML report, click "Export Selected (JSON)" → save as .\selected.json

# Step 3: Apply only the selected items
.\Windows-Security-Audit.ps1 -RemediationFile .\selected.json -AutoRemediate
```

### Remediation Bundles (v6.1.0+)

Five predefined bundles target common hardening goals:

| Bundle | Coverage |
|--------|----------|
| **DisableLegacyProtocols** | SMBv1, TLS 1.0/1.1, SSLv2/3, LLMNR, NetBIOS, LM hash, NTLMv1, RC4, 3DES |
| **HardenAuthentication** | UAC, LSA Protection, Credential Guard, NTLM levels, Anonymous, Cached Logons, Password Policy, WDigest |
| **EnableAuditLogging** | Process Creation, ScriptBlockLogging, ModuleLogging, Transcription, Audit Policy, Event Log Size |
| **LockDownRDP** | RDP enable, NLA, MinEncryption, SecurityLayer, IdleTimeout, MaxIdleTime |
| **EssentialEightLevel1** | ACSC E1-E8: AppControl, Patch Apps, Macros, App Hardening, Admin Privs, Patch OS, MFA, Backups |

Examples:

```powershell
# Apply legacy protocol hardening
.\Windows-Security-Audit.ps1 -RemediationBundle DisableLegacyProtocols -AutoRemediate

# E8 L1 with rollback script for safety
.\Windows-Security-Audit.ps1 -RemediationBundle EssentialEightLevel1 -AutoRemediate -RollbackPath .\e8-rollback.ps1
```

### Rollback Script Generation

The `-RollbackPath` switch generates an inverse script as remediations are applied:

```powershell
# Apply remediations and capture rollback
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -AutoRemediate -RollbackPath .\rollback.ps1

# Later: reverse the changes
.\rollback.ps1
```

The generated rollback script contains:
- Original registry values (read before modification)
- Original service states (Running/Stopped, StartupType)
- Inverse `auditpol` commands
- Comments documenting what each line reverses

---

## Baseline Drift Comparison

Capture a baseline of your current state, then compare future audits against it:

### Step 1: Capture Baseline

```powershell
# Run a clean audit; the JSON file IS the baseline
.\Windows-Security-Audit.ps1 -OutputFormat JSON -OutputPath .\baselines\golden-2026-04-25.json
```

### Step 2: Compare Against Baseline

```powershell
.\Windows-Security-Audit.ps1 -Baseline .\baselines\golden-2026-04-25.json
```

The HTML report includes a Drift Analysis panel:

```
=== Baseline Drift ===
  New failures (regressions):     7
  Resolved findings (improvements): 12
  Stable findings:                 3,892
  Newly introduced:                83
  Removed:                         0
```

Each drift finding is tagged in the HTML report and JSON output, making it easy to focus on what changed since baseline.

### Use Cases

- **Quarterly audit cadence** — capture Q1 baseline, compare Q2/Q3/Q4
- **Pre/post change validation** — capture baseline before patch deployment, compare after
- **Compliance evidence** — show regulators "we maintained X% compliance from Date A to Date B"

---

## Group Policy Export

Convert registry-modifying remediations into a Group Policy `.pol` file for centralized deployment:

```powershell
# Generate GPO from failing checks
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -ExportGPO .\Hardening-Q2-2026.pol
```

Import the `.pol` file into a Group Policy Object via Group Policy Management Editor:

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit the target GPO
3. Navigate to **Computer Configuration → Preferences → Windows Settings → Registry**
4. Right-click → **Import** → select the generated `.pol` file

Note: only registry-modifying remediations are exported; service changes and `auditpol` commands require separate deployment mechanisms.

---

## Cross-Cutting v6.1 Capabilities

These switches add report enrichment without modifying the audit findings themselves:

### Risk Priority Scoring

Adds a 1-100 risk priority column combining severity, exploitability heuristics, exposure context, and asset criticality:

```powershell
.\Windows-Security-Audit.ps1 -ShowRiskPriority
```

Score breakdown:
- **80-100** — Critical priority (Critical/High severity + high exploitability + internet-facing)
- **60-79** — High priority (High severity + moderate exposure)
- **40-59** — Medium priority
- **20-39** — Low priority
- **1-19** — Informational

### Cross-Framework Correlations

Groups findings that test the same underlying control across multiple modules:

```powershell
.\Windows-Security-Audit.ps1 -ShowCorrelations
```

Example correlation panel:

```
=== Cross-Framework Correlations ===

[Correlation: SMBv1 Disabled]
  Tested by 7 modules — all PASS
  Modules: core, stig, ms, nsa, cisa, hipaa, enisa

[Correlation: BitLocker Active on System Drive]
  Tested by 10 modules — 8 PASS, 2 FAIL
  PASS: core, stig, ms, nist, hipaa, gdpr, iso27001, pcidss
  FAIL: cmmc, acsc
  Status mismatch — investigate per-module severity differences
```

### Compensating Controls

Flags failed checks where a passing related control mitigates the risk:

```powershell
.\Windows-Security-Audit.ps1 -ShowCompensatingControls
```

Example:

```
[Compensating Control Detected]
  Failed check:    LSA Protection (RunAsPPL) — Fail
  Compensated by:  Credential Guard active (passes)
  Mitigation:     Credential Guard provides VBS-isolated credential storage
                   that mitigates most LSA credential theft scenarios
```

### Combined Enrichment

```powershell
# All three v6.1 enrichments together
.\Windows-Security-Audit.ps1 -ShowRiskPriority -ShowCorrelations -ShowCompensatingControls
```

---

## Standalone Module Execution

Any module can be invoked directly without the orchestrator. Useful for:
- Quick targeted testing during module development
- CI/CD pipelines that test specific compliance requirements
- Embedding individual checks in larger automation

```powershell
# Run CIS module standalone
cd modules
.\module-cis.ps1

# Pass shared cache (optional — module will warm its own if not provided)
$sharedData = @{ Cache = $null }
.\module-stig.ps1 -SharedData $sharedData
```

The module returns the result array directly; you can pipe it:

```powershell
# Get only failures from STIG module
.\module-stig.ps1 | Where-Object { $_.Status -eq 'Fail' }

# Count results by severity
.\module-nist.ps1 | Group-Object -Property Severity | Format-Table
```

---

## Advanced Workflows

### Continuous Compliance Monitoring

```powershell
# Schedule via Task Scheduler — daily at 3 AM
$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\WinSecAudit\Windows-Security-Audit.ps1" -Modules All -OutputFormat All -OutputPath "C:\WinSecAudit\reports\daily" -JsonLog'

$trigger = New-ScheduledTaskTrigger -Daily -At 3am

Register-ScheduledTask `
    -TaskName "Windows Security Audit Daily" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest `
    -User "SYSTEM"
```

### Multi-Environment Comparison

```powershell
# On each system, capture a baseline
.\Windows-Security-Audit.ps1 -OutputFormat JSON -OutputPath ".\$env:COMPUTERNAME-baseline.json"

# On a central system, compare results
$results = @{}
Get-ChildItem .\baselines\*.json | ForEach-Object {
    $data = Get-Content $_.FullName | ConvertFrom-Json
    $results[$_.BaseName] = $data
}

# Find checks where multiple systems disagree
$results.Values[0].Results | ForEach-Object {
    $check = $_
    $allStatuses = @($results.Values | ForEach-Object {
        ($_.Results | Where-Object { $_.Category -eq $check.Category -and $_.Message -eq $check.Message }).Status
    } | Select-Object -Unique)
    if ($allStatuses.Count -gt 1) {
        Write-Host "DRIFT: $($check.Module) | $($check.Category) — statuses: $($allStatuses -join ',')"
    }
}
```

### CI/CD Integration

```powershell
# Run audit, fail build if compliance < threshold
.\Windows-Security-Audit.ps1 -OutputFormat JSON -OutputPath .\ci-audit.json -Quiet

$results = Get-Content .\ci-audit.json | ConvertFrom-Json
$compliance = $results.ExecutionInfo.ComplianceScore

if ($compliance -lt 85) {
    Write-Error "Compliance below threshold: $compliance% (required: 85%)"
    exit 1
}
exit 0
```

### Compliance Trend Analysis

```powershell
# Aggregate scores from monthly baselines
$baselines = Get-ChildItem .\baselines\*.json | Sort-Object Name
$trend = $baselines | ForEach-Object {
    $data = Get-Content $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{
        Date       = $_.LastWriteTime
        Compliance = $data.ExecutionInfo.ComplianceScore
        Failures   = ($data.Results | Where-Object { $_.Status -eq 'Fail' }).Count
    }
}

$trend | Format-Table
$trend | Export-Csv .\compliance-trend.csv -NoTypeInformation
```

---

## SIEM and Automation Integration

### Splunk

```powershell
# Generate JSON-formatted log for Splunk ingestion
.\Windows-Security-Audit.ps1 -JsonLog -LogFile C:\Splunk\inputs\winsec-audit.json
```

Splunk forwarder configuration (`inputs.conf`):

```ini
[monitor://C:\Splunk\inputs\winsec-audit.json]
disabled = false
sourcetype = winsec_audit_json
index = security
```

### Microsoft Sentinel

```powershell
# Generate SIEM XML output
.\Windows-Security-Audit.ps1 -OutputFormat XML -OutputPath .\sentinel-feed.xml

# Or use the JSON companion via Log Analytics Data Collector API
.\Windows-Security-Audit.ps1 -OutputFormat JSON
# Then push the JSON to Log Analytics via Azure Monitor HTTP Data Collector
```

### Elastic Stack (ELK)

```powershell
# JSON output is directly Logstash-compatible
.\Windows-Security-Audit.ps1 -OutputFormat JSON -OutputPath C:\Logstash\winsec\daily.json
```

Logstash pipeline:

```yaml
input {
  file {
    path => "C:/Logstash/winsec/*.json"
    codec => json
  }
}
filter {
  date { match => [ "Timestamp", "ISO8601" ] }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "winsec-audit-%{+YYYY.MM.dd}"
  }
}
```

### Custom Webhook Notification

```powershell
$results = Get-Content .\reports\latest.json | ConvertFrom-Json
$failures = ($results.Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count

if ($failures -gt 0) {
    $payload = @{
        text = "Critical findings: $failures"
        score = $results.ExecutionInfo.ComplianceScore
    } | ConvertTo-Json
    
    Invoke-WebRequest -Uri 'https://hooks.example.com/winsec' -Method Post -Body $payload -ContentType 'application/json'
}
```

---

## Troubleshooting

For troubleshooting, see [docs/wiki/Troubleshooting Guide.md](docs/wiki/Troubleshooting%20Guide.md). Quick reference:

| Symptom | Common Cause | Fix |
|---------|--------------|-----|
| `cannot be loaded because running scripts is disabled` | Execution policy | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Many `Error` results | Not running as Administrator | Re-launch as Administrator |
| BitLocker check returns `Unknown` | BitLocker feature not installed | Expected on Home editions; finding is informational |
| `auditpol` errors | Standard user privileges | Administrator required for audit policy queries |
| Slow audit | Cache disabled or single-threaded | Add `-Parallel -Workers 8` |
| Empty HTML report | Browser blocking JavaScript | Check browser console; allow file:// or local-file scripts |
| `Get-CimInstance` warnings | Old WMI repository | `winmgmt /verifyrepository` and `winmgmt /salvagerepository` |

For deeper troubleshooting, run with `-LogLevel Debug -Verbose` and inspect the generated log file.

---

## Quick Reference Card

```powershell
# Default audit (all modules, HTML output, auto-logging)
.\Windows-Security-Audit.ps1

# Targeted modules with parallel execution
.\Windows-Security-Audit.ps1 -Modules CIS,STIG,NIST -Parallel -Workers 8

# Multi-format output
.\Windows-Security-Audit.ps1 -OutputFormat All -OutputPath .\audits\Q2

# Baseline drift comparison
.\Windows-Security-Audit.ps1 -Baseline .\baselines\golden.json

# Enriched report
.\Windows-Security-Audit.ps1 -ShowRiskPriority -ShowCorrelations -ShowCompensatingControls

# Interactive remediation of failures
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail

# Auto-remediation with rollback safety
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -AutoRemediate -RollbackPath .\rollback.ps1

# Apply remediation bundle
.\Windows-Security-Audit.ps1 -RemediationBundle EssentialEightLevel1 -AutoRemediate

# Group Policy export
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -ExportGPO .\policy.pol

# Deep diagnostics
.\Windows-Security-Audit.ps1 -LogLevel Debug -Verbose

# Comprehensive help
.\Windows-Security-Audit.ps1 -Help
```

---

**See also:**
- [README.md](docs/project/README.md) — project overview
- [CHANGELOG.md](docs/project/CHANGELOG.md) — release history
- [docs/wiki/Quick Start Guide.md](docs/wiki/Quick%20Start%20Guide.md) — 5-minute setup
- [docs/wiki/Module Documentation.md](docs/wiki/Module%20Documentation.md) — per-module details
- [docs/wiki/Output Reference.md](docs/wiki/Output%20Reference.md) — full output schema
- [docs/wiki/Architecture and Design.md](docs/wiki/Architecture%20and%20Design.md) — internal architecture
- [docs/wiki/Troubleshooting Guide.md](docs/wiki/Troubleshooting%20Guide.md) — problem resolution
