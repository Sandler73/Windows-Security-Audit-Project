# Windows Security Audit Script

<div align="center">

![Version](https://img.shields.io/badge/version-6.1.2-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Server%202016%2B-lightgrey.svg)
![Checks](https://img.shields.io/badge/checks-3,994-brightgreen.svg)
![Frameworks](https://img.shields.io/badge/frameworks-16-orange.svg)

**Module-Based Multi-Framework Windows Security Assessment, Auditing, and Remediation Tool**

[Overview](#-overview) • [Key Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Remediation Capabilities](#-remediation-capabilities) • [Contributing](#-contributing)

</div>

---

## 📋 Overview

The **Windows Security Audit Script** is an advanced PowerShell-based security compliance auditing tool that evaluates Windows systems against multiple industry-standard security frameworks. The current release performs **3,994 automated security checks** across **16 compliance modules**, generating comprehensive reports in HTML, JSON, CSV, and XML with actionable remediation guidance.

Every check includes a severity rating (Critical/High/Medium/Low/Informational) and cross-references to equivalent controls across other frameworks, enabling multi-framework compliance scoring from a single audit run. The tool is fully self-contained — zero external dependencies, pure PowerShell stdlib — and supports parallel execution, baseline drift comparison, rollback script generation, Group Policy export, and predefined remediation bundles.

Whether you're conducting compliance audits, hardening systems, maintaining security baselines, or feeding SIEM/SOAR pipelines, this tool provides the depth and automation you need.

## 🎯 Key Features

### 🔍 **Comprehensive Security Assessment**
- ✅ **3,994 Security Checks** across 16 compliance frameworks
- ✅ **Multi-Framework Coverage** — ACSC Essential Eight, CIS Controls v8, CISA Best Practices/KEV, CMMC 2.0, Core Windows Baseline, ENISA/NIS2, GDPR, HIPAA, ISO 27001:2022, Microsoft Security Baseline, Microsoft Defender for Endpoint, NIST SP 800-53 R5/CSF 2.0/800-171/800-207, NSA Cybersecurity, PCI DSS v4.0.1, SOC 2 Type II, DISA STIG
- ✅ **Modular Architecture** — run all frameworks or select specific modules
- ✅ **Severity Classification** — every check rated Critical/High/Medium/Low/Informational
- ✅ **Cross-Framework Correlation** — every check carries `CrossReferences` mapping to equivalent controls in other frameworks
- ✅ **Standalone Module Execution** — any module can run independently without the orchestrator
- ✅ **Result Validation** — automated 9-field result-object normalization
- ✅ **No External Dependencies** — pure PowerShell stdlib; zero pip/npm/nuget/external network calls

### 📊 **Advanced Reporting**
- ✅ **Interactive HTML Reports** with:
  - 🌓 Dark/Light theme toggle
  - 🔍 Advanced filtering and sorting per column
  - 📤 Export All / Export Selected modal (CSV, Excel, JSON, XML Workbook, SIEM XML, TXT)
  - ☑️ Checkbox-based selective export
  - 📑 Per-module and global export options
  - 📊 Executive dashboard with statistics
- ✅ **SIEM-Compatible XML** output for security monitoring platforms
- ✅ **Multiple Output Formats** - HTML, JSON, CSV, XML, Console, plus 6 browser-based exports
- ✅ **9-Field Result Objects** — Module, Category, Status, Severity, Message, Details, Remediation, CrossReferences, Timestamp
- ✅ **Structured Data** — API and automation-friendly formats

### 🔧 **Intelligent Remediation**
- ✅ **Interactive Remediation** - Review and apply fixes individually
- ✅ **Automated Remediation** - Batch fix with safety confirmations
- ✅ **Selective Remediation** - Target specific status types (Fail, Warning, Info)
- ✅ **Targeted Remediation** - Fix only selected issues from JSON export
- ✅ **Remediation Logging** - Comprehensive audit trail of all changes
- ✅ **Safety Mechanisms** - Double-confirmation and countdown timers
- ✅ **Rollback Support** - Detailed logs for reverting changes

### 📈 **Quality Assurance**
- ✅ **Result Validation** - Ensures data integrity across all modules
- ✅ **Status Normalization** - Consistent categorization (Pass/Fail/Warning/Info/Error)
- ✅ **Module Statistics** - Real-time tracking and reporting
- ✅ **Execution Metadata** - Complete audit trail preservation
- ✅ **Error Handling** - Graceful degradation on check failures

### 🆕 **What's New in 6.1.x**
- ✅ **Risk Priority Scoring** — 1-100 score combining severity, exploitability, exposure, asset criticality (`-ShowRiskPriority`)
- ✅ **Cross-Framework Correlations** — group findings that test the same underlying control across modules (`-ShowCorrelations`)
- ✅ **Compensating Control Detection** — flag failed checks where a passing related control mitigates risk (`-ShowCompensatingControls`)
- ✅ **Baseline Drift Comparison** — diff against previous audit JSON for new failures, resolved findings, regressions (`-Baseline`)
- ✅ **Rollback Script Generation** — auto-generate inverse-script from applied remediations (`-RollbackPath`)
- ✅ **Group Policy Export** — generate `.pol` file from registry-modifying remediations (`-ExportGPO`)
- ✅ **Remediation Bundles** — `DisableLegacyProtocols`, `HardenAuthentication`, `EnableAuditLogging`, `LockDownRDP`, `EssentialEightLevel1` (`-RemediationBundle`)
- ✅ **Comprehensive Help** — robust 10-section in-script help via `-Help`/`-H`/`-?`/`help`/`-help`/`--help`/`--h`
- ✅ **Auto-Logging** — log file auto-generated at `<ScriptRoot>\logs\audit-yyyyMMdd-HHmmss.log` when `-LogFile` omitted; color-coded console output by default
- ✅ **+795 New Checks** — every module expanded; total now 3,994 across 16 modules

See [CHANGELOG.md](CHANGELOG.md) for the complete release history.


## 🏢 Supported Frameworks

| Module | Framework | Checks | Focus Areas |
|--------|-----------|--------|-------------|
| **acsc** | Australian Cyber Security Centre Essential Eight + Maturity Levels | 170 | Application control, patching, macros, hardening, admin privs, MFA, backups + ISM, PSPF, ACSI 33, APP |
| **cis** | CIS Controls v8 + IG2/IG3 + Cloud/Mobile/ICS-OT Companion Guides | 260 | Industry best practices, asset inventory, workload-specific (IIS/Exchange/SQL) detection |
| **cisa** | CISA Best Practices, KEV catalog, Zero Trust Maturity Model | 289 | KEV (CVE-2017-0144, CVE-2021-34527, CVE-2023-24932, CVE-2020-1472), BOD 23-02, Secure by Design, ZTMM 5 pillars, CPGs v1.0.1, Bad Practices, PRNI |
| **cmmc** | CMMC 2.0 L1/L2/L3 + NIST SP 800-172 + DFARS 252.204-7012 | 145 | Access control, audit, config mgmt, IA, media, comms, integrity, SPRS scoring, CDI/CUI |
| **core** | Foundational Windows Security Baseline + Win11 modern features | 243 | TPM 2.0, VBS+HVCI, Kernel DMA, USB policy, Print Spooler, Sandbox, Pluton, System Guard, kCET, MOTW |
| **enisa** | ENISA Cybersecurity + NIS2 Directive + Cyber Resilience Act + DORA | 248 | NIS2 Art. 21, CRA, Threat Landscape, RICT, IoC, EUCC, AI Threat Landscape |
| **gdpr** | GDPR Articles 5/15-21/28/32/35 + ePrivacy + Schrems II | 183 | Privacy by design, encryption, CIA + resilience, DPIA, pseudonymisation |
| **hipaa** | HIPAA Security Rule + NIST SP 800-66 R2 + HITECH + 405(d) HICP | 237 | Sec.164.312 access/audit/integrity/transmission, HHS Recognized Security Practices, Breach Notification, Cures Act, ONC |
| **iso27001** | ISO 27001:2022 + 27002:2022 + 27017/27018 (Cloud) + 27701 (Privacy) | 286 | Annex A controls, automated SoA, ISO 27005 risk + 27031 ICT continuity |
| **ms** | Microsoft Security Baseline (Win11 24H2/Server 2025) + Edge + M365 Apps | 367 | SCT/LGPO, Defender, AppLocker, ASR, Edge baseline, M365 Office macros, Smart App Control, update channels |
| **ms-defenderatp** | Microsoft Defender for Endpoint (ATP/EDR) | 155 | Component currency, Network Protection, CFA, EPP, WDAC, MDI, per-rule ASR (15 GUIDs), Live Response, Cloud Apps, IOCs |
| **nist** | NIST SP 800-53 R5 + CSF 2.0 + 800-171 R3 + 800-207 ZTA + 800-161 SCRM + FedRAMP R5 | 520 | Federal compliance, 8 control families (AC/AU/CM/IA/IR/MP/SC/SI) + 12 framework extensions |
| **nsa** | NSA Cybersecurity (CSI + AD hardening + Top 10 Mitigations) | 225 | Credential isolation, AppWhitelisting, HVCI, AD DC/member hardening, BlackLotus mitigation, CSfC, IPv6 |
| **pcidss** | PCI DSS v4.0/v4.0.1 + PIN Security + 3DS Core + SSF | 279 | Customized Approach, SAQ detection, CHD discovery, network segmentation, SAD prohibition, Req 9 physical |
| **soc2** | SOC 2 Trust Service Criteria + AICPA TSP Section 100 PoF | 162 | Common Criteria + Processing Integrity + Privacy criteria, Type II evidence collection |
| **stig** | DISA STIGs + SRG cross-mapping + Microsoft Defender STIG | 225 | V-finding format, STIG Viewer compatibility, BlackLotus mitigation, CAT I/II/III distribution + POA&M flagging |

**Total Coverage**: 3,994 security checks with severity classification and cross-framework correlation. Coverage spans access control, authentication, auditing/logging, network security, data protection at-rest and in-transit, malware defense, system hardening, EDR, Zero Trust architecture, privacy compliance, payment card security, healthcare data protection, supply chain risk management, and cloud-extension controls.

## 🚀 Quick Start

### Prerequisites

- **Operating System**: Windows 10/11 or Windows Server 2016/2019/2022/2025
- **PowerShell**: Version 5.1 or later (included in modern Windows)
- **Privileges**: Administrator rights required for complete results
- **Privileges for Remediation**: Administrator rights **mandatory** for applying fixes

### Installation

1. **Clone the repository:**
```powershell
   git clone https://github.com/Sandler73/Windows-Security-Audit-Project.git
   cd Windows-Security-Audit-Project
```

2. **Set execution policy (if needed):**
```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. **Verify prerequisites:**
```powershell
   # Check PowerShell version
   $PSVersionTable.PSVersion

   # Check if running as Administrator
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

### Basic Usage

**Run full audit with default HTML report:**
```powershell
.\Windows-Security-Audit.ps1
```

**Run specific frameworks:**
```powershell
.\Windows-Security-Audit.ps1 -Modules Core,NIST,CISA
```

**Run with Defender ATP assessment:**
```powershell
.\Windows-Security-Audit.ps1 -Modules Core,MS,MS-DefenderATP
```

**Generate CSV output:**
```powershell
.\Windows-Security-Audit.ps1 -OutputFormat CSV
```

**SIEM integration with XML:**
```powershell
.\Windows-Security-Audit.ps1 -OutputFormat XML -OutputPath "\\SIEM\imports\audit.xml"
```

**Run a single module standalone (no orchestrator needed):**
```powershell
.\modules\module-cis.ps1
```

## 🔧 Remediation Capabilities

Version 5.3 introduces comprehensive remediation features with multiple workflows to suit different needs and risk tolerances.

### Remediation Modes

#### 1. **Interactive Remediation** (Safest)
Review and approve each fix individually:
```powershell
.\Windows-Security-Audit.ps1 -RemediateIssues
```
- Prompts for each remediation
- Full visibility into changes
- Skip option (Y/N/S)
- Recommended for production systems

#### 2. **Status-Based Remediation**
Target specific severity levels:
```powershell
# Fix only critical failures
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail

# Fix warnings interactively
.\Windows-Security-Audit.ps1 -RemediateIssues_Warning

# Address informational items
.\Windows-Security-Audit.ps1 -RemediateIssues_Info

# Fix everything (all status types)
.\Windows-Security-Audit.ps1 -RemediateIssues
```

#### 3. **Automated Remediation** (Advanced)
Batch remediation with safety confirmations:
```powershell
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -AutoRemediate
```

**Safety Features:**
- Displays all changes before execution
- Requires typing "YES" to confirm
- Secondary confirmation with 10-second timeout
- Requires typing "CONFIRM" to proceed
- Comprehensive remediation logging

#### 4. **Targeted Remediation** (Precision)
Fix only specific issues selected from HTML report:

**Workflow:**
```powershell
# Step 1: Run audit and review findings
.\Windows-Security-Audit.ps1

# Step 2: In HTML report, select specific issues and click "Export Selected"
# This generates a JSON file (e.g., Selected-Report.json)

# Step 3: Run targeted auto-remediation
.\Windows-Security-Audit.ps1 -AutoRemediate -RemediationFile "Selected-Report.json"
```

**Benefits:**
- Surgical precision - fix only what you select
- Review in detail before committing
- Perfect for change control processes
- Ideal for compliance-driven remediation

### Remediation Logging

All remediation actions are logged with full details:
```
Remediation-Log-YYYYMMDD-HHMMSS.json
```

Log includes:
- Timestamp for each action
- Module and category
- Issue description
- Remediation command executed
- Success/failure status
- Error messages (if failed)

### Example Remediation Output
```
========================================================================================================
                                  REMEDIATION MODE
========================================================================================================

[*] Mode: Remediate FAIL issues only
[*] Found 42 issue(s) with remediation available

[*] Issue: SMBv1 protocol is ENABLED
    Module: STIG | Status: Fail | Category: STIG - V-220968 (CAT II)
    Remediation: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Apply remediation? (Y/N/S=Skip remaining): Y
    [+] Remediation applied successfully

[*] Issue: Guest account is ENABLED
    Module: Core | Status: Fail | Category: Core - Accounts
    Remediation: Disable-LocalUser -Name Guest
    Apply remediation? (Y/N/S=Skip remaining): Y
    [+] Remediation applied successfully

========================================================================================================
Remediation Summary:
  Total issues found: 42
  Successfully remediated: 38
  Failed remediations: 2
  Skipped: 2
  Success rate: 90.5%
========================================================================================================

[*] Remediation log saved to: Remediation-Log-20250101-120000.json
[*] Some settings may require a system restart to take effect.
Would you like to restart now? (Y/N):
```

## 📊 Output Formats & Reports

### 1. HTML Report (Interactive) - **Default**

**Features:**
- 🎨 **Theme Toggle** - Switch between light and dark modes
- 📊 **Executive Dashboard** - Summary statistics and compliance overview
- 🔍 **Advanced Filtering** - Filter by status, category, or keyword per column
- ↕️ **Dynamic Sorting** - Click column headers to sort
- 📤 **Export Options**:
  - **Export All** - Complete report in multiple formats
  - **Export Selected** - Choose specific issues via checkboxes
  - **Per-Module Export** - Export individual framework results
  - **Format Options** - CSV, Excel, JSON, XML, TXT
- 📑 **Collapsible Modules** - Expand/collapse each framework section
- 🔧 **Remediation Guidance** - Detailed fix instructions for each finding
- 📱 **Responsive Design** - Works on desktop and tablet displays

**Export Workflow:**
1. Review findings in HTML report
2. Use checkboxes to select specific issues
3. Click "Export Selected" → Choose format (JSON for remediation)
4. Use exported JSON with `-RemediationFile` parameter

### 2. XML Report (SIEM Integration)

**Standardized format for security monitoring platforms:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<security_audit>
  <metadata>
    <export_date>2025-01-01T12:00:00Z</export_date>
    <computer_name>HOSTNAME</computer_name>
    <total_checks>3994</total_checks>
    <pass_count>456</pass_count>
    <fail_count>42</fail_count>
  </metadata>
  <events>
    <event>
      <timestamp>2025-01-01T12:00:00Z</timestamp>
      <module>STIG</module>
      <status>Fail</status>
      <category>V-220968</category>
      <message>SMBv1 protocol is ENABLED</message>
      <remediation>Disable-WindowsOptionalFeature...</remediation>
    </event>
  </events>
</security_audit>
```

**Use Cases:**
- Splunk, QRadar, ArcSight integration
- Automated compliance monitoring
- Trend analysis and alerting
- Centralized security dashboards

### 3. JSON Report (Automation)
```json
{
  "ExecutionInfo": {
    "ComputerName": "HOSTNAME",
    "OSVersion": "Windows 11 Pro",
    "ScanDate": "2025-01-01 12:00:00",
    "Duration": "00:02:34",
    "TotalChecks": 3994,
    "PassCount": 456,
    "FailCount": 42
  },
  "Results": [
    {
      "Module": "STIG",
      "Category": "STIG - TLS/SSL",
      "Status": "Fail",
      "Severity": "High",
      "Message": "V-220968: SMBv1 protocol is ENABLED",
      "Details": "CAT II: Disable SMBv1 immediately — lateral movement vector",
      "Remediation": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
      "CrossReferences": { "STIG": "V-220968", "NIST": "SC-8", "CIS": "18.3.3" },
      "Timestamp": "2025-03-03 12:00:00"
    }
  ]
}
```

### 4. CSV Report (Spreadsheet Analysis)

Excel-compatible format for:
- Pivot tables and dashboards
- Remediation tracking
- Progress monitoring
- Management reporting

### 5. Console Output (Real-Time)
```
========================================================================
                    Windows Security Audit Script v6.1.2
                Comprehensive Multi-Framework Security Assessment
========================================================================

[*] Modules to execute: Core, CIS, MS, MS-DefenderATP, NIST, STIG, NSA, CISA

[Core] Starting core security baseline checks...
[+] Module Core completed: 176 checks (152 pass, 12 fail, 12 warning)

[STIG] Checking DISA STIG compliance...
[+] Module STIG completed: 184 checks (148 pass, 22 fail, 14 warning)

========================================================================
                            AUDIT SUMMARY
========================================================================
Total Checks:    3994
Passed:          1542 (83.1%)
Failed:          156 (8.4%)
Warnings:        118 (6.4%)
Info:            28 (1.5%)
Errors:          0 (0.0%)
Duration:        00:02:34
========================================================================

[+] HTML report saved to: Security-Audit-Report-20250101-120000.html
[*] Opening report in browser...
[+] Audit completed successfully!
```

## 📖 Documentation

Comprehensive documentation is available in the [Project Wiki](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki):

### Getting Started
- **[Quick Start Guide](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Quick-Start-Guide)** - Get up and running in 5 minutes
- **[Usage Guide](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Windows-Security-Audit-Tool-‐-Usage-Guide)** - Detailed command-line options and workflows

### Reference Documentation
- **[Framework Reference](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Framework-Reference)** - Detailed framework mappings and control IDs
- **[Module Documentation](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Module-Documentation)** - Individual module specifications
- **[Output Reference](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Output-Reference)** - Report format specifications

### Advanced Topics
- **[Development Guide](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Development-Guide)** - Contributing and extending modules
- **[Troubleshooting Guide](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Troubleshooting-Guide)** - Common issues and solutions
- **[FAQ](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Frequently-Asked-Questions-(FAQ))** - Frequently asked questions

## 🛠️ Command-Line Parameters
```powershell
.\Windows-Security-Audit.ps1 
    [-Modules <String[]>]              # Frameworks to run (default: All — includes MS-DefenderATP)
    [-OutputFormat <String>]           # Output format: HTML, CSV, JSON, XML, Console
    [-OutputPath <String>]             # Custom output path
    [-RemediateIssues]                 # Interactive remediation (all statuses)
    [-RemediateIssues_Fail]            # Remediate FAIL status only
    [-RemediateIssues_Warning]         # Remediate WARNING status only
    [-RemediateIssues_Info]            # Remediate INFO status only
    [-AutoRemediate]                   # Automated remediation with confirmations
    [-RemediationFile <String>]        # JSON file with selected issues to remediate
```

### Parameter Examples

**Framework Selection:**
```powershell
# Run all frameworks (default)
.\Windows-Security-Audit.ps1

# Run specific frameworks
.\Windows-Security-Audit.ps1 -Modules Core,NIST,CISA

# Run single framework
.\Windows-Security-Audit.ps1 -Modules STIG
```

**Output Control:**
```powershell
# Generate HTML report (default)
.\Windows-Security-Audit.ps1 -OutputFormat HTML

# Generate CSV for Excel analysis
.\Windows-Security-Audit.ps1 -OutputFormat CSV

# Generate XML for SIEM
.\Windows-Security-Audit.ps1 -OutputFormat XML

# Console output only
.\Windows-Security-Audit.ps1 -OutputFormat Console

# Custom output location
.\Windows-Security-Audit.ps1 -OutputPath "C:\SecurityAudits\Report.html"
```

**Remediation Workflows:**
```powershell
# Interactive remediation (review each)
.\Windows-Security-Audit.ps1 -RemediateIssues

# Auto-fix critical failures only
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -AutoRemediate

# Interactive fix warnings
.\Windows-Security-Audit.ps1 -RemediateIssues_Warning

# Targeted remediation from JSON
.\Windows-Security-Audit.ps1 -AutoRemediate -RemediationFile "Selected-Report.json"
```

## 🎯 Use Cases

### 1. Compliance Auditing
**Scenario**: Annual SOC 2, FISMA, or CMMC compliance audit
```powershell
# Generate comprehensive compliance report
.\Windows-Security-Audit.ps1 -Modules NIST,STIG,CIS -OutputFormat HTML

# Export findings to CSV for compliance tracking
# Use HTML report's "Export All" → CSV feature
```

### 2. System Hardening
**Scenario**: Harden new Windows servers before production deployment
```powershell
# Step 1: Baseline audit
.\Windows-Security-Audit.ps1 -Modules Core,CIS,MS

# Step 2: Review and auto-fix critical issues
.\Windows-Security-Audit.ps1 -RemediateIssues_Fail -AutoRemediate

# Step 3: Verify remediation
.\Windows-Security-Audit.ps1 -Modules Core,CIS,MS
```

### 3. Configuration Drift Detection
**Scenario**: Monthly security posture checks
```powershell
# Generate baseline
.\Windows-Security-Audit.ps1 -OutputPath "C:\Baselines\2025-01-baseline.html"

# Compare later
.\Windows-Security-Audit.ps1 -OutputPath "C:\Baselines\2025-02-check.html"

# Use CSV exports to track changes in Excel
```

### 4. Incident Response
**Scenario**: Validate system security after suspected compromise
```powershell
# Quick security validation (core checks)
.\Windows-Security-Audit.ps1 -Modules Core -OutputFormat JSON

# Comprehensive validation (all frameworks)
.\Windows-Security-Audit.ps1 -OutputFormat HTML
```

### 5. SIEM Integration
**Scenario**: Automated compliance monitoring pipeline
```powershell
# Scheduled task to generate XML for SIEM
.\Windows-Security-Audit.ps1 -OutputFormat XML -OutputPath "\\SIEM\drops\%COMPUTERNAME%-audit.xml"
```

### 6. Change Control Validation
**Scenario**: Pre/post-change security validation
```powershell
# Pre-change baseline
.\Windows-Security-Audit.ps1 -OutputPath "Pre-Change-Audit.json"

# Post-change validation
.\Windows-Security-Audit.ps1 -OutputPath "Post-Change-Audit.json"

# Compare JSON files programmatically
```

## 🗂️ Project Structure
```
Windows-Security-Audit/
├── Windows-Security-Audit.ps1    # Main orchestrator (v5.3)
│   ├── Result validation & normalization
│   ├── Module execution engine
│   ├── Multi-format report generation
│   └── Intelligent remediation system
│
├── modules/                              # Compliance framework modules
│   ├── module-acsc.ps1                  # ACSC Essential Eight (123 checks)
│   ├── module-cis.ps1                   # CIS Benchmarks (223 checks)
│   ├── module-cisa.ps1                  # CISA Best Practices (231 checks)
│   ├── module-cmmc.ps1                  # CMMC Level 2 (103 checks)
│   ├── module-core.ps1                  # Core Security Baseline (177 checks)
│   ├── module-enisa.ps1                 # ENISA Guidelines (198 checks)
│   ├── module-gdpr.ps1                  # GDPR Technical Controls (133 checks)
│   ├── module-hipaa.ps1                 # HIPAA Security Rule (184 checks)
│   ├── module-iso27001.ps1              # ISO 27001:2022 (244 checks)
│   ├── module-ms.ps1                    # Microsoft Baselines (314 checks)
│   ├── module-ms-defenderatp.ps1        # Defender ATP (86 checks)
│   ├── module-nist.ps1                  # NIST SP 800-53/CSF (474 checks)
│   ├── module-nsa.ps1                   # NSA Guidance (173 checks)
│   ├── module-pcidss.ps1                # PCI DSS v4.0 (227 checks)
│   ├── module-soc2.ps1                  # SOC 2 Type II (124 checks)
│   └── module-stig.ps1                  # DISA STIGs (185 checks)
│
├── Reports/                              # Generated reports (auto-created)
│   ├── Security-Audit-Report-*.html
│   ├── Security-Audit-Report-*.json
│   ├── Security-Audit-Report-*.csv
│   └── Security-Audit-Report-*.xml
│
├── Logs/                                 # Remediation logs (auto-created)
│   └── Remediation-Log-*.json
│
├── README.md                             # This file
├── CONTRIBUTING.md                       # Contribution guidelines
├── CHANGELOG.md                          # Version history
├── SECURITY.md                           # Security policy
├── LICENSE                               # MIT License
└── .gitignore                            # Git ignore rules
```

## 🔍 What Gets Audited?

### Security Domains

| Domain | Checks | Examples |
|--------|--------|----------|
| **Access Control** | 200+ | Account policies, user rights, privilege management, local admin enumeration |
| **Authentication** | 160+ | Password policies, MFA requirements, credential protection (WDigest, LSASS) |
| **Audit & Accountability** | 140+ | Event logging (18+ subcategories), audit policies, log retention, PowerShell logging |
| **System Hardening** | 250+ | UAC, Secure Boot, service configuration, AutoPlay/AutoRun, least privilege |
| **Network Security** | 180+ | Firewall (all profiles), SMB security, LLMNR, NetBIOS, protocol hardening |
| **Data Protection** | 120+ | BitLocker encryption, EFS usage, data at rest/in transit protection |
| **Malware Defense** | 150+ | Windows Defender (real-time, cloud, behavior), signature updates, ASR rules |
| **Application Control** | 80+ | AppLocker policies, WDAC, software restriction, execution policies |
| **Update Management** | 60+ | Windows Update status, pending updates, automatic update configuration |
| **Incident Response** | 50+ | System Restore, backup configuration, VSS, recovery capabilities |

### Example Checks (Subset)

✅ **Critical Security Controls:**
- SMBv1 protocol disabled (WannaCry/NotPetya vector)
- BitLocker encryption enabled on system drive
- Windows Defender real-time protection active
- PowerShell v2 disabled (no logging, downgrade attacks)
- Guest account disabled
- Built-in Administrator renamed/disabled
- UAC enabled with secure desktop prompts
- Account lockout policy configured (≤5 attempts)
- Network Level Authentication required for RDP
- LSASS running as Protected Process Light

✅ **Compliance Requirements:**
- Minimum password length ≥14 characters (STIG)
- Password history ≥24 passwords (STIG/CIS)
- Audit policy configured for 18+ subcategories (NIST)
- Security event log ≥1024 MB (STIG)
- Firewall enabled on all profiles (CAT I)
- LAN Manager authentication level ≥5 (STIG)
- SMB signing required (NIST/CIS)
- WDigest credential caching disabled (NSA)

✅ **Hardening Measures:**
- Credential Guard enabled (if supported)
- Device Guard/HVCI configured
- Attack Surface Reduction rules active
- Controlled Folder Access (ransomware protection)
- Network Protection enabled
- Exploit Protection configured
- Secure Boot enabled
- Unnecessary services disabled

See [Module Documentation](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Module-Documentation) for complete check listings.

## ⚠️ Important Considerations

### Administrative Privileges

**Audit Mode:**
- Many checks require Administrator privileges
- Non-admin execution shows warnings but continues
- Some checks will return "Unable to verify" without elevation

**Remediation Mode:**
- Administrator privileges **MANDATORY**
- Script validates admin rights before remediation
- Exits gracefully if running without elevation

### Performance & Impact

**Execution Time:**
- Full audit (all 16 modules): 3-7 minutes
- Single module: 15-60 seconds
- Factors: System speed, enabled features, module selection

**System Impact:**
- **Read-only operations** during audit (no changes)
- Minimal CPU/memory usage
- No network traffic (except Windows Update checks)
- Safe to run on production systems

**Remediation Impact:**
- Makes **persistent configuration changes**
- May affect system functionality
- Some changes require restart
- Test in non-production first

### Security & Privacy

✅ **What the script does:**
- Reads system configuration (registry, services, policies)
- Queries Windows Security Center
- Checks file/folder permissions
- Generates local reports

❌ **What the script does NOT do:**
- Transmit data externally
- Install software
- Create network connections (except localhost)
- Access user data or files
- Modify system during audit (only with remediation flags)

**Report Security:**
- Reports may contain sensitive system information
- Store reports securely with appropriate access controls
- Sanitize reports before sharing externally
- Consider encrypting reports for compliance

### Testing & Validation

**Before Production Use:**
1. Test on non-production systems first
2. Review all remediation commands before auto-applying
3. Create system restore point before remediation
4. Have backups available
5. Plan maintenance window for changes requiring restart

**Validation:**
- Run baseline audit, remediate, then re-audit
- Compare before/after results
- Verify system functionality after remediation
- Check application compatibility

### Limitations

- **Local assessment only** - Does not audit remote systems or domains
- **Point-in-time** - Results represent configuration at execution time
- **Platform-specific** - Windows 10/11 and Server 2016+ only
- **Feature detection** - Some checks may not apply to all Windows editions
- **No active scanning** - Does not test for exploitable vulnerabilities

### Disclaimer

This tool is provided for **security assessment and compliance auditing purposes**. Results should be reviewed by qualified security professionals and validated in the context of your environment. The tool identifies potential security issues but does not guarantee comprehensive security coverage. Always test in non-production environments before applying remediations to production systems.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](https://github.com/Sandler73/Windows-Security-Audit-Project/blob/main/CONTRIBUTING.md) for details.

### Ways to Contribute

- 🐛 **Report bugs** - Found an issue? Open a GitHub issue
- 💡 **Suggest features** - Have an idea? Start a discussion
- 📝 **Improve documentation** - Enhance wiki pages and examples
- 🔧 **Submit bug fixes** - Fix issues and submit PRs
- ✨ **Add checks** - Contribute new security checks or modules
- 🧪 **Test** - Validate on different Windows versions
- 🌐 **Translate** - Help with internationalization

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/NewSecurityCheck`)
3. Follow coding standards (see [Development Guide](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Development-Guide))
4. Test thoroughly on multiple Windows versions
5. Update documentation
6. Commit changes (`git commit -m 'Add: New SMB3 encryption check'`)
7. Push to branch (`git push origin feature/NewSecurityCheck`)
8. Open a Pull Request with detailed description

### Coding Standards

- **PowerShell style** - Follow PowerShell best practices
- **Error handling** - Use try/catch blocks appropriately
- **Comments** - Document complex logic
- **Function naming** - Use Verb-Noun format
- **Result format** - Follow standardized output structure
- **Testing** - Validate on Windows 10, 11, Server 2019, 2022

## 📜 License

This project is licensed under the **MIT License** - see [LICENSE](https://github.com/Sandler73/Windows-Security-Audit-Project/blob/main/LICENSE) for details.

### What This Means

✅ **You can:**
- Use commercially
- Modify and distribute
- Use privately
- Sublicense

❌ **You cannot:**
- Hold authors liable
- Use trademarks

📋 **You must:**
- Include license and copyright notice
- State changes made

## 🙏 Acknowledgments

This project builds upon the work and guidance of various security organizations:

### Security Frameworks
- **[DISA](https://public.cyber.mil/stigs/)** - Defense Information Systems Agency STIGs
- **[NIST](https://csrc.nist.gov/)** - National Institute of Standards and Technology
- **[CIS](https://www.cisecurity.org/)** - Center for Internet Security Benchmarks
- **[NSA](https://www.nsa.gov/Cybersecurity/)** - National Security Agency Cybersecurity Guidance
- **[CISA](https://www.cisa.gov/cybersecurity)** - Cybersecurity and Infrastructure Security Agency
- **[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=55319)** - Security Compliance Toolkit

### Community
- Contributors who've submitted PRs and reported issues
- Security professionals who've provided feedback
- Windows administrators who've tested in production environments

### Tools & Libraries
- PowerShell team for the excellent scripting platform
- Windows security community for research and documentation

## 📞 Support & Resources

### Get Help
- **📖 Documentation** - [Project Wiki](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki)
- **❓ Questions** - [GitHub Discussions](https://github.com/Sandler73/Windows-Security-Audit-Project/discussions)
- **🐛 Bug Reports** - [GitHub Issues](https://github.com/Sandler73/Windows-Security-Audit-Project/issues)
- **💬 Community** - [Security Community Forums]

### Stay Updated
- ⭐ **Star the repository** - Get notifications for new releases
- 👀 **Watch** - Follow development activity
- 🔔 **Subscribe to releases** - Get notified of new versions

### Security Issues
- Review [SECURITY.md](https://github.com/Sandler73/Windows-Security-Audit-Project/blob/main/SECURITY.md) for vulnerability reporting
- Report security issues privately via GitHub Security Advisories
- Expected response time: 48-72 hours

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Current Version** | 6.1.2 |
| **Total Security Checks** | 3,994 |
| **Frameworks Covered** | 16 |
| **Code Base** | ~38,000 lines of PowerShell (modules: ~36,000 + orchestrator: ~2,400 + shared lib: ~1,800) |
| **Modules** | 16 specialized compliance modules |
| **Output Formats** | 5 native (HTML, JSON, CSV, XML, Console) + 6 browser-based exports |
| **Windows Versions Tested** | 10 (21H2+), 11 (21H2+), Server 2016, 2019, 2022, 2025 |
| **PowerShell Version** | 5.1+ |
| **Result Fields** | 9 (Module, Category, Status, Severity, Message, Details, Remediation, CrossReferences, Timestamp) |
| **Foundation Library Functions** | 39 |
| **Active Development** | ✅ Yes |

## 📄 Version History

### Version 6.1.2 (Current) - April 2026 (Patch)
- 🐛 **FIXED**: 24 `Get-BitLockerStatus -Cache` parameter-not-found errors across 13 modules
- 🐛 **FIXED**: 3 `Get-OSInfo -Cache` parameter-not-found errors
- 🐛 **FIXED**: 27 `[int]"None"` Int32 conversion errors in CIS/NIST/STIG (replaced with `ConvertTo-SafeInt`)
- 🐛 **FIXED**: No log file generated when `-LogFile` is omitted (shared library now auto-generates `logs\audit-yyyyMMdd-HHmmss.log`)
- 🐛 **FIXED**: `Write-AuditLog` was file-only (now emits color-coded console output, suppressible via `-Quiet`)
- 🐛 **FIXED**: Empty cache-stats display (corrected property names `ServicesCached`/`RegistryCached`/`HotFixesCached`/`LocalUsersCached`)
- ✨ **ADDED**: 15 DEBUG-level statements covering invocation context, prerequisites, module discovery, execution mode, per-module timing, export, completion summary
- ✨ **ADDED**: `-Quiet` and `-ScriptRoot` parameters on `Initialize-AuditLogging`

### Version 6.1.1 - April 2026 (Patch)
- 🐛 **FIXED**: `Get-CachedAuditPolicy` automation regression — function was Mandatory and required user input, breaking unattended runs (now optional + dual return mode: text or parsed objects)
- ✨ **ADDED**: Multiple help-invocation forms (`-Help`, `-H`, `-?`, `-ShowHelp`, `help`, `-help`, `--help`, `--h`, `/?`, `/help`, `/h`)
- ✨ **ADDED**: Comprehensive 10-section `Show-DetailedHelp` function (banner, synopsis, description, frameworks, parameters by group, examples, bundles, quick reference, requirements, more info)
- 📝 **UPDATED**: Comment-based help (`Get-Help`) now documents `-ShowHelp` parameter, all alias forms, and includes a help-invocation example

### Version 6.1.0 - April 2026 (Major Feature Release)
- ✨ **NEW**: Risk priority scoring (1-100 scale combining severity, exploitability, exposure, criticality) via `-ShowRiskPriority`
- ✨ **NEW**: Cross-framework correlation grouping via `-ShowCorrelations`
- ✨ **NEW**: Compensating control detection via `-ShowCompensatingControls`
- ✨ **NEW**: Baseline drift comparison via `-Baseline <path>`
- ✨ **NEW**: Rollback script generation via `-RollbackPath <path>`
- ✨ **NEW**: Group Policy `.pol` file export via `-ExportGPO <path>`
- ✨ **NEW**: Remediation bundles (`DisableLegacyProtocols`, `HardenAuthentication`, `EnableAuditLogging`, `LockDownRDP`, `EssentialEightLevel1`) via `-RemediationBundle`
- ✨ **NEW**: Pre-confirmation impact analysis for auto-remediation (reboot/logoff/service/network/destructive summary)
- 🔧 **EXPANDED**: 3,994 total checks (up from 3,199; +795 across all 16 modules)
- 🔧 **CONSOLIDATED**: NIST module categories (230 → 20) with control-family groupings; precise control IDs preserved in CrossReferences
- 🔧 **EXPANDED**: Foundation library — 10 new cross-cutting functions (`ConvertTo-RegistryRollback`, `ConvertTo-ServiceRollback`, `Get-RemediationImpact`, `Get-RiskPriorityScore`, `Find-CompensatingControls`, `Find-CrossFrameworkCorrelations`, `Compare-ToBaseline`, `Export-RegistryPolicyFile`, `Test-InternetFacingHost`, `Test-DomainControllerHost`)

### Version 6.0.5 - March 2026
- ✨ **NEW**: 8 new compliance modules (ACSC, CMMC, ENISA, GDPR, HIPAA, ISO27001, PCI-DSS, SOC2)
- 🔧 **EXPANDED**: Total checks increased from 1,855 to 3,199 across 16 modules
- 🔧 **IMPROVED**: XSL-styled XML output, report overhaul, 6 browser-based export formats

### Version 6.0.0 - March 2025
- ✨ **NEW**: Severity classification on every check (Critical/High/Medium/Low/Informational)
- ✨ **NEW**: Cross-framework correlation infrastructure
- ✨ **NEW**: Microsoft Defender for Endpoint module (86 checks)
- ✨ **NEW**: Standalone module execution support
- ✨ **NEW**: Cache-aware registry/service/policy helpers via shared library
- ✨ **NEW**: 9-field result objects (added Severity and CrossReferences)
- 🔧 **EXPANDED**: 1,855 total checks across 8 modules

### Version 5.3 - February 2025
- ✨ **NEW**: Interactive and automated remediation system
- ✨ **NEW**: Targeted remediation from HTML report selections
- ✨ **NEW**: SIEM-compatible XML output format
- ✨ **NEW**: Enhanced HTML reports with theme toggle
- ✨ **NEW**: Multi-format export from HTML (CSV, Excel, JSON, XML, TXT)
- 🔧 **IMPROVED**: Safety mechanisms for automated remediation
- 🐛 **FIXED**: Status value consistency across modules

### Version 5.0 - December 2024
- Complete rewrite with modular architecture
- 550+ security checks across 7 frameworks
- Multiple output formats (HTML, JSON, CSV)
- Comprehensive documentation

See [CHANGELOG.md](https://github.com/Sandler73/Windows-Security-Audit-Project/blob/main/CHANGELOG.md) for complete version history.

---

<div align="center">

**⭐ If this project helps you secure Windows systems, please consider giving it a star! ⭐**

**[⬆ Back to Top](#windows-security-audit-script)**

Made with ❤️ for the cybersecurity community

</div>
