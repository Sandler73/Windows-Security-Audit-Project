# Windows Security Audit Script

<div align="center">

![Version](https://img.shields.io/badge/version-6.0-teal.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Server%202016%2B-lightgrey.svg)

[![Supported Frameworks](https://img.shields.io/badge/Supported%20Frameworks-ACSC%20%E2%80%A2%20CIS%20%E2%80%A2%20CISA%20%E2%80%A2%20CMMC%20%E2%80%A2%20ENISA%20%E2%80%A2%20MSB%20%E2%80%A2%20MDE%20%E2%80%A2%20NIST%20%E2%80%A2%20NSA%20%E2%80%A2%20STIG-cyan.svg)]()

[![Regulatory Compliance](https://img.shields.io/badge/Regulatory%20Compliance-GDPR%20%E2%80%A2%20HIPAA%20%E2%80%A2%20ISO%2027001%20%E2%80%A2%20PCI-DSS%20%E2%80%A2%20SOC%202-orange.svg)]()


[![Sponsor](https://img.shields.io/badge/Sponsor-Support%20the%20Project-vanilla.svg)](https://github.com/sponsors/Sandler73)

**Comprehensive Module-Based Multi-Framework Windows Security Assessment/Auditing & Remediation Tool**

[Overview](#-overview) • [Key Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Remediation Capabilities](#-remediation-capabilities) • [Contributing](#-contributing)

</div>

---

## 📋 Overview

The **Windows Security Audit Script** is an advanced PowerShell-based security compliance auditing tool that evaluates Windows systems against multiple industry-standard security frameworks. Version 6.0 introduces **severity classification**, **cross-framework correlation**, **cache-aware architecture**, and **standalone module execution**, building on the intelligent remediation, enhanced reporting, and SIEM integration introduced in v5.3.

The tool performs **3,199 automated security checks** across sixteen compliance modules, generating comprehensive reports in multiple formats with actionable remediation guidance. Every check now includes a severity rating and cross-references to equivalent controls across other frameworks, enabling multi-framework compliance scoring from a single audit run. Whether you're conducting compliance audits, hardening systems, or maintaining security baselines, this tool provides the insights and automation you need.

## 🎯 Key Features

### 🔍 **Comprehensive Security Assessment**
- ✅ **3,199 Security Checks** across 16 major security frameworks
- ✅ **Multi-Framework Coverage** — CIS, NIST, STIG, NSA, CISA, Microsoft, Microsoft Defender ATP, Core, ACSC Essential Eight, CMMC, ENISA, GDPR, HIPAA, ISO 27001, PCI DSS, SOC 2
- ✅ **Modular Architecture** — run all frameworks or select specific modules
- ✅ **Severity Classification** — every check rated Critical/High/Medium/Low/Informational
- ✅ **Cross-Framework Correlation** — 3,000+ cross-reference mappings linking checks to equivalent controls
- ✅ **Standalone Module Execution** — run any module independently for targeted testing
- ✅ **Result Validation** — automated data integrity checks and normalization
- ✅ **No External Dependencies** — pure PowerShell implementation using stdlib only

### 📊 **Advanced Reporting** _(Enhanced in 6.0)_
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

### 🆕 **New in Version 6.0**
- ✅ **Severity Classification** — every check classified by risk impact (Critical/High/Medium/Low/Informational)
- ✅ **Cross-Framework Mapping** — correlate findings across NIST, CIS, STIG, NSA, CISA
- ✅ **Cache-Aware Architecture** — registry query caching for performance optimization
- ✅ **Standalone Execution** — any module can run independently without the orchestrator
- ✅ **Microsoft Defender ATP Module** — 86 EDR/ATP-specific checks
- ✅ **8 New Compliance Frameworks** — ACSC Essential Eight, CMMC 2.0, ENISA, GDPR, HIPAA, ISO 27001:2022, PCI DSS v4.0, SOC 2 Type II
- ✅ **Interactive HTML Dashboard** — severity cards, category detail tables, export modal, remediation priority ranking
- ✅ **6 Browser Export Formats** — CSV, Excel (XLS), JSON, XML Workbook (XSL-styled), SIEM-compatible XML, Plain Text
- ✅ **Automatic JSON Companion** — structured JSON file generated alongside every HTML report
- ✅ **Deep Navy Dark Theme** — matching Linux Security Audit report styling
- ✅ **3.4× more checks** — expanded from 550+ to 3,199 total checks
- ✅ **9-Field Result Objects** — added Severity and CrossReferences to every check output


## 🏢 Supported Frameworks

| Module | Framework | Checks | Focus Areas |
|--------|-----------|--------|------------|
| **Core** | Foundational Windows Security Baseline | 177 | Essential system security, hardware, TLS, PowerShell |
| **CIS** | CIS Microsoft Windows Benchmarks v3.0+ | 223 | Industry best practices, credential protection, MSS registry |
| **MS** | Microsoft Security Baselines (SCT) | 314 | Defender, AppLocker, ASR, exploit protection, 33 categories |
| **MS-DefenderATP** | Microsoft Defender for Endpoint | 86 | EDR, onboarding, TVM, AIR, tamper protection |
| **NIST** | NIST 800-53 Rev 5, CSF 2.0, 800-171 | 474 | Federal compliance, 18 control families (AC, AU, IA, SC, SI, CM) |
| **STIG** | DISA Security Technical Implementation Guide | 185 | DoD requirements, CAT I/II/III, credential/TLS/hardware hardening |
| **NSA** | NSA Cybersecurity Information Sheets | 173 | Nation-state threat mitigation, certificate trust, wireless, exploit mitigation |
| **CISA** | CISA Cybersecurity Performance Goals | 231 | Critical infrastructure, Zero Trust, supply chain, BOD 22-01/23-01 |
| **ACSC** | Australian CSC Essential Eight | 123 | Application control, patching, macros, hardening, admin privileges, MFA, backups |
| **CMMC** | CMMC 2.0 Level 2 | 103 | Access control, audit, config management, authentication, media, comms, integrity |
| **ENISA** | ENISA Cybersecurity Good Practices | 198 | Network security, IAM, patch mgmt, cryptography, logging, data protection |
| **GDPR** | GDPR Technical Controls (Art. 5/25/32/33) | 133 | Privacy by design, encryption, confidentiality, availability, breach response |
| **HIPAA** | HIPAA Security Rule (45 CFR 164) | 184 | Access control, audit controls, authentication, integrity, transmission security |
| **ISO27001** | ISO/IEC 27001:2022 Annex A | 244 | Organizational, people, physical, authentication, backup, cryptography, hardening |
| **PCI-DSS** | PCI DSS v4.0 | 227 | Network security, secure config, stored data, crypto, malware, access control |
| **SOC2** | SOC 2 Type II Trust Service Criteria | 124 | Control activities, logical access, operations, change mgmt, availability |

**Total Coverage**: 3,199 security checks with severity classification and cross-framework correlation across access control, authentication, auditing, network security, data protection, malware defense, system hardening, EDR, Zero Trust architecture, privacy compliance, payment card security, and healthcare data protection.

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
    <total_checks>3199</total_checks>
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
    "TotalChecks": 3199,
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
                    Windows Security Audit Script v6.0
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
Total Checks:    3199
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
| **Current Version** | 6.0 |
| **Total Security Checks** | 3,199 |
| **Frameworks Covered** | 8 |
| **Code Base** | ~21,200 lines of PowerShell (modules: 19,593 + orchestrator: ~1,600) |
| **Modules** | 8 specialized compliance modules |
| **Output Formats** | 5 (HTML, JSON, CSV, XML, Console) |
| **Windows Versions Tested** | 10, 11, Server 2016/2019/2022 |
| **PowerShell Version** | 5.1+ |
| **Result Fields** | 9 (with Severity and CrossReferences) |
| **Cross-Reference Mappings** | 1,568 |
| **Active Development** | ✅ Yes |

## 📄 Version History

### Version 6.0 (Current) - March 2026
- ✨ **NEW**: Severity classification on every check (Critical/High/Medium/Low/Informational)
- ✨ **NEW**: Cross-framework correlation with 1,568 mappings
- ✨ **NEW**: Microsoft Defender for Endpoint module (86 checks)
- ✨ **NEW**: Standalone module execution support
- ✨ **NEW**: Cache-aware registry helpers
- ✨ **NEW**: 9-field result objects (added Severity and CrossReferences)
- 🔧 **EXPANDED**: 3,199 total checks (up from 550+)
- 🔧 **EXPANDED**: 16 modules (expanded from original 8)
- 🐛 **FIXED**: STIG $anonSid unused variable, NIST $Priority/$Severity mismatch, MS $profile reserved variable

### Version 5.3 - February 2026
- ✨ **NEW**: Interactive and automated remediation system
- ✨ **NEW**: Targeted remediation from HTML report selections
- ✨ **NEW**: SIEM-compatible XML output format
- ✨ **NEW**: Enhanced HTML reports with theme toggle
- ✨ **NEW**: Multi-format export from HTML (CSV, Excel, JSON, XML, TXT)
- ✨ **NEW**: Result validation and normalization system
- ✨ **NEW**: Comprehensive remediation logging
- 🔧 **IMPROVED**: Safety mechanisms for automated remediation
- 🔧 **IMPROVED**: Module statistics and execution tracking
- 🐛 **FIXED**: Status value consistency across modules
- 🐛 **FIXED**: Result object validation and repair

### Version 5.0 - December 2025
- Complete rewrite with modular architecture
- 550+ security checks across 7 frameworks
- Multiple output formats (HTML, JSON, CSV)
- Improved error handling and logging
- Comprehensive documentation

See [CHANGELOG.md](https://github.com/Sandler73/Windows-Security-Audit-Project/blob/main/CHANGELOG.md) for complete version history.

---

<div align="center">

**⭐ If this project helps you secure Windows systems, please consider giving it a star! ⭐**

**[⬆ Back to Top](#windows-security-audit-script)**

Made with ❤️ for the Windows security community

**[📖 Documentation](../../wiki/Home)** • **[🐛 Report Bug](https://github.com/Sandler73/Windows-Security-Audit-Project/issues)** • **[✨ Request Feature](https://github.com/Sandler73/Windows-Security-Audit-Project/issues)**

</div>
