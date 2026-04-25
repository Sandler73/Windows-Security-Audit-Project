# Changelog

All notable changes to the Windows Security Audit Script will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- GUI interface option
- Remote system auditing
- Historical trending and metrics dashboard
- PowerBI dashboard template

---

## [6.1.2] - 2026-04-25

### Patch — Test Feedback: Cache Errors, Account Policy Parsing, and Logging Wiring

**This patch resolves 30 errors observed during real-world testing of v6.1.1 plus three logging deficiencies that prevented effective debugging. The errors arose from helper-function API mismatches introduced during v6.1.0's Phase 1-4 module expansion, baseline `[int]` casts that failed on uninitialized `net accounts` policy fields, and a fundamental gap between the orchestrator's logging design and the shared library's implementation.**

### Fixed

- **`Get-BitLockerStatus -Cache` parameter mismatch (24 errors)** — v6.1.0 added 24 call sites passing `-Cache $SharedData.Cache` to `Get-BitLockerStatus`, but the function did not declare a `-Cache` parameter, causing PowerShell to throw "A parameter cannot be found that matches parameter name 'Cache'". The function now accepts `-Cache` for API consistency, serves cached results when present, populates the cache on first call, and returns both `IsEncrypted` and `SystemDriveProtected` properties (the latter expected by Phase 1-4 callers).
- **`Get-OSInfo -Cache` parameter mismatch (3 errors)** — Three v6.1.0 call sites passed `-Cache` to `Get-OSInfo`, which did not accept it. The function now accepts `-Cache` and serves the pre-populated `$Cache.OSInfo` when available, eliminating redundant CIM queries.
- **`[int]` cast failures on uninitialized `net accounts` fields (3 errors)** — Pre-existing baseline code in `module-cis.ps1`, `module-nist.ps1`, and `module-stig.ps1` cast `net accounts` policy strings directly to `[int]`. When Windows reports policy values as `None` or `Unlimited` (unset/disabled), the cast threw "Cannot convert value 'None' to type 'System.Int32'". 27 cast sites across the three modules now use the existing `ConvertTo-SafeInt` helper from `audit-common.ps1`, which returns `0` (or a configurable default) for non-numeric input.
- **No log file generated when `-LogFile` is omitted** — The shared library's `Initialize-AuditLogging` left `$script:LogFilePath = $null` when called without `-LogFile`, silently discarding all log messages. The shared library now auto-generates `<ScriptRoot>\logs\audit-yyyyMMdd-HHmmss.log` (or `.json` when `-JsonLog` is set) when `-LogFile` is empty. This matches the orchestrator's built-in fallback behavior, so the shared-library code path no longer regresses logging.
- **Logging silent on console (only writes to file)** — The shared library's `Write-AuditLog` only wrote to the log file, never the console, so when `-LogFile` was omitted (no file) and the shared library was loaded (no fallback), no log output appeared anywhere. `Write-AuditLog` now emits color-coded console output (`DarkGray` DEBUG, `Gray` INFO, `Yellow` WARNING, `Red` ERROR, `Magenta` CRITICAL) in addition to file output. Console emission is suppressible via `-Quiet` on `Initialize-AuditLogging`.
- **Empty cache stats display** — The orchestrator referenced `$cacheSummary.ServicesCount`, `$cacheSummary.RegistryCacheCount`, and `$cacheSummary.HotfixCount`, but `Get-CacheSummary` returns `ServicesCached`, `RegistryCached`, `HotFixesCached`, and `LocalUsersCached`. The console output `Cache initialized:  services,  registry keys` had empty interpolations because all property references were wrong. Property names now match; the display also includes local-user count.

### Added

- **DEBUG-level logging at major flow points** — v6.1.1 emitted almost no `-Level 'DEBUG'` messages, so `-LogLevel Debug` produced output indistinguishable from `-LogLevel Info`. v6.1.2 adds 15 DEBUG statements covering invocation context (PowerShell version, OS, user, admin status, parameter values), prerequisite checks, module discovery and selection, parallel/sequential execution mode, per-module start/complete with timing, export start/complete with file paths, and per-module timing summary at audit completion. Running with `-LogLevel Debug` now provides genuine deep-dive diagnostic visibility.
- **`-Quiet` and `-ScriptRoot` parameters on `Initialize-AuditLogging`** — The orchestrator now passes these so the shared library can suppress console output in quiet mode and locate the correct directory for auto-generated logs.

### Verification

- All 18 `.ps1` files brace-balanced (delta 0)
- Zero non-ASCII, zero BOMs, zero AI patterns, zero `$null` wrong-side comparisons
- Total check count preserved at 3,994
- All 16 modules retain exactly 1 `return $results` statement
- All 18 file headers and `$moduleVersion`/`$script:ScriptVersion`/`$script:COMMON_LIB_VERSION` synchronized at 6.1.2
- 27 of 27 bad `Get-BitLockerStatus -Cache` calls and 3 of 3 bad `Get-OSInfo -Cache` calls now resolve correctly (function signatures updated)
- 27 of 27 unsafe `[int]$var` casts replaced with `ConvertTo-SafeInt $var`

---

## [6.1.1] - 2026-04-25

### Patch — Post-Release Usability Fixes

**This patch resolves a critical regression introduced in v6.1.0 that broke automation in 9 modules, expands help system invocation forms, and substantially enriches the help content.**

### Fixed

- **`Get-CachedAuditPolicy` automation regression (CRITICAL)** — v6.1.0 introduced 23 call sites across 9 modules (acsc, enisa, gdpr, hipaa, iso27001, nist, pcidss, soc2, stig) that invoked `Get-CachedAuditPolicy` without `-Subcategory`. Because the function declared `Subcategory` as `Mandatory=$true`, PowerShell prompted the user for input on every call, breaking unattended automation. Additionally, the v6.1.0 callers expected object output (`.Subcategory`, `.Setting` properties) while the function returned raw text strings.
  - The function signature now declares `Subcategory` as optional (default `""`).
  - When `-Subcategory` is provided, the original v6.0 string-returning behavior is preserved (full backward compatibility).
  - When `-Subcategory` is omitted, the function parses the entire `auditpol /get /category:*` output and returns a `PSCustomObject[]` array with `Category`, `Subcategory`, and `Setting` properties — matching the v6.1.0 calling pattern.

### Added

- **Multiple help invocation forms** — The previous release only supported PowerShell's built-in `-?`. v6.1.1 recognizes:
  - Bound aliases: `-Help`, `-H`, `-ShowHelp`, `-?`
  - Non-standard forms (caught via `[Parameter(ValueFromRemainingArguments=$true)]`): `help`, `-help`, `--help`, `--h`, `/?`, `/help`, `/h`
- **Comprehensive `Show-DetailedHelp` function** — Replaces the minimal previous help with a 10-section help screen:
  1. Banner with version
  2. SYNOPSIS with all switch groups
  3. DESCRIPTION
  4. SUPPORTED FRAMEWORKS (16 modules, descriptions)
  5. PARAMETERS sectioned by purpose: Module Selection/Output, Remediation, v6.1 Cross-Cutting Capabilities, Performance and Caching, Logging, Help
  6. EXAMPLES (10 worked examples covering all major workflows)
  7. REMEDIATION BUNDLES (v6.1 — all 5 bundles documented with control coverage)
  8. QUICK REFERENCE (Output Formats, Status Values, Severity Levels)
  9. REQUIREMENTS
  10. MORE INFORMATION (paths to docs)
- Color-coded output via `Write-Section`, `Write-SubSection`, `Write-Param`, `Write-Example` helpers.

### Changed

- Comment-based help (`Get-Help` integration) now documents `-ShowHelp` parameter, all alias forms, and includes a help-invocation example.

### Technical Notes

- Help detection runs at the very start of `Start-SecurityAudit` before any logging or initialization, so help displays cleanly without log noise or prerequisite checks.
- The `$RemainingArgs` catch-all is purely additive — it does not affect any existing parameter binding behavior.
- All 18 files brace-balanced; zero non-ASCII; zero BOMs; zero null wrong-side comparisons; total check count preserved at 3,994.

---

## [6.1.0] - 2026-04-25

### Major — Cross-Cutting Capability Release

**This release adds 795 new compliance checks across all 16 modules, introduces seven cross-cutting orchestrator capabilities, and consolidates the NIST module's 230 control-specific categories into 20 framework-aligned groupings while preserving precise control IDs in CrossReferences.**

### Added

#### Foundation Library — 10 New Cross-Cutting Functions
- **`ConvertTo-RegistryRollback`** — Computes the inverse Set-ItemProperty for any forward registry remediation by querying current value state before modification
- **`ConvertTo-ServiceRollback`** — Generates inverse service-state command (Stop/Start/StartupType) based on observed service state
- **`Get-RemediationImpact`** — Classifies remediation operational impact: reboot/logoff requirement, service disruption, network effect, reversibility
- **`Get-RiskPriorityScore`** — Computes 1-100 priority score combining severity, exploitability heuristics, exposure context, and asset criticality
- **`Find-CompensatingControls`** — Identifies failed checks where a passing related control may mitigate the risk (e.g., Credential Guard compensating for missing LSA Protection)
- **`Find-CrossFrameworkCorrelations`** — Groups results across modules that test the same underlying control (SMBv1, TLS protocols, LLMNR, Credential Guard, etc.) to reduce duplicate noise
- **`Compare-ToBaseline`** — Compares current results against a stored baseline JSON: identifies new failures, resolved findings, regressions, and stable findings
- **`Export-RegistryPolicyFile`** — Generates Group Policy `.pol` binary file with PReg signature from registry-modifying remediations
- **`Test-InternetFacingHost`** — Heuristic detection of internet exposure for risk scoring
- **`Test-DomainControllerHost`** — Detects DC role for criticality weighting

#### Orchestrator — 7 New Parameters
- **`-Baseline <path>`** — Compare to a previous audit JSON; report includes drift section with new/resolved/regressions
- **`-ExportGPO <path>`** — Generate Group Policy `.pol` file from selected remediations
- **`-RollbackPath <path>`** — Generate inverse-script alongside auto-remediation
- **`-RemediationBundle <name>`** — Apply predefined remediation collections: `DisableLegacyProtocols`, `HardenAuthentication`, `EnableAuditLogging`, `LockDownRDP`, `EssentialEightLevel1`
- **`-ShowRiskPriority`** — Add 1-100 risk priority score column to reports
- **`-ShowCorrelations`** — Add cross-framework correlation panel
- **`-ShowCompensatingControls`** — Add compensating-control mitigation panel
- Pre-confirmation impact analysis displays reboot/logoff/service/network/destructive counts before auto-remediation
- Per-item impact display in interactive remediation mode

#### Module Expansions (+795 checks across all 16 modules)

| Module | Baseline | New | Delta |
|--------|----------|-----|-------|
| acsc | 123 | 170 | +47 |
| cis | 223 | 260 | +37 |
| cisa | 231 | 289 | +58 |
| cmmc | 103 | 145 | +42 |
| core | 177 | 243 | +66 |
| enisa | 198 | 248 | +50 |
| gdpr | 133 | 183 | +50 |
| hipaa | 184 | 237 | +53 |
| iso27001 | 244 | 286 | +42 |
| ms-defenderatp | 86 | 155 | +69 |
| ms | 314 | 367 | +53 |
| nist | 474 | 520 | +46 |
| nsa | 173 | 225 | +52 |
| pcidss | 227 | 279 | +52 |
| soc2 | 124 | 162 | +38 |
| stig | 185 | 225 | +40 |
| **Total** | **3,199** | **3,994** | **+795** |

#### Coverage Highlights
- **acsc** — Essential Eight Maturity Level computation per strategy, ISM controls, PSPF alignment, ACSI 33 cryptographic protocols, broader Strategies to Mitigate, Australian Privacy Principles
- **cis** — CIS Controls v8 IG2/IG3 maturity, Cloud/Mobile/ICS-OT Companion Guides, workload-specific Benchmark detection (IIS/Exchange/SQL)
- **cisa** — KEV catalog (CVE-2017-0144, CVE-2021-34527, CVE-2023-24932, CVE-2020-1472), BOD 23-02, Secure by Design, Zero Trust Maturity Model (5 pillars), Cross-Sector CPGs v1.0.1, Bad Practices, Pre-Ransomware Notification
- **cmmc** — Level 1 basic safeguarding, Level 3 enhanced (NIST SP 800-172), SPRS scoring (DoD methodology), DFARS 252.204-7012, CDI/CUI handling
- **core** — Windows Hello, VBS+HVCI, Kernel DMA Protection, TPM 2.0 expanded, USB/removable storage, post-PrintNightmare hardening, Windows Sandbox, Enhanced Phishing Protection, MOTW preservation, Pluton, System Guard, kCET
- **enisa** — NIS2 Directive Art. 21, Cyber Resilience Act, Threat Landscape, Reference Incident Classification Taxonomy, IoC good practice, EUCC, DORA, AI Threat Landscape
- **gdpr** — ePrivacy Directive, Schrems II / EDPB Recommendations 01/2020, data subject rights (Art. 15-21), Art. 28 processor, Art. 32(1)(b) CIA + resilience, Art. 35 DPIA, pseudonymisation
- **hipaa** — HHS Recognized Security Practices, NIST SP 800-66 R2, HITECH Sec. 13402(h)/13405(c), 405(d) HICP, Sec. 164.312(a)(2)(iv), Sec. 164.312(e)(2)(ii), Breach Notification Sec. 164.402, 21st Century Cures Sec. 4004, ONC Sec. 170.315
- **iso27001** — ISO 27002:2022 implementation guidance, ISO 27017/27018 cloud, ISO 27701 privacy, automated SoA computation, ISO 27005 risk + 27031 ICT continuity, Annex A.5/A.7
- **ms-defenderatp** — Component currency (engine/platform/signature/NIS), Network Protection per-profile, CFA, Enhanced Phishing Protection, WDAC enumeration, device tagging, Defender for Identity, per-rule ASR (15 GUIDs), plan detection, Live Response, Cloud Apps, custom IOCs
- **ms** — Win11 24H2 / Server 2025 baseline, Edge security baseline, M365 Apps for Enterprise, SCT/LGPO indicators, Pluton + DRTM, Smart App Control, cloud-managed update channels
- **nist** — SP 800-53 Rev 5 extended controls, CSF 2.0 with new GOVERN function, SP 800-171 Rev 3, SP 800-207 Zero Trust Architecture, SP 800-161 Supply Chain Risk Management, FedRAMP Rev 5
- **nsa** — Expanded CSI (CredGuard/AppWhitelist/HVCI), AD hardening (DC + member), Top 10 Mitigation Strategies, BlackLotus (CVE-2023-24932 / KB5025885), CSfC prerequisites, Network Infrastructure Security, IPv6 hardening (Teredo/ISATAP)
- **pcidss** — v4.0.1 Customized Approach, SAQ environment detection, CHD discovery readiness, network segmentation validation, SAD post-authorization prohibition, Req 9 physical security, PCI PIN Security + 3DS Core, PCI Software Security Framework
- **soc2** — Processing Integrity (PI) criteria, Privacy (P) criteria, Type II evidence collection, AICPA TSP Section 100 Points of Focus, common subject matter mappings
- **stig** — SRG cross-mapping (SRG-OS-000004/000033/000185/000257), V-finding format consistency, STIG Viewer compatibility, Microsoft Defender Antivirus STIG, BlackLotus mitigation, CAT I/II/III distribution

### Changed

#### NIST Module Category Consolidation (230 → 20)
- Pre-v6.1: one Category per individual control (e.g., `NIST - AC-2(11)`, `NIST - AC-2(12)`, `NIST - AC-3(7)`) producing 230 distinct categories
- v6.1: control-family groupings (`NIST - AC Access Control`, `NIST - AU Audit Accountability`, `NIST - SI System Information Integrity`, etc.) plus 12 framework-extension categories (CSF GV/PR/DE/RC/RS, ID.AM, 800-53 Rev 5 Extended, 800-171 Rev 3, 800-207 Zero Trust, 800-161 SCRM, FedRAMP Rev 5, CSF 2.0 Mapping)
- Precise control IDs preserved in `CrossReferences` hashtables (e.g., `@{ NIST='AC-2(11)' }`) — no traceability loss
- 466 Category strings transformed; 429 CrossReferences hashtables verified byte-identical pre/post
- Reduces report category clutter while retaining full audit traceability

### Verification
- All 18 files brace-balanced (zero delta)
- Zero non-ASCII characters across the codebase
- Zero BOM bytes
- Zero AI linguistic patterns in any module
- Zero `$null` wrong-side comparisons
- All `return $results` statements preserved
- All 18 file headers synchronized at Version 6.1

---

## [6.0.5] - 2026-03-03

### Major — Full Multi-Framework Parity Release

**This release doubles the framework coverage from 8 to 16 modules and completely overhauls the HTML reporting engine with interactive export capabilities.**

### Added

#### 8 New Compliance Modules
- **module-acsc.ps1** — Australian Cyber Security Centre Essential Eight (123 checks, 8 strategies: Application Control, Patch Applications, Office Macros, App Hardening, Admin Privileges, Patch OS, MFA, Backups)
- **module-cmmc.ps1** — CMMC 2.0 Level 2 (103 checks, 7 control families: Access Control, Audit, Config Mgmt, Authentication, Media, Communications, System Integrity)
- **module-enisa.ps1** — ENISA Cybersecurity Good Practices (198 checks, 10 categories: Network Security, IAM, Patch Mgmt, Cryptography, Logging, Data Protection, Incident Response, Hardening, Web Security, Endpoint)
- **module-gdpr.ps1** — GDPR Technical Controls (133 checks across Articles 5, 25, 32, 33-34: Privacy by Design, Encryption, Confidentiality, Availability, Testing, Breach Response)
- **module-hipaa.ps1** — HIPAA Security Rule (184 checks, 8 safeguard areas: Access Control, Administrative, Audit Controls, Authentication, Integrity, Physical Safeguards, Transmission Security, ePHI Protection)
- **module-iso27001.ps1** — ISO/IEC 27001:2022 Annex A (244 checks, 13 control categories: Organizational, People, Physical, Authentication, Backup, Configuration, Cryptography, Endpoint, Hardening, Logging, Network Security, Privileged Access, Vulnerabilities)
- **module-pcidss.ps1** — PCI DSS v4.0 (227 checks, 11 requirements: Network Security, Secure Config, Stored Data, Crypto Transit, Malware, Secure Systems, Access Control, Authentication, Logging, Testing, Policies)
- **module-soc2.ps1** — SOC 2 Type II Trust Service Criteria (124 checks, 6 categories: Control Activities, Logical Access, Operations, Change Mgmt, Availability, Confidentiality)

#### HTML Report Overhaul
- **Severity cards** — new card row below status summary showing Critical/High/Medium/Low/Informational distribution with click-to-filter
- **Export modal** — replaced per-module buttons with global "Export All" / "Export Selected" modal offering 6 formats: CSV, Excel (XLS), JSON, XML Workbook (XSL-styled), SIEM-compatible XML, Plain Text
- **Category detail tables** — expanded per-module breakdowns showing every check category with pass/fail/warn/info/error counts and per-category compliance score
- **Remediation Priority Ranking** — collapsible Top 50 findings ranked by severity, placed after all module sections
- **Overall Compliance cards** — replaced inline text with 4 color-coded cards: Weighted Score, Overall Rating, Simple Score, Severity-Adjusted Score
- **Deep navy dark theme** — color scheme (#0b0e14, #111822, #1a2332) matching Linux Security Audit report
- **Table of Contents** — moved below host info cards with Remediation Priority entry, collapsible
- **Automatic JSON companion** — every audit generates structured JSON alongside HTML regardless of OutputFormat setting
- **XSL-styled XML Workbook** — XML export renders as styled HTML in browsers via embedded XSLT

#### Console Output Enhancements
- All 16 modules display all 5 severity levels in summary (including zero counts)
- STIG module includes dedicated CAT I/II/III breakdown with total and failed counts per category

### Changed
- Removed HTML auto-open behavior (users open report manually)
- Removed Print button from report banner (browser native print sufficient)
- Status Distribution panel narrowed with vertical legend, Module Compliance given more width
- Banner simplified: centered text, theme toggle top-right corner
- Subtitle changed to "Comprehensive Multi-Framework Security Assessment"

### Enhanced
- All 8 original modules expanded with additional checks, cross-references, and severity coverage
- Total checks increased from 1,855 to 3,199 across 16 modules
- Total module code increased from ~8,000 to 31,457 lines

---

## [6.0.0] - 2025-03-03

### Major — Architecture and Quality Overhaul

**This release represents a comprehensive enhancement of every module in the project, tripling total check coverage and introducing cross-framework correlation, severity classification, and standalone execution capabilities.**

### Added

#### New Module
- **Module-MS-DefenderATP.ps1** — Microsoft Defender for Endpoint (ATP/EDR) module with 86 checks across 14 categories: Onboarding, EDR Block Mode, Connectivity, Scanning, Tamper Protection, ASR Details, Exclusions Audit, AIR, TVM, Custom Indicators, Device Control, Network Protection, Web Filtering, and Advanced Features

#### Severity Classification System
- Every check across all 16 modules now emits a `-Severity` field (Critical, High, Medium, Low, Informational)
- Severity mapping follows framework-native risk levels: STIG CAT I → Critical/High, CAT II → High/Medium, CAT III → Medium/Low; NIST control families mapped by impact level; CISA CPGs mapped by threat category
- Summary banners display severity distribution for failed checks
- 3,199 total checks with 3,199 Severity classifications (100% coverage)

#### Cross-Reference Framework Correlation
- New `-CrossReferences` hashtable parameter on every applicable check
- Maps each check to equivalent controls across NIST SP 800-53, CIS Benchmarks, DISA STIG V-IDs, NSA Guidance, CISA CPGs, and Microsoft Baselines
- 3,000+ cross-reference mappings across all modules (85% coverage; error-result checks excluded by design)
- Enables multi-framework compliance scoring from a single audit run

#### Cache-Aware Registry Helper
- All modules now include a `Get-RegValue` function with SharedData cache integration
- When `audit-common.ps1` is present, registry queries are served from a centralized cache, eliminating redundant reads across modules
- Graceful fallback to direct `Get-ItemProperty` when cache is unavailable
- Cache state reported in summary banners and standalone output

#### Standalone Execution Support
- Every module can now be invoked directly (e.g., `.\module-cis.ps1`) without the main orchestrator
- Standalone mode auto-initializes SharedData (ComputerName, OSVersion, IPAddresses, IsAdmin, ScanDate)
- Attempts cache warmup if `shared_components/audit-common.ps1` is found
- Produces detailed standalone analysis: status distribution with visual bars, category coverage breakdown
- `$moduleVersion` variable referenced in header, summary banner, and standalone output

#### New Check Sections by Module

**Module-Core.ps1** (40 → 176 checks, +340%)
- Hardware Security (15 checks): Secure Boot, UEFI, TPM 2.0, VBS, HVCI, DEP enforcement
- TLS Configuration (6 checks): Protocol enforcement, cipher suites
- PowerShell Security (11 checks): Script Block Logging, Transcription, Constrained Language Mode, v2 engine removal
- AutoPlay/AutoRun (5 checks), Disk Space (4 checks), Name Resolution (5 checks)

**Module-CIS.ps1** (100 → 222 checks, +122%)
- Credential Protection (10 checks): WDigest, Credential Guard, LSASS protection
- DNS Client hardening (11 checks), MSS Registry (21 checks)
- PowerShell Security (14 checks), BitLocker (7 checks)
- Additional Security (14 checks): certificate padding, font blocking, WPAD

**Module-NSA.ps1** (60 → 172 checks, +187%)
- Certificate Trust Management (16 checks): third-party root CAs, certificate pinning, revocation
- Wireless Security (15 checks): Wi-Fi Sense, hotspot reporting, WPA3 assessment
- Exploit Mitigation (8 checks): ASLR, CFG, SEHOP, ACG, CIG
- Network Protocol Security (9 checks): LLMNR, mDNS, WPAD, NetBIOS

**Module-CISA.ps1** (80 → 230 checks, +188%)
- Supply Chain Risk Management (9 checks): PSGallery trust, driver signing, WDAC, WSUS
- Zero Trust Architecture Alignment (15 checks): identity/device/network/data/visibility pillars
- BOD 22-01/23-01 Compliance (13 checks): KEV patch deadlines, asset visibility, vulnerability scanning

**Module-STIG.ps1** (90 → 184 checks, +104%)
- Credential Protection and LSA Hardening (18 checks): WDigest, Credential Guard, RunAsPPL, LM hash, NTLMv2, anonymous SID translation
- TLS/SSL Protocol Enforcement (13 checks): SSL 2.0/3.0 disabled, TLS 1.0/1.1 disabled, TLS 1.2 enforcement, NULL ciphers
- Hardware Security (14 checks): Secure Boot, VBS, DEP, SEHOP, TPM

**Module-NIST.ps1** (50 → 473 checks, +846%)
- 18 NIST 800-53 Rev 5 Control Families with deep check coverage:
  - Access Control (AC): 90+ checks across AC-2 through AC-22
  - Audit and Accountability (AU): 55+ checks
  - Identification and Authentication (IA): 70+ checks
  - System and Communications Protection (SC): 85+ checks
  - System and Information Integrity (SI): 90+ checks
  - Configuration Management (CM): 40+ checks
  - Incident Response (IR), Media Protection (MP)
- NIST Cybersecurity Framework 2.0 mapping (all 6 functions: GV, ID, PR, DE, RS, RC)
- NIST 800-171 Rev 2 CUI protection controls

**Module-MS.ps1** (80 → 313 checks, +291%)
- 33 check categories covering Microsoft's full Security Baseline scope
- Credential Protection (16 checks), Device Guard (16 checks), UAC (16 checks)
- PowerShell Security (18 checks), SMB Security (15 checks)
- BitLocker (11 checks), Defender AV (27 checks)
- LAPS, LDAP Security, Edge Security, Office Security, WinRM

### Changed

#### Enhanced Add-Result Output Format
- Result objects expanded from 7 fields to 9 fields:
  - `Module`, `Category`, `Status`, **`Severity`** (new), `Message`, `Details`, `Remediation`, **`CrossReferences`** (new), `Timestamp`
- All module `Add-Result` function signatures updated with `[ValidateSet()]` on Severity parameter
- Consistent output object schema across all 16 modules

#### Module Summary Banners
- All modules now display enhanced completion banners with:
  - Module version number
  - Pass/Fail/Warning/Info/Error counts with pass percentage
  - Category breakdown with check counts per category
  - Severity distribution for failed checks (Critical/High/Medium/Low)

#### Code Quality Improvements
- `$null` comparisons corrected to left-side placement (`$null -ne $var`) across all modules
- Reserved variable conflicts eliminated (`$profile` → `$fwProfileObj`, `$host` → `$hostObj`, etc.)
- try/catch blocks verified balanced across all modules (totals: Core=36, CIS=35, NSA=42, CISA=47, STIG=36, NIST=92, MS=72, MS-DefenderATP=24)
- All file headers updated to Version 6.0 with comprehensive SYNOPSIS blocks

### Fixed
- **Module-STIG.ps1**: `$anonSid` variable assigned but never used — replaced with `$anonSidTranslation`, split into two proper checks (SID/Name translation + enumeration restrictions), adding 2 new checks
- **Module-NIST.ps1**: Add-Result function signature declared `$Priority` parameter but output object referenced `$Severity` (unbound variable) — corrected parameter name and added missing `$CrossReferences` parameter
- **Module-NIST.ps1**: `-Priority` parameter replaced with `-Severity` across all 473 check calls
- **Module-MS.ps1**: `$profile` reserved variable collision with PowerShell's `$PROFILE` automatic variable — renamed to `$fwProfileObj` in firewall section
- **Module-STIG.ps1**: Audit Policy section missing outer try/catch — wrapped with proper error handling

### Documentation
- Complete overhaul of all 14 documentation files (5 project + 9 wiki)
- README updated with accurate check counts, module inventory, and v6.0 feature descriptions
- Module Documentation rewritten with per-module category tables and accurate check counts
- LICENSE enhanced with supplementary Liability, Warranty, and Copyright Notice sections
- CHANGELOG restructured with comprehensive v5.3 and v6.0 entries
- All wiki pages updated for 8-module architecture and 9-field output format

---

## [5.3.0] - 2025-02-15

### Added
- **Interactive HTML Reports** with dark/light theme toggle
- **Advanced filtering and sorting** per column in HTML output
- **Multi-format export** from HTML reports (CSV, Excel, JSON, XML, TXT)
- **Checkbox-based selective export** for targeted remediation
- **Executive dashboard** with compliance statistics in HTML reports
- **SIEM-Compatible XML** output format for security monitoring platforms
- **Interactive Remediation** — review and apply fixes individually with `-RemediateIssues`
- **Automated Remediation** — batch fix with safety confirmations via `-AutoRemediate`
- **Selective Remediation** — target specific status types (`-RemediateIssues_Fail`, `-RemediateIssues_Warning`, `-RemediateIssues_Info`)
- **Targeted Remediation** — fix only selected issues from JSON export via `-RemediationFile`
- **Remediation Logging** — comprehensive audit trail of all changes applied
- **Safety Mechanisms** — double-confirmation and countdown timers for destructive operations
- **Result Validation** — automated data integrity checks and status normalization

### Changed
- Output formats expanded from 3 (HTML, JSON, CSV) to 5 (HTML, JSON, CSV, XML, Console)
- HTML report engine completely rewritten with interactive features

---

## [5.0.0] - 2024-12-25

### Added
- **Complete project rewrite** with modular architecture
- **Module-Core.ps1** — Foundational Windows security baseline (40+ checks)
- **Module-STIG.ps1** — DISA STIG compliance with CAT I/II/III categorization (90+ checks)
- **Module-NIST.ps1** — NIST 800-53 Rev 5 and Cybersecurity Framework (50+ checks)
- **Module-CIS.ps1** — CIS Benchmarks for Windows (100+ checks)
- **Module-NSA.ps1** — NSA Cybersecurity guidance (60+ checks)
- **Module-CISA.ps1** — CISA Cybersecurity Performance Goals (80+ checks)
- **Module-MS.ps1** — Microsoft Security Baselines and SCT (80+ checks)
- **Total of 550+ automated security checks** across all modules
- **Multiple output formats**: HTML, JSON, and CSV
- **Executive summary** with compliance statistics
- **Color-coded console output** for real-time monitoring
- **Comprehensive error handling** with graceful degradation
- **Detailed remediation guidance** with PowerShell commands
- **Module selection capability** — run all or specific modules
- **Custom output directory** support
- **Verbose and debug modes** for troubleshooting

### Changed
- **Complete architecture redesign** from monolithic to modular
- **Improved performance** — optimized checks for faster execution
- **Enhanced reporting** — more detailed findings with framework mappings
- **Better categorization** — Pass/Fail/Warning/Info/Error status levels
- **Standardized module structure** for consistency and maintainability

### Fixed
- **Audit policy null reference errors** with proper error handling
- **Profile variable colon syntax issues** across all modules
- **BitLocker checks** now handle unsupported editions gracefully
- **Windows Defender checks** properly detect third-party AV scenarios
- **Event log enumeration** with improved error handling
- **Remote Desktop checks** more reliable across Windows versions

### Documentation
- Comprehensive README with quick start and examples
- Wiki pages: Quick Start, Usage Guide, Framework Reference, Troubleshooting, Module Documentation
- CONTRIBUTING.md for developer guidance

---

## [4.0.0] - 2024-XX-XX (Previous Version)

### Note
Version 4.x and earlier used a monolithic script design. Version 5.0 represents a complete rewrite.

---

## Version Comparison

| Version | Modules | Checks | Output Formats | Key Feature | Architecture |
|---------|---------|--------|----------------|-------------|--------------|
| 6.1.0   | 16      | 3,994  | HTML, JSON, CSV, XML, Console + 6 browser exports | Cross-cutting capabilities: risk priority, correlations, baseline drift, rollback, GPO export, bundles | Modular, cache-aware |
| 6.0.5   | 16      | 3,199  | HTML, JSON, CSV, XML, Console + 6 browser exports | 8 new frameworks, XSL-styled XML, report overhaul | Modular, cache-aware |
| 6.0.0   | 8       | 1,855  | HTML, JSON, CSV, XML, Console | Severity + CrossReferences | Modular, cache-aware |
| 5.3.0   | 7       | 550+   | HTML, JSON, CSV, XML, Console | Remediation + Interactive HTML | Modular |
| 5.0.0   | 7       | 550+   | HTML, JSON, CSV | Multi-framework modular | Modular |
| 4.x     | N/A     | ~200   | HTML only | Basic scan | Monolithic |

---

## Upgrade Notes

### Migrating from 5.x to 6.0

**Non-Breaking Changes:**
- All existing command-line parameters remain compatible
- Output format is backwards-compatible (2 new fields appended)
- Module names unchanged for the original 7 modules

**New Capabilities:**
- Results now include `Severity` and `CrossReferences` fields — update any custom parsers
- New module `MS-DefenderATP` available for selection
- Modules can be run standalone for targeted testing
- Enhanced summary output in console

**Migration Steps:**
1. Replace module files in `modules/` directory
2. Update any report-parsing logic to handle 9-field output objects
3. Add `MS-DefenderATP` to module selection if Defender for Endpoint assessment is desired
4. Review enhanced HTML reports for new severity and cross-reference columns

### Migrating from 4.x to 5.0

**Breaking Changes:**
- Command-line parameters have changed
- Output format is different
- Module organization is new

**Migration Steps:**
1. Back up any custom modifications to 4.x script
2. Download/clone version 6.0 (current)
3. Update any automation scripts to use new parameters:
   ```powershell
   # Old (4.x)
   .\SecurityAudit.ps1 -Type Full
   
   # New (6.0)
   .\Windows-Security-Audit.ps1 -Modules Core,STIG,NIST,CIS,NSA,CISA,MS,MS-DefenderATP
   ```
4. Update report parsing logic for new formats
5. Test thoroughly before production use

---

## Support Policy

### Supported Windows Versions

| Version | Support Status | Notes |
|---------|---------------|-------|
| Windows 11 | ✅ Fully Supported | Latest builds tested |
| Windows 10 | ✅ Fully Supported | 21H2 and later |
| Server 2025 | ✅ Fully Supported | Latest builds tested |
| Server 2022 | ✅ Fully Supported | Latest builds tested |
| Server 2019 | ✅ Fully Supported | All builds |
| Server 2016 | ✅ Fully Supported | All builds |
| Windows 10 <21H2 | ⚠️ Limited Support | May work but not actively tested |
| Windows 8.1 | ❌ Not Supported | End of life |
| Server 2012 R2 | ❌ Not Supported | End of extended support |

### PowerShell Versions

| Version | Support Status |
|---------|---------------|
| 7.x | ✅ Fully Compatible |
| 5.1 | ✅ Fully Supported (Minimum) |
| 5.0 | ⚠️ May Work |
| <5.0 | ❌ Not Supported |

---

## Credits

### Acknowledgments

This project builds upon the work of:
- **DISA** — Security Technical Implementation Guides
- **NIST** — Cybersecurity frameworks and controls
- **CIS** — Community-developed benchmarks
- **NSA** — Nation-state threat mitigation guidance
- **CISA** — Critical infrastructure protection guidance
- **Microsoft** — Security baselines and tools
- **Open-source community** — PowerShell modules and tools

See [Framework Reference](https://github.com/Sandler73/Windows-Security-Audit-Project/wiki/Framework-Reference) for detailed citations.

## License

This project is licensed under the MIT License — see the [LICENSE](https://github.com/Sandler73/Windows-Security-Audit-Project/blob/main/LICENSE) file for details.

---

**Note**: This changelog will be updated with each release. Subscribe to repository releases to stay informed of updates.
