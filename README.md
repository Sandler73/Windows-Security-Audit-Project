<p align="center">
  <img src="assets/header-wsap.png" alt="Windows Security Audit Project" width="75%" />
</p>

---

# Windows Security Audit — v6.1.2 Release Notes

**Release Date:** 2026-04-25
**Previous Version:** 6.0
**Status:** Release Candidate — verified

---

## Headline

v6.1 adds **795 new compliance checks** across all 16 modules, introduces **seven cross-cutting orchestrator capabilities**, and **consolidates the NIST module's category structure** from 230 control-specific entries to 20 framework-aligned groupings.

## What's New

### Cross-Cutting Capabilities (orchestrator)

| Switch | Effect |
|--------|--------|
| `-Baseline <path>` | Compare current results to a previous audit JSON; report includes drift section with new failures, resolved findings, regressions, and stable findings |
| `-ExportGPO <path>` | Generate a Group Policy `.pol` binary file from registry-modifying remediations |
| `-RollbackPath <path>` | Generate inverse-script alongside auto-remediation (uses pre-remediation state) |
| `-RemediationBundle <name>` | Apply predefined remediation collections: `DisableLegacyProtocols`, `HardenAuthentication`, `EnableAuditLogging`, `LockDownRDP`, `EssentialEightLevel1` |
| `-ShowRiskPriority` | Add 1-100 risk priority score (severity + exploitability + exposure + asset criticality) |
| `-ShowCorrelations` | Group same-control findings across modules (e.g., "SMBv1 Disabled" tested by 7 modules → one consolidated group) |
| `-ShowCompensatingControls` | Flag failed checks where a passing related control mitigates the risk |

Pre-confirmation impact analysis displays reboot/logoff/service/network/destructive impact summary before any auto-remediation begins.

### Module Coverage Expansions

All 16 modules expanded with new check coverage:

| Module | v6.0 | v6.1 | Delta |
|--------|------|------|-------|
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

### NIST Category Consolidation

Previously, the NIST module produced 230 distinct categories — one per individual 800-53 control (e.g., `NIST - AC-2(11)`, `NIST - AC-2(12)`). v6.1 groups these into **20 categories** by control family:

- 8 control families: AC, AU, CM, IA, IR, MP, SC, SI
- 12 framework-extension categories: CSF GV/PR/DE/RC/RS, ID.AM, 800-53 Rev 5 Extended, 800-171 Rev 3, 800-207 Zero Trust, 800-161 SCRM, FedRAMP Rev 5, CSF 2.0 Mapping

**Precise control IDs are preserved in the `CrossReferences` hashtable** (e.g., `@{ NIST='AC-2(11)' }`). 466 Category strings transformed; 429 CrossReferences hashtables verified byte-identical pre/post. No traceability loss.

## Verification Summary

- All 18 PowerShell files brace-balanced (zero delta)
- Zero non-ASCII characters
- Zero BOM bytes
- Zero AI linguistic patterns
- Zero `$null` wrong-side comparisons
- All `return $results` statements preserved
- All 18 file headers synchronized at Version 6.1
- Documentation consistent across CHANGELOG, README, Home.md, FAQ, all wiki pages

## Upgrade Notes

- **No breaking changes.** All 18 v6.0 orchestrator parameters and 29 v6.0 shared library functions are preserved unchanged.
- **Module standalone execution preserved.** Modules continue to run independently (`.\module-cis.ps1`); new cross-cutting functions are only invoked by the orchestrator.
- **Backward-compatible JSON schema.** Result objects retain all v6.0 fields; `-ShowRiskPriority` adds an optional `RiskPriority` property without altering existing fields.
- **Reports optionally enriched.** New panels (Risk Priority, Cross-Framework Correlations, Compensating Controls, Baseline Drift) are opt-in via switches.

## See Also

- [CHANGELOG.md](docs/project/CHANGELOG.md) — full version history
- [README.md](docs/project/README.md) — project overview, installation, usage
- [tasks/sync_function.md](tasks/sync_function.md) — component manifest and dependency map
