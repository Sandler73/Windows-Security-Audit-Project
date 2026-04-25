<!--
============================================================================
Windows Security Audit Project - Pull Request
============================================================================

Thank you for contributing! Please complete every applicable section below.
PRs missing required information may be closed or held until completed.

Before opening this PR, ensure you have read:
  - docs/project/CONTRIBUTING.md (full contribution guide)
  - docs/wiki/Development Guide.md (architecture & coding patterns)
  - docs/project/SECURITY.md (security review requirements)

============================================================================
-->

## 📝 Summary

<!-- One- or two-sentence summary of what this PR does. -->



## 🎯 Type of Change

<!-- Check ALL that apply -->

- [ ] 🐛 Bug fix (non-breaking change that resolves an issue)
- [ ] ✨ New feature (non-breaking change that adds capability)
- [ ] ➕ New check within an existing module
- [ ] 📚 New compliance module
- [ ] 🔧 Refactor (no functional change, code quality improvement)
- [ ] ⚡ Performance improvement
- [ ] 🛡️ Security fix or hardening
- [ ] 📖 Documentation update
- [ ] 🧪 Test improvement (adding/updating tests, fixing flaky tests)
- [ ] 🔨 Build / CI / tooling change
- [ ] 💥 Breaking change (would cause existing usage to break)

## 🔗 Related Issues

<!--
Closes #123          (will auto-close on merge)
Relates to #456      (mentioned but not closed)
-->



## 📋 Description

<!--
Detailed description. What problem does this solve? What is the approach?
Why this approach over alternatives?
-->



## 🧱 Module / Component Impact

<!-- Check ALL components touched by this PR -->

### Modules
- [ ] acsc
- [ ] cis
- [ ] cisa
- [ ] cmmc
- [ ] core
- [ ] enisa
- [ ] gdpr
- [ ] hipaa
- [ ] iso27001
- [ ] ms
- [ ] ms-defenderatp
- [ ] nist
- [ ] nsa
- [ ] pcidss
- [ ] soc2
- [ ] stig

### Project-wide components
- [ ] Orchestrator (`Windows-Security-Audit.ps1`)
- [ ] Shared library (`shared_components/audit-common.ps1`)
- [ ] Tests (`tests/*.Tests.ps1`)
- [ ] CI/CD workflows (`.github/workflows/*.yml`)
- [ ] Issue / PR templates (`.github/ISSUE_TEMPLATE/`)
- [ ] Documentation — project (`docs/project/`)
- [ ] Documentation — wiki (`docs/wiki/`)
- [ ] Tasks (`tasks/`)
- [ ] `.gitignore`

## 🔢 Check Count Delta

<!--
For PRs that add or remove checks, document the count change.
This helps maintainers verify the v6.1.2 baseline of 3,994 checks
remains accurate, or that the bump in count is intentional.

Run after your changes:
    grep -c "Add-Result" modules/module-<name>.ps1

Skip this section if your PR doesn't change check counts.
-->

| Module | Before | After | Delta |
|--------|-------:|------:|------:|
|        |        |       |       |

**Total project check count after this PR:** <!-- e.g., 3,994 → 3,997 (+3) -->

## 🧪 Testing Performed

<!-- Document what testing you did. PRs without testing evidence may be held. -->

- [ ] Ran the full Pester suite locally: `Invoke-Pester -Path .\tests\`
- [ ] All existing Pester tests pass
- [ ] Added new Pester tests covering this change
- [ ] Manually verified on Windows 11 (version: ___)
- [ ] Manually verified on Windows 10 (version: ___)
- [ ] Manually verified on Windows Server 2025 (build: ___)
- [ ] Manually verified on Windows Server 2022 (build: ___)
- [ ] Manually verified on Windows Server 2019 (build: ___)
- [ ] Manually verified on Windows Server 2016 (build: ___)
- [ ] Tested with PowerShell 5.1 (Desktop)
- [ ] Tested with PowerShell 7.x (Core)
- [ ] Tested standalone module execution (`& .\modules\module-XXX.ps1 -SharedData @{Cache=@{}}`)
- [ ] Tested via orchestrator (`.\Windows-Security-Audit.ps1 -Modules <module>`)
- [ ] Tested with `-Parallel -Workers 4`
- [ ] Tested with `-NoCache`
- [ ] Tested with `-LogLevel Debug -Verbose`
- [ ] Verified all 4 output formats render correctly (HTML, JSON, CSV, XML)

### Manual test commands

<!-- Paste exact commands and abbreviated relevant output -->

```powershell

```

## 🔍 Code Quality Checks

<!-- These are required gates. Confirm before submitting. -->

- [ ] **Brace balance verified:** every `.ps1` file I modified has equal `{` and `}` counts
- [ ] **ASCII-only:** every `.ps1` file I modified contains only ASCII characters (no smart quotes, em-dashes, ellipses, etc.)
- [ ] **No BOM:** every `.ps1` file I modified is saved without a UTF-8 BOM
- [ ] **PSScriptAnalyzer clean:** `Invoke-ScriptAnalyzer -Path .\modules,.\shared_components,.\Windows-Security-Audit.ps1 -Severity Error,Warning` produces no Errors
- [ ] **`$null` left-side comparisons:** I used `$null -eq $x` (not `$x -eq $null`)
- [ ] **No `$matches` shadowing:** I did not use `$matches` as a custom variable (it's a PowerShell automatic variable)
- [ ] **Single `return $results`:** every module file has exactly one `return $results` statement
- [ ] **No unused variables** introduced by this PR

## 📐 Code Conventions

- [ ] Comment-based help (`<# .SYNOPSIS / .DESCRIPTION ... #>`) is current and accurate
- [ ] Try/catch error handling around external system calls (registry, WMI, services, network)
- [ ] Specific exceptions caught where possible (not bare `catch {}`)
- [ ] All new external inputs validated
- [ ] No introduction of external runtime dependencies (zero pip/npm/nuget — PowerShell stdlib only)
- [ ] No outbound network calls during audit execution
- [ ] No credential handling
- [ ] All new functions documented with parameter help
- [ ] Code style consistent with surrounding code in the file

## 🔄 Version & Synchronization

<!-- For PRs that bump the version, ALL of these must be updated together. -->

- [ ] Version bump in `Windows-Security-Audit.ps1` (`$script:ScriptVersion`)
- [ ] Version bump in `shared_components/audit-common.ps1` (`$script:COMMON_LIB_VERSION`)
- [ ] Version bump in every modified module's header `Version:` field
- [ ] Version bump in every modified module's `$moduleVersion` variable
- [ ] `docs/project/CHANGELOG.md` updated with new version section
- [ ] `docs/project/README.md` version line updated
- [ ] Wiki `Changelog.md` updated
- [ ] Shield(s) in README updated if applicable

**OR** check this box if the PR does NOT bump the version:

- [ ] This PR does not change the version

## 📚 Documentation Updates

<!-- Check ALL that you have updated. -->

- [ ] `docs/project/CHANGELOG.md` -- added entry under `[Unreleased]` or new version
- [ ] `docs/project/README.md` -- updated if user-facing change
- [ ] `docs/wiki/<page>.md` -- updated relevant wiki pages
- [ ] `docs/wiki/_Sidebar.md` -- updated if new wiki pages added
- [ ] `tasks/sync_function.md` -- updated if functions added/removed
- [ ] Inline code comments updated
- [ ] Help text in `Show-DetailedHelp` updated if new CLI parameter

**OR** check this box if NO documentation needs updating:

- [ ] This PR is internal-only and requires no documentation updates

## 🛡️ Security Review

<!-- All PRs are expected to consider security implications. -->

- [ ] This PR does not introduce any new external runtime dependencies
- [ ] This PR does not introduce any outbound network calls during audit execution
- [ ] This PR does not handle, store, or transmit credentials
- [ ] This PR does not expand the remediation surface in unsafe ways
- [ ] If this PR adds remediation logic: dual-confirmation gating preserved
- [ ] If this PR adds remediation logic: rollback support is implemented or rationale documented
- [ ] No new code paths execute external binaries via shell expansion (use `&` operator with array splatting, not `Invoke-Expression`)
- [ ] No new code paths use `Invoke-Expression` against unvalidated input

## 📸 Screenshots / Output Samples

<!--
For UI changes (HTML report) or output format changes, include before/after screenshots
or sample output blocks. For internal changes, this section can be omitted.
-->



## ✅ Self-Review Checklist

- [ ] I have performed a self-review of my own code
- [ ] My commit messages are descriptive
- [ ] I have not committed any sensitive data (credentials, internal hostnames, real org names)
- [ ] I have not committed any audit output files (HTML/JSON/CSV/XML reports, log files)
- [ ] I have rebased my branch onto the latest `main` (or the PR is based on a recent commit)
- [ ] I have considered backward compatibility (or this PR is explicitly breaking and labeled as such)
- [ ] I am willing to address review feedback in a timely manner

## 📋 Reviewer Notes

<!--
Anything you want a reviewer to focus on?
Known limitations of this PR? Followup work?
-->



<!--
============================================================================
Maintainer Use Only
============================================================================

Pre-merge checklist:
  - [ ] CI workflows pass (lint, unit-tests, integration-tests)
  - [ ] Code coverage acceptable
  - [ ] No conflicts with main
  - [ ] Documentation diffs reviewed
  - [ ] Version sync verified across all 18 .ps1 files
  - [ ] Total Add-Result count consistent with claim
  - [ ] CHANGELOG correctly placed and formatted
============================================================================
-->
