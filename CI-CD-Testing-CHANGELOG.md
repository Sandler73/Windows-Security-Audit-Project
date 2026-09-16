# CI/CD and Testing Changelog

Changes to the continuous integration pipeline, the automated test suites, and
the repository automation that supports them.

## Why this is separate from CHANGELOG.md

`CHANGELOG.md` records changes to the **product**: the audit framework, its
modules, its shared components, its reports, and the documentation shipped with
it. That is what a reader consults to understand what the tool does now that it
did not do before, or what defect affecting them was fixed.

Work on GitHub Actions workflows, Pester harnesses, runner images, and report
publishing does not change the product. Recording it alongside product history
obscures the signal a changelog exists to carry. It is tracked here instead, in
the same format, so the history is preserved without diluting the product record.

**Where a boundary case belongs:**

- A test that fails and thereby exposes a genuine defect in the framework: the
  **defect fix** is a product change and belongs in `CHANGELOG.md`; the test
  correction belongs here.
- A change to a shipped component that happens to be exercised by CI: product
  change, `CHANGELOG.md`.
- A test, workflow, or repository automation change with no effect on the
  shipped artefact: here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). These
entries are not versioned against the framework release number, because the
pipeline is not part of the released artefact; they are grouped by date.

---

## 2026-07-25

### Fixed

- Unit test summary job reported failure while every test passed. Pester writes
  NUnit-schema XML, but the report action was configured with a JUnit parser, so
  it aborted with `TypeError: Cannot read properties of undefined (reading '$')`.
  The reporter now matches the emitted schema; the publish step is non-blocking;
  and the job's verdict comes from a summary computed directly from the result
  files, which reads both NUnit and JUnit roots so a future format change cannot
  silently break reporting
- Self-hosted jobs queued indefinitely against runners that were not registered,
  burning roughly 500 minutes per run. `timeout-minutes` does not cover queue
  time, so the configured 30- and 45-minute limits never applied. All five
  self-hosted jobs across three workflows are now gated behind an
  `ENABLE_SELF_HOSTED` repository variable
- Hosted runner images: `windows-2019` was retired by GitHub in June 2025 and
  `windows-2022` did not provision. Jobs targeting an unavailable image queue
  rather than fail. Matrices now target `windows-2025` and `windows-latest`
- Unit test jobs executed only three of the fifteen Pester suites. The workflow
  carried a hardcoded file list, so every suite added since it was written was
  invisible to CI and could have been failing for several releases. Suites are
  now discovered from the tests directory
- End-to-end assertions located output non-recursively while reports are written
  to a per-host subdirectory, so nine tests failed to find files that existed.
  Searches are recursive and additionally assert that the containing directory
  is named for the audited host
- Version assertions were pinned to a fixed version string in four test files
  and failed on every release after the pin was written. The expected version is
  now derived from the orchestrator, which the project treats as the single
  source of truth. An intermediate fix placed the interpolating expression inside
  single-quoted PowerShell strings, which do not interpolate, leaving the pattern
  literal; patterns are now built in a variable
- A report assertion compared a section title containing `&` against rendered
  HTML, where it is encoded as `&amp;`
- Catalogue and help switches were passed to the orchestrator as variables, which
  binds them positionally to the first positional parameter and is rejected by its
  `ValidateSet`. Switches are splatted so they bind by name
- Catalogue output is written with `Write-Host`, which goes to the Information
  stream, so `2>&1` captured nothing and an emptiness check failed a working
  command. Redirection corrected

### Added

- `tests/comment-hygiene.Tests.ps1`: fails the build if version markers, phase or
  work-item identifiers, or process bookkeeping appear in code comments. Framework
  and product versions named in comments, and the CMMC rollout phases, are
  explicitly permitted
- `component-surface` integration job: loads every shared component, asserts each
  public entry point by name, and checks behavioural invariants including
  one-to-one topic-to-entry coverage and conservative handling of unknown impact
- `parameter-surface` integration job: exercises the operator-facing parameters
  added since v6.3, verifies documented help forms, confirms parameter validation
  is enforced, and checks that reports land in the documented output layout with
  hostnames in filenames
- `CodeQL` workflow. CodeQL has no PowerShell extractor, so pointing it at this
  repository alone would report coverage it does not provide; it is paired with a
  PowerShell security pass over injection, credential, and code-safety rules, plus
  remediation-safety invariants asserting that state capture precedes apply, that
  the typed confirmation gate is retained, that impact tiers add to rather than
  bypass it, and that post-apply verification is present
- `CODEOWNERS` and a Dependabot configuration covering the GitHub Actions used by
  CI. The framework itself has no runtime dependencies by design, but the
  pipeline's actions go stale

### Removed

- Documentation-accuracy workflow and its in-repository tooling. They were built
  against the development tree, which carries wiki and working-state directories
  that are not part of the published repository: wiki content is transferred to
  the GitHub wiki, and the task directory is development state. A gate that audits
  content the repository does not contain produces failures without value

---

## 2026-07-22

### Added

- Pester suites for the report template renderers and the audit profiles
  component; module schema baselines regenerated
