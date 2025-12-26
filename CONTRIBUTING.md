# Contributing to Windows Security Audit Script

Thank you for considering contributing to this project! This document provides guidelines for contributing to make the process smooth and effective for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submission Process](#submission-process)
- [Module Development](#module-development)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive experience for everyone. We expect all contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

## How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
1. Check the [Troubleshooting Guide](https://github.com/Sandler73/Windows-Security-Audit-Script/wiki/Troubleshooting)
2. Search existing [Issues](https://github.com/Sandler73/Windows-Security-Audit-Script/issues) to avoid duplicates
3. Collect information about the bug

**When submitting a bug report, include:**
- Clear, descriptive title
- Exact steps to reproduce
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Environment details:
  - Windows version (e.g., Windows 11 Pro 23H2)
  - PowerShell version (`$PSVersionTable.PSVersion`)
  - Script version
  - Module(s) affected

**Example Bug Report:**
```markdown
## Bug Description
Module-STIG.ps1 fails on Windows Server 2016 when checking BitLocker

## Steps to Reproduce
1. Run script on Windows Server 2016 Standard
2. Include STIG module
3. Script errors when reaching BitLocker checks

## Expected Behavior
Should gracefully handle BitLocker not being available

## Actual Behavior
```
Get-BitLockerVolume : Access denied
```

## Environment
- OS: Windows Server 2016 Standard (Build 14393)
- PowerShell: 5.1.14393.5582
- Script Version: 5.0
```

### Suggesting Enhancements

**Before submitting an enhancement:**
1. Check if it's already been suggested
2. Determine which component it affects (orchestrator, specific module, output format)
3. Consider if it fits the project's scope

**When suggesting an enhancement:**
- Use a clear, descriptive title
- Provide detailed description of the enhancement
- Explain why this enhancement would be useful
- Provide examples of how it would be used
- List any alternative solutions you've considered

### Your First Code Contribution

Unsure where to begin? Look for issues labeled:
- `good first issue` - Simple issues for newcomers
- `help wanted` - Issues where we need community help
- `documentation` - Improvements to documentation

### Pull Requests

Follow this process for contributions:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Make** your changes
4. **Test** thoroughly on multiple Windows versions
5. **Commit** with clear messages (`git commit -m 'Add AmazingFeature'`)
6. **Push** to your fork (`git push origin feature/AmazingFeature`)
7. **Open** a Pull Request

## Development Setup

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges for testing
- Git for version control
- Code editor (VS Code recommended)

### Setting Up Development Environment

1. **Fork and clone the repository:**
```powershell
git clone https://github.com/YOUR-USERNAME/Windows-Security-Audit-Script.git
cd Windows-Security-Audit-Script
```

2. **Install VS Code extensions (recommended):**
   - PowerShell
   - PowerShell Preview
   - GitLens

3. **Create test environment:**
```powershell
# Create test directory
New-Item -ItemType Directory -Path ".\TestResults"

# Set execution policy for development
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### Recommended Tools

- **PSScriptAnalyzer** - PowerShell linter
  ```powershell
  Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
  ```

- **Pester** - PowerShell testing framework
  ```powershell
  Install-Module -Name Pester -Scope CurrentUser -Force
  ```

## Coding Standards

### PowerShell Style Guide

Follow these conventions for consistency:

#### 1. Naming Conventions

```powershell
# Functions: Verb-Noun format
function Get-SecuritySettings { }
function Test-Compliance { }

# Variables: camelCase
$userName = "admin"
$isEnabled = $true

# Constants: UPPER_CASE
$MAX_RETRY_COUNT = 3

# Parameters: PascalCase
param(
    [string]$ModuleName,
    [int]$TimeoutSeconds
)
```

#### 2. Formatting

```powershell
# Use spaces, not tabs (4 spaces)
# Opening braces on same line for functions/loops
if ($condition) {
    # Code here
}

# Proper indentation
function Test-Something {
    param(
        [string]$Parameter
    )
    
    if ($Parameter) {
        Write-Host "Processing..."
    }
}
```

#### 3. Comments

```powershell
# Single-line comments for brief explanations
$result = Get-Data  # Retrieves data from source

<#
    Multi-line comments for:
    - Function documentation
    - Complex logic explanations
    - Section headers
#>
```

#### 4. Error Handling

```powershell
# Always use try/catch for operations that might fail
try {
    $result = Get-SomethingThatMightFail -ErrorAction Stop
    Add-Result -Category "Test" -Status "Pass" -Message "Success"
} catch {
    Add-Result -Category "Test" -Status "Error" -Message "Failed: $_"
}

# Use -ErrorAction appropriately
Get-Service -Name "NonExistent" -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Critical" -ErrorAction Stop
```

### Module Structure

All modules must follow this structure:

```powershell
# Module-Example.ps1
# Brief description
# Version: 5.0
# Based on: Framework Name

<#
.SYNOPSIS
    Brief summary

.DESCRIPTION
    Detailed description

.PARAMETER SharedData
    Hashtable containing shared data

.NOTES
    Author: Name
    Version: 5.0
    Based on: Framework
#>

param(
    [Parameter(Mandatory=$false)]
    [hashtable]$SharedData = @{}
)

$moduleName = "Example"
$results = @()

# Helper function
function Add-Result {
    param($Category, $Status, $Message, $Details = "", $Remediation = "")
    $script:results += [PSCustomObject]@{
        Module = $moduleName
        Category = $Category
        Status = $Status
        Message = $Message
        Details = $Details
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

Write-Host "`n[$moduleName] Starting checks..." -ForegroundColor Cyan

# Checks organized by category
Write-Host "[$moduleName] Checking Category..." -ForegroundColor Yellow

try {
    # Check implementation
    Add-Result -Category "$moduleName - Check" -Status "Pass" `
        -Message "Description" `
        -Details "Details" `
        -Remediation "Fix command"
} catch {
    Add-Result -Category "$moduleName - Check" -Status "Error" `
        -Message "Failed: $_"
}

# Summary statistics
$passCount = ($results | Where-Object { $_.Status -eq "Pass" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Fail" }).Count
$totalChecks = $results.Count

Write-Host "`n[$moduleName] Module completed:" -ForegroundColor Cyan
Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor Red

return $results
```

### Add-Result Function Standards

```powershell
Add-Result -Category "Module - Check ID" -Status "Pass|Fail|Warning|Info|Error" `
    -Message "Brief one-line description" `
    -Details "Detailed explanation including why it matters and framework reference" `
    -Remediation "Exact PowerShell command or GPO path to fix the issue"
```

**Status Values:**
- `Pass` - Check passed, meets requirement
- `Fail` - Check failed, security issue detected
- `Warning` - Potential issue or deviation from best practice
- `Info` - Informational only, no action required
- `Error` - Check could not be completed

## Testing Guidelines

### Manual Testing

Test your changes on multiple Windows versions:

**Minimum Test Matrix:**
- Windows 10 (latest)
- Windows 11 (latest)
- Windows Server 2019 or 2022

**Test Scenarios:**
1. **Full run:** All modules, all outputs
2. **Individual module:** Your modified module only
3. **Error conditions:** Systems where checks might fail
4. **Different privileges:** Admin vs non-admin

### Testing Checklist

Before submitting a PR, verify:

- [ ] Script runs without errors
- [ ] No typos or syntax errors (use PSScriptAnalyzer)
- [ ] Proper error handling (try/catch where needed)
- [ ] Meaningful status values (Pass/Fail/Warning/Info)
- [ ] Remediation commands are correct and tested
- [ ] Output formats correctly (HTML, JSON, CSV)
- [ ] No performance regression (script completes in reasonable time)
- [ ] Tested on at least 2 Windows versions
- [ ] Documentation updated if needed

### Using PSScriptAnalyzer

```powershell
# Install if not already installed
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser

# Analyze your module
Invoke-ScriptAnalyzer -Path ".\Modules\Module-YourModule.ps1"

# Analyze entire project
Invoke-ScriptAnalyzer -Path ".\" -Recurse

# Fix common issues automatically
Invoke-ScriptAnalyzer -Path ".\Modules\Module-YourModule.ps1" -Fix
```

### Test Script Template

```powershell
# Test-Module.ps1
# Quick test script for module development

param(
    [string]$ModuleName = "STIG"
)

Write-Host "Testing Module-$ModuleName.ps1..." -ForegroundColor Cyan

try {
    # Import and run module
    $results = & ".\Modules\Module-$ModuleName.ps1"
    
    # Verify results structure
    $results | ForEach-Object {
        if (-not $_.Module) { Write-Warning "Missing Module property" }
        if (-not $_.Category) { Write-Warning "Missing Category property" }
        if (-not $_.Status) { Write-Warning "Missing Status property" }
    }
    
    # Display summary
    $results | Group-Object Status | Format-Table Count, Name
    
    Write-Host "`n✓ Module executed successfully" -ForegroundColor Green
    
} catch {
    Write-Host "`n✗ Module failed: $_" -ForegroundColor Red
}
```

## Submission Process

### Pull Request Guidelines

**PR Title Format:**
```
[Component] Brief description

Examples:
[Module-STIG] Add Windows 11 specific checks
[Orchestrator] Fix CSV output formatting
[Docs] Update troubleshooting guide
```

**PR Description Should Include:**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- Tested on: Windows 10 Pro 22H2, Windows Server 2022
- Test results: All checks pass, no errors

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings from PSScriptAnalyzer
- [ ] Tested on multiple Windows versions
```

### Review Process

1. **Automated checks** run on your PR (syntax, style)
2. **Maintainer review** of code and functionality
3. **Feedback** provided if changes needed
4. **Merge** once approved

**Review Timeline:**
- Initial review: Within 1 week
- Feedback response: As needed
- Final approval: Within 1 week of final changes

## Module Development

### Adding a New Module

1. **Choose a framework/standard** to implement
2. **Research** the official documentation
3. **Create** module file in `Modules/` folder:
   ```
   Modules/Module-FrameworkName.ps1
   ```
4. **Follow** the module structure template
5. **Document** each check with proper references
6. **Test** thoroughly
7. **Update** orchestrator to include new module
8. **Add** documentation to wiki

### Module Naming Convention

```
Module-FrameworkName.ps1

Examples:
Module-STIG.ps1
Module-NIST.ps1
Module-ISO27001.ps1  (for future additions)
```

### Check Development Best Practices

```powershell
# Good: Specific, actionable, properly categorized
Add-Result -Category "STIG - V-220929 (CAT I)" -Status "Fail" `
    -Message "Guest account is ENABLED" `
    -Details "STIG CAT I: Guest account must be disabled to prevent anonymous access" `
    -Remediation "Disable-LocalUser -Name Guest"

# Bad: Vague, no context, no remediation
Add-Result -Category "Check" -Status "Fail" `
    -Message "Problem found"
```

### Referencing Security Standards

Always include framework references in Details:

```powershell
-Details "NIST 800-53 AC-2: Account management requires regular review..."
-Details "CIS Benchmark 1.1.1: Password policy must enforce complexity..."
-Details "STIG V-220718: Minimum password length protects against..."
```

## Questions?

- **General questions:** [GitHub Discussions](https://github.com/Sandler73/Windows-Security-Audit-Script/discussions)
- **Bugs/Features:** [GitHub Issues](https://github.com/Sandler73/Windows-Security-Audit-Script/issues)
- **Security concerns:** Contact maintainers directly

---

**Thank you for contributing to making Windows systems more secure!** 🛡️
