# Changelog

All notable changes to the Windows Security Audit Script will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Features planned but not yet implemented

### Changed
- Changes planned for next release

### Fixed
- Bug fixes in development

## [5.0.0] - 2024-12-25

### Added
- **Complete project rewrite** with modular architecture
- **Module-Core.ps1** - Foundational Windows security baseline (40+ checks)
- **Module-STIG.ps1** - DISA STIG compliance with CAT I/II/III categorization (90+ checks)
- **Module-NIST.ps1** - NIST 800-53 Rev 5 and Cybersecurity Framework (50+ checks)
- **Module-CIS.ps1** - CIS Benchmarks for Windows (100+ checks)
- **Module-NSA.ps1** - NSA Cybersecurity guidance (60+ checks)
- **Module-CISA.ps1** - CISA Cybersecurity Performance Goals (80+ checks)
- **Module-MS.ps1** - Microsoft Security Baselines and SCT (80+ checks)
- **Total of 550+ automated security checks** across all modules
- **Multiple output formats**: HTML, JSON, and CSV
- **Executive summary** with compliance statistics
- **Color-coded console output** for real-time monitoring
- **Comprehensive error handling** with graceful degradation
- **Detailed remediation guidance** with PowerShell commands
- **Module selection capability** - Run all or specific modules
- **Custom output directory** support
- **Verbose and debug modes** for troubleshooting

### Changed
- **Complete architecture redesign** from monolithic to modular
- **Improved performance** - Optimized checks for faster execution
- **Enhanced reporting** - More detailed findings with framework mappings
- **Better categorization** - Pass/Fail/Warning/Info/Error status levels
- **Standardized module structure** for consistency and maintainability

### Fixed
- **Audit policy null reference errors** with proper error handling
- **Profile variable colon syntax issues** across all modules
- **BitLocker checks** now handle unsupported editions gracefully
- **Windows Defender checks** properly detect third-party AV scenarios
- **Event log enumeration** with improved error handling
- **Remote Desktop checks** more reliable across Windows versions

### Documentation
- **Comprehensive README** with quick start and examples
- **Wiki pages created**:
  - Quick Start Guide
  - Usage Guide
  - Framework Reference with citations
  - Troubleshooting Guide
  - Module Documentation
- **CONTRIBUTING.md** for developer guidance
- **Code of Conduct** for community standards

### Technical Improvements
- **Modular design** - Each framework in separate module file
- **Consistent structure** - All modules follow same pattern
- **Proper scoping** - No variable conflicts between modules
- **Better logging** - Module-level progress indicators
- **Result aggregation** - Centralized result collection and reporting
- **Summary statistics** - Per-module and overall compliance metrics

## [4.0.0] - 2024-XX-XX (Previous Version)

### Note
Version 4.x and earlier used a monolithic script design. Version 5.0 represents a complete rewrite.

## Version Comparison

| Version | Modules | Checks | Output Formats | Architecture |
|---------|---------|--------|----------------|--------------|
| 5.0.0   | 7       | 550+   | HTML, JSON, CSV | Modular |
| 4.x     | N/A     | ~200   | HTML only      | Monolithic |

## Upgrade Notes

### Migrating from 4.x to 5.0

**Breaking Changes:**
- Command-line parameters have changed
- Output format is different
- Module organization is new

**Migration Steps:**
1. Back up any custom modifications to 4.x script
2. Download/clone version 5.0
3. Update any automation scripts to use new parameters:
   ```powershell
   # Old (4.x)
   .\SecurityAudit.ps1 -Type Full
   
   # New (5.0)
   .\Windows-Security-Audit-Script.ps1 -Modules Core,STIG,NIST,CIS,NSA,CISA,MS
   ```
4. Update report parsing logic for new formats
5. Test thoroughly before production use

**What's Better in 5.0:**
- ✅ 2.5x more security checks
- ✅ Better framework alignment
- ✅ Multiple output formats
- ✅ Easier to maintain and extend
- ✅ More detailed remediation guidance
- ✅ Better error handling
- ✅ Comprehensive documentation

## Future Roadmap

### Planned for v5.1
- [ ] Additional Windows Server specific checks
- [ ] Enhanced report filtering and search
- [ ] Baseline comparison feature
- [ ] Integration with popular SIEM systems
- [ ] Azure AD/Entra ID module
- [ ] Compliance reporting templates

### Planned for v6.0
- [ ] GUI interface option
- [ ] Remote system auditing
- [ ] Historical trending and metrics
- [ ] Auto-remediation capabilities (opt-in)
- [ ] Custom check framework
- [ ] Docker container support for testing

### Under Consideration
- ISO 27001 module
- PCI-DSS module
- HIPAA Security Rule module
- SOC 2 controls module
- Automated scheduling and notification
- PowerBI dashboard template
- REST API for programmatic access

## How to Contribute

See [CONTRIBUTING.md](https://github.com/Sandler73/Windows-Security-Audit-Script/blob/main/CONTRIBUTING.md) for guidelines on:
- Reporting bugs
- Suggesting features
- Submitting pull requests
- Adding new modules
- Improving documentation

## Support Policy

### Supported Windows Versions

| Version | Support Status | Notes |
|---------|---------------|-------|
| Windows 11 | ✅ Fully Supported | Latest builds tested |
| Windows 10 | ✅ Fully Supported | 21H2 and later |
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

## Security Advisories

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, email security concerns to: [maintainer email]

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 48 hours.

## Credits

### Contributors
- Project maintainers and contributors (see GitHub Contributors page)

### Acknowledgments

This project builds upon the work of:
- **DISA** - Security Technical Implementation Guides
- **NIST** - Cybersecurity frameworks and controls
- **CIS** - Community-developed benchmarks
- **NSA** - Nation-state threat mitigation guidance
- **CISA** - Critical infrastructure protection guidance
- **Microsoft** - Security baselines and tools
- **Open-source community** - PowerShell modules and tools

See [Framework Reference](https://github.com/Sandler73/Windows-Security-Audit-Script/wiki/Framework-Reference) for detailed citations.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Sandler73/Windows-Security-Audit-Script/blob/main/LICENSE) file for details.

## Links

- **Repository**: https://github.com/Sandler73/Windows-Security-Audit-Script
- **Documentation**: https://github.com/Sandler73/Windows-Security-Audit-Script/wiki
- **Issues**: https://github.com/Sandler73/Windows-Security-Audit-Script/issues
- **Discussions**: https://github.com/Sandler73/Windows-Security-Audit-Script/discussions

---

**Note**: This changelog will be updated with each release. Subscribe to repository releases to stay informed of updates.
