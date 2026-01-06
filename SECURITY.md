# Security Policy

## Our Commitment

The security of the Windows Security Audit Script and the systems it runs on is our top priority. We take all security vulnerabilities seriously and are committed to responsible disclosure and timely remediation.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 5.0.x   | :white_check_mark: | Current release, actively maintained |
| 4.x     | :x:                | End of life, upgrade recommended |
| < 4.0   | :x:                | No longer supported |

We recommend always using the latest release version for the most up-to-date security features and protections.

## Security Considerations for Users

### Before Running the Script

**Verify Source:**
- Only download from the official GitHub repository: https://github.com/Sandler73/Windows-Security-Audit-Project/tree/main
- Verify file integrity using checksums (provided in releases)
- Review the code before execution (open source for transparency)

**Understand What It Does:**
- Script is **read-only** and makes no configuration changes
- Accesses system configuration and security settings
- Generates reports containing sensitive system information
- Requires administrator privileges for comprehensive checks

**Test First:**
- Run in test/dev environment before production
- Verify behavior matches expectations
- Review generated reports for sensitive information

### When Running the Script

**Execution Environment:**
- Run only on systems you have authorization to audit
- Use latest PowerShell version (5.1+ or 7.x)
- Execute from trusted location on disk
- Do not run from network shares or untrusted sources

**Privilege Management:**
- Use admin account only when necessary
- Consider using managed service accounts for scheduled runs
- Audit script execution in your environment
- Follow principle of least privilege

### Handling Reports

**Reports Contain Sensitive Information:**
- System configuration details
- Security settings and weaknesses
- User account information
- Network configuration
- Installed software inventory

**Secure Report Storage:**
- Store in protected directory with appropriate ACLs
- Limit access to security team members only
- Encrypt reports if transmitting via email
- Do not commit reports to version control
- Implement retention policy and secure deletion

**Report Transmission:**
```powershell
# Example: Encrypt before sending
Protect-CmsMessage -To "CN=SecurityTeam" -Path ".\Reports\*.html" -OutFile ".\Reports\Encrypted.cms"
```

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. If you discover a security issue, please report it privately.

### What to Report

Please report any issues that could:
- Allow unauthorized access to systems
- Cause data leakage or exposure
- Enable privilege escalation
- Bypass security controls
- Cause denial of service
- Execute arbitrary code

### What NOT to Report

Please do not open public GitHub issues for:
- Security vulnerabilities (use private disclosure below)
- Theoretical issues without proof of concept
- Issues in dependencies (report to their maintainers)
- Social engineering attempts

### How to Report

**Private Disclosure (Preferred):**

1. **Email:** <email_address>
   - Use PGP encryption if possible (key below)
   - Include "SECURITY" in subject line

2. **GitHub Security Advisory:**
   - Go to https://github.com/Sandler73/Windows-Security-Audit-Script/security/advisories
   - Click "Report a vulnerability"
   - Fill out the private disclosure form

**What to Include:**

```markdown
## Vulnerability Report

**Summary:**
Brief description of the vulnerability

**Affected Versions:**
Which versions are affected (e.g., 5.0.0, all versions, etc.)

**Severity:**
Your assessment (Critical, High, Medium, Low)

**Details:**
Detailed technical description

**Proof of Concept:**
Steps to reproduce or PoC code (if applicable)

**Impact:**
What an attacker could achieve

**Suggested Fix:**
Your recommendations (if any)

**Disclosure Timeline:**
Your preferred disclosure timeline

**Reporter:**
Your name/handle and contact information
```

### Response Timeline

We are committed to:

| Stage | Timeline | Action |
|-------|----------|--------|
| **Initial Response** | 48 hours | Acknowledge receipt of report |
| **Assessment** | 7 days | Evaluate severity and impact |
| **Fix Development** | 30 days | Develop and test fix (severity dependent) |
| **Disclosure** | 90 days | Public disclosure (coordinated with reporter) |

**Note:** Timeline may be shorter for critical vulnerabilities or longer for complex issues. We will keep you informed throughout the process.

### What to Expect

1. **Acknowledgment:** We'll confirm receipt within 48 hours
2. **Assessment:** We'll evaluate the issue and determine severity
3. **Communication:** Regular updates on progress
4. **Credit:** Public acknowledgment in security advisory (if desired)
5. **Coordinated Disclosure:** We'll work with you on disclosure timing

## Security Best Practices for Contributors

### Code Review

All contributions undergo security review:
- No hardcoded credentials or secrets
- Proper input validation
- Safe handling of file paths
- Appropriate error handling
- No code execution from untrusted input

### Secure Development

**Do:**
- ✅ Use parameterized queries
- ✅ Validate and sanitize all inputs
- ✅ Handle errors gracefully
- ✅ Use least privilege principles
- ✅ Document security considerations
- ✅ Review dependencies for vulnerabilities

**Don't:**
- ❌ Store secrets in code
- ❌ Execute external commands without validation
- ❌ Use `Invoke-Expression` with user input
- ❌ Disable security features
- ❌ Ignore security warnings

### Testing for Security

Before submitting code:

```powershell
# Check for common security issues
Invoke-ScriptAnalyzer -Path ".\Module.ps1" -Settings PSGallery

# Review for sensitive data exposure
Select-String -Path ".\Module.ps1" -Pattern "(password|secret|key|token)" -CaseSensitive
```

## Known Security Considerations

### By Design

**Requires Administrator Privileges:**
- Many checks require elevated permissions
- This is expected and necessary
- Script does not attempt privilege escalation
- Run with appropriate safeguards

**Accesses Sensitive Information:**
- Reads security configurations
- Accesses password policies (not passwords)
- Enumerates accounts and permissions
- This is necessary for security auditing

**Generates Detailed Reports:**
- Reports contain system security posture
- May reveal vulnerabilities
- Secure report storage is user's responsibility
- Reports are local-only by default

### Limitations

**Not a Security Tool Itself:**
- Script does not protect the system
- Only assesses configuration
- Does not detect or prevent attacks
- Use as part of defense-in-depth strategy

**Point-in-Time Assessment:**
- Results valid at execution time only
- Does not provide continuous monitoring
- Re-run regularly to detect drift

**Framework Coverage:**
- Implements many, not all, framework controls
- Should not be sole compliance validation
- Supplement with other tools and processes

## Security Updates

### Receiving Updates

**Watch the Repository:**
- Click "Watch" on GitHub
- Select "Custom" → "Releases"
- Receive notifications of new versions

**Security Advisories:**
- GitHub Security Advisories
- CHANGELOG.md for security fixes
- Release notes

### Applying Updates

```powershell
# Backup current version first
Copy-Item -Path ".\Windows-Security-Audit-Script" -Destination ".\Backup" -Recurse

# Update via Git
git pull origin main

# Or download and replace manually
# Review CHANGELOG.md for breaking changes
```

### Critical Updates

For critical security vulnerabilities:
- Immediate notification via GitHub Security Advisory
- Emergency patch release
- Detailed mitigation guidance
- Expedited disclosure timeline

## Responsible Disclosure Hall of Fame

We appreciate researchers who responsibly disclose vulnerabilities:

<!-- Security researchers who report vulnerabilities will be acknowledged here -->

**Want to be listed?** Report a valid security vulnerability following our responsible disclosure process.

---

## Security Checklist for Users

**Before First Run:**
- [ ] Downloaded from official GitHub repository
- [ ] Verified checksums/signatures
- [ ] Reviewed code for understanding
- [ ] Tested in non-production environment
- [ ] Documented approval/authorization

**Each Run:**
- [ ] Running on authorized systems only
- [ ] Using appropriate privileges
- [ ] Reports will be securely stored
- [ ] Environment is prepared for audit

**After Run:**
- [ ] Reports stored in secure location
- [ ] Access restricted to authorized personnel
- [ ] Sensitive findings documented appropriately
- [ ] Remediation planning initiated

---

## Additional Resources

- **GitHub Security:** https://docs.github.com/en/code-security
- **PowerShell Security Best Practices:** https://docs.microsoft.com/en-us/powershell/scripting/security/
- **NIST Secure Software Development Framework:** https://csrc.nist.gov/projects/ssdf
- **OWASP Secure Coding Practices:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/

---

## Contact

**Security Issues:** [Create private security advisory](https://github.com/Sandler73/Windows-Security-Audit-Project/security/advisories/new)

**General Questions:** [GitHub Discussions](https://github.com/Sandler73/Windows-Security-Audit-Project/discussions)

**Other Issues:** [GitHub Issues](https://github.com/Sandler73/Windows-Security-Audit-Project/issues)

---

**Last Updated:** December 2024

This security policy is subject to change. Please review periodically for updates.
