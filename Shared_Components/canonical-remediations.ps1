# canonical-remediations.ps1
# Canonical remediation topics and normalization for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Topic classifier and canonical remediation text: one authoritative fix
    form per hardening topic.

.DESCRIPTION
    Parity equivalent of the Linux canonical_remediations component. The
    audited module tree carries the same fix in divergent variant forms (e.g.
    PowerShell script block logging with and without -Type DWord; security
    event log sizing at 1 GB in some modules and 256 MB in others; SMB signing
    via Set-SmbServerConfiguration in one module and raw registry in another).
    This component provides:

    - A topic table: topic id -> canonical remediation command, rationale, and
      match patterns (applied to a finding's message + category).
    - Get-RemediationTopic: classify a finding to a topic (or $null).
    - Get-CanonicalRemediation: the canonical command for a topic.
    - ConvertTo-CanonicalRemediation: normalize a finding's remediation to the
      canonical form when a topic matches (original text returned unchanged
      otherwise -- never invents a fix for an unclassified finding).
    - Test-ValueIndependentTopic: whether the canonical form is complete as-is
      (value-independent) or carries an operator-supplied value.

    Every canonical command is sourced from remediation strings already
    present in the audited module tree (provenance-safe); where variants
    disagreed, the stricter/more current form was selected and noted.

    Consumers: the remediation library and rollback generator (v6.4), report
    remediation indexes, and future remediation-script emission.

.EXAMPLE
    . .\shared_components\canonical-remediations.ps1
    Get-RemediationTopic -Message "SMB signing is not required" -Category "NIST - SC"
    # -> SmbSigningServer

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: none
    Security: data + classification only; executes nothing
    Version: 6.6.0
#>

# ============================================================================
# Topic table. Match: regex alternatives evaluated case-insensitively against
# "<message> :: <category>". First declared match wins (order matters: more
# specific topics precede broader ones).
# ============================================================================
$script:CanonicalTopics = [ordered]@{
    'SmbV1Protocol' = @{
        Canonical        = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        Rationale        = 'SMBv1 is legacy, exploit-prone (EternalBlue class), and replaced by SMBv2/3'
        ValueIndependent = $true
        Match            = @('SMB\s*v?1', 'SMB1')
    }
    'SmbSigningServer' = @{
        Canonical        = "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        Rationale        = 'Server-side SMB signing prevents relay and tampering'
        ValueIndependent = $true
        Match            = @('SMB.*sign', 'RequireSecuritySignature', 'server.*signing')
    }
    'NtlmCompatibility' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
        Rationale        = 'Level 5 sends NTLMv2 only and refuses LM/NTLMv1'
        ValueIndependent = $true
        Match            = @('LmCompatibilityLevel', 'NTLMv1', 'LAN Manager auth')
    }
    'NtlmV1SsoBlock' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name BlockNtlmv1SSO -Value 1"
        Rationale        = 'Blocks NTLMv1-derived SSO ahead of the October 2026 enforcement default'
        ValueIndependent = $true
        Match            = @('BlockNtlmv1SSO', 'NTLMv1-derived')
    }
    'WDigestCredentialCaching' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
        Rationale        = 'Prevents plaintext credential retention in LSASS memory'
        ValueIndependent = $true
        Match            = @('WDigest', 'UseLogonCredential')
    }
    'LsaProtection' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1"
        Rationale        = 'Runs LSASS as a protected process, blocking credential-dumping tooling'
        ValueIndependent = $true
        Match            = @('RunAsPPL', 'LSA [Pp]rotection', 'LSASS.*protect')
    }
    'RestrictAnonymous' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1"
        Rationale        = 'Blocks anonymous enumeration of SAM accounts and shares'
        ValueIndependent = $true
        Match            = @('RestrictAnonymous', 'anonymous enumeration')
    }
    'RdpNetworkLevelAuth' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        Rationale        = 'NLA authenticates before session establishment, cutting RDP pre-auth attack surface'
        ValueIndependent = $true
        Match            = @('Network Level Auth', '\bNLA\b', 'UserAuthentication.*RDP', 'RDP.*UserAuthentication')
    }
    'UacEnableLua' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
        Rationale        = 'UAC is the platform privilege-elevation boundary'
        ValueIndependent = $true
        Match            = @('EnableLUA', '\bUAC\b.*(disabled|off|not enabled)', 'User Account Control.*(disabled|off)')
    }
    'UacAdminConsentPrompt' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2"
        Rationale        = 'Prompt-on-secure-desktop for admin elevation (deny auto-elevate)'
        ValueIndependent = $true
        Match            = @('ConsentPromptBehaviorAdmin', 'admin.*consent.*prompt')
    }
    'GuestAccount' = @{
        Canonical        = "Disable-LocalUser -Name Guest"
        Rationale        = 'The built-in Guest account is an unauthenticated access path'
        ValueIndependent = $true
        Match            = @('Guest account', "'Guest'")
    }
    'PasswordMinLength' = @{
        Canonical        = "net accounts /minpwlen:14"
        Rationale        = '14+ characters per current CIS/STIG guidance'
        ValueIndependent = $false
        Match            = @('minimum password length', 'minpwlen', 'password.*too short')
    }
    'PasswordHistory' = @{
        Canonical        = "net accounts /uniquepw:24"
        Rationale        = '24 remembered passwords per baseline guidance'
        ValueIndependent = $false
        Match            = @('password history', 'uniquepw')
    }
    'AccountLockoutThreshold' = @{
        Canonical        = "net accounts /lockoutthreshold:5"
        Rationale        = 'Bounded invalid-attempt threshold blunts online guessing'
        ValueIndependent = $false
        Match            = @('lockout threshold', 'lockoutthreshold', 'invalid logon attempts')
    }
    'SecurityEventLogSize' = @{
        Canonical        = "wevtutil sl Security /ms:1073741824"
        Rationale        = '1 GB security log per STIG V2R8 one-week retention intent (stricter of the 256 MB / 1 GB variants in the tree)'
        ValueIndependent = $false
        Match            = @('[Ss]ecurity (event )?log.*(size|retention|wraps)', 'wevtutil sl Security')
    }
    'PowerShellScriptBlockLogging' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord"
        Rationale        = 'Script block logging is the primary PowerShell attack-visibility control (canonical form carries -Type DWord, unifying the two variants in the tree)'
        ValueIndependent = $true
        Match            = @('[Ss]cript ?[Bb]lock ?[Ll]ogging', 'EnableScriptBlockLogging')
    }
    'DefenderRealTimeProtection' = @{
        Canonical        = "Set-MpPreference -DisableRealtimeMonitoring `$false"
        Rationale        = 'Real-time protection is the base Defender control'
        ValueIndependent = $true
        Match            = @('[Rr]eal-?[Tt]ime ([Pp]rotection|[Mm]onitoring)', 'DisableRealtimeMonitoring')
    }
    'DefenderSignatures' = @{
        Canonical        = "Update-MpSignature"
        Rationale        = 'Stale signatures degrade detection'
        ValueIndependent = $true
        Match            = @('signature.*(age|stale|out.?of.?date)', 'Update-MpSignature', 'definitions.*old')
    }
    'DefenderNetworkProtection' = @{
        Canonical        = "Set-MpPreference -EnableNetworkProtection Enabled"
        Rationale        = 'Network protection blocks known-bad destinations at the network layer'
        ValueIndependent = $true
        Match            = @('[Nn]etwork [Pp]rotection')
    }
    'DefenderControlledFolderAccess' = @{
        Canonical        = "Set-MpPreference -EnableControlledFolderAccess Enabled"
        Rationale        = 'CFA is the anti-ransomware write-protection control'
        ValueIndependent = $true
        Match            = @('[Cc]ontrolled [Ff]older [Aa]ccess')
    }
    'AutorunDisable' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255"
        Rationale        = 'AutoRun on any drive type is a removable-media execution vector'
        ValueIndependent = $true
        Match            = @('[Aa]uto[Rr]un', 'NoDriveTypeAutoRun', '[Aa]uto[Pp]lay')
    }
    'InactivityLock' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900"
        Rationale        = '15-minute machine inactivity lock per baseline guidance'
        ValueIndependent = $false
        Match            = @('InactivityTimeoutSecs', 'inactivity.*(lock|timeout)', 'session lock')
    }
    'BitLockerSystemDrive' = @{
        Canonical        = "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest"
        Rationale        = 'XTS-AES-256 full-volume encryption for data at rest'
        ValueIndependent = $true
        Match            = @('BitLocker', 'encryption at rest.*(drive|volume|disk)', 'system drive.*encrypt')
    }
    'AuditPolicyLogon' = @{
        Canonical        = "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"
        Rationale        = 'Logon success+failure auditing is the base authentication evidence trail'
        ValueIndependent = $true
        Match            = @("subcategory:'?Logon'?", 'audit.*logon events', 'Audit Policy.*[Ll]ogon', '[Ll]ogon auditing', 'auditpol.*[Ll]ogon')
    }
    'AuditPolicyChange' = @{
        Canonical        = "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable"
        Rationale        = 'Detects tampering with the audit configuration itself'
        ValueIndependent = $true
        Match            = @('Audit Policy Change')
    }
    'TimeService' = @{
        Canonical        = "Start-Service -Name W32Time; Set-Service -Name W32Time -StartupType Automatic"
        Rationale        = 'Accurate time underpins log correlation and Kerberos'
        ValueIndependent = $true
        Match            = @('W32Time', '[Tt]ime service', '\bNTP\b')
    }
    'EventLogService' = @{
        Canonical        = "Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic"
        Rationale        = 'The event log service is the evidence backbone; nothing downstream works without it'
        ValueIndependent = $true
        Match            = @('Event ?Log service', "Start-Service -Name EventLog")
    }
    'AutomaticUpdates' = @{
        Canonical        = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0 -Type DWord"
        Rationale        = 'Automatic updates are the default patch-currency mechanism'
        ValueIndependent = $true
        Match            = @('NoAutoUpdate', '[Aa]utomatic [Uu]pdates.*(disabled|off)')
    }
}

# Precompiled match table: topic -> single alternation regex
$script:CompiledTopicPatterns = @{}
foreach ($topicName in $script:CanonicalTopics.Keys) {
    $pats = $script:CanonicalTopics[$topicName].Match
    $script:CompiledTopicPatterns[$topicName] = [regex]::new(
        ('(' + (($pats) -join ')|(') + ')'),
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

# ============================================================================
# API
# ============================================================================
function Get-RemediationTopic {
    <#
    .SYNOPSIS
        Classify a finding (message + category) to a canonical topic id, or
        $null when no topic matches. First declared match wins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message,
        [string]$Category = ''
    )
    $blob = "$Message :: $Category"
    foreach ($topicName in $script:CanonicalTopics.Keys) {
        if ($script:CompiledTopicPatterns[$topicName].IsMatch($blob)) { return $topicName }
    }
    return $null
}

function Get-CanonicalRemediation {
    <#
    .SYNOPSIS
        Canonical remediation command for a topic ($null for unknown topics).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Topic)
    $def = $script:CanonicalTopics[$Topic]
    if ($def) { return $def.Canonical }
    return $null
}

function Test-ValueIndependentTopic {
    <#
    .SYNOPSIS
        $true when the topic's canonical command is complete as-is; $false
        when it embeds a baseline value an operator may tailor. Unknown
        topics return $false (conservative).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Topic)
    $def = $script:CanonicalTopics[$Topic]
    if ($def) { return [bool]$def.ValueIndependent }
    return $false
}

function ConvertTo-CanonicalRemediation {
    <#
    .SYNOPSIS
        Normalize a finding's remediation to the canonical form when a topic
        matches; otherwise return the original text unchanged. Never invents
        a fix for an unclassified finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message,
        [string]$Category = '',
        [AllowEmptyString()][string]$Remediation = ''
    )
    $topic = Get-RemediationTopic -Message $Message -Category $Category
    if ($topic) { return (Get-CanonicalRemediation -Topic $topic) }
    return $Remediation
}

function Get-CanonicalTopics {
    <#
    .SYNOPSIS
        All topic ids in declaration (priority) order.
    #>
    return @($script:CanonicalTopics.Keys)
}

function Get-CanonicalTopicIndex {
    <#
    .SYNOPSIS
        Full topic table (id -> Canonical/Rationale/ValueIndependent/Match)
        for consumers such as the remediation library and rollback generator.
    #>
    return $script:CanonicalTopics
}
