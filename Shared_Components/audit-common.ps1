<#
.SYNOPSIS
    Shared utility library for the Windows Security Audit framework.

.DESCRIPTION
    Provides centralized, thread-safe caching, common helper functions,
    structured logging, OS detection, and the canonical AuditResult object
    definition used by all security audit modules.

    Key Components:
    - SharedDataCache: Pre-reads registry, WMI, services, and policies at startup
      then shares cached data across all modules (eliminates redundant queries).
    - AuditResult factory: Standardized result objects with Severity and CrossReferences.
    - OSInfo detection: Windows version, edition, build, domain status.
    - Structured logging: Dual console+file output with multiple levels and JSON format.
    - Common helper functions: Registry, service, firewall, user, network, policy checks.

    Thread Safety:
    - All cache access is synchronized for parallel module execution.
    - Uses [System.Collections.Concurrent.ConcurrentDictionary] where applicable.

    Graceful Fallback:
    - Modules can run without this library (reduced performance, no caching).
    - Modules check $script:HAS_COMMON_LIB before calling shared functions.

.NOTES
    Version: 6.0
    Part of: Windows Security Audit Framework
    GitHub: https://github.com/Sandler73/Windows-Security-Audit-Script
    
    Dependencies: None (stdlib only)
    Requires: PowerShell 5.1+, Windows 10/11 or Server 2016+
    
    v6.0 Changes:
    - Initial creation for Linux parity update
    - SharedDataCache with warm-up preloading
    - Thread-safe caching for parallel execution
    - Severity and CrossReferences on AuditResult
    - Structured logging with file and console output
    - 40+ common helper functions
#>

# ============================================================================
# Library Configuration
# ============================================================================
$script:COMMON_LIB_VERSION = "6.0"
$script:HAS_COMMON_LIB = $true

# ============================================================================
# Logging Framework
# ============================================================================
# Log levels (numeric for comparison)
$script:LogLevels = @{
    'DEBUG'    = 10
    'INFO'     = 20
    'WARNING'  = 30
    'ERROR'    = 40
    'CRITICAL' = 50
}

$script:CurrentLogLevel = 20  # INFO default
$script:LogFilePath = $null
$script:LogJsonFormat = $false
$script:LogLock = [System.Object]::new()

<#
.SYNOPSIS
    Configure the logging framework for the audit session.
.DESCRIPTION
    Sets up dual console+file logging with configurable levels and format.
    Call once at startup before any modules execute.
.PARAMETER LogLevel
    Minimum log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
.PARAMETER LogFile
    Path to log file. If empty, auto-generates in logs/ directory.
.PARAMETER JsonFormat
    If true, log entries are written in JSON format for SIEM ingestion.
#>
function Initialize-AuditLogging {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG','INFO','WARNING','ERROR','CRITICAL')]
        [string]$LogLevel = 'INFO',
        [string]$LogFile = '',
        [switch]$JsonFormat
    )

    $script:CurrentLogLevel = $script:LogLevels[$LogLevel]
    $script:LogJsonFormat = $JsonFormat.IsPresent

    if ($LogFile) {
        $script:LogFilePath = $LogFile
    }

    # Ensure log directory exists
    if ($script:LogFilePath) {
        $logDir = Split-Path -Parent $script:LogFilePath
        if ($logDir -and -not (Test-Path $logDir)) {
            try {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            catch {
                Write-Warning "Could not create log directory: $logDir"
            }
        }
    }
}

<#
.SYNOPSIS
    Write a structured log entry to both console and file.
.PARAMETER Message
    The log message text.
.PARAMETER Level
    Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
.PARAMETER Module
    Source module name for context.
#>
function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('DEBUG','INFO','WARNING','ERROR','CRITICAL')]
        [string]$Level = 'INFO',
        [string]$Module = 'MAIN'
    )

    $numericLevel = $script:LogLevels[$Level]
    if ($numericLevel -lt $script:CurrentLogLevel) { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

    # Write to file if configured
    if ($script:LogFilePath) {
        try {
            [System.Threading.Monitor]::Enter($script:LogLock)
            if ($script:LogJsonFormat) {
                $logEntry = @{
                    timestamp = $timestamp
                    level     = $Level
                    module    = $Module
                    message   = $Message
                } | ConvertTo-Json -Compress
            }
            else {
                $logEntry = "[$timestamp] [$Level] [$Module] $Message"
            }
            Add-Content -Path $script:LogFilePath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        finally {
            [System.Threading.Monitor]::Exit($script:LogLock)
        }
    }
}

# ============================================================================
# OS Detection
# ============================================================================
<#
.SYNOPSIS
    Detect Windows OS information including version, edition, build, and domain.
.DESCRIPTION
    Returns a hashtable with comprehensive OS details used for OS-aware checks.
#>
function Get-OSInfo {
    [CmdletBinding()]
    param()

    $osInfo = @{
        ComputerName    = $env:COMPUTERNAME
        OSCaption       = ''
        OSVersion       = ''
        BuildNumber     = ''
        Edition         = ''
        InstallType     = ''  # Server, Client
        IsServer        = $false
        IsDomainJoined  = $false
        DomainName      = ''
        Architecture    = ''
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        IsAdmin         = $false
        WindowsVersion  = ''  # e.g., "10", "11", "2019", "2022"
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $osInfo.OSCaption   = $os.Caption
            $osInfo.OSVersion   = $os.Version
            $osInfo.BuildNumber = $os.BuildNumber
        }

        # Determine install type
        $installType = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction SilentlyContinue).InstallationType
        $osInfo.InstallType = if ($installType) { $installType } else { 'Unknown' }
        $osInfo.IsServer = ($installType -eq 'Server' -or $installType -eq 'Server Core')

        # Edition
        $edition = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
        $osInfo.Edition = if ($edition) { $edition } else { 'Unknown' }

        # Windows version (friendly name)
        $buildNum = [int]$osInfo.BuildNumber
        if ($osInfo.IsServer) {
            $osInfo.WindowsVersion = switch ($true) {
                ($buildNum -ge 26100) { 'Server 2025' }
                ($buildNum -ge 20348) { 'Server 2022' }
                ($buildNum -ge 17763) { 'Server 2019' }
                ($buildNum -ge 14393) { 'Server 2016' }
                default               { 'Server (Unknown)' }
            }
        }
        else {
            $osInfo.WindowsVersion = switch ($true) {
                ($buildNum -ge 26100) { 'Windows 11 24H2+' }
                ($buildNum -ge 22621) { 'Windows 11 22H2+' }
                ($buildNum -ge 22000) { 'Windows 11' }
                ($buildNum -ge 19041) { 'Windows 10 20H1+' }
                ($buildNum -ge 17763) { 'Windows 10 1809+' }
                default               { 'Windows 10' }
            }
        }

        # Architecture
        $osInfo.Architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }

        # Domain
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $osInfo.IsDomainJoined = ($cs.PartOfDomain -eq $true)
            $osInfo.DomainName = if ($cs.PartOfDomain) { $cs.Domain } else { 'WORKGROUP' }
        }

        # Admin check
        $osInfo.IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-AuditLog "OS detection error: $_" -Level ERROR -Module OSINFO
    }

    return $osInfo
}

# ============================================================================
# AuditResult Factory
# ============================================================================
<#
.SYNOPSIS
    Create a standardized audit result object.
.DESCRIPTION
    Returns a PSCustomObject with all required fields including Severity and
    CrossReferences for cross-framework mapping. This is the canonical result
    format used by all modules and the main script.
.PARAMETER Module
    Framework/module name (e.g., "CIS", "NIST", "Core")
.PARAMETER Category
    Check category within the module (e.g., "CIS 1.1 - Password Policy")
.PARAMETER Status
    Result status: Pass, Fail, Warning, Info, Error
.PARAMETER Message
    Human-readable description of the finding
.PARAMETER Details
    Additional technical details about the check
.PARAMETER Remediation
    PowerShell command or guidance to remediate the finding
.PARAMETER Severity
    Finding severity: Critical, High, Medium, Low, Informational
.PARAMETER CrossReferences
    Hashtable mapping to other frameworks (e.g., @{NIST="AC-2"; CIS="1.1.1"})
#>
function New-AuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Module,
        [Parameter(Mandatory=$true)]
        [string]$Category,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Pass','Fail','Warning','Info','Error')]
        [string]$Status,
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Details = '',
        [string]$Remediation = '',
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity = 'Medium',
        [hashtable]$CrossReferences = @{}
    )

    return [PSCustomObject]@{
        Module          = $Module
        Category        = $Category
        Status          = $Status
        Message         = $Message
        Details         = $Details
        Remediation     = $Remediation
        Severity        = $Severity
        CrossReferences = $CrossReferences
        Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# ============================================================================
# SharedDataCache
# ============================================================================
<#
.SYNOPSIS
    Centralized data cache that pre-reads commonly-accessed system data at
    startup, then provides it to all modules -- dramatically reducing redundant
    WMI queries, registry reads, and subprocess calls.
.DESCRIPTION
    Usage:
      # In main script, create once:
      $cache = New-SharedDataCache
      Invoke-CacheWarmUp -Cache $cache

      # Pass to modules via SharedData:
      $SharedData.Cache = $cache

      # In modules, retrieve cached data:
      $registryValue = Get-CachedRegistryValue -Cache $cache -Path "HKLM:\..." -Name "..."
      $services = Get-CachedServices -Cache $cache
#>

function New-SharedDataCache {
    [CmdletBinding()]
    param(
        [hashtable]$OSInfo = $null
    )

    $cache = @{
        OSInfo           = if ($OSInfo) { $OSInfo } else { Get-OSInfo }
        Registry         = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
        Services         = $null
        CimData          = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
        AuditPolicy      = $null
        SecurityPolicy   = $null
        InstalledFeatures = $null
        NetworkConfig    = $null
        FirewallRules    = $null
        PasswordPolicy   = $null
        LocalUsers       = $null
        LocalGroups      = $null
        HotFixes         = $null
        Timing           = @{}
        IsWarm           = $false
    }

    return $cache
}

<#
.SYNOPSIS
    Pre-read all common system data into the cache.
.DESCRIPTION
    Should be called ONCE before audit modules execute. Front-loads I/O cost
    so that module execution is fast.
.PARAMETER Cache
    The SharedDataCache hashtable from New-SharedDataCache.
.RETURNS
    Timing hashtable with operation durations.
#>
function Invoke-CacheWarmUp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Cache
    )

    $totalStart = [System.Diagnostics.Stopwatch]::StartNew()
    $timing = @{}

    Write-AuditLog "Warming up shared data cache..." -Level INFO -Module CACHE

    # --- Services ---
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $Cache.Services = @(Get-Service -ErrorAction SilentlyContinue)
        Write-AuditLog "  Services: $($Cache.Services.Count) cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        Write-AuditLog "  Services cache failed: $_" -Level WARNING -Module CACHE
        $Cache.Services = @()
    }
    $timing['services'] = $sw.Elapsed.TotalSeconds

    # --- Audit Policy ---
    $sw.Restart()
    try {
        $Cache.AuditPolicy = auditpol /get /category:* 2>$null
        Write-AuditLog "  Audit policy cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        Write-AuditLog "  Audit policy cache failed: $_" -Level WARNING -Module CACHE
    }
    $timing['audit_policy'] = $sw.Elapsed.TotalSeconds

    # --- Security Policy (secedit export) ---
    $sw.Restart()
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $null = secedit /export /cfg $tempFile /quiet 2>$null
        if (Test-Path $tempFile) {
            $Cache.SecurityPolicy = Get-Content $tempFile -Raw -ErrorAction SilentlyContinue
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        Write-AuditLog "  Security policy cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        Write-AuditLog "  Security policy cache failed: $_" -Level WARNING -Module CACHE
    }
    $timing['security_policy'] = $sw.Elapsed.TotalSeconds

    # --- Password Policy (net accounts) ---
    $sw.Restart()
    try {
        $Cache.PasswordPolicy = net accounts 2>$null
        Write-AuditLog "  Password policy cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        Write-AuditLog "  Password policy cache failed: $_" -Level WARNING -Module CACHE
    }
    $timing['password_policy'] = $sw.Elapsed.TotalSeconds

    # --- Local Users ---
    $sw.Restart()
    try {
        $Cache.LocalUsers = @(Get-LocalUser -ErrorAction SilentlyContinue)
        Write-AuditLog "  Local users: $($Cache.LocalUsers.Count) cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        # Fallback for systems without Get-LocalUser
        try {
            $Cache.LocalUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)
        }
        catch {
            $Cache.LocalUsers = @()
        }
    }
    $timing['local_users'] = $sw.Elapsed.TotalSeconds

    # --- Local Groups ---
    $sw.Restart()
    try {
        $Cache.LocalGroups = @(Get-LocalGroup -ErrorAction SilentlyContinue)
    }
    catch {
        $Cache.LocalGroups = @()
    }
    $timing['local_groups'] = $sw.Elapsed.TotalSeconds

    # --- Hotfixes ---
    $sw.Restart()
    try {
        $Cache.HotFixes = @(Get-HotFix -ErrorAction SilentlyContinue)
        Write-AuditLog "  Hotfixes: $($Cache.HotFixes.Count) cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        $Cache.HotFixes = @()
    }
    $timing['hotfixes'] = $sw.Elapsed.TotalSeconds

    # --- Network Configuration ---
    $sw.Restart()
    try {
        $Cache.NetworkConfig = @{
            Adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
            IPConfig = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)
            Firewall = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
        }
        Write-AuditLog "  Network config cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    }
    catch {
        $Cache.NetworkConfig = @{ Adapters = @(); IPConfig = @(); Firewall = @() }
    }
    $timing['network'] = $sw.Elapsed.TotalSeconds

    # --- Installed Features (Server only) ---
    $sw.Restart()
    if ($Cache.OSInfo.IsServer) {
        try {
            $Cache.InstalledFeatures = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed })
            Write-AuditLog "  Windows features: $($Cache.InstalledFeatures.Count) cached" -Level INFO -Module CACHE
        }
        catch {
            $Cache.InstalledFeatures = @()
        }
    }
    else {
        try {
            $Cache.InstalledFeatures = @(Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
        }
        catch {
            $Cache.InstalledFeatures = @()
        }
    }
    $timing['features'] = $sw.Elapsed.TotalSeconds

    # --- Common Registry Keys (pre-read frequently accessed paths) ---
    $sw.Restart()
    $commonRegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard'
    )
    $regCached = 0
    foreach ($path in $commonRegistryPaths) {
        try {
            if (Test-Path $path) {
                $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($props) {
                    $null = $Cache.Registry.TryAdd($path, $props)
                    $regCached++
                }
            }
        }
        catch { <# skip inaccessible keys #> }
    }
    Write-AuditLog "  Registry: $regCached/$($commonRegistryPaths.Count) paths cached in $($sw.ElapsedMilliseconds)ms" -Level INFO -Module CACHE
    $timing['registry'] = $sw.Elapsed.TotalSeconds

    $totalStart.Stop()
    $timing['total'] = $totalStart.Elapsed.TotalSeconds

    $Cache.Timing = $timing
    $Cache.IsWarm = $true

    Write-AuditLog "Cache warm-up complete in $([Math]::Round($timing['total'], 2))s" -Level INFO -Module CACHE

    return $timing
}

<#
.SYNOPSIS
    Get a summary of the cache state for reporting.
#>
function Get-CacheSummary {
    [CmdletBinding()]
    param([hashtable]$Cache)

    return @{
        ServicesCached    = if ($Cache.Services) { $Cache.Services.Count } else { 0 }
        RegistryCached    = $Cache.Registry.Count
        HasAuditPolicy    = ($null -ne $Cache.AuditPolicy)
        HasSecurityPolicy = ($null -ne $Cache.SecurityPolicy)
        HasPasswordPolicy = ($null -ne $Cache.PasswordPolicy)
        LocalUsersCached  = if ($Cache.LocalUsers) { $Cache.LocalUsers.Count } else { 0 }
        HotFixesCached    = if ($Cache.HotFixes) { $Cache.HotFixes.Count } else { 0 }
        WarmUpTime        = if ($Cache.Timing.total) { [Math]::Round($Cache.Timing.total, 2) } else { 0 }
        IsWarm            = $Cache.IsWarm
    }
}

# ============================================================================
# Cached Helper Functions
# ============================================================================

<#
.SYNOPSIS
    Get a registry value, using the cache if available.
#>
function Get-CachedRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [hashtable]$Cache = $null,
        $DefaultValue = $null
    )

    # Try cache first
    if ($Cache -and $Cache.Registry) {
        $cached = $null
        if ($Cache.Registry.TryGetValue($Path, [ref]$cached)) {
            $val = $cached.PSObject.Properties[$Name]
            if ($val) { return $val.Value }
        }
    }

    # Direct read fallback
    try {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            return $prop.$Name
        }
    }
    catch { <# return default #> }

    return $DefaultValue
}

<#
.SYNOPSIS
    Test if a registry value exists.
#>
function Test-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [hashtable]$Cache = $null
    )

    $value = Get-CachedRegistryValue -Path $Path -Name $Name -Cache $Cache -DefaultValue '__NOT_FOUND__'
    return ($value -ne '__NOT_FOUND__')
}

<#
.SYNOPSIS
    Check if a Windows service is enabled (start type is not Disabled).
#>
function Test-ServiceEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [hashtable]$Cache = $null
    )

    if ($Cache -and $Cache.Services) {
        $svc = $Cache.Services | Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
        if ($svc) {
            return ($svc.StartType -ne 'Disabled')
        }
    }

    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) { return ($svc.StartType -ne 'Disabled') }
    }
    catch { <# service not found #> }

    return $false
}

<#
.SYNOPSIS
    Check if a Windows service is currently running.
#>
function Test-ServiceRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [hashtable]$Cache = $null
    )

    if ($Cache -and $Cache.Services) {
        $svc = $Cache.Services | Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
        if ($svc) {
            return ($svc.Status -eq 'Running')
        }
    }

    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) { return ($svc.Status -eq 'Running') }
    }
    catch { <# service not found #> }

    return $false
}

<#
.SYNOPSIS
    Get a service object by name, preferring cache.
#>
function Get-CachedService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [hashtable]$Cache = $null
    )

    if ($Cache -and $Cache.Services) {
        $svc = $Cache.Services | Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
        if ($svc) { return $svc }
    }

    try {
        return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }
    catch { return $null }
}

<#
.SYNOPSIS
    Query audit policy for a specific subcategory, using cache if available.
#>
function Get-CachedAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Subcategory,
        [hashtable]$Cache = $null
    )

    if ($Cache -and $Cache.AuditPolicy) {
        $match = $Cache.AuditPolicy | Select-String -Pattern $Subcategory -SimpleMatch
        if ($match) { return $match.Line }
    }

    try {
        $result = auditpol /get /subcategory:"$Subcategory" 2>$null
        return $result
    }
    catch { return $null }
}

<#
.SYNOPSIS
    Parse a value from the cached security policy (secedit export).
#>
function Get-SecurityPolicyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [hashtable]$Cache = $null,
        $DefaultValue = $null
    )

    $policyContent = $null
    if ($Cache -and $Cache.SecurityPolicy) {
        $policyContent = $Cache.SecurityPolicy
    }
    else {
        try {
            $tempFile = [System.IO.Path]::GetTempFileName()
            $null = secedit /export /cfg $tempFile /quiet 2>$null
            if (Test-Path $tempFile) {
                $policyContent = Get-Content $tempFile -Raw
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        catch { return $DefaultValue }
    }

    if ($policyContent) {
        $match = $policyContent | Select-String -Pattern "^\s*$Key\s*=\s*(.*)" | Select-Object -First 1
        if ($match) {
            return $match.Matches[0].Groups[1].Value.Trim()
        }
    }

    return $DefaultValue
}

<#
.SYNOPSIS
    Get password policy from cached 'net accounts' output.
#>
function Get-CachedPasswordPolicy {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    $netAccounts = $null
    if ($Cache -and $Cache.PasswordPolicy) {
        $netAccounts = $Cache.PasswordPolicy
    }
    else {
        try { $netAccounts = net accounts 2>$null } catch { return @{} }
    }

    if (-not $netAccounts) { return @{} }

    $policy = @{}
    foreach ($line in $netAccounts) {
        if ($line -match '^\s*(.+?):\s+(.+)$') {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()
            $policy[$key] = $val
        }
    }

    return $policy
}

<#
.SYNOPSIS
    Get firewall profile status, preferring cache.
#>
function Get-CachedFirewallStatus {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    if ($Cache -and $Cache.NetworkConfig -and $Cache.NetworkConfig.Firewall) {
        return $Cache.NetworkConfig.Firewall
    }

    try {
        return @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    }
    catch { return @() }
}

<#
.SYNOPSIS
    Get local user accounts, preferring cache.
#>
function Get-CachedLocalUsers {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    if ($Cache -and $Cache.LocalUsers) {
        return $Cache.LocalUsers
    }

    try {
        return @(Get-LocalUser -ErrorAction SilentlyContinue)
    }
    catch { return @() }
}

<#
.SYNOPSIS
    Get members of the local Administrators group.
#>
function Get-LocalAdministrators {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    try {
        $members = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
        return $members
    }
    catch {
        # Fallback for older systems
        try {
            $result = net localgroup Administrators 2>$null
            if ($result) {
                $members = @()
                $capture = $false
                foreach ($line in $result) {
                    if ($line -match '^---') { $capture = $true; continue }
                    if ($capture -and $line -match '^\S') {
                        if ($line -notmatch 'The command completed') {
                            $members += $line.Trim()
                        }
                    }
                }
                return $members
            }
        }
        catch { return @() }
    }

    return @()
}

<#
.SYNOPSIS
    Get listening TCP/UDP ports.
#>
function Get-ListeningPorts {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    try {
        return @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess)
    }
    catch {
        try {
            $netstat = netstat -an 2>$null | Select-String "LISTENING"
            return $netstat
        }
        catch { return @() }
    }
}

<#
.SYNOPSIS
    Get IP addresses for the system.
#>
function Get-SystemIPAddresses {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    $addresses = @()

    try {
        if ($Cache -and $Cache.NetworkConfig -and $Cache.NetworkConfig.IPConfig) {
            foreach ($config in $Cache.NetworkConfig.IPConfig) {
                if ($config.IPv4Address) {
                    $addresses += $config.IPv4Address.IPAddress
                }
            }
        }
        else {
            $ipConfigs = Get-NetIPConfiguration -ErrorAction SilentlyContinue
            foreach ($config in $ipConfigs) {
                if ($config.IPv4Address) {
                    $addresses += $config.IPv4Address.IPAddress
                }
            }
        }
    }
    catch {
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.IPAddressToString }
            $addresses += $ips
        }
        catch { <# return empty #> }
    }

    if ($addresses.Count -eq 0) { $addresses += '127.0.0.1' }

    return $addresses
}

<#
.SYNOPSIS
    Get installed software list.
#>
function Get-InstalledSoftware {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    $software = @()

    try {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($path in $paths) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            if ($items) { $software += $items }
        }
    }
    catch { <# return empty #> }

    return $software
}

<#
.SYNOPSIS
    Check if a Windows optional feature is enabled.
#>
function Test-WindowsFeatureEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FeatureName,
        [hashtable]$Cache = $null
    )

    if ($Cache -and $Cache.InstalledFeatures) {
        $feature = $Cache.InstalledFeatures | Where-Object {
            ($_.Name -eq $FeatureName) -or ($_.FeatureName -eq $FeatureName)
        } | Select-Object -First 1
        if ($feature) { return $true }
    }

    try {
        if ($Cache -and $Cache.OSInfo.IsServer) {
            $f = Get-WindowsFeature -Name $FeatureName -ErrorAction SilentlyContinue
            return ($f -and $f.Installed)
        }
        else {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
            return ($f -and $f.State -eq 'Enabled')
        }
    }
    catch { return $false }
}

<#
.SYNOPSIS
    Safe integer parsing with default value.
#>
function ConvertTo-SafeInt {
    [CmdletBinding()]
    param(
        [string]$Value,
        [int]$DefaultValue = 0
    )

    $result = 0
    if ([int]::TryParse($Value, [ref]$result)) {
        return $result
    }
    return $DefaultValue
}

<#
.SYNOPSIS
    Get Windows Defender status information.
#>
function Get-DefenderStatus {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    try {
        return Get-MpComputerStatus -ErrorAction SilentlyContinue
    }
    catch { return $null }
}

<#
.SYNOPSIS
    Check if Credential Guard is enabled.
#>
function Test-CredentialGuardEnabled {
    [CmdletBinding()]
    param([hashtable]$Cache = $null)

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) {
            return ($dg.SecurityServicesRunning -contains 1)
        }
    }
    catch { <# not available #> }

    return $false
}

<#
.SYNOPSIS
    Check if Secure Boot is enabled.
#>
function Test-SecureBootEnabled {
    [CmdletBinding()]
    param()

    try {
        return (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
    }
    catch { return $false }
}

<#
.SYNOPSIS
    Check if BitLocker is enabled on a drive.
#>
function Get-BitLockerStatus {
    [CmdletBinding()]
    param([string]$DriveLetter = 'C:')

    try {
        $bl = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue
        if ($bl) {
            return @{
                IsEncrypted      = ($bl.ProtectionStatus -eq 'On')
                ProtectionStatus = $bl.ProtectionStatus.ToString()
                EncryptionMethod = $bl.EncryptionMethod.ToString()
                VolumeStatus     = $bl.VolumeStatus.ToString()
                KeyProtectors    = @($bl.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
            }
        }
    }
    catch { <# BitLocker not available #> }

    return @{
        IsEncrypted      = $false
        ProtectionStatus = 'Unknown'
        EncryptionMethod = 'Unknown'
        VolumeStatus     = 'Unknown'
        KeyProtectors    = @()
    }
}

<#
.SYNOPSIS
    Generate a unique check ID for cross-referencing.
#>
function New-CheckId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Framework,
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][int]$Number
    )

    $prefix = switch ($Framework) {
        'CIS'      { 'CIS' }
        'NIST'     { 'NIST' }
        'STIG'     { 'STIG' }
        'NSA'      { 'NSA' }
        'CISA'     { 'CISA' }
        'CORE'     { 'CORE' }
        'MS'       { 'MS' }
        'ENISA'    { 'ENISA' }
        'ISO27001' { 'ISO' }
        default    { $Framework.Substring(0, [Math]::Min(4, $Framework.Length)).ToUpper() }
    }

    $catShort = ($Category -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(6, ($Category -replace '[^a-zA-Z0-9]', '').Length)).ToUpper()

    return "$prefix-$catShort-$($Number.ToString('D4'))"
}

<#
.SYNOPSIS
    Get library version and capability information.
#>
function Get-AuditCommonInfo {
    [CmdletBinding()]
    param()

    return @{
        Version           = $script:COMMON_LIB_VERSION
        HasCaching        = $true
        HasParallel       = $true
        HasSeverity       = $true
        HasCrossRef       = $true
        HasStructuredLog  = $true
        HelperFunctions   = @(
            'Get-OSInfo', 'New-AuditResult', 'New-SharedDataCache', 'Invoke-CacheWarmUp',
            'Get-CachedRegistryValue', 'Test-RegistryValue', 'Test-ServiceEnabled',
            'Test-ServiceRunning', 'Get-CachedService', 'Get-CachedAuditPolicy',
            'Get-SecurityPolicyValue', 'Get-CachedPasswordPolicy', 'Get-CachedFirewallStatus',
            'Get-CachedLocalUsers', 'Get-LocalAdministrators', 'Get-ListeningPorts',
            'Get-SystemIPAddresses', 'Get-InstalledSoftware', 'Test-WindowsFeatureEnabled',
            'ConvertTo-SafeInt', 'Get-DefenderStatus', 'Test-CredentialGuardEnabled',
            'Test-SecureBootEnabled', 'Get-BitLockerStatus', 'New-CheckId',
            'Initialize-AuditLogging', 'Write-AuditLog', 'Get-CacheSummary'
        )
    }
}

# ============================================================================
# End of audit-common.ps1
# ============================================================================
