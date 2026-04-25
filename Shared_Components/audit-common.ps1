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
    Version: 6.1.2
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
$script:COMMON_LIB_VERSION = "6.1.2"
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
$script:LogConsoleEnabled = $true   # v6.1.2: Console emission (toggle via Initialize-AuditLogging -Quiet)
$script:LogStartTime = $null

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
        [switch]$JsonFormat,
        [switch]$Quiet,
        [string]$ScriptRoot = ''
    )

    $script:CurrentLogLevel = $script:LogLevels[$LogLevel]
    $script:LogJsonFormat = $JsonFormat.IsPresent
    $script:LogConsoleEnabled = -not $Quiet.IsPresent
    $script:LogStartTime = Get-Date

    # v6.1.2: Auto-generate log file path when none supplied (matches orchestrator
    # built-in fallback behavior so logs are always captured by default).
    if ($LogFile) {
        $script:LogFilePath = $LogFile
    }
    else {
        # Choose a default log directory. Prefer the script's logs/ subfolder when
        # the orchestrator passes its $PSScriptRoot; otherwise fall back to CWD.
        $logDir = if ($ScriptRoot) { Join-Path $ScriptRoot 'logs' } else { Join-Path (Get-Location).Path 'logs' }
        if (-not (Test-Path $logDir)) {
            try {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            catch {
                Write-Warning "Could not create log directory: $logDir"
                $logDir = (Get-Location).Path
            }
        }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $extension = if ($script:LogJsonFormat) { 'json' } else { 'log' }
        $script:LogFilePath = Join-Path $logDir "audit-$stamp.$extension"
    }

    # Ensure log directory exists for explicit path
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

        # Create the log file with a header on first use
        if (-not (Test-Path $script:LogFilePath)) {
            try {
                $header = "# Windows Security Audit Log - Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                Set-Content -Path $script:LogFilePath -Value $header -Encoding UTF8
            }
            catch {
                Write-Warning "Could not create log file: $script:LogFilePath"
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

    # v6.1.2: Console emission. Color by level. Suppressed via -Quiet on
    # Initialize-AuditLogging or when console output is intentionally disabled.
    if ($script:LogConsoleEnabled) {
        $color = switch ($Level) {
            'DEBUG'    { 'DarkGray' }
            'INFO'     { 'Gray' }
            'WARNING'  { 'Yellow' }
            'ERROR'    { 'Red' }
            'CRITICAL' { 'Magenta' }
            default    { 'White' }
        }
        $consoleLine = "[$timestamp] [$Level] [$Module] $Message"
        Write-Host $consoleLine -ForegroundColor $color
    }

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
    param(
        [hashtable]$Cache = $null
    )

    # Cache-aware: serve from $Cache.OSInfo if populated by warmup
    if ($Cache -and $Cache.OSInfo -and $Cache.OSInfo.ComputerName) {
        return $Cache.OSInfo
    }

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
    Query audit policy. Without -Subcategory, returns parsed objects for all
    subcategories. With -Subcategory, returns the matching auditpol text line(s)
    for backward compatibility with existing callers.
.DESCRIPTION
    auditpol output rows have the form:
        System audit policy
        Category/Subcategory                      Setting
        ---------                                 -------
        System
          Security System Extension               No Auditing
          System Integrity                        Success and Failure
          ...

    When -Subcategory is supplied, the original v6.0 behavior is retained: the
    matching raw text line(s) are returned as a string. When -Subcategory is
    omitted, the function parses the entire auditpol output and returns an array
    of PSCustomObjects with Category, Subcategory, and Setting properties.
.PARAMETER Subcategory
    Optional. Specific subcategory name to query. When omitted, all subcategories
    are returned as parsed objects.
.PARAMETER Cache
    Optional shared data cache hashtable.
.OUTPUTS
    With -Subcategory: System.String (raw auditpol line).
    Without -Subcategory: PSCustomObject[] with Category, Subcategory, Setting.
#>
function Get-CachedAuditPolicy {
    [CmdletBinding()]
    param(
        [string]$Subcategory = "",
        [hashtable]$Cache = $null
    )

    # Backward-compatible string-returning mode (Subcategory provided)
    if ($Subcategory) {
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

    # Object-returning mode (no Subcategory): parse all rows
    $rawLines = $null
    if ($Cache -and $Cache.AuditPolicy) {
        $rawLines = $Cache.AuditPolicy
    }
    else {
        try {
            $rawLines = auditpol /get /category:* 2>$null
        }
        catch {
            return @()
        }
    }

    if (-not $rawLines) { return @() }

    $parsed = @()
    $currentCategory = $null

    foreach ($line in $rawLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # Skip header lines
        if ($line -match '^System audit policy' -or
            $line -match '^Category/Subcategory' -or
            $line -match '^-{3,}' -or
            $line -match '^Machine Name:' -or
            $line -match '^Policy Target:') {
            continue
        }

        # Category lines have no leading whitespace and no Setting column.
        # Subcategory lines have leading whitespace and a Setting column.
        if ($line -match '^\S' -and $line -notmatch '\s{2,}\S') {
            $currentCategory = $line.Trim()
            continue
        }

        # Subcategory row: split on multiple spaces
        if ($line -match '^\s+(\S.*?)\s{2,}(.+)$') {
            $sub = $matches[1].Trim()
            $setting = $matches[2].Trim()
            $parsed += [PSCustomObject]@{
                Category    = $currentCategory
                Subcategory = $sub
                Setting     = $setting
            }
        }
    }

    return $parsed
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
    param(
        [string]$DriveLetter = 'C:',
        [hashtable]$Cache = $null
    )

    # Cache-aware: serve from $Cache.BitLocker if previously populated
    if ($Cache -and $Cache.ContainsKey('BitLocker') -and $Cache.BitLocker -and $Cache.BitLocker.ContainsKey($DriveLetter)) {
        return $Cache.BitLocker[$DriveLetter]
    }

    try {
        $bl = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue
        if ($bl) {
            $result = @{
                IsEncrypted          = ($bl.ProtectionStatus -eq 'On')
                SystemDriveProtected = ($bl.ProtectionStatus -eq 'On')
                ProtectionStatus     = $bl.ProtectionStatus.ToString()
                EncryptionMethod     = $bl.EncryptionMethod.ToString()
                VolumeStatus         = $bl.VolumeStatus.ToString()
                KeyProtectors        = @($bl.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
            }
            # Populate cache for subsequent callers
            if ($Cache) {
                if (-not $Cache.ContainsKey('BitLocker') -or -not $Cache.BitLocker) {
                    $Cache.BitLocker = @{}
                }
                $Cache.BitLocker[$DriveLetter] = $result
            }
            return $result
        }
    }
    catch { <# BitLocker not available #> }

    $unavailable = @{
        IsEncrypted          = $false
        SystemDriveProtected = $false
        ProtectionStatus     = 'Unknown'
        EncryptionMethod     = 'Unknown'
        VolumeStatus         = 'Unknown'
        KeyProtectors        = @()
    }
    if ($Cache) {
        if (-not $Cache.ContainsKey('BitLocker') -or -not $Cache.BitLocker) {
            $Cache.BitLocker = @{}
        }
        $Cache.BitLocker[$DriveLetter] = $unavailable
    }
    return $unavailable
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
            'Initialize-AuditLogging', 'Write-AuditLog', 'Get-CacheSummary',
            'ConvertTo-RegistryRollback', 'ConvertTo-ServiceRollback', 'Get-RemediationImpact',
            'Get-RiskPriorityScore', 'Find-CompensatingControls', 'Find-CrossFrameworkCorrelations',
            'Compare-ToBaseline', 'Export-RegistryPolicyFile', 'Test-InternetFacingHost',
            'Test-DomainControllerHost'
        )
    }
}

# ============================================================================
# v6.1 Foundation Enhancements
# Cross-cutting capability functions added in version 6.1.
# All functions below are additive; no existing functions are modified.
# ============================================================================

<#
.SYNOPSIS
    Compute a registry-write rollback command from a forward Set-ItemProperty.
.DESCRIPTION
    Given a remediation string that performs Set-ItemProperty, query the current
    value at the target path/name and produce the inverse command that would
    restore the prior state. Supports DWord, QWord, String, ExpandString, and
    MultiString value types. Returns $null when the target value does not exist
    or when the input string is not a recognized registry write pattern.
.PARAMETER ForwardCommand
    The remediation command string (e.g., "Set-ItemProperty -Path 'HKLM:\...' ...").
.OUTPUTS
    System.String. Rollback command, or $null when not derivable.
#>
function ConvertTo-RegistryRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ForwardCommand
    )

    $pattern = "Set-ItemProperty\s+-Path\s+['""]([^'""]+)['""].*?-Name\s+['""]?([\w\(\)\s\-\.]+?)['""]?\s+-Value\s+([^\s;]+)(?:\s+-Type\s+(\w+))?"
    $match = [regex]::Match($ForwardCommand, $pattern)
    if (-not $match.Success) { return $null }

    $regPath = $match.Groups[1].Value
    $regName = $match.Groups[2].Value.Trim()
    $valueType = if ($match.Groups[4].Success) { $match.Groups[4].Value } else { 'DWord' }

    try {
        $existing = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
        $priorValue = $existing.$regName

        if ($priorValue -is [array]) {
            $valueLiteral = '@(' + (($priorValue | ForEach-Object { "'$_'" }) -join ',') + ')'
        }
        elseif ($priorValue -is [string]) {
            $escaped = $priorValue -replace "'", "''"
            $valueLiteral = "'$escaped'"
        }
        else {
            $valueLiteral = $priorValue
        }

        return "Set-ItemProperty -Path '$regPath' -Name '$regName' -Value $valueLiteral -Type $valueType"
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return "Remove-ItemProperty -Path '$regPath' -Name '$regName' -ErrorAction SilentlyContinue"
    }
    catch [System.Management.Automation.PSArgumentException] {
        return "Remove-ItemProperty -Path '$regPath' -Name '$regName' -ErrorAction SilentlyContinue"
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Generate a rollback command for a service state change.
.DESCRIPTION
    For a forward command that stops or sets a service, produce the inverse
    based on the current observed service state. Returns $null when the
    forward command is not a recognized service-state pattern or when the
    service does not exist on the host.
.PARAMETER ForwardCommand
    The service-state command to invert (Stop-Service, Start-Service, Set-Service).
.OUTPUTS
    System.String. Rollback command, or $null when not derivable.
#>
function ConvertTo-ServiceRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ForwardCommand
    )

    $svcMatch = [regex]::Match($ForwardCommand, "(?:Stop-Service|Start-Service|Set-Service|Restart-Service)\s+(?:-Name\s+)?['""]?([\w\-\$]+)['""]?")
    if (-not $svcMatch.Success) { return $null }
    $serviceName = $svcMatch.Groups[1].Value

    try {
        $svc = Get-Service -Name $serviceName -ErrorAction Stop
        $currentStatus = $svc.Status
        $currentStartType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop).StartMode

        $statusInverse = switch ($currentStatus) {
            'Running' { "Stop-Service -Name '$serviceName' -Force -ErrorAction SilentlyContinue" }
            'Stopped' { "Start-Service -Name '$serviceName' -ErrorAction SilentlyContinue" }
            default   { $null }
        }

        if ($ForwardCommand -match "Set-Service.*-StartupType") {
            return "Set-Service -Name '$serviceName' -StartupType $currentStartType"
        }
        return $statusInverse
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Classify the operational impact of a remediation command.
.DESCRIPTION
    Inspect a remediation string and return an impact classification used by
    the orchestrator to summarize what an operator is committing to before
    confirmation. The classification considers reboot requirements, session
    impact, service disruption, and network effects.
.PARAMETER Remediation
    The remediation command string.
.OUTPUTS
    Hashtable with Category, RequiresReboot, RequiresLogoff, ServiceImpact,
    NetworkImpact, and Reversible properties.
#>
function Get-RemediationImpact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Remediation
    )

    $impact = @{
        Category       = 'None'
        RequiresReboot = $false
        RequiresLogoff = $false
        ServiceImpact  = $false
        NetworkImpact  = $false
        Reversible     = $true
    }

    if ([string]::IsNullOrWhiteSpace($Remediation)) {
        return $impact
    }

    $rem = $Remediation

    if ($rem -match 'Restart-Computer|shutdown\s+/r|bcdedit') {
        $impact.RequiresReboot = $true
        $impact.Category = 'RequiresRestart'
    }

    $rebootRequiringRegistryNames = @(
        'EnableLUA', 'RunAsPPL', 'LsaCfgFlags', 'NoLMHash', 'LmCompatibilityLevel',
        'EnableVirtualizationBasedSecurity', 'RequirePlatformSecurityFeatures',
        'NoAutoUpdate', 'fDenyTSConnections', 'RestrictAnonymous'
    )
    foreach ($rebootName in $rebootRequiringRegistryNames) {
        if ($rem -match "\b$rebootName\b") {
            $impact.RequiresReboot = $true
            $impact.Category = 'RequiresRestart'
            break
        }
    }

    if ($rem -match 'logoff|gpupdate.*\/logoff|klist purge') {
        $impact.RequiresLogoff = $true
        if ($impact.Category -eq 'None') { $impact.Category = 'RequiresLogoff' }
    }

    if ($rem -match '(?:Stop|Restart|Set)-Service|net\s+stop|sc\s+(?:stop|config)') {
        $impact.ServiceImpact = $true
        if ($impact.Category -eq 'None') { $impact.Category = 'ServiceImpact' }
    }

    if ($rem -match 'Set-NetFirewall|netsh\s+advfirewall|Disable-NetAdapter|Set-NetAdapter|Disable-NetAdapterBinding') {
        $impact.NetworkImpact = $true
        if ($impact.Category -eq 'None') { $impact.Category = 'NetworkImpact' }
    }

    if ($rem -match 'Format-|Remove-Item.*-Recurse|Clear-Disk|Reset-') {
        $impact.Reversible = $false
        $impact.Category = 'Destructive'
    }

    if ($impact.Category -eq 'None' -and $rem -match 'Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|reg\s+add|reg\s+delete') {
        $impact.Category = 'Reversible'
    }

    return $impact
}

<#
.SYNOPSIS
    Calculate a 1-100 risk priority score for a single result object.
.DESCRIPTION
    Combine severity, exploitability heuristics, exposure heuristics, and asset
    criticality into a normalized score that reflects which findings deserve
    earliest remediation. Result is independent from raw severity and accounts
    for environmental factors.
.PARAMETER Result
    A single audit result PSCustomObject.
.PARAMETER ExposureContext
    Optional hashtable. Recognized keys: IsDomainController (bool),
    IsInternetFacing (bool), HasListeningServices (bool).
.OUTPUTS
    Integer between 1 and 100.
#>
function Get-RiskPriorityScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Result,
        [hashtable]$ExposureContext = @{}
    )

    $severityWeight = switch ($Result.Severity) {
        'Critical'      { 40 }
        'High'          { 30 }
        'Medium'        { 18 }
        'Low'           { 8 }
        'Informational' { 2 }
        default         { 10 }
    }

    $exploitability = 0
    $exploitableKeywords = 'SMBv1|TLS 1\.0|TLS 1\.1|SSL|RC4|MD5|NTLM|WDigest|LLMNR|NetBIOS|Anonymous|Guest|Print Spooler|RDP|WinRM'
    if ($Result.Message -match $exploitableKeywords -or $Result.Category -match $exploitableKeywords) {
        $exploitability = 25
    }
    elseif ($Result.Message -match 'enabled|allowed|permitted' -and $Result.Status -eq 'Fail') {
        $exploitability = 15
    }
    else {
        $exploitability = 5
    }

    $exposure = 5
    if ($ExposureContext.ContainsKey('IsInternetFacing') -and $ExposureContext.IsInternetFacing) {
        $exposure += 12
    }
    if ($ExposureContext.ContainsKey('HasListeningServices') -and $ExposureContext.HasListeningServices) {
        $exposure += 5
    }

    $criticality = 5
    if ($ExposureContext.ContainsKey('IsDomainController') -and $ExposureContext.IsDomainController) {
        $criticality = 10
    }

    $statusModifier = switch ($Result.Status) {
        'Fail'    { 1.0 }
        'Warning' { 0.6 }
        'Error'   { 0.5 }
        'Info'    { 0.2 }
        'Pass'    { 0.0 }
        default   { 0.5 }
    }

    $rawScore = ($severityWeight + $exploitability + $exposure + $criticality) * $statusModifier
    $bounded = [Math]::Max(1, [Math]::Min(100, [int][Math]::Round($rawScore)))
    return $bounded
}

<#
.SYNOPSIS
    Detect compensating controls that mitigate a failed check.
.DESCRIPTION
    Inspect the full result set for known compensating-control pairs. When a
    failed check has a corresponding compensating control passing elsewhere
    in the audit, return information allowing the caller to display the
    mitigation context or downgrade severity for prioritization.
.PARAMETER Results
    The complete audit result array (all modules).
.OUTPUTS
    Array of hashtables with FailedCheck, CompensatingControl, and Description.
#>
function Find-CompensatingControls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    $compensationMap = @(
        @{
            FailedPattern         = 'RunAsPPL|LSA Protection'
            CompensatingPattern   = 'Credential Guard|EnableVirtualizationBasedSecurity'
            Description           = 'Credential Guard provides comparable LSASS credential protection through VBS isolation.'
        },
        @{
            FailedPattern         = 'WDigest'
            CompensatingPattern   = 'Credential Guard|EnableVirtualizationBasedSecurity'
            Description           = 'Credential Guard prevents WDigest credential extraction even when UseLogonCredential is permissive.'
        },
        @{
            FailedPattern         = 'SMBv1'
            CompensatingPattern   = 'firewall.*SMB|RequireSecuritySignature'
            Description           = 'Network-layer SMB restrictions or signing requirements may compensate for legacy protocol exposure.'
        },
        @{
            FailedPattern         = 'NoLMHash|LM Hash'
            CompensatingPattern   = 'LmCompatibilityLevel.*5|NTLMv2 only'
            Description           = 'Restricting authentication to NTLMv2 prevents LM hash use even when storage is permitted.'
        },
        @{
            FailedPattern         = 'PasswordExpiry|Password.*Age'
            CompensatingPattern   = 'Multi.?Factor|MFA|Windows Hello|Smart Card'
            Description           = 'Multi-factor or certificate-based authentication reduces reliance on password rotation policy.'
        }
    )

    $compensations = @()
    $passResults = @($Results | Where-Object { $_.Status -eq 'Pass' })

    foreach ($result in $Results) {
        if ($result.Status -ne 'Fail' -and $result.Status -ne 'Warning') { continue }
        $combined = "$($result.Category) $($result.Message)"

        foreach ($mapping in $compensationMap) {
            if ($combined -match $mapping.FailedPattern) {
                $compensator = $passResults | Where-Object {
                    "$($_.Category) $($_.Message)" -match $mapping.CompensatingPattern
                } | Select-Object -First 1

                if ($compensator) {
                    $compensations += @{
                        FailedCheck         = $result
                        CompensatingControl = $compensator
                        Description         = $mapping.Description
                    }
                }
            }
        }
    }

    return $compensations
}

<#
.SYNOPSIS
    Identify check results sharing the same underlying technical assertion.
.DESCRIPTION
    Group results across multiple compliance modules that test the same
    underlying control (same registry value, service, or audit subcategory).
    The returned grouping enables a consolidated view that shows one finding
    per real-world control state with all framework references attached,
    reducing duplicate noise in remediation planning.
.PARAMETER Results
    The complete audit result array (all modules).
.OUTPUTS
    Array of hashtables with Signature, Frameworks, Status, and Members.
#>
function Find-CrossFrameworkCorrelations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    $signaturePatterns = @{
        'SMBv1 Disabled'                    = 'SMBv1|SMB.*1\.0|SMB.*Version 1'
        'TLS 1.0 Disabled'                  = 'TLS\s*1\.0'
        'TLS 1.1 Disabled'                  = 'TLS\s*1\.1'
        'LLMNR Disabled'                    = 'LLMNR|EnableMulticast'
        'NetBIOS over TCP/IP Disabled'      = 'NetBIOS|NodeType'
        'WDigest Credential Storage'        = 'WDigest|UseLogonCredential'
        'NTLMv1 Restricted'                 = 'LmCompatibilityLevel|NTLMv1'
        'Anonymous Access Restricted'       = 'RestrictAnonymous|Anonymous'
        'UAC Enabled'                       = 'EnableLUA|UAC'
        'LSA Protection (RunAsPPL)'         = 'RunAsPPL|LSA Protection'
        'Credential Guard Active'           = 'Credential Guard|EnableVirtualizationBasedSecurity'
        'BitLocker on System Drive'         = 'BitLocker.*(?:C:|System|OS Drive)'
        'Secure Boot Enabled'               = 'Secure Boot|SecureBoot'
        'Defender Real-Time Protection'     = 'Real.?Time.*Protection|DisableRealtimeMonitoring'
        'Firewall Profile Enabled'          = 'Firewall.*(?:Domain|Private|Public)'
        'PowerShell Script Block Logging'   = 'ScriptBlockLogging'
        'Audit Process Creation'            = 'Process Creation.*Audit|Audit.*Process Creation'
        'RDP NLA Required'                  = 'NLA|UserAuthentication.*1|Network Level Authentication'
        'Print Spooler Restricted'          = 'Print Spooler|Spooler.*service'
        'Remote Registry Service'           = 'RemoteRegistry'
    }

    $correlations = @()
    foreach ($signature in $signaturePatterns.Keys) {
        $pattern = $signaturePatterns[$signature]
        $matchingResults = @($Results | Where-Object {
            "$($_.Category) $($_.Message)" -match $pattern
        })

        if ($matchingResults.Count -ge 2) {
            $frameworks = @($matchingResults | Select-Object -ExpandProperty Module -Unique)
            $statuses = @($matchingResults | Select-Object -ExpandProperty Status -Unique)
            $consensusStatus = if ($statuses -contains 'Fail') { 'Fail' }
                              elseif ($statuses -contains 'Warning') { 'Warning' }
                              elseif ($statuses -contains 'Pass') { 'Pass' }
                              else { $statuses[0] }

            $correlations += @{
                Signature   = $signature
                Frameworks  = $frameworks
                Status      = $consensusStatus
                MemberCount = $matchingResults.Count
                Members     = $matchingResults
            }
        }
    }

    return $correlations
}

<#
.SYNOPSIS
    Compare current audit results against a stored baseline.
.DESCRIPTION
    Load a baseline JSON produced by a previous audit and identify drift:
    new failures (absent from baseline), resolved findings (failing in baseline,
    now passing), regressions (passing in baseline, now failing), and stable
    findings (status unchanged). The comparison key is Module+Category+Message.
.PARAMETER CurrentResults
    The current audit result array.
.PARAMETER BaselinePath
    Path to a baseline JSON file.
.OUTPUTS
    Hashtable with NewFailures, Resolved, Regressions, Stable, BaselineDate,
    and BaselineHost properties.
#>
function Compare-ToBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$CurrentResults,
        [Parameter(Mandatory = $true)]
        [string]$BaselinePath
    )

    if (-not (Test-Path $BaselinePath)) {
        throw "Baseline file not found: $BaselinePath"
    }

    $baseline = $null
    try {
        $baseline = Get-Content $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to parse baseline file: $($_.Exception.Message)"
    }

    $baselineResults = if ($baseline.Results) { $baseline.Results } else { $baseline }
    $baselineDate = if ($baseline.GeneratedAt) { $baseline.GeneratedAt } else { 'Unknown' }
    $baselineHost = if ($baseline.ComputerName) { $baseline.ComputerName } else { 'Unknown' }

    $makeKey = { param($r) "$($r.Module)|$($r.Category)|$($r.Message)" }

    $baselineMap = @{}
    foreach ($br in $baselineResults) {
        $key = & $makeKey $br
        $baselineMap[$key] = $br
    }

    $currentMap = @{}
    foreach ($cr in $CurrentResults) {
        $key = & $makeKey $cr
        $currentMap[$key] = $cr
    }

    $newFailures = @()
    $resolved = @()
    $regressions = @()
    $stable = @()

    foreach ($key in $currentMap.Keys) {
        $current = $currentMap[$key]
        if (-not $baselineMap.ContainsKey($key)) {
            if ($current.Status -in @('Fail', 'Warning')) {
                $newFailures += $current
            }
            continue
        }
        $prior = $baselineMap[$key]
        if ($prior.Status -in @('Fail', 'Warning') -and $current.Status -eq 'Pass') {
            $resolved += $current
        }
        elseif ($prior.Status -eq 'Pass' -and $current.Status -in @('Fail', 'Warning')) {
            $regressions += $current
        }
        else {
            $stable += $current
        }
    }

    return @{
        NewFailures   = $newFailures
        Resolved      = $resolved
        Regressions   = $regressions
        Stable        = $stable
        BaselineDate  = $baselineDate
        BaselineHost  = $baselineHost
        BaselineCount = $baselineResults.Count
        CurrentCount  = $CurrentResults.Count
    }
}

<#
.SYNOPSIS
    Construct a binary registry policy file (.pol) from remediation entries.
.DESCRIPTION
    Generate a Group Policy registry.pol file from a collection of registry-based
    remediations. The output follows the Microsoft .pol binary format: signature
    PReg (50 52 65 67 in UTF-16LE) plus version (1 00 00 00 LE), followed by
    null-delimited UTF-16LE policy entries with the structure
    [;key;value;type;size;data;]. Only registry-modifying remediations are
    converted; non-registry remediations are skipped with a warning return.
.PARAMETER Remediations
    Array of remediation strings.
.PARAMETER OutputPath
    Destination path for the .pol file.
.OUTPUTS
    Hashtable with WrittenCount, SkippedCount, and OutputPath.
#>
function Export-RegistryPolicyFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Remediations,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $regTypeMap = @{
        'String'       = 1
        'ExpandString' = 2
        'Binary'       = 3
        'DWord'        = 4
        'DWordBE'      = 5
        'MultiString'  = 7
        'QWord'        = 11
    }

    $polEntries = New-Object System.Collections.Generic.List[byte]
    $headerBytes = [System.Text.Encoding]::Unicode.GetBytes('PReg')
    $polEntries.AddRange([byte[]]$headerBytes)
    $polEntries.AddRange([byte[]]@(0x01, 0x00, 0x00, 0x00))

    $written = 0
    $skipped = 0

    foreach ($rem in $Remediations) {
        $pattern = "Set-ItemProperty\s+-Path\s+['""]([^'""]+)['""].*?-Name\s+['""]?([\w\(\)\s\-\.]+?)['""]?\s+-Value\s+([^\s;]+)(?:\s+-Type\s+(\w+))?"
        $match = [regex]::Match($rem, $pattern)
        if (-not $match.Success) { $skipped++; continue }

        $regPath = $match.Groups[1].Value
        $regName = $match.Groups[2].Value.Trim()
        $regValue = $match.Groups[3].Value
        $regTypeName = if ($match.Groups[4].Success) { $match.Groups[4].Value } else { 'DWord' }

        $hivePrefix = ''
        if ($regPath -match '^HKLM:\\(.+)$') {
            $relativePath = $matches[1]
        }
        elseif ($regPath -match '^HKCU:\\(.+)$') {
            $relativePath = $matches[1]
        }
        else {
            $skipped++
            continue
        }

        if (-not $regTypeMap.ContainsKey($regTypeName)) {
            $skipped++
            continue
        }
        $typeCode = $regTypeMap[$regTypeName]

        $valueBytes = $null
        switch ($regTypeName) {
            'DWord' {
                $intValue = 0
                if (-not [int]::TryParse($regValue, [ref]$intValue)) { $skipped++; continue }
                $valueBytes = [System.BitConverter]::GetBytes([uint32]$intValue)
            }
            'QWord' {
                $longValue = 0L
                if (-not [long]::TryParse($regValue, [ref]$longValue)) { $skipped++; continue }
                $valueBytes = [System.BitConverter]::GetBytes([uint64]$longValue)
            }
            default {
                $stringValue = $regValue.Trim("'", '"')
                $valueBytes = [System.Text.Encoding]::Unicode.GetBytes($stringValue + "`0")
            }
        }

        $entryBytes = New-Object System.Collections.Generic.List[byte]
        $entryBytes.AddRange([byte[]]@(0x5B, 0x00))
        $entryBytes.AddRange([byte[]]([System.Text.Encoding]::Unicode.GetBytes($relativePath + "`0")))
        $entryBytes.AddRange([byte[]]@(0x3B, 0x00))
        $entryBytes.AddRange([byte[]]([System.Text.Encoding]::Unicode.GetBytes($regName + "`0")))
        $entryBytes.AddRange([byte[]]@(0x3B, 0x00))
        $entryBytes.AddRange([byte[]]([System.BitConverter]::GetBytes([uint32]$typeCode)))
        $entryBytes.AddRange([byte[]]@(0x3B, 0x00))
        $entryBytes.AddRange([byte[]]([System.BitConverter]::GetBytes([uint32]$valueBytes.Length)))
        $entryBytes.AddRange([byte[]]@(0x3B, 0x00))
        $entryBytes.AddRange([byte[]]$valueBytes)
        $entryBytes.AddRange([byte[]]@(0x5D, 0x00))

        $polEntries.AddRange($entryBytes)
        $written++
    }

    [System.IO.File]::WriteAllBytes($OutputPath, $polEntries.ToArray())

    return @{
        WrittenCount = $written
        SkippedCount = $skipped
        OutputPath   = $OutputPath
    }
}

<#
.SYNOPSIS
    Determine whether the host appears internet-facing for risk scoring.
.DESCRIPTION
    Heuristic check used to inform Get-RiskPriorityScore exposure context.
    Inspects routing table for default gateway with a public next-hop and
    confirms public IP assignment on at least one active adapter.
.OUTPUTS
    Boolean.
#>
function Test-InternetFacingHost {
    [CmdletBinding()]
    param()

    try {
        $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
        if (-not $routes) { return $false }

        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($addr in $adapters) {
            $ip = $addr.IPAddress
            $isPrivate = $ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0\.)'
            if (-not $isPrivate) { return $true }
        }
        return $false
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Determine whether the host is a domain controller for risk scoring.
.OUTPUTS
    Boolean.
#>
function Test-DomainControllerHost {
    [CmdletBinding()]
    param()

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.DomainRole -in @(4, 5)) { return $true }
        return $false
    }
    catch {
        return $false
    }
}
