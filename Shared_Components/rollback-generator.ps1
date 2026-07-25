# rollback-generator.ps1
# State capture and rollback script generation for the Windows Security Audit framework
# Version: 6.6.0

<#
.SYNOPSIS
    Captures pre-change system state and generates a standalone rollback
    script, enabling the framework's capture-before-apply rule.

.DESCRIPTION
    Parity equivalent of the Linux rollback_generator component. Consumes the
    rollback-capture specs declared by remediation-library.ps1 and produces:

    1. CaptureRecord objects -- one per spec -- holding the pre-change state:
         Type, Target, State ('absent' when the setting does not exist),
         Payload (Base64 for exported file content), CapturedAt, Error.
       Capture failures become Error records; capture NEVER throws and NEVER
       modifies state (read-only exports only).

    2. A standalone rollback .ps1 (New-RollbackScript) that restores captured
       state in REVERSE capture order (LIFO), with:
         - its own typed confirmation prompt before any restore action
         - per-record guarded restore blocks (one failure cannot abort the
           remaining restores; failures are reported at the end)
         - absent-value semantics: values that did not exist pre-change are
           REMOVED on rollback, not written back
         - Base64-embedded payloads for secedit/auditpol/file content so
           exported data cannot break the generated script's syntax
         - manual-type records emitted as prominent operator instructions

    Safety limits (mirroring the Linux component):
         - payload cap 1 MB per capture (larger exports become Error records)
         - file_content paths validated against a conservative safe-path
           pattern; non-conforming paths are refused as Error records

    Supported capture types (superset of the library's declared specs):
      registry_value, service_state, security_policy, audit_policy,
      mp_preference, smb_server_config, windows_feature, local_user_enabled,
      eventlog_size, firewall_profile, file_content, manual

.EXAMPLE
    . .\shared_components\canonical-remediations.ps1
    . .\shared_components\remediation-library.ps1
    . .\shared_components\rollback-generator.ps1
    $plan = New-RemediationPlan -Topics @('GuestAccount','LsaProtection')
    $records = Invoke-PlanCapture -Plan $plan
    New-RollbackScript -CaptureRecords $records -OutputPath .\rollback.ps1

.NOTES
    Requires: PowerShell 5.1+
    Dependencies: none at load; capture handlers are availability-guarded
    Security: capture is strictly read-only; the generated script modifies
    state only after its own confirmation prompt
    Version: 6.6.0
#>

$script:MaxCaptureBytes = 1MB
# Conservative Windows path allowlist: drive-rooted, no reparse tricks, no quotes
$script:SafePathPattern = '^[A-Za-z]:\\[A-Za-z0-9 ._\-\\()]+$'

function New-CaptureRecord {
    param(
        [Parameter(Mandatory=$true)][string]$Type,
        [string]$Target = '',
        $State = $null,
        [string]$Payload = $null,
        [string]$ErrorMessage = $null,
        [string]$Note = $null
    )
    return [PSCustomObject]@{
        Type       = $Type
        Target     = $Target
        State      = $State
        Payload    = $Payload
        Note       = $Note
        CapturedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Error      = $ErrorMessage
    }
}

function ConvertTo-CappedBase64 {
    <#
    .SYNOPSIS
        Read a file into Base64 with the 1 MB cap; throws on oversize so the
        caller converts it into an Error record.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    $fi = Get-Item -Path $Path -ErrorAction Stop
    if ($fi.Length -gt $script:MaxCaptureBytes) {
        throw "capture exceeds $($script:MaxCaptureBytes) byte cap ($($fi.Length) bytes)"
    }
    $bytes = [System.IO.File]::ReadAllBytes($fi.FullName)
    return [Convert]::ToBase64String($bytes)
}

# ============================================================================
# Capture (read-only)
# ============================================================================
function Invoke-RollbackCapture {
    <#
    .SYNOPSIS
        Execute one capture spec (from a library entry's RollbackCapture)
        and return a CaptureRecord. Read-only; never throws.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Spec)
    $type = "$($Spec.Type)"
    try {
        switch ($type) {
            'registry_value' {
                $target = "$($Spec.Path)::$($Spec.Name)"
                try {
                    $item = Get-ItemProperty -Path $Spec.Path -Name $Spec.Name -ErrorAction Stop
                    $val = $item.$($Spec.Name)
                    $kind = $null
                    try { $kind = "$((Get-Item -Path $Spec.Path -ErrorAction Stop).GetValueKind($Spec.Name))" } catch { $kind = $null }
                    return New-CaptureRecord -Type $type -Target $target -State @{ Value = $val; Kind = $kind }
                } catch [System.Management.Automation.ItemNotFoundException] {
                    return New-CaptureRecord -Type $type -Target $target -State 'absent'
                } catch [System.Management.Automation.PSArgumentException] {
                    return New-CaptureRecord -Type $type -Target $target -State 'absent'
                }
            }
            'service_state' {
                $s = Get-Service -Name $Spec.Name -ErrorAction Stop
                $start = $null
                try { $start = "$($s.StartType)" } catch { $start = $null }
                return New-CaptureRecord -Type $type -Target $Spec.Name -State @{ Status = "$($s.Status)"; StartType = $start }
            }
            'security_policy' {
                if (-not (Get-Command 'secedit' -ErrorAction SilentlyContinue) -and -not (Get-Command 'secedit.exe' -ErrorAction SilentlyContinue)) {
                    throw 'secedit unavailable'
                }
                $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-secpol-" + [guid]::NewGuid().ToString('N') + ".inf")
                try {
                    & secedit /export /cfg $tmp /quiet 2>$null | Out-Null
                    if (-not (Test-Path $tmp)) { throw 'secedit export produced no file' }
                    $b64 = ConvertTo-CappedBase64 -Path $tmp
                    return New-CaptureRecord -Type $type -Target 'SECURITYPOLICY' -State 'exported' -Payload $b64
                } finally {
                    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
                }
            }
            'audit_policy' {
                if (-not (Get-Command 'auditpol' -ErrorAction SilentlyContinue) -and -not (Get-Command 'auditpol.exe' -ErrorAction SilentlyContinue)) {
                    throw 'auditpol unavailable'
                }
                $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wsa-auditpol-" + [guid]::NewGuid().ToString('N') + ".csv")
                try {
                    & auditpol /backup /file:$tmp 2>$null | Out-Null
                    if (-not (Test-Path $tmp)) { throw 'auditpol backup produced no file' }
                    $b64 = ConvertTo-CappedBase64 -Path $tmp
                    return New-CaptureRecord -Type $type -Target 'AUDITPOLICY' -State 'exported' -Payload $b64
                } finally {
                    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
                }
            }
            'mp_preference' {
                $mp = Get-MpPreference -ErrorAction Stop
                return New-CaptureRecord -Type $type -Target $Spec.Name -State @{ Value = $mp.$($Spec.Name) }
            }
            'smb_server_config' {
                $cfg = Get-SmbServerConfiguration -ErrorAction Stop
                return New-CaptureRecord -Type $type -Target $Spec.Name -State @{ Value = $cfg.$($Spec.Name) }
            }
            'windows_feature' {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $Spec.Name -ErrorAction Stop
                return New-CaptureRecord -Type $type -Target $Spec.Name -State @{ State = "$($f.State)" }
            }
            'local_user_enabled' {
                $u = Get-LocalUser -Name $Spec.Name -ErrorAction Stop
                return New-CaptureRecord -Type $type -Target $Spec.Name -State @{ Enabled = [bool]$u.Enabled }
            }
            'eventlog_size' {
                $l = Get-WinEvent -ListLog $Spec.LogName -ErrorAction Stop
                return New-CaptureRecord -Type $type -Target $Spec.LogName -State @{ MaximumSizeInBytes = [int64]$l.MaximumSizeInBytes }
            }
            'firewall_profile' {
                $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
                $states = @{}
                foreach ($fp in $profiles) { $states[$fp.Name] = [bool]$fp.Enabled }
                return New-CaptureRecord -Type $type -Target 'ALLPROFILES' -State $states
            }
            'file_content' {
                $path = "$($Spec.Path)"
                if ($path -notmatch $script:SafePathPattern) {
                    return New-CaptureRecord -Type $type -Target $path -ErrorMessage 'path refused by safe-path validation'
                }
                if (-not (Test-Path $path)) {
                    return New-CaptureRecord -Type $type -Target $path -State 'absent'
                }
                $b64 = ConvertTo-CappedBase64 -Path $path
                return New-CaptureRecord -Type $type -Target $path -State 'exists' -Payload $b64
            }
            'manual' {
                return New-CaptureRecord -Type $type -Target 'MANUAL' -State 'note' -Note "$($Spec.Note)"
            }
            default {
                return New-CaptureRecord -Type $type -Target "$($Spec.Name)$($Spec.Path)" -ErrorMessage "unknown capture type '$type'"
            }
        }
    } catch {
        return New-CaptureRecord -Type $type -Target "$($Spec.Name)$($Spec.Path)$($Spec.LogName)" -ErrorMessage "$($_.Exception.Message)"
    }
}

function Invoke-PlanCapture {
    <#
    .SYNOPSIS
        Capture pre-change state for every step of a remediation plan
        (New-RemediationPlan output). Returns records annotated with their
        originating topic, in plan order.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Plan)
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($step in @($Plan.Steps)) {
        foreach ($spec in @($step.RollbackCapture)) {
            $rec = Invoke-RollbackCapture -Spec $spec
            $rec | Add-Member -NotePropertyName Topic -NotePropertyValue $step.Topic -Force
            $records.Add($rec)
        }
        if (@($step.RollbackCapture).Count -eq 0) {
            $rec = New-CaptureRecord -Type 'none' -Target $step.Topic -State 'no capture declared' -Note 'This step declares no rollback capture (e.g. signature updates are not rolled back)'
            $rec | Add-Member -NotePropertyName Topic -NotePropertyValue $step.Topic -Force
            $records.Add($rec)
        }
    }
    return @($records)
}

# ============================================================================
# Rollback script generation
# ============================================================================
function New-RollbackScript {
    <#
    .SYNOPSIS
        Generate a standalone rollback .ps1 from capture records. Restores in
        REVERSE capture order; includes its own typed confirmation; guarded
        per-record blocks; failures reported at the end without aborting the
        remaining restores.
    .OUTPUTS
        The output path on success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][array]$CaptureRecords,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [string]$GeneratedBy = 'Windows Security Audit'
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Rollback script generated by $GeneratedBy")
    [void]$sb.AppendLine("# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("# Records: $(@($CaptureRecords).Count) (restored in reverse capture order)")
    [void]$sb.AppendLine("# This script modifies system state. Review it fully before running.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine('$ErrorActionPreference = "Continue"')
    [void]$sb.AppendLine('$confirmPhrase = "ROLLBACK"')
    [void]$sb.AppendLine('Write-Host "This will restore the captured pre-remediation state." -ForegroundColor Yellow')
    [void]$sb.AppendLine('$answer = Read-Host "Type $confirmPhrase to proceed"')
    [void]$sb.AppendLine('if ($answer -cne $confirmPhrase) { Write-Host "Aborted." -ForegroundColor Red; exit 1 }')
    [void]$sb.AppendLine('$failures = [System.Collections.Generic.List[string]]::new()')
    [void]$sb.AppendLine("")

    $ordered = @($CaptureRecords)
    [array]::Reverse($ordered)

    $idx = 0
    foreach ($rec in $ordered) {
        $idx++
        $topicLbl = if ($rec.PSObject.Properties.Name -contains 'Topic') { " (topic: $($rec.Topic))" } else { '' }
        [void]$sb.AppendLine("# --- [$idx/$(@($ordered).Count)] $($rec.Type) :: $($rec.Target)$topicLbl")

        if ($rec.Error) {
            [void]$sb.AppendLine("Write-Host '[$idx] SKIPPED: capture failed for $($rec.Type) $($rec.Target): $($rec.Error -replace ""'"",'')' -ForegroundColor Yellow")
            [void]$sb.AppendLine("")
            continue
        }
        if ($rec.Type -in @('none')) {
            [void]$sb.AppendLine("# No rollback action: $($rec.Note -replace '[\r\n]',' ')")
            [void]$sb.AppendLine("")
            continue
        }
        if ($rec.Type -eq 'manual') {
            [void]$sb.AppendLine("Write-Host '[$idx] MANUAL STEP REQUIRED: $(($rec.Note) -replace ""'"",'' -replace '[\r\n]',' ')' -ForegroundColor Magenta")
            [void]$sb.AppendLine("")
            continue
        }

        [void]$sb.AppendLine('try {')
        switch ($rec.Type) {
            'registry_value' {
                $path, $name = $rec.Target -split '::', 2
                if ("$($rec.State)" -eq 'absent') {
                    [void]$sb.AppendLine("    Remove-ItemProperty -Path '$path' -Name '$name' -ErrorAction Stop")
                    [void]$sb.AppendLine("    Write-Host '[$idx] removed $name (was absent before remediation)' -ForegroundColor Green")
                } else {
                    $val = $rec.State.Value
                    $valLit = if ($val -is [string]) { "'" + ($val -replace "'", "''") + "'" } else { "$val" }
                    $typeArg = if ($rec.State.Kind) { " -Type $($rec.State.Kind)" } else { '' }
                    [void]$sb.AppendLine("    if (-not (Test-Path '$path')) { New-Item -Path '$path' -Force | Out-Null }")
                    [void]$sb.AppendLine("    Set-ItemProperty -Path '$path' -Name '$name' -Value $valLit$typeArg -ErrorAction Stop")
                    [void]$sb.AppendLine("    Write-Host '[$idx] restored $name = $valLit' -ForegroundColor Green")
                }
            }
            'service_state' {
                $st = $rec.State
                if ($st.StartType) {
                    [void]$sb.AppendLine("    Set-Service -Name '$($rec.Target)' -StartupType $($st.StartType) -ErrorAction Stop")
                }
                if ("$($st.Status)" -eq 'Running') {
                    [void]$sb.AppendLine("    Start-Service -Name '$($rec.Target)' -ErrorAction Stop")
                } elseif ("$($st.Status)" -eq 'Stopped') {
                    [void]$sb.AppendLine("    Stop-Service -Name '$($rec.Target)' -Force -ErrorAction Stop")
                }
                [void]$sb.AppendLine("    Write-Host '[$idx] restored service $($rec.Target) to $($st.Status)/$($st.StartType)' -ForegroundColor Green")
            }
            'security_policy' {
                [void]$sb.AppendLine("    `$inf = Join-Path ([System.IO.Path]::GetTempPath()) 'wsa-rollback-secpol.inf'")
                [void]$sb.AppendLine("    [System.IO.File]::WriteAllBytes(`$inf, [Convert]::FromBase64String('$($rec.Payload)'))")
                [void]$sb.AppendLine("    `$db = Join-Path ([System.IO.Path]::GetTempPath()) 'wsa-rollback-secpol.sdb'")
                [void]$sb.AppendLine("    & secedit /configure /db `$db /cfg `$inf /quiet")
                [void]$sb.AppendLine("    Remove-Item `$inf, `$db -Force -ErrorAction SilentlyContinue")
                [void]$sb.AppendLine("    Write-Host '[$idx] security policy restored from pre-remediation export' -ForegroundColor Green")
            }
            'audit_policy' {
                [void]$sb.AppendLine("    `$csv = Join-Path ([System.IO.Path]::GetTempPath()) 'wsa-rollback-auditpol.csv'")
                [void]$sb.AppendLine("    [System.IO.File]::WriteAllBytes(`$csv, [Convert]::FromBase64String('$($rec.Payload)'))")
                [void]$sb.AppendLine("    & auditpol /restore /file:`$csv")
                [void]$sb.AppendLine("    Remove-Item `$csv -Force -ErrorAction SilentlyContinue")
                [void]$sb.AppendLine("    Write-Host '[$idx] audit policy restored from pre-remediation backup' -ForegroundColor Green")
            }
            'mp_preference' {
                $val = $rec.State.Value
                $valLit = if ($val -is [string]) { "'" + ($val -replace "'", "''") + "'" } elseif ($val -is [bool]) { "`$$val" } else { "$val" }
                [void]$sb.AppendLine("    Set-MpPreference -$($rec.Target) $valLit -ErrorAction Stop")
                [void]$sb.AppendLine("    Write-Host '[$idx] restored Defender preference $($rec.Target)' -ForegroundColor Green")
            }
            'smb_server_config' {
                $val = $rec.State.Value
                $valLit = if ($val -is [bool]) { "`$$val" } else { "$val" }
                [void]$sb.AppendLine("    Set-SmbServerConfiguration -$($rec.Target) $valLit -Force -ErrorAction Stop")
                [void]$sb.AppendLine("    Write-Host '[$idx] restored SMB server setting $($rec.Target)' -ForegroundColor Green")
            }
            'windows_feature' {
                if ("$($rec.State.State)" -eq 'Enabled') {
                    [void]$sb.AppendLine("    Enable-WindowsOptionalFeature -Online -FeatureName '$($rec.Target)' -NoRestart -ErrorAction Stop | Out-Null")
                } else {
                    [void]$sb.AppendLine("    Disable-WindowsOptionalFeature -Online -FeatureName '$($rec.Target)' -NoRestart -ErrorAction Stop | Out-Null")
                }
                [void]$sb.AppendLine("    Write-Host '[$idx] restored feature $($rec.Target) to $($rec.State.State) (reboot may be required)' -ForegroundColor Green")
            }
            'local_user_enabled' {
                if ($rec.State.Enabled) {
                    [void]$sb.AppendLine("    Enable-LocalUser -Name '$($rec.Target)' -ErrorAction Stop")
                } else {
                    [void]$sb.AppendLine("    Disable-LocalUser -Name '$($rec.Target)' -ErrorAction Stop")
                }
                [void]$sb.AppendLine("    Write-Host '[$idx] restored account $($rec.Target) enabled=$($rec.State.Enabled)' -ForegroundColor Green")
            }
            'eventlog_size' {
                [void]$sb.AppendLine("    & wevtutil sl '$($rec.Target)' /ms:$($rec.State.MaximumSizeInBytes)")
                [void]$sb.AppendLine("    Write-Host '[$idx] restored $($rec.Target) log size to $($rec.State.MaximumSizeInBytes) bytes' -ForegroundColor Green")
            }
            'firewall_profile' {
                foreach ($k in $rec.State.Keys) {
                    $en = if ($rec.State[$k]) { 'True' } else { 'False' }
                    [void]$sb.AppendLine("    Set-NetFirewallProfile -Name '$k' -Enabled $en -ErrorAction Stop")
                }
                [void]$sb.AppendLine("    Write-Host '[$idx] restored firewall profile enablement' -ForegroundColor Green")
            }
            'file_content' {
                if ("$($rec.State)" -eq 'absent') {
                    [void]$sb.AppendLine("    Remove-Item -Path '$($rec.Target)' -Force -ErrorAction Stop")
                    [void]$sb.AppendLine("    Write-Host '[$idx] removed $($rec.Target) (absent before remediation)' -ForegroundColor Green")
                } else {
                    [void]$sb.AppendLine("    [System.IO.File]::WriteAllBytes('$($rec.Target)', [Convert]::FromBase64String('$($rec.Payload)'))")
                    [void]$sb.AppendLine("    Write-Host '[$idx] restored file content: $($rec.Target)' -ForegroundColor Green")
                }
            }
            default {
                [void]$sb.AppendLine("    Write-Host '[$idx] no restore handler for type $($rec.Type)' -ForegroundColor Yellow")
            }
        }
        [void]$sb.AppendLine('} catch {')
        [void]$sb.AppendLine("    `$failures.Add('[$idx] $($rec.Type) $($rec.Target -replace ""'"",'') : ' + `$_.Exception.Message)")
        [void]$sb.AppendLine('}')
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine('if ($failures.Count -gt 0) {')
    [void]$sb.AppendLine('    Write-Host "Rollback completed with $($failures.Count) failure(s):" -ForegroundColor Red')
    [void]$sb.AppendLine('    $failures | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }')
    [void]$sb.AppendLine('    exit 2')
    [void]$sb.AppendLine('}')
    [void]$sb.AppendLine('Write-Host "Rollback completed successfully." -ForegroundColor Green')

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
    return $OutputPath
}
