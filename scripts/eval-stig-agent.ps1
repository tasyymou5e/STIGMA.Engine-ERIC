#Requires -Version 5.1
<#
.SYNOPSIS
    STIGMA EvalStig Agent — background worker that processes Evaluate-STIG job files.

.DESCRIPTION
    Polls ./scripts/eval-jobs/ every 5 seconds for pending .json job files.
    Processes ONE job at a time (sequential) to avoid resource contention.
    Writes a .log file alongside each job for real-time UI streaming.
    Writes a .done file (value: "completed" or "failed") when finished.
    Writes a .files JSON file listing all .cklb / .ckl output files.
    Respects a .cancel marker file to abort a running job.

.NOTES
    Run manually : pwsh -File scripts\eval-stig-agent.ps1
    Install task : pwsh -File scripts\setup-eval-stig-agent.ps1
#>

param(
    [int]$PollIntervalSeconds = 5,
    [int]$CancelCheckSeconds  = 30,
    [int]$MaxAgentLogLines    = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Paths ──────────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$JobsDir     = Join-Path $ScriptDir   'eval-jobs'
$AgentLog    = Join-Path $ScriptDir   'eval-stig-agent.log'

# ── Locate Invoke-EvaluateSTIG.ps1 ────────────────────────────────────────────
$InvokeSTIG = $null
$CandidatePaths = @(
    'C:\Temp\Evaulate.STIG\Auxiliary\Invoke-EvaluateSTIG.ps1',
    (Join-Path $ProjectRoot 'Evaulate.STIG\Auxiliary\Invoke-EvaluateSTIG.ps1')
)
foreach ($p in $CandidatePaths) {
    if (Test-Path $p) { $InvokeSTIG = $p; break }
}
if (-not $InvokeSTIG) {
    $msg = "Invoke-EvaluateSTIG.ps1 not found. Searched:`n" +
           ($CandidatePaths -join "`n")
    Add-Content -Path $AgentLog -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] $msg" -Encoding UTF8
    Write-Error $msg
    exit 1
}

# ── Ensure jobs directory exists ───────────────────────────────────────────────
if (-not (Test-Path $JobsDir)) {
    New-Item -ItemType Directory -Path $JobsDir -Force | Out-Null
}

# ── Logging ───────────────────────────────────────────────────────────────────
function Write-AgentLog {
    param(
        [ValidateSet('INFO','WARN','ERROR','SCAN')]
        [string]$Level   = 'INFO',
        [string]$Message
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $AgentLog -Value $line -Encoding UTF8

    # Rolling cap
    try {
        $lines = Get-Content $AgentLog -ErrorAction Stop
        if ($lines.Count -gt $MaxAgentLogLines) {
            $lines | Select-Object -Last ($MaxAgentLogLines - 500) |
                Set-Content $AgentLog -Encoding UTF8
        }
    } catch {}
}

# Append a line to an individual job .log file
function Write-JobLog {
    param([string]$LogFile, [string]$Level = 'INFO', [string]$Message)
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

# ── Get-StigOutputFiles ────────────────────────────────────────────────────────
# Finds all .cklb and .ckl files generated under outputPath\<hostname>\
# and writes them to a .files JSON file alongside the .done marker.
function Get-StigOutputFiles {
    param(
        [string]$OutputPath,
        [string]$FilesJsonPath
    )

    $found = @()
    if (Test-Path $OutputPath) {
        $found = Get-ChildItem -Path $OutputPath -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -in '.cklb', '.ckl' } |
                 Select-Object -ExpandProperty FullName
    }

    $payload = @{
        discoveredAt = (Get-Date -Format 'o')
        outputPath   = $OutputPath
        files        = @($found)
        count        = $found.Count
    }

    $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $FilesJsonPath -Encoding UTF8
    return $found.Count
}

# ── Process a single job ───────────────────────────────────────────────────────
function Invoke-Job {
    param([System.IO.FileInfo]$JobFile)

    $base       = $JobFile.FullName -replace '\.json$', ''
    $runningFile = "$base.running"
    $doneFile    = "$base.done"
    $logFile     = "$base.log"
    $filesFile   = "$base.files"
    $cancelFile  = "$base.cancel"

    # ── Create .running marker ────────────────────────────────────────────────
    Set-Content -Path $runningFile -Value (Get-Date -Format 'o') -Encoding UTF8

    Write-AgentLog INFO "Processing job: $($JobFile.Name)"
    Write-JobLog $logFile INFO "=== STIGMA EvalStig Agent — Job Start ==="
    Write-JobLog $logFile INFO "Job file : $($JobFile.FullName)"
    Write-JobLog $logFile INFO "Agent    : $InvokeSTIG"

    # ── Read + zero credential ─────────────────────────────────────────────────
    $job = $null
    try {
        $raw = Get-Content $JobFile.FullName -Raw -Encoding UTF8
        $job = $raw | ConvertFrom-Json
    } catch {
        Write-JobLog $logFile ERROR "Failed to parse job JSON: $_"
        Write-AgentLog ERROR "Failed to parse $($JobFile.Name): $_"
        Set-Content -Path $doneFile -Value 'failed' -Encoding UTF8
        Remove-Item $runningFile -ErrorAction SilentlyContinue
        return
    }

    # Zero the credential immediately after reading
    if ($job.PSObject.Properties['credential']) {
        $job.credential = $null
        try {
            $sanitized = $raw | ConvertFrom-Json
            $sanitized.credential = $null
            $sanitized | ConvertTo-Json -Depth 10 |
                Set-Content -Path $JobFile.FullName -Encoding UTF8
        } catch {}
    }

    # ── Extract job parameters ─────────────────────────────────────────────────
    $outputPath     = if ($job.PSObject.Properties['outputPath'])     { $job.outputPath }     else { $null }
    $selectSTIG     = if ($job.PSObject.Properties['selectSTIG'])     { $job.selectSTIG }     else { $null }
    $excludeSTIG    = if ($job.PSObject.Properties['excludeSTIG'])    { $job.excludeSTIG }    else { $null }
    $answerKey      = if ($job.PSObject.Properties['answerKey'])      { $job.answerKey }      else { 'DEFAULT' }
    $afPath         = if ($job.PSObject.Properties['afPath'])         { $job.afPath }         else { $null }
    $output         = if ($job.PSObject.Properties['output'])         { $job.output }         else { 'CKL,CKLB' }
    $scanType       = if ($job.PSObject.Properties['scanType'])       { $job.scanType }       else { 'Unclassified' }
    $marking        = if ($job.PSObject.Properties['marking'])        { $job.marking }        else { $null }
    $previousToKeep = if ($job.PSObject.Properties['previousToKeep']) { $job.previousToKeep } else { 3 }
    $vulnTimeout    = if ($job.PSObject.Properties['vulnTimeout'])    { $job.vulnTimeout }    else { 15 }

    # ── WinRM connection settings (default: HTTPS port 5986) ─────────────────
    $winrmUseSSL       = if ($job.PSObject.Properties['winrmUseSSL'])      { [bool]$job.winrmUseSSL }      else { $true }
    $winrmPort         = if ($job.PSObject.Properties['winrmPort'])         { [int]$job.winrmPort }         else { if ($winrmUseSSL) { 5986 } else { 5985 } }
    $winrmSkipCertCheck = if ($job.PSObject.Properties['winrmSkipCertCheck']) { [bool]$job.winrmSkipCertCheck } else { $true }

    $protocol = if ($winrmUseSSL) { 'HTTPS' } else { 'HTTP' }
    Write-JobLog $logFile INFO "WinRM: $protocol port $winrmPort (SkipCertCheck=$winrmSkipCertCheck)"

    # Configure WSMan client settings for this session so Evaluate-STIG
    # inherits HTTPS/port when it creates PSSession objects internally.
    if ($winrmUseSSL) {
        try {
            # Trust all HTTPS targets (lab/domain certs without a trusted CA)
            $sessionOpts = New-PSSessionOption -SkipCACheck:$winrmSkipCertCheck `
                                               -SkipCNCheck:$winrmSkipCertCheck `
                                               -SkipRevocationCheck:$winrmSkipCertCheck `
                                               -Port $winrmPort
            # Set as the default so child calls inherit the options
            $PSDefaultParameterValues['New-PSSession:SessionOption'] = $sessionOpts
            $PSDefaultParameterValues['Invoke-Command:SessionOption'] = $sessionOpts
            $PSDefaultParameterValues['New-PSSession:UseSSL']         = $true
            $PSDefaultParameterValues['Invoke-Command:UseSSL']         = $true
            $PSDefaultParameterValues['New-PSSession:Port']            = $winrmPort
            $PSDefaultParameterValues['Invoke-Command:Port']           = $winrmPort
            Write-JobLog $logFile INFO "WinRM HTTPS session defaults configured (port $winrmPort)"
        } catch {
            Write-JobLog $logFile WARN "Could not set WinRM session defaults: $_ — scan will use system defaults"
        }
    } else {
        # HTTP (unencrypted) — only for isolated lab networks
        try {
            $sessionOpts = New-PSSessionOption -Port $winrmPort
            $PSDefaultParameterValues['New-PSSession:SessionOption'] = $sessionOpts
            $PSDefaultParameterValues['Invoke-Command:SessionOption'] = $sessionOpts
            $PSDefaultParameterValues['New-PSSession:Port']           = $winrmPort
            $PSDefaultParameterValues['Invoke-Command:Port']          = $winrmPort
            Write-JobLog $logFile WARN "WinRM HTTP (unencrypted) configured on port $winrmPort — use HTTPS in production"
        } catch {}
    }

    # ── Establish persistent PSSession to every remote target ────────────────
    # Sessions are created once here (port/SSL/creds set at session creation time).
    # All subsequent Invoke-Command calls reuse these sessions via Get-PSSession,
    # avoiding repeated authentication and connection setup overhead.
    $targetHosts    = @($job.targetHosts)
    $localAliases   = @('localhost', '127.0.0.1', '.')
    $remoteHosts    = $targetHosts | Where-Object { $_ -notin $localAliases }
    $localHosts     = $targetHosts | Where-Object { $_ -in  $localAliases }

    foreach ($h in $localHosts) {
        Write-JobLog $logFile INFO "Target '$h' is local — no PSSession needed"
    }

    # Build credential object if supplied
    $psCred = $null
    if ($job.PSObject.Properties['_credentialObj'] -and $job._credentialObj) {
        # already a PSCredential (set below before zeroing raw creds)
    }
    if ($psCred -eq $null -and
        $job.PSObject.Properties['credential'] -and $job.credential -and
        $job.credential.username -and $job.credential.password) {
        $secPw  = ConvertTo-SecureString $job.credential.password -AsPlainText -Force
        $psCred = New-Object PSCredential($job.credential.username, $secPw)
    }

    $establishedSessions = @()
    if ($remoteHosts.Count -gt 0) {
        Write-JobLog $logFile INFO "Establishing persistent PSSession(s) to: $($remoteHosts -join ', ')"

        $sessionParams = @{
            ComputerName  = $remoteHosts
            Port          = $winrmPort
            UseSSL        = $winrmUseSSL
            SessionOption = $sessionOpts
            ErrorAction   = 'SilentlyContinue'
        }
        if ($psCred) { $sessionParams['Credential'] = $psCred }

        try {
            $establishedSessions = @(New-PSSession @sessionParams)
        } catch {
            Write-JobLog $logFile WARN "New-PSSession error: $_ — will retry per-host"
        }

        # Per-host retry for any that failed
        $connectedNames = $establishedSessions | ForEach-Object { $_.ComputerName }
        foreach ($h in $remoteHosts) {
            if ($h -in $connectedNames) {
                $s = $establishedSessions | Where-Object { $_.ComputerName -eq $h } | Select-Object -First 1
                Write-JobLog $logFile INFO "PSSession OK — $h (Id=$($s.Id), State=$($s.State))"
                continue
            }
            Write-JobLog $logFile WARN "PSSession failed for $h — retrying individually"
            $single = @{ ComputerName = $h; Port = $winrmPort; UseSSL = $winrmUseSSL
                         SessionOption = $sessionOpts; ErrorAction = 'SilentlyContinue' }
            if ($psCred) { $single['Credential'] = $psCred }
            try {
                $s = New-PSSession @single
                if ($s) {
                    $establishedSessions += $s
                    Write-JobLog $logFile INFO "PSSession retry OK — $h (Id=$($s.Id))"
                }
            } catch {
                Write-JobLog $logFile WARN "PSSession retry failed for ${h}: $_ — target will be skipped or may error during scan"
                Write-JobLog $logFile WARN "To enable WinRM on $h run: Enable-PSRemoting -Force; winrm quickconfig -transport:https"
            }
        }

        # Pre-flight validation: run a lightweight probe over reused sessions
        if ($establishedSessions.Count -gt 0) {
            Write-JobLog $logFile INFO "Pre-flight probe via Get-PSSession ($($establishedSessions.Count) session(s))..."
            try {
                $probeResults = Invoke-Command -Session (Get-PSSession) -ScriptBlock {
                    [PSCustomObject]@{
                        Host      = $env:COMPUTERNAME
                        PSVersion = $PSVersionTable.PSVersion.ToString()
                        OS        = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                    }
                } -ErrorAction SilentlyContinue
                foreach ($r in $probeResults) {
                    if ($r) {
                        Write-JobLog $logFile INFO "  $($r.Host)  PSv$($r.PSVersion)  $($r.OS)"
                    }
                }
            } catch {
                Write-JobLog $logFile WARN "Pre-flight probe error (non-fatal): $_"
            }
        } else {
            Write-JobLog $logFile WARN "No remote sessions established — scan will attempt local execution only"
        }
    }

    # ── Ensure output directory ────────────────────────────────────────────────
    if ($outputPath -and -not (Test-Path $outputPath)) {
        try {
            New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
            Write-JobLog $logFile INFO "Created output directory: $outputPath"
        } catch {
            Write-JobLog $logFile WARN "Could not create output directory '$outputPath': $_"
        }
    }

    # ── Build Invoke-EvaluateSTIG parameters ──────────────────────────────────
    # Prefer passing pre-established PSSession objects so Invoke-EvaluateSTIG
    # reuses existing authenticated connections rather than creating new ones.
    # Fall back to -ComputerName if -PSSession is not supported.
    $invokeArgs = @()

    # Determine how to pass targets: PSSession (preferred) or ComputerName
    $evalStigCmd     = Get-Command $InvokeSTIG -ErrorAction SilentlyContinue
    $supportsSessions = $evalStigCmd -and
                        ($evalStigCmd.Parameters.ContainsKey('PSSession') -or
                         $evalStigCmd.Parameters.ContainsKey('Session'))
    $sessionParamName = if ($evalStigCmd -and $evalStigCmd.Parameters.ContainsKey('PSSession')) { 'PSSession' } else { 'Session' }

    if ($establishedSessions.Count -gt 0 -and $supportsSessions) {
        # Export session connection info so the child wrapper process can reconnect.
        # PSSession objects live in the parent process; the child gets ComputerName +
        # port/SSL/cred so it can call New-PSSession and pass (Get-PSSession) directly.
        $invokeArgs += '-ComputerName'
        $invokeArgs += ($remoteHosts -join ',')
        Write-JobLog $logFile INFO "Sessions pre-validated; child wrapper will reconnect via -ComputerName with inherited PSDefaultParameterValues"
        # $PSDefaultParameterValues already set above — child inherits port/SSL via env
    } elseif ($targetHosts.Count -gt 0) {
        # ComputerName fallback — $PSDefaultParameterValues injects port/SSL/options
        $invokeArgs += '-ComputerName'
        $invokeArgs += ($targetHosts -join ',')
        Write-JobLog $logFile INFO "Using -ComputerName with PSDefaultParameterValues (port=$winrmPort, ssl=$winrmUseSSL)"
    }

    if ($outputPath)     { $invokeArgs += '-OutputPath';     $invokeArgs += $outputPath     }
    if ($output)         { $invokeArgs += '-Output';         $invokeArgs += $output         }
    if ($answerKey)      { $invokeArgs += '-AnswerKey';      $invokeArgs += $answerKey      }
    if ($scanType)       { $invokeArgs += '-ScanType';       $invokeArgs += $scanType       }
    if ($previousToKeep) { $invokeArgs += '-PreviousToKeep'; $invokeArgs += $previousToKeep }
    if ($vulnTimeout)    { $invokeArgs += '-VulnTimeout';    $invokeArgs += $vulnTimeout    }
    if ($afPath)         { $invokeArgs += '-AFPath';         $invokeArgs += $afPath         }
    if ($marking)        { $invokeArgs += '-Marking';        $invokeArgs += $marking        }

    if ($selectSTIG) {
        $invokeArgs += '-SelectSTIG'
        if ($selectSTIG -is [System.Array]) {
            $invokeArgs += ($selectSTIG -join ',')
        } else {
            $invokeArgs += [string]$selectSTIG
        }
    }
    if ($excludeSTIG) {
        $invokeArgs += '-ExcludeSTIG'
        if ($excludeSTIG -is [System.Array]) {
            $invokeArgs += ($excludeSTIG -join ',')
        } else {
            $invokeArgs += [string]$excludeSTIG
        }
    }

    Write-JobLog $logFile INFO "Invoke-EvaluateSTIG args: $($invokeArgs -join ' ')"
    Write-JobLog $logFile SCAN "=== Scan starting ==="
    Write-AgentLog SCAN "Job $($JobFile.BaseName) — scan starting (outputPath=$outputPath)"

    # ── Launch scan process ────────────────────────────────────────────────────
    # We use a child script block written to a temp .ps1 so we can capture
    # full transcript output into the .log file while monitoring for .cancel.
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
    if (-not $pwsh) { $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe' }

    # Build a wrapper script that starts a transcript, calls Invoke-EvaluateSTIG,
    # then stops the transcript.
    # Serialise PSDefaultParameterValues entries so the child process inherits
    # WinRM settings and can call New-PSSession / Invoke-Command with the same
    # port + SSL settings, then reuse all sessions via Get-PSSession.
    $pdpLines = @()
    foreach ($kvp in $PSDefaultParameterValues.GetEnumerator()) {
        $k = $kvp.Key
        $v = $kvp.Value
        if ($v -is [bool]) {
            $pdpLines += "`$PSDefaultParameterValues['$k'] = `$$($v.ToString().ToLower())"
        } elseif ($v -is [int] -or $v -is [long]) {
            $pdpLines += "`$PSDefaultParameterValues['$k'] = $v"
        } elseif ($v -is [Microsoft.PowerShell.Commands.PSSessionOption]) {
            # Reconstruct session option — pass key flags only
            $sc = $v.SkipCACheck.ToString().ToLower()
            $cn = $v.SkipCNCheck.ToString().ToLower()
            $rv = $v.SkipRevocationCheck.ToString().ToLower()
            $pt = $v.MaxConnectionRetryCount   # not port — port comes from separate key
            $pdpLines += "`$PSDefaultParameterValues['$k'] = New-PSSessionOption -SkipCACheck:`$$sc -SkipCNCheck:`$$cn -SkipRevocationCheck:`$$rv"
        }
    }
    $pdpBlock = $pdpLines -join "`n"

    # Build remote host list (non-local only) for session pre-connection
    $remoteHostList = ($remoteHosts -join "','")
    $credBlock = ''
    if ($psCred) {
        $escapedUser = $psCred.UserName -replace "'", "''"
        $credBlock = @"
`$_secPw  = ConvertTo-SecureString '$($psCred.GetNetworkCredential().Password -replace "'","''")' -AsPlainText -Force
`$_cred   = New-Object PSCredential('$escapedUser', `$_secPw)
`$_credParam = @{ Credential = `$_cred }
"@
    } else {
        $credBlock = '$_credParam = @{}'
    }

    $argLine = ($invokeArgs | ForEach-Object { if ($_ -match '\s') { "'$_'" } else { $_ } }) -join ' '

    $wrapperContent = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Continue'

# Restore WinRM PSDefaultParameterValues in this child process
$pdpBlock

# Pre-establish persistent sessions to remote hosts so all Invoke-Command calls
# inside Invoke-EvaluateSTIG.ps1 automatically reuse them via Get-PSSession.
$credBlock
`$_remoteHosts = @('$remoteHostList')
if (`$_remoteHosts.Count -gt 0 -and `$_remoteHosts[0] -ne '') {
    `$_sessParams = @{
        ComputerName  = `$_remoteHosts
        Port          = $winrmPort
        UseSSL        = `$$($winrmUseSSL.ToString().ToLower())
        ErrorAction   = 'SilentlyContinue'
    }
    if (`$PSDefaultParameterValues['New-PSSession:SessionOption']) {
        `$_sessParams['SessionOption'] = `$PSDefaultParameterValues['New-PSSession:SessionOption']
    }
    `$_sessParams += `$_credParam
    `$null = New-PSSession @`$_sessParams
    Write-Host "[INFO] Persistent sessions: `$(Get-PSSession | Measure-Object | Select-Object -Expand Count) established"
}

Start-Transcript -Path '$logFile' -Append -Force | Out-Null
try {
    & '$InvokeSTIG' $argLine
} catch {
    Write-Error `$_.Exception.Message
    exit 1
} finally {
    # Clean up sessions before transcript ends
    Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
    Stop-Transcript | Out-Null
}
"@

    $wrapperScript = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
    Set-Content -Path $wrapperScript -Value $wrapperContent -Encoding UTF8

    $procArgs = @{
        FilePath         = $pwsh
        ArgumentList     = "-NonInteractive -ExecutionPolicy Bypass -File `"$wrapperScript`""
        NoNewWindow      = $true
        PassThru         = $true
        RedirectStandardOutput = "$base.stdout.tmp"
        RedirectStandardError  = "$base.stderr.tmp"
    }

    $proc = $null
    try {
        $proc = Start-Process @procArgs
    } catch {
        Write-JobLog $logFile ERROR "Failed to start scan process: $_"
        Write-AgentLog ERROR "Failed to start process for $($JobFile.BaseName): $_"
        Set-Content -Path $doneFile -Value 'failed' -Encoding UTF8
        Remove-Item $runningFile -ErrorAction SilentlyContinue
        Remove-Item $wrapperScript -ErrorAction SilentlyContinue
        return
    }

    # ── Monitor: poll for .cancel, merge stdout/stderr into .log ──────────────
    $startTime   = Get-Date
    $cancelled   = $false
    $lastMerge   = [datetime]::MinValue

    while (-not $proc.HasExited) {
        Start-Sleep -Seconds $CancelCheckSeconds

        # Flush stdout/stderr into .log
        foreach ($tmp in @("$base.stdout.tmp", "$base.stderr.tmp")) {
            if (Test-Path $tmp) {
                try {
                    $lines = Get-Content $tmp -ErrorAction Stop
                    if ($lines) {
                        Add-Content -Path $logFile -Value $lines -Encoding UTF8
                        Clear-Content -Path $tmp -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
        }

        # Check for cancellation
        if (Test-Path $cancelFile) {
            Write-JobLog $logFile WARN "Cancel file detected — stopping scan process (PID $($proc.Id))"
            Write-AgentLog WARN "Job $($JobFile.BaseName) — cancelled by user"
            try { $proc | Stop-Process -Force -ErrorAction Stop } catch {}
            $cancelled = $true
            break
        }

        $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
        Write-JobLog $logFile INFO "Scan still running... elapsed ${elapsed}m"
        Write-AgentLog INFO "Job $($JobFile.BaseName) — still running (${elapsed}m)"
    }

    # Final flush of stdout/stderr
    foreach ($tmp in @("$base.stdout.tmp", "$base.stderr.tmp")) {
        if (Test-Path $tmp) {
            try {
                $lines = Get-Content $tmp -ErrorAction Stop
                if ($lines) { Add-Content -Path $logFile -Value $lines -Encoding UTF8 }
            } catch {}
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }
    Remove-Item $wrapperScript -ErrorAction SilentlyContinue

    $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)

    if ($cancelled) {
        Write-JobLog $logFile WARN "=== Scan cancelled after ${elapsed}m ==="
        Set-Content -Path $doneFile -Value 'cancelled' -Encoding UTF8
        Remove-Item $cancelFile -ErrorAction SilentlyContinue
        Write-AgentLog WARN "Job $($JobFile.BaseName) — done (cancelled, ${elapsed}m)"
    } elseif ($proc.ExitCode -eq 0) {
        Write-JobLog $logFile INFO "=== Scan completed successfully in ${elapsed}m ==="
        Set-Content -Path $doneFile -Value 'completed' -Encoding UTF8
        Write-AgentLog INFO "Job $($JobFile.BaseName) — done (completed, ${elapsed}m)"
    } else {
        Write-JobLog $logFile ERROR "=== Scan failed (exit code $($proc.ExitCode)) after ${elapsed}m ==="
        Set-Content -Path $doneFile -Value 'failed' -Encoding UTF8
        Write-AgentLog ERROR "Job $($JobFile.BaseName) — done (failed, exit=$($proc.ExitCode), ${elapsed}m)"
    }

    # ── Discover output files ──────────────────────────────────────────────────
    $searchPath = if ($outputPath) { $outputPath } else {
        Join-Path (Split-Path $InvokeSTIG -Parent | Split-Path -Parent) 'STIGS'
    }
    $fileCount = Get-StigOutputFiles -OutputPath $searchPath -FilesJsonPath $filesFile
    Write-JobLog $logFile INFO "Output files discovered: $fileCount (see $filesFile)"
    Write-AgentLog INFO "Job $($JobFile.BaseName) — $fileCount output file(s) written to $filesFile"

    # ── Session teardown ──────────────────────────────────────────────────────
    # Close all persistent sessions established for this job
    if ($establishedSessions.Count -gt 0) {
        Write-JobLog $logFile INFO "Closing $($establishedSessions.Count) PSSession(s)..."
        Remove-PSSession -Session $establishedSessions -ErrorAction SilentlyContinue
        Write-JobLog $logFile INFO "PSSession(s) closed"
    }
    # Cleanup $PSDefaultParameterValues entries set for this job scope
    foreach ($key in @(
        'New-PSSession:SessionOption', 'Invoke-Command:SessionOption',
        'New-PSSession:UseSSL',        'Invoke-Command:UseSSL',
        'New-PSSession:Port',          'Invoke-Command:Port'
    )) { $PSDefaultParameterValues.Remove($key) }

    # ── Cleanup ───────────────────────────────────────────────────────────────
    Remove-Item $runningFile -ErrorAction SilentlyContinue
}

# ── Main polling loop ──────────────────────────────────────────────────────────
Write-AgentLog INFO "EvalStig Agent started (poll=${PollIntervalSeconds}s, jobsDir=$JobsDir)"
Write-AgentLog INFO "Invoke-EvaluateSTIG: $InvokeSTIG"

while ($true) {
    # Find pending jobs: .json files with no matching .running or .done
    $pending = Get-ChildItem -Path $JobsDir -Filter '*.json' -File -ErrorAction SilentlyContinue |
               Where-Object {
                   $base = $_.FullName -replace '\.json$', ''
                   (-not (Test-Path "$base.running")) -and
                   (-not (Test-Path "$base.done"))
               } |
               Sort-Object CreationTime

    if ($pending) {
        # Process only the oldest pending job this cycle (sequential)
        $job = $pending[0]
        try {
            Invoke-Job -JobFile $job
        } catch {
            Write-AgentLog ERROR "Unhandled exception processing $($job.Name): $_"
            $base = $job.FullName -replace '\.json$', ''
            Set-Content -Path "$base.done"    -Value 'failed'  -Encoding UTF8
            Remove-Item       "$base.running" -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
