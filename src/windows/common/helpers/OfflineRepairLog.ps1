<#
.SYNOPSIS
    Buffered logging for helper functions that return a value.

.DESCRIPTION
    The library's Logger.ps1 functions write with Write-Output, which is the same stream
    a PowerShell function returns its value on. A helper that both logs and returns a
    value therefore returns the log lines as well, silently corrupting the result.

    This helper solves that: helper functions call Add-OfflineRepairLog, which buffers the
    message without writing anything, and the calling script calls Write-OfflineRepairLog
    at statement level to flush the buffer through the standard Log-* functions.

    Rules:
      - Inside a function that returns a value, use Add-OfflineRepairLog.
      - Call Write-OfflineRepairLog only at script level, never from a function whose
        return value is used, and always flush in the script's finally block.

.NOTES
    Name:   OfflineRepairLog.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).

.VERSION
    v1.0: Initial version.
#>

if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) {
    $script:OfflineRepairLogBuffer = [System.Collections.Generic.List[object]]::new()
}

function Add-OfflineRepairLog {
    <#
    .SYNOPSIS
        Buffers a log message without writing to the output stream.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('Info', 'Warning', 'Error', 'Output')][string]$Level = 'Info'
    )

    if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) {
        $script:OfflineRepairLogBuffer = [System.Collections.Generic.List[object]]::new()
    }
    [void]$script:OfflineRepairLogBuffer.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
}

function Write-OfflineRepairLog {
    <#
    .SYNOPSIS
        Flushes the buffered helper messages through the library Log-* functions.

    .DESCRIPTION
        Call this only at script level. It writes to the output stream, so calling it
        inside a function whose return value is used would corrupt that value.
    #>
    if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) { return }
    if ($script:OfflineRepairLogBuffer.Count -eq 0) { return }

    $entries = @($script:OfflineRepairLogBuffer)
    $script:OfflineRepairLogBuffer.Clear()

    foreach ($entry in $entries) {
        if ([string]::IsNullOrEmpty($entry.Message)) { continue }
        switch ($entry.Level) {
            'Warning' { Log-Warning $entry.Message }
            'Error' { Log-Error $entry.Message }
            'Output' { Log-Output $entry.Message }
            default { Log-Info $entry.Message }
        }
    }
}

function Get-OfflineRepairLog {
    <#
    .SYNOPSIS
        Returns the buffered messages without flushing them.
    #>
    if (-not (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue)) { return @() }
    return @($script:OfflineRepairLogBuffer)
}

function Clear-OfflineRepairLog {
    <#
    .SYNOPSIS
        Discards the buffered messages.
    #>
    if (Get-Variable -Name OfflineRepairLogBuffer -Scope Script -ErrorAction SilentlyContinue) {
        $script:OfflineRepairLogBuffer.Clear()
    }
}
