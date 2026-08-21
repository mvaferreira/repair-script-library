<#
.SYNOPSIS
    Shared primitives for the offline repair helpers: buffered logging, drive-safe paths
    and offline binary trust checks.

.DESCRIPTION
    Buffered logging
    ----------------
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

    Drive-safe paths
    ----------------
    Join-Path and Test-Path throw DriveNotFoundException when a path refers to a drive
    letter that is not a live PowerShell drive. Offline repairs work with letters that
    come and go (EFI and Recovery partitions are mounted temporarily, and a partition can
    still advertise a stale access path), so Join-OfflinePath builds the string without
    resolving the drive and Test-OfflinePath answers false instead of throwing.

.NOTES
    Name:   OfflineRepairCommon.ps1
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

function Join-OfflinePath {
    <#
    .SYNOPSIS
        Joins a root and a child path without requiring the drive to exist.

    .DESCRIPTION
        Join-Path resolves the drive qualifier and throws DriveNotFoundException for a
        letter that is not currently mounted. Offline repairs routinely build paths on
        letters that are being mounted, are already unmounted, or are stale entries left
        on a partition, so the join is done as plain string composition instead.

    .PARAMETER Root
        Root of the path, with or without a trailing backslash. For example 'D:' or 'D:\'.

    .PARAMETER ChildPath
        Relative path under the root, with or without a leading backslash.

    .EXAMPLE
        Join-OfflinePath -Root 'X:' -ChildPath 'Windows\System32\ntdll.dll'
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Root,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ChildPath
    )

    if ([string]::IsNullOrWhiteSpace($Root)) { return $null }
    $trimmedRoot = $Root.TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($ChildPath)) { return "$trimmedRoot\" }
    return "$trimmedRoot\$($ChildPath.TrimStart('\'))"
}

function Test-OfflinePath {
    <#
    .SYNOPSIS
        Tests a path, returning false instead of throwing when the drive does not exist.

    .PARAMETER Path
        Path to test. Treated literally, so square brackets and braces are safe.

    .EXAMPLE
        if (Test-OfflinePath 'X:\Windows\System32\ntdll.dll') { 'found' }
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) }
    catch { return $false }
}

function Test-OfflineFileSignature {
    <#
    .SYNOPSIS
        Reports whether a binary on the offline disk is a trustworthy Microsoft file.

    .DESCRIPTION
        Authenticode alone is not enough offline. Most Windows inbox binaries are catalog
        signed, and the catalog store of the broken installation is not available to the
        rescue VM, so Get-AuthenticodeSignature reports NotSigned for perfectly good files.
        Boot manager payloads are compressed stubs that are not parseable at all. The
        version resource is therefore used as a fallback before a file is called untrusted.

    .PARAMETER FilePath
        Full path to the file on the offline disk.

    .OUTPUTS
        PSCustomObject with Path, IsSigned, IsMicrosoft, Status and Subject.

    .EXAMPLE
        (Test-OfflineFileSignature -FilePath 'D:\Windows\System32\drivers\storvsc.sys').IsMicrosoft
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath
    )

    $result = [PSCustomObject]@{
        Path        = $FilePath
        IsSigned    = $false
        IsMicrosoft = $false
        Status      = 'FileNotFound'
        Subject     = ''
    }

    if (-not (Test-OfflinePath $FilePath)) { return $result }

    $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.Length -eq 0) {
        $result.Status = 'ZeroByte'
        return $result
    }

    try { $signature = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop }
    catch {
        $result.Status = 'Error'
        return $result
    }

    $result.Status = [string]$signature.Status
    $result.Subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }

    if ($signature.Status -eq 'Valid') {
        $result.IsSigned = $true
        if ($result.Subject -match 'O=Microsoft Corporation') { $result.IsMicrosoft = $true }
        return $result
    }

    $versionInfo = $item.VersionInfo
    if ($versionInfo -and $versionInfo.CompanyName -match 'Microsoft') {
        $result.IsSigned = $true
        $result.IsMicrosoft = $true
        $result.Status = 'CatalogSigned'
        $result.Subject = $versionInfo.CompanyName
    }
    elseif ($signature.Status -in @('UnknownError', 'NotSupportedFileFormat')) {
        # Not parseable by Authenticode and carrying no version resource, for example a
        # compressed boot stub. Inconclusive rather than untrusted.
        $result.Status = 'NotVerifiable'
        $result.IsSigned = $true
        $result.IsMicrosoft = $true
    }

    return $result
}
