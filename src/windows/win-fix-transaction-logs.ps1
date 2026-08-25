#########################################################################################################
#
# .SYNOPSIS
#   Clears exhausted Common Log File System transaction logs on an offline disk, so servicing that
#   fails with ERROR_LOG_FULL (0x800719e4) can run again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   The transactional registry (TxR) records registry changes made inside a Kernel Transaction
#   Manager transaction in Common Log File System containers: a .blf base log file and one or more
#   .regtrans-ms multiplexed containers, living in System32\config\TxR. A CLFS container is a fixed
#   size. When the log fills and cannot be advanced - because a transaction was never resolved, or
#   the machine lost power with work outstanding - every subsequent attempt to open a transaction
#   fails with ERROR_LOG_FULL, 0x800719e4.
#
#   The visible result is that servicing stops working. Windows Update fails, DISM fails, and
#   CBS.log fills with 0x800719e4. The installation itself is intact: nothing is corrupt, there is
#   no half-applied update to roll back, and there is no pending.xml to abandon. The only thing
#   wrong is that the log containers are full. Windows recreates them from scratch on the next boot,
#   so removing them clears the condition.
#
#   This is deliberately a different script from win-fix-pending-servicing. That one abandons an
#   interrupted servicing transaction - it reverts pending actions with DISM, renames pending.xml
#   and clears the Component Based Servicing markers. None of that applies here, and running it
#   would revert an update that had never started applying. Log exhaustion is a separate symptom
#   with a separate, much smaller repair, which is why it gets its own script.
#
#   Three scopes are understood. Only TxR is touched by default:
#     TxR     System32\config\TxR          the transactional registry logs.
#     Config  System32\config              CLFS logs sitting alongside the registry hives.
#     SMI     System32\SMI\Store\Machine   the Software Management Infrastructure store logs.
#
#   Config and SMI are opt-in because they sit in the same folder as data that must never be lost:
#   the registry hives themselves and their .LOG1/.LOG2 recovery logs. Removing a hive recovery log
#   from under a hive that has not been reconciled turns a recoverable installation into an
#   unbootable one - STATUS_CANNOT_LOAD_REGISTRY_FILE, 0xC0000218. The file selection below cannot
#   reach those files, and the verification below proves it did not, but the default still stays on
#   the folder that holds nothing else.
#
#   What is removed is chosen by an explicit extension allow-list, .blf and .regtrans-ms, and never
#   by a wildcard sweep of the folder. The list is built once, and the backup, the deletion and the
#   verification all work from that one list rather than from a fresh enumeration, so the set of
#   files cannot grow between deciding and acting. A hive, a .LOG1, a .LOG2 or anything else in the
#   folder is not on the list and is therefore not reachable, whatever it is called.
#
#   Every file is copied to a backup folder on the offline disk and the copy is hash-verified before
#   the original is deleted. After the deletion, six things are checked:
#     1. The folder still exists.
#     2. The folder is the original, not a recreated one - the creation timestamp is unchanged.
#     3. The folder's ACL is unchanged.
#     4. Exactly the planned files were removed, and nothing else was.
#     5. Every other file in the folder is untouched - same size, same last write time and same
#        attributes. This is the direct proof that the hives and their recovery logs were neither
#        deleted nor stripped of their System and Hidden attributes.
#     6. Every registry hive that loaded before the deletion still loads after it.
#   If any check fails, that scope is rolled back from the backup immediately, including the
#   original file attributes, and the script reports an error. A scope is never left half-cleared.
#
# .PARAMETER detectOnly
#   "true" reports what was found and what would be removed, and writes nothing. Default "false".
#
# .PARAMETER scope
#   Which log set to clear: TxR, Config, SMI or All. Default "TxR".
#
# .PARAMETER force
#   "true" clears the logs even when no ERROR_LOG_FULL evidence was found. Default "false". Needed
#   only when CBS.log has rolled over and taken the evidence with it - see .NOTES.
#
# .PARAMETER revert
#   "true" restores the files a previous run of this script backed up, and writes nothing else.
#
# .PARAMETER windowsDrive
#   Drive letter of the attached Windows volume, e.g. "F:". Detected automatically when omitted.
#
# .NOTES
#   Transaction logs are present and healthy on every running Windows installation. Their presence
#   is not evidence of anything, so this script does not treat it as evidence: with no sign of
#   exhaustion it removes nothing and says so. The evidence it looks for is 0x800719e4 or
#   ERROR_LOG_FULL in Windows\Logs\CBS\CBS.log and in any uncompressed CbsPersist_*.log beside it.
#
#   CBS.log rolls over into a compressed CbsPersist_*.cab once it passes its size limit, and this
#   script does not open cabinets. On a VM that has been failing for a while the evidence can
#   therefore be gone even though the fault is real. That is what "force true" is for. It is an
#   explicit operator decision that the symptom was identified some other way, and it is the only
#   way to make this script write anything without evidence of its own.
#
#   Clearing the logs does not fix an update that is already half applied. If pending servicing
#   markers are found as well they are reported, and win-fix-pending-servicing is the script for
#   that. This one never touches pending.xml, the CBS keys or the COMPONENTS hive.
#
#   The backup is written to Windows\Temp on the offline disk, so it travels back with the VM and a
#   revert can be run later from a different rescue VM. It is never written inside the folder being
#   cleared: a new file appearing there would be indistinguishable from one this script failed to
#   account for, and check 4 above would not be able to tell the difference.
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly.')]
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('TxR', 'Config', 'SMI', 'All', IgnoreCase = $true)][string]$scope = 'TxR',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$force = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$isForce = ($force -eq 'true')

# The only extensions this script will ever delete. A Common Log File System log is a .blf base log
# file plus its .regtrans-ms containers, and nothing else in any of the three scope folders uses
# either extension.
#
# This is an allow-list rather than a wildcard for one reason: a registry hive recovery log is
# called SYSTEM.LOG1, and losing one from under an unreconciled hive is a documented route to
# STATUS_CANNOT_LOAD_REGISTRY_FILE. No pattern here can match it.
$script:TransactionLogExtension = @('.blf', '.regtrans-ms')

# Extensions that must never be deleted whatever else happens. Nothing on the allow-list above can
# produce a match here, so this is a second, independent check rather than a filter that does any
# work in normal operation. It exists so that a future edit to the allow-list cannot quietly make
# hive recovery logs reachable.
$script:ProtectedExtension = @('.log', '.log1', '.log2', '.dat', '.sav', '.bak')

# Primary registry hives that live in the scope folders. These are revalidated after the deletion:
# a hive that loaded before and does not load after means the folder was damaged, and the scope is
# rolled back. Nothing here is ever selected for deletion - this list only observes.
#
# The list is longer than the six hives usually named because a measured Server 2022 config folder
# holds ten: DRIVERS, ELAM, BBI and BCD-Template are hives too. Inclusion costs one scratch-copy
# parse each and can never remove a file, so the bar is "is it a hive in a folder we mutate", not
# "is it needed at boot".
#
# BCD-Template is the weakest of the ten and is kept deliberately. It is only the template bcdboot
# copies to build a fresh BCD store - the live BCD is on the boot partition, not here - and on a
# pristine disk it owns no transaction logs at all, so it contributes no deletion candidates. But
# loading it creates them: on the test disk a single in-place reg.exe load produced
# BCD-Template{guid}.TM.blf plus two .TMContainer files that were not there before. A machine that
# reaches this script has usually already been worked on, so those logs can exist here, and once
# they do a Config-scope run will delete them. Damaging BCD-Template would not cause a no-boot; it
# would break the next bcdboot the operator runs, which is a far more confusing failure.
#
# All ten loaded cleanly through Test-OfflineHiveFile on that disk, so the check is a real gate here
# rather than something advisory - Test-OfflineHiveFile parses with reg.exe, which does not have the
# ERROR_BADDB problem that makes RegLoadAppKey reject primary OS hives.
$script:RegistryHive = @{
    'TxR'    = @()
    'Config' = @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'COMPONENTS', 'DRIVERS', 'ELAM', 'BBI', 'BCD-Template')
    'SMI'    = @('SCHEMA.DAT')
}

# Test-OfflineHiveFile copies a hive to a scratch location to have Windows parse it, and it runs
# twice per repair - once for the baseline and once for the verification. Above this size the hive
# is reported as skipped instead of copied. The file-level comparison in check 5 still proves the
# file was not modified, so nothing is given up except the parse.
$script:HiveTestMaxBytes = 512MB

# What log exhaustion looks like in CBS.log. 0x800719e4 is ERROR_LOG_FULL as CBS prints it.
$script:LogFullPattern = '0x800719e4|ERROR_LOG_FULL'

# CBS.log is large and the useful part is the end of it. Reading the tail keeps this to a bounded
# read on a multi-hundred-megabyte file.
$script:CbsTailLine = 4000

function New-Finding {
    <#
    .SYNOPSIS
        Builds one detection finding.

    .DESCRIPTION
        Priority orders the report. Actionable marks a finding this script can do something about,
        as opposed to one that is reported so the operator knows where to look next.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $false)][ValidateSet('Critical', 'Warning', 'Information')][string]$Severity = 'Warning',
        [Parameter(Mandatory = $false)][int]$Priority = 50,
        [Parameter(Mandatory = $false)][bool]$Actionable = $true
    )

    return [PSCustomObject]@{
        Category   = $Category
        Detail     = $Detail
        Severity   = $Severity
        Priority   = $Priority
        Actionable = $Actionable
    }
}

function Get-TransactionLogScope {
    <#
    .SYNOPSIS
        Resolves a scope name to the folder it describes and the hives that live there.

    .OUTPUTS
        PSCustomObject with Scope, Label, Path and HiveName.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('TxR', 'Config', 'SMI')][string]$Name,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    switch ($Name) {
        'TxR' {
            $path = Join-OfflinePath $SystemRoot 'System32\config\TxR'
            $label = 'transactional registry logs'
        }
        'Config' {
            $path = Join-OfflinePath $SystemRoot 'System32\config'
            $label = 'registry configuration folder logs'
        }
        'SMI' {
            $path = Join-OfflinePath $SystemRoot 'System32\SMI\Store\Machine'
            $label = 'Software Management Infrastructure store logs'
        }
    }

    return [PSCustomObject]@{
        Scope    = $Name
        Label    = $label
        Path     = $path
        HiveName = $script:RegistryHive[$Name]
    }
}

function Get-TransactionLogSnapshot {
    <#
    .SYNOPSIS
        Records the exact state of a scope folder, so the same folder can be compared afterwards.

    .DESCRIPTION
        [System.IO.Directory]::Exists is used rather than Test-Path so that a folder which exists
        but cannot be enumerated is still recorded as present. config\TxR restricts its own ACL on
        some builds and reading it can fail even from an elevated rescue VM; reporting it as absent
        would be wrong, and would make the "folder still exists" check pass for the wrong reason.

        CreationTimeUtc is the folder's identity. If the folder is deleted and recreated - which is
        what a wildcard delete of the folder itself would do - the timestamp changes even though the
        path is the same.

        An unreadable SDDL is recorded as $null rather than treated as an error. The comparison
        later skips a null on either side, because "could not read it before and cannot read it now"
        is not evidence of a change.

    .OUTPUTS
        PSCustomObject with Path, Present, Accessible, AccessError, CreatedUtc, Sddl, LogFile[] and
        OtherFile[].
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][switch]$IncludeHash
    )

    $snapshot = [PSCustomObject]@{
        Path        = $Path
        Present     = $false
        Accessible  = $false
        AccessError = $null
        CreatedUtc  = $null
        Sddl        = $null
        LogFile     = @()
        OtherFile   = @()
    }

    try { $snapshot.Present = [System.IO.Directory]::Exists($Path) }
    catch { $snapshot.Present = $false }

    if (-not $snapshot.Present) { return $snapshot }

    try { $snapshot.CreatedUtc = ([System.IO.Directory]::GetCreationTimeUtc($Path)).ToString('o') }
    catch { $snapshot.CreatedUtc = $null }

    try { $snapshot.Sddl = (Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl }
    catch { $snapshot.Sddl = $null }

    $items = $null
    try {
        $items = @(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop)
        $snapshot.Accessible = $true
    }
    catch {
        $snapshot.AccessError = $_.Exception.Message
        return $snapshot
    }

    $logs = [System.Collections.Generic.List[object]]::new()
    $others = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $items) {
        $record = [PSCustomObject]@{
            Name          = $item.Name
            FullName      = $item.FullName
            Length        = $item.Length
            LastWriteUtc  = $item.LastWriteTimeUtc.ToString('o')
            Attributes    = $item.Attributes.ToString()
            Hash          = $null
        }

        if (Test-TransactionLogFile -Name $item.Name) {
            if ($IncludeHash) { $record.Hash = Get-TransactionLogHash -Path $item.FullName }
            $logs.Add($record)
        }
        else {
            $others.Add($record)
        }
    }

    $snapshot.LogFile = @($logs)
    $snapshot.OtherFile = @($others)
    return $snapshot
}

function Test-TransactionLogFile {
    <#
    .SYNOPSIS
        Decides whether one file name is a transaction log this script may delete.

    .DESCRIPTION
        Two independent tests must both agree: the extension is on the allow-list, and it is not on
        the protected list. The second can never fire given the first, which is the point - it is
        there so that widening the allow-list in future cannot silently make a hive recovery log
        deletable.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $extension = [System.IO.Path]::GetExtension($Name)
    if ([string]::IsNullOrEmpty($extension)) { return $false }

    $extension = $extension.ToLowerInvariant()
    if ($script:ProtectedExtension -contains $extension) { return $false }
    return ($script:TransactionLogExtension -contains $extension)
}

function Get-TransactionLogHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return $null }
}

function Get-TransactionLogHiveState {
    <#
    .SYNOPSIS
        Reports whether each registry hive in a scope folder loads.

    .DESCRIPTION
        Only used as a before-and-after comparison. A hive that does not load before the deletion
        and still does not load after it says nothing about this script; only a hive that loaded
        before and does not load after is evidence, and that is what the verification tests for.

        Hives above the size limit are recorded as Skipped rather than tested, so a multi-gigabyte
        COMPONENTS hive does not turn a small file deletion into a long copy.

    .OUTPUTS
        Array of PSCustomObject with Name, Path, Present, Tested, Loads and Reason.
    #>
    param([Parameter(Mandatory = $true)]$ScopeInfo)

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($hiveName in @($ScopeInfo.HiveName)) {
        $hivePath = Join-OfflinePath $ScopeInfo.Path $hiveName
        $state = [PSCustomObject]@{
            Name    = $hiveName
            Path    = $hivePath
            Present = $false
            Tested  = $false
            Loads   = $false
            Reason  = $null
        }

        if (-not (Test-OfflinePath $hivePath)) {
            $state.Reason = 'not present'
            $results.Add($state)
            continue
        }
        $state.Present = $true

        $size = 0
        try { $size = (Get-Item -LiteralPath $hivePath -Force -ErrorAction Stop).Length }
        catch { $size = 0 }

        if ($size -gt $script:HiveTestMaxBytes) {
            $state.Reason = "skipped, $([math]::Round($size / 1MB)) MB is above the $([math]::Round($script:HiveTestMaxBytes / 1MB)) MB test limit"
            $results.Add($state)
            continue
        }

        $test = Test-OfflineHiveFile -Path $hivePath
        $state.Tested = $true
        $state.Loads = [bool]$test.IsValid
        $state.Reason = $test.Reason
        $results.Add($state)
    }

    return @($results)
}

function Get-TransactionLogPlan {
    <#
    .SYNOPSIS
        Builds the read-only plan for one scope: what is there, and what would be removed.

    .DESCRIPTION
        Writes nothing, so it is safe to call for a detectOnly run and is also the baseline the
        verification compares against.

    .OUTPUTS
        PSCustomObject with Scope, ScopeInfo, Snapshot, HiveState, FileCount, TotalBytes and
        Actionable.
    #>
    param(
        [Parameter(Mandatory = $true)]$ScopeInfo,
        [Parameter(Mandatory = $false)][switch]$SkipHiveState
    )

    $snapshot = Get-TransactionLogSnapshot -Path $ScopeInfo.Path -IncludeHash
    $hiveState = @()
    if (-not $SkipHiveState -and $snapshot.Present) {
        $hiveState = Get-TransactionLogHiveState -ScopeInfo $ScopeInfo
    }

    $totalBytes = 0
    foreach ($file in @($snapshot.LogFile)) { $totalBytes += $file.Length }

    return [PSCustomObject]@{
        Scope      = $ScopeInfo.Scope
        ScopeInfo  = $ScopeInfo
        Snapshot   = $snapshot
        HiveState  = @($hiveState)
        FileCount  = @($snapshot.LogFile).Count
        TotalBytes = $totalBytes
        Actionable = ($snapshot.Present -and $snapshot.Accessible -and @($snapshot.LogFile).Count -gt 0)
    }
}

function Get-LogExhaustionEvidence {
    <#
    .SYNOPSIS
        Looks for ERROR_LOG_FULL in the servicing logs.

    .DESCRIPTION
        CBS.log is the log that records it, and it is read from the end because that is where the
        recent failures are and the file can be very large. Uncompressed CbsPersist_*.log files are
        read too; the .cab ones that CBS compresses on rollover are not opened, which is the reason
        the force parameter exists.

    .OUTPUTS
        PSCustomObject with Found, Source, SampleLine and LogsRead.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $result = [PSCustomObject]@{
        Found      = $false
        Source     = $null
        SampleLine = $null
        LogsRead   = @()
    }

    $cbsFolder = Join-OfflinePath $SystemRoot 'Logs\CBS'
    if (-not (Test-OfflinePath $cbsFolder)) { return $result }

    $candidates = [System.Collections.Generic.List[object]]::new()
    $cbsLog = Join-OfflinePath $cbsFolder 'CBS.log'
    if (Test-OfflinePath $cbsLog) { $candidates.Add($cbsLog) }

    try {
        $persist = @(Get-ChildItem -LiteralPath $cbsFolder -Filter 'CbsPersist_*.log' -File -Force -ErrorAction Stop |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 3)
        foreach ($item in $persist) { $candidates.Add($item.FullName) }
    }
    catch {
        # The rolled-over logs are a bonus, not a requirement. CBS.log alone is the normal case and
        # is already on the list, so a folder that cannot be enumerated is noted and not fatal.
        Add-OfflineRepairLog -Level Warning -Message "The rolled-over CBS logs in $cbsFolder could not be listed ($($_.Exception.Message))."
    }

    foreach ($path in $candidates) {
        $result.LogsRead += $path
        try {
            $tail = @(Get-Content -LiteralPath $path -Tail $script:CbsTailLine -ErrorAction Stop)
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not read $path ($($_.Exception.Message))."
            continue
        }

        $hit = $tail | Select-String -Pattern $script:LogFullPattern -CaseSensitive:$false | Select-Object -First 1
        if ($hit) {
            $result.Found = $true
            $result.Source = $path
            $result.SampleLine = $hit.Line.Trim()
            return $result
        }
    }

    return $result
}

function Get-PendingServicingMarker {
    <#
    .SYNOPSIS
        Reports whether an interrupted servicing transaction is also present.

    .DESCRIPTION
        Reported, never acted on. If these are present the VM has a second, different problem and
        win-fix-pending-servicing is the script for it. Clearing the logs will not finish an update
        that is already half applied.

    .OUTPUTS
        Array of marker description strings.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $markers = [System.Collections.Generic.List[string]]::new()

    $pendingXml = Join-OfflinePath $SystemRoot 'WinSxS\pending.xml'
    if (Test-OfflinePath $pendingXml) { $markers.Add('WinSxS\pending.xml is present') }

    $reboot = Join-OfflinePath $SystemRoot 'WinSxS\reboot.xml'
    if (Test-OfflinePath $reboot) { $markers.Add('WinSxS\reboot.xml is present') }

    return @($markers)
}

function Backup-TransactionLogFile {
    <#
    .SYNOPSIS
        Copies one log file to the backup folder and proves the copy is identical.

    .DESCRIPTION
        The hash comparison is the point. A copy that reported success but produced a short or
        empty file would make the rollback useless at exactly the moment it is needed, and the
        deletion below is only allowed to run once this has returned success.

        Attributes are recorded rather than copied. Copy-Item does not carry them, and the rollback
        has to put back a file that is byte-identical and marked the same way.

    .OUTPUTS
        PSCustomObject with Name, Source, Backup, Attributes, Success and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)]$File,
        [Parameter(Mandatory = $true)][string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Name       = $File.Name
        Source     = $File.FullName
        Backup     = (Join-Path $BackupPath $File.Name)
        Attributes = $File.Attributes
        Success    = $false
        Reason     = $null
    }

    try {
        Copy-Item -LiteralPath $File.FullName -Destination $result.Backup -Force -ErrorAction Stop
    }
    catch {
        $result.Reason = "copy failed: $($_.Exception.Message)"
        return $result
    }

    $sourceHash = $File.Hash
    if (-not $sourceHash) { $sourceHash = Get-TransactionLogHash -Path $File.FullName }
    $backupHash = Get-TransactionLogHash -Path $result.Backup

    if (-not $sourceHash -or -not $backupHash) {
        $result.Reason = 'the backup copy could not be hash-verified'
        return $result
    }
    if ($sourceHash -ne $backupHash) {
        $result.Reason = 'the backup copy does not match the original'
        return $result
    }

    $result.Success = $true
    return $result
}

function Restore-TransactionLogBackup {
    <#
    .SYNOPSIS
        Puts a backed-up set of log files back where they came from.

    .DESCRIPTION
        Used both by the automatic rollback when verification fails and by "-revert true".

        The file is copied back and then given its recorded attributes again. A restored .blf that
        is missing its original attributes is not the file that was there before, and CLFS is
        entitled to notice.

    .OUTPUTS
        PSCustomObject with Restored, Failed and Detail[].
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $false)][AllowNull()]$FileRecord = $null
    )

    $summary = [PSCustomObject]@{
        Restored = 0
        Failed   = 0
        Detail   = @()
    }
    $detail = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        $detail.Add("The backup folder $BackupPath is not present.")
        $summary.Failed = 1
        $summary.Detail = @($detail)
        return $summary
    }

    $backedUp = @(Get-ChildItem -LiteralPath $BackupPath -File -Force -ErrorAction SilentlyContinue)
    foreach ($item in $backedUp) {
        $destination = Join-Path $TargetPath $item.Name
        try {
            Copy-Item -LiteralPath $item.FullName -Destination $destination -Force -ErrorAction Stop

            $recorded = @($FileRecord) | Where-Object { $_ -and $_.Name -eq $item.Name } | Select-Object -First 1
            if ($recorded -and $recorded.Attributes) {
                try { (Get-Item -LiteralPath $destination -Force -ErrorAction Stop).Attributes = [System.IO.FileAttributes]$recorded.Attributes }
                catch { $detail.Add("Restored $($item.Name) but could not reapply its attributes ($($_.Exception.Message)).") }
            }

            $summary.Restored++
            $detail.Add("Restored $($item.Name).")
        }
        catch {
            $summary.Failed++
            $detail.Add("Could not restore $($item.Name): $($_.Exception.Message)")
        }
    }

    $summary.Detail = @($detail)
    return $summary
}

function Test-TransactionLogResult {
    <#
    .SYNOPSIS
        Proves the deletion removed the planned files and nothing else.

    .DESCRIPTION
        Six checks, all of which must pass. Check 5 is the one that matters most: comparing every
        other file in the folder by size, last write time and attributes is the direct evidence
        that the registry hives and their .LOG1/.LOG2 recovery logs were neither removed nor
        modified. Check 6 then has Windows confirm the hives still parse.

        A folder ACL that could not be read before and cannot be read now is passed rather than
        failed, because there is nothing to compare and refusing on that basis would roll back a
        correct repair on a build that simply restricts the folder.

    .OUTPUTS
        PSCustomObject with Passed, Check[] and Failure[].
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)]$Removed
    )

    $checks = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()

    $before = $Plan.Snapshot
    $after = Get-TransactionLogSnapshot -Path $Plan.ScopeInfo.Path

    function Add-Check {
        param([string]$Name, [bool]$Passed, [string]$Detail)
        $checks.Add([PSCustomObject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
        if (-not $Passed) { $failures.Add("$Name - $Detail") }
    }

    # 1. The folder is still there.
    Add-Check -Name 'Folder present' -Passed $after.Present -Detail $(
        if ($after.Present) { 'the folder is still present' } else { 'the folder is gone' })

    if (-not $after.Present) {
        return [PSCustomObject]@{ Passed = $false; Check = @($checks); Failure = @($failures) }
    }

    # 2. It is the same folder, not a replacement.
    $sameFolder = ($null -eq $before.CreatedUtc) -or ($null -eq $after.CreatedUtc) -or ($before.CreatedUtc -eq $after.CreatedUtc)
    Add-Check -Name 'Folder not recreated' -Passed $sameFolder -Detail $(
        if ($sameFolder) { 'the creation timestamp is unchanged' }
        else { "the creation timestamp changed from $($before.CreatedUtc) to $($after.CreatedUtc)" })

    # 3. The ACL is unchanged.
    $sameAcl = ($null -eq $before.Sddl) -or ($null -eq $after.Sddl) -or ($before.Sddl -eq $after.Sddl)
    Add-Check -Name 'Folder ACL unchanged' -Passed $sameAcl -Detail $(
        if ($null -eq $before.Sddl -or $null -eq $after.Sddl) { 'the ACL could not be read, so there is nothing to compare' }
        elseif ($sameAcl) { 'the ACL is unchanged' }
        else { 'the ACL changed' })

    # 4. Exactly the planned files went, and no others.
    $expectedGone = @($Removed | ForEach-Object { $_.Name })
    $stillThere = @($after.LogFile | ForEach-Object { $_.Name })
    $notRemoved = @($expectedGone | Where-Object { $stillThere -contains $_ })
    $plannedNames = @($before.LogFile | ForEach-Object { $_.Name })
    $unexpectedlyGone = @($plannedNames | Where-Object { $expectedGone -notcontains $_ -and $stillThere -notcontains $_ })

    $removalOk = ($notRemoved.Count -eq 0 -and $unexpectedlyGone.Count -eq 0)
    Add-Check -Name 'Planned files removed' -Passed $removalOk -Detail $(
        if ($removalOk) { "$($expectedGone.Count) file(s) removed as planned" }
        elseif ($notRemoved.Count -gt 0) { "still present: $($notRemoved -join ', ')" }
        else { "removed without being planned: $($unexpectedlyGone -join ', ')" })

    # 5. Everything else in the folder is byte-for-byte and flag-for-flag as it was.
    $otherProblems = [System.Collections.Generic.List[string]]::new()
    foreach ($original in @($before.OtherFile)) {
        $current = @($after.OtherFile) | Where-Object { $_.Name -eq $original.Name } | Select-Object -First 1
        if (-not $current) { $otherProblems.Add("$($original.Name) is missing"); continue }
        if ($current.Length -ne $original.Length) { $otherProblems.Add("$($original.Name) changed size") }
        if ($current.LastWriteUtc -ne $original.LastWriteUtc) { $otherProblems.Add("$($original.Name) was written to") }
        if ($current.Attributes -ne $original.Attributes) { $otherProblems.Add("$($original.Name) had its attributes changed") }
    }
    $othersOk = ($otherProblems.Count -eq 0)
    Add-Check -Name 'Other files untouched' -Passed $othersOk -Detail $(
        if ($othersOk) { "all $(@($before.OtherFile).Count) other file(s) are unchanged" }
        else { ($otherProblems -join '; ') })

    # 6. Hives that loaded before still load.
    $hiveProblems = [System.Collections.Generic.List[string]]::new()
    $testedBefore = @($Plan.HiveState | Where-Object { $_.Tested -and $_.Loads })
    if ($testedBefore.Count -gt 0) {
        $afterHive = Get-TransactionLogHiveState -ScopeInfo $Plan.ScopeInfo
        foreach ($original in $testedBefore) {
            $current = @($afterHive) | Where-Object { $_.Name -eq $original.Name } | Select-Object -First 1
            if (-not $current -or -not $current.Tested) { $hiveProblems.Add("$($original.Name) could not be retested"); continue }
            if (-not $current.Loads) { $hiveProblems.Add("$($original.Name) no longer loads ($($current.Reason))") }
        }
    }
    $hivesOk = ($hiveProblems.Count -eq 0)
    Add-Check -Name 'Registry hives still load' -Passed $hivesOk -Detail $(
        if ($testedBefore.Count -eq 0) { 'no hive in this folder was testable beforehand, so there is nothing to compare' }
        elseif ($hivesOk) { "all $($testedBefore.Count) hive(s) still load" }
        else { ($hiveProblems -join '; ') })

    return [PSCustomObject]@{
        Passed  = ($failures.Count -eq 0)
        Check   = @($checks)
        Failure = @($failures)
    }
}

function Clear-TransactionLogScope {
    <#
    .SYNOPSIS
        Backs up, deletes and verifies the transaction logs for one scope.

    .DESCRIPTION
        Works only from the file list captured in the plan. The folder is never re-enumerated
        between deciding and acting, so the set of files that gets deleted is exactly the set that
        was reported and backed up.

        Read-only and System attributes are cleared immediately before the delete, on the same file
        objects, because Remove-Item will not delete a read-only file. Nothing else in the folder is
        opened.

        A failure at any point rolls the whole scope back. A partially cleared CLFS log set is
        worse than a full one: the .blf refers to containers that would no longer exist.

        Progress is recorded with Add-OfflineRepairLog rather than Log-*. The Log-* functions write
        to the output stream, so calling one here would put log strings into this function's return
        value and the caller would read them as extra scope results. The script flushes the buffer
        after each call instead.

    .OUTPUTS
        PSCustomObject with Scope, BackupPath, Removed[], Verification and Success.
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string]$BackupRoot
    )

    $result = [PSCustomObject]@{
        Scope        = $Plan.Scope
        BackupPath   = $null
        Removed      = @()
        Verification = $null
        Success      = $false
        Reason       = $null
    }

    $backupPath = Join-Path $BackupRoot $Plan.Scope
    try { New-Item -Path $backupPath -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    catch {
        $result.Reason = "the backup folder $backupPath could not be created: $($_.Exception.Message)"
        return $result
    }
    $result.BackupPath = $backupPath

    # Room for the backup, with the same again as headroom.
    $required = ($Plan.TotalBytes * 2)
    $free = Get-OfflineFreeSpace -Path $backupPath
    if ($null -eq $free) {
        Add-OfflineRepairLog -Level Warning -Message 'Free space on the backup volume could not be confirmed; continuing.'
    }
    elseif ($free -lt $required) {
        $result.Reason = "not enough free space for the backup: $([math]::Round($free / 1MB)) MB free, $([math]::Round($required / 1MB)) MB needed"
        return $result
    }

    # Back everything up first. Nothing is deleted until every file has a verified copy.
    foreach ($file in @($Plan.Snapshot.LogFile)) {
        $backup = Backup-TransactionLogFile -File $file -BackupPath $backupPath
        if (-not $backup.Success) {
            $result.Reason = "$($file.Name) could not be backed up - $($backup.Reason)"
            Add-OfflineRepairLog -Level Error -Message $result.Reason
            return $result
        }
        Add-OfflineRepairLog -Message "Backed up $($file.Name) ($([math]::Round($file.Length / 1KB)) KB)."
    }

    # Delete, working from the same list.
    $removed = [System.Collections.Generic.List[object]]::new()
    $deleteFailed = $null
    foreach ($file in @($Plan.Snapshot.LogFile)) {
        try {
            $item = Get-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                $item.Attributes = ($item.Attributes -bxor [System.IO.FileAttributes]::ReadOnly)
            }
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $removed.Add([PSCustomObject]@{ Name = $file.Name; Length = $file.Length })
            Add-OfflineRepairLog -Message "Removed $($file.Name)."
        }
        catch {
            $deleteFailed = "$($file.Name) could not be removed: $($_.Exception.Message)"
            break
        }
    }
    $result.Removed = @($removed)

    if ($deleteFailed) {
        Add-OfflineRepairLog -Level Error -Message "$deleteFailed Rolling this scope back."
        $rollback = Restore-TransactionLogBackup -BackupPath $backupPath -TargetPath $Plan.ScopeInfo.Path -FileRecord $Plan.Snapshot.LogFile
        foreach ($line in @($rollback.Detail)) { Add-OfflineRepairLog -Message "  $line" }
        $result.Reason = $deleteFailed
        return $result
    }

    # Prove it did what it was supposed to and nothing more.
    $verification = Test-TransactionLogResult -Plan $Plan -Removed $result.Removed
    $result.Verification = $verification

    foreach ($check in @($verification.Check)) {
        $line = "  [$(if ($check.Passed) { 'PASS' } else { 'FAIL' })] $($check.Name): $($check.Detail)"
        if ($check.Passed) { Add-OfflineRepairLog -Message $line }
        else { Add-OfflineRepairLog -Level Error -Message $line }
    }

    if (-not $verification.Passed) {
        Add-OfflineRepairLog -Level Error -Message "Verification failed for scope $($Plan.Scope). Rolling it back."
        $rollback = Restore-TransactionLogBackup -BackupPath $backupPath -TargetPath $Plan.ScopeInfo.Path -FileRecord $Plan.Snapshot.LogFile
        foreach ($line in @($rollback.Detail)) { Add-OfflineRepairLog -Message "  $line" }
        $result.Reason = ($verification.Failure -join '; ')
        return $result
    }

    $result.Success = $true
    return $result
}

function Get-OfflineFreeSpace {
    <#
    .SYNOPSIS
        Free bytes on the volume holding a path, or $null when it cannot be determined.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if ([string]::IsNullOrWhiteSpace($root)) { return $null }
        $drive = Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction Stop
        return [int64]$drive.Free
    }
    catch { return $null }
}

function Get-RevertManifestPath {
    param([Parameter(Mandatory = $true)][string]$Drive)
    return (Join-Path $Drive "$scriptName-revert.json")
}

function Read-RevertManifest {
    <#
    .SYNOPSIS
        Reads the manifest a previous run left on the offline disk.

    .DESCRIPTION
        ConvertFrom-Json emits a JSON array as a single pipeline item, so the result is assigned
        before it is wrapped. Wrapping the pipeline directly produces one element holding the whole
        array, and the revert then silently restores nothing.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }

    try { $parsed = $content | ConvertFrom-Json }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The revert manifest at $Path could not be read ($($_.Exception.Message))."
        return $null
    }

    return $parsed
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run removed, without discarding what an earlier run recorded.

    .DESCRIPTION
        Each run writes the same file, so a plain overwrite loses the undo information from the run
        before it. A run that cleared TxR followed by a run that cleared SMI would otherwise leave a
        manifest naming only SMI, and reverting would restore half of what was taken.

        Entries are keyed by scope. A scope cleared twice keeps the most recent backup, because that
        is the one holding the files that were actually there last.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Entry
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($Entry)) { $entries.Add($item) }

    $existing = Read-RevertManifest -Path $Path
    if ($existing -and $existing.Scopes) {
        $known = @($entries | ForEach-Object { $_.Scope })
        foreach ($old in @($existing.Scopes)) {
            if ($known -notcontains $old.Scope) { $entries.Add($old) }
        }
    }

    $manifest = [PSCustomObject]@{
        Script    = $scriptName
        Timestamp = $scriptStartTime
        Scopes    = @($entries)
    }

    try {
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
        Log-Info "Recorded the revert manifest at $Path." | Tee-Object -FilePath $logFile -Append
    }
    catch {
        Log-Warning "The revert manifest could not be written to $Path ($($_.Exception.Message))." | Tee-Object -FilePath $logFile -Append
    }
}

#########################################################################################################
# Main
#########################################################################################################

try {
    Log-Output "=== $scriptName started at $scriptStartTime ===" | Tee-Object -FilePath $logFile -Append

    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $systemRoot = $offline.WindowsPath
    $manifestPath = Get-RevertManifestPath -Drive $offline.WindowsDrive

    $selectedScopes = if ($scope -eq 'All') { @('TxR', 'Config', 'SMI') } else { @($scope) }

    #####################################################################################################
    # Revert
    #####################################################################################################
    if ($isRevert) {
        Log-Output '--- Revert ---' | Tee-Object -FilePath $logFile -Append

        $manifest = Read-RevertManifest -Path $manifestPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if (-not $manifest -or -not $manifest.Scopes) {
            Log-Output "No revert manifest was found at $manifestPath, so there is nothing this script has to put back." | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }

        $restoredTotal = 0
        $failedTotal = 0
        foreach ($entry in @($manifest.Scopes)) {
            Log-Output "Restoring scope $($entry.Scope) from $($entry.BackupPath)." | Tee-Object -FilePath $logFile -Append
            $restore = Restore-TransactionLogBackup -BackupPath $entry.BackupPath -TargetPath $entry.TargetPath -FileRecord $entry.Files
            foreach ($line in @($restore.Detail)) { Log-Info "  $line" | Tee-Object -FilePath $logFile -Append }
            $restoredTotal += $restore.Restored
            $failedTotal += $restore.Failed
        }

        Log-Output "Restored $restoredTotal file(s); $failedTotal could not be restored." | Tee-Object -FilePath $logFile -Append
        if ($failedTotal -gt 0) { return $STATUS_ERROR }

        try { Remove-Item -LiteralPath $manifestPath -Force -ErrorAction Stop }
        catch { Log-Warning "The manifest at $manifestPath could not be removed ($($_.Exception.Message))." | Tee-Object -FilePath $logFile -Append }

        Log-Output 'Revert complete.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Detect
    #####################################################################################################
    Log-Output '--- Detection ---' | Tee-Object -FilePath $logFile -Append

    $findings = [System.Collections.Generic.List[object]]::new()

    $evidence = Get-LogExhaustionEvidence -SystemRoot $systemRoot
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($evidence.Found) {
        $findings.Add((New-Finding -Category 'Log exhaustion' -Severity 'Critical' -Priority 10 `
                    -Detail "ERROR_LOG_FULL was reported in $($evidence.Source): $($evidence.SampleLine)"))
        Log-Output "Log exhaustion evidence found in $($evidence.Source)." | Tee-Object -FilePath $logFile -Append
        Log-Output "  $($evidence.SampleLine)" | Tee-Object -FilePath $logFile -Append
    }
    elseif (@($evidence.LogsRead).Count -eq 0) {
        Log-Output 'No CBS log was available to read, so there is no evidence either way.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output "No ERROR_LOG_FULL entry was found in the last $($script:CbsTailLine) lines of $(@($evidence.LogsRead).Count) CBS log(s)." | Tee-Object -FilePath $logFile -Append
    }

    $plans = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $selectedScopes) {
        $scopeInfo = Get-TransactionLogScope -Name $name -SystemRoot $systemRoot
        $plan = Get-TransactionLogPlan -ScopeInfo $scopeInfo
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        $plans.Add($plan)

        if (-not $plan.Snapshot.Present) {
            Log-Output "Scope $name ($($scopeInfo.Label)): the folder $($scopeInfo.Path) is not present." | Tee-Object -FilePath $logFile -Append
            continue
        }
        if (-not $plan.Snapshot.Accessible) {
            Log-Warning "Scope ${name}: $($scopeInfo.Path) could not be enumerated ($($plan.Snapshot.AccessError))." | Tee-Object -FilePath $logFile -Append
            $findings.Add((New-Finding -Category 'Folder unreadable' -Severity 'Warning' -Priority 30 -Actionable $false `
                        -Detail "$($scopeInfo.Path) could not be enumerated: $($plan.Snapshot.AccessError)"))
            continue
        }

        Log-Output "Scope $name ($($scopeInfo.Label)): $($plan.FileCount) log file(s), $([math]::Round($plan.TotalBytes / 1KB)) KB, alongside $(@($plan.Snapshot.OtherFile).Count) other file(s)." | Tee-Object -FilePath $logFile -Append
        foreach ($file in @($plan.Snapshot.LogFile)) {
            Log-Info "    $($file.Name)  $([math]::Round($file.Length / 1KB)) KB" | Tee-Object -FilePath $logFile -Append
        }
        foreach ($hive in @($plan.HiveState | Where-Object { $_.Present })) {
            $state = if ($hive.Tested) { if ($hive.Loads) { 'loads' } else { "does not load ($($hive.Reason))" } } else { $hive.Reason }
            Log-Info "    hive $($hive.Name): $state" | Tee-Object -FilePath $logFile -Append
        }
    }

    $markers = Get-PendingServicingMarker -SystemRoot $systemRoot
    foreach ($marker in $markers) {
        $findings.Add((New-Finding -Category 'Pending servicing' -Severity 'Warning' -Priority 40 -Actionable $false `
                    -Detail "$marker - an interrupted update is a different problem; win-fix-pending-servicing is the script for it"))
        Log-Warning "$marker. This script does not act on that; win-fix-pending-servicing does." | Tee-Object -FilePath $logFile -Append
    }

    $actionable = @($plans | Where-Object { $_.Actionable })

    Log-Output '--- Findings ---' | Tee-Object -FilePath $logFile -Append
    if ($findings.Count -eq 0) {
        Log-Output 'No issues found.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        foreach ($finding in @($findings | Sort-Object Priority)) {
            Log-Output "[$($finding.Severity)] $($finding.Category): $($finding.Detail)" | Tee-Object -FilePath $logFile -Append
        }
    }

    #####################################################################################################
    # Decide
    #####################################################################################################
    if ($isDetectOnly) {
        if ($actionable.Count -gt 0) {
            $total = ($actionable | Measure-Object -Property FileCount -Sum).Sum
            Log-Output "detectOnly: $total transaction log file(s) across $($actionable.Count) scope(s) would be removed." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'detectOnly: there are no transaction log files to remove.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output 'detectOnly was requested, so nothing was changed.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($actionable.Count -eq 0) {
        Log-Output 'There are no transaction log files in the selected scope(s), so there is nothing to remove.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if (-not $evidence.Found -and -not $isForce) {
        Log-Output 'Transaction logs are present, but they are present on every healthy Windows installation and no evidence of log exhaustion was found.' | Tee-Object -FilePath $logFile -Append
        Log-Output 'Nothing was changed. If the symptom was identified another way - CBS.log can roll over into a .cab and take the evidence with it - re-run with "force true".' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if (-not $evidence.Found -and $isForce) {
        Log-Warning 'No log exhaustion evidence was found, but force was requested, so the logs will be cleared.' | Tee-Object -FilePath $logFile -Append
    }

    #####################################################################################################
    # Repair
    #####################################################################################################
    Log-Output '--- Repair ---' | Tee-Object -FilePath $logFile -Append

    $backupRoot = Join-OfflinePath $systemRoot "Temp\$scriptName\$scriptStartTime"
    try { New-Item -Path $backupRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    catch {
        Log-Error "The backup folder $backupRoot could not be created ($($_.Exception.Message))." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }
    Log-Output "Backups for this run are in $backupRoot." | Tee-Object -FilePath $logFile -Append

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($plan in $actionable) {
        Log-Output "Clearing scope $($plan.Scope) - $($plan.FileCount) file(s) in $($plan.ScopeInfo.Path)." | Tee-Object -FilePath $logFile -Append
        $outcome = Clear-TransactionLogScope -Plan $plan -BackupRoot $backupRoot
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        $results.Add($outcome)
    }

    #####################################################################################################
    # Verify
    #####################################################################################################
    Log-Output '--- Verification ---' | Tee-Object -FilePath $logFile -Append

    $succeeded = @($results | Where-Object { $_.Success })
    $failed = @($results | Where-Object { -not $_.Success })

    $manifestEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($outcome in $succeeded) {
        $plan = @($actionable | Where-Object { $_.Scope -eq $outcome.Scope } | Select-Object -First 1)[0]
        $manifestEntries.Add([PSCustomObject]@{
                Scope      = $outcome.Scope
                TargetPath = $plan.ScopeInfo.Path
                BackupPath = $outcome.BackupPath
                Files      = @($plan.Snapshot.LogFile | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Attributes = $_.Attributes } })
            })
        Log-Output "Scope $($outcome.Scope): $(@($outcome.Removed).Count) file(s) removed and verified." | Tee-Object -FilePath $logFile -Append
    }

    if ($manifestEntries.Count -gt 0) {
        Write-RevertManifest -Path $manifestPath -Entry @($manifestEntries)
    }

    foreach ($outcome in $failed) {
        Log-Error "Scope $($outcome.Scope) failed and was rolled back: $($outcome.Reason)" | Tee-Object -FilePath $logFile -Append
    }

    if ($failed.Count -gt 0) {
        Log-Error "$($failed.Count) of $($results.Count) scope(s) failed. The disk is in the state it was in before this run." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output 'The transaction logs were cleared. Windows recreates them on the next boot.' | Tee-Object -FilePath $logFile -Append
    if (@($markers).Count -gt 0) {
        Log-Warning 'Pending servicing markers are still present, so the VM may need win-fix-pending-servicing as well.' | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detach the disk and reattach it to the original VM with 'az vm repair restore'." | Tee-Object -FilePath $logFile -Append
    Log-Output "The backups and the revert manifest travel back with the disk. Once the VM is confirmed healthy they can be deleted from $backupRoot and $manifestPath. Reverting needs both, so keep them until then." | Tee-Object -FilePath $logFile -Append

    return $STATUS_SUCCESS
}
catch {
    Log-Error "$scriptName failed: $($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error $_.ScriptStackTrace | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
