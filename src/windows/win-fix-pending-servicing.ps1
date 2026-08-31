#########################################################################################################
#
# .SYNOPSIS
#   Abandons a stuck Windows servicing transaction on an offline disk, so a VM caught in an
#   "Undoing changes made to your computer" boot loop can start again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   A Windows update applies in two stages. The online stage stages the payload and writes a
#   transaction describing what the next boot must finish; the offline stage runs during boot and
#   completes or rolls back that transaction. When the offline stage cannot finish - the payload is
#   damaged, the component store is inconsistent, or the VM lost power part way through - the boot
#   loader keeps handing control back to the same unfinished transaction. The VM reports "Getting
#   Windows ready", then "Undoing changes made to your computer", then restarts and does it again.
#   Nothing about that loop times out on its own.
#
#   This script removes the transaction rather than the update. It asks DISM to revert the pending
#   actions, and then clears the markers the boot path reads to decide there is servicing work
#   outstanding:
#     1. WinSxS\pending.xml, the manifest of the operations the next boot is expected to finish.
#     2. Control\Session Manager\SetupExecute, the hook smss.exe reads to launch poqexec.exe against
#        that manifest. A healthy installation carries this as an empty REG_MULTI_SZ. It is cleared
#        both when it was already stale and when this run is what made it stale by renaming
#        pending.xml aside - leaving it set is what turns this repair into a boot stopper.
#     3. The Component Based Servicing keys PackagesPending, RebootPending and RebootInProgress.
#        CBS\SessionsPending is read but never removed: a healthy image carries one completed record
#        per servicing session there, so only a session that never reached Complete=1 is reported,
#        and the records themselves are history this script does not rewrite.
#     4. The COMPONENTS values that record an interrupted transaction - ExecutionState,
#        PendingXmlIdentifier, NextQueueEntryIndex, NextQueueEntryIndexBCDB,
#        AdvancedInstallersNeedResolving and StoreDirty.
#     5. The transactional registry logs under System32\config\TxR, which hold the uncommitted
#        registry side of that same transaction.
#
#   A leftover SetupExecute is worth calling out because it presents differently from the boot loop
#   above and leaves no other marker behind. smss.exe runs the hook before the Event Log service
#   starts, so a VM stopped there writes nothing about it: the console shows a black screen with a
#   spinner rather than "Undoing changes", the guest agent never reports Ready, extension operations
#   wedge, and the newest event in System.evtx is from the previous boot. Every servicing marker
#   reads clean, because the transaction really did finish - only the hook was left behind.
#
#   Everything is driven by evidence. The script reports every marker it finds before it changes
#   anything, and if it finds none it changes nothing and says so - which is the answer an operator
#   needs, because it means the boot loop has some other cause and this script is aimed at the wrong
#   problem. The TxR logs are never cleared on their own evidence: they are present and healthy on
#   every running Windows installation. They are cleared when a servicing marker was found, or when
#   CBS reports ERROR_LOG_FULL (0x800719e4), which is a transaction that stalled because it ran out
#   of CLFS log space and leaves no marker of its own to find. Either way something independent has
#   already established that the transaction is stuck.
#
#   Clearing them is verified rather than assumed. Every file is hash-verified into a backup before
#   anything is deleted, the folder is re-examined afterwards against six checks - still present, not
#   recreated, ACL unchanged, planned files gone, no other file touched, hives still loading - and any
#   failure restores everything that was removed and fails the run. An operator who is told the logs
#   were cleared and reboots into the same loop has been actively misled, so the run reports what
#   actually happened.
#
#   The SOFTWARE and COMPONENTS hives are backed up before either is written to, and every reversible
#   change is recorded in a manifest on the offline disk so "-revert true" can put it back.
#
# .RESOLVES
#   A VM that loops on "Getting Windows ready", "Undoing changes made to your computer" or
#   "Failure configuring Windows updates - reverting changes", a VM that restarts repeatedly during
#   the update stage of boot, and a VM left unbootable after an update was interrupted by a power
#   loss, a forced deallocation or a crash mid-servicing.
#
# .PARAMETER detectOnly
#   "true" to report the servicing state and what would be cleared, and make no changes at all.
#   Defaults to "false".
#
# .PARAMETER disableWindowsUpdate
#   "true" to also set Start=4 on wuauserv, UsoSvc, WaaSMedicSvc and UpdateOrchestrator, so the VM
#   cannot immediately re-download and re-stage the update that broke it. Defaults to "false".
#
#   This is a workaround, not a repair, which is why it is off by default and has to be asked for by
#   name. It leaves the VM unpatched and therefore exposed, so it is only appropriate as a way to
#   hold a VM still long enough to collect data or take a backup. The original Start values are
#   recorded in the revert manifest, and the summary prints the commands to turn the services back on
#   from inside the running VM.
#
# .PARAMETER revert
#   "true" to undo a previous run of this script from the manifest it left on the offline disk:
#   Windows Update services go back to their original Start values, the renamed pending.xml is
#   renamed back, and the TxR logs are restored from the copy taken before they were deleted.
#   Defaults to "false".
#
#   Reverting deliberately puts the servicing transaction back, so a VM that was in a boot loop will
#   go back into it. It exists for the case where this script was aimed at the wrong problem and the
#   disk needs to be handed on unchanged. The registry keys are not restored from the manifest; they
#   come back with the hive backup, whose path is printed in the summary.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-pending-servicing --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-pending-servicing --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-pending-servicing --parameters disableWindowsUpdate=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-pending-servicing --parameters revert=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   How this differs from win-remove-patch, which is the script it is most likely to be confused
#   with. That one removes a named package: an operator runs win-get-patches, decides which update is
#   at fault, and DISM removes that package from the image. It needs the update to be identified
#   first, and it changes what is installed. This script never removes a package and never needs one
#   named. It abandons the in-flight transaction and leaves the installed set alone, which is what a
#   boot loop needs, because in a loop the update has not finished installing in the first place -
#   there is frequently nothing to remove yet. Use this one first: it is the smaller change, and if
#   the VM boots afterwards the offending update can then be identified and removed from inside the
#   running VM, which is far easier than doing it offline.
#
#   How this differs from win-sfc-sf-corruption, which also runs DISM /RevertPendingActions. There
#   that command is a prelude: it runs so that the SFC scan which follows it can succeed, and the
#   script goes on to run SFC, DISM /RestoreHealth, rewrite the Boot Configuration Data to disable
#   the recovery console and set bootstatuspolicy to IgnoreAllFailures, and replace the SYSTEM hive
#   with the RegBack copy. All of that is a great deal of collateral change for an operator whose
#   only problem is an unfinished transaction. This script performs the revert and clears the
#   markers, and does nothing else. Run win-sfc-sf-corruption when the system files themselves are
#   damaged, not when servicing is merely stuck.
#
#   Not ported from the source material this script was split out of, on purpose:
#
#     DISM /Remove-Package over every package DISM reports as Pending. That is win-remove-patch's
#     job, it is a much larger change than the symptom calls for, and against an image whose
#     component store is mid-transaction it usually fails anyway. The pending packages are still
#     reported here, because naming them is exactly the evidence an operator needs to decide whether
#     to reach for win-remove-patch next.
#
#     DISM /StartComponentCleanup. It reclaims superseded components and cannot affect whether the
#     VM boots. It is slow, it is best-effort, and running it against an image whose transaction was
#     only just reverted adds risk for no benefit to the symptom being repaired.
#
#     Copying System32\config wholesale to a backup folder before touching anything. That folder
#     holds the registry hives, so on a real server the copy runs to gigabytes and can fill the
#     rescue VM's disk. Only the files this script actually deletes are backed up, and the hives are
#     backed up properly through the hive backup helper.
#
#     Deleting *.blf and *.regtrans-ms directly under System32\config. The transactional registry
#     logs live in config\TxR, which is handled. The files sitting in config itself are the hive
#     recovery logs, and removing those from under a hive that is dirty is a documented way to turn a
#     recoverable installation into an unbootable one with STATUS_CANNOT_LOAD_REGISTRY_FILE. This
#     script only ever looks inside config\TxR, where every file is a transaction artifact, and the
#     removal helper additionally refuses .log, .log1 and .log2 by name wherever it is pointed. Use
#     win-fix-transaction-logs when the logs in config itself, or under SMI\Store\Machine, need
#     clearing - it takes a scope parameter for exactly that.
#
#   DISM exit codes that are not failures. 0x800F082F means there were no pending actions to revert,
#   which on a disk whose markers were left behind by a half-finished transaction is a normal and
#   useful result rather than an error - the markers still need clearing. 3010 means the operation
#   succeeded and wants a reboot, which is exactly what is about to happen. Both are reported as
#   information, and neither stops the rest of the repair.
#
#   DISM is run against the offline image from the rescue VM, so the rescue VM's own Windows version
#   matters. Servicing an image newer than the host DISM is not supported and can fail with
#   0x800F081E or simply report the image as incompatible. "az vm repair create" picks a rescue image
#   that matches the source by default, so this is normally handled; if DISM refuses the image, the
#   marker clearing still runs and is usually enough on its own.
#
#   Changes are made to the active control set only, so Last Known Good remains available as an
#   independent escape route that does not need this script to have worked.
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$disableWindowsUpdate = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-OfflineFileRemoval.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$doDisableWindowsUpdate = ($disableWindowsUpdate -eq 'true')

# The COMPONENTS values that record an interrupted servicing transaction. A value that is absent, 0
# or empty is the state a settled installation is in, so only a value outside that set is evidence.
$script:PendingComponentValue = @(
    'ExecutionState',
    'PendingXmlIdentifier',
    'NextQueueEntryIndex',
    'NextQueueEntryIndexBCDB',
    'AdvancedInstallersNeedResolving',
    'StoreDirty'
)

# The Component Based Servicing keys whose mere presence means work is outstanding.
#
# SessionsPending is deliberately NOT in this list. It is normal bookkeeping: a healthy, fully
# booted Server 2022 image carries it with one child per servicing session that has already
# finished, each holding Complete=1. Treating its presence as evidence reports a healthy machine as
# mid-transaction, which would run a DISM revert and clear the TxR logs on a VM that was fine. It is
# checked separately, by completion state, in Get-IncompleteServicingSession.
$script:PendingCbsKey = @('PackagesPending', 'RebootPending', 'RebootInProgress')

# Bookkeeping key holding one child per servicing session. Evidence only when a session never
# reached Complete=1.
$script:SessionsPendingKey = 'SessionsPending'

# The services that re-download and re-stage an update. Only touched when disableWindowsUpdate is
# asked for by name. UpdateOrchestrator is included because it schedules the install that UsoSvc
# then drives; leaving it running puts the VM straight back where it started.
$script:WindowsUpdateService = @('wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'UpdateOrchestrator')

# CLFS transaction artifacts under config\TxR. Selection is delegated to Use-OfflineFileRemoval,
# which applies these as a two-layer allow-list: a file must match an allowed extension AND must not
# match a protected one. That is stricter than a wildcard, because a protected name can never be
# selected no matter what else matches.
#
# The earlier wildcard pair here - '*.TxR.blf' and '*.TxR.*.regtrans-ms' - was measured against a
# real Server 2022 disk and matched only 4 of the 7 files actually present in config\TxR. It missed
# '{guid}.TM.blf' and both '{guid}.TMContainer*.regtrans-ms', which are the transaction manager's own
# logs - precisely the ones holding the uncommitted state this script is trying to clear. Clearing 4
# of 7 leaves the transaction half-described, so the allow-list is by extension instead.
#
# Every file in config\TxR is a transaction artifact, so this is safe there. The hive recovery logs
# that must never be removed live one level up in config itself, which this script does not touch.
$script:TxRExtension = @('.blf', '.regtrans-ms')
$script:ProtectedExtension = @('.log', '.log1', '.log2', '.dat', '.sav', '.bak')

# config\TxR holds no registry hives, so there is nothing for the helper to revalidate there. The
# limit is still passed so the behaviour is explicit rather than defaulted.
$script:HiveTestMaxBytes = 512MB

# What log exhaustion looks like in CBS.log. 0x800719e4 is ERROR_LOG_FULL as CBS prints it. This
# duplicates the detection in win-fix-transaction-logs on purpose: both scenarios need the evidence,
# and a scenario script has to stand on its own rather than send the operator to another run id.
$script:LogFullPattern = '0x800719e4|ERROR_LOG_FULL'

# CBS.log is large and the useful part is the end of it. Reading the tail keeps this to a bounded
# read on a multi-hundred-megabyte file.
$script:CbsTailLine = 4000

$script:CbsSoftwareKey = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
$script:ComponentsKey = 'HKLM:\BROKENCOMPONENTS'

# Session Manager runs SetupExecute before anything else in the boot chain, and servicing points it
# at poqexec.exe to finish the operations listed in pending.xml. Windows clears the value when the
# operation completes, so on a healthy installation it is an empty REG_MULTI_SZ - measured against a
# freshly deployed Server 2022 marketplace image, which reports exactly that.
#
# A value left behind with no pending.xml to read is a boot stopper of its own. smss.exe launches
# poqexec against a manifest that is not there and the boot goes no further, which lands before the
# Event Log service starts, so the VM writes nothing about it: the console shows a black screen with
# a spinner, the guest agent never reports Ready, extensions wedge, and the newest event in
# System.evtx is from the previous boot. Nothing in the CBS or COMPONENTS markers records this, so
# without checking the value directly the disk reads as perfectly clean.
$script:SessionManagerSubKey = 'Control\Session Manager'
$script:SetupExecuteValue = 'SetupExecute'

function New-Finding {
    <#
    .SYNOPSIS
        One piece of evidence that servicing is mid-transaction.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Marker,
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $false)][string]$Kind = 'Servicing'
    )

    return [PSCustomObject]@{
        Marker = $Marker
        Detail = $Detail
        Kind   = $Kind
    }
}

function Get-ServicingRegistryState {
    <#
    .SYNOPSIS
        Reads the CBS and COMPONENTS markers. Must be called with SOFTWARE mounted.

    .DESCRIPTION
        Returns the raw state rather than findings, so the caller can report it whether or not it
        amounts to evidence of a stuck transaction.

        COMPONENTS is optional. When it is not mounted the transaction values read back as absent,
        which is not evidence, and the CBS keys in SOFTWARE are still checked.
    #>
    $cbs = @{}
    foreach ($key in $script:PendingCbsKey) {
        $path = Join-Path $script:CbsSoftwareKey $key
        $cbs[$key] = if (Test-Path $path) {
            [PSCustomObject]@{
                Present    = $true
                ChildCount = @(Get-ChildItem $path -ErrorAction SilentlyContinue).Count
            }
        }
        else {
            [PSCustomObject]@{ Present = $false; ChildCount = 0 }
        }
    }

    $componentValues = @{}
    $props = Get-ItemProperty $script:ComponentsKey -ErrorAction SilentlyContinue
    foreach ($name in $script:PendingComponentValue) {
        $value = if ($props) { $props.$name } else { $null }
        $componentValues[$name] = $value
    }

    return [PSCustomObject]@{
        Cbs                = $cbs
        ComponentValues    = $componentValues
        ComponentsFound    = ($null -ne $props)
        IncompleteSessions = @(Get-IncompleteServicingSession -SessionsKeyPath (Join-Path $script:CbsSoftwareKey $script:SessionsPendingKey))
    }
}

function Get-IncompleteServicingSession {
    <#
    .SYNOPSIS
        Servicing sessions that started and never finished. Must be called with SOFTWARE mounted.

    .DESCRIPTION
        Each child of CBS\SessionsPending records one servicing session, and a session that finished
        holds Complete=1. A healthy installation keeps those completed records for the life of the
        image, so the presence of the key, or of children under it, is not evidence of anything.

        Only a child that never reached Complete=1 is evidence: that is a session which was
        interrupted, which is the state this script exists to clear.
    #>
    param([Parameter(Mandatory = $true)][string]$SessionsKeyPath)

    if (-not (Test-Path $SessionsKeyPath)) { return @() }

    $incomplete = [System.Collections.Generic.List[object]]::new()
    foreach ($child in @(Get-ChildItem $SessionsKeyPath -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue
        $complete = if ($props) { $props.Complete } else { $null }
        if ("$complete" -eq '1') { continue }

        $phase = if ($props -and $null -ne $props.LastCommittedPhase) { $props.LastCommittedPhase } else { 'unknown' }
        [void]$incomplete.Add([PSCustomObject]@{
                Name  = $child.PSChildName
                Phase = $phase
            })
    }

    return @($incomplete)
}

function Test-PendingComponentValue {
    <#
    .SYNOPSIS
        True when a COMPONENTS value is set to something that indicates an unfinished transaction.

    .DESCRIPTION
        Absent, 0 and empty all mean "nothing outstanding". Anything else is evidence.
    #>
    param([Parameter(Mandatory = $false)]$Value)

    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return ($Value.Trim() -ne '') }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) { return ($Value -ne 0) }
    if ($Value -is [byte[]]) { return ($Value.Length -gt 0) }
    return $true
}

function Get-TxRState {
    <#
    .SYNOPSIS
        Builds the removal plan for the CLFS transaction artifacts under System32\config\TxR.
    .DESCRIPTION
        Selection, backup, deletion, verification and rollback all live in Use-OfflineFileRemoval, so
        this is a thin wrapper that supplies this script's allow-list and nothing else. Present and
        Files are kept as aliases over the plan so the call sites below read the same as before.

        config\TxR declares no hives, so no hive is loaded here. That matters: loading a hive in place
        writes KTM logs next to it and would change the very folder this script is about to verify.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $txrPath = Join-Path $WindowsPath 'System32\config\TxR'
    $plan = Get-OfflineRemovalPlan -Path $txrPath -Label 'TxR' `
        -MatchExtension $script:TxRExtension -ProtectedExtension $script:ProtectedExtension `
        -HiveName @() -HiveMaxBytes $script:HiveTestMaxBytes `
        -IncludeHash

    # -IncludeHash is not optional here. Backup-OfflineFile re-hashes each copy and compares it with
    # the hash recorded in the snapshot; with no hash recorded there is nothing to compare against and
    # a silently corrupt backup would be accepted as good.
    #
    # Actionable is added by the caller rather than the helper, so it has to be spelled out the same
    # way win-fix-transaction-logs spells it. A plan with no Actionable property reads as $false and
    # would quietly disable the whole repair.
    $snapshot = $plan.Snapshot
    $plan | Add-Member -NotePropertyName 'Actionable' -NotePropertyValue (
        $snapshot.Present -and $snapshot.Accessible -and @($snapshot.MatchedFile).Count -gt 0) -Force
    $plan | Add-Member -NotePropertyName 'Present' -NotePropertyValue ([bool]$snapshot.Present) -Force
    $plan | Add-Member -NotePropertyName 'Files' -NotePropertyValue (@($snapshot.MatchedFile)) -Force
    return $plan
}

function Get-LogExhaustionEvidence {
    <#
    .SYNOPSIS
        Looks for ERROR_LOG_FULL in the offline CBS logs.
    .DESCRIPTION
        A servicing transaction that ran out of CLFS log space reports 0x800719e4 and then stops
        making progress, which presents as the same "Undoing changes" loop as any other stuck
        transaction. Finding it here is what authorises clearing config\TxR, so that the operator gets
        the whole repair from one run rather than being sent to win-fix-transaction-logs afterwards.

        This is a twin of the function of the same name in win-fix-transaction-logs. The duplication
        is deliberate: both scenarios need the evidence independently, and copying 60 lines of
        read-only detection is cheaper than coupling two scenario scripts together.

        Only the tail of each log is read. CBS.log runs to hundreds of megabytes on a machine that has
        been patching for years, and the useful record is always at the end.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $cbsFolder = Join-Path $WindowsPath 'Logs\CBS'
    $result = [PSCustomObject]@{ Found = $false; Source = ''; Line = ''; LogsRead = 0 }

    if (-not (Test-Path -LiteralPath $cbsFolder)) { return $result }

    # CbsPersist_*.log are the rolled-over generations of CBS.log. A transaction that filled the log
    # some time ago has its record in one of those rather than in the current file.
    $logs = @(Get-ChildItem -LiteralPath $cbsFolder -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'CBS.log' -or $_.Name -like 'CbsPersist_*.log' } |
            Sort-Object LastWriteTimeUtc -Descending)

    foreach ($log in $logs) {
        $result.LogsRead++
        try {
            $tail = @(Get-Content -LiteralPath $log.FullName -Tail $script:CbsTailLine -ErrorAction Stop)
        }
        catch {
            Add-OfflineRepairLog -Level Info -Message "Could not read $($log.Name) ($($_.Exception.Message))."
            continue
        }

        $hit = @($tail | Where-Object { $_ -match $script:LogFullPattern }) | Select-Object -Last 1
        if ($hit) {
            $result.Found = $true
            $result.Source = $log.FullName
            $result.Line = $hit.Trim()
            return $result
        }
    }

    return $result
}

function Get-WindowsUpdateServiceState {
    <#
    .SYNOPSIS
        Current Start value of each Windows Update service. Must be called with SYSTEM mounted.
    #>
    $root = Get-OfflineSystemRootPath
    $state = [System.Collections.Generic.List[object]]::new()

    foreach ($name in $script:WindowsUpdateService) {
        $path = "$root\Services\$name"
        if (-not (Test-Path $path)) { continue }
        $start = (Get-ItemProperty $path -ErrorAction SilentlyContinue).Start
        [void]$state.Add([PSCustomObject]@{
                Service = $name
                Path    = $path
                Start   = $start
            })
    }

    return @($state)
}

function Get-SetupExecuteState {
    <#
    .SYNOPSIS
        The Session Manager SetupExecute hook. Must be called with SYSTEM mounted.

    .DESCRIPTION
        Returns the raw value rather than a verdict, because whether it counts as evidence depends
        on something this function cannot see: whether the pending.xml it names still exists. That
        decision is made in Get-ServicingFinding with both halves in hand.

        The value is REG_MULTI_SZ. An absent value and an empty one are the same thing to the boot
        path and are reported as the same thing here.
    #>
    $root = Get-OfflineSystemRootPath
    $path = "$root\$script:SessionManagerSubKey"

    if (-not (Test-Path $path)) {
        return [PSCustomObject]@{ KeyPresent = $false; Path = $path; Entries = @(); Set = $false }
    }

    $raw = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$script:SetupExecuteValue
    $entries = @(@($raw) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    return [PSCustomObject]@{
        KeyPresent = $true
        Path       = $path
        Entries    = $entries
        Set        = ($entries.Count -gt 0)
    }
}

function Get-DismPendingPackage {
    <#
    .SYNOPSIS
        Asks DISM which packages the offline image reports as Pending.

    .DESCRIPTION
        Best effort and never fatal. An image whose component store is mid-transaction frequently
        refuses to enumerate, which is itself worth reporting rather than treating as a failure.
        Naming the pending packages is the evidence an operator needs to decide whether
        win-remove-patch is the next step.
    #>
    param([Parameter(Mandatory = $true)][string]$Drive)

    $result = [PSCustomObject]@{ Succeeded = $false; Packages = @(); Message = '' }

    try {
        $text = & dism.exe /Image:$Drive /Get-Packages /Format:List 2>&1 | Out-String -Width 9999
        if ($LASTEXITCODE -ne 0) {
            $result.Message = "DISM /Get-Packages exited with code $LASTEXITCODE."
            return $result
        }

        $packages = foreach ($block in ($text -split "(\r?\n){2,}")) {
            $fields = @{}
            foreach ($line in ($block -split "\r?\n")) {
                if ($line -match '^\s*([^:]+?)\s*:\s*(.+?)\s*$') { $fields[$matches[1]] = $matches[2] }
            }
            if ($fields.ContainsKey('Package Identity')) { [PSCustomObject]$fields }
        }

        $result.Succeeded = $true
        $result.Packages = @($packages | Where-Object { $_.State -eq 'Pending' } | ForEach-Object { $_.'Package Identity' })
    }
    catch {
        $result.Message = $_.Exception.Message
    }

    return $result
}

function Invoke-DismRevertPendingAction {
    <#
    .SYNOPSIS
        Asks DISM to revert the in-flight servicing transaction on the offline image.

    .DESCRIPTION
        0x800F082F ("no pending actions") and 3010 ("reboot required") are both normal outcomes here
        and are reported as information. Any other non-zero code is reported as a warning and the
        marker clearing still runs, because the markers are what the boot path actually reads.
    #>
    param([Parameter(Mandatory = $true)][string]$Drive)

    $scratch = Join-Path $env:TEMP "dism-scratch-$scriptStartTime"
    if (-not (Test-Path -LiteralPath $scratch)) { New-Item -Path $scratch -ItemType Directory -Force | Out-Null }

    Add-OfflineRepairLog -Level Info -Message "Running dism.exe /Image:$Drive /Cleanup-Image /RevertPendingActions"
    $output = & dism.exe /Image:$Drive /Cleanup-Image /RevertPendingActions /ScratchDir:$scratch 2>&1 | Out-String
    $code = $LASTEXITCODE

    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

    $noPending = ($code -eq -2146498513 -or $code -eq 2148468783 -or $output -match '0x800[fF]082[fF]')

    if ($code -eq 0) {
        Add-OfflineRepairLog -Level Info -Message 'DISM reverted the pending actions.'
    }
    elseif ($code -eq 3010) {
        Add-OfflineRepairLog -Level Info -Message 'DISM reverted the pending actions and reported that a restart is required (3010), which is expected.'
    }
    elseif ($noPending) {
        Add-OfflineRepairLog -Level Info -Message 'DISM reported no pending actions to revert (0x800F082F). The markers below are cleared regardless, because they are what the boot path reads.'
    }
    else {
        Add-OfflineRepairLog -Level Warning -Message "DISM exited with code $code. Marker clearing continues, because the markers are what the boot path reads."
        foreach ($line in ($output -split "\r?\n" | Where-Object { $_ -match '\S' } | Select-Object -Last 5)) {
            Add-OfflineRepairLog -Level Warning -Message "  $($line.Trim())"
        }
    }

    return [PSCustomObject]@{ ExitCode = $code; NoPendingActions = $noPending }
}

function Get-ServicingFinding {
    <#
    .SYNOPSIS
        Turns the raw servicing state into the list of markers that count as evidence.

    .DESCRIPTION
        Separated from both the reading and the reporting so the rule "absent, zero or empty is not
        evidence" is decided in exactly one place, and can be tested without an offline disk.

        A CBS key in PendingCbsKey counts the moment it exists, whether or not it holds entries: the
        boot path reads its presence, not its contents. SessionsPending is not one of those keys, and
        counts only when it holds a session that never completed.
    #>
    param(
        [Parameter(Mandatory = $true)][bool]$HasPendingXml,
        [Parameter(Mandatory = $false)][long]$PendingXmlSize = 0,
        [Parameter(Mandatory = $true)]$RegistryState,
        [Parameter(Mandatory = $false)]$SetupExecuteState = $null
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if ($HasPendingXml) {
        [void]$findings.Add((New-Finding -Marker 'WinSxS\pending.xml' -Detail "present, $PendingXmlSize byte(s)"))
    }

    # SetupExecute counts only when the manifest it points at is gone. With pending.xml present the
    # hook is doing its job and describes real outstanding work, which the finding above already
    # covers; clearing it there would strand the operation rather than finish it. With pending.xml
    # absent nothing can satisfy the hook and Session Manager has no way past it.
    if ($SetupExecuteState -and $SetupExecuteState.Set -and -not $HasPendingXml) {
        [void]$findings.Add((New-Finding -Marker "$script:SessionManagerSubKey\$script:SetupExecuteValue" `
                    -Detail "set to '$($SetupExecuteState.Entries -join ' | ')' with no pending.xml for it to read" `
                    -Kind 'SetupExecute'))
    }

    foreach ($key in $script:PendingCbsKey) {
        $entry = $RegistryState.Cbs[$key]
        if ($entry.Present) {
            $plural = if ($entry.ChildCount -eq 1) { 'y' } else { 'ies' }
            [void]$findings.Add((New-Finding -Marker "CBS\$key" -Detail "present with $($entry.ChildCount) entr$plural"))
        }
    }

    foreach ($session in @($RegistryState.IncompleteSessions)) {
        [void]$findings.Add((New-Finding -Marker "CBS\$script:SessionsPendingKey\$($session.Name)" `
                    -Detail "session never completed, last committed phase $($session.Phase)" `
                    -Kind 'Session'))
    }

    foreach ($name in $script:PendingComponentValue) {
        $value = $RegistryState.ComponentValues[$name]
        if (Test-PendingComponentValue -Value $value) {
            [void]$findings.Add((New-Finding -Marker "COMPONENTS\$name" -Detail "set to '$value'"))
        }
    }

    return @($findings)
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

    try {
        $parsed = $content | ConvertFrom-Json
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The revert manifest at $Path could not be read ($($_.Exception.Message))."
        return $null
    }

    return $parsed
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run changed, without discarding what an earlier run recorded.

    .DESCRIPTION
        Each run writes the same file, so a plain overwrite loses the undo information from the run
        before it. A repair that backs up the TxR logs followed by a disableWindowsUpdate run would
        leave a manifest naming the services but no TxR backup folder, and the revert would then
        report success while restoring nothing.

        Anything this run did not set is therefore carried forward from the existing manifest, and
        services keep the Start value recorded the first time they were seen: that is the one that
        was genuinely theirs before any run of this script touched them.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $existing = Read-RevertManifest -Path $Path
    if ($existing) {
        if ([string]::IsNullOrEmpty($Manifest.PendingXmlRenamedTo) -and $existing.PendingXmlRenamedTo) {
            $Manifest.PendingXmlRenamedTo = $existing.PendingXmlRenamedTo
        }
        if ([string]::IsNullOrEmpty($Manifest.TxRBackupFolder) -and $existing.TxRBackupFolder) {
            $Manifest.TxRBackupFolder = $existing.TxRBackupFolder
        }
        if (-not @($Manifest.SetupExecute).Count -and @($existing.SetupExecute).Count) {
            $Manifest.SetupExecute = $existing.SetupExecute
        }

        $known = @(@($Manifest.Services) | ForEach-Object { $_.Service })
        $carried = @(@($existing.Services) | Where-Object { $known -notcontains $_.Service })
        if ($carried.Count -gt 0) {
            $Manifest.Services = @(@($Manifest.Services) + $carried)
        }
    }

    ConvertTo-Json -InputObject $Manifest -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8 -Force
    Add-OfflineRepairLog -Level Info -Message "Recorded what was changed in $Path"
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, disableWindowsUpdate=$doDisableWindowsUpdate, revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $manifestPath = Get-RevertManifestPath -Drive $offline.WindowsDrive
    $pendingXmlPath = Join-Path $offline.WindowsPath 'WinSxS\pending.xml'

    # COMPONENTS is present on a normal installation, but Mount-OfflineHive throws when a hive file
    # is missing, and mounting it together with SOFTWARE would then lose the CBS read as well. It is
    # only ever mounted once it is known to be there.
    $componentsHivePath = Get-OfflineHiveFilePath -WindowsPath $offline.WindowsPath -Hive 'COMPONENTS'
    $hasComponentsHive = Test-OfflinePath $componentsHivePath
    $servicingHive = if ($hasComponentsHive) { @('SOFTWARE', 'COMPONENTS') } else { @('SOFTWARE') }
    if (-not $hasComponentsHive) {
        Log-Warning "The COMPONENTS hive is not present at $componentsHivePath. The CBS keys in SOFTWARE are still checked; the COMPONENTS transaction values are reported as absent." | Tee-Object -FilePath $logFile -Append
    }

    # ---------------------------------------------------------------------------------------------
    # Revert
    # ---------------------------------------------------------------------------------------------
    if ($isRevert) {
        $manifest = Read-RevertManifest -Path $manifestPath
        if ($null -eq $manifest) {
            Log-Output "No revert manifest was found at $manifestPath, so this script has not changed anything on this disk. No changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }

        $restored = 0
        $services = @($manifest.Services)
        $script:RevertCount = 0

        if ($services.Count -gt 0) {
            Log-Info "Revert manifest holds $($services.Count) Windows Update service(s): $(($services | ForEach-Object { $_.Service }) -join ', ')" | Tee-Object -FilePath $logFile -Append

            Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
                $root = Get-OfflineSystemRootPath
                foreach ($entry in $services) {
                    $path = "$root\Services\$($entry.Service)"
                    if (-not (Test-Path $path)) {
                        Add-OfflineRepairLog -Level Warning -Message "$($entry.Service): the service key is no longer present, so it was not restored."
                        continue
                    }
                    $current = (Get-ItemProperty $path -ErrorAction SilentlyContinue).Start
                    Set-ItemProperty -Path $path -Name Start -Value ([int]$entry.OriginalStart) -Type DWord -Force
                    Add-OfflineRepairLog -Level Info -Message "$($entry.Service): Start $current -> $($entry.OriginalStart) (restored)."
                    $script:RevertCount++
                }
            }
        }

        # $script:RevertCount is used because the hive script block runs in a child scope.
        $restored = [int]$script:RevertCount

        $setupExecuteOriginal = @(@($manifest.SetupExecute) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($setupExecuteOriginal.Count -gt 0) {
            $script:SetupExecuteRestored = $false
            # Passed through a script-scoped variable rather than $using:, which is only valid in a
            # remote or job script block. Invoke-WithHive runs this one locally in a child scope.
            $script:SetupExecuteToRestore = [string[]]$setupExecuteOriginal
            Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
                $state = Get-SetupExecuteState
                if (-not $state.KeyPresent) {
                    Add-OfflineRepairLog -Level Warning -Message "$script:SessionManagerSubKey is no longer present, so $script:SetupExecuteValue was not restored."
                    return
                }
                Set-ItemProperty -Path $state.Path -Name $script:SetupExecuteValue -Value $script:SetupExecuteToRestore -Type MultiString -Force -ErrorAction Stop
                $after = Get-SetupExecuteState
                if ($after.Set) {
                    $script:SetupExecuteRestored = $true
                    Add-OfflineRepairLog -Level Info -Message "Restored $script:SessionManagerSubKey\$script:SetupExecuteValue to '$($after.Entries -join ' | ')'."
                }
                else {
                    Add-OfflineRepairLog -Level Error -Message "$script:SetupExecuteValue reads back empty after the restore. It was NOT restored."
                }
            }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            if ($script:SetupExecuteRestored) { $restored++ }
        }

        if ($manifest.PendingXmlRenamedTo -and (Test-Path -LiteralPath $manifest.PendingXmlRenamedTo)) {
            if (Test-Path -LiteralPath $pendingXmlPath) {
                Log-Warning "pending.xml already exists again, so $($manifest.PendingXmlRenamedTo) was left in place." | Tee-Object -FilePath $logFile -Append
            }
            else {
                Rename-Item -LiteralPath $manifest.PendingXmlRenamedTo -NewName 'pending.xml' -Force
                Log-Info "Renamed $($manifest.PendingXmlRenamedTo) back to pending.xml." | Tee-Object -FilePath $logFile -Append
                $restored++
            }
        }

        if ($manifest.TxRBackupFolder -and (Test-Path -LiteralPath $manifest.TxRBackupFolder)) {
            # Restore-OfflineFileSet rather than a copy loop, so the attributes come back too. A
            # transaction log restored without its original attributes is not the file that was taken.
            $txrPath = Join-Path $offline.WindowsPath 'System32\config\TxR'
            $result = Restore-OfflineFileSet -BackupPath $manifest.TxRBackupFolder -TargetPath $txrPath
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
            $copied = [int]$result.Restored
            if ($result.Failed -gt 0) {
                Log-Warning "$($result.Failed) TxR transaction file(s) could not be restored from $($manifest.TxRBackupFolder)." | Tee-Object -FilePath $logFile -Append
            }
            if ($copied -gt 0) {
                Log-Info "Restored $copied TxR transaction file(s) from $($manifest.TxRBackupFolder)." | Tee-Object -FilePath $logFile -Append
                $restored += $copied
            }
        }

        if ($restored -gt 0) {
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
            Log-Output "Restored $restored item(s) and removed the manifest." | Tee-Object -FilePath $logFile -Append
            Log-Output "The registry keys this script cleared are not restored from the manifest. Use the hive backup recorded in the log of the original run if they are needed." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'Nothing in the manifest could be restored. The manifest was left in place.' | Tee-Object -FilePath $logFile -Append
        }

        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # ---------------------------------------------------------------------------------------------
    # Detect
    # ---------------------------------------------------------------------------------------------
    $findings = [System.Collections.Generic.List[object]]::new()

    $hasPendingXml = Test-Path -LiteralPath $pendingXmlPath
    $pendingXmlSize = if ($hasPendingXml) { (Get-Item -LiteralPath $pendingXmlPath).Length } else { 0 }

    $registryState = Invoke-WithHive -Hive $servicingHive -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-ServicingRegistryState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $setupExecute = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-SetupExecuteState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # @() is not decoration. Get-ServicingFinding returns a List[object], and Windows PowerShell 5.1
    # - which is what runs on the rescue VM - unrolls a returned single-element list into the bare
    # object it held. A PSCustomObject has no Count, so $findings.Count reads back as $null and both
    # "-gt 0" and "-eq 0" are false: the script reports the disk clean while simultaneously offering
    # to repair it. It only shows up when exactly one marker is found, which is why it survived every
    # earlier test disk. Every other collection in this file is wrapped the same way.
    $findings = @(Get-ServicingFinding -HasPendingXml $hasPendingXml -PendingXmlSize $pendingXmlSize -RegistryState $registryState -SetupExecuteState $setupExecute)

    $txr = Get-TxRState -WindowsPath $offline.WindowsPath

    # Log exhaustion is a second, independent reason the transaction logs need clearing. A servicing
    # transaction that hit ERROR_LOG_FULL stalls in exactly the same way as one that was interrupted,
    # but leaves none of the markers above behind, so without this check the operator would be told
    # nothing is wrong on a VM that is genuinely stuck.
    $logFull = Get-LogExhaustionEvidence -WindowsPath $offline.WindowsPath
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    if ($logFull.Found) {
        Log-Warning "Log exhaustion: ERROR_LOG_FULL was reported in $($logFull.Source): $($logFull.Line)" | Tee-Object -FilePath $logFile -Append
    }
    elseif ($logFull.LogsRead -gt 0) {
        Log-Info "No ERROR_LOG_FULL entry was found in the last $($script:CbsTailLine) lines of $($logFull.LogsRead) CBS log(s)." | Tee-Object -FilePath $logFile -Append
    }

    # Two separate authorisations, each tied to its own evidence. The servicing markers authorise the
    # DISM revert, the pending.xml rename and the CBS registry edits. Either the markers or log
    # exhaustion authorise clearing config\TxR. Clearing the logs on log exhaustion alone is the whole
    # point: that is the case where there is no marker to find.
    #
    # A leftover SetupExecute is deliberately not one of those markers. It is evidence that a hook was
    # left behind, not that a transaction is open: on the disk this was first measured on, pending.xml
    # was absent, every CBS key was clean and DISM reported nothing pending. Letting it authorise the
    # DISM revert, the hive backups and a wipe of 14 TxR transaction files would be changing things no
    # evidence says are broken. It is reported with the rest and authorises only its own repair.
    $servicingFindings = @($findings | Where-Object { $_.Kind -ne 'SetupExecute' })
    $clearTxR = ($servicingFindings.Count -gt 0 -or $logFull.Found) -and $txr.Actionable

    # Report the state before deciding anything.
    if ($findings.Count -gt 0) {
        # The headline has to match what was actually found. A leftover hook is not an open
        # transaction, and telling an operator servicing is mid-transaction when DISM, pending.xml
        # and the CBS keys are all clean sends them looking for a component store problem that is
        # not there.
        if ($servicingFindings.Count -gt 0) {
            Log-Info "Servicing is mid-transaction. $($findings.Count) marker(s) found:" | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info "No servicing transaction is open - pending.xml is absent, the CBS pending keys do not exist and the COMPONENTS transaction values are clear - but $($findings.Count) leftover marker(s) were found:" | Tee-Object -FilePath $logFile -Append
        }
        foreach ($finding in $findings) {
            Log-Info "  $($finding.Marker): $($finding.Detail)" | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Info 'No servicing pending markers are present: pending.xml is absent, the CBS pending keys do not exist, every recorded servicing session completed, the COMPONENTS transaction values are unset or zero, and Session Manager holds no leftover SetupExecute hook.' | Tee-Object -FilePath $logFile -Append
    }

    if ($setupExecute.Set -and $hasPendingXml) {
        Log-Info "Session Manager SetupExecute is set to '$($setupExecute.Entries -join ' | ')'. pending.xml is present, so the hook still has a manifest to read and is not a fault on its own. It is cleared alongside that manifest, because renaming pending.xml aside while leaving the hook set is what turns a servicing repair into a boot stopper." | Tee-Object -FilePath $logFile -Append
    }

    if ($txr.Present) {
        $why = if ($servicingFindings.Count -gt 0) { 'a servicing marker above was found' }
        elseif ($logFull.Found) { 'CBS reported log exhaustion' }
        else { 'neither a servicing marker nor log exhaustion was found, so they are left alone' }
        Log-Info "config\TxR holds $(@($txr.Files).Count) transaction file(s). These are normal on a healthy installation and are cleared only because $why." | Tee-Object -FilePath $logFile -Append
    }

    # Name the pending packages. Evidence only; nothing here is removed by this script.
    $dism = Get-DismPendingPackage -Drive $offline.WindowsDrive
    if ($dism.Succeeded) {
        if (@($dism.Packages).Count -gt 0) {
            Log-Info "DISM reports $(@($dism.Packages).Count) package(s) in the Pending state:" | Tee-Object -FilePath $logFile -Append
            foreach ($package in @($dism.Packages)) {
                Log-Info "  $package" | Tee-Object -FilePath $logFile -Append
            }
            Log-Info 'This script does not remove packages. If the VM still fails after this repair, win-get-patches and win-remove-patch are the pair that remove one by name.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info 'DISM reports no packages in the Pending state.' | Tee-Object -FilePath $logFile -Append
        }
    }
    else {
        Log-Info "DISM could not enumerate the packages on this image$(if ($dism.Message) { ": $($dism.Message)." } else { '.' }) That is common while a transaction is outstanding and does not stop the repair." | Tee-Object -FilePath $logFile -Append
    }

    $updateServices = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-WindowsUpdateServiceState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($doDisableWindowsUpdate) {
        Log-Info "Windows Update services on this disk: $((@($updateServices) | ForEach-Object { "$($_.Service)=Start $($_.Start)" }) -join ', ')" | Tee-Object -FilePath $logFile -Append
    }

    # ---------------------------------------------------------------------------------------------
    # Detect only
    # ---------------------------------------------------------------------------------------------
    if ($isDetectOnly) {
        if ($servicingFindings.Count -gt 0) {
            $clearable = @($servicingFindings | Where-Object { $_.Kind -ne 'Session' }).Count
            $sessions = @($servicingFindings | Where-Object { $_.Kind -eq 'Session' }).Count
            if ($clearable -gt 0) {
                Log-Output "$clearable servicing marker(s) would be cleared, and DISM would be asked to revert the pending actions." | Tee-Object -FilePath $logFile -Append
            }
            if ($sessions -gt 0) {
                Log-Output "$sessions incomplete servicing session(s) would be left in place for DISM to resolve. Their records are history this script does not rewrite." | Tee-Object -FilePath $logFile -Append
            }
        }
        if ($setupExecute.Set) {
            Log-Output "Session Manager $script:SetupExecuteValue would be cleared to the empty value a healthy installation carries, so smss.exe stops launching poqexec.exe at boot." | Tee-Object -FilePath $logFile -Append
        }
        if ($clearTxR) {
            Log-Output "$(@($txr.Files).Count) TxR transaction file(s) would be backed up and removed, and the removal verified before the run is called a success." | Tee-Object -FilePath $logFile -Append
        }
        if ($findings.Count -eq 0 -and -not $clearTxR -and -not $setupExecute.Set) {
            Log-Output 'Nothing would be changed. This disk shows no sign of an unfinished servicing transaction, so an "Undoing changes" boot loop on this VM has some other cause.' | Tee-Object -FilePath $logFile -Append
        }
        if ($doDisableWindowsUpdate) {
            Log-Output "$(@($updateServices).Count) Windows Update service(s) would be disabled." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output 'Re-run without detectOnly to apply.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($findings.Count -eq 0 -and -not $clearTxR -and -not $doDisableWindowsUpdate -and -not $setupExecute.Set) {
        Log-Output 'Nothing was changed. This disk shows no sign of an unfinished servicing transaction, so an "Undoing changes" boot loop on this VM has some other cause.' | Tee-Object -FilePath $logFile -Append
        Log-Output 'win-fix-inaccessible-boot-device covers a stop 0x7B, win-fix-registry-corruption covers a damaged hive, and win-sfc-sf-corruption covers damaged system files.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # ---------------------------------------------------------------------------------------------
    # Repair
    # ---------------------------------------------------------------------------------------------
    $manifest = [PSCustomObject]@{
        Script              = $scriptName
        Timestamp           = $scriptStartTime
        Services            = @()
        PendingXmlRenamedTo = ''
        TxRBackupFolder     = ''
        SetupExecute        = $null
    }
    $changes = 0
    $txrRemoved = 0
    $script:SystemHiveBackedUp = $false

    if ($servicingFindings.Count -gt 0) {
        $softwareBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SOFTWARE'
        Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append
        if ($hasComponentsHive) {
            $componentsBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'COMPONENTS'
            Log-Info "COMPONENTS hive backed up to $componentsBackup" | Tee-Object -FilePath $logFile -Append
        }

        # DISM first: a successful revert consumes pending.xml itself, and there is no point renaming
        # a file the supported tool is about to remove properly.
        Invoke-DismRevertPendingAction -Drive $offline.WindowsDrive | Out-Null
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if (Test-Path -LiteralPath $pendingXmlPath) {
            # WinSxS is owned by TrustedInstaller and denies writes even to SYSTEM, so the plain
            # rename is refused on a real image. Rename-OfflineProtectedFile retries it after taking
            # the parent folder, and puts the folder's owner and DACL back either way - measured on
            # Server 2022, where the unassisted rename failed every time.
            $renamedTo = "pending.xml.bak-$scriptStartTime"
            $rename = Rename-OfflineProtectedFile -Path $pendingXmlPath -NewName $renamedTo
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

            if ($rename.Renamed) {
                $manifest.PendingXmlRenamedTo = $rename.NewPath
                Log-Info "Renamed pending.xml to $renamedTo. $($rename.Reason) To undo: Rename-Item -LiteralPath '$($manifest.PendingXmlRenamedTo)' -NewName 'pending.xml'" | Tee-Object -FilePath $logFile -Append
                if ($rename.TookOwnership) {
                    Log-Info "WinSxS ownership was borrowed for the rename and its original owner and ACL have been put back: restored=$($rename.Restored)." | Tee-Object -FilePath $logFile -Append
                }
                $changes++
            }
            else {
                Log-Warning "pending.xml could not be renamed. $($rename.Reason) The DISM revert above is the supported way to consume it." | Tee-Object -FilePath $logFile -Append
                if ($rename.TookOwnership -and -not $rename.Restored) {
                    Log-Warning "WinSxS ownership was taken for the retry and could not be put back. Restore it with: icacls `"$(Split-Path -Path $pendingXmlPath -Parent)`" /setowner `"NT SERVICE\TrustedInstaller`"" | Tee-Object -FilePath $logFile -Append
                }
            }
        }
        else {
            Log-Info 'pending.xml is no longer present, so there was nothing to rename.' | Tee-Object -FilePath $logFile -Append
        }

        $script:RegistryChanges = 0
        Invoke-WithHive -Hive $servicingHive -WindowsPath $offline.WindowsPath -ScriptBlock {
            foreach ($key in $script:PendingCbsKey) {
                $path = Join-Path $script:CbsSoftwareKey $key
                if (-not (Test-Path $path)) { continue }

                # The CBS pending keys are TrustedInstaller's and deny delete to everyone else, so
                # the plain Remove-Item is refused and - with SilentlyContinue - refused silently.
                # Invoke-OfflineProtectedKeyRemoval verifies the plain attempt, takes the subtree
                # only if it is still there, and puts every descriptor back if the delete still
                # fails, so a refusal never leaves a key owned by SYSTEM.
                $outcome = Invoke-OfflineProtectedKeyRemoval -Path $path -Label "CBS\$key"
                if ($outcome.Removed) {
                    Add-OfflineRepairLog -Level Info -Message "Removed CBS\$key. $($outcome.Reason)"
                    $script:RegistryChanges++
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "CBS\$key could not be removed. $($outcome.Reason)"
                }
            }

            foreach ($name in $script:PendingComponentValue) {
                $value = (Get-ItemProperty $script:ComponentsKey -ErrorAction SilentlyContinue).$name
                if (-not (Test-PendingComponentValue -Value $value)) { continue }

                # The value is read back rather than assumed either way: these keys carry their own
                # ACL, and the removal reports nothing when it is denied. Unlike the CBS keys the
                # COMPONENTS key survives, so its descriptor is always put back.
                $outcome = Invoke-OfflineProtectedValueRemoval -Path $script:ComponentsKey -Name $name -StillSet {
                    param($current) Test-PendingComponentValue -Value $current
                }
                if ($outcome.Removed) {
                    Add-OfflineRepairLog -Level Info -Message "Cleared COMPONENTS\$name (was '$value'). $($outcome.Reason)"
                    $script:RegistryChanges++
                }
                else {
                    Add-OfflineRepairLog -Level Warning -Message "COMPONENTS\$name could not be cleared. $($outcome.Reason)"
                }
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        $changes += [int]$script:RegistryChanges
    }

    # ---------------------------------------------------------------------------------------------
    # Session Manager SetupExecute
    #
    # Outside the findings block on purpose. The hook has to be cleared in both of the cases that
    # reach here, and only one of them is a finding:
    #   1. pending.xml was already gone. The hook is stale, it is the finding, and it is the whole
    #      reason the VM will not boot.
    #   2. pending.xml was present and has just been renamed aside above. The hook was legitimate a
    #      moment ago and is stale now, because this run is what removed the file it reads. Leaving
    #      it set would hand the VM back with a boot stopper this script created.
    #
    # It runs after the rename for that reason, so case 2 is decided on what the disk looks like
    # when the repair is finished rather than when it started.
    # ---------------------------------------------------------------------------------------------
    if ($setupExecute.Set) {
        $script:SetupExecuteCleared = $false
        $original = @($setupExecute.Entries)

        if (-not $script:SystemHiveBackedUp) {
            $systemBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SYSTEM'
            Log-Info "SYSTEM hive backed up to $systemBackup" | Tee-Object -FilePath $logFile -Append
            $script:SystemHiveBackedUp = $true
        }

        Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $state = Get-SetupExecuteState
            if (-not $state.KeyPresent) {
                Add-OfflineRepairLog -Level Warning -Message "$script:SessionManagerSubKey is not present on this disk, so $script:SetupExecuteValue could not be cleared."
                return
            }
            if (-not $state.Set) {
                Add-OfflineRepairLog -Level Info -Message "$script:SetupExecuteValue is already empty, so there was nothing to clear."
                return
            }

            $was = ($state.Entries -join ' | ')

            # Set to an empty REG_MULTI_SZ rather than deleting the value. That is what a healthy
            # installation carries - measured on a freshly deployed Server 2022 image - and Session
            # Manager reads the value's contents, not its presence.
            Set-ItemProperty -Path $state.Path -Name $script:SetupExecuteValue -Value ([string[]]@()) -Type MultiString -Force -ErrorAction Stop

            # Read back rather than assume. This value sits in the SYSTEM hive under an ACL that can
            # refuse a write without raising, and an operator told the hook was cleared who then
            # reboots into the same black screen has been actively misled.
            $after = Get-SetupExecuteState
            if ($after.Set) {
                Add-OfflineRepairLog -Level Error -Message "$script:SetupExecuteValue still reads back as '$($after.Entries -join ' | ')' after the write. It was NOT cleared."
            }
            else {
                $script:SetupExecuteCleared = $true
                Add-OfflineRepairLog -Level Info -Message "Cleared $script:SessionManagerSubKey\$script:SetupExecuteValue (was '$was'), verified empty on read-back. To undo: reg add `"HKLM\SYSTEM\ControlSet001\$script:SessionManagerSubKey`" /v $script:SetupExecuteValue /t REG_MULTI_SZ /d `"$was`" /f"
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if ($script:SetupExecuteCleared) {
            $manifest.SetupExecute = $original
            $changes++
        }
    }

    # ---------------------------------------------------------------------------------------------
    # Transaction logs
    #
    # Deliberately after the DISM revert rather than before it. The CLFS logs under config\TxR hold
    # the uncommitted state of the transaction, which is what DISM reads to work out what to undo.
    # Deleting them first would take that away from the supported tool and leave the revert with
    # nothing to act on. Clearing them afterwards removes what the revert could not consume.
    #
    # Removal runs through Use-OfflineFileRemoval, so every file is hash-verified into a backup before
    # anything is deleted, the folder is re-examined afterwards against six checks, and a failure
    # restores everything it removed. A raw copy-then-delete loop cannot tell the difference between a
    # clean removal and one that silently took a file it should not have.
    # ---------------------------------------------------------------------------------------------
    if ($clearTxR) {
        $backupRoot = Join-Path $offline.WindowsPath "Temp\$scriptName\$scriptStartTime"
        $outcome = Invoke-OfflineRemovalPlan -Plan $txr -BackupRoot $backupRoot
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if ($outcome.Success) {
            $manifest.TxRBackupFolder = $outcome.BackupPath
            $txrRemoved = @($outcome.Removed).Count
            Log-Info "Removed $txrRemoved TxR transaction file(s) and verified the removal. Backed up to $($outcome.BackupPath)." | Tee-Object -FilePath $logFile -Append
            $changes += $txrRemoved
        }
        else {
            # The helper has already put back whatever it removed, so the disk is as it was found.
            # Report it rather than continue quietly: an operator who believes the logs were cleared
            # and reboots into the same loop has been actively misled.
            Log-Error "The transaction logs could not be cleared safely: $($outcome.Reason)" | Tee-Object -FilePath $logFile -Append
            foreach ($failure in @($outcome.Verification.Failure)) {
                Log-Error "  $failure" | Tee-Object -FilePath $logFile -Append
            }
            Log-Error 'Everything that was removed has been restored, so config\TxR is as it was found. No further change was made.' | Tee-Object -FilePath $logFile -Append
            Write-RevertManifest -Path $manifestPath -Manifest $manifest | Out-Null
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_ERROR
        }
    }

    # ---------------------------------------------------------------------------------------------
    # Windows Update services, only when asked for by name
    # ---------------------------------------------------------------------------------------------
    if ($doDisableWindowsUpdate) {
        Log-Warning 'Disabling Windows Update is a workaround, not a repair. The VM stays unpatched until the services are turned back on.' | Tee-Object -FilePath $logFile -Append

        $recorded = [System.Collections.Generic.List[object]]::new()
        foreach ($service in @($updateServices)) {
            if ($service.Start -eq 4) {
                Log-Info "  $($service.Service) is already disabled." | Tee-Object -FilePath $logFile -Append
                continue
            }
            [void]$recorded.Add([PSCustomObject]@{ Service = $service.Service; OriginalStart = [int]$service.Start })
        }

        if ($recorded.Count -gt 0) {
            if (-not $script:SystemHiveBackedUp) {
                $systemBackup = Backup-OfflineHiveFile -WindowsPath $offline.WindowsPath -Hive 'SYSTEM'
                Log-Info "SYSTEM hive backed up to $systemBackup" | Tee-Object -FilePath $logFile -Append
                $script:SystemHiveBackedUp = $true
            }

            $script:ServiceChanges = 0
            Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
                $root = Get-OfflineSystemRootPath
                foreach ($entry in $recorded) {
                    $path = "$root\Services\$($entry.Service)"
                    if (-not (Test-Path $path)) { continue }
                    Set-ItemProperty -Path $path -Name Start -Value 4 -Type DWord -Force
                    Add-OfflineRepairLog -Level Info -Message "reg add `"$($path -replace '^HKLM:\\BROKENSYSTEM', 'HKLM\SYSTEM')`" /v Start /t REG_DWORD /d 4 /f   # was $($entry.OriginalStart)"
                    $script:ServiceChanges++
                }
            }
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

            $manifest.Services = @($recorded)
            $changes += [int]$script:ServiceChanges
            Log-Info "Disabled $([int]$script:ServiceChanges) Windows Update service(s)." | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Info 'Every Windows Update service on this disk is already disabled.' | Tee-Object -FilePath $logFile -Append
        }
    }

    # ---------------------------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------------------------
    if ($changes -eq 0) {
        Log-Output 'Nothing was changed.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($manifest.PendingXmlRenamedTo -or $manifest.TxRBackupFolder -or @($manifest.Services).Count -gt 0 -or @($manifest.SetupExecute).Count -gt 0) {
        Write-RevertManifest -Path $manifestPath -Manifest $manifest
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    # Re-read, so the summary reports what the disk now says rather than what was intended.
    $after = Invoke-WithHive -Hive $servicingHive -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-ServicingRegistryState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $remaining = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $pendingXmlPath) { [void]$remaining.Add('WinSxS\pending.xml') }
    foreach ($key in $script:PendingCbsKey) {
        if ($after.Cbs[$key].Present) { [void]$remaining.Add("CBS\$key") }
    }
    foreach ($name in $script:PendingComponentValue) {
        if (Test-PendingComponentValue -Value $after.ComponentValues[$name]) { [void]$remaining.Add("COMPONENTS\$name") }
    }

    # The hook is re-read for the same reason as the markers above: the SYSTEM hive carries its own
    # ACL, Set-ItemProperty can be refused, and a summary that reports it cleared on the strength of
    # having attempted the write would send the operator back into the same black screen.
    $setupExecuteAfter = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        return (Get-SetupExecuteState)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    if ($setupExecuteAfter.Set) { [void]$remaining.Add("$script:SessionManagerSubKey\$script:SetupExecuteValue") }

    # Report what was actually done rather than infer it from one condition. Three things can change
    # this disk independently - the servicing markers, the transaction logs, and the Windows Update
    # services - and any combination of them is possible, because the markers and log exhaustion are
    # separate authorisations. Keying the summary on the markers alone produced "No stuck servicing
    # transaction was found, so nothing was cleared. 7 change(s) ... all of them to the Windows
    # Update services" on a run that had removed 7 transaction logs and touched no service at all.
    #
    # Finding a marker is not the same as clearing it. WinSxS is owned by TrustedInstaller and the
    # CBS keys carry their own ACL, so the rename and the deletes can all be refused while the run
    # still succeeds at everything else. Claim the transaction only when the disk agrees it is gone.
    $serviceChanges = @($manifest.Services).Count
    $setupExecuteChanges = if (@($manifest.SetupExecute).Count -gt 0) { 1 } else { 0 }
    $markerWork = $changes - $txrRemoved - $serviceChanges - $setupExecuteChanges

    $did = [System.Collections.Generic.List[string]]::new()
    if ($findings.Count -gt 0 -and $servicingFindings.Count -gt 0) {
        if ($remaining.Count -eq 0) {
            # Either the edits landed, or the DISM revert consumed pending.xml on its own - that one
            # leaves nothing for this script to count, so trust the re-read rather than the counter.
            [void]$did.Add('cleared the stuck servicing transaction')
        }
        elseif ($markerWork -gt 0) {
            [void]$did.Add('cleared part of the stuck servicing transaction')
        }
    }
    if ($setupExecuteChanges -gt 0) { [void]$did.Add("cleared the leftover Session Manager $script:SetupExecuteValue hook") }
    if ($txrRemoved -gt 0) { [void]$did.Add("removed $txrRemoved transaction log file(s) from config\TxR") }
    if ($serviceChanges -gt 0) { [void]$did.Add("disabled $serviceChanges Windows Update service(s)") }

    if ($did.Count -gt 0) {
        $summary = $did -join ', '
        Log-Output "$($summary.Substring(0, 1).ToUpper())$($summary.Substring(1)): $changes change(s) on $($offline.WindowsPath)." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output "$changes change(s) on $($offline.WindowsPath)." | Tee-Object -FilePath $logFile -Append
    }

    if ($remaining.Count -gt 0) {
        # Log-Output, not Log-Warning: only Log-Output reaches the summary az prints. As a warning
        # the one line that says the repair did not work was invisible to the operator, who saw
        # only the success lines above it.
        Log-Output "These markers are still present after the repair: $($remaining -join ', '). They are owned by TrustedInstaller and this script could not take them. Re-run this script, and if they persist the component store itself is damaged - win-sfc-sf-corruption is the next step." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output 'No servicing pending markers remain on this disk.' | Tee-Object -FilePath $logFile -Append
    }

    if (@($manifest.Services).Count -gt 0) {
        Log-Output 'Windows Update is disabled on this disk. Turn it back on from inside the VM once it boots:' | Tee-Object -FilePath $logFile -Append
        foreach ($entry in @($manifest.Services)) {
            Log-Output "  sc.exe config $($entry.Service) start= $(switch ([int]$entry.OriginalStart) { 2 { 'auto' } 3 { 'demand' } 0 { 'boot' } 1 { 'system' } default { 'demand' } })" | Tee-Object -FilePath $logFile -Append
        }
    }

    Log-Output "Re-run with -revert true to undo this, or run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
