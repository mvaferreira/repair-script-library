#########################################################################################################
#
# .SYNOPSIS
#   Repairs the logon subsystem of an offline Windows disk: Winlogon, Session Manager, the profile
#   list and the setup-mode command.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". Every value the
#   logon path depends on is checked against the binary it actually points at, only the entries that
#   are provably broken are changed, and the result is re-checked. A healthy disk produces no writes.
#
#   Detection, in boot order:
#     1. Session Manager BootExecute. Smss.exe runs these native images before Win32 starts. An
#        entry whose binary is missing hangs the VM at a black screen with no error, because there
#        is no subsystem loaded yet to report one. The Windows default "autocheck autochk *" is
#        always kept, and its absence is itself reported.
#     2. Session Manager SetupExecute. Same execution context, normally empty.
#     3. Setup mode. A non-zero SYSTEM\Setup\SetupType makes the session manager run
#        SYSTEM\Setup\CmdLine before the logon UI appears. A dangling command there stalls the boot,
#        and it is a common leftover from an earlier repair attempt, because that key is the hook
#        password-reset and user-rights tools use.
#     4. Winlogon Shell and Userinit. Both are comma separated lists of commands. An entry whose
#        binary is missing produces 0xC000021A, because Winlogon treats the failure to start
#        userinit.exe as a critical system process failure.
#     5. ProfileList. A SID carrying a .bak twin, or the temporary-profile bit in State, is the
#        "We can't sign in to your account" / "User Profile Service failed the logon" pattern.
#
#   Repair changes only what detection found. Dangling list entries are dropped individually, the
#   surviving entries are preserved in order, and the Windows default is written back only when
#   removing the broken entries would otherwise leave the value empty. A customised shell or an
#   extra Userinit command whose binary is present is reported and deliberately left alone.
#
# .RESOLVES
#   Stop error 0xC000021A STATUS_SYSTEM_PROCESS_TERMINATED, a black screen before the logon UI,
#   "The User Profile Service service failed the sign-in", "We can't sign in to your account" and
#   logons that land in a temporary profile, and a VM that hangs on "Please wait" or re-enters setup
#   on every boot.
#
# .PARAMETER detectOnly
#   "true" to report what would be changed and make no writes at all. Defaults to "false".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-logon-subsystem --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-logon-subsystem --parameters detectOnly=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The Windows default for Userinit is written using the guest's own SystemRoot, read from
#   SOFTWARE\Microsoft\Windows NT\CurrentVersion, rather than a hardcoded C:\Windows. A guest whose
#   Windows directory is not on C: would otherwise be given a value that cannot resolve at boot.
#
#   A hive that will not load at all is a different problem and belongs to
#   win-fix-registry-corruption. This script needs SYSTEM and SOFTWARE to mount before it can read
#   anything, so run that one first if either hive is damaged.
#
#   ExcludeFromKnownDlls entries are reported and never removed. Legitimate application compatibility
#   shims use them, so removing them blindly can break working software, but they are also a DLL
#   preloading vector and worth an operator's attention.
#
#   A ProfileImagePath pointing at a directory that no longer exists is reported and not repaired.
#   Deleting the profile entry would let the user log on with a brand new profile and silently
#   abandon the old one, which is a data loss decision an operator has to make deliberately.
#
#   Autoruns under Run, RunOnce and the Startup folders are deliberately out of scope. They are
#   started by userinit.exe and the shell after a successful logon, so they cannot stop a boot, and a
#   VM affected by one is still reachable online where it can be fixed without a disk swap.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
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

# The only BootExecute entry Windows ships with. Restored when removing dangling entries would
# otherwise leave the value empty, because an empty BootExecute means autochk never runs and a dirty
# volume is then mounted without being checked.
$script:DefaultBootExecute = 'autocheck autochk *'

# Winlogon values are comma separated lists. Each list has one binary that must be present for the
# logon to complete; everything else in the list is optional and is preserved when it resolves.
$script:WinlogonValueSpec = @(
    [PSCustomObject]@{
        Name          = 'Userinit'
        Required      = 'userinit.exe'
        TrailingComma = $true
        Purpose       = 'starts the user session, applies the profile and launches the shell'
    }
    [PSCustomObject]@{
        Name          = 'Shell'
        Required      = 'explorer.exe'
        TrailingComma = $false
        Purpose       = 'the desktop shell userinit.exe launches'
    }
)

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][ValidateSet('SYSTEM', 'SOFTWARE')][string]$Hive,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Hive       = $Hive
        Repairable = $Repairable
        Repaired   = $false
        Data       = $Data
    }
}

function Resolve-LogonCommand {
    <#
    .SYNOPSIS
        Resolves one command from a logon value to a file on the offline disk.

    .DESCRIPTION
        The values this script reads hold commands, not plain paths: they can carry arguments, be
        quoted, use the guest's drive letter, or name a bare executable that the loader finds on the
        system path. Only the program part is resolved, and it is looked for in System32 and in the
        Windows directory, which is where every binary these values legitimately reference lives.

        Existence is decided against the offline disk, so a value naming a binary the guest no longer
        has is correctly reported as dangling even though the string itself looks valid.

    .OUTPUTS
        PSCustomObject with Command, Binary, Resolved, Exists and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Command,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $result = [PSCustomObject]@{
        Command  = $Command
        Binary   = $null
        Resolved = $null
        Exists   = $false
        Reason   = $null
    }

    $text = "$Command".Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        $result.Reason = 'the entry is empty'
        return $result
    }

    # A quoted program keeps its spaces; an unquoted one ends at the first space.
    if ($text.StartsWith('"')) {
        $close = $text.IndexOf('"', 1)
        $binary = if ($close -gt 1) { $text.Substring(1, $close - 1) } else { $text.Trim('"') }
    }
    else {
        $binary = ($text -split '\s+', 2)[0]
    }

    $binary = $binary.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($binary)) {
        $result.Reason = 'no program name could be read from the entry'
        return $result
    }
    $result.Binary = $binary

    # A wildcard is an argument to the preceding program, never a program itself.
    if ($binary -eq '*') {
        $result.Reason = 'the entry is an argument, not a program'
        return $result
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($binary -match '[\\/]' -or $binary -match '^[A-Za-z]:' -or $binary -match '^%') {
        [void]$candidates.Add((Resolve-OfflineImagePath -ImagePath $binary -WindowsDrive $WindowsDrive))
    }
    else {
        $names = if ([System.IO.Path]::GetExtension($binary)) { @($binary) } else { @("$binary.exe", "$binary.com") }
        foreach ($name in $names) {
            [void]$candidates.Add((Join-OfflinePath -Root $WindowsPath -ChildPath "System32\$name"))
            [void]$candidates.Add((Join-OfflinePath -Root $WindowsPath -ChildPath $name))
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-OfflinePath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
            if ($null -ne $item -and -not $item.PSIsContainer -and $item.Length -gt 0) {
                $result.Resolved = $candidate
                $result.Exists = $true
                return $result
            }
            if ($null -ne $item -and $item.Length -eq 0) {
                $result.Resolved = $candidate
                $result.Reason = "the binary is 0 bytes: $candidate"
                return $result
            }
        }
    }

    $result.Resolved = $candidates[0]
    $result.Reason = "the binary was not found on the offline disk (looked for $($candidates -join ', '))"
    return $result
}

function Get-GuestSystemRoot {
    <#
    .SYNOPSIS
        Returns the guest's own view of its Windows directory, for example "C:\Windows".

    .DESCRIPTION
        Needed because a repaired value is read by the guest at its next boot, where the offline
        drive letter this rescue VM sees is meaningless. Falls back to C:\Windows only when the
        value is absent, which is the same assumption Windows setup makes.
    #>
    $current = Get-ItemProperty 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    foreach ($value in @($current.SystemRoot, $current.PathName)) {
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value -match '^[A-Za-z]:\\') { return $value.TrimEnd('\') }
    }
    return 'C:\Windows'
}

function Get-WinlogonState {
    <#
    .SYNOPSIS
        Reads Winlogon Shell and Userinit and resolves every command in each of them.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $keyPath = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $state = [PSCustomObject]@{
        KeyPath        = $keyPath
        Available      = $false
        Reason         = $null
        GuestSystemRoot = Get-GuestSystemRoot
        Values         = @()
    }

    if (-not (Test-Path $keyPath)) {
        $state.Reason = "the Winlogon key is not present at $keyPath"
        return $state
    }
    $state.Available = $true

    $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
    $values = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($spec in $script:WinlogonValueSpec) {
        $raw = $props.$($spec.Name)
        $entries = @()
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $entries = @("$raw" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        $resolutions = @($entries | ForEach-Object {
                Resolve-LogonCommand -Command $_ -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
            })

        [void]$values.Add([PSCustomObject]@{
                Name          = $spec.Name
                Purpose       = $spec.Purpose
                Required      = $spec.Required
                TrailingComma = $spec.TrailingComma
                Present       = ($null -ne $raw)
                Raw           = "$raw"
                Resolutions   = $resolutions
                Dangling      = @($resolutions | Where-Object { -not $_.Exists })
                Good          = @($resolutions | Where-Object { $_.Exists })
                HasRequired   = (@($resolutions | Where-Object { $_.Exists -and (Split-Path -Path $_.Resolved -Leaf) -ieq $spec.Required }).Count -gt 0)
                Default       = if ($spec.Name -eq 'Userinit') { "$($state.GuestSystemRoot)\system32\userinit.exe" } else { 'explorer.exe' }
            })
    }

    $state.Values = @($values)
    return $state
}

function Get-SessionManagerState {
    <#
    .SYNOPSIS
        Reads the Session Manager lists that run before Win32 starts and resolves each entry.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $keyPath = "$SystemRoot\Control\Session Manager"
    $state = [PSCustomObject]@{
        KeyPath              = $keyPath
        Available            = $false
        Reason               = $null
        BootExecute          = @()
        BootExecutePresent   = $false
        SetupExecute         = @()
        ExcludeFromKnownDlls = @()
    }

    if (-not (Test-Path $keyPath)) {
        $state.Reason = "the Session Manager key is not present at $keyPath"
        return $state
    }
    $state.Available = $true

    $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
    $state.BootExecutePresent = ($null -ne $props.BootExecute)

    foreach ($valueName in @('BootExecute', 'SetupExecute')) {
        $entries = @($props.$valueName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
        $resolved = foreach ($entry in $entries) {
            # "autocheck autochk *" is the default. Its program is the second token, because
            # autocheck is the native subsystem prefix rather than an image name.
            $isDefault = ($entry -match '^autocheck\s+autochk\b')
            $program = if ($entry -match '^autocheck\s+(\S+)') { $Matches[1] } else { $entry }

            $resolution = Resolve-LogonCommand -Command $program -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
            [PSCustomObject]@{
                Entry      = $entry
                IsDefault  = $isDefault
                Resolution = $resolution
                Exists     = $resolution.Exists
                Vendor     = if ($resolution.Exists) { (Get-Item -LiteralPath $resolution.Resolved -ErrorAction SilentlyContinue).VersionInfo.CompanyName } else { $null }
            }
        }
        $state.$valueName = @($resolved)
    }

    $state.ExcludeFromKnownDlls = @($props.ExcludeFromKnownDlls | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    return $state
}

function Get-SetupModeState {
    <#
    .SYNOPSIS
        Reads the setup-mode hook that runs before the logon UI appears.

    .DESCRIPTION
        A non-zero SetupType makes the session manager run CmdLine in a SYSTEM console session
        before anyone can log on. It is the hook that offline password-reset and user-rights tools
        use, so a leftover entry from an earlier repair attempt is a realistic cause of a VM that
        never reaches the logon screen.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $keyPath = 'HKLM:\BROKENSYSTEM\Setup'
    $state = [PSCustomObject]@{
        KeyPath             = $keyPath
        Available           = $false
        SetupType           = 0
        CmdLine             = ''
        SystemSetupInProgress = 0
        Resolution          = $null
    }

    if (-not (Test-Path $keyPath)) { return $state }
    $state.Available = $true

    $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
    if ($null -ne $props.SetupType) { $state.SetupType = [int]$props.SetupType }
    if ($null -ne $props.SystemSetupInProgress) { $state.SystemSetupInProgress = [int]$props.SystemSetupInProgress }
    $state.CmdLine = "$($props.CmdLine)".Trim()

    if (-not [string]::IsNullOrWhiteSpace($state.CmdLine)) {
        $state.Resolution = Resolve-LogonCommand -Command $state.CmdLine -WindowsPath $WindowsPath -WindowsDrive $WindowsDrive
    }

    return $state
}

function Get-ProfileListState {
    <#
    .SYNOPSIS
        Reads the machine profile list and flags the entries that stop a user logging on.

    .DESCRIPTION
        Three separate conditions are reported. A SID with a .bak twin means the profile service
        failed to load the real profile and created a replacement, which is what produces "We can't
        sign in to your account". The temporary-profile bit in State is the same failure recorded on
        a single key. A ProfileImagePath pointing at a directory that is gone is reported only,
        because choosing to abandon a profile is an operator's decision.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $basePath = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $state = [PSCustomObject]@{
        KeyPath   = $basePath
        Available = $false
        Reason    = $null
        Profiles  = @()
    }

    if (-not (Test-Path $basePath)) {
        $state.Reason = "the ProfileList key is not present at $basePath"
        return $state
    }
    $state.Available = $true

    $profiles = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($key in @(Get-ChildItem $basePath -ErrorAction SilentlyContinue)) {
        $name = $key.PSChildName

        # Only real user accounts. Built-in service SIDs never carry these faults and their
        # profiles are recreated by Windows, so acting on them adds risk without benefit.
        if ($name -notmatch '^S-1-5-21-') { continue }
        # Handle each SID once, from its primary key.
        if ($name -match '\.(bak|old)$') { continue }

        $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
        $bakPath = "$basePath\$name.bak"
        $hasBak = Test-Path $bakPath
        $bakProps = if ($hasBak) { Get-ItemProperty $bakPath -ErrorAction SilentlyContinue } else { $null }

        # Resolve-OfflineImagePath is for binaries and trims its result at the file extension, so a
        # profile directory is translated here instead: swap the guest's drive letter for the one
        # this rescue VM mounted the disk on.
        $guestPath = "$($props.ProfileImagePath)"
        $offlinePath = $null
        if ($guestPath -match '^[A-Za-z]:\\(.*)$') {
            $offlinePath = Join-OfflinePath -Root $WindowsDrive -ChildPath $Matches[1]
        }

        $profileState = if ($null -ne $props.State) { [int]$props.State } else { 0 }
        [void]$profiles.Add([PSCustomObject]@{
                Sid                = $name
                KeyPath            = "$basePath\$name"
                BakKeyPath         = $bakPath
                HasBak             = $hasBak
                State              = $profileState
                IsTemporary        = (($profileState -band 0x8) -ne 0)
                RefCount           = $props.RefCount
                GuestProfilePath   = $guestPath
                OfflineProfilePath = $offlinePath
                ProfileExists      = ($null -ne $offlinePath -and (Test-OfflinePath $offlinePath))
                BakProfilePath     = if ($null -ne $bakProps) { "$($bakProps.ProfileImagePath)" } else { $null }
            })
    }

    $state.Profiles = @($profiles)
    return $state
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Builds the findings list from evidence only.

    .DESCRIPTION
        A value being non-default is never a finding on its own. A value only becomes one when the
        binary it names is missing from the offline disk, or when the value that has to be there to
        reach a desktop is not there at all. That keeps a customised but working configuration
        untouched, which matters because a blanket reset of these keys is itself a way to break a VM.
    #>
    param(
        [Parameter(Mandatory = $true)]$Winlogon,
        [Parameter(Mandatory = $true)]$SessionManager,
        [Parameter(Mandatory = $true)]$SetupMode,
        [Parameter(Mandatory = $true)]$ProfileList
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -- Session Manager, runs first at boot ------------------------------------------------------
    if ($SessionManager.Available) {
        foreach ($valueName in @('BootExecute', 'SetupExecute')) {
            $entries = @($SessionManager.$valueName)
            $dangling = @($entries | Where-Object { -not $_.Exists })
            if ($dangling.Count -eq 0) { continue }

            $keep = @($entries | Where-Object { $_.Exists } | ForEach-Object { $_.Entry })
            foreach ($bad in $dangling) {
                [void]$findings.Add((New-Finding -Cause "${valueName}Dangling" -Item $bad.Entry -Hive 'SYSTEM' `
                            -Message "Session Manager $valueName runs '$($bad.Entry)' before Win32 starts, but $($bad.Resolution.Reason). Smss.exe waits on an image it cannot start, so the VM stops at a black screen with no error text. The entry will be removed and the remaining $($keep.Count) entry(s) kept." `
                            -Data ([PSCustomObject]@{ ValueName = $valueName; Keep = $keep; Remove = $bad.Entry })))
            }
        }

        $bootEntries = @($SessionManager.BootExecute)
        $hasDefault = (@($bootEntries | Where-Object { $_.IsDefault -and $_.Exists }).Count -gt 0)

        # When every BootExecute entry is dangling, removing them would leave the value empty, so the
        # dangling repair writes the default back itself. Raising a separate finding here as well
        # would describe one write as two, and the second would find nothing left to do.
        $bootSurvives = (@($bootEntries | Where-Object { $_.Exists }).Count -gt 0)
        $defaultRestoredByDanglingRepair = ((@($bootEntries | Where-Object { -not $_.Exists }).Count -gt 0) -and -not $bootSurvives)

        if (-not $hasDefault -and $SessionManager.BootExecutePresent -and -not $defaultRestoredByDanglingRepair) {
            [void]$findings.Add((New-Finding -Cause 'BootExecuteDefaultMissing' -Item 'BootExecute' -Hive 'SYSTEM' `
                        -Message "Session Manager BootExecute does not run the Windows default '$($script:DefaultBootExecute)', so autochk never runs and a volume left dirty by the failure is mounted without being checked. The default will be restored alongside any entry that resolves." `
                        -Data ([PSCustomObject]@{ ValueName = 'BootExecute'; Keep = @($bootEntries | Where-Object { $_.Exists } | ForEach-Object { $_.Entry }) })))
        }

        foreach ($dll in @($SessionManager.ExcludeFromKnownDlls)) {
            [void]$findings.Add((New-Finding -Cause 'ExcludedKnownDll' -Item $dll -Hive 'SYSTEM' -Repairable $false `
                        -Message "'$dll' is listed in ExcludeFromKnownDlls, so the loader takes it from the application directory instead of the KnownDlls section. Application compatibility shims use this legitimately, so it is reported rather than removed, but it is also how a DLL is preloaded ahead of the system copy and is worth confirming."))
        }
    }
    else {
        [void]$findings.Add((New-Finding -Cause 'SessionManagerMissing' -Item 'Session Manager' -Hive 'SYSTEM' -Repairable $false `
                    -Message "$($SessionManager.Reason). Without it the session manager has no configuration to start from, which is registry damage rather than a logon fault: run win-fix-registry-corruption against this disk."))
    }

    # -- Setup mode, runs before the logon UI -----------------------------------------------------
    if ($SetupMode.Available -and $SetupMode.SetupType -ne 0) {
        if ([string]::IsNullOrWhiteSpace($SetupMode.CmdLine)) {
            [void]$findings.Add((New-Finding -Cause 'SetupTypeWithoutCommand' -Item 'SetupType' -Hive 'SYSTEM' `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) but CmdLine is empty, so the VM enters setup mode at boot and has nothing to run there. SetupType will be set back to 0." `
                        -Data $SetupMode))
        }
        elseif ($null -ne $SetupMode.Resolution -and -not $SetupMode.Resolution.Exists) {
            [void]$findings.Add((New-Finding -Cause 'SetupModeDanglingCommand' -Item 'CmdLine' -Hive 'SYSTEM' `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) and CmdLine runs '$($SetupMode.CmdLine)' before the logon UI, but $($SetupMode.Resolution.Reason). The boot stalls in setup mode waiting on a command that cannot start. This is the hook offline password and user-rights tools use, so it is most likely a leftover from an earlier repair. SetupType will be set back to 0 and CmdLine cleared." `
                        -Data $SetupMode))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'SetupModeActive' -Item 'CmdLine' -Hive 'SYSTEM' -Repairable $false `
                        -Message "SYSTEM\Setup\SetupType is $($SetupMode.SetupType) and CmdLine runs '$($SetupMode.CmdLine)' before the logon UI. The command exists on the disk, so this may be a servicing or provisioning step that is genuinely meant to run and it has been left alone. If the VM hangs before the logon screen, clear SetupType and CmdLine by hand." `
                        -Data $SetupMode))
        }
    }

    # -- Winlogon ---------------------------------------------------------------------------------
    if ($Winlogon.Available) {
        foreach ($value in @($Winlogon.Values)) {
            if (-not $value.Present -or $value.Resolutions.Count -eq 0) {
                [void]$findings.Add((New-Finding -Cause 'WinlogonValueMissing' -Item $value.Name -Hive 'SOFTWARE' `
                            -Message "Winlogon has no usable $($value.Name) value, which $($value.Purpose). Winlogon treats that as a critical system process failure and bugchecks with 0xC000021A. It will be set to the Windows default '$($value.Default)'." `
                            -Data $value))
                continue
            }

            # One finding per value, not per broken entry. The repair rewrites the whole value in a
            # single write, so splitting this into several findings would report repairs that never
            # happened: the first write already corrects everything the others would have asked for.
            if ($value.Dangling.Count -gt 0 -or -not $value.HasRequired) {
                $reasons = [System.Collections.Generic.List[string]]::new()
                foreach ($bad in @($value.Dangling)) {
                    [void]$reasons.Add("it runs '$($bad.Command)', but $($bad.Reason)")
                }
                if (-not $value.HasRequired) {
                    [void]$reasons.Add("it never runs $($value.Required), which $($value.Purpose)")
                }

                $plan = if ($value.Dangling.Count -gt 0) { "The $($value.Dangling.Count) broken entry(s) will be removed and the $($value.Good.Count) working one(s) kept" } else { 'The working entries will be kept' }
                if (-not $value.HasRequired) { $plan += ", and '$($value.Default)' added ahead of them" }

                [void]$findings.Add((New-Finding -Cause 'WinlogonValueBroken' -Item $value.Name -Hive 'SOFTWARE' `
                            -Message "Winlogon $($value.Name) is set to '$($value.Raw)' and cannot complete a logon: $($reasons -join '; '). Winlogon treats this as a critical system process failure and bugchecks with 0xC000021A. $plan." `
                            -Data $value))
            }
            elseif ($value.Good.Count -gt 1) {
                $extra = @($value.Good | Where-Object { (Split-Path -Path $_.Resolved -Leaf) -ine $value.Required } | ForEach-Object { $_.Command })
                if ($extra.Count -gt 0) {
                    [void]$findings.Add((New-Finding -Cause 'WinlogonExtraCommand' -Item $value.Name -Hive 'SOFTWARE' -Repairable $false `
                                -Message "Winlogon $($value.Name) also runs $($extra -join ', ') at every logon. Each one exists on the disk so none was removed, but anything started from this value runs before the desktop appears and is worth confirming as expected." `
                                -Data $value))
                }
            }
        }
    }
    else {
        [void]$findings.Add((New-Finding -Cause 'WinlogonKeyMissing' -Item 'Winlogon' -Hive 'SOFTWARE' -Repairable $false `
                    -Message "$($Winlogon.Reason). The key itself being gone is registry damage rather than a logon fault: run win-fix-registry-corruption against this disk."))
    }

    # -- Profile list ------------------------------------------------------------------------------
    foreach ($userProfile in @($ProfileList.Profiles)) {
        if ($userProfile.HasBak) {
            [void]$findings.Add((New-Finding -Cause 'ProfileBakDuplicate' -Item $userProfile.Sid -Hive 'SOFTWARE' `
                        -Message "Profile $($userProfile.Sid) has a .bak twin, which is what the profile service leaves behind when it cannot load the real profile and signs the user into a replacement. Primary points at '$($userProfile.GuestProfilePath)' and the .bak at '$($userProfile.BakProfilePath)'. The .bak entry will be made primary again and the replacement kept aside as .old." `
                        -Data $userProfile))
            continue
        }

        if ($userProfile.IsTemporary) {
            [void]$findings.Add((New-Finding -Cause 'ProfileTemporaryFlag' -Item $userProfile.Sid -Hive 'SOFTWARE' `
                        -Message "Profile $($userProfile.Sid) has the temporary-profile bit set in State ($($userProfile.State)), so every logon lands in a throwaway profile and changes are discarded at sign-out. The bit will be cleared and State returned to $($userProfile.State -band (-bnot 0x8))." `
                        -Data $userProfile))
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($userProfile.GuestProfilePath) -and -not $userProfile.ProfileExists) {
            [void]$findings.Add((New-Finding -Cause 'ProfileDirectoryMissing' -Item $userProfile.Sid -Hive 'SOFTWARE' -Repairable $false `
                        -Message "Profile $($userProfile.Sid) points at '$($userProfile.GuestProfilePath)', which does not exist on the disk, so the profile service fails this user's logon. It is reported and not repaired: removing the entry lets the user in with an empty new profile and abandons whatever is left of the old one, which is a data loss decision to make deliberately." `
                        -Data $userProfile))
        }
    }

    return @($findings)
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applies the one change a finding calls for. Returns $true when something was written.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    switch -Regex ($Finding.Cause) {
        '^(BootExecute|SetupExecute)Dangling$' {
            $data = $Finding.Data
            $keyPath = "$SystemRoot\Control\Session Manager"
            $current = @((Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).$($data.ValueName))
            $keep = @($current | Where-Object { $_.Trim() -ne $data.Remove })

            # An earlier finding on the same value may already have removed this entry.
            if ($keep.Count -eq $current.Count -and $current.Count -gt 0) { return $false }

            if ($keep.Count -gt 0) {
                Set-ItemProperty -Path $keyPath -Name $data.ValueName -Value ([string[]]$keep) -Type MultiString -Force -ErrorAction Stop
            }
            elseif ($data.ValueName -eq 'BootExecute') {
                # Never leave BootExecute empty: that silently disables the boot-time volume check.
                Set-ItemProperty -Path $keyPath -Name 'BootExecute' -Value ([string[]]@($script:DefaultBootExecute)) -Type MultiString -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "BootExecute had no surviving entry, so the Windows default '$($script:DefaultBootExecute)' was written back."
            }
            else {
                Remove-ItemProperty -Path $keyPath -Name 'SetupExecute' -Force -ErrorAction Stop
            }

            Add-OfflineRepairLog -Message "$($data.ValueName): removed '$($data.Remove)'."
            return $true
        }

        '^BootExecuteDefaultMissing$' {
            $keyPath = "$SystemRoot\Control\Session Manager"
            $current = @((Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).BootExecute | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if (@($current | Where-Object { $_ -match '^autocheck\s+autochk\b' }).Count -gt 0) { return $false }

            $value = @($script:DefaultBootExecute) + $current
            Set-ItemProperty -Path $keyPath -Name 'BootExecute' -Value ([string[]]$value) -Type MultiString -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "BootExecute: added the Windows default '$($script:DefaultBootExecute)' ahead of $($current.Count) existing entry(s)."
            return $true
        }

        '^(SetupTypeWithoutCommand|SetupModeDanglingCommand)$' {
            $keyPath = 'HKLM:\BROKENSYSTEM\Setup'
            $before = $Finding.Data
            Set-ItemProperty -Path $keyPath -Name 'SetupType' -Value 0 -Type DWord -Force -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($before.CmdLine)) {
                Set-ItemProperty -Path $keyPath -Name 'CmdLine' -Value '' -Type String -Force -ErrorAction Stop
            }
            Add-OfflineRepairLog -Message "Setup: SetupType $($before.SetupType) -> 0, CmdLine '$($before.CmdLine)' -> empty. The VM will boot straight to the logon screen instead of into setup mode."
            return $true
        }

        '^Winlogon(ValueMissing|ValueBroken)$' {
            $value = $Finding.Data
            $keyPath = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

            $keep = @($value.Good | ForEach-Object { $_.Command })
            $parts = if ($value.HasRequired) { $keep } else { @($value.Default) + $keep }
            if ($parts.Count -eq 0) { $parts = @($value.Default) }

            $newValue = ($parts -join ',')
            if ($value.TrailingComma) { $newValue = "$newValue," }

            $existing = "$((Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).$($value.Name))"
            if ($existing -eq $newValue) { return $false }

            Set-ItemProperty -Path $keyPath -Name $value.Name -Value $newValue -Type String -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "Winlogon $($value.Name): '$existing' -> '$newValue'."
            return $true
        }

        '^ProfileBakDuplicate$' {
            $userProfile = $Finding.Data
            $basePath = Split-Path -Path $userProfile.KeyPath -Parent
            $oldPath = "$($userProfile.KeyPath).old"

            if (-not (Test-Path $userProfile.BakKeyPath)) { return $false }
            if (Test-Path $oldPath) { Remove-Item -Path $oldPath -Recurse -Force -ErrorAction Stop }

            Rename-Item -Path $userProfile.KeyPath -NewName "$($userProfile.Sid).old" -Force -ErrorAction Stop
            Rename-Item -Path $userProfile.BakKeyPath -NewName $userProfile.Sid -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($userProfile.Sid): the replacement profile entry was renamed to .old and the .bak entry restored as the primary one."

            $restored = "$basePath\$($userProfile.Sid)"
            $props = Get-ItemProperty $restored -ErrorAction SilentlyContinue

            $state = if ($null -ne $props.State) { [int]$props.State } else { 0 }
            if (($state -band 0x8) -ne 0) {
                $newState = $state -band (-bnot 0x8)
                Set-ItemProperty -Path $restored -Name 'State' -Value $newState -Type DWord -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "$($userProfile.Sid): State $state -> $newState (temporary-profile bit cleared)."
            }
            if ($null -ne $props.RefCount -and [int]$props.RefCount -ne 0) {
                Set-ItemProperty -Path $restored -Name 'RefCount' -Value 0 -Type DWord -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "$($userProfile.Sid): RefCount $($props.RefCount) -> 0, so the profile is not treated as still loaded."
            }
            return $true
        }

        '^ProfileTemporaryFlag$' {
            $userProfile = $Finding.Data
            $props = Get-ItemProperty $userProfile.KeyPath -ErrorAction SilentlyContinue
            $state = if ($null -ne $props.State) { [int]$props.State } else { 0 }
            if (($state -band 0x8) -eq 0) { return $false }

            $newState = $state -band (-bnot 0x8)
            Set-ItemProperty -Path $userProfile.KeyPath -Name 'State' -Value $newState -Type DWord -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($userProfile.Sid): State $state -> $newState (temporary-profile bit cleared)."

            if ($null -ne $props.RefCount -and [int]$props.RefCount -ne 0) {
                Set-ItemProperty -Path $userProfile.KeyPath -Name 'RefCount' -Value 0 -Type DWord -Force -ErrorAction Stop
                Add-OfflineRepairLog -Message "$($userProfile.Sid): RefCount $($props.RefCount) -> 0."
            }
            return $true
        }

        default { return $false }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $winlogon = Get-WinlogonState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        $sessionManager = Get-SessionManagerState -SystemRoot $systemRoot -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        $setupMode = Get-SetupModeState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive
        $profileList = Get-ProfileListState -WindowsDrive $offline.WindowsDrive

        return [PSCustomObject]@{
            ControlSet     = (Split-Path -Path $systemRoot -Leaf)
            Winlogon       = $winlogon
            SessionManager = $sessionManager
            SetupMode      = $setupMode
            ProfileList    = $profileList
            Findings       = @(Get-AllFinding -Winlogon $winlogon -SessionManager $sessionManager -SetupMode $setupMode -ProfileList $profileList)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    Log-Info "Control set $($context.ControlSet): guest Windows directory $($context.Winlogon.GuestSystemRoot)." | Tee-Object -FilePath $logFile -Append
    foreach ($value in @($context.Winlogon.Values)) {
        Log-Info "Winlogon $($value.Name) = '$($value.Raw)' ($($value.Good.Count) of $($value.Resolutions.Count) entry(s) resolve to a file on the disk)." | Tee-Object -FilePath $logFile -Append
    }
    if ($context.SessionManager.Available) {
        Log-Info "Session Manager: $(@($context.SessionManager.BootExecute).Count) BootExecute entry(s), $(@($context.SessionManager.SetupExecute).Count) SetupExecute entry(s), $(@($context.SessionManager.ExcludeFromKnownDlls).Count) ExcludeFromKnownDlls entry(s)." | Tee-Object -FilePath $logFile -Append
        foreach ($entry in @($context.SessionManager.BootExecute)) {
            $who = if ($entry.IsDefault) { 'Windows default' } elseif ($entry.Vendor) { "from '$($entry.Vendor)'" } else { 'no version information' }
            Log-Info "  BootExecute '$($entry.Entry)': $(if ($entry.Exists) { "resolves to $($entry.Resolution.Resolved), $who" } else { $entry.Resolution.Reason })" | Tee-Object -FilePath $logFile -Append
        }
    }
    if ($context.SetupMode.SystemSetupInProgress -eq 1) {
        Log-Warning 'SYSTEM\Setup\SystemSetupInProgress is 1, so the guest believes Windows setup has not finished. That is normal only for a VM captured mid-Sysprep, and it was left alone.' | Tee-Object -FilePath $logFile -Append
    }
    Log-Info "Profile list: $(@($context.ProfileList.Profiles).Count) user profile(s)." | Tee-Object -FilePath $logFile -Append

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($findings.Count -eq 0) {
        Log-Output 'No logon subsystem fault was found. Every Session Manager, Winlogon and profile entry resolves to a file that is present on the disk, and the VM is not held in setup mode. No changes were made.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Back up only the hives that are actually about to be written.
    $hivesToWrite = @($repairable | ForEach-Object { $_.Hive } | Sort-Object -Unique)
    foreach ($hive in $hivesToWrite) {
        $backup = Backup-OfflineHiveFile -Hive $hive -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "$hive hive backed up to $backup" | Tee-Object -FilePath $logFile -Append
    }

    $repairedCount = 0
    $failed = @()

    if ($repairable.Count -gt 0) {
        $repairOutcome = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $systemRoot = Get-OfflineSystemRootPath
            $done = 0
            $errors = [System.Collections.Generic.List[string]]::new()
            foreach ($finding in $repairable) {
                try {
                    if (Repair-Finding -Finding $finding -SystemRoot $systemRoot) {
                        $finding.Repaired = $true
                        $done++
                    }
                }
                catch {
                    [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                    Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
                }
            }
            return [PSCustomObject]@{ Repaired = $done; Errors = @($errors) }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        $repairedCount = $repairOutcome.Repaired
        $failed = @($repairOutcome.Errors)
    }

    # Verify against freshly read state rather than trusting the writes above.
    $remaining = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        return @(Get-AllFinding `
                -Winlogon (Get-WinlogonState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive) `
                -SessionManager (Get-SessionManagerState -SystemRoot $systemRoot -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive) `
                -SetupMode (Get-SetupModeState -WindowsPath $offline.WindowsPath -WindowsDrive $offline.WindowsDrive) `
                -ProfileList (Get-ProfileListState -WindowsDrive $offline.WindowsDrive))
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($unrepairable.Count -gt 0) { $summary += " $($unrepairable.Count) issue(s) need a decision and were only reported." }

    if ($failed.Count -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($failed.Count) repair(s) failed and $($stillRepairable.Count) issue(s) are still present." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    foreach ($finding in $unrepairable) {
        Log-Output "  [MANUAL] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    if ($repairedCount -gt 0) {
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
