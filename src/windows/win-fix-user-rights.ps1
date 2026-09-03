#########################################################################################################
#
# .SYNOPSIS
#   Repairs user rights that a removed Group Policy left tattooed on an offline disk, so a VM that
#   refuses RDP - or refuses every logon - can be signed into again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   THE FAULT
#
#   User rights are not Group Policy settings in the usual sense. When a GPO assigns "Deny log on
#   through Remote Desktop Services", the Local Security Authority writes that assignment into its
#   own policy database on the machine. Removing the GPO, unlinking it, or moving the VM out of the
#   OU does NOT take the assignment away: nothing goes back to undo it. The setting is left behind -
#   tattooed - and the VM keeps refusing logons for a policy that no longer exists anywhere.
#
#   The usual presentation is an Azure VM that is running, reachable on 3389, with the Remote Desktop
#   service healthy and the firewall open, that still answers every RDP attempt with
#   "The connection was denied because the user account is not authorized for remote login."
#   Nothing in the network path is wrong, so the network path is not where the repair belongs.
#
#   WHY THE REPAIR IS A FIRST-BOOT HOOK AND NOT AN OFFLINE WRITE
#
#   The repair is 'secedit /configure', and secedit cannot run against an offline disk: it talks to
#   a live LSA through the policy API, not to a hive file. So the repair is armed rather than
#   applied. This script writes a payload to the disk and points SYSTEM\Setup\CmdLine at it with
#   SetupType 2, which is the hook the session manager runs in a SYSTEM console session before the
#   logon UI appears. The VM applies its own repair on the next boot, then clears the hook and
#   deletes the payload.
#
#   That hook is used rather than a Group Policy startup script because a domain-joined VM can have
#   its local Group Policy state replaced by the domain's own, which is exactly the situation this
#   fault tends to arise in. SYSTEM\Setup is not Group Policy, so domain policy does not affect it.
#
#   WHY IT DOES NOT WRITE THE RIGHTS DIRECTLY
#
#   Logon rights live in the SECURITY hive as a bitmask per account, and this script reads them from
#   there. Writing them back by hand is a different proposition: the LSA policy database also holds
#   the privilege LUID lists and the security descriptors that reference them, and hand-editing that
#   structure is how offline tools corrupt a policy database. secedit is the supported writer, so
#   secedit does the writing.
#
#   DETECTION, AND WHY A HEALTHY DISK IS LEFT ALONE
#
#   The library rule is that a blanket reset is never armed on a VM whose rights are fine, so the
#   fault is confirmed from the offline disk first. Logon rights are readable without a live LSA:
#
#     SECURITY\Policy\Accounts\<SID>\ActSysAc
#
#   holds a 4-byte SECURITY_ACCESS mask in the subkey's default value - note that ActSysAc is a
#   subkey, not a value on the account key. The SECURITY hive denies read to every account including
#   SYSTEM, so it is read through the backup-restore path in Use-OfflineProtectedResource.ps1.
#
#   The mask bits were measured against 'secedit /export /areas USER_RIGHTS' on a live Server 2022,
#   build 20348, across all 12 accounts that carry rights - the decode below agrees with secedit on
#   every one of them:
#
#     0x001 Interactive         0x040 DenyInteractive        BUILTIN\Users              0x003
#     0x002 Network             0x080 DenyNetwork            Everyone                   0x002
#     0x004 Batch               0x100 DenyBatch              BUILTIN\Backup Operators   0x007
#     0x010 Service             0x200 DenyService            BUILTIN\Administrators     0x407
#     0x020 Proxy               0x800 DenyRemoteInteractive  BUILTIN\Remote Desktop U.  0x400
#     0x400 RemoteInteractive                                NT SERVICE\ALL SERVICES    0x010
#
#   A finding is only raised for a state that actually refuses a logon:
#
#     - DenyRemoteInteractive / DenyInteractive / DenyNetwork on a broad group. This is the tattoo
#       itself. A deny right beats every allow right it meets, so one of these on Administrators,
#       Users, Everyone or Authenticated Users locks the corresponding logon type out.
#     - MissingRemoteInteractive - neither Administrators nor Remote Desktop Users can log on
#       through Remote Desktop Services, so nobody can RDP in.
#     - MissingInteractive - Administrators cannot log on at the console either, which is what turns
#       a lost RDP session into a VM with no way in at all.
#     - MissingServiceLogon - NT SERVICE\ALL SERVICES lost SeServiceLogonRight, which stops services
#       from starting and can present as 0xC000021A rather than as a logon failure.
#
#   A deny right on a service account or a narrow single-user SID is reported as context and is not
#   a finding: denying one account is how deny rights are legitimately used.
#
#   On a healthy disk every check passes, no finding is produced, and this script writes nothing.
#
#   WHAT THE PAYLOAD APPLIES
#
#     secedit /configure /db <temp>.sdb /cfg %windir%\inf\defltbase.inf /areas USER_RIGHTS
#
#   defltbase.inf is the shipped default security template. On Server 2022 20348 it carries a
#   [Privilege Rights] section that sets all five deny rights to empty and restores
#   SeRemoteInteractiveLogonRight to Administrators and Remote Desktop Users - measured, 39,580
#   bytes - which is precisely the tattoo this scenario removes.
#
#   /areas USER_RIGHTS is not optional and is a deliberate departure from the monolithic script this
#   replaces, which ran defltbase.inf with no /areas at all. Without it secedit applies every area in
#   the template - account and audit policy, registry and file system ACLs, service configuration -
#   on a production VM that was only ever refusing a logon. The blast radius is narrowed to the one
#   area that carries the fault.
#
#   The before and after exports are kept on the disk as the audit trail, so what changed can be
#   read afterwards rather than inferred.
#
#   Reference: "User Rights Assignment"
#   https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-rights-assignment
#
# .RESOLVES
#   RDP or console logon refused by a tattooed user right after the GPO that set it was removed.
#   Not a no-boot repair: the disk has to be able to boot for the payload to run.
#
# .PARAMETER detectOnly
#   Report what is on the disk and change nothing.
#
# .PARAMETER revert
#   Undo the Setup hook and remove the payload, restoring SYSTEM\Setup to what was recorded.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, when it should not be auto-detected.
#
# .PARAMETER force
#   Arm the reset even when detection finds nothing wrong. Off by default on purpose: a blanket
#   user-rights reset on a VM whose rights are fine is a change with no fault behind it.
#
# .EXAMPLE
#   az vm repair create -g sourceRG -n sourceVM --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-user-rights --parameters detectOnly=true --run-on-repair --verbose
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-user-rights --run-on-repair --verbose
#   az vm repair restore -g sourceRG -n sourceVM --yes
#
# .NOTES
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   The repair completes on the next boot of the repaired VM, not on the rescue VM. After
#   'az vm repair restore', the first boot runs the payload before the logon UI appears.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Values are consumed inside script blocks passed to the offline hive helpers, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$revert = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$force = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineRegistryHive.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')
$isForced = ($force -eq 'true')

# Windows\Temp is used rather than a new folder so nothing is left behind that the image did not
# already have. The exports are deliberately NOT deleted by the payload: they are the audit trail.
$script:PayloadRelativePath = 'Temp\win-fix-user-rights.cmd'
$script:ResultRelativePath = 'Temp\win-fix-user-rights.result'
$script:ManifestRelativePath = 'Temp\win-fix-user-rights-revert.json'
$script:BeforeRelativePath = 'Temp\win-fix-user-rights-before.inf'
$script:AfterRelativePath = 'Temp\win-fix-user-rights-after.inf'

# SetupType 2 is 'setup in progress', the state that makes the session manager run CmdLine before
# the logon UI. 0 is the settled state a healthy installation sits in.
$script:SetupTypeRunCmdLine = 2

# SECURITY_ACCESS_* from ntsecapi.h. Measured against secedit on Server 2022 20348 - see the header.
$script:LogonRightBits = [ordered]@{
    0x0001 = 'SeInteractiveLogonRight'
    0x0002 = 'SeNetworkLogonRight'
    0x0004 = 'SeBatchLogonRight'
    0x0010 = 'SeServiceLogonRight'
    0x0020 = 'SeProxyLogonRight'
    0x0040 = 'SeDenyInteractiveLogonRight'
    0x0080 = 'SeDenyNetworkLogonRight'
    0x0100 = 'SeDenyBatchLogonRight'
    0x0200 = 'SeDenyServiceLogonRight'
    0x0400 = 'SeRemoteInteractiveLogonRight'
    0x0800 = 'SeDenyRemoteInteractiveLogonRight'
}

# Groups broad enough that denying them locks out administration itself. A deny right on one of
# these is the tattoo; a deny right on a single service account is normal administration.
$script:BroadSids = [ordered]@{
    'S-1-1-0'       = 'Everyone'
    'S-1-5-11'      = 'Authenticated Users'
    'S-1-5-32-544'  = 'BUILTIN\Administrators'
    'S-1-5-32-545'  = 'BUILTIN\Users'
    'S-1-5-32-555'  = 'BUILTIN\Remote Desktop Users'
}

$script:SidAdministrators = 'S-1-5-32-544'
$script:SidRemoteDesktopUsers = 'S-1-5-32-555'
$script:SidAllServices = 'S-1-5-80-0'

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
    }
}

function Write-OperatorLog {
    <#
    .SYNOPSIS
        Flushes buffered helper narration to the detail log, promoting only Warning and Error.

    .DESCRIPTION
        Run Command returns at most 4096 characters and keeps the tail, and Log-Info reaches stdout
        exactly as Log-Output does, each line carrying a ~31-character level and timestamp prefix.
        Narration that only helps after the fact therefore goes to the log file on disk, so the
        returned log keeps the findings and the conclusion.

        Warnings are not demoted, because some of them change what the operator does next.
    #>
    param([Parameter(Mandatory = $false)][string]$LogPath = $logFile)

    foreach ($entry in @(Get-OfflineRepairLog)) {
        $line = "[$($entry.Level)] $($entry.Message)"
        switch ($entry.Level) {
            'Error' { Log-Error $entry.Message | Tee-Object -FilePath $LogPath -Append }
            'Warning' { Log-Warning $entry.Message | Tee-Object -FilePath $LogPath -Append }
            default { $line | Out-File -FilePath $LogPath -Append }
        }
    }
    Clear-OfflineRepairLog
}

function ConvertTo-LogonRightName {
    <#
    .SYNOPSIS
        Decodes a SECURITY_ACCESS mask into the SeXxx right names it carries.
    #>
    param([Parameter(Mandatory = $true)][uint32]$Mask)

    # Enumerated, not indexed. LogonRightBits is an OrderedDictionary keyed by integers, and an
    # integer in the indexer binds to the positional overload: $LogonRightBits[0x0400] asks for the
    # item at index 1024, which is out of range and comes back empty, while $LogonRightBits[0x0004]
    # quietly returns the fifth entry. Decoding through the indexer reported every healthy disk as
    # having lost its logon rights - measured on a stock 20348 disk, not theorised.
    $names = @()
    foreach ($entry in $script:LogonRightBits.GetEnumerator()) {
        if ($Mask -band $entry.Key) { $names += $entry.Value }
    }
    return , $names
}

function Resolve-SidFriendlyName {
    <#
    .SYNOPSIS
        Best-effort friendly name for a SID, falling back to the SID itself.

    .DESCRIPTION
        Well-known SIDs resolve on the rescue VM because they are the same everywhere. A SID local
        to the broken machine will not resolve here, and that is not an error - it is reported as
        the raw SID, which is still what the operator needs to see.
    #>
    param([Parameter(Mandatory = $true)][string]$Sid)

    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

function Get-OfflineLogonRight {
    <#
    .SYNOPSIS
        Reads the logon rights of every account in the offline LSA policy database.

    .DESCRIPTION
        SECURITY\Policy\Accounts holds one subkey per account that has been granted a logon right or
        a privilege. The mask lives in the default value of the ActSysAc SUBKEY, not in a value on
        the account key - measured, because assuming otherwise reads nothing and reports a broken
        disk as healthy.

        The whole hive denies read to every account including SYSTEM, so both the enumeration and
        the read go through the backup-restore path.

    .OUTPUTS
        PSCustomObject with Ok, Accounts (array of Sid/Name/Mask/Rights) and Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $result = [PSCustomObject]@{ Ok = $false; Accounts = @(); Reason = $null }

    try {
        Mount-OfflineHive -WindowsPath $WindowsPath -Hive 'SECURITY'
    }
    catch {
        $result.Reason = "the SECURITY hive could not be loaded: $($_.Exception.Message)"
        return $result
    }

    try {
        $accountsPath = 'HKLM\BROKENSECURITY\Policy\Accounts'

        $listing = Get-OfflinePrivilegedRegistrySubKeyName -Path $accountsPath
        if (-not $listing.Ok) {
            $result.Reason = "the account list could not be read: $($listing.Error)"
            return $result
        }
        if (-not $listing.Exists) {
            $result.Reason = 'SECURITY\Policy\Accounts is not present on this disk'
            return $result
        }

        $accounts = New-Object System.Collections.ArrayList

        foreach ($sid in @($listing.Names)) {
            $value = Get-OfflinePrivilegedRegistryValue -Path "$accountsPath\$sid\ActSysAc" -Name ''

            # An account with privileges but no logon rights has no ActSysAc subkey at all. That is
            # a normal shape, not a read failure, and it carries no logon right to judge.
            if (-not $value.Ok -or -not $value.Found) { continue }
            if ($value.ByteLength -lt 4) { continue }

            $mask = [System.BitConverter]::ToUInt32($value.Bytes, 0)

            [void]$accounts.Add([PSCustomObject]@{
                    Sid    = $sid
                    Name   = (Resolve-SidFriendlyName -Sid $sid)
                    Mask   = $mask
                    Rights = (ConvertTo-LogonRightName -Mask $mask)
                })
        }

        $result.Accounts = @($accounts)
        $result.Ok = $true
        return $result
    }
    catch {
        $result.Reason = "the logon rights could not be read: $($_.Exception.Message)"
        return $result
    }
    finally {
        try { Dismount-OfflineHive -Hive 'SECURITY' } catch { }
    }
}

function Get-OfflineSetupState {
    <#
    .SYNOPSIS
        Reads SYSTEM\Setup\SetupType and CmdLine from the offline disk.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $state = [PSCustomObject]@{ Available = $false; SetupType = 0; CmdLine = ''; Reason = $null }

    try {
        $props = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SYSTEM' -ScriptBlock {
            $key = 'HKLM:\BROKENSYSTEM\Setup'
            if (-not (Test-Path $key)) { return $null }
            return Get-ItemProperty -Path $key -ErrorAction Stop
        }
    }
    catch {
        $state.Reason = "the SYSTEM hive could not be read: $($_.Exception.Message)"
        return $state
    }

    if ($null -eq $props) {
        $state.Reason = 'the SYSTEM\Setup key is not present on this disk'
        return $state
    }

    $state.Available = $true
    if ($null -ne $props.SetupType) { $state.SetupType = [int]$props.SetupType }
    if ($null -ne $props.CmdLine) { $state.CmdLine = "$($props.CmdLine)".Trim() }

    return $state
}

function Set-OfflineSetupHook {
    <#
    .SYNOPSIS
        Points SYSTEM\Setup\CmdLine at the payload and puts the disk into setup mode.

    .DESCRIPTION
        Every value is read back after being written. A hive write that silently fails would
        otherwise be reported as a successful repair, and the guest would boot without the hook.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$GuestPayloadPath
    )

    $result = [PSCustomObject]@{
        Applied = $false; PreviousSetupType = 0; PreviousCmdLine = ''; Reason = $null
    }

    $before = Get-OfflineSetupState -WindowsPath $WindowsPath
    if (-not $before.Available) {
        $result.Reason = $before.Reason
        return $result
    }

    $result.PreviousSetupType = $before.SetupType
    $result.PreviousCmdLine = $before.CmdLine

    $command = 'cmd.exe /c "{0}"' -f $GuestPayloadPath
    $setupType = $script:SetupTypeRunCmdLine

    try {
        # Invoke-WithHive runs the block with '& $ScriptBlock' and passes no arguments, so the block
        # reads $command and $setupType from this scope rather than taking parameters.
        $readBack = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SYSTEM' -ScriptBlock {
            $key = 'HKLM:\BROKENSYSTEM\Setup'
            Set-ItemProperty -Path $key -Name 'CmdLine' -Value $command -Type String -Force -ErrorAction Stop
            Set-ItemProperty -Path $key -Name 'SetupType' -Value $setupType -Type DWord -Force -ErrorAction Stop
            $props = Get-ItemProperty -Path $key -ErrorAction Stop
            return [PSCustomObject]@{ CmdLine = "$($props.CmdLine)"; SetupType = [int]$props.SetupType }
        }
    }
    catch {
        $result.Reason = "the Setup hook could not be written: $($_.Exception.Message)"
        return $result
    }

    if ($null -eq $readBack) {
        $result.Reason = 'the Setup hook was written but could not be read back'
        return $result
    }
    if ($readBack.CmdLine -ne $command) {
        $result.Reason = "CmdLine reads back as '$($readBack.CmdLine)' instead of '$command'"
        return $result
    }
    if ($readBack.SetupType -ne $script:SetupTypeRunCmdLine) {
        $result.Reason = "SetupType reads back as $($readBack.SetupType) instead of $($script:SetupTypeRunCmdLine)"
        return $result
    }

    $result.Applied = $true
    return $result
}

function Restore-OfflineSetupHook {
    <#
    .SYNOPSIS
        Puts SYSTEM\Setup back the way it was found.

    .DESCRIPTION
        Restores the recorded values rather than assuming the healthy state, so a disk that
        legitimately carried a setup command keeps it. An empty recorded CmdLine means the value was
        absent or blank, and it is removed rather than written as an empty string.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][int]$SetupType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CmdLine
    )

    $result = [PSCustomObject]@{ Restored = $false; Reason = $null }

    $targetSetupType = $SetupType
    $targetCmdLine = $CmdLine

    try {
        $readBack = Invoke-WithHive -WindowsPath $WindowsPath -Hive 'SYSTEM' -ScriptBlock {
            $key = 'HKLM:\BROKENSYSTEM\Setup'
            Set-ItemProperty -Path $key -Name 'SetupType' -Value $targetSetupType -Type DWord -Force -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($targetCmdLine)) {
                Remove-ItemProperty -Path $key -Name 'CmdLine' -Force -ErrorAction SilentlyContinue
            }
            else {
                Set-ItemProperty -Path $key -Name 'CmdLine' -Value $targetCmdLine -Type String -Force -ErrorAction Stop
            }
            $props = Get-ItemProperty -Path $key -ErrorAction Stop
            return [PSCustomObject]@{ CmdLine = "$($props.CmdLine)"; SetupType = [int]$props.SetupType }
        }
    }
    catch {
        $result.Reason = "the Setup hook could not be restored: $($_.Exception.Message)"
        return $result
    }

    if ($null -eq $readBack -or $readBack.SetupType -ne $SetupType) {
        $result.Reason = "SetupType did not read back as $SetupType after being restored"
        return $result
    }

    $result.Restored = $true
    return $result
}

function Write-UserRightsPayload {
    <#
    .SYNOPSIS
        Writes the batch file the guest runs at boot.

    .DESCRIPTION
        The payload does five things, in this order:

          1. Exports the current user rights, which is the "before" half of the audit trail. It is
             taken first so it still reflects the fault even if the configure step fails.
          2. Applies defltbase.inf, scoped to /areas USER_RIGHTS so nothing outside user rights is
             touched. The monolithic script this replaces omitted /areas and therefore also reset
             account policy, audit policy and file and registry ACLs.
          3. Exports again, so before and after can be compared on the disk afterwards.
          4. Writes a result file carrying the exit code of each step, which is how the rescue VM
             learns what happened inside a guest it cannot otherwise see.
          5. Clears the Setup hook and deletes itself, so the VM does not re-enter setup mode and
             the payload cannot run twice.

        Deleting itself is the last line, which makes it the completion signal: if the file is still
        there, the payload stopped early.

        secedit's own log is sent to %WINDIR%\Temp rather than the default under the profile, since
        the payload runs before any profile is loaded.

        The file is written as ASCII with CRLF because cmd.exe will not reliably parse a batch file
        saved as UTF-8 with a byte order mark.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PayloadPath,
        [Parameter(Mandatory = $true)][string]$GuestResultPath,
        [Parameter(Mandatory = $true)][string]$GuestBeforePath,
        [Parameter(Mandatory = $true)][string]$GuestAfterPath
    )

    $result = [PSCustomObject]@{ Written = $false; Reason = $null }

    $parent = Split-Path -Path $PayloadPath -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        try { New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null }
        catch {
            $result.Reason = "the payload folder '$parent' could not be created: $($_.Exception.Message)"
            return $result
        }
    }

    $lines = @(
        '@echo off'
        'setlocal'
        'set RESULT=' + $GuestResultPath
        'set BEFORE=' + $GuestBeforePath
        'set AFTER=' + $GuestAfterPath
        'set SDB=%WINDIR%\Temp\win-fix-user-rights.sdb'
        'set SECLOG=%WINDIR%\Temp\win-fix-user-rights-secedit.log'
        'if exist "%SDB%" del /f /q "%SDB%"'
        'secedit /export /areas USER_RIGHTS /cfg "%BEFORE%" /quiet'
        'set RC_BEFORE=%ERRORLEVEL%'
        'secedit /configure /db "%SDB%" /cfg "%WINDIR%\inf\defltbase.inf" /areas USER_RIGHTS /log "%SECLOG%" /quiet'
        'set RC_CONFIGURE=%ERRORLEVEL%'
        'secedit /export /areas USER_RIGHTS /cfg "%AFTER%" /quiet'
        'set RC_AFTER=%ERRORLEVEL%'
        '> "%RESULT%" echo before=%RC_BEFORE%'
        '>> "%RESULT%" echo configure=%RC_CONFIGURE%'
        '>> "%RESULT%" echo after=%RC_AFTER%'
        '>> "%RESULT%" echo done=1'
        'reg add "HKLM\SYSTEM\Setup" /v SetupType /t REG_DWORD /d 0 /f'
        'reg delete "HKLM\SYSTEM\Setup" /v CmdLine /f'
        'endlocal'
        'del /f /q "%~f0"'
    )

    try {
        $text = ($lines -join "`r`n") + "`r`n"
        [System.IO.File]::WriteAllText($PayloadPath, $text, [System.Text.Encoding]::ASCII)
    }
    catch {
        $result.Reason = "the payload could not be written to '$PayloadPath': $($_.Exception.Message)"
        return $result
    }

    if (-not (Test-Path -LiteralPath $PayloadPath)) {
        $result.Reason = "the payload was written to '$PayloadPath' but the file is not there"
        return $result
    }
    if ((Get-Item -LiteralPath $PayloadPath).Length -le 0) {
        $result.Reason = "the payload at '$PayloadPath' is empty"
        return $result
    }

    $result.Written = $true
    return $result
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run changed, so -revert has something to undo rather than a guess.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][int]$PreviousSetupType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$PreviousCmdLine
    )

    try {
        $manifest = [PSCustomObject]@{
            Script            = 'win-fix-user-rights'
            Written           = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
            PreviousSetupType = $PreviousSetupType
            PreviousCmdLine   = $PreviousCmdLine
        }
        $manifest | ConvertTo-Json -Depth 4 | Out-File -FilePath $ManifestPath -Encoding ascii -Force
        return $true
    }
    catch {
        return $false
    }
}

function Read-RevertManifest {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    }
    catch { return $null }
}

function Get-UserRightsFinding {
    <#
    .SYNOPSIS
        Turns the decoded logon rights into the set of states that actually refuse a logon.

    .DESCRIPTION
        Only a state that stops somebody signing in is a finding. AppLocker taught this library the
        lesson directly: a setting being present is not a fault, and reporting it as one produces a
        script that rewrites healthy machines.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts)

    $findings = New-Object System.Collections.ArrayList
    $byName = @{}
    foreach ($a in $Accounts) { $byName[$a.Sid] = $a }

    # 1. A deny right tattooed on a broad group. This is the fault the scenario is named for.
    $denyMap = [ordered]@{
        'SeDenyRemoteInteractiveLogonRight' = 'log on through Remote Desktop Services'
        'SeDenyInteractiveLogonRight'       = 'log on locally'
        'SeDenyNetworkLogonRight'           = 'access this computer from the network'
    }

    foreach ($sid in $script:BroadSids.Keys) {
        $account = $byName[$sid]
        if ($null -eq $account) { continue }

        foreach ($right in $denyMap.Keys) {
            if ($account.Rights -notcontains $right) { continue }
            [void]$findings.Add((New-Finding -Cause 'TattooedDenyRight' -Item "$($script:BroadSids[$sid]) / $right" `
                        -Message "$($script:BroadSids[$sid]) is denied '$($denyMap[$right])'. A deny right overrides every allow right, so this refuses that logon type for the whole group even though no Group Policy still sets it."))
        }
    }

    # 2. Nobody can reach the machine over RDP.
    $adminRights = if ($byName[$script:SidAdministrators]) { $byName[$script:SidAdministrators].Rights } else { @() }
    $rduRights = if ($byName[$script:SidRemoteDesktopUsers]) { $byName[$script:SidRemoteDesktopUsers].Rights } else { @() }

    if (($adminRights -notcontains 'SeRemoteInteractiveLogonRight') -and
        ($rduRights -notcontains 'SeRemoteInteractiveLogonRight')) {
        [void]$findings.Add((New-Finding -Cause 'MissingRemoteInteractiveLogon' -Item 'SeRemoteInteractiveLogonRight' `
                    -Message "Neither BUILTIN\Administrators nor BUILTIN\Remote Desktop Users holds 'Allow log on through Remote Desktop Services', so no account can sign in over RDP however healthy the listener and firewall are."))
    }

    # 3. Console logon is gone too, which is what removes the last way in.
    if ($null -ne $byName[$script:SidAdministrators] -and $adminRights -notcontains 'SeInteractiveLogonRight') {
        [void]$findings.Add((New-Finding -Cause 'MissingInteractiveLogon' -Item 'SeInteractiveLogonRight' `
                    -Message "BUILTIN\Administrators does not hold 'Allow log on locally', so administrators cannot sign in at the console either."))
    }

    # 4. Services cannot start. This presents as 0xC000021A far more often than as a logon failure.
    $svc = $byName[$script:SidAllServices]
    if ($null -ne $svc) {
        if ($svc.Rights -notcontains 'SeServiceLogonRight') {
            [void]$findings.Add((New-Finding -Cause 'MissingServiceLogon' -Item 'SeServiceLogonRight' `
                        -Message "NT SERVICE\ALL SERVICES does not hold 'Log on as a service', which stops service accounts starting and can present as a 0xC000021A stop rather than a logon failure."))
        }
        if ($svc.Rights -contains 'SeDenyServiceLogonRight') {
            [void]$findings.Add((New-Finding -Cause 'TattooedDenyRight' -Item 'NT SERVICE\ALL SERVICES / SeDenyServiceLogonRight' `
                        -Message "NT SERVICE\ALL SERVICES is denied 'Log on as a service', which stops service accounts starting."))
        }
    }

    # Not comma-wrapped. The caller collects this with @(), and a comma wrap plus that @() nest the
    # array one level deeper: three findings arrive as a single item whose .Cause member-enumerates
    # to all three names and whose .Item resolves to the IList indexer rather than a value.
    return @($findings)
}

#########################################################################################################
# Main
#########################################################################################################

try {
    Log-Output "START: Running script $scriptName" | Tee-Object -FilePath $logFile -Append
    $scriptStartTime | Out-File -FilePath $logFile -Append

    Clear-OfflineRepairLog

    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OperatorLog

    if (-not $offline -or -not $offline.WindowsPath) {
        Log-Error 'No offline Windows installation was found on the attached disk.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    $windowsPath = $offline.WindowsPath
    Log-Output "Offline Windows installation: $windowsPath" | Tee-Object -FilePath $logFile -Append

    $payloadPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:PayloadRelativePath
    $resultPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ResultRelativePath
    $manifestPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ManifestRelativePath

    # The guest sees its own Windows directory, which is not the drive letter it has here.
    $guestWindows = 'C:\Windows'
    $guestPayloadPath = "$guestWindows\$($script:PayloadRelativePath)"
    $guestResultPath = "$guestWindows\$($script:ResultRelativePath)"
    $guestBeforePath = "$guestWindows\$($script:BeforeRelativePath)"
    $guestAfterPath = "$guestWindows\$($script:AfterRelativePath)"

    #####################################################################################################
    # Revert
    #####################################################################################################
    if ($isRevert) {
        Log-Output 'REVERT: undoing the Setup hook and removing the payload.' | Tee-Object -FilePath $logFile -Append

        $manifest = Read-RevertManifest -ManifestPath $manifestPath
        if ($null -eq $manifest) {
            Log-Warning 'No revert manifest was found, so there is nothing recorded to undo.' | Tee-Object -FilePath $logFile -Append
        }

        $restoredCount = 0

        if ($null -ne $manifest -and $null -ne $manifest.PreviousSetupType) {
            $restore = Restore-OfflineSetupHook -WindowsPath $windowsPath `
                -SetupType ([int]$manifest.PreviousSetupType) -CmdLine "$($manifest.PreviousCmdLine)"

            if ($restore.Restored) {
                Log-Output "Setup hook restored to SetupType=$([int]$manifest.PreviousSetupType)." | Tee-Object -FilePath $logFile -Append
                $restoredCount++
            }
            else {
                Log-Warning "The Setup hook could not be restored: $($restore.Reason)" | Tee-Object -FilePath $logFile -Append
            }
        }

        foreach ($stale in @($payloadPath, $resultPath)) {
            if (Test-Path -LiteralPath $stale) {
                Remove-Item -LiteralPath $stale -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $stale) {
                    Log-Warning "'$stale' could not be removed." | Tee-Object -FilePath $logFile -Append
                }
                else {
                    Log-Output "Removed '$stale'." | Tee-Object -FilePath $logFile -Append
                    $restoredCount++
                }
            }
        }

        if (Test-Path -LiteralPath $manifestPath) {
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
        }

        Log-Output 'The user rights themselves are not changed by a revert. Nothing was applied on this disk: the reset runs on the next boot, so undoing the hook before that boot is all there is to undo.' | Tee-Object -FilePath $logFile -Append
        Log-Output "REVERT COMPLETE: restored $restoredCount item(s)." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Detect
    #####################################################################################################
    $rights = Get-OfflineLogonRight -WindowsPath $windowsPath
    Write-OperatorLog

    if (-not $rights.Ok) {
        Log-Error "The offline user rights could not be read, so nothing is armed: $($rights.Reason)." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "Read logon rights for $(@($rights.Accounts).Count) account(s) from the offline SECURITY hive." | Tee-Object -FilePath $logFile -Append

    # The full table goes to the detail log; the returned log keeps the findings.
    foreach ($account in @($rights.Accounts)) {
        "  $($account.Sid) [$($account.Name)] mask=0x$('{0:X4}' -f $account.Mask) $(@($account.Rights) -join ', ')" |
            Out-File -FilePath $logFile -Append
    }

    $findings = @(Get-UserRightsFinding -Accounts @($rights.Accounts))

    $setupState = Get-OfflineSetupState -WindowsPath $windowsPath
    if (-not $setupState.Available) {
        Log-Error "The Setup hook cannot be used on this disk: $($setupState.Reason)." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # A setup command already pointing at something real is a servicing or provisioning step.
    # Overwriting it would discard work the image is part way through.
    $hookInUse = ($setupState.SetupType -ne 0 -and
        -not [string]::IsNullOrWhiteSpace($setupState.CmdLine) -and
        $setupState.CmdLine -notlike '*win-fix-user-rights*')

    if ($hookInUse) {
        $findings += New-Finding -Cause 'SetupHookInUse' -Item 'CmdLine' -Repairable $false `
            -Message "SYSTEM\Setup is already in setup mode running '$($setupState.CmdLine)'. That is left alone, because overwriting it would discard a servicing or provisioning step this image is part way through."
    }

    # defltbase.inf is what the payload applies. If it is not on the disk there is nothing to arm.
    $defltbase = Join-OfflinePath -Root $windowsPath -ChildPath 'inf\defltbase.inf'
    $haveTemplate = Test-OfflinePath $defltbase
    if (-not $haveTemplate) {
        $findings += New-Finding -Cause 'TemplateMissing' -Item 'inf\defltbase.inf' -Repairable $false `
            -Message 'The default security template inf\defltbase.inf is not on this disk, so there is nothing for secedit to apply. Copy it from a machine at the same build, or reset the rights by hand from a console session.'
    }

    #####################################################################################################
    # Report
    #####################################################################################################
    foreach ($finding in $findings) {
        $tag = if ($finding.Repairable) { 'FOUND' } else { 'FOUND (not repairable here)' }
        Log-Output "  [$tag] $($finding.Cause) - $($finding.Item)" | Tee-Object -FilePath $logFile -Append
        Log-Output "           $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
    # so a summary printed first is the first thing a long run loses.
    if ($findings.Count -eq 0) {
        Log-Output 'No user-rights fault was found: every logon right this script checks is in a state that permits sign-in.' | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output "Detect found $($findings.Count) issue(s)." | Tee-Object -FilePath $logFile -Append
    }

    if ($isDetectOnly) {
        Log-Output 'DETECT ONLY: nothing was changed on this disk.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    #####################################################################################################
    # Repair
    #####################################################################################################
    $repairable = @($findings | Where-Object { $_.Repairable })

    if ($hookInUse -or -not $haveTemplate) {
        Log-Error 'Nothing is armed, because a blocking condition above has to be resolved first.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    if ($repairable.Count -eq 0 -and -not $isForced) {
        Log-Output 'Nothing was armed: this disk has no user-rights fault to repair. Re-run with -force true to reset user rights anyway.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($repairable.Count -eq 0 -and $isForced) {
        Log-Warning 'FORCED: no fault was detected, but -force true was passed, so the reset is armed anyway. Every user right on this VM returns to the shipped default on its next boot, and any deliberate customisation is lost.' | Tee-Object -FilePath $logFile -Append
    }

    $payload = Write-UserRightsPayload -PayloadPath $payloadPath -GuestResultPath $guestResultPath `
        -GuestBeforePath $guestBeforePath -GuestAfterPath $guestAfterPath

    if (-not $payload.Written) {
        Log-Error "The payload could not be written: $($payload.Reason)." | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # Stale results from an earlier run would be read as this run's outcome.
    if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue }

    $hook = Set-OfflineSetupHook -WindowsPath $windowsPath -GuestPayloadPath $guestPayloadPath
    if (-not $hook.Applied) {
        Log-Error "The Setup hook could not be armed: $($hook.Reason)." | Tee-Object -FilePath $logFile -Append
        Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
        return $STATUS_ERROR
    }

    [void](Write-RevertManifest -ManifestPath $manifestPath `
            -PreviousSetupType $hook.PreviousSetupType -PreviousCmdLine $hook.PreviousCmdLine)

    Log-Output '' | Tee-Object -FilePath $logFile -Append
    foreach ($finding in $repairable) {
        Log-Output "  [ARMED] $($finding.Cause) - $($finding.Item)" | Tee-Object -FilePath $logFile -Append
    }

    Log-Output "ARMED $($repairable.Count) of $($repairable.Count) repairable finding(s): user rights reset to the shipped default on the next boot." | Tee-Object -FilePath $logFile -Append
    Log-Output "The payload applies defltbase.inf scoped to /areas USER_RIGHTS, so nothing outside user rights is changed." | Tee-Object -FilePath $logFile -Append
    Log-Output "Audit trail written on the repaired VM: $guestBeforePath and $guestAfterPath." | Tee-Object -FilePath $logFile -Append
    Log-Output "Run 'az vm repair restore' and let the VM boot once; the reset runs before the logon UI appears." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
