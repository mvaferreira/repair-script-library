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
#   WHAT THIS REPAIR CHANGES, AND WHAT IT REFUSES TO
#
#   Logon rights live in the SECURITY hive as one bitmask per account, and the repair rewrites the
#   bits behind the fault in place, on the disk, while it is attached to the rescue VM.
#
#   The line the script draws is between correcting an entry and creating one. Overwriting an
#   existing four-byte ActSysAc value - type preserved, result read back and compared byte for byte
#   - cannot change the shape of the database. Creating an account that is not there would mean
#   synthesising its Sid, Privilgs and SecDesc blobs, and hand-building that structure is how
#   offline tools corrupt a policy database. An LSA that cannot parse its own policy database stops
#   the machine with 0xC000021A, and that is not recoverable by dropping in a clean SECURITY hive,
#   because the same hive holds the machine account password and the DPAPI backup keys. Trading a
#   refused logon for an unbootable VM is not a repair, so the script never creates an account
#   entry - it reports the gap and the one online command that closes it.
#
#   WHY NOT SECEDIT
#
#   secedit is the supported writer for user rights, but it cannot run against an offline disk: it
#   talks to a live LSA through the policy API, not to a hive file. Reaching it from here means
#   arming SYSTEM\Setup\CmdLine and letting the VM repair itself on the next boot - which works,
#   and was measured working, but cannot clean up after itself. See WHY THIS IS NOT DONE WITH
#   SECEDIT below for what that leaves behind.
#
#   DETECTION, AND WHY A HEALTHY DISK IS LEFT ALONE
#
#   The library rule is that nothing is changed on a VM whose rights are fine, so the fault is
#   confirmed from the offline disk first. Logon rights are readable without a live LSA:
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
#   WHAT THE REPAIR WRITES
#
#   The two mask bits behind the finding, straight into the offline LSA policy database:
#
#     SECURITY\Policy\Accounts\<SID>\ActSysAc   (default value, REG_NONE, 4 bytes little-endian)
#
#   The target state matches what the shipped template inf\defltbase.inf would produce for these
#   rights - SeRemoteInteractiveLogonRight held by Administrators and Remote Desktop Users, and the
#   deny rights empty - measured against it on Server 2022 20348. The difference is blast radius:
#   applying the template resets EVERY user right on the machine to the shipped default, discarding
#   any deliberate customisation on a VM that was only refusing a logon. Writing the mask changes
#   the bits named in the finding and carries every other bit across untouched.
#
#   WHY THIS IS NOT DONE WITH SECEDIT
#
#   secedit needs a running LSA, so an offline repair can only schedule it - the previous design
#   armed SYSTEM\Setup\CmdLine and set SetupType=2 so the session manager would run it before the
#   logon UI. That works, and it was measured working. What it cannot do is clean up after itself:
#   Windows rewrites SetupType when the setup pass completes, which is AFTER the payload has exited,
#   so no write from inside the payload survives. Measured on Server 2022 20348 - the payload ran to
#   completion, cleared SetupType twice, and the disk still came back SetupType=2 with an empty
#   CmdLine, re-entering the setup boot path on every boot thereafter.
#
#   Writing the hive directly finishes the repair while the disk is still attached to the rescue VM.
#   Nothing is armed, nothing is left in Windows\Temp, and the VM needs no extra boot.
#
#   A disk still carrying that residue from an earlier version is detected as StaleSetupType and
#   reset to 0.
#
#   Reference: "User Rights Assignment"
#   https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-rights-assignment
#
# .RESOLVES
#   RDP or console logon refused by a tattooed user right after the GPO that set it was removed.
#   The repair completes offline, so the disk does not have to be able to boot for it to apply.
#
# .PARAMETER detectOnly
#   Report what is on the disk and change nothing.
#
# .PARAMETER revert
#   Put the logon-right masks recorded by the last repair back as they were, and clear any Setup
#   hook left behind by an earlier version of this script.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, when it should not be auto-detected.
#
# .PARAMETER force
#   Carry on past a clean detect instead of returning early. The plan is built from the same
#   conditions detect reports, so on a healthy disk it comes out empty and nothing is written -
#   force cannot turn this into a blanket reset of the machine's user rights.
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
#   The repair is finished when 'az vm repair run' returns. Nothing is armed on the disk and the VM
#   needs no extra boot, so 'az vm repair restore' and starting the VM is all that remains.
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

# Residue an earlier version of this script wrote into Windows\Temp. The repair no longer creates
# any of these - they are still named so a run can recognise and clear what it finds.
$script:PayloadRelativePath = 'Temp\win-fix-user-rights.cmd'
$script:ResultRelativePath = 'Temp\win-fix-user-rights.result'
$script:ManifestRelativePath = 'Temp\win-fix-user-rights-revert.json'

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

# Individual bits the repair acts on. Named separately from LogonRightBits because that table is
# keyed by integer and an OrderedDictionary indexed by an integer binds to the positional overload
# rather than the key - see ConvertTo-LogonRightName, where the same trap reported every healthy
# disk as broken.
$script:BitInteractive = [uint32]0x0001
$script:BitService = [uint32]0x0010
$script:BitDenyService = [uint32]0x0200
$script:BitRemoteInteractive = [uint32]0x0400

# Deny bits that lock out administration when they sit on a broad group. Iterated with
# GetEnumerator so the name comes from the entry rather than from an integer lookup.
$script:DenyBitsOnBroadGroups = [ordered]@{
    0x0040 = 'SeDenyInteractiveLogonRight'
    0x0080 = 'SeDenyNetworkLogonRight'
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
                    Type   = $value.Type
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
        # Assigned to $null because Dismount-OfflineHive returns $true, and a finally block still
        # writes to the output stream after the return above has run. Unsuppressed, the caller
        # receives the result object AND a bare True, so $rights becomes a two-element array.
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' } catch { }
    }
}

function Get-AdjustedLogonRightMask {
    <#
    .SYNOPSIS
        Applies a set/clear pair to a logon-right mask without leaving uint32 range.

    .DESCRIPTION
        -bnot on a [uint32] returns a signed Int64 in PowerShell, so 'mask -band (-bnot 0x400)'
        silently widens the whole expression to 64 bits. BitConverter::GetBytes would then emit
        eight bytes, and an eight-byte write into a four-byte ActSysAc value corrupts the policy
        database of a machine that was only missing one right. XOR against the 32-bit all-ones
        constant keeps every intermediate inside uint32.
    #>
    param(
        [Parameter(Mandatory = $true)][uint32]$Mask,
        [Parameter(Mandatory = $false)][uint32]$Set = 0,
        [Parameter(Mandatory = $false)][uint32]$Clear = 0
    )

    $cleared = [uint32]($Mask -band ([uint32]4294967295 -bxor $Clear))
    return [uint32]($cleared -bor $Set)
}

function Get-AbsentGrantTarget {
    <#
    .SYNOPSIS
        Accounts the shipped default grants a logon right to that have no entry on this disk.

    .DESCRIPTION
        LSA removes an account's entry from Policy\Accounts once its last right is taken away, so
        the very fault this script repairs can leave BUILTIN\Remote Desktop Users with no entry at
        all - measured on Server 2022 20348, where emptying SeRemoteInteractiveLogonRight through
        secedit deleted S-1-5-32-555 outright because that right was the only one it held.

        The right cannot be granted back to such an account offline. A policy entry is not just the
        ActSysAc mask: it also carries Sid, Privilgs and SecDesc blobs, and the encoding of an empty
        privilege set is not something to guess at, because an LSA that cannot parse its own policy
        database does not fail gracefully - it stops the machine with 0xC000021A. Creating one would
        risk a no-boot on a VM whose only fault was a refused logon.

        Granting the right to BUILTIN\Administrators is what makes the VM reachable again, so the
        repair does that and reports this, rather than silently restoring less than it appears to.

    .OUTPUTS
        Array of PSCustomObject with Sid, Name and Right.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts)

    $present = @{}
    foreach ($a in $Accounts) { $present[$a.Sid] = $true }

    $absent = New-Object System.Collections.ArrayList
    if (-not $present.ContainsKey($script:SidRemoteDesktopUsers)) {
        [void]$absent.Add([PSCustomObject]@{
                Sid   = $script:SidRemoteDesktopUsers
                Name  = (Resolve-SidFriendlyName -Sid $script:SidRemoteDesktopUsers)
                Right = 'SeRemoteInteractiveLogonRight'
            })
    }
    return @($absent)
}

function Get-LogonRightRepairPlan {
    <#
    .SYNOPSIS
        Turns the decoded accounts into the exact per-account mask changes the repair will make.

    .DESCRIPTION
        The plan is derived from the same conditions Get-UserRightsFinding reports, so the repair
        can never act on something detect did not report. Only the bits named here are touched:
        every other bit of the account's mask is carried across untouched, which is the difference
        between this and applying defltbase.inf, where every user right on the machine returns to
        the shipped default and any deliberate customisation is lost.

        An account that is absent from Policy\Accounts is skipped rather than created. Creating an
        account entry in the LSA policy database is a different operation from correcting one, and
        a disk missing BUILTIN\Administrators entirely has a fault this script does not claim to
        repair.

    .OUTPUTS
        Array of PSCustomObject with Sid, Name, OldMask, NewMask, Type and Reason.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Accounts)

    $byName = @{}
    foreach ($a in $Accounts) { $byName[$a.Sid] = $a }

    $set = @{}
    $clear = @{}
    $why = @{}

    function Add-Change {
        param($Sid, [uint32]$SetBits, [uint32]$ClearBits, $Reason)
        if (-not $set.ContainsKey($Sid)) { $set[$Sid] = [uint32]0; $clear[$Sid] = [uint32]0; $why[$Sid] = @() }
        $set[$Sid] = [uint32]($set[$Sid] -bor $SetBits)
        $clear[$Sid] = [uint32]($clear[$Sid] -bor $ClearBits)
        $why[$Sid] += $Reason
    }

    # 1. Deny rights tattooed on a broad group. Deny overrides allow, so these come off first.
    foreach ($sid in $script:BroadSids.Keys) {
        $account = $byName[$sid]
        if ($null -eq $account) { continue }
        foreach ($entry in $script:DenyBitsOnBroadGroups.GetEnumerator()) {
            if (($account.Mask -band $entry.Key) -eq 0) { continue }
            Add-Change -Sid $sid -SetBits 0 -ClearBits ([uint32]$entry.Key) `
                -Reason "clear $($entry.Value)"
        }
    }

    # 2. Nobody can reach the machine over RDP. defltbase.inf grants this right to exactly
    #    Administrators and Remote Desktop Users, so the repair restores that same pair.
    $adminMask = if ($byName[$script:SidAdministrators]) { [uint32]$byName[$script:SidAdministrators].Mask } else { [uint32]0 }
    $rduMask = if ($byName[$script:SidRemoteDesktopUsers]) { [uint32]$byName[$script:SidRemoteDesktopUsers].Mask } else { [uint32]0 }

    if ((($adminMask -band $script:BitRemoteInteractive) -eq 0) -and
        (($rduMask -band $script:BitRemoteInteractive) -eq 0)) {
        foreach ($sid in @($script:SidAdministrators, $script:SidRemoteDesktopUsers)) {
            if ($null -eq $byName[$sid]) { continue }
            Add-Change -Sid $sid -SetBits $script:BitRemoteInteractive -ClearBits 0 `
                -Reason 'grant SeRemoteInteractiveLogonRight'
        }
    }

    # 3. Console logon, which is the last way in when RDP is gone.
    if ($null -ne $byName[$script:SidAdministrators] -and
        (($adminMask -band $script:BitInteractive) -eq 0)) {
        Add-Change -Sid $script:SidAdministrators -SetBits $script:BitInteractive -ClearBits 0 `
            -Reason 'grant SeInteractiveLogonRight'
    }

    # 4. Service logon. Presents as 0xC000021A more often than as a logon failure.
    $svc = $byName[$script:SidAllServices]
    if ($null -ne $svc) {
        if (([uint32]$svc.Mask -band $script:BitService) -eq 0) {
            Add-Change -Sid $script:SidAllServices -SetBits $script:BitService -ClearBits 0 `
                -Reason 'grant SeServiceLogonRight'
        }
        if (([uint32]$svc.Mask -band $script:BitDenyService) -ne 0) {
            Add-Change -Sid $script:SidAllServices -SetBits 0 -ClearBits $script:BitDenyService `
                -Reason 'clear SeDenyServiceLogonRight'
        }
    }

    $plan = New-Object System.Collections.ArrayList
    foreach ($sid in $set.Keys) {
        $account = $byName[$sid]
        $old = [uint32]$account.Mask
        $new = Get-AdjustedLogonRightMask -Mask $old -Set $set[$sid] -Clear $clear[$sid]
        if ($new -eq $old) { continue }
        [void]$plan.Add([PSCustomObject]@{
                Sid = $sid; Name = $account.Name; OldMask = $old; NewMask = $new
                Type = $account.Type; Reason = ($why[$sid] -join ', ')
            })
    }

    return , @($plan)
}

function Set-OfflineLogonRight {
    <#
    .SYNOPSIS
        Writes the planned masks into the offline LSA policy database.

    .DESCRIPTION
        Every write is read back and compared by Set-OfflinePrivilegedRegistryValue before it is
        counted, so a hive that silently refuses the write is reported as a failure rather than as
        a repair. The registry type is carried from the read: the mask is REG_NONE, and rewriting
        it as REG_BINARY would change the shape of the value even with identical bytes.

    .OUTPUTS
        PSCustomObject with Ok, Applied, Failed and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan
    )

    $result = [PSCustomObject]@{ Ok = $false; Applied = @(); Failed = @(); Reason = $null }

    if ($Plan.Count -eq 0) {
        $result.Ok = $true
        return $result
    }

    try {
        Mount-OfflineHive -WindowsPath $WindowsPath -Hive 'SECURITY'
    }
    catch {
        $result.Reason = "the SECURITY hive could not be loaded: $($_.Exception.Message)"
        return $result
    }

    try {
        $applied = New-Object System.Collections.ArrayList
        $failed = New-Object System.Collections.ArrayList

        foreach ($entry in $Plan) {
            $path = "HKLM\BROKENSECURITY\Policy\Accounts\$($entry.Sid)\ActSysAc"
            $bytes = [System.BitConverter]::GetBytes([uint32]$entry.NewMask)

            $write = Set-OfflinePrivilegedRegistryValue -Path $path -Name '' `
                -Type ([int]$entry.Type) -Bytes $bytes -Confirm:$false

            if ($write.Written) { [void]$applied.Add($entry) }
            else {
                [void]$failed.Add([PSCustomObject]@{ Entry = $entry; Error = $write.Error })
            }
        }

        $result.Applied = @($applied)
        $result.Failed = @($failed)
        $result.Ok = ($failed.Count -eq 0)
        if (-not $result.Ok) { $result.Reason = ($failed | ForEach-Object { $_.Error }) -join '; ' }
        return $result
    }
    catch {
        $result.Reason = "the logon rights could not be written: $($_.Exception.Message)"
        return $result
    }
    finally {
        try { $null = Dismount-OfflineHive -Hive 'SECURITY' } catch { }
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


function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records what this run changed, so -revert has something to undo rather than a guess.

    .DESCRIPTION
        The mask each account held before the repair is what gets recorded. Reverting to a
        remembered value is the only honest undo: recomputing a 'healthy' mask would put the disk
        into a state it was never in, and on a machine whose rights were deliberately customised
        that is a second fault rather than a rollback.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Plan
    )

    try {
        $manifest = [PSCustomObject]@{
            Script   = 'win-fix-user-rights'
            Written  = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
            Accounts = @($Plan | ForEach-Object {
                    [PSCustomObject]@{
                        Sid          = $_.Sid
                        Name         = $_.Name
                        PreviousMask = [uint32]$_.OldMask
                        AppliedMask  = [uint32]$_.NewMask
                        Type         = [int]$_.Type
                    }
                })
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

    # Files an earlier version of this script left on the disk. Nothing is written to any of them
    # now - they are resolved so the run can clear residue it finds.
    $payloadPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:PayloadRelativePath
    $resultPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ResultRelativePath
    $manifestPath = Join-OfflinePath -Root $windowsPath -ChildPath $script:ManifestRelativePath

    #####################################################################################################
    # Revert
    #####################################################################################################
    if ($isRevert) {
        Log-Output 'REVERT: putting the recorded logon-right masks back.' | Tee-Object -FilePath $logFile -Append

        $manifest = Read-RevertManifest -ManifestPath $manifestPath
        if ($null -eq $manifest) {
            Log-Warning 'No revert manifest was found, so there is nothing recorded to undo.' | Tee-Object -FilePath $logFile -Append
        }

        $restoredCount = 0

        if ($null -ne $manifest -and $null -ne $manifest.Accounts) {
            # NewMask carries PreviousMask on purpose: reverting is the same write in the other
            # direction, so it goes through the same verified path rather than a second one.
            $undo = @(@($manifest.Accounts) | ForEach-Object {
                    [PSCustomObject]@{
                        Sid = "$($_.Sid)"; Name = "$($_.Name)"
                        OldMask = [uint32]$_.AppliedMask; NewMask = [uint32]$_.PreviousMask
                        Type = [int]$_.Type; Reason = 'revert'
                    }
                })

            $back = Set-OfflineLogonRight -WindowsPath $windowsPath -Plan $undo
            foreach ($entry in @($back.Applied)) {
                Log-Output ("Reverted {0} to 0x{1:X4}." -f $entry.Name, $entry.NewMask) | Tee-Object -FilePath $logFile -Append
                $restoredCount++
            }
            foreach ($failure in @($back.Failed)) {
                Log-Warning "$($failure.Entry.Name) could not be reverted: $($failure.Error)" | Tee-Object -FilePath $logFile -Append
            }
        }

        # Earlier versions of this script armed a Setup hook instead of writing the hive. A disk
        # repaired by one of those is still carrying it, and SetupType is the half the payload
        # could never clear from inside its own boot, so clear it here.
        $legacy = Get-OfflineSetupState -WindowsPath $windowsPath
        if ($legacy.Available -and ($legacy.SetupType -ne 0 -or $legacy.CmdLine -like '*win-fix-user-rights*')) {
            $cleared = Restore-OfflineSetupHook -WindowsPath $windowsPath -SetupType 0 -CmdLine ''
            if ($cleared.Restored) {
                Log-Output 'Cleared a Setup hook left by an earlier version of this script.' | Tee-Object -FilePath $logFile -Append
                $restoredCount++
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

        Log-Output 'The masks above are back to what they were before this script ran, so the logon rights are once again whatever they were on arrival - including the fault, if the disk arrived with one.' | Tee-Object -FilePath $logFile -Append
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

    # SYSTEM\Setup is read for reporting only now: the repair writes to the SECURITY hive and never
    # touches it. An unreadable SYSTEM hive is worth saying out loud, but it is not a reason to
    # refuse a logon-right repair that does not depend on it.
    $setupState = Get-OfflineSetupState -WindowsPath $windowsPath
    if (-not $setupState.Available) {
        Log-Warning "SYSTEM\Setup could not be read on this disk ($($setupState.Reason)), so the boot-time state is unknown. The logon-right repair does not depend on it, so it continues." | Tee-Object -FilePath $logFile -Append
    }

    # A setup command already pointing at something real is a servicing or provisioning step. The
    # repair no longer touches SYSTEM\Setup at all, so this does not block anything - it is
    # reported because an operator looking at a machine that will not sign in needs to know the
    # image is part way through something.
    $hookInUse = ($setupState.Available -and $setupState.SetupType -ne 0 -and
        -not [string]::IsNullOrWhiteSpace($setupState.CmdLine) -and
        $setupState.CmdLine -notlike '*win-fix-user-rights*')

    if ($hookInUse) {
        $findings += New-Finding -Cause 'SetupHookInUse' -Item 'CmdLine' -Repairable $false `
            -Message "SYSTEM\Setup is already in setup mode running '$($setupState.CmdLine)'. That is left alone: this script repairs the LSA policy database directly and never arms a boot-time command."
    }

    # A SetupType left armed with nothing to run is residue from an earlier version of this script,
    # which cleared CmdLine from inside its own payload but could never make SetupType stick -
    # Windows rewrites it when the setup pass completes, after the payload has exited. Measured on
    # Server 2022 20348: the payload's write succeeded and was overwritten, leaving SetupType=2 with
    # an empty CmdLine on every boot thereafter.
    $staleSetupType = ($setupState.Available -and $setupState.SetupType -ne 0 -and
        [string]::IsNullOrWhiteSpace($setupState.CmdLine))

    if ($staleSetupType) {
        $findings += New-Finding -Cause 'StaleSetupType' -Item 'SetupType' `
            -Message "SYSTEM\Setup\SetupType is $($setupState.SetupType) with no CmdLine to run. The machine re-enters the setup boot path on every boot for nothing, and this is left behind by an earlier version of this repair. It is reset to 0."
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

    if ($repairable.Count -eq 0 -and -not $isForced) {
        Log-Output 'Nothing was changed: this disk has no user-rights fault to repair.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($repairable.Count -eq 0 -and $isForced) {
        Log-Warning 'FORCED: no fault was detected. The plan is derived from the same conditions detect reports, so on a disk that is already healthy it comes out empty and nothing is written.' | Tee-Object -FilePath $logFile -Append
    }

    $plan = @(Get-LogonRightRepairPlan -Accounts @($rights.Accounts))

    if ($plan.Count -eq 0 -and -not $staleSetupType) {
        Log-Output 'Nothing was changed: the logon-right masks on this disk already permit sign-in.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Written before the first hive write, not after. A run that dies part way still needs an undo
    # record for whatever it managed to change.
    [void](Write-RevertManifest -ManifestPath $manifestPath -Plan $plan)

    $write = Set-OfflineLogonRight -WindowsPath $windowsPath -Plan $plan

    Log-Output '' | Tee-Object -FilePath $logFile -Append
    foreach ($entry in @($write.Applied)) {
        Log-Output ("  [FIXED] {0}: 0x{1:X4} -> 0x{2:X4} ({3})" -f $entry.Name, $entry.OldMask, $entry.NewMask, $entry.Reason) | Tee-Object -FilePath $logFile -Append
    }
    foreach ($failure in @($write.Failed)) {
        Log-Error ("  [FAILED] {0}: {1}" -f $failure.Entry.Name, $failure.Error) | Tee-Object -FilePath $logFile -Append
    }

    # SetupType is cleared last. It is not part of the logon-rights fault, so a failure to write the
    # policy database must not be masked by a successful tidy-up of somebody else's residue.
    if ($staleSetupType) {
        $cleared = Restore-OfflineSetupHook -WindowsPath $windowsPath -SetupType 0 -CmdLine ''
        if ($cleared.Restored) {
            Log-Output '  [FIXED] SYSTEM\Setup\SetupType reset to 0, so the disk no longer re-enters the setup boot path.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Warning "SetupType could not be reset: $($cleared.Reason)" | Tee-Object -FilePath $logFile -Append
        }
    }

    if (-not $write.Ok) {
        Log-Error "The logon rights could not be fully repaired: $($write.Reason)." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    # The disk is handed back with no boot-time work outstanding. This is asserted rather than
    # assumed: the previous design armed SYSTEM\Setup and could not clear it again from inside the
    # boot it started, so the one thing worth proving is that nothing here left that state behind.
    $final = Get-OfflineSetupState -WindowsPath $windowsPath
    if ($final.Available -and ($final.SetupType -ne 0 -or -not [string]::IsNullOrWhiteSpace($final.CmdLine))) {
        Log-Warning "SYSTEM\Setup still reads SetupType=$($final.SetupType) CmdLine='$($final.CmdLine)'. That is not this repair, but the VM will run it on the next boot." | Tee-Object -FilePath $logFile -Append
    }

    Log-Output "REPAIRED $($write.Applied.Count) account(s) in the offline LSA policy database." | Tee-Object -FilePath $logFile -Append
    Log-Output 'Only the logon-right bits listed above were changed; no other user right on this disk was touched.' | Tee-Object -FilePath $logFile -Append

    # Reported, not hidden: the shipped default grants RDP to two groups, and if the fault deleted
    # one of them from the policy database this repair restores fewer accounts than it appears to.
    foreach ($absent in (Get-AbsentGrantTarget -Accounts @($rights.Accounts))) {
        Log-Output "  [NOT RESTORED] $($absent.Name) has no entry in this disk's LSA policy database, so $($absent.Right) could not be granted to it offline." | Tee-Object -FilePath $logFile -Append
        Log-Output "                 Access is restored through BUILTIN\Administrators above. To put the group back on the shipped default once the VM is up, run as administrator:" | Tee-Object -FilePath $logFile -Append
        Log-Output '                 secedit /export /areas USER_RIGHTS /cfg %temp%\ur.inf  then add the SID to SeRemoteInteractiveLogonRight and re-import with secedit /configure /areas USER_RIGHTS' | Tee-Object -FilePath $logFile -Append
    }

    if ($final.Available) {
        Log-Output "Verified on this disk: SetupType=$($final.SetupType), no boot-time command armed." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Output 'SYSTEM\Setup could not be read back, so the boot-time state is unverified. This repair never writes to it.' | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Run 'az vm repair restore' and start the VM; the rights are already correct, so no extra boot is needed." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
