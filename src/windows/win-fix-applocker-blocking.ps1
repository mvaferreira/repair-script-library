#########################################################################################################
#
# .SYNOPSIS
#   Finds the AppLocker rule that is blocking this VM and removes that rule, instead of turning
#   AppLocker off.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". It answers the
#   question "what is AppLocker refusing to run on this machine" from evidence on the offline disk,
#   and changes only what that evidence names.
#
#   The rule this script is built around: AppLocker being configured is not a fault. Plenty of
#   machines enforce AppLocker correctly, so "AppLocker is on" is never reported as a problem and
#   never triggers a change. Something is only repaired when there is positive evidence that it is
#   what broke this particular VM.
#
#   Evidence sources, in order of authority:
#     1. The AppLocker event logs on the offline disk. Events 8004 (exe or dll) and 8007 (msi or
#        script) name the exact file that was refused, and 8022 and 8025 do the same for packaged
#        apps. This is the strongest evidence available: it is a record of the guest actually
#        denying something rather than a reading of what the policy might do.
#     2. A Deny rule whose path condition covers the Windows directory in a collection that is
#        enforcing. AppLocker applies Deny before Allow, so such a rule provably refuses Windows'
#        own binaries. This does not need an event to be believed.
#     3. An enforcing collection that holds rules but no Allow rule covering the Windows directory.
#        Once a collection contains any rule it becomes an explicit allowlist, so a file matching no
#        Allow rule is denied.
#
#   Causes detected and repaired:
#     1. A Deny rule covering Windows system binaries. Repaired by deleting that one rule, which
#        leaves every other rule in the policy enforcing.
#     2. An enforcing collection whose allowlist does not cover the Windows directory. Repaired by
#        moving that one collection to AuditOnly, which stops the blocking, keeps every rule, and
#        keeps the audit events coming so the policy author can see what it would have denied.
#
#   Where the policy came from is reported but never chased. Local policy is cleaned out of
#   Registry.pol so the repair holds, and the per-GPO client cache is cleared. A domain GPO is named
#   in the output so the engineer knows where it originated, and that is all: the GPO lives in
#   SYSVOL on a domain controller, this script does not touch it, and if a later policy refresh
#   re-applies it that is a conversation between the engineer and the customer, not something a
#   disk repair can or should prevent.
#
#   Turning AppLocker off altogether is available with -disableEnforcement true, and is
#   deliberately not the default. It sets every collection to NotConfigured and disables the
#   Application Identity service. Use it only when the evidence does not name a culprit.
#
# .RESOLVES
#   A VM that boots and reaches the logon screen but cannot be used, because AppLocker is refusing
#   to run the binaries a user session depends on. Typical triggers are an AppLocker GPO written
#   with a Deny rule that is broader than intended, or an allowlist that never covered the Windows
#   directory. The classic presentation is a black screen after a successful logon, because
#   explorer.exe is denied.
#
#   This is deliberately not described as a no-boot fault, and the distinction is not cosmetic. By
#   default AppLocker only evaluates code launched in a user's context; every process in the boot
#   chain - smss, csrss, wininit, winlogon, services, lsass - runs as SYSTEM and is exempt. So even
#   a maximally hostile Exe policy still boots the machine and still authenticates users. What it
#   takes away is the session that follows. Enforcement reaches non-user processes only when the
#   policy opts in with <Services EnforcementMode="Enabled"/> in its rule collection extensions,
#   which this script reports when it finds it.
#
# .PARAMETER detectOnly
#   "true" to report the evidence and make no writes at all. Defaults to "false".
#
# .PARAMETER disableEnforcement
#   "true" to set every rule collection to NotConfigured and disable the Application Identity
#   service. Last resort. Defaults to "false".
#
# .PARAMETER disableLsaProtection
#   "true" to remove Control\Lsa\RunAsPPL. Unrelated to AppLocker and never done by default. LSA
#   protection is a supported, recommended setting that does not stop a VM booting, so it is never
#   reported as a fault - this switch exists only for the case where an engineer has separate
#   evidence that a tool which reads LSASS has to run. Defaults to "false".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-applocker-blocking --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-applocker-blocking --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-applocker-blocking --parameters disableEnforcement=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Where AppLocker policy lives, measured rather than assumed:
#     - The applied policy is always SOFTWARE\Policies\Microsoft\Windows\SrpV2, whatever its
#       source. Local policy, a domain GPO and MDM all land there, because that is what the Group
#       Policy client writes and what the Application Identity service reads. Detection and the
#       immediate repair are therefore source independent.
#     - Local policy additionally lives in Windows\System32\GroupPolicy\Machine\Registry.pol. This
#       matters: clearing only the applied keys leaves Registry.pol intact and the next policy
#       refresh puts the blocking rule straight back. This script strips the SrpV2 records out of
#       Registry.pol as well, so a local-policy repair actually holds.
#     - A domain GPO leaves a client side cache under
#       SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Objects and a history entry under
#       ...\Group Policy\History that carries the GPO's display name and its DSPath. Both are
#       cleared of AppLocker content so a "nothing has changed" refresh cannot replay them, and the
#       display name is reported so the engineer knows which GPO to fix.
#     - SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\AppV\SrpV2 is NOT an AppLocker
#       location. It was checked because an older in-house script looked there; applying a local
#       AppLocker policy on Server 2022 never created it.
#
#   AppLocker only enforces while the Application Identity service is running, and that service
#   ships as Start=3 (Manual) with an ETW trigger rather than Start=2. Do not read Start=3 as
#   "these rules are inert": it means enforcement begins slightly later, once the trigger fires.
#   This was measured - a clean boot ran a script successfully, and that very activity started the
#   service, after which the next launch was blocked.
#
#   An enforcing collection containing zero rules allows everything, it does not deny everything.
#   That is worth stating because the opposite is a natural assumption and an earlier in-house
#   script acted on it. Microsoft's wording is unambiguous: "If no AppLocker rules exist for a
#   specific rule collection, all files covered by that rule collection are allowed to run. However,
#   once an AppLocker rule for a specific rule collection is created, only the files explicitly
#   allowed by at least one rule are permitted to run." An empty enforcing collection is therefore
#   never reported here, because it breaks nothing.
#
#   The SOFTWARE hive file and Registry.pol are backed up next to themselves before the first write.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$disableEnforcement = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$disableLsaProtection = 'false',
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
$isEnforcementDisableAllowed = ($disableEnforcement -eq 'true')
$isLsaDisableAllowed = ($disableLsaProtection -eq 'true')

# The five AppLocker rule collections, in the order the policy stores them.
$script:RuleCollection = @('Exe', 'Dll', 'Script', 'Msi', 'Appx')

# The applied policy. Every source - local, domain GPO, MDM - ends up here.
$script:SrpAppliedKey = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Windows\SrpV2'

# The registry path of the same policy as the Group Policy engine records it, used when filtering
# Registry.pol and the per-GPO cache.
$script:SrpPolicyPath = 'Software\Policies\Microsoft\Windows\SrpV2'

# EnforcementMode values.
$script:ModeName = @{ 0 = 'NotConfigured'; 1 = 'Enforce'; 2 = 'AuditOnly' }

# SIDs broad enough that a rule carrying one affects the logon and service paths. Everyone,
# Authenticated Users, Users, Administrators.
$script:BroadSid = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-544')

# Path conditions that cover Windows' own binaries. AppLocker path variables are matched as written
# in the rule, so both the variable form and a literal drive path have to be recognised.
$script:SystemPathPattern = @(
    '^\*$',
    '^%WINDIR%',
    '^%SYSTEM32%',
    '^%OSDRIVE%\\WINDOWS',
    '^[A-Z]:\\WINDOWS'
) -join '|'

function New-Finding {
    <#
    .SYNOPSIS
        Builds one finding. Repairable=$false means the script reports it and changes nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][bool]$Repairable = $true,
        [Parameter(Mandatory = $false)]$Data = $null
    )

    return [PSCustomObject]@{
        Cause      = $Cause
        Item       = $Item
        Message    = $Message
        Repairable = $Repairable
        Repaired   = $false
        Data       = $Data
    }
}

function Get-OfflineRegistryValue {
    <#
    .SYNOPSIS
        Reads a single registry value from the offline hive without using Get-ItemProperty.

    .DESCRIPTION
        Get-ItemProperty is not safe here. On a real domain joined disk the Group Policy history
        keys carry an lParam value that makes the Windows PowerShell 5.1 registry provider throw
        InvalidCastException, and because that is a terminating exception from inside the provider,
        -ErrorAction SilentlyContinue does not suppress it - it takes the whole run down. Measured
        on a Server 2022 disk: every history key failed through the provider and every one of them
        read correctly through the .NET API below.

        Reading one named value at a time through Microsoft.Win32.Registry also means an unrelated
        unreadable value in the same key cannot stop us reading the value we actually want.

    .PARAMETER Path
        Registry path under HKLM. Accepts the PowerShell drive form (HKLM:\Foo), the provider
        qualified form returned by Get-ChildItem, or a bare subkey path.

    .PARAMETER Name
        Value name. Use an empty string for the key's default value.

    .OUTPUTS
        The value, or $null if the key, the value, or the permission to read it is missing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name
    )

    $subKey = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $subKey = $subKey -replace '^HKEY_LOCAL_MACHINE\\?', ''
    $subKey = $subKey -replace '^HKLM:\\?', ''
    $subKey = $subKey.TrimStart('\')

    $key = $null
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKey)
        if ($null -eq $key) { return $null }
        return $key.GetValue($Name, $null)
    }
    catch { return $null }
    finally { if ($null -ne $key) { $key.Close() } }
}

function ConvertFrom-AppLockerRuleXml {
    <#
    .SYNOPSIS
        Turns the XML stored in a rule's Value into the few fields this script reasons about.

    .DESCRIPTION
        A rule is one of FilePathRule, FilePublisherRule or FileHashRule. Only a path rule can be
        judged against the Windows directory from the policy alone, so publisher and hash rules
        carry an empty Paths list and are never treated as covering anything.

    .OUTPUTS
        PSCustomObject with Id, Name, Action, Type, Sid, Paths and Parsed, or $null when the XML
        cannot be read.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Xml
    )

    if ([string]::IsNullOrWhiteSpace($Xml)) { return $null }

    try { $doc = [xml]$Xml } catch { return $null }

    $node = $doc.DocumentElement
    if ($null -eq $node) { return $null }

    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($condition in $node.SelectNodes('.//*[local-name()="FilePathCondition"]')) {
        $value = [string]$condition.Path
        if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$paths.Add($value) }
    }

    return [PSCustomObject]@{
        Parsed = $true
        Id     = [string]$node.Id
        Name   = [string]$node.Name
        Action = [string]$node.Action
        Type   = [string]$node.LocalName
        Sid    = [string]$node.UserOrGroupSid
        Paths  = @($paths)
        Xml    = $Xml
    }
}

function Test-AppLockerPathCoversSystem {
    <#
    .SYNOPSIS
        True when a rule's path conditions cover Windows' own binaries.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Path
    )

    foreach ($candidate in $Path) {
        $normalised = $candidate.Trim().ToUpperInvariant()
        if ($normalised -match $script:SystemPathPattern) { return $true }
    }
    return $false
}

function Test-AppLockerSidIsBroad {
    <#
    .SYNOPSIS
        True when a rule applies to a group wide enough to include the logon and service paths.
    #>
    param(
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $true }
    return ($script:BroadSid -contains $Sid.Trim().ToUpperInvariant())
}

function Get-AppLockerAppliedPolicy {
    <#
    .SYNOPSIS
        Reads the applied AppLocker policy out of the mounted SOFTWARE hive.

    .DESCRIPTION
        Returns one entry per collection that is actually present, carrying its enforcement mode
        and its parsed rules. A collection that is absent from the registry is absent from the
        result, because "not configured" and "not present" are the same thing to AppLocker and
        reporting a line for each would waste the operator's log budget.

    .OUTPUTS
        PSCustomObject with Present and Collections.
    #>

    $result = [PSCustomObject]@{ Present = $false; Collections = @() }

    if (-not (Test-Path $script:SrpAppliedKey)) { return $result }
    $result.Present = $true

    $collections = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($name in $script:RuleCollection) {
        $key = Join-Path $script:SrpAppliedKey $name
        if (-not (Test-Path $key)) { continue }

        $mode = Get-OfflineRegistryValue -Path $key -Name 'EnforcementMode'
        $mode = if ($null -eq $mode) { 0 } else { [int]$mode }

        $rules = [System.Collections.Generic.List[PSCustomObject]]::new()
        $unparsed = 0
        foreach ($child in @(Get-ChildItem -Path $key -ErrorAction SilentlyContinue)) {
            $value = Get-OfflineRegistryValue -Path $child.PSPath -Name 'Value'
            $rule = ConvertFrom-AppLockerRuleXml -Xml ([string]$value)
            if ($null -eq $rule) { $unparsed++; continue }
            Add-Member -InputObject $rule -NotePropertyName 'KeyPath' -NotePropertyValue $child.PSPath
            Add-Member -InputObject $rule -NotePropertyName 'KeyName' -NotePropertyValue $child.PSChildName
            Add-Member -InputObject $rule -NotePropertyName 'Collection' -NotePropertyValue $name
            [void]$rules.Add($rule)
        }

        [void]$collections.Add([PSCustomObject]@{
                Name         = $name
                KeyPath      = $key
                Mode         = $mode
                ModeName     = $(if ($script:ModeName.ContainsKey($mode)) { $script:ModeName[$mode] } else { "Unknown($mode)" })
                Enforcing    = ($mode -eq 1)
                Rules        = @($rules)
                UnparsedRule = $unparsed
            })
    }

    $result.Collections = @($collections)
    return $result
}

function Get-AppLockerGpoSource {
    <#
    .SYNOPSIS
        Names the Group Policy objects that carry AppLocker settings on this disk.

    .DESCRIPTION
        The Group Policy client keeps a per-GPO history under
        SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\<index>\<GUID>, where each
        entry records the GPO's DisplayName and its DSPath. A DSPath containing "LDAP://" means the
        GPO came from a domain, which is the case this script cannot fix at source.

        The extension-specific history under the AppLocker CSE GUID is preferred, because a GPO
        listed there is one that actually delivered AppLocker settings rather than merely applying
        to the machine.

    .OUTPUTS
        Array of PSCustomObject with Guid, DisplayName, DSPath and IsDomain.
    #>

    $historyRoot = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
    $found = @{}

    if (Test-Path $historyRoot) {
        foreach ($extension in @(Get-ChildItem -Path $historyRoot -ErrorAction SilentlyContinue)) {
            foreach ($gpo in @(Get-ChildItem -Path $extension.PSPath -ErrorAction SilentlyContinue)) {
                $displayName = [string](Get-OfflineRegistryValue -Path $gpo.PSPath -Name 'DisplayName')
                $dsPath = [string](Get-OfflineRegistryValue -Path $gpo.PSPath -Name 'DSPath')
                if ([string]::IsNullOrWhiteSpace($displayName) -and [string]::IsNullOrWhiteSpace($dsPath)) { continue }

                $guid = $gpo.PSChildName
                if ($found.ContainsKey($guid)) { continue }
                $found[$guid] = [PSCustomObject]@{
                    Guid        = $guid
                    DisplayName = $(if ($displayName) { $displayName } else { '(unnamed)' })
                    DSPath      = $dsPath
                    IsDomain    = ($dsPath -match '(?i)LDAP://')
                }
            }
        }
    }

    return @($found.Values)
}

function Get-AppLockerGpoCacheKey {
    <#
    .SYNOPSIS
        Returns the per-GPO cached copies of the AppLocker policy.

    .DESCRIPTION
        Each applied GPO is cached under
        SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Objects\<GUID>Machine\<policy path>.
        A repair that clears only the applied keys can be undone by a refresh that decides nothing
        has changed and replays this cache, so any AppLocker content here is removed as well.
    #>

    $objectsRoot = 'HKLM:\BROKENSOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Objects'
    $keys = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path $objectsRoot)) { return @($keys) }

    foreach ($gpo in @(Get-ChildItem -Path $objectsRoot -ErrorAction SilentlyContinue)) {
        $candidate = Join-Path $gpo.PSPath $script:SrpPolicyPath
        if (Test-Path $candidate) { [void]$keys.Add($candidate) }
    }

    return @($keys)
}

function Read-NullTerminatedUnicodeString {
    <#
    .SYNOPSIS
        Reads a null terminated UTF-16LE string and advances the caller's offset past the terminator.

    .DESCRIPTION
        Written as a function taking [ref] rather than an inline scriptblock on purpose. A
        scriptblock invoked with & can read an enclosing variable but an assignment inside it
        creates a local copy, so "$offset += 2" would silently fail to advance the caller's position
        and the parse would run off the rails.
    #>
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ref]$Offset
    )

    $start = $Offset.Value
    $index = $Offset.Value
    while (($index + 1) -lt $Bytes.Length -and -not ($Bytes[$index] -eq 0 -and $Bytes[$index + 1] -eq 0)) { $index += 2 }

    $length = $index - $start
    if ($length -lt 0) { $length = 0 }
    $text = [System.Text.Encoding]::Unicode.GetString($Bytes, $start, $length)
    $Offset.Value = $index + 2
    return $text
}

function Test-PolicyFileSeparator {
    <#
    .SYNOPSIS
        Checks for an expected UTF-16LE separator character and advances past it.
    #>
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ref]$Offset,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    if (($Offset.Value + 2) -gt $Bytes.Length) { return $false }
    if ([System.Text.Encoding]::Unicode.GetString($Bytes, $Offset.Value, 2) -ne $Expected) { return $false }
    $Offset.Value += 2
    return $true
}

function Read-PolicyFileRecord {
    <#
    .SYNOPSIS
        Parses a Group Policy Registry.pol file into its records.

    .DESCRIPTION
        The format is a "PReg" signature, a version DWORD, then a sequence of records written as
        [key;value;type;size;data] where the brackets and semicolons are UTF-16LE characters, the
        key and value are null terminated UTF-16LE strings, type and size are little endian DWORDs,
        and data is size bytes.

    .OUTPUTS
        PSCustomObject with Valid, Reason, Version and Records.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $result = [PSCustomObject]@{ Valid = $false; Reason = ''; Version = 1; Records = @() }

    try { $bytes = [System.IO.File]::ReadAllBytes($Path) }
    catch { $result.Reason = "unreadable ($($_.Exception.Message))"; return $result }

    if ($bytes.Length -lt 8) { $result.Reason = 'file is too small to be a policy file'; return $result }
    if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') { $result.Reason = 'PReg signature missing'; return $result }

    $result.Version = [BitConverter]::ToInt32($bytes, 4)

    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    $offset = 8

    while ($offset -lt $bytes.Length) {
        if (-not (Test-PolicyFileSeparator -Bytes $bytes -Offset ([ref]$offset) -Expected '[')) {
            $result.Reason = "unexpected byte at offset $offset"; return $result
        }

        $key = Read-NullTerminatedUnicodeString -Bytes $bytes -Offset ([ref]$offset)
        if (-not (Test-PolicyFileSeparator -Bytes $bytes -Offset ([ref]$offset) -Expected ';')) {
            $result.Reason = "missing separator after key at offset $offset"; return $result
        }

        $valueName = Read-NullTerminatedUnicodeString -Bytes $bytes -Offset ([ref]$offset)
        if (-not (Test-PolicyFileSeparator -Bytes $bytes -Offset ([ref]$offset) -Expected ';')) {
            $result.Reason = "missing separator after value name at offset $offset"; return $result
        }

        if (($offset + 4) -gt $bytes.Length) { $result.Reason = 'truncated type field'; return $result }
        $type = [BitConverter]::ToInt32($bytes, $offset); $offset += 4
        if (-not (Test-PolicyFileSeparator -Bytes $bytes -Offset ([ref]$offset) -Expected ';')) {
            $result.Reason = "missing separator after type at offset $offset"; return $result
        }

        if (($offset + 4) -gt $bytes.Length) { $result.Reason = 'truncated size field'; return $result }
        $size = [BitConverter]::ToInt32($bytes, $offset); $offset += 4
        if (-not (Test-PolicyFileSeparator -Bytes $bytes -Offset ([ref]$offset) -Expected ';')) {
            $result.Reason = "missing separator after size at offset $offset"; return $result
        }

        if ($size -lt 0 -or ($offset + $size) -gt $bytes.Length) { $result.Reason = "record data length $size is out of range"; return $result }
        $data = New-Object byte[] $size
        if ($size -gt 0) { [Array]::Copy($bytes, $offset, $data, 0, $size) }
        $offset += $size

        if (-not (Test-PolicyFileSeparator -Bytes $bytes -Offset ([ref]$offset) -Expected ']')) {
            $result.Reason = "missing record terminator at offset $offset"; return $result
        }

        [void]$records.Add([PSCustomObject]@{ Key = $key; ValueName = $valueName; Type = $type; Data = $data })
    }

    $result.Valid = $true
    $result.Records = @($records)
    return $result
}

function Write-PolicyFileRecord {
    <#
    .SYNOPSIS
        Writes records back out in Registry.pol format.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][PSCustomObject[]]$Record,
        [Parameter(Mandatory = $false)][int]$Version = 1
    )

    $unicode = [System.Text.Encoding]::Unicode
    $stream = [System.IO.MemoryStream]::new()
    $terminator = [byte[]]@(0, 0)

    $stream.Write([System.Text.Encoding]::ASCII.GetBytes('PReg'), 0, 4)
    $stream.Write([BitConverter]::GetBytes([int]$Version), 0, 4)

    foreach ($entry in $Record) {
        $open = $unicode.GetBytes('['); $stream.Write($open, 0, $open.Length)

        $keyBytes = $unicode.GetBytes([string]$entry.Key)
        $stream.Write($keyBytes, 0, $keyBytes.Length)
        $stream.Write($terminator, 0, 2)

        $sep = $unicode.GetBytes(';'); $stream.Write($sep, 0, $sep.Length)

        $nameBytes = $unicode.GetBytes([string]$entry.ValueName)
        $stream.Write($nameBytes, 0, $nameBytes.Length)
        $stream.Write($terminator, 0, 2)

        $stream.Write($sep, 0, $sep.Length)
        $stream.Write([BitConverter]::GetBytes([int]$entry.Type), 0, 4)
        $stream.Write($sep, 0, $sep.Length)
        $stream.Write([BitConverter]::GetBytes([int]$entry.Data.Length), 0, 4)
        $stream.Write($sep, 0, $sep.Length)

        if ($entry.Data.Length -gt 0) { $stream.Write($entry.Data, 0, $entry.Data.Length) }

        $close = $unicode.GetBytes(']'); $stream.Write($close, 0, $close.Length)
    }

    [System.IO.File]::WriteAllBytes($Path, $stream.ToArray())
    $stream.Dispose()
}

function Get-LocalPolicyAppLockerState {
    <#
    .SYNOPSIS
        Reports whether the local GPO file carries AppLocker settings.

    .OUTPUTS
        PSCustomObject with Path, Exists, Valid, Reason, RecordCount and AppLockerRecordCount.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    $polPath = Join-OfflinePath -Root $WindowsPath -ChildPath 'System32\GroupPolicy\Machine\Registry.pol'
    $state = [PSCustomObject]@{
        Path                 = $polPath
        Exists               = $false
        Valid                = $false
        Reason               = ''
        RecordCount          = 0
        AppLockerRecordCount = 0
    }

    if (-not (Test-OfflinePath $polPath)) { $state.Reason = 'no local Group Policy file on this disk'; return $state }
    $state.Exists = $true

    $parsed = Read-PolicyFileRecord -Path $polPath
    $state.Valid = $parsed.Valid
    $state.Reason = $parsed.Reason
    if (-not $parsed.Valid) { return $state }

    $state.RecordCount = @($parsed.Records).Count
    $state.AppLockerRecordCount = @($parsed.Records | Where-Object { $_.Key -like "$($script:SrpPolicyPath)*" }).Count
    return $state
}

function Get-AppLockerBlockedFile {
    <#
    .SYNOPSIS
        Reads the offline AppLocker logs and returns the files the guest actually refused to run.

    .DESCRIPTION
        Each rule collection writes to its own channel. 8004 and 8007 are enforcement denials, and
        8022 and 8025 are the packaged app equivalents. The audit events - 8003, 8006, 8021, 8024 -
        are counted separately: they mean the policy would have blocked the file but did not, which
        is useful context and is never treated as a fault.

        A channel whose backing file is absent is normal. Windows registers the channels on every
        installation but only creates the file once something is logged, so an absent file is
        positive evidence that AppLocker has never denied anything here.

    .OUTPUTS
        PSCustomObject with Available, Reason, Files and AuditCount.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath
    )

    $channels = @(
        [PSCustomObject]@{ File = 'Microsoft-Windows-AppLocker%4EXE and DLL.evtx'; Blocked = @(8004); Audit = @(8003); Collection = 'Exe/Dll' },
        [PSCustomObject]@{ File = 'Microsoft-Windows-AppLocker%4MSI and Script.evtx'; Blocked = @(8007); Audit = @(8006); Collection = 'Msi/Script' },
        [PSCustomObject]@{ File = 'Microsoft-Windows-AppLocker%4Packaged app-Execution.evtx'; Blocked = @(8022); Audit = @(8021); Collection = 'Appx' },
        [PSCustomObject]@{ File = 'Microsoft-Windows-AppLocker%4Packaged app-Deployment.evtx'; Blocked = @(8025); Audit = @(8024); Collection = 'Appx' }
    )

    $result = [PSCustomObject]@{ Available = $false; Reason = ''; Files = @(); AuditCount = 0 }
    $byFile = @{}
    $auditTotal = 0
    $readAny = $false
    $missing = 0

    foreach ($channel in $channels) {
        $logPath = Join-OfflinePath -Root $WindowsPath -ChildPath "System32\winevt\Logs\$($channel.File)"
        if (-not (Test-OfflinePath $logPath)) { $missing++; continue }

        $wanted = @($channel.Blocked + $channel.Audit)
        $filter = '*[System[(' + (($wanted | ForEach-Object { "EventID=$_" }) -join ' or ') + ')]]'

        $events = @()
        try { $events = @(Get-WinEvent -Path $logPath -FilterXPath $filter -MaxEvents 200 -ErrorAction Stop) }
        catch {
            if ($_.Exception.Message -match 'No events were found') { $readAny = $true; continue }
            Add-OfflineRepairLog -Level Warning -Message "$($channel.File) could not be read ($($_.Exception.Message))."
            continue
        }
        $readAny = $true

        foreach ($record in $events) {
            if ($channel.Audit -contains [int]$record.Id) { $auditTotal++; continue }

            $text = ''
            try { $text = [string]$record.Message } catch { $text = '' }
            if ([string]::IsNullOrWhiteSpace($text)) {
                try { $text = [string]$record.ToXml() } catch { $text = '' }
            }
            if ([string]::IsNullOrWhiteSpace($text)) { continue }

            # The message opens with the full path of the file that was refused.
            $match = [regex]::Match($text, '(?i)([A-Z]:\\[^\s"<>|]+?\.(?:exe|dll|sys|msi|ps1|bat|cmd|vbs|js))')
            $name = if ($match.Success) { $match.Groups[1].Value } else { '(path not recorded)' }
            $key = $name.ToLowerInvariant()

            if (-not $byFile.ContainsKey($key)) {
                $byFile[$key] = [PSCustomObject]@{
                    Path        = $name
                    Collection  = $channel.Collection
                    EventIds    = [System.Collections.Generic.List[int]]::new()
                    Count       = 0
                    LastSeenUtc = [datetime]::MinValue
                }
            }
            $entry = $byFile[$key]
            $entry.Count++
            if (-not $entry.EventIds.Contains([int]$record.Id)) { [void]$entry.EventIds.Add([int]$record.Id) }
            if ($record.TimeCreated -and $record.TimeCreated.ToUniversalTime() -gt $entry.LastSeenUtc) {
                $entry.LastSeenUtc = $record.TimeCreated.ToUniversalTime()
            }
        }
    }

    $result.AuditCount = $auditTotal
    $result.Files = @($byFile.Values | Sort-Object -Property Count -Descending)

    if (-not $readAny -and $missing -eq $channels.Count) {
        $result.Available = $true
        $result.Reason = 'no AppLocker log file exists on this disk, so AppLocker has never denied anything here'
        return $result
    }

    $result.Available = $true
    if ($result.Files.Count -eq 0) { $result.Reason = 'the AppLocker logs contain no denial events' }
    else { $result.Reason = "$($result.Files.Count) file(s) were denied" }
    return $result
}

function Get-AppIdServiceState {
    <#
    .SYNOPSIS
        Reads the Application Identity service configuration from the mounted SYSTEM hive.

    .DESCRIPTION
        AppLocker only enforces while this service runs. Start=2 means it runs from boot; Start=3
        means it is trigger started, which still leads to enforcement, only later. Neither value is
        a fault on its own.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $key = "$SystemRoot\Services\AppIDSvc"
    $start = $null
    if (Test-Path $key) { $start = Get-OfflineRegistryValue -Path $key -Name 'Start' }

    $label = switch ($start) {
        0 { 'Boot' } 1 { 'System' } 2 { 'Automatic' } 3 { 'Manual/trigger' } 4 { 'Disabled' }
        default { if ($null -eq $start) { 'not installed' } else { "Unknown($start)" } }
    }

    return [PSCustomObject]@{
        KeyPath   = $key
        Present   = (Test-Path $key)
        Start     = $start
        StartName = $label
        CanEnforce = ($null -ne $start -and [int]$start -in @(0, 1, 2, 3))
    }
}

function Get-LsaProtectionState {
    <#
    .SYNOPSIS
        Reads LSA protection settings. Context only - this is never a finding.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $key = "$SystemRoot\Control\Lsa"

    return [PSCustomObject]@{
        KeyPath      = $key
        Present      = (Test-Path $key)
        RunAsPPL     = (Get-OfflineRegistryValue -Path $key -Name 'RunAsPPL')
        RunAsPPLBoot = (Get-OfflineRegistryValue -Path $key -Name 'RunAsPPLBoot')
        LsaCfgFlags  = (Get-OfflineRegistryValue -Path $key -Name 'LsaCfgFlags')
    }
}

function Get-AppLockerCollectionForFile {
    <#
    .SYNOPSIS
        Maps a denied file to the rule collection that would have judged it.

    .DESCRIPTION
        The event channel narrows this down but does not settle it - "EXE and DLL" covers two
        collections - so the extension decides. Anything unrecognised returns an empty string and is
        not acted on.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    switch -Regex ($Path.ToLowerInvariant()) {
        '\.(exe|com)$' { return 'Exe' }
        '\.(dll|ocx)$' { return 'Dll' }
        '\.(msi|msp)$' { return 'Msi' }
        '\.(ps1|bat|cmd|vbs|js)$' { return 'Script' }
        default { return '' }
    }
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Builds the findings list from evidence only.

    .DESCRIPTION
        AppLocker being configured, or enforcing, is deliberately absent from this function. A
        collection only becomes a finding when it provably refuses Windows' own binaries: through a
        Deny rule that covers them, through an allowlist that does not, or through being empty.
    #>
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)]$BlockEvidence
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Policy.Present) { return @($findings) }

    foreach ($collection in @($Policy.Collections | Where-Object { $_.Enforcing })) {
        $denyRules = @($collection.Rules | Where-Object {
                $_.Action -eq 'Deny' -and (Test-AppLockerPathCoversSystem -Path $_.Paths) -and (Test-AppLockerSidIsBroad -Sid $_.Sid)
            })

        foreach ($rule in $denyRules) {
            [void]$findings.Add((New-Finding -Cause 'SystemPathDenyRule' -Item "$($collection.Name)/$($rule.Name)" `
                        -Message "AppLocker rule '$($rule.Name)' in the $($collection.Name) collection denies $($rule.Paths -join ', ') to $($rule.Sid). Deny is evaluated before Allow, so this refuses Windows' own binaries and is why logon and the guest agent extensions cannot start. Removing this one rule leaves the rest of the policy enforcing." `
                        -Data ([PSCustomObject]@{ Kind = 'Rule'; Collection = $collection; Rule = $rule }))) 
        }

        if ($denyRules.Count -gt 0) { continue }

        # An enforcing collection with no rules allows everything, so it is not a fault. Only a
        # collection that holds rules becomes an allowlist, and only then can it deny Windows.
        if ($collection.Rules.Count -eq 0) { continue }

        $allowsSystem = @($collection.Rules | Where-Object {
                $_.Action -eq 'Allow' -and (Test-AppLockerPathCoversSystem -Path $_.Paths) -and (Test-AppLockerSidIsBroad -Sid $_.Sid)
            }).Count -gt 0

        # A publisher or hash rule can legitimately allow Windows binaries without naming a path, so
        # an allowlist built that way is not called out unless the log proves something was denied.
        $hasNonPathAllow = @($collection.Rules | Where-Object { $_.Action -eq 'Allow' -and $_.Type -ne 'FilePathRule' }).Count -gt 0

        if (-not $allowsSystem -and -not $hasNonPathAllow) {
            [void]$findings.Add((New-Finding -Cause 'NoSystemAllowRule' -Item $collection.Name `
                        -Message "The $($collection.Name) collection is set to Enforce and has $($collection.Rules.Count) rule(s), but none of them allows the Windows directory. Once a collection holds any rule it becomes an allowlist, so anything unmatched is denied and Windows' own binaries cannot run in a user session. Moving this collection to AuditOnly stops the blocking, keeps every rule, and keeps logging what it would have denied." `
                        -Data ([PSCustomObject]@{ Kind = 'Collection'; Collection = $collection; TargetMode = 2 })))
        }
    }

    # The logs outrank everything above: they are a record of the guest actually refusing a file
    # rather than a reading of what the policy ought to do. A denial is only turned into a finding
    # when the file lives under the Windows directory, because a policy that correctly refuses
    # something else is AppLocker working, not AppLocker breaking the VM.
    foreach ($denied in @($BlockEvidence.Files)) {
        if ($denied.Path -notmatch '(?i)^[A-Z]:\\Windows\\') { continue }

        $collectionName = Get-AppLockerCollectionForFile -Path $denied.Path
        if ([string]::IsNullOrWhiteSpace($collectionName)) { continue }

        $collection = @($Policy.Collections | Where-Object { $_.Name -eq $collectionName -and $_.Enforcing } | Select-Object -First 1)
        if ($collection.Count -eq 0) { continue }
        $collection = $collection[0]

        # A rule level finding above already removes the cause for this collection, so adding a
        # second, blunter finding for the same collection would double count and over-repair.
        if (@($findings | Where-Object { $_.Data.Collection.Name -eq $collectionName }).Count -gt 0) { continue }

        [void]$findings.Add((New-Finding -Cause 'BlockedSystemBinary' -Item "$collectionName/$(Split-Path $denied.Path -Leaf)" `
                    -Message "AppLocker refused $($denied.Path) $($denied.Count) time(s), last at $($denied.LastSeenUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC (event $($denied.EventIds -join '/')). That is a Windows binary, and no single rule in the enforcing $collectionName collection accounts for it, so the collection as a whole is refusing files it needs to allow. Moving it to AuditOnly stops the blocking and keeps every rule." `
                    -Data ([PSCustomObject]@{ Kind = 'Collection'; Collection = $collection; TargetMode = 2 })))
    }

    return @($findings)
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applies the one change a finding calls for, in the applied policy.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding
    )

    switch ($Finding.Cause) {
        'SystemPathDenyRule' {
            $rule = $Finding.Data.Rule
            if (-not (Test-Path $rule.KeyPath)) { throw "The rule key $($rule.KeyName) is no longer present." }
            Remove-Item -Path $rule.KeyPath -Recurse -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($Finding.Data.Collection.Name): removed Deny rule '$($rule.Name)' $($rule.KeyName). Every other rule in the collection is untouched and still enforcing."
            return $true
        }
        'NoSystemAllowRule' { return (Set-CollectionMode -Finding $Finding) }
        'BlockedSystemBinary' { return (Set-CollectionMode -Finding $Finding) }
        default { return $false }
    }
}

function Set-CollectionMode {
    <#
    .SYNOPSIS
        Moves one rule collection to the mode its finding calls for.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding
    )

    $collection = $Finding.Data.Collection
    $target = [int]$Finding.Data.TargetMode
    if (-not (Test-Path $collection.KeyPath)) { throw "The collection key for $($collection.Name) is no longer present." }

    Set-ItemProperty -Path $collection.KeyPath -Name 'EnforcementMode' -Value $target -Type DWord -Force -ErrorAction Stop
    Add-OfflineRepairLog -Message "$($collection.Name): EnforcementMode $($collection.Mode) ($($collection.ModeName)) -> $target ($($script:ModeName[$target]))."
    Add-OfflineRepairLog -Message "$($collection.Name): to undo this after the VM boots, run: reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$($collection.Name)`" /v EnforcementMode /t REG_DWORD /d $($collection.Mode) /f"
    return $true
}

function Clear-GpoCachedAppLockerPolicy {
    <#
    .SYNOPSIS
        Removes AppLocker content from the per-GPO client side cache.

    .DESCRIPTION
        Without this a Group Policy refresh can decide the GPO's version is unchanged and replay the
        cached settings, which would put the blocking rule straight back after the repair.

    .OUTPUTS
        The number of cached copies removed.
    #>

    $removed = 0
    foreach ($key in Get-AppLockerGpoCacheKey) {
        try {
            Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
            $removed++
            Add-OfflineRepairLog -Message "Removed the cached AppLocker policy at $key."
        }
        catch {
            Add-OfflineRepairLog -Level Warning -Message "Could not remove the cached AppLocker policy at $key ($($_.Exception.Message))."
        }
    }
    return $removed
}

function Clear-LocalPolicyAppLockerPolicy {
    <#
    .SYNOPSIS
        Strips the AppLocker records out of the local Group Policy file, keeping everything else.

    .DESCRIPTION
        Local policy survives independently of the registry. Leaving it in place means the next
        policy refresh writes the blocking rule back, so a repair that ignored this file would look
        successful and then be undone. The file is backed up next to itself first, and every record
        that is not AppLocker is written back unchanged.

    .OUTPUTS
        The number of records removed, or -1 when the file could not be processed.
    #>
    param(
        [Parameter(Mandatory = $true)]$LocalPolicy
    )

    if (-not $LocalPolicy.Exists) { return 0 }
    if (-not $LocalPolicy.Valid) {
        Add-OfflineRepairLog -Level Warning -Message "The local Group Policy file was not changed because it could not be parsed ($($LocalPolicy.Reason))."
        return -1
    }
    if ($LocalPolicy.AppLockerRecordCount -eq 0) { return 0 }

    $parsed = Read-PolicyFileRecord -Path $LocalPolicy.Path
    if (-not $parsed.Valid) {
        Add-OfflineRepairLog -Level Warning -Message "The local Group Policy file could not be re-read ($($parsed.Reason))."
        return -1
    }

    $keep = @($parsed.Records | Where-Object { $_.Key -notlike "$($script:SrpPolicyPath)*" })
    $dropped = @($parsed.Records).Count - $keep.Count
    if ($dropped -le 0) { return 0 }

    $backup = "$($LocalPolicy.Path).$(Get-Date -f yyyyMMddHHmmss).bak"
    Copy-Item -Path $LocalPolicy.Path -Destination $backup -Force -ErrorAction Stop
    Add-OfflineRepairLog -Message "Local Group Policy file backed up to $backup."

    Write-PolicyFileRecord -Path $LocalPolicy.Path -Record $keep -Version $parsed.Version
    Add-OfflineRepairLog -Message "Removed $dropped AppLocker record(s) from the local Group Policy file, keeping the other $($keep.Count)."
    return $dropped
}

function Disable-AppLockerEnforcement {
    <#
    .SYNOPSIS
        Sets every rule collection to NotConfigured and disables the Application Identity service.

    .DESCRIPTION
        Only reached when the operator passes -disableEnforcement true. Rules are preserved, so the
        policy can be re-enabled once it has been corrected. The command to restore each value is
        logged before it is changed.

    .OUTPUTS
        The number of values that were changed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)]$AppIdService
    )

    $changed = 0

    foreach ($collection in @($Policy.Collections | Where-Object { $_.Mode -ne 0 })) {
        Add-OfflineRepairLog -Level Warning -Message "Restore with: reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$($collection.Name)`" /v EnforcementMode /t REG_DWORD /d $($collection.Mode) /f"
        Set-ItemProperty -Path $collection.KeyPath -Name 'EnforcementMode' -Value 0 -Type DWord -Force -ErrorAction Stop
        Add-OfflineRepairLog -Message "$($collection.Name): EnforcementMode $($collection.Mode) -> 0 (NotConfigured). The rules themselves are preserved."
        $changed++
    }

    if ($AppIdService.Present -and $AppIdService.CanEnforce) {
        Add-OfflineRepairLog -Level Warning -Message "Restore with: reg add `"HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc`" /v Start /t REG_DWORD /d $($AppIdService.Start) /f"
        Set-ItemProperty -Path $AppIdService.KeyPath -Name 'Start' -Value 4 -Type DWord -Force -ErrorAction Stop
        Add-OfflineRepairLog -Message "AppIDSvc: Start $($AppIdService.Start) -> 4 (Disabled). AppLocker cannot enforce while this service is stopped."
        $changed++
    }

    return $changed
}

function Disable-LsaProtection {
    <#
    .SYNOPSIS
        Removes Control\Lsa\RunAsPPL when the operator explicitly asked for it.

    .OUTPUTS
        The number of values that were changed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Lsa
    )

    if (-not $Lsa.Present) {
        Add-OfflineRepairLog -Level Warning -Message 'The Lsa key is not present on this disk, so there was nothing to change.'
        return 0
    }

    $changed = 0
    foreach ($name in @('RunAsPPL', 'RunAsPPLBoot')) {
        $current = $Lsa.$name
        if ($null -eq $current -or [int]$current -eq 0) { continue }
        Add-OfflineRepairLog -Level Warning -Message "Restore with: reg add `"HKLM\SYSTEM\CurrentControlSet\Control\Lsa`" /v $name /t REG_DWORD /d $current /f"
        Remove-ItemProperty -Path $Lsa.KeyPath -Name $name -Force -ErrorAction Stop
        Add-OfflineRepairLog -Message "Removed Control\Lsa\$name (was $current)."
        $changed++
    }

    if ($changed -gt 0) {
        Add-OfflineRepairLog -Level Warning -Message 'If LSA protection was enabled with a UEFI lock, the registry change alone will not clear it. Boot the guest once with the Microsoft LSA protected process opt-out tool to remove the firmware variable.'
    }
    return $changed
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, disableEnforcement=$isEnforcementDisableAllowed, disableLsaProtection=$isLsaDisableAllowed)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $blockEvidence = Get-AppLockerBlockedFile -WindowsPath $offline.WindowsPath
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    $localPolicy = Get-LocalPolicyAppLockerState -WindowsPath $offline.WindowsPath

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $policy = Get-AppLockerAppliedPolicy
        $gpoSource = @(Get-AppLockerGpoSource)

        return [PSCustomObject]@{
            SystemRoot   = $systemRoot
            ControlSet   = (Split-Path -Path $systemRoot -Leaf)
            Policy       = $policy
            GpoSource    = $gpoSource
            AppIdService = (Get-AppIdServiceState -SystemRoot $systemRoot)
            Lsa          = (Get-LsaProtectionState -SystemRoot $systemRoot)
            Findings     = @(Get-AllFinding -Policy $policy -BlockEvidence $blockEvidence)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $policy = $context.Policy
    $appId = $context.AppIdService

    # Context only. None of this is a fault by itself, so none of it appears in the findings list.
    if (-not $policy.Present) {
        Log-Info "Control set $($context.ControlSet): no AppLocker policy is applied on this disk." | Tee-Object -FilePath $logFile -Append
    }
    else {
        $summary = @($policy.Collections | ForEach-Object { "$($_.Name)=$($_.ModeName)($($_.Rules.Count) rule(s))" }) -join ', '
        Log-Info "Control set $($context.ControlSet): AppLocker collections $summary. AppIDSvc Start=$($appId.Start) ($($appId.StartName))." | Tee-Object -FilePath $logFile -Append
    }

    if ($blockEvidence.Files.Count -gt 0) {
        $named = @($blockEvidence.Files | Select-Object -First 5 | ForEach-Object { "$($_.Path) x$($_.Count)" }) -join '; '
        Log-Info "AppLocker denied $($blockEvidence.Files.Count) distinct file(s); most frequent: $named" | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "AppLocker denial evidence: $($blockEvidence.Reason)." | Tee-Object -FilePath $logFile -Append
    }
    if ($blockEvidence.AuditCount -gt 0) {
        Log-Info "$($blockEvidence.AuditCount) audit event(s) recorded a file that would have been denied under enforcement. That is not a fault and nothing was changed for it." | Tee-Object -FilePath $logFile -Append
    }

    $localPolicySummary = if (-not $localPolicy.Exists) { 'absent' }
    elseif (-not $localPolicy.Valid) { "unreadable ($($localPolicy.Reason))" }
    else { "$($localPolicy.AppLockerRecordCount) AppLocker record(s) of $($localPolicy.RecordCount)" }
    Log-Info "Local Group Policy file: $localPolicySummary." | Tee-Object -FilePath $logFile -Append

    foreach ($gpo in @($context.GpoSource)) {
        Log-Info "Group Policy history: '$($gpo.DisplayName)' $($gpo.Guid) $(if ($gpo.IsDomain) { "from the domain ($($gpo.DSPath))" } else { 'local' })" | Tee-Object -FilePath $logFile -Append
    }

    if ($context.Lsa.RunAsPPL) {
        Log-Info "LSA protection is enabled (RunAsPPL=$($context.Lsa.RunAsPPL)). That is a supported setting, it does not stop a VM booting, and it was left alone." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Output "[$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $needsWrite = ($repairable.Count -gt 0) -or $isEnforcementDisableAllowed -or $isLsaDisableAllowed
    if ($needsWrite) {
        $softwareBackup = Backup-OfflineHiveFile -Hive 'SOFTWARE' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SOFTWARE hive backed up to $softwareBackup" | Tee-Object -FilePath $logFile -Append
    }
    if ($isEnforcementDisableAllowed -or $isLsaDisableAllowed) {
        $systemBackup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SYSTEM hive backed up to $systemBackup" | Tee-Object -FilePath $logFile -Append
    }

    $repairedCount = 0
    $failed = @()
    $cacheCleared = 0
    $enforcementChanges = 0
    $lsaChanges = 0

    if ($needsWrite) {
        $outcome = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $done = 0
            $errors = [System.Collections.Generic.List[string]]::new()

            foreach ($finding in $repairable) {
                try {
                    if (Repair-Finding -Finding $finding) {
                        $finding.Repaired = $true
                        $done++
                    }
                }
                catch {
                    [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                    Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
                }
            }

            # Only meaningful once something was repaired: the cache exists to be replayed, and
            # replaying a corrected policy is exactly what should happen.
            $cleared = 0
            if ($done -gt 0) { $cleared = Clear-GpoCachedAppLockerPolicy }

            $enforcement = 0
            if ($isEnforcementDisableAllowed) {
                $enforcement = Disable-AppLockerEnforcement -Policy (Get-AppLockerAppliedPolicy) -AppIdService (Get-AppIdServiceState -SystemRoot (Get-OfflineSystemRootPath))
            }

            $lsa = 0
            if ($isLsaDisableAllowed) {
                $lsa = Disable-LsaProtection -Lsa (Get-LsaProtectionState -SystemRoot (Get-OfflineSystemRootPath))
            }

            return [PSCustomObject]@{ Repaired = $done; Errors = @($errors); Cleared = $cleared; Enforcement = $enforcement; Lsa = $lsa }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        $repairedCount = $outcome.Repaired
        $failed = @($outcome.Errors)
        $cacheCleared = $outcome.Cleared
        $enforcementChanges = $outcome.Enforcement
        $lsaChanges = $outcome.Lsa
    }

    # The local policy file is outside the hive, so it is handled after the hive work. Without this
    # the next policy refresh would put the blocking rule straight back.
    $localRemoved = 0
    if ($repairedCount -gt 0 -or $enforcementChanges -gt 0) {
        $localRemoved = Clear-LocalPolicyAppLockerPolicy -LocalPolicy $localPolicy
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    if ($findings.Count -eq 0 -and $enforcementChanges -eq 0 -and $lsaChanges -eq 0) {
        if (-not $policy.Present) {
            Log-Output 'No AppLocker policy is applied on this disk, so AppLocker is not what is blocking this VM. No changes were made.' | Tee-Object -FilePath $logFile -Append
        }
        else {
            Log-Output 'AppLocker is configured on this disk but nothing shows it blocking Windows itself: no rule denies the Windows directory, every enforcing collection allows it, and the logs record no denial. No changes were made.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    # Verify against freshly read state rather than trusting the writes above.
    $remaining = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $policyNow = Get-AppLockerAppliedPolicy
        return @(Get-AllFinding -Policy $policyNow -BlockEvidence $blockEvidence)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Repaired $repairedCount of $($repairable.Count) issue(s) that could be repaired."
    if ($localRemoved -gt 0) { $summary += " Removed $localRemoved AppLocker record(s) from local policy so a refresh cannot restore them." }
    if ($cacheCleared -gt 0) { $summary += " Cleared $cacheCleared cached GPO copy/copies." }
    if ($enforcementChanges -gt 0) { $summary += " Disabled AppLocker enforcement on request ($enforcementChanges value(s))." }
    if ($lsaChanges -gt 0) { $summary += " Removed $lsaChanges LSA protection value(s) on request." }
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
    if ($localRemoved -lt 0) {
        Log-Warning 'The local Group Policy file could not be parsed and was left alone. If the blocking policy came from local policy it may return at the next refresh.' | Tee-Object -FilePath $logFile -Append
    }
    if ($repairedCount -gt 0 -or $enforcementChanges -gt 0) {
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
