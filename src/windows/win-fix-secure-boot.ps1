#########################################################################################################
# .SYNOPSIS
#   Repairs the signed boot chain a Generation 2 VM starts through, when those files are stale,
#   corrupt or missing.
#
# .DESCRIPTION
#   A Gen2 VM starts by having its firmware run \EFI\Microsoft\Boot\bootmgfw.efi from the EFI System
#   Partition. That boot manager loads winload.efi, which loads ci.dll, the kernel and the Code
#   Integrity policy files. Every one of those is signed, and every one of them is checked before
#   the next is allowed to run.
#
#   When one of them is corrupt, or when the copy on the EFI System Partition is left behind by an
#   update that refreshed only the Windows partition, the chain stops. The usual result is
#   0xc0430001 - STATUS_ERROR_LOADING_REGISTRY, reported by winload before anything has started.
#   There is no event log to read afterwards, because nothing ever got far enough to write one.
#
#   Evidence used, in order:
#     1. The three artifacts on the EFI System Partition, compared by SHA256 against the copies
#        Windows keeps on its own partition. Windows stages the boot manager at
#        Windows\Boot\EFI\bootmgfw.efi and the Secure Boot policy at
#        Windows\System32\SecureBootUpdates\SKUSiPolicy.p7b, and servicing keeps those current. A
#        difference means the EFI System Partition is stale; an absence means the firmware has
#        nothing to run.
#     2. The boot chain files on the Windows partition, compared by SHA256 against the copies held
#        in the component store under Windows\WinSxS. A file that matches no copy in the store is
#        not the file Windows shipped.
#     3. The Secure Boot state the guest last booted with, read from the Measured Boot log. This
#        sets how serious a stale policy file is, and is reported either way.
#
#   Causes detected and repaired:
#     1. A missing or stale artifact on the EFI System Partition. Repaired by copying the current
#        file from the Windows partition, after backing up whatever was there.
#     2. A boot chain file on the Windows partition that matches no copy in the component store.
#        Repaired with a targeted "sfc /SCANFILE" against that one file, which sources the
#        replacement from the guest's own store and so is always the right build.
#
#   Reported but never repaired automatically:
#     - A file with no copy at all in the component store. Nothing can be verified against it and
#       nothing trustworthy can be put in its place, so it is reported with the path.
#     - A source file missing from the Windows partition when the EFI System Partition needs it.
#       Copying a boot manager from anywhere other than this installation is how a VM ends up
#       running a different build's loader, so the script stops and says what is missing.
#
# .RESOLVES
#   Gen2 boot failures in the loader, before the kernel starts and before any event log exists.
#   Typically 0xc0430001, a Secure Boot violation screen, or a VM that returns to the firmware boot
#   menu after an update that refreshed the Windows partition but not the EFI System Partition.
#
#   This script does NOT cover:
#     - A driver being refused once Windows is running. That leaves Code Integrity events behind
#       and is handled by win-fix-code-integrity.
#     - Boot configuration content - a missing, empty or wrong BCD store. Use win-fix-bcd.
#     - A missing or unreadable EFI System Partition itself, as opposed to stale files on a healthy
#       one. Use win-fix-boot-partition.
#     - Component store corruption in general. This script only ever touches the fixed list of boot
#       chain files below and never runs a full scan. If corruption is broader, use
#       win-sfc-sf-corruption.
#
# .PARAMETER detectOnly
#   'true' reports what is wrong and changes nothing at all. No file is written and sfc is never
#   invoked, because offline sfc repairs even when asked only to verify - see .NOTES.
#
# .PARAMETER revert
#   'true' puts back every file this script replaced, using the backups it took, and restores the
#   original state.
#
# .PARAMETER windowsDrive
#   Skips discovery and uses this drive letter as the offline Windows volume.
#
# .NOTES
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Offline "sfc /VERIFYFILE" REPAIRS, despite its own help text saying "No repair operation is
#   performed". Measured on a Server 2022 disk with winload.efi deliberately corrupted, /VERIFYFILE
#   logged "Cannot repair member file 'winload.efi' ... hash mismatch" and then "Repairing file
#   \??\C:\Windows\System32\winload.efi from store", rewriting both the store copy and the file. It
#   is therefore never used, and detection is done by hashing instead. That is also why sfc is not
#   run at all under -detectOnly.
#
#   sfc's exit code is 0 whether or not it found anything, and it writes UTF-16 to the console,
#   which is unreadable when captured. Only /OFFLOGFILE is parsed, for the [SR] lines.
#
#   The boot chain files are owned by NT SERVICE\TrustedInstaller and deny write even to SYSTEM, so
#   every write goes through Copy-OfflineProtectedFile, which captures the original security
#   descriptor, takes ownership only when a plain attempt was actually refused, and replays the
#   whole descriptor afterwards. A repaired guest boots with TrustedInstaller owning its system
#   files again.
#
#   The Secure Boot state cannot be read from an offline registry hive. Windows keeps it in
#   Control\SecureBoot\State, which is a volatile key: it is recreated from the firmware at every
#   boot and never written to the hive file. It is read from the Measured Boot log instead - see
#   Get-OfflineSecureBootState.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$revert = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = ''
)

. .\src\windows\common\setup\init.ps1
. .\src\windows\common\helpers\OfflineRepairCommon.ps1
. .\src\windows\common\helpers\Get-OfflineWindowsDisk.ps1
. .\src\windows\common\helpers\Use-OfflineProtectedResource.ps1

$scriptStartTime = Get-Date -f yyyyMMddHHmmss
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
$logFile = "$env:PUBLIC\Desktop\$($scriptName).log"

$isDetectOnly = ($detectOnly -eq 'true')
$isRevert = ($revert -eq 'true')

$script:BackupSuffix = ".$scriptName-backup-$scriptStartTime"
$script:BackupManifest = [System.Collections.Generic.List[PSCustomObject]]::new()

# The boot chain, in the order the firmware and the loader walk it. Optional entries are absent on
# healthy installations often enough that their absence is not a fault: winresume.efi only exists
# where hibernation was configured, and the Hyper-V loader only where virtualisation based security
# is in use. Everything else is present on every Gen2 Server image, so a missing one is a finding.
$script:BootChainFile = @(
    @{ RelativePath = 'Windows\Boot\EFI\bootmgfw.efi'; Label = 'Windows-staged boot manager'; Optional = $false }
    @{ RelativePath = 'Windows\System32\winload.efi'; Label = 'OS loader (winload.efi)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\winresume.efi'; Label = 'resume loader (winresume.efi)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\ci.dll'; Label = 'Code Integrity engine (ci.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\ntoskrnl.exe'; Label = 'NT kernel (ntoskrnl.exe)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\hal.dll'; Label = 'hardware abstraction layer (hal.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\kdcom.dll'; Label = 'kernel debug transport (kdcom.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\pshed.dll'; Label = 'platform hardware error driver (pshed.dll)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\drivers\clfs.sys'; Label = 'Common Log File System driver (clfs.sys)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\hvloader.dll'; Label = 'Hyper-V loader (hvloader.dll)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\hvix64.exe'; Label = 'Hyper-V hypervisor image (hvix64.exe)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\CodeIntegrity\SiPolicy.p7b'; Label = 'Code Integrity policy (SiPolicy.p7b)'; Optional = $true }
    @{ RelativePath = 'Windows\System32\CodeIntegrity\Driver.stl'; Label = 'driver revocation list (Driver.stl)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\CodeIntegrity\DriverSiPolicy.p7b'; Label = 'driver signing policy (DriverSiPolicy.p7b)'; Optional = $false }
    @{ RelativePath = 'Windows\System32\SecureBootUpdates\SKUSiPolicy.p7b'; Label = 'Secure Boot SKU policy source (SKUSiPolicy.p7b)'; Optional = $false }
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

function Get-FileHashValue {
    <#
    .SYNOPSIS
        SHA256 of a file, or an empty string when it cannot be read.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return '' }
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not hash $Path : $($_.Exception.Message)"
        return ''
    }
}

function Get-OfflineSecureBootState {
    <#
    .SYNOPSIS
        Reads the Secure Boot state the guest last booted with, from the Measured Boot log.

    .DESCRIPTION
        The obvious source, Control\SecureBoot\State\UEFISecureBootEnabled, does not work offline.
        That key is volatile: Windows recreates it from the firmware at every boot and never writes
        it to the SYSTEM hive file. Saving and reloading the hive on a running Server 2022 VM shows
        AvailableUpdates, SBAT and Servicing surviving while State disappears, so an attached disk
        never carries it. On a Generation 1 VM the key does not exist even while running.

        The firmware measures the EFI_GLOBAL_VARIABLE "SecureBoot" - a single byte, 0 or 1 - into
        PCR[7], and Windows writes the whole TCG log to Windows\Logs\MeasuredBoot at every boot.
        That is an ordinary file on the Windows partition, so it can simply be read.

        The record is UEFI_VARIABLE_DATA from the TCG PC Client Platform Firmware Profile:

            EFI_GUID VariableName;       // +0,  16 bytes
            UINT64   UnicodeNameLength;  // +16, in CHAR16 units
            UINT64   VariableDataLength; // +24, in bytes
            CHAR16   UnicodeName[];      // +32
            INT8     VariableData[];     // the state byte

        An absent or empty log is reported as unknown rather than as "off". Azure allows Secure Boot
        to be enabled with the vTPM disabled, and such a VM writes no Measured Boot log at all while
        still having Secure Boot on, so absence proves nothing.

    .OUTPUTS
        PSCustomObject with Known, Enabled, Source and MeasuredUtc.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsDrive)

    $result = [PSCustomObject]@{ Known = $false; Enabled = $false; Source = ''; MeasuredUtc = $null }

    $logDir = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Logs\MeasuredBoot'
    if (-not (Test-OfflinePath $logDir)) {
        $result.Source = 'no Measured Boot log folder'
        return $result
    }

    $logs = @(Get-ChildItem -LiteralPath $logDir -Filter '*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($logs.Count -eq 0) {
        $result.Source = 'the Measured Boot log folder is empty'
        return $result
    }

    # EFI_GLOBAL_VARIABLE {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}, in the little-endian order the
    # first three fields of an EFI_GUID are actually stored in.
    $guid = [byte[]]@(0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C)

    foreach ($log in ($logs | Select-Object -First 3)) {
        try { $bytes = [System.IO.File]::ReadAllBytes($log.FullName) }
        catch {
            Add-OfflineRepairLog -Level Info -Message "Could not read the Measured Boot log $($log.Name): $($_.Exception.Message)"
            continue
        }

        for ($i = 0; $i -le $bytes.Length - 64; $i++) {
            if ($bytes[$i] -ne $guid[0]) { continue }

            $matched = $true
            for ($j = 1; $j -lt 16; $j++) {
                if ($bytes[$i + $j] -ne $guid[$j]) { $matched = $false; break }
            }
            if (-not $matched) { continue }

            $nameLength = [BitConverter]::ToUInt64($bytes, $i + 16)
            $dataLength = [BitConverter]::ToUInt64($bytes, $i + 24)

            # Guards against a random 16-byte run that happens to match the GUID. A real record
            # names a variable of a few characters and carries a byte or two of data.
            if ($nameLength -eq 0 -or $nameLength -gt 64) { continue }
            if ($dataLength -lt 1 -or $dataLength -gt 65536) { continue }
            if (($i + 32 + ($nameLength * 2) + $dataLength) -gt $bytes.Length) { continue }

            $nameBytes = New-Object byte[] ($nameLength * 2)
            [Array]::Copy($bytes, $i + 32, $nameBytes, 0, $nameLength * 2)
            if ([System.Text.Encoding]::Unicode.GetString($nameBytes) -ne 'SecureBoot') { continue }

            $result.Known = $true
            $result.Enabled = ($bytes[$i + 32 + ($nameLength * 2)] -eq 1)
            $result.Source = "Measured Boot log $($log.Name)"
            $result.MeasuredUtc = $log.LastWriteTimeUtc
            return $result
        }
    }

    $result.Source = 'the SecureBoot variable was not present in the most recent Measured Boot logs'
    return $result
}

function Get-EfiFallbackBootFileName {
    <#
    .SYNOPSIS
        The removable-media fallback loader name for this image's architecture.

    .DESCRIPTION
        Firmware that cannot find a boot entry falls back to \EFI\Boot\boot<arch>.efi. The name is
        architecture specific, and writing an x64 loader to the ARM64 name leaves the firmware
        refusing it just as firmly as if there were no loader at all.

        The architecture is read from the Machine field of the kernel's own PE header rather than
        from the rescue VM, which may be a different architecture than the disk attached to it, and
        rather than from the registry, which would need a hive mount for two bytes.
    #>
    param([Parameter(Mandatory = $true)][string]$WindowsDrive)

    $kernel = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\ntoskrnl.exe'
    $machine = 0

    try {
        $stream = [System.IO.File]::Open($kernel, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $header = New-Object byte[] 1024
            $read = $stream.Read($header, 0, 1024)
            if ($read -ge 512 -and $header[0] -eq 0x4D -and $header[1] -eq 0x5A) {
                $peOffset = [BitConverter]::ToInt32($header, 0x3C)
                if ($peOffset -gt 0 -and ($peOffset + 6) -lt $read -and
                    [System.Text.Encoding]::ASCII.GetString($header, $peOffset, 4) -eq "PE`0`0") {
                    $machine = [BitConverter]::ToUInt16($header, $peOffset + 4)
                }
            }
        }
        finally { $stream.Dispose() }
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not read the architecture from $kernel ($($_.Exception.Message)). Assuming x64, which is what every Azure Gen2 Windows image except the ARM64 sizes uses."
    }

    switch ($machine) {
        0xAA64 { return 'bootaa64.efi' }
        0x8664 { return 'bootx64.efi' }
        0x014C { return 'bootia32.efi' }
        default {
            if ($machine -ne 0) {
                Add-OfflineRepairLog -Level Warning -Message ("The kernel reports an unrecognised PE machine type 0x{0:X4}. Assuming x64." -f $machine)
            }
            return 'bootx64.efi'
        }
    }
}

function Get-ComponentStoreCopy {
    <#
    .SYNOPSIS
        Every copy of a file held in the component store.

    .DESCRIPTION
        WinSxS directories are named after the component, not the file, so
        "Get-ChildItem WinSxS -Filter '*winload*'" finds nothing at all - winload.efi lives in
        amd64_microsoft-windows-b..vironment-os-loader_<key>_<version>_none_<hash>. The file is
        matched one wildcard level down instead, which is where servicing puts it.

        Every copy is returned rather than the newest, because a file that matches ANY copy in the
        store is a file the store vouches for. Picking the newest and demanding a match would flag
        a perfectly healthy installation the moment an update is staged but not yet active.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    $winsxs = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\WinSxS'
    if (-not (Test-OfflinePath $winsxs)) { return @() }

    try {
        return @(Get-ChildItem -Path (Join-Path $winsxs "*\$FileName") -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 })
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "Could not search the component store for $FileName : $($_.Exception.Message)"
        return @()
    }
}

function Get-EspArtifactSpec {
    <#
    .SYNOPSIS
        The three files on the EFI System Partition, each with the Windows-partition copy that is
        the authority for it.

    .DESCRIPTION
        The fallback loader is deliberately the same source file as the Microsoft one. Firmware that
        has lost its boot entry falls back to \EFI\Boot, and Windows expects to find its own boot
        manager there.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$BootDrive
    )

    $bootManagerSource = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Boot\EFI\bootmgfw.efi'
    $skuPolicySource = Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\SecureBootUpdates\SKUSiPolicy.p7b'
    $fallbackName = Get-EfiFallbackBootFileName -WindowsDrive $WindowsDrive

    return @(
        @{
            Item        = 'bootmgfw'
            Label       = 'EFI boot manager'
            Source      = $bootManagerSource
            Destination = Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Microsoft\Boot\bootmgfw.efi'
        }
        @{
            Item        = 'fallback'
            Label       = "EFI fallback boot manager ($fallbackName)"
            Source      = $bootManagerSource
            Destination = Join-OfflinePath -Root $BootDrive -ChildPath "EFI\Boot\$fallbackName"
        }
        @{
            Item        = 'skusipolicy'
            Label       = 'Secure Boot SKU policy'
            Source      = $skuPolicySource
            Destination = Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Microsoft\Boot\SKUSiPolicy.p7b'
        }
    )
}

function Get-EspFinding {
    <#
    .SYNOPSIS
        Compares each EFI System Partition artifact with its Windows-partition source.

    .DESCRIPTION
        Hash comparison only. Nothing here writes, so this is safe under -detectOnly.

        A missing source is reported and not repaired. The source is what makes the copy correct for
        this installation, and taking a boot manager from anywhere else - the rescue VM, another
        image - is how a guest ends up running a loader from a different build.
    #>
    param(
        [Parameter(Mandatory = $true)][array]$Specs
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($spec in $Specs) {
        $sourceHash = Get-FileHashValue -Path $spec.Source
        if (-not $sourceHash) {
            [void]$findings.Add((New-Finding -Cause 'MissingSource' -Item $spec.Item -Repairable $false `
                        -Message "The $($spec.Label) cannot be refreshed because its source on the Windows partition, $($spec.Source), is missing or unreadable. Only this installation's own copy is safe to use, so nothing was changed. Repair the component store from matching media, or apply the pending update, then run this again." `
                        -Data $spec))
            continue
        }

        $destinationHash = Get-FileHashValue -Path $spec.Destination
        if (-not $destinationHash) {
            [void]$findings.Add((New-Finding -Cause 'MissingEspArtifact' -Item $spec.Item `
                        -Message "The $($spec.Label) is missing from the EFI System Partition at $($spec.Destination), so the firmware has nothing to run. It will be copied from $($spec.Source)." `
                        -Data $spec))
            continue
        }

        if ($destinationHash -ne $sourceHash) {
            [void]$findings.Add((New-Finding -Cause 'StaleEspArtifact' -Item $spec.Item `
                        -Message "The $($spec.Label) on the EFI System Partition does not match the copy Windows keeps at $($spec.Source), so an update refreshed the Windows partition without refreshing the EFI System Partition. It will be replaced." `
                        -Data $spec))
            continue
        }

        Add-OfflineRepairLog -Level Info -Message "$($spec.Label) on the EFI System Partition matches $($spec.Source)."
    }

    return @($findings)
}

function Get-BootChainFinding {
    <#
    .SYNOPSIS
        Compares each boot chain file with the copies in the component store.

    .DESCRIPTION
        Hash comparison only, for the reason set out in .NOTES: offline sfc rewrites files even when
        asked only to verify, so it cannot be part of detection.

        A file that matches at least one copy in the store is intact. A file that matches none is
        not what Windows shipped. A file the store has no copy of at all cannot be judged either
        way, and is reported rather than guessed at.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($spec in $script:BootChainFile) {
        $path = Join-OfflinePath -Root $WindowsDrive -ChildPath $spec.RelativePath
        $fileName = Split-Path -Path $spec.RelativePath -Leaf
        $present = Test-OfflinePath $path

        if (-not $present) {
            if ($spec.Optional) {
                Add-OfflineRepairLog -Level Info -Message "$($spec.Label) is not present, which is normal on an installation that does not use it."
                continue
            }
            [void]$findings.Add((New-Finding -Cause 'MissingBootChainFile' -Item $spec.RelativePath `
                        -Message "The $($spec.Label) is missing from $path. The loader cannot continue without it. It will be restored from the component store." `
                        -Data $spec))
            continue
        }

        $hash = Get-FileHashValue -Path $path
        $storeCopies = @(Get-ComponentStoreCopy -WindowsDrive $WindowsDrive -FileName $fileName)

        if ($storeCopies.Count -eq 0) {
            [void]$findings.Add((New-Finding -Cause 'NoStoreCopy' -Item $spec.RelativePath -Repairable $false `
                        -Message "The $($spec.Label) at $path holds no copy in the component store, so whether it is intact cannot be established and nothing can be put in its place. Check it by hand against a VM of the same build, or repair the component store with win-sfc-sf-corruption." `
                        -Data $spec))
            continue
        }

        $storeHashes = @($storeCopies | ForEach-Object { Get-FileHashValue -Path $_.FullName } | Where-Object { $_ })
        if ($hash -and ($storeHashes -contains $hash)) {
            Add-OfflineRepairLog -Level Info -Message "$($spec.Label) matches a copy in the component store."
            continue
        }

        [void]$findings.Add((New-Finding -Cause 'CorruptBootChainFile' -Item $spec.RelativePath `
                    -Message "The $($spec.Label) at $path matches none of the $($storeCopies.Count) copy(ies) the component store holds of $fileName, so it is not the file Windows shipped. It will be repaired from the store." `
                    -Data $spec))
    }

    return @($findings)
}

function Get-BackupPath {
    <#
    .SYNOPSIS
        A backup path beside the file, unique to this run.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $candidate = "$Path$script:BackupSuffix"
    $counter = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = "$Path$script:BackupSuffix-$counter"
        $counter++
    }
    return $candidate
}

function Backup-Artifact {
    <#
    .SYNOPSIS
        Copies a file aside before it is replaced, and records it so -revert can find it.

    .DESCRIPTION
        A file that does not exist yet is still recorded, with an empty backup path. Reverting then
        means deleting what this script created, which is what putting the disk back requires.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        [void]$script:BackupManifest.Add([PSCustomObject]@{ Path = $Path; BackupPath = ''; Existed = $false })
        return $true
    }

    $backupPath = Get-BackupPath -Path $Path
    try {
        Copy-Item -LiteralPath $Path -Destination $backupPath -Force -ErrorAction Stop
        [void]$script:BackupManifest.Add([PSCustomObject]@{ Path = $Path; BackupPath = $backupPath; Existed = $true })
        Add-OfflineRepairLog -Level Info -Message "Backed up $Path to $backupPath."
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "Could not back up $Path : $($_.Exception.Message)"
        return $false
    }
}

function Invoke-OfflineSfcScanFile {
    <#
    .SYNOPSIS
        Repairs one file from the guest's own component store with a targeted sfc.

    .DESCRIPTION
        Only ever /SCANFILE, and only ever against a file detection has already found to be wrong.
        The store it sources from belongs to the guest, so the replacement is the right build by
        construction - which is why no rescue-host or cross-build source is offered anywhere here.

        sfc exits 0 whether or not it repaired anything and writes UTF-16 to the console, so neither
        is usable. /OFFLOGFILE is parsed instead. The log is written to the rescue VM rather than the
        guest, so a failed repair leaves nothing behind on the disk being repaired.

    .OUTPUTS
        PSCustomObject with Succeeded, Detail and LogLines.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $drive = $WindowsDrive.TrimEnd('\')
    $sfcLog = Join-Path $env:TEMP ("sfc-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $sfcArgs = @(
        "/SCANFILE=$Path"
        "/OFFBOOTDIR=$drive\"
        "/OFFWINDIR=$drive\Windows"
        "/OFFLOGFILE=$sfcLog"
    )

    Add-OfflineRepairLog -Level Info -Message "Running: sfc.exe $($sfcArgs -join ' ')"
    try { $null = & sfc.exe @sfcArgs 2>&1 }
    catch {
        return [PSCustomObject]@{ Succeeded = $false; Detail = "sfc could not be started: $($_.Exception.Message)"; LogLines = @() }
    }

    $lines = @()
    if (Test-Path -LiteralPath $sfcLog) {
        $lines = @(Get-Content -LiteralPath $sfcLog -ErrorAction SilentlyContinue | Where-Object { $_ -match '\[SR\]' })
        Remove-Item -LiteralPath $sfcLog -Force -ErrorAction SilentlyContinue
    }

    foreach ($line in ($lines | Select-Object -Last 8)) {
        Add-OfflineRepairLog -Level Info -Message "  sfc: $($line.Trim())"
    }

    if ($lines.Count -eq 0) {
        return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc produced no offline log, so nothing can be said about what it did.'; LogLines = @() }
    }

    $repaired = @($lines | Where-Object { $_ -match 'Repair complete|successfully repaired|Repairing file' })
    $unrepairable = @($lines | Where-Object { $_ -match 'Cannot repair member file' -and $_ -notmatch 'Repaired file' })

    if ($repaired.Count -gt 0) {
        return [PSCustomObject]@{ Succeeded = $true; Detail = 'sfc repaired the file from the component store.'; LogLines = $lines }
    }
    if ($unrepairable.Count -gt 0) {
        return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc found the file damaged but could not repair it, which means the component store copy is damaged too.'; LogLines = $lines }
    }

    return [PSCustomObject]@{ Succeeded = $false; Detail = 'sfc reported no repair.'; LogLines = $lines }
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Applies the one change a finding calls for.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    switch ($Finding.Cause) {
        { $_ -in @('MissingEspArtifact', 'StaleEspArtifact') } {
            $spec = $Finding.Data
            $destinationDir = Split-Path -Path $spec.Destination -Parent
            if (-not (Test-Path -LiteralPath $destinationDir)) {
                try { $null = New-Item -Path $destinationDir -ItemType Directory -Force -ErrorAction Stop }
                catch { return [PSCustomObject]@{ Repaired = $false; Detail = "Could not create $destinationDir : $($_.Exception.Message)" } }
            }

            if (-not (Backup-Artifact -Path $spec.Destination)) {
                return [PSCustomObject]@{ Repaired = $false; Detail = "The existing $($spec.Label) could not be backed up, so it was left alone." }
            }

            $copy = Copy-OfflineProtectedFile -Source $spec.Source -Destination $spec.Destination
            if (-not $copy.Copied) {
                return [PSCustomObject]@{ Repaired = $false; Detail = $copy.Reason }
            }

            # Verified by re-reading, not by trusting the copy that was just made.
            $sourceHash = Get-FileHashValue -Path $spec.Source
            $destinationHash = Get-FileHashValue -Path $spec.Destination
            if (-not $destinationHash -or $destinationHash -ne $sourceHash) {
                return [PSCustomObject]@{ Repaired = $false; Detail = "The $($spec.Label) was written but does not match its source afterwards." }
            }

            return [PSCustomObject]@{ Repaired = $true; Detail = "Copied $($spec.Source) to $($spec.Destination)." }
        }

        { $_ -in @('CorruptBootChainFile', 'MissingBootChainFile') } {
            $spec = $Finding.Data
            $path = Join-OfflinePath -Root $WindowsDrive -ChildPath $spec.RelativePath
            $fileName = Split-Path -Path $spec.RelativePath -Leaf

            if (Test-Path -LiteralPath $path) {
                if (-not (Backup-Artifact -Path $path)) {
                    return [PSCustomObject]@{ Repaired = $false; Detail = "The $($spec.Label) could not be backed up, so it was left alone." }
                }
            }

            $sfc = Invoke-OfflineSfcScanFile -Path $path -WindowsDrive $WindowsDrive
            if (-not $sfc.Succeeded) {
                return [PSCustomObject]@{ Repaired = $false; Detail = $sfc.Detail }
            }

            $hash = Get-FileHashValue -Path $path
            $storeHashes = @(Get-ComponentStoreCopy -WindowsDrive $WindowsDrive -FileName $fileName |
                ForEach-Object { Get-FileHashValue -Path $_.FullName } | Where-Object { $_ })
            if (-not $hash -or -not ($storeHashes -contains $hash)) {
                return [PSCustomObject]@{ Repaired = $false; Detail = "sfc reported a repair, but $path still matches no copy in the component store." }
            }

            return [PSCustomObject]@{ Repaired = $true; Detail = "Repaired $path from the component store." }
        }

        default {
            return [PSCustomObject]@{ Repaired = $false; Detail = "No repair is defined for $($Finding.Cause)." }
        }
    }
}

function Get-RevertCandidate {
    <#
    .SYNOPSIS
        Finds the backups a previous run of this script left behind.

    .DESCRIPTION
        The run timestamp is part of the suffix, so the newest set is chosen and the rest are left
        alone. Reverting the newest run is what an operator means by "put it back".
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$BootDrive
    )

    $roots = @(
        (Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Microsoft\Boot')
        (Join-OfflinePath -Root $BootDrive -ChildPath 'EFI\Boot')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\CodeIntegrity')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\SecureBootUpdates')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\System32\drivers')
        (Join-OfflinePath -Root $WindowsDrive -ChildPath 'Windows\Boot\EFI')
    )

    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($root in $roots) {
        if (-not (Test-OfflinePath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter "*.$scriptName-backup-*" -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -notmatch "^(?<original>.+)\.$([regex]::Escape($scriptName))-backup-(?<stamp>\d{14})(-\d+)?$") { continue }
            [void]$found.Add([PSCustomObject]@{
                    BackupPath   = $file.FullName
                    OriginalPath = Join-Path $root $Matches['original']
                    Stamp        = $Matches['stamp']
                })
        }
    }

    if ($found.Count -eq 0) { return @() }

    $newestStamp = @($found | Sort-Object Stamp -Descending | Select-Object -First 1).Stamp
    return @($found | Where-Object { $_.Stamp -eq $newestStamp })
}

function Invoke-Revert {
    <#
    .SYNOPSIS
        Puts back the files the most recent run replaced.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $true)][string]$BootDrive
    )

    $candidates = @(Get-RevertCandidate -WindowsDrive $WindowsDrive -BootDrive $BootDrive)
    if ($candidates.Count -eq 0) {
        Log-Output 'No backups from a previous run of this script were found, so there is nothing to put back.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    Log-Output "Restoring $($candidates.Count) file(s) backed up by the run of $($candidates[0].Stamp)." | Tee-Object -FilePath $logFile -Append

    $restored = 0
    $failed = 0
    foreach ($candidate in $candidates) {
        $copy = Copy-OfflineProtectedFile -Source $candidate.BackupPath -Destination $candidate.OriginalPath
        if ($copy.Copied) {
            $restored++
            Log-Output "  Restored $($candidate.OriginalPath) from $($candidate.BackupPath)." | Tee-Object -FilePath $logFile -Append
            Remove-Item -LiteralPath $candidate.BackupPath -Force -ErrorAction SilentlyContinue
        }
        else {
            $failed++
            Log-Warning "  Could not restore $($candidate.OriginalPath): $($copy.Reason)" | Tee-Object -FilePath $logFile -Append
        }
    }

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($failed -gt 0) {
        Log-Error "Restored $restored file(s), but $failed could not be put back." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "Restored $restored file(s). The disk is back in the state it was in before this script ran." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}

try {
    Log-Output "Starting $scriptName." | Tee-Object -FilePath $logFile

    $offline = if ($windowsDrive) { Get-OfflineWindowsDisk -WindowsDrive $windowsDrive } else { Get-OfflineWindowsDisk }
    Log-Output "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName))." | Tee-Object -FilePath $logFile -Append

    if ($offline.Generation -ne 2) {
        Log-Error 'This disk is Generation 1 (MBR/BIOS) and has no EFI System Partition, so there is no signed EFI boot chain to repair. A Gen1 boot failure is a boot sector, boot configuration or partition problem: use win-fix-boot-partition or win-fix-bcd.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    if (-not $offline.BootDrive) {
        Log-Error 'No EFI System Partition could be mounted on this disk. If it is missing or its file system is unreadable, use win-fix-boot-partition to rebuild it, then run this script again.' | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output "EFI System Partition: $($offline.BootDrive)" | Tee-Object -FilePath $logFile -Append

    if ($isRevert) {
        return Invoke-Revert -WindowsDrive $offline.WindowsDrive -BootDrive $offline.BootDrive
    }

    # Context, not a verdict. Secure Boot being on or off is normal either way; it decides how
    # serious a stale policy file is, and it is stated plainly so the engineer can weigh the rest.
    $secureBoot = Get-OfflineSecureBootState -WindowsDrive $offline.WindowsDrive
    if ($secureBoot.Known) {
        Log-Info "Secure Boot was $(if ($secureBoot.Enabled) { 'enabled' } else { 'disabled' }) when the guest last booted, measured $($secureBoot.MeasuredUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC (source: $($secureBoot.Source))." | Tee-Object -FilePath $logFile -Append
    }
    else {
        Log-Info "The Secure Boot state could not be established offline ($($secureBoot.Source)). Windows keeps it in a volatile registry key that is never written to disk, so this is expected on a VM without a vTPM and is not itself a fault." | Tee-Object -FilePath $logFile -Append
    }

    $espSpecs = @(Get-EspArtifactSpec -WindowsDrive $offline.WindowsDrive -BootDrive $offline.BootDrive)
    $findings = @()
    $findings += @(Get-EspFinding -Specs $espSpecs)
    $findings += @(Get-BootChainFinding -WindowsDrive $offline.WindowsDrive)

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($findings.Count -eq 0) {
        Log-Output 'The EFI boot chain on this disk is intact. Every file on the EFI System Partition matches the copy Windows keeps, and every boot chain file matches the component store. No changes were made.' | Tee-Object -FilePath $logFile -Append
        if ($secureBoot.Known -and -not $secureBoot.Enabled) {
            Log-Output 'Secure Boot was disabled at the last boot, so a signature problem in the boot chain would not have stopped this VM in the first place. Look at win-fix-bcd for the boot configuration, or win-fix-inaccessible-boot-device if the failure is a 0x7B.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    foreach ($finding in $findings) {
        Log-Output "[$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        Log-Output "detectOnly was requested, so nothing was changed. $($repairable.Count) issue(s) can be repaired, $($unrepairable.Count) need a decision." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedCount = 0
    $failed = @()
    foreach ($finding in $repairable) {
        $result = Repair-Finding -Finding $finding -WindowsDrive $offline.WindowsDrive
        if ($result.Repaired) {
            $finding.Repaired = $true
            $repairedCount++
            Log-Output "  Repaired [$($finding.Cause)] $($result.Detail)" | Tee-Object -FilePath $logFile -Append
        }
        else {
            $failed += $finding
            Log-Warning "  Repair failed [$($finding.Cause)] $($result.Detail)" | Tee-Object -FilePath $logFile -Append
        }
    }

    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Verified against freshly read state rather than by trusting the repairs above.
    $remaining = @()
    $remaining += @(Get-EspFinding -Specs $espSpecs)
    $remaining += @(Get-BootChainFinding -WindowsDrive $offline.WindowsDrive)
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
        if ($secureBoot.Known -and -not $secureBoot.Enabled) {
            Log-Output 'Secure Boot was disabled at the last boot. If it was turned off to work around this failure, re-enable it once the VM boots, so the chain that has just been repaired is actually enforced.' | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
        Log-Output "If the VM still fails to start, run this script again with -revert true to put the original files back." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
