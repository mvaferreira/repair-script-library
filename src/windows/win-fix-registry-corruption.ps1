#########################################################################################################
#
# .SYNOPSIS
#   Repairs corrupted or unloadable registry hives on an offline Windows disk.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". Every hive is
#   validated, only the damaged ones are repaired, and the result is re-validated. A healthy disk
#   produces no writes at all.
#
#   Detection, per hive:
#     1. The hive file is missing.
#     2. The hive file is 0 bytes.
#     3. The hive file does not start with the 'regf' signature.
#     4. Windows itself cannot parse the hive. This is the authoritative check: the file is copied
#        to scratch space with its transaction logs and handed to RegLoadAppKey, so a hive that is
#        merely dirty is repaired by log replay and is correctly reported as healthy.
#     5. chkreg.exe reports repairable structural damage in a hive that still loads.
#
#   Repair escalates only as far as it needs to, per hive:
#     a. chkreg.exe /R /C on a scratch copy. The result must load through RegLoadAppKey before it
#        is allowed anywhere near the disk, so a failed repair can never replace a working hive.
#     b. Restore from Windows\System32\Config\RegBack when the hive cannot be repaired in place.
#        The RegBack set is validated first: every candidate must load, SYSTEM and SOFTWARE must
#        both be present, SAM and SECURITY are restored only as a pair, and any hive whose
#        timestamp is out of step with the core set is excluded rather than mixed in.
#
#   The original file is copied next to itself before any replacement, and a restore that fails
#   part way through rolls every hive it touched back to the file it started with.
#
# .RESOLVES
#   Stop error 0xC0000218 STATUS_CANNOT_LOAD_REGISTRY_FILE, stop error 0x74 BAD_SYSTEM_CONFIG_INFO,
#   "Windows failed to load because the system registry file is missing or corrupt", and boot loops
#   that follow a storage failure, an unclean shutdown during servicing, or a restore that left a
#   truncated hive behind.
#
# .PARAMETER detectOnly
#   "true" to report what would be changed and make no writes at all. Defaults to "false".
#
# .PARAMETER allowRegBack
#   "false" to stop after the in-place chkreg repair and never fall back to RegBack. Defaults to
#   "true". RegBack contents can be weeks old on Windows 10 1803 and later, where the periodic
#   backup is disabled by default, so a restore can roll back configuration.
#
# .PARAMETER hive
#   Limit the run to a single hive: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT or COMPONENTS.
#   Defaults to "all".
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --parameters allowRegBack=false --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-registry-corruption --parameters hive=SOFTWARE --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   chkreg.exe ships in this repository at src\windows\common\tools\chkreg.exe and is used from
#   there, so the script needs no network access on the rescue VM.
#
#   A hive that is structurally sound but semantically wrong is a different problem. A missing
#   Winlogon or Session Manager key belongs to win-fix-logon-subsystem, and boot storage driver
#   settings belong to win-fix-inaccessible-boot-device.
#
#   After recovery, consider re-enabling the periodic RegBack backup on the repaired VM with
#   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager
#   EnablePeriodicBackup = 1, so a future incident has a recent restore point.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$allowRegBack = 'true',
    [Parameter(Mandatory = $false)][ValidateSet('all', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'COMPONENTS', IgnoreCase = $true)][string]$hive = 'all',
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
$isRegBackAllowed = ($allowRegBack -eq 'true')
$hiveFilter = if ($hive -eq 'all') { $null } else { $hive.ToUpperInvariant() }

# SYSTEM and SOFTWARE are required for the OS to start at all, so a problem with either is an
# error. The rest degrade the installation without stopping the boot, so they are reported as
# warnings and repaired opportunistically.
function Get-OfflineHiveSpec {
    @(
        [PSCustomObject]@{ Name = 'SYSTEM'; Required = $true; Description = 'machine configuration, drivers and services' }
        [PSCustomObject]@{ Name = 'SOFTWARE'; Required = $true; Description = 'installed software and OS settings' }
        [PSCustomObject]@{ Name = 'SAM'; Required = $false; Description = 'local accounts' }
        [PSCustomObject]@{ Name = 'SECURITY'; Required = $false; Description = 'local security policy' }
        [PSCustomObject]@{ Name = 'DEFAULT'; Required = $false; Description = 'default user profile' }
        [PSCustomObject]@{ Name = 'COMPONENTS'; Required = $false; Description = 'servicing component store' }
    )
}

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Cause,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][bool]$Repairable,
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

function Get-ChkRegPath {
    <#
    .SYNOPSIS
        Returns the path of the in-repo chkreg.exe, or an empty string when it is unavailable.
    #>
    $candidate = Join-Path (Get-Location).Path 'src\windows\common\tools\chkreg.exe'
    if (Test-OfflinePath $candidate) { return $candidate }

    Add-OfflineRepairLog -Level Warning -Message "chkreg.exe was not found at $candidate. Structural repair is unavailable and only RegBack restore can be used."
    return ''
}

function Invoke-ChkReg {
    <#
    .SYNOPSIS
        Runs chkreg.exe against a hive file and reports what it found.

    .DESCRIPTION
        Always runs on a scratch copy, never on the file on the offline disk. In repair mode the
        repaired file is left in scratch space for the caller to validate before it is used;
        chkreg writes the compacted result to <file>.BAK when /C succeeds.

    .OUTPUTS
        PSCustomObject with Ran, FoundProblem, RepairedPath and Output.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ChkRegPath,
        [Parameter(Mandatory = $true)][string]$HivePath,
        [Parameter(Mandatory = $true)][string]$ScratchDir,
        [Parameter(Mandatory = $false)][bool]$Repair = $false
    )

    $result = [PSCustomObject]@{
        Ran          = $false
        FoundProblem = $false
        RepairedPath = ''
        Output       = ''
    }

    $working = Join-Path $ScratchDir (Split-Path -Path $HivePath -Leaf)
    Copy-Item -LiteralPath $HivePath -Destination $working -Force -ErrorAction Stop
    foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
        if (Test-OfflinePath "$HivePath$suffix") {
            Copy-Item -LiteralPath "$HivePath$suffix" -Destination "$working$suffix" -Force -ErrorAction SilentlyContinue
        }
    }

    # chkreg writes progress to stderr, so both streams are coerced to plain strings to keep
    # PowerShell from turning ordinary output into NativeCommandError records.
    if ($Repair) {
        $raw = & $ChkRegPath /F "$working" /R /C 2>&1 | ForEach-Object { "$_" }
    }
    else {
        $raw = & $ChkRegPath /F "$working" 2>&1 | ForEach-Object { "$_" }
    }

    $result.Ran = $true
    $result.Output = (@($raw) -join "`n").Trim()
    $result.FoundProblem = ($result.Output -match '\.\.\.\s*fixed' -or $result.Output -match 'corrupt')

    if ($Repair) {
        # /C writes the compacted hive alongside the repaired one; prefer it when present.
        $result.RepairedPath = if (Test-OfflinePath "$working.BAK") { "$working.BAK" } else { $working }
    }

    return $result
}

function Get-RegBackPlan {
    <#
    .SYNOPSIS
        Chooses which RegBack hives may safely be restored together.

    .DESCRIPTION
        A RegBack directory is not automatically a usable backup set. Every candidate must load,
        SYSTEM and SOFTWARE must both be usable or nothing is restored, SAM and SECURITY are only
        valid as a pair because they cross-reference each other, and any hive whose timestamp is
        out of step with the core set is excluded rather than mixed with hives from another point
        in time.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $false)][timespan]$MaximumSkew = ([timespan]::FromHours(24))
    )

    $regBack = Join-OfflinePath -Root $ConfigPath -ChildPath 'RegBack'
    $usable = @()
    $excluded = @()

    if (-not (Test-OfflinePath $regBack)) {
        return [PSCustomObject]@{ CanRestore = $false; Hives = @(); Excluded = @(); Reason = "RegBack directory not found at $regBack." }
    }

    foreach ($spec in (Get-OfflineHiveSpec)) {
        $source = Join-OfflinePath -Root $regBack -ChildPath $spec.Name
        if (-not (Test-OfflinePath $source)) {
            $excluded += [PSCustomObject]@{ Name = $spec.Name; Reason = 'Not present in RegBack.' }
            continue
        }

        $validation = Test-OfflineHiveFile -Path $source
        if (-not $validation.IsValid) {
            $excluded += [PSCustomObject]@{ Name = $spec.Name; Reason = $validation.Reason }
            continue
        }

        $usable += [PSCustomObject]@{
            Name       = $spec.Name
            Required   = $spec.Required
            SourcePath = $source
            LivePath   = (Join-OfflinePath -Root $ConfigPath -ChildPath $spec.Name)
            WrittenUtc = (Get-Item -LiteralPath $source -Force).LastWriteTimeUtc
        }
    }

    $core = @($usable | Where-Object { $_.Required })
    $missingCore = @(@('SYSTEM', 'SOFTWARE') | Where-Object { $_ -notin @($core.Name) })
    if ($missingCore.Count -gt 0) {
        return [PSCustomObject]@{
            CanRestore = $false
            Hives      = @()
            Excluded   = @($excluded)
            Reason     = "RegBack has no usable $($missingCore -join ' and ') hive, so it is not a complete backup set."
        }
    }

    $newestCore = (@($core.WrittenUtc) | Sort-Object -Descending | Select-Object -First 1)
    $selected = @($core)
    foreach ($candidate in @($usable | Where-Object { -not $_.Required })) {
        $skew = [timespan]::FromTicks([math]::Abs(($candidate.WrittenUtc - $newestCore).Ticks))
        if ($skew -gt $MaximumSkew) {
            $excluded += [PSCustomObject]@{ Name = $candidate.Name; Reason = "Written $([math]::Round($skew.TotalHours, 1)) hours away from the core set." }
            continue
        }
        $selected += $candidate
    }

    # SAM and SECURITY reference each other, so restoring one without the other breaks logon.
    $hasSam = @($selected | Where-Object { $_.Name -eq 'SAM' }).Count -eq 1
    $hasSecurity = @($selected | Where-Object { $_.Name -eq 'SECURITY' }).Count -eq 1
    if ($hasSam -ne $hasSecurity) {
        $selected = @($selected | Where-Object { $_.Name -notin @('SAM', 'SECURITY') })
        $excluded += [PSCustomObject]@{ Name = 'SAM/SECURITY'; Reason = 'The identity hives must be restored as a pair and only one of them is usable.' }
    }

    return [PSCustomObject]@{ CanRestore = $true; Hives = @($selected); Excluded = @($excluded); Reason = '' }
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Validates every in-scope hive and returns one finding per problem.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $false)][string]$HiveFilter = $null,
        [Parameter(Mandatory = $false)][string]$ChkRegPath = '',
        [Parameter(Mandatory = $true)][string]$ScratchDir
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($spec in (Get-OfflineHiveSpec)) {
        if ($HiveFilter -and $spec.Name -ne $HiveFilter) { continue }

        $path = Join-OfflinePath -Root $ConfigPath -ChildPath $spec.Name
        $validation = Test-OfflineHiveFile -Path $path

        if (-not $validation.Exists) {
            # An absent optional hive is normal on many images, so only the required ones are reported.
            if ($spec.Required) {
                [void]$findings.Add((New-Finding -Cause 'HiveMissing' -Item $spec.Name -Repairable $true `
                            -Message "the $($spec.Name) hive file is missing from $ConfigPath, so Windows cannot read its $($spec.Description)" `
                            -Data ([PSCustomObject]@{ Path = $path; Spec = $spec })))
            }
            else {
                Add-OfflineRepairLog -Message "$($spec.Name): not present on this image, which is normal for an optional hive."
            }
            continue
        }

        if ($validation.IsValid) {
            Add-OfflineRepairLog -Message "$($spec.Name): loads correctly ($($validation.Size) bytes)."

            if ($ChkRegPath) {
                $check = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $path -ScratchDir $ScratchDir -Repair $false
                if ($check.FoundProblem) {
                    [void]$findings.Add((New-Finding -Cause 'HiveDamaged' -Item $spec.Name -Repairable $true `
                                -Message "the $($spec.Name) hive still loads but chkreg reports repairable structural damage, which degrades $($spec.Description) and can bugcheck later" `
                                -Data ([PSCustomObject]@{ Path = $path; Spec = $spec; ChkRegOutput = $check.Output })))
                }
                else {
                    Add-OfflineRepairLog -Message "$($spec.Name): chkreg found no structural damage."
                }
            }
            continue
        }

        $cause = if ($validation.Size -eq 0) { 'HiveEmpty' } else { 'HiveUnloadable' }
        [void]$findings.Add((New-Finding -Cause $cause -Item $spec.Name -Repairable $true `
                    -Message "the $($spec.Name) hive cannot be loaded by Windows ($($validation.Reason)), which stops it providing $($spec.Description)" `
                    -Data ([PSCustomObject]@{ Path = $path; Spec = $spec; Reason = $validation.Reason })))
    }

    return @($findings)
}

function Repair-HiveInPlace {
    <#
    .SYNOPSIS
        Repairs one hive with chkreg and installs the result only if Windows can load it.

    .OUTPUTS
        $true when the hive on disk was replaced with a repaired copy.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$ChkRegPath,
        [Parameter(Mandatory = $true)][string]$ScratchDir
    )

    $path = $Finding.Data.Path
    if (-not (Test-OfflinePath $path)) {
        Add-OfflineRepairLog -Message "$($Finding.Item): no file to repair in place."
        return $false
    }
    if ((Get-Item -LiteralPath $path -Force).Length -eq 0) {
        Add-OfflineRepairLog -Message "$($Finding.Item): the file is 0 bytes, so chkreg has nothing to work with."
        return $false
    }

    $repair = Invoke-ChkReg -ChkRegPath $ChkRegPath -HivePath $path -ScratchDir $ScratchDir -Repair $true
    if (-not $repair.RepairedPath -or -not (Test-OfflinePath $repair.RepairedPath)) {
        Add-OfflineRepairLog -Level Warning -Message "$($Finding.Item): chkreg produced no output file."
        return $false
    }

    # The repaired file must prove itself before it is allowed to replace a file on the disk.
    $validation = Test-OfflineHiveFile -Path $repair.RepairedPath
    if (-not $validation.IsValid) {
        Add-OfflineRepairLog -Level Warning -Message "$($Finding.Item): the chkreg output still does not load ($($validation.Reason)), so the file on disk was left alone."
        return $false
    }

    $backup = "$path.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $path -Destination $backup -Force -ErrorAction Stop
    Copy-Item -LiteralPath $repair.RepairedPath -Destination $path -Force -ErrorAction Stop

    $after = Test-OfflineHiveFile -Path $path
    if (-not $after.IsValid) {
        Copy-Item -LiteralPath $backup -Destination $path -Force -ErrorAction SilentlyContinue
        Add-OfflineRepairLog -Level Warning -Message "$($Finding.Item): the replaced file did not validate on disk, so the original was put back from $backup."
        return $false
    }

    # The logs describe the file that was just replaced and would be replayed over the repair.
    foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
        if (Test-OfflinePath "$path$suffix") {
            Move-Item -LiteralPath "$path$suffix" -Destination "$path$suffix.bak-$(Get-Date -Format yyyyMMddHHmmss)" -Force -ErrorAction SilentlyContinue
        }
    }

    Add-OfflineRepairLog -Message "$($Finding.Item): repaired with chkreg and verified. Original saved as $backup."
    return $true
}

function Restore-HiveFromRegBack {
    <#
    .SYNOPSIS
        Restores the selected RegBack hives, rolling every touched file back if any step fails.

    .OUTPUTS
        String array of the hive names that were restored.
    #>
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string[]]$Wanted
    )

    $targets = @($Plan.Hives | Where-Object { $_.Name -in $Wanted })
    if ($targets.Count -eq 0) { return @() }

    # SYSTEM and SOFTWARE come from the same point in time, so restoring one without the other
    # produces a pair that disagree about installed software and services.
    $core = @($Plan.Hives | Where-Object { $_.Required })
    foreach ($item in $core) {
        if ($item.Name -notin @($targets.Name)) { $targets += $item }
    }

    $stamp = Get-Date -Format yyyyMMddHHmmss
    $touched = [System.Collections.Generic.List[PSCustomObject]]::new()
    $restored = [System.Collections.Generic.List[string]]::new()

    try {
        foreach ($item in $targets) {
            $backup = $null
            if (Test-OfflinePath $item.LivePath) {
                $backup = "$($item.LivePath).bak-$stamp"
                Copy-Item -LiteralPath $item.LivePath -Destination $backup -Force -ErrorAction Stop
            }
            [void]$touched.Add([PSCustomObject]@{ LivePath = $item.LivePath; Backup = $backup })

            Copy-Item -LiteralPath $item.SourcePath -Destination $item.LivePath -Force -ErrorAction Stop

            $sourceHash = (Get-FileHash -LiteralPath $item.SourcePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $liveHash = (Get-FileHash -LiteralPath $item.LivePath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($sourceHash -ne $liveHash) { throw "the restored $($item.Name) hive does not match its RegBack source." }

            # Stale logs describe the hive that was just replaced and would undo the restore.
            foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
                if (Test-OfflinePath "$($item.LivePath)$suffix") {
                    Move-Item -LiteralPath "$($item.LivePath)$suffix" -Destination "$($item.LivePath)$suffix.bak-$stamp" -Force -ErrorAction SilentlyContinue
                }
            }

            [void]$restored.Add($item.Name)
            Add-OfflineRepairLog -Message "$($item.Name): restored from RegBack and hash verified."
        }
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "RegBack restore failed ($($_.Exception.Message)). Rolling back every hive that was touched."
        for ($i = $touched.Count - 1; $i -ge 0; $i--) {
            $entry = $touched[$i]
            try {
                if ($entry.Backup -and (Test-OfflinePath $entry.Backup)) {
                    Copy-Item -LiteralPath $entry.Backup -Destination $entry.LivePath -Force -ErrorAction Stop
                }
                elseif (Test-OfflinePath $entry.LivePath) {
                    Remove-Item -LiteralPath $entry.LivePath -Force -ErrorAction Stop
                }
            }
            catch {
                Add-OfflineRepairLog -Level Warning -Message "Rollback of $($entry.LivePath) failed: $($_.Exception.Message)"
            }
        }
        throw
    }

    return @($restored)
}

Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, allowRegBack=$isRegBackAllowed, hive=$hive)" | Tee-Object -FilePath $logFile -Append

$scratchDir = Join-Path $env:TEMP "rsl-chkreg-$scriptStartTime"

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $configPath = Join-OfflinePath -Root $offline.WindowsPath -ChildPath 'System32\Config'
    if (-not (Test-OfflinePath $configPath)) {
        throw "The registry directory was not found at $configPath."
    }

    New-Item -Path $scratchDir -ItemType Directory -Force | Out-Null
    $chkRegPath = Get-ChkRegPath
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    if ($chkRegPath) { Log-Info "Using chkreg.exe from $chkRegPath" | Tee-Object -FilePath $logFile -Append }

    $findings = @(Get-AllFinding -ConfigPath $configPath -HiveFilter $hiveFilter -ChkRegPath $chkRegPath -ScratchDir $scratchDir)
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    if ($findings.Count -eq 0) {
        Log-Output "No registry hive corruption was found in $configPath. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isDetectOnly) {
        Log-Output "Detect only: found $($findings.Count) damaged hive(s). No changes were made." | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $findings) {
            Log-Output "  [FIXABLE] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedInPlace = [System.Collections.Generic.List[string]]::new()
    $needRegBack = [System.Collections.Generic.List[string]]::new()

    foreach ($finding in $findings) {
        if ($chkRegPath -and $finding.Cause -ne 'HiveMissing') {
            if (Repair-HiveInPlace -Finding $finding -ChkRegPath $chkRegPath -ScratchDir $scratchDir) {
                $finding.Repaired = $true
                [void]$repairedInPlace.Add($finding.Item)
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                continue
            }
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        [void]$needRegBack.Add($finding.Item)
    }

    $restored = @()
    if ($needRegBack.Count -gt 0) {
        if (-not $isRegBackAllowed) {
            Log-Warning "$($needRegBack.Count) hive(s) could not be repaired in place and allowRegBack is false, so no restore was attempted: $($needRegBack -join ', ')" | Tee-Object -FilePath $logFile -Append
        }
        else {
            $plan = Get-RegBackPlan -ConfigPath $configPath
            Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

            foreach ($item in @($plan.Excluded)) {
                Log-Info "RegBack excluded $($item.Name): $($item.Reason)" | Tee-Object -FilePath $logFile -Append
            }

            if (-not $plan.CanRestore) {
                Log-Warning "RegBack cannot be used: $($plan.Reason)" | Tee-Object -FilePath $logFile -Append
            }
            else {
                $restored = @(Restore-HiveFromRegBack -Plan $plan -Wanted ([string[]]@($needRegBack)))
                Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
                foreach ($finding in $findings) {
                    if ($finding.Item -in $restored) { $finding.Repaired = $true }
                }
            }
        }
    }

    # Verify against freshly read files rather than trusting the writes above.
    $remaining = @(Get-AllFinding -ConfigPath $configPath -HiveFilter $hiveFilter -ChkRegPath $chkRegPath -ScratchDir $scratchDir)
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    foreach ($finding in $remaining) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairedCount = @($findings | Where-Object { $_.Repaired }).Count
    $summary = "Repaired $repairedCount of $($findings.Count) damaged hive(s) in $configPath."
    if ($repairedInPlace.Count -gt 0) { $summary += " Repaired in place: $($repairedInPlace -join ', ')." }
    if ($restored.Count -gt 0) { $summary += " Restored from RegBack: $($restored -join ', ')." }

    if ($remaining.Count -gt 0) {
        Log-Error "$summary $($remaining.Count) hive(s) are still damaged and need a source image or a disk level repair." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    Log-Output "Every replaced hive was saved next to itself with a .bak-<timestamp> suffix." | Tee-Object -FilePath $logFile -Append
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
finally {
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    if ($scratchDir -and (Test-Path -LiteralPath $scratchDir)) {
        Remove-Item -LiteralPath $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    "$(Get-Date -f yyyyMMddHHmmss)" | Out-File -FilePath $logFile -Append
}
