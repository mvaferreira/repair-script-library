<#
.SYNOPSIS
    Helper functions that locate and prepare the offline Windows installation on a
    broken OS disk attached to a rescue VM.

.DESCRIPTION
    'az vm repair create' attaches the broken OS disk to a rescue VM as a data disk.
    Before any offline repair can run, the disk must be brought online, every partition
    that matters must be reachable through a drive letter, and the correct Windows
    installation must be selected when the disk carries more than one.

    This helper does all of that. Unlike Get-Disk-Partitions.ps1 it also assigns
    temporary drive letters to partitions that have none (EFI System and Recovery
    partitions), which offline boot repairs need.

    Exposed functions:
      Get-OfflineWindowsDisk        Main entry point. Returns the resolved offline install.
      Set-OfflineDisksOnline        Bring attached virtual data disks online and writable.
      Add-PartitionDriveLetter      Assign a free drive letter to a partition via diskpart.
      Get-FreeDriveLetter           Return the next unused drive letter.
      Stop-NestedRepairVm           Stop a nested Hyper-V repair VM holding the disk.

    Get-OfflineWindowsDisk sets $script:OfflineWindowsDrive, which the offline registry
    hive helper (Use-OfflineRegistryHive.ps1) uses as its default Windows path.

.NOTES
    Name:   Get-OfflineWindowsDisk.ps1
    Requires: common/setup/init.ps1 to be dot-sourced first (for the Log-* functions).
    The rescue VM's own system disk is always excluded from the search.

.VERSION
    v1.0: Initial version.
#>

function Get-FreeDriveLetter {
    <#
    .SYNOPSIS
        Returns the next unused drive letter, searching from Z: downwards by default.
    #>
    param(
        [Parameter(Mandatory = $false)][string[]]$Exclude = @()
    )

    $used = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter)" })
    $used += @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $used += $Exclude | ForEach-Object { $_.TrimEnd(':', '\') }

    foreach ($letter in ([char[]](90..68))) {
        # Z down to E - A-D are reserved for floppies and the rescue VM system/temp disks.
        if ($used -notcontains "$letter") { return "$letter" }
    }

    throw 'No free drive letter is available on the rescue VM.'
}

function Stop-NestedRepairVm {
    <#
    .SYNOPSIS
        Stops a running nested Hyper-V VM so its VHD can be mounted offline.

    .DESCRIPTION
        Only relevant when the repair VM was created with 'az vm repair create --enable-nested'.
        Returns the names of the VMs that were stopped. Silently does nothing when the
        Hyper-V role is not installed.
    #>
    $stopped = @()

    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return $stopped }

    try {
        $running = @(Get-VM -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' })
    }
    catch {
        Log-Info "Hyper-V is present but VMs could not be enumerated: $($_.Exception.Message)"
        return $stopped
    }

    foreach ($vm in $running) {
        Log-Info "Stopping nested Hyper-V VM '$($vm.Name)' so its disk can be mounted offline."
        Stop-VM -Name $vm.Name -TurnOff -Force -ErrorAction SilentlyContinue
        $stopped += $vm.Name
    }

    if ($stopped.Count -gt 0) { Start-Sleep -Seconds 3 }
    return $stopped
}

function Set-OfflineDisksOnline {
    <#
    .SYNOPSIS
        Brings every attached virtual data disk online and clears the read-only flag.

    .DESCRIPTION
        The rescue VM's own system disk is never touched. Returns the disk numbers
        that were processed.
    #>
    param(
        [Parameter(Mandatory = $false)][int[]]$ExcludeDiskNumber = @()
    )

    $processed = @()
    $disks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
            $_.FriendlyName -like '*Virtual Disk*' -and $_.Number -notin $ExcludeDiskNumber
        })

    foreach ($disk in $disks) {
        # diskpart is used rather than Set-Disk because it succeeds on disks whose
        # partition table is damaged, which is common on the disks we are repairing.
        $script = @"
select disk $($disk.Number)
attributes disk clear readonly noerr
online disk noerr
"@
        $null = $script | diskpart.exe 2>&1
        $processed += $disk.Number
    }

    if ($processed.Count -gt 0) {
        Log-Info "Brought attached virtual disk(s) online: $($processed -join ', ')"
    }
    else {
        Log-Warning 'No attached virtual data disk was found on the rescue VM.'
    }

    # Give the volume stack a moment to surface the new volumes.
    Start-Sleep -Seconds 2
    return $processed
}

function Add-PartitionDriveLetter {
    <#
    .SYNOPSIS
        Assigns a free drive letter to a partition that does not have one.

    .DESCRIPTION
        Set-Partition -NewDriveLetter fails on EFI System and Recovery partitions, so
        diskpart is used instead. Returns the assigned drive letter, or $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$DiskNumber,
        [Parameter(Mandatory = $true)][int]$PartitionNumber,
        [Parameter(Mandatory = $false)][string]$DriveLetter
    )

    if ([string]::IsNullOrWhiteSpace($DriveLetter)) { $DriveLetter = Get-FreeDriveLetter }
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')

    $script = @"
select disk $DiskNumber
select partition $PartitionNumber
assign letter=$DriveLetter noerr
"@
    $null = $script | diskpart.exe 2>&1
    Start-Sleep -Milliseconds 500

    $partition = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -ErrorAction SilentlyContinue
    if ($partition -and $partition.DriveLetter) {
        Log-Info "Assigned drive letter $($partition.DriveLetter): to disk $DiskNumber partition $PartitionNumber ($($partition.Type))."
        return "$($partition.DriveLetter)"
    }

    Log-Warning "Could not assign a drive letter to disk $DiskNumber partition $PartitionNumber ($(if ($partition) { $partition.Type } else { 'unknown' }))."
    return $null
}

function Get-OfflineWindowsInstallCandidate {
    <#
    .SYNOPSIS
        Builds a scored candidate object for one offline Windows installation.

    .DESCRIPTION
        Scoring prefers an installation that has both core hives, the boot loader
        binary expected for the disk's firmware generation, and the highest build
        number, and penalises an installation that is mid-setup.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AccessPath,
        [Parameter(Mandatory = $true)]$PartitionInfo,
        [Parameter(Mandatory = $true)][int]$Generation
    )

    $normalizedPath = if ($AccessPath -match '\\$') { $AccessPath } else { "$AccessPath\" }
    $windowsRoot = Join-Path $normalizedPath 'Windows'
    $systemHivePath = Join-Path $windowsRoot 'System32\Config\SYSTEM'
    $softwareHivePath = Join-Path $windowsRoot 'System32\Config\SOFTWARE'
    $winloadName = if ($Generation -eq 2) { 'System32\winload.efi' } else { 'System32\winload.exe' }
    $expectedWinload = Join-Path $windowsRoot $winloadName

    $candidate = [ordered]@{
        AccessPath          = $normalizedPath
        Drive               = $normalizedPath.TrimEnd('\').ToUpperInvariant()
        DiskNumber          = $PartitionInfo.DiskNumber
        PartitionNumber     = $PartitionInfo.PartitionNumber
        PartitionType       = "$($PartitionInfo.Type)"
        IsActive            = [bool]$PartitionInfo.IsActive
        WindowsRoot         = $windowsRoot
        SystemHivePresent   = [bool](Test-Path -LiteralPath $systemHivePath)
        SoftwareHivePresent = [bool](Test-Path -LiteralPath $softwareHivePath)
        HasExpectedWinload  = [bool](Test-Path -LiteralPath $expectedWinload)
        ProductName         = ''
        CurrentBuildNumber  = ''
        GuestComputerName   = ''
        SetupInProgress     = $false
        Score               = 0
        Selected            = $false
    }

    if ($candidate.SystemHivePresent -and $candidate.SoftwareHivePresent) {
        # Load under a unique temporary key so this probe never collides with the
        # BROKEN<HIVE> mounts used by the repair itself.
        $tempBase = 'RSLPROBE_{0}' -f ([guid]::NewGuid().ToString('N'))
        $softwareKey = "${tempBase}_SOFTWARE"
        $systemKey = "${tempBase}_SYSTEM"
        $loadedKeys = [System.Collections.Generic.List[string]]::new()

        try {
            $null = reg.exe load "HKLM\$softwareKey" "$softwareHivePath" 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                [void]$loadedKeys.Add($softwareKey)
                $cv = Get-ItemProperty "HKLM:\$softwareKey\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
                if ($cv) {
                    $candidate.ProductName = [string]$cv.ProductName
                    $candidate.CurrentBuildNumber = [string]$cv.CurrentBuildNumber
                }
            }

            $null = reg.exe load "HKLM\$systemKey" "$systemHivePath" 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                [void]$loadedKeys.Add($systemKey)
                $currentSet = (Get-ItemProperty "HKLM:\$systemKey\Select" -ErrorAction SilentlyContinue).Current
                $controlSetName = if ($currentSet) { 'ControlSet{0:d3}' -f $currentSet } else { 'ControlSet001' }
                $candidate.GuestComputerName = [string]((Get-ItemProperty "HKLM:\$systemKey\$controlSetName\Control\ComputerName\ComputerName" -ErrorAction SilentlyContinue).ComputerName)

                $setup = Get-ItemProperty "HKLM:\$systemKey\Setup" -ErrorAction SilentlyContinue
                if ($setup -and (($null -ne $setup.SetupType -and "$($setup.SetupType)" -ne '0') -or -not [string]::IsNullOrWhiteSpace($setup.CmdLine))) {
                    $candidate.SetupInProgress = $true
                }
            }
        }
        finally {
            $Error.Clear()
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            for ($i = $loadedKeys.Count - 1; $i -ge 0; $i--) {
                $null = reg.exe unload "HKLM\$($loadedKeys[$i])" 2>&1
            }
        }
    }

    if (Test-Path -LiteralPath (Join-Path $normalizedPath '$WINDOWS.~BT')) { $candidate.SetupInProgress = $true }

    $score = 0
    if ($candidate.SystemHivePresent) { $score += 10 }
    if ($candidate.SoftwareHivePresent) { $score += 10 }
    if ($candidate.HasExpectedWinload) { $score += 30 } else { $score -= 25 }
    if ($candidate.ProductName) { $score += 10 }

    $buildInt = 0
    if ([int]::TryParse($candidate.CurrentBuildNumber, [ref]$buildInt)) {
        $score += [Math]::Min([int]($buildInt / 1000), 30)
    }
    if ($candidate.SetupInProgress) { $score -= 20 }

    $candidate.Score = $score
    return [PSCustomObject]$candidate
}

function Get-OfflineWindowsDisk {
    <#
    .SYNOPSIS
        Locates the offline Windows installation on the attached broken OS disk.

    .DESCRIPTION
        Stops a nested repair VM if one is running, brings the attached virtual disks
        online, assigns drive letters to partitions that have none, then selects the
        best Windows installation and its matching boot partition.

        Sets $script:OfflineWindowsDrive for the offline registry hive helper.

    .PARAMETER DiskNumber
        Restrict the search to a specific disk number.

    .PARAMETER WindowsDrive
        Skip discovery and use this drive letter as the offline Windows volume.

    .OUTPUTS
        PSCustomObject with DiskNumber, Generation, WindowsDrive, WindowsPath,
        BootDrive, BcdStorePath, ProductName, GuestComputerName and Candidates.

    .EXAMPLE
        $offline = Get-OfflineWindowsDisk
        Invoke-WithHive 'SYSTEM' { Get-ItemProperty "$(Get-OfflineSystemRootPath)\Services\disk" }
    #>
    param(
        [Parameter(Mandatory = $false)][int]$DiskNumber = -1,
        [Parameter(Mandatory = $false)][string]$WindowsDrive
    )

    $systemDiskNumber = -1
    try {
        $systemDiskNumber = (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop).DiskNumber
    }
    catch {
        Log-Warning "Could not determine the rescue VM system disk number: $($_.Exception.Message)"
    }

    $null = Stop-NestedRepairVm
    $null = Set-OfflineDisksOnline -ExcludeDiskNumber @($systemDiskNumber | Where-Object { $_ -ge 0 })

    $disks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
            $_.FriendlyName -like '*Virtual Disk*' -and $_.Number -ne $systemDiskNumber -and
            ($DiskNumber -lt 0 -or $_.Number -eq $DiskNumber)
        })

    if ($disks.Count -eq 0) {
        throw 'No attached broken OS disk was found. Create the rescue VM with "az vm repair create" first.'
    }

    # Give every partition a drive letter. EFI System and Recovery partitions have none
    # by default, and offline boot repairs cannot reach them without one.
    foreach ($disk in $disks) {
        foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            if ($part.DriveLetter) { continue }
            if ($part.Size -lt 1MB) { continue }
            $null = Add-PartitionDriveLetter -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
        }
    }

    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($disk in $disks) {
        $generation = if ($disk.PartitionStyle -eq 'GPT') { 2 } elseif ($disk.PartitionStyle -eq 'MBR') { 1 } else { 0 }

        foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            $accessPaths = @($part.AccessPaths | Where-Object { $_ -and $_ -match '^[A-Za-z]:' })
            foreach ($accessPath in $accessPaths) {
                if (-not (Test-Path -LiteralPath (Join-Path $accessPath 'Windows\System32\ntdll.dll'))) { continue }

                $normalized = if ($accessPath -match '\\$') { $accessPath } else { "$accessPath\" }
                if ($candidates | Where-Object { $_.AccessPath -eq $normalized } | Select-Object -First 1) { continue }

                [void]$candidates.Add((Get-OfflineWindowsInstallCandidate -AccessPath $normalized -PartitionInfo $part -Generation $generation))
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($WindowsDrive)) {
        $wanted = $WindowsDrive.TrimEnd(':', '\').ToUpperInvariant() + ':'
        $forced = @($candidates | Where-Object { $_.Drive -eq $wanted })
        if ($forced.Count -eq 0) {
            throw "No offline Windows installation was found on drive $wanted."
        }
        $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
        $forced | ForEach-Object { [void]$candidates.Add($_) }
    }

    if ($candidates.Count -eq 0) {
        throw 'No offline Windows installation was found on the attached disk(s).'
    }

    $sorted = @($candidates | Sort-Object @{ Expression = 'Score'; Descending = $true },
        @{ Expression = { [int]($_.CurrentBuildNumber -as [int]) }; Descending = $true }, PartitionNumber)
    $selected = $sorted[0]
    foreach ($candidate in $sorted) { $candidate.Selected = ($candidate.Drive -eq $selected.Drive) }

    if ($sorted.Count -gt 1) {
        Log-Warning "$($sorted.Count) Windows installations found on the attached disk(s). Selected $($selected.Drive) (score $($selected.Score))."
    }

    $selectedDisk = Get-Disk -Number $selected.DiskNumber -ErrorAction SilentlyContinue
    $generation = if ($selectedDisk.PartitionStyle -eq 'GPT') { 2 } elseif ($selectedDisk.PartitionStyle -eq 'MBR') { 1 } else { 0 }

    # Locate the boot partition and its BCD store on the same disk.
    $bootDrive = $null
    $bcdStorePath = $null
    foreach ($part in (Get-Partition -DiskNumber $selected.DiskNumber -ErrorAction SilentlyContinue)) {
        foreach ($accessPath in @($part.AccessPaths | Where-Object { $_ -and $_ -match '^[A-Za-z]:' })) {
            $efiBcd = Join-Path $accessPath 'EFI\Microsoft\Boot\BCD'
            $biosBcd = Join-Path $accessPath 'Boot\BCD'

            if ($generation -eq 2 -and "$($part.Type)" -eq 'System' -and (Test-Path -LiteralPath $efiBcd)) {
                $bootDrive = $accessPath.TrimEnd('\'); $bcdStorePath = $efiBcd; break
            }
            if ($generation -ne 2 -and (Test-Path -LiteralPath $biosBcd)) {
                $bootDrive = $accessPath.TrimEnd('\'); $bcdStorePath = $biosBcd; break
            }
        }
        if ($bootDrive) { break }
    }

    if (-not $bootDrive) {
        Log-Warning 'No BCD store was found on the attached disk. Boot configuration repairs will not be available.'
    }

    $script:OfflineWindowsDrive = $selected.Drive

    $result = [PSCustomObject]@{
        DiskNumber        = $selected.DiskNumber
        PartitionStyle    = "$($selectedDisk.PartitionStyle)"
        Generation        = $generation
        WindowsDrive      = $selected.Drive
        WindowsPath       = $selected.WindowsRoot
        PartitionNumber   = $selected.PartitionNumber
        BootDrive         = $bootDrive
        BcdStorePath      = $bcdStorePath
        ProductName       = $selected.ProductName
        BuildNumber       = $selected.CurrentBuildNumber
        GuestComputerName = $selected.GuestComputerName
        SetupInProgress   = $selected.SetupInProgress
        Candidates        = $sorted
    }

    Log-Info "Offline Windows: $($result.WindowsPath) (disk $($result.DiskNumber), Gen$($result.Generation), $($result.ProductName) build $($result.BuildNumber))"
    if ($result.GuestComputerName) { Log-Info "Guest computer name: $($result.GuestComputerName)" }
    if ($result.BootDrive) { Log-Info "Boot partition: $($result.BootDrive) (BCD: $($result.BcdStorePath))" }

    return $result
}
