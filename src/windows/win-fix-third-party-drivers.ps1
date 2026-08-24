#########################################################################################################
#
# .SYNOPSIS
#   Disables third party kernel drivers that stop a VM booting, while refusing to touch any driver
#   the VM needs to reach its disk or its network.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create". A third party
#   filter or endpoint driver that loads at Boot or System start can bugcheck or hang the guest
#   before logon. Setting Start=4 on that driver is the offline equivalent of booting into safe
#   mode: Windows stops loading it, the VM boots, and the driver can be repaired or reinstalled
#   from inside.
#
#   The risk this script is built around is the opposite mistake. Disabling the wrong driver turns
#   a recoverable failure into an unrecoverable one:
#     - Disable the storage miniport or a disk filter and the guest bugchecks 0x7B
#       INACCESSIBLE_BOOT_DEVICE, with no disk to repair from.
#     - Disable a disk encryption filter and the volume is unreadable, which looks identical to
#       corruption.
#     - Disable the Mellanox NIC driver behind Accelerated Networking and the guest boots to a VM
#       with no network, so nobody can reach it to undo the change.
#
#   A vendor name list does not prevent that, because the vendor that owns the boot path differs
#   per image. The protection here is structural: a driver is protected because of the job it is
#   registered to do, whoever wrote it. The checks, any one of which protects a driver:
#     1. It is in the boot critical driver list below.
#     2. The PnP device tree shows it servicing a device in a protected class: storage adapter,
#        disk, volume, hard disk controller, system bus or network. This is read from
#        Enum\<enumerator>\<device>\<instance>, where Service names the driver and ClassGUID names
#        the class, so it holds for any vendor.
#     3. Its Group puts it on the storage, file system, filter or network load path, for example
#        "SCSI Miniport", "Boot Bus Extender", "Filter" or "NDIS".
#     4. It is registered as an UpperFilters or LowerFilters entry on a protected device class.
#        This is the check that catches encryption and storage filters, which have no PnP device of
#        their own and so are invisible to check 2.
#     5. It is registered as a filter on a specific boot critical device instance.
#     6. It appears in the CriticalDeviceDatabase, which is what Windows uses to start a driver
#        before the PnP tree is available.
#     7. Its binary is signed by, or carries the company name of, a vendor whose drivers an Azure
#        VM genuinely needs for storage, networking or GPU. This is the weakest check and is a
#        backstop only, never the sole reason a driver is considered safe to disable.
#
#   No parameter overrides that protected set. A protected driver is reported with the reason it
#   was protected, and left alone. If the evidence really does name a protected driver, the fix is
#   to replace the driver file or roll the image back, not to unload the boot path.
#
#   Causes detected and repaired:
#     1. A third party Boot or System start kernel driver that is not protected by any check above.
#        Repaired by setting Start=4 on that service.
#     2. A third party Boot or System start driver whose binary is missing from the disk. A Boot
#        start driver with no file bugchecks 0x7B on its own, so this is repaired the same way.
#
#   Reported but never repaired:
#     - Every protected driver, with the check that protected it.
#     - Drivers at Auto or Demand start. They load after the boot path is up, so disabling them
#       cannot fix a boot failure and is pure risk.
#
# .RESOLVES
#   Boot failures, bugchecks and pre logon hangs caused by a third party kernel driver, typically
#   after an antivirus, EDR, backup or monitoring agent update. Also the case where a driver file
#   was deleted or quarantined but its service was left at Boot start.
#
# .PARAMETER detectOnly
#   "true" to report what would be disabled and make no writes at all. Defaults to "false".
#
# .PARAMETER driverName
#   Service name of a single driver to disable, for example "mydriver". Use this when a bugcheck or
#   a log has already named the culprit. The protection checks still apply. When omitted, every
#   unprotected third party Boot and System start driver is considered.
#
# .PARAMETER revert
#   "true" to put back the Start values recorded by an earlier run of this script on this disk.
#   Reads the revert manifest written to the root of the offline Windows drive.
#
# .PARAMETER windowsDrive
#   Drive letter of the offline Windows installation, for example "F". Only needed when more than
#   one Windows installation is attached and the automatically selected one is not the right one.
#
# .EXAMPLE
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-third-party-drivers --parameters detectOnly=true --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-third-party-drivers --parameters driverName=myfilter --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-third-party-drivers --run-on-repair --verbose
#   az vm repair run -g sourceRG -n sourceVM --run-id win-fix-third-party-drivers --parameters revert=true --run-on-repair --verbose
#
# .NOTES
#   Author: Marcus Ferreira
#
#   Switch parameters are declared as ValidateSet strings on purpose. The extension turns
#   "--parameters name=value" into "-name value", and passing a value to a real [switch] also binds
#   that value to the next positional parameter.
#
#   Changes are applied to the active control set only, the one Select\Current points at, which is
#   the one the guest will boot. A driver disabled here is still enabled in LastKnownGood, so
#   choosing Last Known Good Configuration at boot undoes the repair. That is deliberate: it leaves
#   the operator an escape route that does not need the rescue VM.
#
#   Service Group names are compared case insensitively because Windows itself is inconsistent
#   about them. A stock Windows Server 2022 image ships both "SCSI miniport" and "SCSI Miniport",
#   and spells the PnP filter group "PNP Filter".
#
#   File system minifilter groups are matched individually rather than as an "FSFilter *" family.
#   The group is the driver's altitude band: the bands below the file system, such as Encryption
#   and Bottom, can leave the volume unreadable if the driver stops loading, while Anti-Virus and
#   Activity Monitor sit above it and are safe to disable. A stock image carries live drivers at
#   System start in both bands, so matching the whole family would spare the antivirus and endpoint
#   drivers that are the usual cause of this failure.
#
#   The revert manifest is written to the root of the offline Windows drive so that it travels back
#   to the source VM with the disk. Every change is also printed as a "reg add" command in the log,
#   because the rescue VM and its desktop log are deleted by "az vm repair restore".
#
#   The SYSTEM hive file is backed up next to itself before the first write.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$driverName = '',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false')][string]$revert = 'false',
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
$targetDriver = $driverName.Trim()

# Drivers the VM boots through. Disabling one of these swaps the current failure for a 0x7B, so
# they are never candidates, whoever the evidence names.
$script:BootCriticalDriver = @(
    'acpi', 'pci', 'vmbus', 'storvsc', 'storahci', 'stornvme', 'storport', 'disk', 'partmgr',
    'volmgr', 'volmgrx', 'volsnap', 'mountmgr', 'fltmgr', 'ntfs', 'refs', 'vdrvroot', 'msisadrv',
    'pcw', 'fvevol', 'iorate', 'wof', 'clfs', 'ksecdd', 'cng', 'intelide', 'atapi', 'ataport',
    'amdsata', 'iastorv', 'iastora', 'vhdmp', 'spaceport', 'netvsc', 'ndis', 'tcpip', 'afd',
    'netbt', 'tdx', 'http', 'hvsocket', 'winhv', 'hyperkbd', 'vpci', 'storufs', 'sdstor',
    'bindflt', 'fileinfo', 'wcifs', 'msfs', 'npfs'
)

# Device classes that carry the boot path or the only route back into the VM. A driver servicing a
# device in one of these, or filtering the class, is protected regardless of who wrote it.
$script:ProtectedDeviceClass = @{
    '{4d36e967-e325-11ce-bfc1-08002be10318}' = 'DiskDrive'
    '{4d36e96a-e325-11ce-bfc1-08002be10318}' = 'HDC'
    '{4d36e97b-e325-11ce-bfc1-08002be10318}' = 'SCSIAdapter'
    '{4d36e97d-e325-11ce-bfc1-08002be10318}' = 'System'
    '{71a27cdd-812a-11d0-bec7-08002be2092f}' = 'Volume'
    '{533c5b84-ec70-11d2-9505-00c04f79deaf}' = 'VolumeSnapshot'
    '{4d36e972-e325-11ce-bfc1-08002be10318}' = 'Net'
    '{4d36e968-e325-11ce-bfc1-08002be10318}' = 'Display'
    '{4d36e980-e325-11ce-bfc1-08002be10318}' = 'FloppyDisk'
    '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}' = 'HIDClass'
}

# Load order groups that put a driver on the storage, file system or network path. Windows itself
# is inconsistent about the casing, so these are matched case insensitively: a stock Windows Server
# 2022 image ships both "SCSI miniport" and "SCSI Miniport", and "PNP Filter" rather than "PnP".
#
# The file system filter groups are deliberately not matched as a family. A minifilter's group is
# its altitude band, and only the bands that sit below the file system can make the volume
# unreadable. "FSFilter Anti-Virus" and "FSFilter Activity Monitor" sit above it, and a stock image
# carries live examples of both at System start, so protecting the whole family would spare exactly
# the antivirus and monitoring drivers this script exists to disable.
$script:ProtectedGroupPattern = @(
    '^SCSI (Miniport|Class|CDROM Class)$',
    '^Boot Bus Extender$',
    '^System Bus Extender$',
    '^Primary Disk$',
    '^(Boot )?File System$',
    '^(PnP )?Filter$',
    '^FSFilter (Bottom|Encryption|Virtualization|Infrastructure|System Recovery|Physical Quota Management)$',
    '^NDIS',
    '^Network',
    '^PNP_TDI$',
    '^TDI$',
    '^Port$',
    '^Video( Init| Save)?$',
    '^WdfLoadGroup$',
    '^Pointer Port$',
    '^Keyboard Port$'
)

# Vendors whose drivers an Azure VM can genuinely need for storage, networking or GPU. Mellanox in
# particular is Accelerated Networking: disabling it offline produces a VM that boots and cannot be
# reached. This is a backstop behind the structural checks, never the only reason to spare a driver.
$script:PlatformVendorPattern = (@(
        'Mellanox', 'NVIDIA', 'Intel', 'Advanced Micro Devices', 'AMD', 'Chelsio', 'Marvell',
        'Broadcom', 'QLogic', 'Emulex', 'Solarflare', 'Xilinx', 'Amazon', 'Google'
    ) | ForEach-Object { [regex]::Escape($_) }) -join '|'

$script:MicrosoftVendorPattern = 'Microsoft'

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

function Get-MultiStringValue {
    <#
    .SYNOPSIS
        Reads a REG_MULTI_SZ value as a string array, tolerating a missing key or value.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return @() }
    $value = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($null -eq $value) { return @() }
    return @($value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Get-DeviceTopology {
    <#
    .SYNOPSIS
        Builds the vendor independent map of which drivers are on the boot or network path.

    .DESCRIPTION
        Four lookups, keyed by lower case service name, each holding the human readable reason:
          ServiceClass    - the driver is the function driver for a device in a protected class.
          ClassFilter     - the driver filters a protected device class as a whole.
          InstanceFilter  - the driver filters one specific device in a protected class.
          CriticalDevice  - the driver is named in the CriticalDeviceDatabase.

        Only the ServiceClass map can be built from Enum, and it only covers drivers that own a PnP
        device. Filter drivers have no device of their own, which is why the other three exist.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $serviceClass = @{}
    $classFilter = @{}
    $instanceFilter = @{}
    $criticalDevice = @{}

    $record = {
        param($Table, $Service, $Reason)
        if ([string]::IsNullOrWhiteSpace($Service)) { return }
        $key = $Service.Trim().ToLowerInvariant()
        if (-not $Table.ContainsKey($key)) { $Table[$key] = [System.Collections.Generic.List[string]]::new() }
        if (-not $Table[$key].Contains($Reason)) { [void]$Table[$key].Add($Reason) }
    }

    # 1. Function drivers. Enum\<enumerator>\<device>\<instance> holds Service and ClassGUID, which
    #    is how Windows itself decides what a driver is for. Depth 2 from Enum reaches the instance
    #    keys without walking the whole tree.
    $enumRoot = "$SystemRoot\Enum"
    if (Test-Path -LiteralPath $enumRoot) {
        foreach ($instance in (Get-ChildItem -LiteralPath $enumRoot -Recurse -Depth 2 -ErrorAction SilentlyContinue)) {
            $properties = Get-ItemProperty -LiteralPath $instance.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $properties) { continue }

            $classGuid = $properties.ClassGUID
            if ([string]::IsNullOrWhiteSpace($classGuid)) { continue }
            $className = $script:ProtectedDeviceClass[$classGuid.Trim().ToLowerInvariant()]
            if (-not $className) { continue }

            $deviceId = $instance.PSPath -replace '^.*\\Enum\\', ''
            if ($properties.Service) {
                & $record $serviceClass $properties.Service "it is the driver for $deviceId, a device in the protected $className class"
            }
            foreach ($filterName in @('UpperFilters', 'LowerFilters')) {
                foreach ($filter in (Get-MultiStringValue -Path $instance.PSPath -Name $filterName)) {
                    & $record $instanceFilter $filter "it is a $filterName entry on $deviceId, a device in the protected $className class"
                }
            }
        }
    }

    # 2. Class wide filters. This is where storage and encryption filter drivers live, and they are
    #    the ones most likely to be mistaken for a removable third party driver.
    foreach ($entry in $script:ProtectedDeviceClass.GetEnumerator()) {
        $classPath = "$SystemRoot\Control\Class\$($entry.Key)"
        if (-not (Test-Path -LiteralPath $classPath)) { continue }
        foreach ($filterName in @('UpperFilters', 'LowerFilters')) {
            foreach ($filter in (Get-MultiStringValue -Path $classPath -Name $filterName)) {
                & $record $classFilter $filter "it is a $filterName entry on the protected $($entry.Value) device class"
            }
        }
    }

    # 3. CriticalDeviceDatabase. Empty on a stock image, populated by storage vendors and by some
    #    P2V and migration tooling, and what Windows uses before the PnP tree is available.
    $cddbPath = "$SystemRoot\Control\CriticalDeviceDatabase"
    if (Test-Path -LiteralPath $cddbPath) {
        foreach ($entry in (Get-ChildItem -LiteralPath $cddbPath -ErrorAction SilentlyContinue)) {
            $service = (Get-ItemProperty -LiteralPath $entry.PSPath -Name 'Service' -ErrorAction SilentlyContinue).Service
            if ($service) {
                & $record $criticalDevice $service "it is named in the CriticalDeviceDatabase entry $($entry.PSChildName), so Windows starts it before the device tree exists"
            }
        }
    }

    return [PSCustomObject]@{
        ServiceClass   = $serviceClass
        ClassFilter    = $classFilter
        InstanceFilter = $instanceFilter
        CriticalDevice = $criticalDevice
    }
}

function Get-DriverInventory {
    <#
    .SYNOPSIS
        Reads every kernel and file system driver service, with the facts needed to judge it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    $drivers = [System.Collections.Generic.List[object]]::new()
    $servicesPath = "$SystemRoot\Services"
    if (-not (Test-Path -LiteralPath $servicesPath)) { return @() }

    foreach ($service in (Get-ChildItem -LiteralPath $servicesPath -ErrorAction SilentlyContinue)) {
        $properties = Get-ItemProperty -LiteralPath $service.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $properties) { continue }

        # Type 1 is a kernel driver and Type 2 a file system driver. Everything else is a user mode
        # service and cannot bugcheck the boot path.
        $type = $properties.Type
        if ($type -isnot [int] -or $type -notin @(1, 2)) { continue }

        $imagePath = $properties.ImagePath
        $resolved = ''
        $exists = $false
        $vendor = ''

        if (-not [string]::IsNullOrWhiteSpace($imagePath)) {
            $resolved = Resolve-OfflineImagePath -ImagePath $imagePath -WindowsDrive $WindowsDrive
        }
        else {
            # A driver with no ImagePath loads from System32\drivers\<name>.sys by convention.
            $resolved = Join-OfflinePath -Root $WindowsDrive -ChildPath "Windows\System32\drivers\$($service.PSChildName).sys"
        }

        if (Test-OfflinePath $resolved) {
            $exists = $true
            try { $vendor = (Get-Item -LiteralPath $resolved -ErrorAction Stop).VersionInfo.CompanyName } catch { $vendor = '' }
        }

        $isMicrosoft = $false
        if ($vendor -and $vendor -match $script:MicrosoftVendorPattern) { $isMicrosoft = $true }

        [void]$drivers.Add([PSCustomObject]@{
                Service      = $service.PSChildName
                Start        = $(if ($properties.Start -is [int]) { $properties.Start } else { -1 })
                Type         = $type
                Group        = $(if ($properties.Group) { [string]$properties.Group } else { '' })
                ImagePath    = $(if ($imagePath) { [string]$imagePath } else { '' })
                ResolvedPath = $resolved
                FileName     = $(if ($resolved) { Split-Path -Path $resolved -Leaf } else { '' })
                Exists       = $exists
                Vendor       = $vendor
                IsMicrosoft  = $isMicrosoft
            })
    }

    return @($drivers)
}

function Test-DriverProtected {
    <#
    .SYNOPSIS
        Returns the reason a driver must not be disabled, or an empty string when it is a candidate.

    .DESCRIPTION
        Checks run cheapest and most authoritative first. The vendor check is last because a company
        name in a resource block is the weakest evidence here: it is unsigned metadata that any
        driver can carry. It only ever protects, never exposes.
    #>
    param(
        [Parameter(Mandatory = $true)]$Driver,
        [Parameter(Mandatory = $true)]$Topology
    )

    $key = $Driver.Service.ToLowerInvariant()

    if ($script:BootCriticalDriver -contains $key) {
        return 'it is a boot critical driver: the VM reaches its disk, bus or network through it'
    }

    foreach ($table in @(
            @{ Map = $Topology.ServiceClass; },
            @{ Map = $Topology.ClassFilter; },
            @{ Map = $Topology.InstanceFilter; },
            @{ Map = $Topology.CriticalDevice; }
        )) {
        if ($table.Map.ContainsKey($key)) { return ($table.Map[$key] -join '; ') }
    }

    if (-not [string]::IsNullOrWhiteSpace($Driver.Group)) {
        foreach ($pattern in $script:ProtectedGroupPattern) {
            if ($Driver.Group -match $pattern) {
                return "its load order group `"$($Driver.Group)`" puts it on the storage, file system or network path"
            }
        }
    }

    if ($Driver.Vendor -and $Driver.Vendor -match $script:PlatformVendorPattern) {
        return "its binary is published by $($Driver.Vendor), a vendor whose drivers an Azure VM can need for storage, networking or GPU"
    }

    return ''
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Turns the driver inventory into findings, honouring detect scope and the protected set.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Drivers,
        [Parameter(Mandatory = $true)]$Topology,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$TargetService = ''
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($driver in $Drivers) {
        if ($TargetService -and $driver.Service -ne $TargetService) { continue }

        # Microsoft drivers are not what this scenario is for. win-fix-code-integrity-boot-failure
        # and win-fix-inaccessible-boot-device handle the inbox ones.
        if ($driver.IsMicrosoft) { continue }

        $protectedReason = Test-DriverProtected -Driver $driver -Topology $Topology
        if ($protectedReason) {
            [void]$findings.Add((New-Finding -Cause 'ProtectedDriver' -Item $driver.Service -Repairable $false `
                        -Message "$($driver.Service) ($(if ($driver.FileName) { $driver.FileName } else { 'no image path' }), $(if ($driver.Vendor) { $driver.Vendor } else { 'unknown vendor' })) was NOT disabled because $protectedReason." `
                        -Data $driver))
            continue
        }

        # Auto and Demand start drivers load after the boot path is up, so disabling them cannot fix
        # a boot failure. Reported only when explicitly named, otherwise they are just noise.
        if ($driver.Start -notin @(0, 1)) {
            if ($TargetService) {
                [void]$findings.Add((New-Finding -Cause 'NotOnBootPath' -Item $driver.Service -Repairable $false `
                            -Message "$($driver.Service) is at Start=$($driver.Start), which loads after the boot path is already up. Disabling it cannot fix a boot failure, so it was left alone." `
                            -Data $driver))
            }
            continue
        }

        if (-not $driver.Exists) {
            [void]$findings.Add((New-Finding -Cause 'MissingDriverImage' -Item $driver.Service `
                        -Message "$($driver.Service) is configured to load at $(if ($driver.Start -eq 0) { 'Boot' } else { 'System' }) start but its image is missing from the disk ($($driver.ResolvedPath)). Windows bugchecks on a Boot start driver it cannot load." `
                        -Data $driver))
            continue
        }

        [void]$findings.Add((New-Finding -Cause 'ThirdPartyBootDriver' -Item $driver.Service `
                    -Message "$($driver.Service) ($($driver.FileName), $(if ($driver.Vendor) { $driver.Vendor } else { 'unknown vendor' })) is a third party driver loading at $(if ($driver.Start -eq 0) { 'Boot' } else { 'System' }) start and is on no protected path." `
                    -Data $driver))
    }

    return @($findings)
}

function Get-RevertManifestPath {
    <#
    .SYNOPSIS
        Path of the revert manifest, at the root of the offline Windows drive so it travels with it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive
    )

    return (Join-OfflinePath -Root $WindowsDrive -ChildPath 'win-fix-third-party-drivers-revert.json')
}

function Read-RevertManifest {
    <#
    .SYNOPSIS
        Reads the recorded original Start values. Returns an empty array when there is nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    if (-not (Test-OfflinePath $ManifestPath)) { return @() }
    try {
        $content = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) { return @() }

        # ConvertFrom-Json emits a JSON array as ONE pipeline item, so @($content | ConvertFrom-Json)
        # yields a single element that is itself the array. Assigning first collapses it, and @()
        # on the variable then flattens properly. Without this a three driver manifest reads back
        # as one entry whose Service property is an array of three names.
        $parsed = $content | ConvertFrom-Json
        return @($parsed)
    }
    catch {
        Add-OfflineRepairLog -Level Warning -Message "The revert manifest $ManifestPath could not be read ($($_.Exception.Message))."
        return @()
    }
}

function Write-RevertManifest {
    <#
    .SYNOPSIS
        Records the original Start value of each disabled driver.

    .DESCRIPTION
        An existing entry is never overwritten. Running the script twice must not record the
        disabled value as the original, or revert would put the driver back as disabled.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries
    )

    if ($Entries.Count -eq 0) { return }

    $existing = @(Read-RevertManifest -ManifestPath $ManifestPath)
    $known = @{}
    foreach ($entry in $existing) { $known[$entry.Service.ToLowerInvariant()] = $true }

    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $existing) { [void]$merged.Add($entry) }
    foreach ($entry in $Entries) {
        if ($known.ContainsKey($entry.Service.ToLowerInvariant())) { continue }
        [void]$merged.Add($entry)
    }

    $json = ConvertTo-Json -InputObject @($merged) -Depth 4
    Set-Content -LiteralPath $ManifestPath -Value $json -Encoding UTF8 -Force -ErrorAction Stop
    Add-OfflineRepairLog -Message "Revert manifest written to $ManifestPath ($($merged.Count) entry(s))."
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Disables the one driver a finding names, and returns the manifest entry for it.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][string]$ControlSet
    )

    $driver = $Finding.Data
    $keyPath = "$SystemRoot\Services\$($driver.Service)"
    if (-not (Test-Path -LiteralPath $keyPath)) { throw "The service key $keyPath is no longer present." }

    # Re-read Start rather than trusting the inventory, so a concurrent change cannot make the
    # manifest record a value that was never there.
    $currentStart = (Get-ItemProperty -LiteralPath $keyPath -Name 'Start' -ErrorAction SilentlyContinue).Start
    if ($currentStart -isnot [int]) { throw "The service key $keyPath has no readable Start value." }
    if ($currentStart -eq 4) {
        Add-OfflineRepairLog -Message "$($driver.Service): already disabled, nothing to do."
        return $null
    }

    Set-ItemProperty -LiteralPath $keyPath -Name 'Start' -Value 4 -Type DWord -Force -ErrorAction Stop
    Add-OfflineRepairLog -Message "$($driver.Service): Start $currentStart -> 4 (disabled) in $ControlSet."
    Add-OfflineRepairLog -Message "$($driver.Service): to undo this after the VM boots, run: reg add `"HKLM\SYSTEM\CurrentControlSet\Services\$($driver.Service)`" /v Start /t REG_DWORD /d $currentStart /f"

    return [PSCustomObject]@{
        Service       = $driver.Service
        OriginalStart = $currentStart
        Type          = $driver.Type
        Group         = $driver.Group
        ImagePath     = $driver.ImagePath
        Vendor        = $driver.Vendor
        Cause         = $Finding.Cause
        DisabledAt    = (Get-Date -Format 'o')
        ControlSet    = $ControlSet
    }
}

function Invoke-DriverRevert {
    <#
    .SYNOPSIS
        Puts back every Start value recorded in the manifest.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries
    )

    $restored = 0
    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $Entries) {
        $keyPath = "$SystemRoot\Services\$($entry.Service)"
        if (-not (Test-Path -LiteralPath $keyPath)) {
            [void]$errors.Add("$($entry.Service): the service key is no longer present.")
            continue
        }

        $currentStart = (Get-ItemProperty -LiteralPath $keyPath -Name 'Start' -ErrorAction SilentlyContinue).Start
        if ($currentStart -eq $entry.OriginalStart) {
            Add-OfflineRepairLog -Message "$($entry.Service): already at Start=$($entry.OriginalStart), nothing to do."
            continue
        }

        try {
            Set-ItemProperty -LiteralPath $keyPath -Name 'Start' -Value ([int]$entry.OriginalStart) -Type DWord -Force -ErrorAction Stop
            Add-OfflineRepairLog -Message "$($entry.Service): Start $currentStart -> $($entry.OriginalStart) (restored)."
            $restored++
        }
        catch {
            [void]$errors.Add("$($entry.Service): $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{ Restored = $restored; Errors = @($errors) }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly, driverName=$(if ($targetDriver) { $targetDriver } else { '<all>' }), revert=$isRevert)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append

    $manifestPath = Get-RevertManifestPath -WindowsDrive $offline.WindowsDrive

    if ($isRevert) {
        $entries = @(Read-RevertManifest -ManifestPath $manifestPath)
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if ($entries.Count -eq 0) {
            Log-Output "No revert manifest was found at $manifestPath, so this script has not disabled anything on this disk. No changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }

        Log-Info "Revert manifest holds $($entries.Count) driver(s): $(@($entries.Service) -join ', ')" | Tee-Object -FilePath $logFile -Append

        if ($isDetectOnly) {
            foreach ($entry in $entries) {
                Log-Output "  [WOULD RESTORE] $($entry.Service): Start -> $($entry.OriginalStart)" | Tee-Object -FilePath $logFile -Append
            }
            Log-Output "Detect only: no changes were made." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_SUCCESS
        }

        $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append

        $revertOutcome = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            return (Invoke-DriverRevert -SystemRoot (Get-OfflineSystemRootPath) -Entries $entries)
        }
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

        if ($revertOutcome.Errors.Count -gt 0) {
            foreach ($failure in $revertOutcome.Errors) { Log-Warning $failure | Tee-Object -FilePath $logFile -Append }
            Log-Error "Restored $($revertOutcome.Restored) of $($entries.Count) driver(s). $($revertOutcome.Errors.Count) failed." | Tee-Object -FilePath $logFile -Append
            Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
            return $STATUS_ERROR
        }

        Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
        Log-Output "Restored $($revertOutcome.Restored) driver(s) to their original Start value and removed the manifest." | Tee-Object -FilePath $logFile -Append
        Log-Output "Run 'az vm repair restore' to swap the disk back to the original VM." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $context = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $topology = Get-DeviceTopology -SystemRoot $systemRoot
        $drivers = @(Get-DriverInventory -SystemRoot $systemRoot -WindowsDrive $offline.WindowsDrive)
        $findings = @(Get-AllFinding -Drivers $drivers -Topology $topology -TargetService $targetDriver)

        return [PSCustomObject]@{
            SystemRoot = $systemRoot
            ControlSet = (Split-Path -Path $systemRoot -Leaf)
            Topology   = $topology
            Drivers    = $drivers
            Findings   = $findings
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $thirdParty = @($context.Drivers | Where-Object { -not $_.IsMicrosoft })
    $protectedPathCount = @($context.Topology.ServiceClass.Keys).Count + @($context.Topology.ClassFilter.Keys).Count +
    @($context.Topology.InstanceFilter.Keys).Count + @($context.Topology.CriticalDevice.Keys).Count

    Log-Info "Control set $($context.ControlSet): $($context.Drivers.Count) kernel and file system driver(s) configured, $($thirdParty.Count) of them non-Microsoft." | Tee-Object -FilePath $logFile -Append
    Log-Info "Device tree, class filters and CriticalDeviceDatabase mark $protectedPathCount driver registration(s) as being on a protected path." | Tee-Object -FilePath $logFile -Append

    if ($targetDriver -and @($context.Drivers | Where-Object { $_.Service -eq $targetDriver }).Count -eq 0) {
        Log-Warning "No kernel or file system driver service named '$targetDriver' exists in $($context.ControlSet). Check the spelling: this is the service name, not the file name." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    $protected = @($findings | Where-Object { $_.Cause -eq 'ProtectedDriver' })
    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    foreach ($finding in $protected) {
        Log-Info "PROTECTED $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }
    foreach ($finding in $repairable) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    if ($repairable.Count -eq 0) {
        Log-Output "No third party driver on this disk is both loading at Boot or System start and off every protected path. Nothing was changed." | Tee-Object -FilePath $logFile -Append
        if ($protected.Count -gt 0) {
            Log-Output "$($protected.Count) third party driver(s) were deliberately left alone because the VM boots or reaches the network through them. They are listed above with the reason." | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($isDetectOnly) {
        Log-Output "Detect only: $($repairable.Count) driver(s) would be disabled, $($protected.Count) protected driver(s) would be left alone. No changes were made." | Tee-Object -FilePath $logFile -Append
        foreach ($finding in $repairable) {
            Log-Output "  [WOULD DISABLE] $($finding.Item): $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        foreach ($finding in $unrepairable) {
            Log-Output "  [PROTECTED    ] $($finding.Item): $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append

    $repairOutcome = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $controlSet = Split-Path -Path $systemRoot -Leaf
        $done = 0
        $entries = [System.Collections.Generic.List[object]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()

        foreach ($finding in $repairable) {
            try {
                $entry = Repair-Finding -Finding $finding -SystemRoot $systemRoot -ControlSet $controlSet
                if ($null -ne $entry) {
                    [void]$entries.Add($entry)
                    $finding.Repaired = $true
                    $done++
                }
            }
            catch {
                [void]$errors.Add("$($finding.Item): $($_.Exception.Message)")
                Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
            }
        }

        return [PSCustomObject]@{ Repaired = $done; Entries = @($entries); Errors = @($errors) }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    if ($repairOutcome.Entries.Count -gt 0) {
        Write-RevertManifest -ManifestPath $manifestPath -Entries $repairOutcome.Entries
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
    }

    # Verify against freshly read state rather than trusting the writes above.
    $remaining = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $topology = Get-DeviceTopology -SystemRoot $systemRoot
        $drivers = @(Get-DriverInventory -SystemRoot $systemRoot -WindowsDrive $offline.WindowsDrive)
        return @(Get-AllFinding -Drivers $drivers -Topology $topology -TargetService $targetDriver)
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $stillRepairable = @($remaining | Where-Object { $_.Repairable })
    foreach ($finding in $stillRepairable) {
        Log-Warning "STILL PRESENT [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $summary = "Disabled $($repairOutcome.Repaired) of $($repairable.Count) third party driver(s)."
    if ($protected.Count -gt 0) { $summary += " $($protected.Count) driver(s) were protected and left alone." }

    if ($repairOutcome.Errors.Count -gt 0 -or $stillRepairable.Count -gt 0) {
        Log-Error "$summary $($repairOutcome.Errors.Count) change(s) failed and $($stillRepairable.Count) driver(s) are still enabled." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_ERROR
    }

    Log-Output $summary | Tee-Object -FilePath $logFile -Append
    Log-Output "Every change is printed above as a 'reg add' command, and recorded in $manifestPath on the OS disk. Re-run with -revert true to put them all back." | Tee-Object -FilePath $logFile -Append
    Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM." | Tee-Object -FilePath $logFile -Append
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
