# Windows Shared Helper Scripts

Each helper script and description should be listed here.

| Helper | Description |
|---|---|
| `Logger.ps1` | `Log-Output` / `Log-Info` / `Log-Warning` / `Log-Error` / `Log-Debug`. Imported automatically by `common/setup/init.ps1`. |
| `Get-Disk-Partitions.ps1` | Returns partitions of attached disks whose `Win32_diskdrive` model is `Microsoft Virtual Disk`, bringing them online with `diskpart`. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v2.ps1` | As v1, with `$partitionlist` initialised to an array so a single result is not unrolled. **SCSI-attached disks only.** |
| `Get-Disk-Partitions-v3.ps1` | `Get-Disk-Partitions-v3` selects attached disks by **BusType** (SCSI/SAS/RAID/NVMe) instead of the SCSI-only model string, so it also works when the repair VM uses the NVMe disk controller. Excludes the Azure resource disk. `Get-Windows-OsDrives-v3` narrows the result to drive letters that contain a Windows installation. |
| `OfflineRepairCommon.ps1` | Shared primitives for offline repair: buffered logging, path joining and validation, Authenticode/catalog signature inspection, and the offline-target gate (`Set-OfflineRepairRoot` / `Assert-OfflineTarget`) that binds every other offline helper to the attached disk. |
| `Get-OfflineWindowsDisk.ps1` | Finds the offline Windows installation on the attached disk, brings its disks online, assigns and tracks temporary drive letters for hidden EFI System and Recovery partitions, and releases them again. Selects by **BusType**, excludes the resource disk, and refuses to return the rescue VM's own boot/system disk. Binds the offline root for `Assert-OfflineTarget`. |

**Which one to use:** new scripts should use **v3**. v1 and v2 are retained because existing scripts depend
on them; they return nothing on a repair VM created with the NVMe disk controller.

`Get-OfflineWindowsDisk.ps1` solves a different problem from the `Get-Disk-Partitions` family: it
identifies the *Windows installation* to repair and binds it as the offline root, rather than
returning every attached partition. It selects disks by `BusType` for the same reason **v3** does.
