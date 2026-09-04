#########################################################################################################
#
# .SYNOPSIS
#   Restores the private key permissions behind the Remote Desktop listener certificate on an offline
#   disk, so a VM whose RDP service is running and listening but drops every connection can be reached
#   again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM where everything about Remote Desktop looks right. TermService is running, the
#   listener is on 3389, a certificate is present in the Remote Desktop store and it has not expired -
#   and every client is disconnected the moment the TLS handshake starts. The certificate is fine. The
#   private key behind it cannot be read by the account that has to read it.
#
#   TermService runs as NETWORK SERVICE. The listener's private key lives in a container file under
#   ProgramData\Microsoft\Crypto\RSA\MachineKeys, and NETWORK SERVICE needs read access to it on every
#   handshake. Strip that one access control entry and the service still starts, still listens, and
#   still fails every connection.
#
#   What makes this a repair rather than a wait is that Windows never recovers from it on its own.
#   Measured on a live VM: delete the certificate and its key and Windows mints a brand new key
#   container with correct permissions within seconds of the services restarting, so a MISSING
#   certificate is not a fault and is deliberately not repaired here. But leave a valid certificate in
#   place and break the permissions on its key, and nothing ever triggers regeneration - the
#   certificate has not expired, so there is nothing for Windows to renew. The VM stays unreachable
#   indefinitely.
#
#   The usual cause is a hardening pass over MachineKeys. Removing "Everyone" from that folder, or
#   replacing permissions on child objects, is a common and well-intentioned change; it takes
#   NETWORK SERVICE off the existing key containers with it. The damage often surfaces months later,
#   when the six-month self-signed certificate is renewed and the new key inherits the hardened
#   permissions.
#
#   "Prepare a Windows VHD or VHDX to upload to Azure"
#   (https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image) does not
#   describe these permissions, so there is no documented target to restore. The target used here was
#   measured instead, on healthy marketplace images of every supported build - Server 2012 R2 (9600),
#   2016 (14393), 2019 (17763), 2022 (20348), 2025 (26100) and Windows 11 (26100):
#
#     - The MachineKeys folder carries O:SYG:SYD:PAI(A;;0x12019f;;;WD)(A;;FA;;;BA) on all six.
#     - The key container is owned by SYSTEM, which holds FullControl, and NETWORK SERVICE holds Read
#       on all six.
#     - The third entry differs by build, and it SWAPS rather than accumulates. Up to and including
#       2016 it is BUILTIN\Administrators with Read. From 17763 onward that entry is gone and
#       NT SERVICE\SessionEnv holds FullControl instead. Writing one build's permissions onto the
#       other would be a change to a machine that had nothing wrong with it, so the build number is
#       read from the offline installation and the matching set is used.
#
#   The trigger and the target are deliberately not the same thing, exactly as in
#   win-fix-rdp-connectivity:
#
#     - The TRIGGER is the one condition that was proven to prevent RDP: NETWORK SERVICE cannot read
#       an RDP key container, because its access control entry is missing or is denied. A healthy VM
#       produces no findings and this script writes nothing at all.
#     - The TARGET, once that is found, is the full measured set for the build. A container that is
#       being repaired anyway is put back to the state its build ships with.
#
#   The MachineKeys folder permissions are repaired only alongside a broken container, never on their
#   own. That is a measured decision rather than a cautious one: a folder hardened to SYSTEM and
#   Administrators, with the key containers left correct, was tested and RDP kept working - Windows
#   even renewed the certificate successfully through it. Reporting that folder as a fault would fire
#   on a machine that is perfectly reachable. But the same hardened folder shaped the container
#   Windows created next, which came out without the SessionEnv entry, so a folder left hardened is
#   how a repaired VM breaks again at the next renewal. When a container has already proven the
#   certificate path is broken, the folder is put back with it.
#
#   Three things this script will not do, because the monolithic script it replaces did them and each
#   one is worse than the fault:
#
#     - It does not generate a certificate. The old script built one on the rescue VM, wrote the PFX
#       and its password in clear text into C:\temp on the target, and hijacked the target's first
#       boot with SetupType and CmdLine to import it. Windows generates its own certificate correctly
#       and unprompted once the permissions allow it.
#     - It does not run takeown and icacls recursively across MachineKeys. That grants NETWORK SERVICE
#       read on every private key on the machine - IIS, SQL, EFS, anything else stored there - and
#       reassigns ownership of all of them. Only container files belonging to the RDP listener are
#       touched here.
#     - It does not open a firewall rule. The old script enabled FPS-SMB-In-TCP as a side effect of
#       copying the PFX across. Nothing here needs SMB.
#
#   If the permissions are repaired and RDP still fails, the remaining option is to create a
#   certificate by hand and pin it to the listener with SSLCertificateSHA1Hash. That is an operator's
#   decision, it is temporary by nature, and it is the thing win-fix-rdp-connectivity removes - so it
#   is named here rather than done.
#
#   Access control entries are only ever ADDED. The existing descriptor is never replaced, so
#   permissions someone added deliberately survive the repair, and the original SDDL of anything
#   changed is written to the log so it can be put back by hand.
#
# .RESOLVES
#   A VM that boots, whose Remote Desktop service is running and listening on 3389, and which
#   disconnects every client immediately; an RDP client reporting an internal error before the logon
#   screen; RDP lost after a security hardening baseline was applied to the machine's private key
#   store; and RDP that failed months after such a baseline, when the listener certificate was renewed.
#
# .PARAMETER detectOnly
#   "true" to report what is wrong with the listener key permissions and change nothing at all.
#   Defaults to "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached offline Windows installation. Detected automatically when not
#   supplied.
#
# .NOTES
#   A VM that refuses RDP because remote connections are turned off, because the listener values are
#   out of range, or because a certificate is pinned to the listener, is win-fix-rdp-connectivity's
#   fault to fix. Run that one first. It removes SSLCertificateSHA1Hash so Windows generates a fresh
#   certificate - and that regeneration depends on the permissions this script repairs, so on a
#   machine where both are wrong, connectivity first and this one second.
#
#   TermService, SessionEnv and UmRdpService are reported when disabled but are never written here,
#   because win-fix-rdp-connectivity owns them.
#
#   The Remote Desktop certificate store itself is not modified, and neither is the machine key store
#   when it is absent. Neither is a fault: Windows recreates the store, the folder and the key, and
#   was measured doing all three.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Scripts run non-interactively through Run Command; report-only is detectOnly. New-Finding builds an object and changes nothing.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Add-OfflinePathAce uses $Ace inside the $apply script block, which the analyzer does not follow.')]
Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
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

$script:MachineKeysSubPath = 'ProgramData\Microsoft\Crypto\RSA\MachineKeys'
$script:DocUrl = 'https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image'

# Every Remote Desktop listener key container measured on 9600, 14393, 17763, 20348 and 26100 began
# with this prefix. It is the machine-independent hash of the container name the Terminal Server CSP
# asks for, so it identifies the listener's own keys without needing the certificate store parsed.
# Anything else in MachineKeys belongs to another component and is not touched.
$script:RdpContainerPrefix = 'f686aace'

# NT SERVICE\SessionEnv. Service SIDs are derived from the service name rather than issued per
# machine, so this value is the same on every Windows installation and is safe to write offline.
$script:SessionEnvSid = 'S-1-5-80-4022436659-1090538466-1613889075-870485073-3428993833'

$script:SidSystem = 'S-1-5-18'
$script:SidNetworkService = 'S-1-5-20'
$script:SidAdministrators = 'S-1-5-32-544'
$script:SidEveryone = 'S-1-1-0'

# Access masks as they appear in the measured descriptors.
$script:MaskFullControl = 0x1F01FF
$script:MaskReadSync = 0x120089   # FILE_GENERIC_READ, shown as "Read, Synchronize"
$script:MaskFolderEveryone = 0x12019F   # read plus the write that lets a new container be created

# The build at which the third entry on the container swaps from Administrators to SessionEnv.
$script:SessionEnvBuild = 17763

# Certificate services. Start=2 is Automatic and Start=3 is Manual; both were measured identical on
# all six builds. Only Start=4 (Disabled) is treated as evidence, so a service someone deliberately
# left demand-started is never "corrected". Owner names the script that repairs it, so that two
# scripts never write the same value.
$script:ServiceSpec = @(
    [PSCustomObject]@{ Name = 'CryptSvc'; Start = 2; Owner = $null; Purpose = 'Cryptographic Services - stores and serves the machine certificates' }
    [PSCustomObject]@{ Name = 'KeyIso'; Start = 3; Owner = $null; Purpose = 'CNG Key Isolation - performs the private key operations for the handshake' }
    [PSCustomObject]@{ Name = 'CertPropSvc'; Start = 3; Owner = $null; Purpose = 'Certificate Propagation' }
    [PSCustomObject]@{ Name = 'SessionEnv'; Start = 3; Owner = 'win-fix-rdp-connectivity'; Purpose = 'Remote Desktop Configuration - generates the listener certificate' }
    [PSCustomObject]@{ Name = 'TermService'; Start = 3; Owner = 'win-fix-rdp-connectivity'; Purpose = 'Remote Desktop Services - the listener itself' }
    [PSCustomObject]@{ Name = 'UmRdpService'; Start = 3; Owner = 'win-fix-rdp-connectivity'; Purpose = 'RD User Mode Port Redirector' }
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
        [Parameter(Mandatory = $true)][ValidateSet('SYSTEM', 'FILE')][string]$Hive,
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

function Get-RequiredContainerAce {
    <#
    .SYNOPSIS
        The access control entries a listener key container carries on this build.

    .DESCRIPTION
        Measured on healthy images rather than assumed. The third entry swaps at 17763 - it is
        Administrators with Read up to 2016 and SessionEnv with FullControl from 2019 - so returning
        both would write an entry the build does not ship with.
    #>
    param([Parameter(Mandatory = $true)][int]$BuildNumber)

    $required = @(
        [PSCustomObject]@{ Sid = $script:SidSystem; Mask = $script:MaskFullControl; Rights = 'FullControl'; Who = 'NT AUTHORITY\SYSTEM'; Critical = $false }
        [PSCustomObject]@{ Sid = $script:SidNetworkService; Mask = $script:MaskReadSync; Rights = 'Read'; Who = 'NT AUTHORITY\NETWORK SERVICE'; Critical = $true }
    )

    if ($BuildNumber -ge $script:SessionEnvBuild) {
        $required += [PSCustomObject]@{ Sid = $script:SessionEnvSid; Mask = $script:MaskFullControl; Rights = 'FullControl'; Who = 'NT SERVICE\SessionEnv'; Critical = $false }
    }
    else {
        $required += [PSCustomObject]@{ Sid = $script:SidAdministrators; Mask = $script:MaskReadSync; Rights = 'Read'; Who = 'BUILTIN\Administrators'; Critical = $false }
    }

    return @($required)
}

function Test-SddlGrant {
    <#
    .SYNOPSIS
        Whether a captured SDDL grants one SID at least the given access, and whether it denies it.

    .DESCRIPTION
        The descriptor is parsed rather than resolved through Get-Acl's identity references, because
        an offline installation carries SIDs this rescue VM cannot translate to names - a domain
        account, or a service SID for a service that is not installed here - and a translation
        failure must never be read as "the entry is missing".
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sddl,
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$Mask
    )

    $granted = $false
    $denied = $false

    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if ($null -ne $raw.DiscretionaryAcl) {
        foreach ($ace in $raw.DiscretionaryAcl) {
            if ($ace.SecurityIdentifier.Value -ne $Sid) { continue }
            if ($ace.AceType -eq 'AccessDenied' -and ($ace.AccessMask -band $Mask)) { $denied = $true }
            if ($ace.AceType -eq 'AccessAllowed' -and (($ace.AccessMask -band $Mask) -eq $Mask)) { $granted = $true }
        }
    }

    return [PSCustomObject]@{ Granted = $granted; Denied = $denied }
}

function Get-PathSddl {
    <#
    .SYNOPSIS
        The security descriptor of a file or folder, read even when its parent denies a listing.

    .DESCRIPTION
        Get-OfflinePathSecurity goes through Get-Acl, and the PowerShell provider resolves even a
        literal path in a way that needs access to the parent directory. A key container sitting in
        a hardened MachineKeys folder therefore comes back "unreadable" when its own descriptor is
        perfectly readable - and that is the exact shape this script exists to repair, so reporting
        it as unreadable would abandon the machine at the first hurdle. Measured: with the store
        hardened, Get-Acl on a container inside it fails with "Access is denied" while the .NET call
        below succeeds, because that one needs only the traverse right every account already has.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][switch]$IsDirectory
    )

    $sddl = Get-OfflinePathSecurity -Path $Path
    if ($sddl) { return $sddl }

    try {
        $info = if ($IsDirectory) { [System.IO.DirectoryInfo]::new($Path) } else { [System.IO.FileInfo]::new($Path) }
        return $info.GetAccessControl('Owner,Group,Access').GetSecurityDescriptorSddlForm('Owner,Group,Access')
    }
    catch { return $null }
}

function Get-KeyStoreState {
    <#
    .SYNOPSIS
        Reads the MachineKeys folder and every Remote Desktop listener key container on the disk.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$VolumeRoot,
        [Parameter(Mandatory = $true)][int]$BuildNumber
    )

    $folder = Join-Path $VolumeRoot $script:MachineKeysSubPath
    $folderExists = Test-Path -LiteralPath $folder
    $folderSddl = $null
    $folderOk = $true

    if ($folderExists) {
        $folderSddl = Get-PathSddl -Path $folder -IsDirectory
        if ($folderSddl) {
            $folderOk = (Test-SddlGrant -Sddl $folderSddl -Sid $script:SidEveryone -Mask $script:MaskFolderEveryone).Granted
        }
    }

    $required = Get-RequiredContainerAce -BuildNumber $BuildNumber
    $containers = @()
    $folderListed = $true

    if ($folderExists) {
        $filter = { $_.Name -like "$($script:RdpContainerPrefix)*" }
        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop | Where-Object $filter)
        }
        catch {
            # A store hardened hard enough to refuse this account a listing must never be read as
            # "no key container is present" - that would report a broken machine as healthy, and a
            # hardened store is precisely the case this script exists for. It is borrowed for the
            # length of the listing and handed straight back.
            $captured = Grant-OfflinePathAccess -Path $folder
            if ($captured) {
                if (-not $folderSddl) {
                    $folderSddl = $captured
                    $folderOk = (Test-SddlGrant -Sddl $captured -Sid $script:SidEveryone -Mask $script:MaskFolderEveryone).Granted
                }
                try { $files = @(Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop | Where-Object $filter) }
                catch { $folderListed = $false }
                [void](Restore-OfflinePathSecurity -Path $folder -Sddl $captured)
            }
            else { $folderListed = $false }
        }

        foreach ($file in $files) {
            $sddl = Get-PathSddl -Path $file.FullName
            if (-not $sddl) {
                # Same borrow and return. A container whose descriptor denies even READ_CONTROL is
                # the shape this script repairs, so it must be looked at rather than written off.
                $captured = Grant-OfflinePathAccess -Path $file.FullName
                if ($captured) {
                    $sddl = $captured
                    [void](Restore-OfflinePathSecurity -Path $file.FullName -Sddl $captured)
                }
            }

            $missing = @()
            $blocked = @()
            $readable = $true

            if (-not $sddl) { $readable = $false }
            else {
                foreach ($ace in $required) {
                    $check = Test-SddlGrant -Sddl $sddl -Sid $ace.Sid -Mask $ace.Mask
                    if ($check.Denied) { $blocked += $ace }
                    elseif (-not $check.Granted) { $missing += $ace }
                }
            }

            # Only NETWORK SERVICE was proven to stop RDP, so only NETWORK SERVICE fires a finding.
            $nsBroken = @(@($missing) + @($blocked) | Where-Object { $_.Sid -eq $script:SidNetworkService }).Count -gt 0

            $containers += [PSCustomObject]@{
                Path     = $file.FullName
                Name     = $file.Name
                Sddl     = $sddl
                Readable = $readable
                Missing  = @($missing)
                Blocked  = @($blocked)
                NsBroken = $nsBroken
            }
        }
    }

    return [PSCustomObject]@{
        FolderPath   = $folder
        FolderExists = $folderExists
        FolderSddl   = $folderSddl
        FolderOk     = $folderOk
        FolderListed = $folderListed
        Required     = @($required)
        Containers   = @($containers)
    }
}

function Get-CertificateServiceState {
    <#
    .SYNOPSIS
        Reads the Start value of every service the listener certificate depends on.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $services = foreach ($spec in $script:ServiceSpec) {
        $path = Join-Path $SystemRoot "Services\$($spec.Name)"
        $exists = Test-Path -LiteralPath $path
        $start = $null
        $denied = $false

        if ($exists) {
            $found = $false
            $value = Get-OfflineProtectedRegistryValue -Path $path -Name 'Start' -Found ([ref]$found) -Denied ([ref]$denied)
            if ($found) { $start = [int]$value }
        }

        [PSCustomObject]@{
            Name     = $spec.Name
            Spec     = $spec
            Path     = $path
            Exists   = $exists
            Start    = $start
            Denied   = $denied
            Disabled = ($exists -and $start -eq 4)
        }
    }

    return @($services)
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Turns the state that was read into the list of things actually preventing the handshake.
    #>
    param(
        [Parameter(Mandatory = $true)]$KeyStore,
        [Parameter(Mandatory = $true)]$Services
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # --- The key containers -----------------------------------------------------------------------
    # A missing MachineKeys folder is deliberately not a fault. Measured on a live VM: renaming the
    # folder away and deleting the certificate produced a new folder, a new key container and a
    # working listener within seconds of the services restarting. Reporting it would fire on a
    # machine that Windows repairs by itself.
    if ($KeyStore.FolderExists) {
        if (-not $KeyStore.FolderListed) {
            [void]$findings.Add((New-Finding -Cause 'MachineKeysFolderUnreadable' -Item 'MachineKeys' -Hive 'FILE' -Repairable $false `
                        -Message "$($KeyStore.FolderPath) could not be listed even after taking ownership of it, so whether the listener's key container is intact is unknown. Nothing was changed. Inspect it by hand before concluding the certificate is not the problem."))
        }
        foreach ($container in @($KeyStore.Containers)) {
            if (-not $container.Readable) {
                [void]$findings.Add((New-Finding -Cause 'ContainerSecurityUnreadable' -Item $container.Name -Hive 'FILE' -Repairable $false `
                            -Message "The security descriptor of $($container.Path) could not be read, so its permissions were left alone rather than replaced with something that was never compared against."))
                continue
            }
            if (-not $container.NsBroken) { continue }

            $blockedNs = @(@($container.Blocked) | Where-Object { $_.Sid -eq $script:SidNetworkService }).Count -gt 0
            $how = if ($blockedNs) { 'is explicitly denied' } else { 'has no entry' }
            $alsoMissing = @(@($container.Missing) | Where-Object { $_.Sid -ne $script:SidNetworkService } | ForEach-Object { $_.Who })

            $message = "NT AUTHORITY\NETWORK SERVICE $how on the listener key container $($container.Name). TermService runs as NETWORK SERVICE and reads this key on every handshake, so the service starts, the port listens and every connection is dropped. Windows will not repair this by itself, because the certificate is still valid and there is nothing for it to renew."
            if ($alsoMissing.Count -gt 0) { $message += " $($alsoMissing -join ' and ') is also missing and will be restored with it." }
            $message += " Current: $($container.Sddl)"

            [void]$findings.Add((New-Finding -Cause 'ContainerKeyUnreadable' -Item $container.Name -Hive 'FILE' -Data $container -Message $message))
        }

        # Only alongside a broken container - see the header. On its own a hardened folder was
        # measured NOT to prevent RDP, so it must not fire on a machine that is reachable.
        $broken = @(@($KeyStore.Containers) | Where-Object { $_.NsBroken })
        if ($broken.Count -gt 0 -and -not $KeyStore.FolderOk) {
            [void]$findings.Add((New-Finding -Cause 'MachineKeysFolderHardened' -Item 'MachineKeys' -Hive 'FILE' -Data $KeyStore `
                        -Message "The machine key store at $($KeyStore.FolderPath) no longer grants Everyone the read and write access that every measured build ships with. This does not block RDP on its own and would not have been touched by itself, but it is the folder the listener's next key container is created in - one created under these permissions came out incomplete when tested - so it is restored alongside the container. Current: $($KeyStore.FolderSddl)"))
        }
    }

    # --- Services ---------------------------------------------------------------------------------
    foreach ($service in @($Services)) {
        if (-not $service.Exists) {
            if (-not $service.Spec.Owner) {
                [void]$findings.Add((New-Finding -Cause 'CertificateServiceMissing' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                            -Message "The $($service.Name) service key is missing ($($service.Spec.Purpose)). That is a damaged installation rather than a configuration fault, and this script will not create one."))
            }
            continue
        }
        if (-not $service.Disabled) { continue }

        if ($service.Spec.Owner) {
            [void]$findings.Add((New-Finding -Cause 'DependencyServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). The listener certificate cannot be used while it is, but $($service.Spec.Owner) owns this service and will restore it to Start=$($service.Spec.Start). It was not changed here."))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'CertificateServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Data $service `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). Without it the private key operations behind the handshake cannot run. It will be set to Start=$($service.Spec.Start), the value measured on every supported build."))
        }
    }

    return $findings.ToArray()
}

function Add-OfflinePathAce {
    <#
    .SYNOPSIS
        Adds access control entries to a file or folder, taking ownership only if refused.

    .DESCRIPTION
        Entries are added to the descriptor that is already there; it is never replaced. Anything an
        administrator added deliberately survives, and a denied entry for the same SID is removed
        first because a deny beats an allow no matter which order they appear in.

        Ownership is only taken when the plain write is actually refused, and the original owner is
        put back afterwards, so a container that is repaired does not come away owned by the rescue
        VM's administrator.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Ace,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $false)][switch]$IsDirectory
    )

    # Told rather than probed. Get-Item on a path inside a hardened folder fails for the same
    # provider reason Get-Acl does, and the caller always knows which of the two it is holding.
    $isDirectory = [bool]$IsDirectory
    $original = Get-PathSddl -Path $Path -IsDirectory:$isDirectory
    if (-not $original) {
        Add-OfflineRepairLog -Level Warning -Message "Could not read the security descriptor of $Path, so it was left alone."
        return $false
    }

    $apply = {
        $current = Get-PathSddl -Path $Path -IsDirectory:$isDirectory
        if (-not $current) { throw "The security descriptor of $Path could not be read." }

        # Worked at the raw level rather than through FileSecurity.AddAccessRule. .NET refuses to
        # modify a list whose entries are out of canonical order - a deny sitting after an allow,
        # which hardening scripts and hand written tools both produce - and an already damaged
        # descriptor is exactly the one that needs repairing. Rebuilding it restores the order
        # Windows expects while keeping every flag, including which entries were inherited.
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($current)
        $revision = 2
        $existing = @()
        if ($null -ne $raw.DiscretionaryAcl) {
            $revision = $raw.DiscretionaryAcl.Revision
            for ($i = 0; $i -lt $raw.DiscretionaryAcl.Count; $i++) { $existing += $raw.DiscretionaryAcl[$i] }
        }

        # A deny beats an allow whatever the order, so any deny for these accounts goes first.
        $targets = @(@($Ace) | ForEach-Object { $_.Sid })
        $existing = @($existing | Where-Object { -not ($_.AceType.ToString() -like '*Denied*' -and $targets -contains $_.SecurityIdentifier.Value) })

        foreach ($entry in @($Ace)) {
            # The measured mask, not the friendly name: [FileSystemRights]::Read is 0x20089, while
            # every build ships 0x120089 - the same rights plus Synchronize.
            $existing += [System.Security.AccessControl.CommonAce]::new(
                'None', 'AccessAllowed', [int]$entry.Mask,
                [System.Security.Principal.SecurityIdentifier]::new($entry.Sid), $false, $null)
        }

        # Canonical order: explicit deny, explicit allow, inherited deny, inherited allow.
        $inheritedFlag = [int][System.Security.AccessControl.AceFlags]::Inherited
        $ordered = @(
            @($existing | Where-Object { -not ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -like '*Denied*' })
            @($existing | Where-Object { -not ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -notlike '*Denied*' })
            @($existing | Where-Object { ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -like '*Denied*' })
            @($existing | Where-Object { ([int]$_.AceFlags -band $inheritedFlag) -and $_.AceType.ToString() -notlike '*Denied*' })
        )

        $newAcl = [System.Security.AccessControl.RawAcl]::new($revision, $ordered.Count)
        for ($i = 0; $i -lt $ordered.Count; $i++) { $newAcl.InsertAce($i, $ordered[$i]) }
        $raw.DiscretionaryAcl = $newAcl

        $sd = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
        $sd.SetSecurityDescriptorSddlForm($raw.GetSddlForm('Access'), 'Access')
        Save-OfflinePathSecurity -Path $Path -Security $sd -IsDirectory:$isDirectory
    }

    try {
        & $apply
        Add-OfflineRepairLog -Message "$Description Original descriptor was $original"
        return $true
    }
    catch {
        Add-OfflineRepairLog -Level Info -Message "$Path refused the permission change ($($_.Exception.Message)); taking ownership and retrying."
    }

    $captured = $null
    try { $captured = Grant-OfflinePathAccess -Path $Path }
    catch { Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be taken ($($_.Exception.Message))." }
    if (-not $captured) {
        Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be taken, so its permissions were left alone."
        return $false
    }

    try {
        & $apply

        # Hand the object back. The DACL just written is kept; only the owner is replayed, and only
        # when taking it actually changed the owner.
        $ownerNow = Get-OfflineSddlOwner -Sddl (Get-PathSddl -Path $Path -IsDirectory:$isDirectory)
        $ownerWas = Get-OfflineSddlOwner -Sddl $captured
        if ($ownerWas -and $ownerNow -ne $ownerWas) {
            $ownerOnly = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
            $ownerOnly.SetOwner([System.Security.Principal.SecurityIdentifier]::new($ownerWas))
            try { Save-OfflinePathSecurity -Path $Path -Security $ownerOnly -IsDirectory:$isDirectory }
            catch { Add-OfflineRepairLog -Level Warning -Message "Ownership of $Path could not be handed back to $ownerWas. Restore it with: icacls `"$Path`" /setowner `"NT AUTHORITY\SYSTEM`"" }
        }

        Add-OfflineRepairLog -Message "$Description Ownership was taken to do it. Original descriptor was $original"
        return $true
    }
    catch {
        Restore-OfflinePathSecurity -Path $Path -Sddl $captured | Out-Null
        Add-OfflineRepairLog -Level Warning -Message "$Path could not be repaired ($($_.Exception.Message)); its original permissions were put back."
        return $false
    }
}

function Repair-FileFinding {
    <#
    .SYNOPSIS
        Repairs one finding that lives on the file system rather than in a hive.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    switch -Regex ($Finding.Cause) {

        '^ContainerKeyUnreadable$' {
            $container = $Finding.Data
            $restore = @(@($container.Missing) + @($container.Blocked))
            if ($restore.Count -eq 0) { return $false }
            $who = @($restore | ForEach-Object { "$($_.Who) ($($_.Rights))" }) -join ', '
            return (Add-OfflinePathAce -Path $container.Path -Ace $restore `
                    -Description "$($container.Name): restored $who on the listener key container, so the Remote Desktop service can read its private key again.")
        }

        '^MachineKeysFolderHardened$' {
            $ace = [PSCustomObject]@{ Sid = $script:SidEveryone; Mask = $script:MaskFolderEveryone; Rights = 'Read, Write, Synchronize'; Who = 'Everyone' }
            return (Add-OfflinePathAce -Path $Finding.Data.FolderPath -Ace $ace -IsDirectory `
                    -Description 'MachineKeys: restored the read and write access every measured build grants on the machine key store, so the next listener key container is created complete.')
        }

        default { return $false }
    }
}

function Repair-RegistryFinding {
    <#
    .SYNOPSIS
        Repairs one finding that lives in the SYSTEM hive.
    #>
    param([Parameter(Mandatory = $true)]$Finding)

    switch -Regex ($Finding.Cause) {

        '^CertificateServiceDisabled$' {
            $service = $Finding.Data
            $outcome = Invoke-OfflineProtectedRegistryWrite -Path $service.Path -Description "$($service.Name) Start" -Action {
                Set-ItemProperty -Path $service.Path -Name 'Start' -Value ([uint32]$service.Spec.Start) -Type DWord -Force -ErrorAction Stop
            }
            if ($outcome.Written) {
                Add-OfflineRepairLog -Message "$($service.Name): Start 4 (Disabled) -> $($service.Spec.Start), the value measured on every supported build."
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "$($service.Name) Start could not be written: $($outcome.Reason)"
            return $false
        }

        default { return $false }
    }
}

"$scriptStartTime" | Out-File -FilePath $logFile -Append
Log-Output "START: Running script $scriptName (detectOnly=$isDetectOnly)" | Tee-Object -FilePath $logFile -Append

try {
    $offline = Get-OfflineWindowsDisk -WindowsDrive $windowsDrive
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $buildNumber = 0
    [void][int]::TryParse("$($offline.BuildNumber)", [ref]$buildNumber)
    $volumeRoot = Split-Path -Path $offline.WindowsPath -Parent

    Log-Info "Offline Windows installation: $($offline.WindowsPath) on disk $($offline.DiskNumber) ($($offline.ProductName) build $($offline.BuildNumber))" | Tee-Object -FilePath $logFile -Append
    Log-Info "Listener certificate permissions are not covered by $($script:DocUrl); the target below was measured on healthy images of 9600, 14393, 17763, 20348 and 26100." | Tee-Object -FilePath $logFile -Append

    if ($buildNumber -le 0) {
        Log-Warning 'The build number of the offline installation could not be read. The pre-17763 permission set is assumed, which grants Administrators read rather than SessionEnv full control.' | Tee-Object -FilePath $logFile -Append
    }

    $keyStore = Get-KeyStoreState -VolumeRoot $volumeRoot -BuildNumber $buildNumber
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $services = Get-CertificateServiceState -SystemRoot $systemRoot

        return [PSCustomObject]@{
            ControlSet = (Split-Path -Path $systemRoot -Leaf)
            Services   = @($services)
            Findings   = @(Get-AllFinding -KeyStore $keyStore -Services $services)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    Log-Info "Control set $($context.ControlSet)." | Tee-Object -FilePath $logFile -Append
    Log-Info "Machine key store: $($keyStore.FolderPath) $(if ($keyStore.FolderExists) { 'present' } else { 'absent - not a fault, Windows recreates it and the key with it on the next start' })." | Tee-Object -FilePath $logFile -Append
    if ($keyStore.FolderExists) {
        Log-Info "  Folder descriptor: $($keyStore.FolderSddl)" | Tee-Object -FilePath $logFile -Append
    }

    Log-Info "Expected on build $($offline.BuildNumber): $(@($keyStore.Required | ForEach-Object { "$($_.Who)=$($_.Rights)" }) -join ', ')." | Tee-Object -FilePath $logFile -Append

    if (@($keyStore.Containers).Count -eq 0 -and $keyStore.FolderExists) {
        # Measured: with no container present Windows generates a new one, with correct permissions,
        # within seconds of the Remote Desktop services starting. Stated so nobody reads it as a fault.
        Log-Info 'No Remote Desktop listener key container is present. That is not a fault: Windows generates one on the next start, and it was measured doing so.' | Tee-Object -FilePath $logFile -Append
    }
    foreach ($container in @($keyStore.Containers)) {
        Log-Info "  $($container.Name): $(if ($container.NsBroken) { 'NETWORK SERVICE cannot read it' } else { 'NETWORK SERVICE can read it' })." | Tee-Object -FilePath $logFile -Append
    }

    foreach ($service in @($context.Services)) {
        $shown = if (-not $service.Exists) { 'no service key' } elseif ($null -eq $service.Start) { '(Start not set)' } else { "Start=$($service.Start)" }
        Log-Info "  $($service.Name): $shown - $($service.Spec.Purpose)." | Tee-Object -FilePath $logFile -Append
    }

    $findings = @($context.Findings)
    foreach ($finding in $findings) {
        Log-Info "FOUND [$($finding.Cause)] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
    }

    $repairable = @($findings | Where-Object { $_.Repairable })
    $unrepairable = @($findings | Where-Object { -not $_.Repairable })

    if ($isDetectOnly) {
        foreach ($finding in $findings) {
            Log-Output "  [$(if ($finding.Repairable) { 'FIXABLE' } else { 'MANUAL ' })] $($finding.Message)" | Tee-Object -FilePath $logFile -Append
        }
        # The count comes after the list on purpose. Run Command keeps the tail of a 4096-character log,
        # so a summary printed first is the first thing a long run loses.
        Log-Output "Detect only: found $($findings.Count) issue(s), $($repairable.Count) of which this script can repair. No changes were made." | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    if ($findings.Count -eq 0) {
        Log-Output 'No listener certificate fault was found. The Remote Desktop service account can read the listener private key and the services behind it are not disabled. No changes were made.' | Tee-Object -FilePath $logFile -Append
        Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
        return $STATUS_SUCCESS
    }

    $repairedCount = 0
    $failed = [System.Collections.Generic.List[string]]::new()

    # --- File system repairs, outside any hive ----------------------------------------------------
    foreach ($finding in @($repairable | Where-Object { $_.Hive -eq 'FILE' })) {
        try {
            if (Repair-FileFinding -Finding $finding) {
                $finding.Repaired = $true
                $repairedCount++
            }
        }
        catch {
            [void]$failed.Add("$($finding.Item): $($_.Exception.Message)")
            Add-OfflineRepairLog -Level Warning -Message "$($finding.Item): repair failed ($($_.Exception.Message))."
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # --- Registry repairs -------------------------------------------------------------------------
    $registryFindings = @($repairable | Where-Object { $_.Hive -eq 'SYSTEM' })
    if ($registryFindings.Count -gt 0) {
        $backup = Backup-OfflineHiveFile -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath
        Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append
        Log-Info "SYSTEM hive backed up to $backup" | Tee-Object -FilePath $logFile -Append

        $repairOutcome = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
            $done = 0
            $errors = [System.Collections.Generic.List[string]]::new()
            foreach ($finding in $registryFindings) {
                try {
                    if (Repair-RegistryFinding -Finding $finding) {
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

        $repairedCount += $repairOutcome.Repaired
        foreach ($failure in @($repairOutcome.Errors)) { [void]$failed.Add($failure) }
    }

    # Verify against freshly read state rather than trusting the writes above.
    $verifyKeyStore = Get-KeyStoreState -VolumeRoot $volumeRoot -BuildNumber $buildNumber
    $remaining = Invoke-WithHive -Hive 'SYSTEM' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        return @(Get-AllFinding -KeyStore $verifyKeyStore -Services (Get-CertificateServiceState -SystemRoot $systemRoot))
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
        Log-Output "Run 'az vm repair restore' to swap the repaired disk back to the original VM. If RDP still fails once it boots, the remaining option is to create a certificate by hand and pin it to the listener with SSLCertificateSHA1Hash, which is a temporary measure and an operator's decision." | Tee-Object -FilePath $logFile -Append
    }
    Log-Output "Detail log: $logFile" | Tee-Object -FilePath $logFile -Append
    return $STATUS_SUCCESS
}
catch {
    Log-Error "$($_.Exception.Message)" | Tee-Object -FilePath $logFile -Append
    Log-Error "$($_.ScriptStackTrace)" | Tee-Object -FilePath $logFile -Append
    return $STATUS_ERROR
}
