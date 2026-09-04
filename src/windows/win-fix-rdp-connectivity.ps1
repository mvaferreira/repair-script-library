#########################################################################################################
#
# .SYNOPSIS
#   Restores Remote Desktop on an offline disk, so an Azure VM that boots and is on the network but
#   refuses every RDP connection can be reached again.
#
# .DESCRIPTION
#   Runs against the broken OS disk attached to a rescue VM by "az vm repair create".
#
#   This is the VM that answers ping, whose guest agent may still be reporting, and whose boot
#   diagnostics show a healthy logon screen - and which refuses every RDP connection anyway. Nothing
#   is corrupt and nothing failed to start; the Terminal Server configuration simply says that remote
#   connections are not allowed, or the listener cannot negotiate a session with any client.
#
#   Every value this script writes comes from "Prepare a Windows VHD or VHDX to upload to Azure"
#   (https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image), which
#   is the supported description of how a Windows VM must be configured to be reachable in Azure.
#   The goal is a VM an engineer can get back into, not a VM restored to whatever Windows ships with.
#
#   Where the two differ, the document wins. That distinction is not theoretical: a healthy Server
#   2022 marketplace image was read before this script was written and it disagrees with the
#   document in two places - IKEEXT is Manual on the image where the document says Automatic, and
#   KeepAliveTimeout is 0 where the document says 1. Restoring "the Windows default" would put
#   IKEEXT back to a value the Azure guidance does not ask for.
#
#   That same comparison decides what counts as a fault. Those two deviations exist on a machine that
#   is perfectly reachable, so "differs from the document" cannot be the trigger for a repair - it
#   would fire on every healthy Azure VM and change two values that were never the problem. So:
#
#     - The TRIGGER is evidence that RDP is actually prevented. A healthy VM produces no findings and
#       this script writes nothing at all.
#     - The TARGET, once something is found to be broken, is the value the document specifies.
#
#   Four configurations are treated as evidence, and all four are readable and repairable offline:
#
#     1. fDenyTSConnections=1. This is "Allow remote connections to this computer" turned off. The
#        document sets it in two places - the Terminal Server key and the Group Policy copy under
#        SOFTWARE - and the policy copy wins, so a VM can have the base key correct and still refuse
#        everything. Both are checked and both are repaired; repairing one and leaving the other
#        produces a VM that is exactly as unreachable and a log that claims success.
#
#     2. A required service disabled (Start=4). The document lists the services that must be running
#        for a VM to be reachable, with the startup type each one needs, and a disabled service
#        cannot start whatever else is correct. Only Start=4 is treated as evidence, so a service
#        deliberately left demand-started is never "corrected" into something else.
#
#     3. An out-of-range SecurityLayer, UserAuthentication or MinEncryptionLevel on the RDP-Tcp
#        listener. Windows does not clamp these - a value outside the documented set leaves the
#        listener unable to agree a security layer with any client, which reaches the user as an
#        immediate disconnect with no useful error.
#
#     4. A certificate pinned to the listener, or TLS 1.2 explicitly disabled in SCHANNEL. Step 8 of
#        the document removes SSLCertificateSHA1Hash for exactly this reason: if the pinned
#        certificate's private key no longer resolves, the handshake fails before authentication and
#        the client reports a generic internal error. Removing the pin lets Windows generate a fresh
#        self-signed listener certificate on the next start. TLS 1.2 is not in the document, but RDP
#        negotiates over TLS and a hardening script that disabled 1.2 alongside 1.0 and 1.1 leaves
#        the listener with nothing to offer; enabling it is a repair rather than a downgrade, and
#        1.0 and 1.1 are not touched either way.
#
#   Faults that belong to another script are reported with their owner named rather than repaired
#   here, so two scripts never write the same value:
#
#     - nsi, Dhcp, Dnscache and iphlpsvc disabled -> win-fix-network-connectivity
#     - BFE and mpssvc disabled                   -> win-fix-firewall-service
#     - a listener certificate that is present but broken, and its private key permissions
#                                                 -> win-fix-rdp-certificate
#
#   Three things are never done unless asked for by name, because each trades away security or
#   working configuration to gain access, and that is an operator's decision rather than a script's:
#
#     - NLA is only turned off with -disableNla. The document configures UserAuthentication=1, so
#       NLA being enabled is the supported state and is never reported as a fault.
#     - A non-standard listener port is reported, never reset, unless -resetListenerPort is passed.
#       The document specifies 3389 for an image being prepared, but a deployed VM whose port was
#       moved deliberately has a firewall rule and a network security group that followed it, and
#       resetting the port on one of those removes the access it was meant to restore. Measured on
#       a repaired VM: with the listener moved to 33890 the service started and listened on
#       0.0.0.0:33890, and the connection was still refused, because the built-in "Remote Desktop -
#       User Mode (TCP-In)" rule is scoped to 3389. A moved port needs its own rule at both layers,
#       which is why this is reported for a decision rather than repaired.
#     - The machine-wide SSL cipher suite policy is only cleared with -clearCipherSuitePolicy. It is
#       present on a healthy Azure image, carrying the platform's intended cipher order, so deleting
#       it on sight would strip working configuration off every machine this ran against. Only an
#       EMPTY suite list is treated as a fault, because that genuinely leaves nothing to negotiate.
#
#   AllowEncryptionOracle is not written by this script under any parameter. Setting it to 2 makes
#   CredSSP accept the CVE-2018-0886 downgrade again, and a repair script is not the place to
#   reintroduce a remote code execution vulnerability on a machine about to go back into service.
#
#   -applyAzureBaseline applies the document's full Remote Desktop registry configuration - the
#   keep-alive, reconnect, LanAdapter and MaxInstanceCount values - rather than only what is broken.
#   It is off by default because those values do not prevent a connection and one of them differs on
#   a healthy image. Pass it when a VM's Terminal Server configuration has been edited enough that
#   returning it wholesale to the documented state is quicker than reasoning about each value.
#
#   The SYSTEM and SOFTWARE hives are backed up before either is written to.
#
# .RESOLVES
#   A VM that boots and responds on the network but refuses RDP, an RDP client reporting that the
#   remote computer is not accepting connections, a session that disconnects immediately after the
#   handshake with an internal error, RDP lost after a hardening baseline or service-tuning script
#   was applied, and a VM whose Remote Desktop services were disabled by policy.
#
# .PARAMETER detectOnly
#   "true" to report the Remote Desktop configuration and what would be changed, and make no changes
#   at all. Defaults to "false".
#
# .PARAMETER windowsDrive
#   The drive letter of the attached offline Windows installation. Detected automatically when not
#   supplied.
#
# .PARAMETER applyAzureBaseline
#   "true" to also apply the documented keep-alive, reconnect, LanAdapter and MaxInstanceCount
#   values from "Prepare a Windows VHD to upload to Azure", whether or not they are currently wrong.
#   Defaults to "false" - see the note above.
#
# .PARAMETER disableNla
#   "true" to turn Network Level Authentication off on the listener. Defaults to "false". The Azure
#   guidance enables NLA, so this is a deliberate deviation from it. Pass this only when the VM
#   cannot be reached because its clients cannot pre-authenticate - a broken machine account or an
#   unreachable domain controller - and turn it back on once the VM is in.
#
# .PARAMETER resetListenerPort
#   "true" to reset the RDP listener to port 3389, the port the document specifies. Defaults to
#   "false", because a deployed VM may have been moved off 3389 deliberately.
#
# .PARAMETER clearCipherSuitePolicy
#   "true" to remove the machine-wide SSL cipher suite policy. Defaults to "false", because this
#   policy is present and correct on a healthy Azure VM. Pass this only when the configured suite
#   list is known to exclude everything the RDP listener can offer.
#
# .NOTES
#   A hive that will not load at all is a different problem and belongs to
#   win-fix-registry-corruption. This script needs SYSTEM and SOFTWARE to mount before it can read
#   anything, so run that one first if either hive is damaged.
#
#   A VM that is unreachable at the network layer - no ping, no agent - is not this script's fault to
#   fix. Run win-fix-network-connectivity first and come back here only if RDP is still refused once
#   the VM is on the network.
#
#   The document also requires the Windows Firewall to be ON for all three profiles, with the Remote
#   Desktop rule group enabled. Nothing in this script turns a firewall off.
#
# .VERSION
#   v1.0: Initial version.
#
#########################################################################################################

Param(
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$detectOnly = 'false',
    [Parameter(Mandatory = $false)][string]$windowsDrive = '',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$applyAzureBaseline = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$disableNla = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$resetListenerPort = 'false',
    [Parameter(Mandatory = $false)][ValidateSet('true', 'false', IgnoreCase = $true)][string]$clearCipherSuitePolicy = 'false'
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
$wantBaseline = ($applyAzureBaseline -eq 'true')
$wantDisableNla = ($disableNla -eq 'true')
$wantResetPort = ($resetListenerPort -eq 'true')
$wantClearCiphers = ($clearCipherSuitePolicy -eq 'true')

$script:TerminalServerSubPath = 'Control\Terminal Server'
$script:RdpTcpSubPath = 'Control\Terminal Server\WinStations\RDP-Tcp'
$script:TerminalServerPolicyPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$script:CipherPolicyPath = 'HKLM:\BROKENSOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
$script:StandardRdpPort = 3389
$script:DocUrl = 'https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image'

# The services "Prepare a Windows VHD to upload to Azure" requires, with the startup type it gives
# each one. Automatic is Start=2 and Manual is Start=3.
#
#   Automatic: BFE, Dhcp, Dnscache, IKEEXT, iphlpsvc, nsi, mpssvc, RemoteRegistry
#   Manual:    Netlogon, Netman, TermService
#
# IKEEXT is the one worth knowing about: the document says Automatic, a healthy Server 2022
# marketplace image ships it Manual. The document is what a VM in Azure is supported at, so it is
# the value used when the service is found disabled - but a service that is merely Manual is not
# disabled, produces no finding, and is left alone.
#
# Owner names which script restores the value. RDP's own services are repaired here; the rest are
# reported so that two scripts never write the same value.
$script:ServiceSpec = @(
    [PSCustomObject]@{ Name = 'TermService'; DocStart = 3; Owner = $null; Source = 'documented Manual'; Purpose = 'Remote Desktop Services - the listener itself' }
    [PSCustomObject]@{ Name = 'SessionEnv'; DocStart = 3; Owner = $null; Source = 'not in the document; Windows ships it Manual'; Purpose = 'Remote Desktop Configuration' }
    [PSCustomObject]@{ Name = 'UmRdpService'; DocStart = 3; Owner = $null; Source = 'not in the document; Windows ships it Manual'; Purpose = 'RD User Mode Port Redirector' }
    [PSCustomObject]@{ Name = 'Netlogon'; DocStart = 3; Owner = $null; Source = 'documented Manual'; Purpose = 'Net Logon - domain logon for domain-joined VMs' }
    [PSCustomObject]@{ Name = 'Netman'; DocStart = 3; Owner = $null; Source = 'documented Manual'; Purpose = 'Network Connections' }
    [PSCustomObject]@{ Name = 'RemoteRegistry'; DocStart = 2; Owner = $null; Source = 'documented Automatic'; Purpose = 'Remote Registry - remote troubleshooting of this VM' }
    [PSCustomObject]@{ Name = 'nsi'; DocStart = 2; Owner = 'win-fix-network-connectivity'; Source = 'documented Automatic'; Purpose = 'Network Store Interface - TCP/IP does not come up without it' }
    [PSCustomObject]@{ Name = 'Dhcp'; DocStart = 2; Owner = 'win-fix-network-connectivity'; Source = 'documented Automatic'; Purpose = 'DHCP Client - no lease means no address' }
    [PSCustomObject]@{ Name = 'Dnscache'; DocStart = 2; Owner = 'win-fix-network-connectivity'; Source = 'documented Automatic'; Purpose = 'DNS Client' }
    [PSCustomObject]@{ Name = 'iphlpsvc'; DocStart = 2; Owner = 'win-fix-network-connectivity'; Source = 'documented Automatic'; Purpose = 'IP Helper' }
    [PSCustomObject]@{ Name = 'IKEEXT'; DocStart = 2; Owner = 'win-fix-network-connectivity'; Source = 'documented Automatic, though a healthy image ships it Manual'; Purpose = 'IKE and AuthIP keying modules' }
    [PSCustomObject]@{ Name = 'BFE'; DocStart = 2; Owner = 'win-fix-firewall-service'; Source = 'documented Automatic'; Purpose = 'Base Filtering Engine - mpssvc cannot start without it' }
    [PSCustomObject]@{ Name = 'mpssvc'; DocStart = 2; Owner = 'win-fix-firewall-service'; Source = 'documented Automatic'; Purpose = 'Windows Firewall - no inbound rules means no RDP' }
)

# Documented value sets for the listener. A value outside its set is the fault; a value inside it is
# left alone even when it is not the documented target, because it is a supported configuration.
$script:ListenerValueSpec = @(
    [PSCustomObject]@{ Name = 'SecurityLayer'; Valid = @(0, 1, 2); DocValue = 2; Purpose = 'how the listener secures the connection (0 RDP, 1 negotiate, 2 TLS)' }
    [PSCustomObject]@{ Name = 'UserAuthentication'; Valid = @(0, 1); DocValue = 1; Purpose = 'whether Network Level Authentication is required' }
    [PSCustomObject]@{ Name = 'MinEncryptionLevel'; Valid = @(1, 2, 3, 4); DocValue = 3; Purpose = 'the minimum encryption the listener accepts' }
)

# The document's Remote Desktop registry configuration, steps 3 to 7. None of these prevent a
# connection on their own, so they are only written when -applyAzureBaseline is passed. Hive says
# which of the two mounted hives the value lives in.
$script:BaselineValueSpec = @(
    [PSCustomObject]@{ Name = 'LanAdapter'; Value = 0; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'the listener listens on every network interface' }
    [PSCustomObject]@{ Name = 'KeepAliveTimeout'; Value = 1; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'keep-alive timeout' }
    [PSCustomObject]@{ Name = 'fInheritReconnectSame'; Value = 1; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'inherit the reconnect setting' }
    [PSCustomObject]@{ Name = 'fReconnectSame'; Value = 0; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'reconnect from any client rather than only the original one' }
    [PSCustomObject]@{ Name = 'MaxInstanceCount'; Value = 4294967295; Hive = 'SYSTEM'; Scope = 'Listener'; Purpose = 'do not limit concurrent connections' }
    [PSCustomObject]@{ Name = 'KeepAliveEnable'; Value = 1; Hive = 'SOFTWARE'; Scope = 'Policy'; Purpose = 'keep-alive enabled' }
    [PSCustomObject]@{ Name = 'KeepAliveInterval'; Value = 1; Hive = 'SOFTWARE'; Scope = 'Policy'; Purpose = 'keep-alive interval' }
    [PSCustomObject]@{ Name = 'fDisableAutoReconnect'; Value = 0; Hive = 'SOFTWARE'; Scope = 'Policy'; Purpose = 'automatic reconnect allowed' }
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

function Get-OfflineValueState {
    <#
    .SYNOPSIS
        Reads one value, distinguishing "not set" from "could not be read".

    .DESCRIPTION
        Returns Value, Found and Denied rather than a bare value, because a key locked against
        Administrators returns nothing at all and that must never be reported as "not set". A repair
        that then writes a documented default over a value it never managed to read is changing
        something it never looked at.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $found = $false
    $denied = $false
    $value = Get-OfflineProtectedRegistryValue -Path $Path -Name $Name -Found ([ref]$found) -Denied ([ref]$denied)

    return [PSCustomObject]@{
        Path   = $Path
        Name   = $Name
        Value  = $value
        Found  = $found
        Denied = $denied
    }
}

function Get-TerminalServerState {
    <#
    .SYNOPSIS
        Reads the Terminal Server configuration: the deny switch, the listener and its values.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $tsPath = Join-Path $SystemRoot $script:TerminalServerSubPath
    $rdpPath = Join-Path $SystemRoot $script:RdpTcpSubPath
    $listenerPresent = Test-Path -LiteralPath $rdpPath

    $listener = @()
    if ($listenerPresent) {
        foreach ($spec in $script:ListenerValueSpec) {
            $read = Get-OfflineValueState -Path $rdpPath -Name $spec.Name
            $listener += [PSCustomObject]@{
                Spec    = $spec
                Value   = $read.Value
                Found   = $read.Found
                Denied  = $read.Denied
                IsValid = ((-not $read.Found) -or ($spec.Valid -contains [int]$read.Value))
            }
        }
    }

    $baseline = @()
    foreach ($spec in $script:BaselineValueSpec) {
        $path = if ($spec.Scope -eq 'Listener') { $rdpPath } else { $script:TerminalServerPolicyPath }
        if (($spec.Scope -eq 'Listener') -and (-not $listenerPresent)) { continue }
        $read = Get-OfflineValueState -Path $path -Name $spec.Name
        $baseline += [PSCustomObject]@{
            Spec    = $spec
            Path    = $path
            Value   = $read.Value
            Found   = $read.Found
            Matches = ($read.Found -and ([string]$read.Value -eq [string]$spec.Value))
        }
    }

    $policyPresent = Test-Path -LiteralPath $script:TerminalServerPolicyPath

    return [PSCustomObject]@{
        TerminalServerPath = $tsPath
        RdpTcpPath         = $rdpPath
        ListenerPresent    = $listenerPresent
        BaseDeny           = Get-OfflineValueState -Path $tsPath -Name 'fDenyTSConnections'
        PolicyPresent      = $policyPresent
        PolicyDeny         = $(if ($policyPresent) { Get-OfflineValueState -Path $script:TerminalServerPolicyPath -Name 'fDenyTSConnections' } else { $null })
        Listener           = @($listener)
        Baseline           = @($baseline)
        Port               = $(if ($listenerPresent) { Get-OfflineValueState -Path $rdpPath -Name 'PortNumber' } else { $null })
        PinnedCertificate  = $(if ($listenerPresent) { Get-OfflineValueState -Path $rdpPath -Name 'SSLCertificateSHA1Hash' } else { $null })
    }
}

function Get-RdpServiceState {
    <#
    .SYNOPSIS
        Reads the Start value of every service the Azure guidance requires for connectivity.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $services = foreach ($spec in $script:ServiceSpec) {
        $path = Join-Path $SystemRoot "Services\$($spec.Name)"
        $exists = Test-Path -LiteralPath $path
        $start = $null
        $denied = $false
        if ($exists) {
            $value = Get-OfflineValueState -Path $path -Name 'Start'
            if ($value.Found) { $start = [int]$value.Value }
            $denied = $value.Denied
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

function Get-SchannelState {
    <#
    .SYNOPSIS
        Reads whether TLS 1.2 is explicitly disabled, and the machine-wide cipher suite policy.

    .DESCRIPTION
        Only TLS 1.2 is examined. A hardening baseline that disables 1.0 and 1.1 and leaves 1.2 on is
        healthy, common and correct, so reporting on those would fire on machines with nothing wrong.
    #>
    param([Parameter(Mandatory = $true)][string]$SystemRoot)

    $base = Join-Path $SystemRoot 'Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
    $sides = foreach ($side in @('Client', 'Server')) {
        $path = Join-Path $base $side
        $enabled = Get-OfflineValueState -Path $path -Name 'Enabled'
        $disabledByDefault = Get-OfflineValueState -Path $path -Name 'DisabledByDefault'

        # Absent means "Windows decides", which for TLS 1.2 on a supported build means enabled. Only
        # an explicit Enabled=0 or DisabledByDefault=1 is evidence of a fault.
        [PSCustomObject]@{
            Side              = $side
            Path              = $path
            Enabled           = $enabled
            DisabledByDefault = $disabledByDefault
            IsDisabled        = (($enabled.Found -and [int]$enabled.Value -eq 0) -or
                                 ($disabledByDefault.Found -and [int]$disabledByDefault.Value -eq 1))
        }
    }

    $cipherPresent = Test-Path -LiteralPath $script:CipherPolicyPath
    $functions = $(if ($cipherPresent) { Get-OfflineValueState -Path $script:CipherPolicyPath -Name 'Functions' } else { $null })
    $functionCount = 0
    if ($functions -and $functions.Found) {
        $functionCount = @(@($functions.Value) -join ',' -split '[,;]' | Where-Object { $_ -and $_.Trim() }).Count
    }

    return [PSCustomObject]@{
        Tls12          = @($sides)
        CipherPresent  = $cipherPresent
        Functions      = $functions
        FunctionCount  = $functionCount
        FunctionsEmpty = ($null -ne $functions -and $functions.Found -and $functionCount -eq 0)
    }
}

function Get-AllFinding {
    <#
    .SYNOPSIS
        Turns the state that was read into the list of things that are actually preventing RDP.
    #>
    param(
        [Parameter(Mandatory = $true)]$TerminalServer,
        [Parameter(Mandatory = $true)]$Services,
        [Parameter(Mandatory = $true)]$Schannel
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # --- RDP administratively denied -------------------------------------------------------------
    if ($TerminalServer.BaseDeny.Found -and [int]$TerminalServer.BaseDeny.Value -ne 0) {
        [void]$findings.Add((New-Finding -Cause 'RdpDeniedBase' -Item 'fDenyTSConnections' -Hive 'SYSTEM' `
                    -Message "Remote connections are turned off at $($TerminalServer.TerminalServerPath) (fDenyTSConnections=$($TerminalServer.BaseDeny.Value)). Nothing can connect until this is 0."))
    }
    if ($TerminalServer.PolicyDeny -and $TerminalServer.PolicyDeny.Found -and [int]$TerminalServer.PolicyDeny.Value -ne 0) {
        [void]$findings.Add((New-Finding -Cause 'RdpDeniedPolicy' -Item 'fDenyTSConnections (policy)' -Hive 'SOFTWARE' `
                    -Message "Group Policy turns remote connections off (fDenyTSConnections=$($TerminalServer.PolicyDeny.Value) under Policies\Microsoft\Windows NT\Terminal Services). The policy copy overrides the Terminal Server key, so this alone refuses every connection."))
    }

    # --- The listener -----------------------------------------------------------------------------
    if (-not $TerminalServer.ListenerPresent) {
        [void]$findings.Add((New-Finding -Cause 'RdpListenerMissing' -Item 'RDP-Tcp' -Hive 'SYSTEM' -Repairable $false `
                    -Message "The RDP-Tcp listener key is missing at $($TerminalServer.RdpTcpPath). Recreating a listener from nothing needs the Remote Desktop role reinstalled in the guest; this script will not fabricate one."))
    }
    else {
        foreach ($value in @($TerminalServer.Listener)) {
            if ($value.Denied) {
                [void]$findings.Add((New-Finding -Cause 'ListenerValueUnreadable' -Item $value.Spec.Name -Hive 'SYSTEM' -Repairable $false `
                            -Message "$($value.Spec.Name) could not be read even after taking the key. It was left alone rather than overwritten with a documented default."))
                continue
            }
            if (-not $value.IsValid) {
                [void]$findings.Add((New-Finding -Cause 'ListenerValueInvalid' -Item $value.Spec.Name -Hive 'SYSTEM' -Data $value `
                            -Message "$($value.Spec.Name)=$($value.Value) is outside the documented set ($($value.Spec.Valid -join ', ')) - $($value.Spec.Purpose). Windows does not clamp this, so the listener cannot agree a session with any client. It will be set to $($value.Spec.DocValue)."))
            }
        }

        # Step 8 of the Azure guidance. A pin whose private key no longer resolves fails the
        # handshake before authentication; removing it lets Windows generate a fresh certificate.
        if ($TerminalServer.PinnedCertificate -and $TerminalServer.PinnedCertificate.Found) {
            [void]$findings.Add((New-Finding -Cause 'ListenerCertificatePinned' -Item 'SSLCertificateSHA1Hash' -Hive 'SYSTEM' `
                        -Message "A certificate is pinned to the listener (SSLCertificateSHA1Hash). If its private key no longer resolves the TLS handshake fails before authentication and the client reports a generic internal error. The Azure guidance removes this value so Windows generates a fresh self-signed listener certificate on the next start. If RDP still fails afterwards, the certificate store or the private key permissions are the problem and win-fix-rdp-certificate owns those."))
        }

        if ($TerminalServer.Port -and $TerminalServer.Port.Found -and [int]$TerminalServer.Port.Value -ne $script:StandardRdpPort) {
            $portFinding = New-Finding -Cause 'ListenerPortNonStandard' -Item 'PortNumber' -Hive 'SYSTEM' -Repairable $wantResetPort -Data $TerminalServer.Port `
                -Message "The listener is on port $($TerminalServer.Port.Value) rather than the documented $($script:StandardRdpPort)."
            if ($wantResetPort) { $portFinding.Message += " -resetListenerPort was passed, so it will be reset to $($script:StandardRdpPort)." }
            else { $portFinding.Message += " This was left alone in case the port was moved deliberately. Be aware the built-in 'Remote Desktop - User Mode (TCP-In)' rule only allows $($script:StandardRdpPort), so a moved port needs its own Windows Firewall rule and a matching NSG rule; without both, the listener starts and connections are still refused. Re-run with -resetListenerPort true to move it back." }
            [void]$findings.Add($portFinding)
        }

        if ($wantBaseline) {
            $drift = @($TerminalServer.Baseline | Where-Object { -not $_.Matches })
            if ($drift.Count -gt 0) {
                [void]$findings.Add((New-Finding -Cause 'AzureBaselineRequested' -Item 'Azure RDP baseline' -Hive 'SYSTEM' -Data $drift `
                            -Message "-applyAzureBaseline was passed. $($drift.Count) of $(@($TerminalServer.Baseline).Count) documented Remote Desktop value(s) do not match the guidance and will be set: $(@($drift | ForEach-Object { "$($_.Spec.Name)=$(if ($_.Found) { $_.Value } else { '(not set)' })->$($_.Spec.Value)" }) -join ', ')."))
            }
        }
    }

    # --- Services ---------------------------------------------------------------------------------
    foreach ($service in @($Services)) {
        if (-not $service.Exists) {
            # Only RDP's own services are worth reporting as missing. A missing Netlogon on a
            # workgroup VM is normal and is not this script's business.
            if (-not $service.Spec.Owner -and $service.Name -in @('TermService', 'SessionEnv', 'UmRdpService')) {
                [void]$findings.Add((New-Finding -Cause 'RdpServiceMissing' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                            -Message "The $($service.Name) service key is missing ($($service.Spec.Purpose)). That is a damaged installation rather than a configuration fault, and this script will not create one."))
            }
            continue
        }
        if (-not $service.Disabled) { continue }

        if ($service.Spec.Owner) {
            [void]$findings.Add((New-Finding -Cause 'DependencyServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Repairable $false `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). RDP cannot work while it is, but $($service.Spec.Owner) owns this service and will restore it to Start=$($service.Spec.DocStart) ($($service.Spec.Source)). It was not changed here."))
        }
        else {
            [void]$findings.Add((New-Finding -Cause 'RdpServiceDisabled' -Item $service.Name -Hive 'SYSTEM' -Data $service `
                        -Message "$($service.Name) is disabled (Start=4) - $($service.Spec.Purpose). It will be set to Start=$($service.Spec.DocStart), $($service.Spec.Source)."))
        }
    }

    # --- SCHANNEL ---------------------------------------------------------------------------------
    $disabledSides = @($Schannel.Tls12 | Where-Object { $_.IsDisabled })
    if ($disabledSides.Count -gt 0) {
        [void]$findings.Add((New-Finding -Cause 'Tls12Disabled' -Item 'TLS 1.2' -Hive 'SYSTEM' -Data $disabledSides `
                    -Message "TLS 1.2 is explicitly disabled for $(@($disabledSides | ForEach-Object { $_.Side }) -join ' and '). RDP negotiates over TLS, so this closes the handshake. It will be enabled; TLS 1.0 and 1.1 are not touched."))
    }

    if ($Schannel.FunctionsEmpty) {
        [void]$findings.Add((New-Finding -Cause 'CipherPolicyEmpty' -Item 'Functions' -Hive 'SOFTWARE' `
                    -Message 'The machine-wide SSL cipher suite policy is present but lists no cipher suites, which leaves nothing for the TLS handshake to agree on. The empty value will be removed so Windows uses its own list.'))
    }
    elseif ($Schannel.CipherPresent -and $wantClearCiphers) {
        [void]$findings.Add((New-Finding -Cause 'CipherPolicyClearRequested' -Item 'Functions' -Hive 'SOFTWARE' `
                    -Message "-clearCipherSuitePolicy was passed, so the machine-wide SSL cipher suite policy ($($Schannel.FunctionCount) suite(s)) will be removed and Windows will use its own list."))
    }

    # --- Requested security reduction --------------------------------------------------------------
    # Never discovered. It only exists because the operator asked for it by name.
    if ($wantDisableNla -and $TerminalServer.ListenerPresent) {
        $nla = @($TerminalServer.Listener | Where-Object { $_.Spec.Name -eq 'UserAuthentication' })
        if ($nla.Count -eq 0 -or -not $nla[0].Found -or [int]$nla[0].Value -ne 0) {
            [void]$findings.Add((New-Finding -Cause 'NlaDisableRequested' -Item 'UserAuthentication' -Hive 'SYSTEM' `
                        -Message '-disableNla was passed, so Network Level Authentication will be turned off (UserAuthentication=0). The Azure guidance enables NLA, so this is a deliberate deviation from it: it lets a client reach the logon screen before authenticating. Turn it back on once the VM is reachable.'))
        }
    }

    return $findings.ToArray()
}

function Set-OfflineRdpDword {
    <#
    .SYNOPSIS
        Writes one DWORD, taking the key only if the ACL refuses, and logging what changed.

    .DESCRIPTION
        A hardened VM is exactly the kind of machine that ends up needing this script, and those are
        the machines whose Terminal Server key is locked against Administrators. The write is tried
        plainly first; the descriptor is only touched when it is actually refused, and is put back in
        a finally either way.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$NewValue,
        [Parameter(Mandatory = $true)][string]$Message
    )

    # MaxInstanceCount is 4294967295, which is a valid DWORD but not a valid Int32.
    $typed = [uint32]$NewValue

    $outcome = Invoke-OfflineProtectedRegistryWrite -Path $Path -Description $Name -Action {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $typed -Type DWord -Force -ErrorAction Stop
    }

    if ($outcome.Written) { Add-OfflineRepairLog -Message $Message }
    else { Add-OfflineRepairLog -Level Warning -Message "$Name could not be written: $($outcome.Reason)" }
    return $outcome.Written
}

function Repair-Finding {
    <#
    .SYNOPSIS
        Repairs one finding. Returns $true when something was actually changed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$SystemRoot
    )

    $rdpPath = Join-Path $SystemRoot $script:RdpTcpSubPath

    switch -Regex ($Finding.Cause) {

        '^RdpDeniedBase$' {
            $path = Join-Path $SystemRoot $script:TerminalServerSubPath
            return (Set-OfflineRdpDword -Path $path -Name 'fDenyTSConnections' -NewValue 0 `
                    -Message 'fDenyTSConnections 1 -> 0 on the Terminal Server key, so remote connections are allowed again.')
        }

        '^RdpDeniedPolicy$' {
            return (Set-OfflineRdpDword -Path $script:TerminalServerPolicyPath -Name 'fDenyTSConnections' -NewValue 0 `
                    -Message 'fDenyTSConnections 1 -> 0 on the Group Policy copy, which overrides the Terminal Server key.')
        }

        '^RdpServiceDisabled$' {
            $service = $Finding.Data
            return (Set-OfflineRdpDword -Path $service.Path -Name 'Start' -NewValue $service.Spec.DocStart `
                    -Message "$($service.Name): Start 4 (Disabled) -> $($service.Spec.DocStart), $($service.Spec.Source).")
        }

        '^ListenerValueInvalid$' {
            $value = $Finding.Data
            return (Set-OfflineRdpDword -Path $rdpPath -Name $value.Spec.Name -NewValue $value.Spec.DocValue `
                    -Message "$($value.Spec.Name): $($value.Value) -> $($value.Spec.DocValue) (was outside the documented set).")
        }

        '^ListenerPortNonStandard$' {
            if (-not $wantResetPort) { return $false }
            return (Set-OfflineRdpDword -Path $rdpPath -Name 'PortNumber' -NewValue $script:StandardRdpPort `
                    -Message "PortNumber $($Finding.Data.Value) -> $($script:StandardRdpPort), as requested by -resetListenerPort.")
        }

        '^ListenerCertificatePinned$' {
            $outcome = Invoke-OfflineProtectedValueRemoval -Path $rdpPath -Name 'SSLCertificateSHA1Hash' -StillSet {
                param($Current)
                return ($null -ne $Current)
            }
            if ($outcome.Removed) {
                Add-OfflineRepairLog -Message "The pinned listener certificate was removed, so Windows generates a fresh self-signed one on the next start. $($outcome.Reason)"
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "The pinned listener certificate could not be removed: $($outcome.Reason)"
            return $false
        }

        '^Tls12Disabled$' {
            $changed = $false
            foreach ($side in @($Finding.Data)) {
                if (Set-OfflineRdpDword -Path $side.Path -Name 'Enabled' -NewValue 1 -Message "TLS 1.2 $($side.Side): Enabled -> 1.") { $changed = $true }
                if (Set-OfflineRdpDword -Path $side.Path -Name 'DisabledByDefault' -NewValue 0 -Message "TLS 1.2 $($side.Side): DisabledByDefault -> 0.") { $changed = $true }
            }
            return $changed
        }

        '^AzureBaselineRequested$' {
            $changed = $false
            foreach ($item in @($Finding.Data)) {
                $was = $(if ($item.Found) { $item.Value } else { '(not set)' })
                if (Set-OfflineRdpDword -Path $item.Path -Name $item.Spec.Name -NewValue $item.Spec.Value `
                        -Message "$($item.Spec.Name): $was -> $($item.Spec.Value) ($($item.Spec.Purpose), per the Azure guidance).") { $changed = $true }
            }
            return $changed
        }

        '^(CipherPolicyEmpty|CipherPolicyClearRequested)$' {
            $outcome = Invoke-OfflineProtectedValueRemoval -Path $script:CipherPolicyPath -Name 'Functions' -StillSet {
                param($Current)
                return ($null -ne $Current)
            }
            if ($outcome.Removed) {
                Add-OfflineRepairLog -Message "The machine-wide SSL cipher suite policy was removed, so Windows uses its own list. $($outcome.Reason)"
                return $true
            }
            Add-OfflineRepairLog -Level Warning -Message "The cipher suite policy could not be removed: $($outcome.Reason)"
            return $false
        }

        '^NlaDisableRequested$' {
            return (Set-OfflineRdpDword -Path $rdpPath -Name 'UserAuthentication' -NewValue 0 `
                    -Message 'UserAuthentication -> 0, so Network Level Authentication is off. This was requested with -disableNla and should be turned back on once the VM is reachable.')
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
    Log-Info "Target values follow $($script:DocUrl)" | Tee-Object -FilePath $logFile -Append

    $context = Invoke-WithHive -Hive 'SYSTEM', 'SOFTWARE' -WindowsPath $offline.WindowsPath -ScriptBlock {
        $systemRoot = Get-OfflineSystemRootPath
        $terminalServer = Get-TerminalServerState -SystemRoot $systemRoot
        $services = Get-RdpServiceState -SystemRoot $systemRoot
        $schannel = Get-SchannelState -SystemRoot $systemRoot

        return [PSCustomObject]@{
            ControlSet     = (Split-Path -Path $systemRoot -Leaf)
            TerminalServer = $terminalServer
            Services       = @($services)
            Schannel       = $schannel
            Findings       = @(Get-AllFinding -TerminalServer $terminalServer -Services $services -Schannel $schannel)
        }
    }
    Write-OfflineRepairLog | Tee-Object -FilePath $logFile -Append

    # Context. None of this is a fault by itself, so none of it appears in the findings list.
    $ts = $context.TerminalServer
    Log-Info "Control set $($context.ControlSet)." | Tee-Object -FilePath $logFile -Append
    Log-Info "Terminal Server: fDenyTSConnections=$(if ($ts.BaseDeny.Found) { $ts.BaseDeny.Value } else { '(not set)' }), Group Policy copy $(if ($ts.PolicyDeny -and $ts.PolicyDeny.Found) { "= $($ts.PolicyDeny.Value)" } else { 'not configured' })." | Tee-Object -FilePath $logFile -Append

    if ($ts.ListenerPresent) {
        foreach ($value in @($ts.Listener)) {
            $shown = if ($value.Denied) { '(unreadable)' } elseif ($value.Found) { $value.Value } else { '(not set, Windows default)' }
            Log-Info "  RDP-Tcp $($value.Spec.Name) = $shown - $($value.Spec.Purpose)." | Tee-Object -FilePath $logFile -Append
        }
        Log-Info "  RDP-Tcp PortNumber = $(if ($ts.Port.Found) { $ts.Port.Value } else { '(not set)' })." | Tee-Object -FilePath $logFile -Append
    }

    $disabledServices = @($context.Services | Where-Object { $_.Disabled })
    Log-Info "Services: $(@($context.Services | Where-Object { $_.Exists }).Count) of $(@($context.Services).Count) required service key(s) present, $($disabledServices.Count) disabled." | Tee-Object -FilePath $logFile -Append
    foreach ($service in @($context.Services)) {
        $shown = if (-not $service.Exists) { 'no service key' } elseif ($null -eq $service.Start) { '(Start not set)' } else { "Start=$($service.Start)" }
        Log-Info "  $($service.Name): $shown, $($service.Spec.Source)." | Tee-Object -FilePath $logFile -Append
    }

    # Presence is normal here and is stated as such, so nobody reads this line as a fault.
    if ($context.Schannel.CipherPresent) {
        Log-Info "A machine-wide SSL cipher suite policy is configured with $($context.Schannel.FunctionCount) suite(s). That is normal on an Azure image and was not treated as a fault." | Tee-Object -FilePath $logFile -Append
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
        Log-Output 'No Remote Desktop fault was found. Remote connections are allowed, the listener and its services are configured for them, and TLS 1.2 is available. No changes were made.' | Tee-Object -FilePath $logFile -Append
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
                    -TerminalServer (Get-TerminalServerState -SystemRoot $systemRoot) `
                    -Services (Get-RdpServiceState -SystemRoot $systemRoot) `
                    -Schannel (Get-SchannelState -SystemRoot $systemRoot))
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
