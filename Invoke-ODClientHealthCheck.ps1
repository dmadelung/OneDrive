#Requires -Version 5.1
<#
.SYNOPSIS
    OneDrive for Business client health diagnostic — runs as the signed-in user.

.DESCRIPTION
    Evaluates OneDrive client install state, KFM policy delivery (Computer
    Configuration AND User Configuration), prerequisites, runtime redirect
    state, and known blockers. Emits a self-contained HTML report with a
    full configuration snapshot of every OneDrive policy value found under
    both HKLM and HKCU policy roots.

    Designed to run interactively in the signed-in user's context. Can also
    be run on-demand via Invoke-AsCurrentUser or scheduled task projection
    when remediating remotely.

.PARAMETER ExpectedTenantId
    Tenant GUID. Used to validate KFM policy values and the signed-in
    account's tenant. If omitted, tenant-match checks return Unknown.

.PARAMETER OutputPath
    Folder where the HTML report is written. Defaults to the directory
    containing the script ($PSScriptRoot). Override to a non-redirected path
    (e.g. %ProgramData%\ODHealthCheck) when running as a scheduled task or
    Intune remediation to avoid the report landing inside a KFM-managed folder.

.PARAMETER WarnHours / FailHours
    GP refresh age (hours) thresholds. Defaults: 24 / 48.

.PARAMETER WarnQuotaGB / FailQuotaGB
    OneDrive quota free-space thresholds. Defaults: 5 / 1.

.PARAMETER WarnLocalDiskGB / FailLocalDiskGB
    Local disk free-space thresholds for the drive hosting the OneDrive
    folder. Defaults: 10 / 2.

.PARAMETER LargeFolderThresholdGB
    Per-folder size that triggers a "large folder" warning. Default: 50.

.PARAMETER MinClientVersion
    Minimum acceptable OneDrive client version string. Anything older is
    flagged as a Warning. Default: '26.055.0323.0004' (production release
    as of April 2026 — update to match your approved floor). The value is
    parsed as a dotted-quad [version]; unparseable strings skip the
    comparison and emit an Info result.

.PARAMETER StrictExit
    Promote Warning conditions to exit code 1. Useful when wiring this into
    Intune Proactive Remediation as a detection script.

.PARAMETER NoOpen
    Do not auto-launch the HTML report at the end of the run.

.PARAMETER PassThru
    Emit the full results collection to the pipeline in addition to writing
    the HTML report. Useful for fleet aggregation.

.EXAMPLE
    .\Invoke-ODClientHealthCheck.ps1 -ExpectedTenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

.EXAMPLE
    # Intune Proactive Remediation detection script pattern
    .\Invoke-ODClientHealthCheck.ps1 -ExpectedTenantId '...' -NoOpen -StrictExit

.EXAMPLE
    # Fleet aggregation: capture results object, write CSV, suppress HTML auto-open
    $r = .\Invoke-ODClientHealthCheck.ps1 -ExpectedTenantId '...' -NoOpen -PassThru
    $r | Export-Csv -Path '\\server\share\ODHealth.csv' -Append -NoTypeInformation

.NOTES
    Version  : 4.0.0
    Requires : PowerShell 5.1+, Windows 10 build 16299 or later
    Platforms: Windows only (uses HKLM/HKCU registry, dsregcmd.exe,
               Win32_OperatingSystem WMI class)
    Run as   : Signed-in interactive user. HKCU-scoped checks are inaccurate
               when run elevated or under a different identity (e.g. SYSTEM);
               a warning is emitted automatically when elevation is detected.
    Intune   : For Proactive Remediation use -NoOpen -StrictExit and deploy
               as the detection script. This tool is diagnostic only — no
               remediation script is included.
    License  : MIT — free to use, modify, and redistribute with attribution.

.LINK
    https://learn.microsoft.com/sharepoint/use-group-policy
.LINK
    https://learn.microsoft.com/sharepoint/ideal-state-configuration
#>

[CmdletBinding()]
param(
    [string]$ExpectedTenantId = '',

    [string]$OutputPath = $PSScriptRoot,

    [int]$WarnHours = 24,
    [int]$FailHours = 48,

    [double]$WarnQuotaGB = 5,
    [double]$FailQuotaGB = 1,

    [double]$WarnLocalDiskGB = 10,
    [double]$FailLocalDiskGB = 2,

    [int]$LargeFolderThresholdGB = 50,

    [string]$MinClientVersion = '26.055.0323.0004',

    [switch]$StrictExit,
    [switch]$NoOpen,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
#region CONSTANTS
# ============================================================================
$SCRIPT_VERSION = '4.0.0'

# Policy roots — both Computer Configuration (HKLM) and User Configuration (HKCU)
$OD_POLICY_HKLM     = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
$OD_POLICY_HKCU     = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'

# Signed-in account state
$OD_ACCOUNT_HKCU    = 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1'
$OD_KFM_HKCU        = 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\KFM'

# Shell folders (where Desktop/Documents/Pictures actually point)
$SHELL_FOLDERS_HKCU = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'

# OneDrive client log
$SYNCDIAG_PATH      = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log'

# OneDrive can be installed per-user or per-machine. Per-machine became default
# in newer builds, but per-user installs persist on long-tenured devices.
$OD_EXE_CANDIDATES = @(
    (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'),
    "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe",
    "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
)

# Group Policy state keys live under HKLM in both cases — user-side state
# keys are subkeys keyed by SID. Read-only access to HKLM is permitted from
# user context, so this works without elevation.
$GP_STATE_MACHINE   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}'

# Documented HKLM scalar policy names — drives "Not configured" placeholders.
# Subkey policies (AllowTenantList, BlockTenantList, DiskSpaceCheckThresholdMB,
# DefaultRootDir) are already enumerated by Get-AllRegValues' subkey walk.
$Script:KnownODHKLMPolicies = @(
    'AutoMountTeamSites','AutomaticUploadBandwidthPercentage','BlockExternalSync',
    'DisableHydrationToast','DisableOfflineMode','DisablePersonalSync','DisableTutorial',
    'DownloadBandwidthLimit','EnableADAL','EnableAllOcsiClients',
    'EnableAutomaticUploadBandwidthManagement','EnableSyncAdminReports',
    'FilesOnDemandEnabled','KFMBlockOptIn','KFMBlockOptOut','KFMOptInWithWizard',
    'KFMSilentOptIn','KFMSilentOptInDesktop','KFMSilentOptInDocuments','KFMSilentOptInPictures',
    'KFMSilentOptInWithNotification','LocalMassDeleteFileDeleteThreshold',
    'MinDiskSpaceLimitInMB','OpenAtLogin','PreventNetworkTrafficPreUserSignIn',
    'SharePointOnPremFrontDoorUrl','SharePointOnPremPrioritization','SharePointOnPremTenantName',
    'SilentAccountConfig','UploadBandwidthLimit','WarningMinDiskSpaceLimitInMB'
)

# Policy descriptions (learn.microsoft.com/sharepoint/use-group-policy) — shown
# as sub-text under each policy name in the Configuration Snapshot table.
$Script:OD_POLICY_DESCRIPTIONS = @{
    'AllowTenantList'                      = 'Allow syncing only for specific Azure AD tenants (value names = tenant GUIDs)'
    'AutoMountTeamSites'                   = 'Automatically sync SharePoint team site libraries on sign-in'
    'AutomaticUploadBandwidthPercentage'   = 'Throttle uploads to a % of available throughput (1–99)'
    'BlockExternalSync'                    = 'Prevent syncing libraries shared from outside the organisation'
    'BlockTenantList'                      = 'Block syncing for specific Azure AD tenants (value names = tenant GUIDs)'
    'DefaultRootDir'                       = 'Override default local OneDrive folder location (per-tenant subkey)'
    'DiskSpaceCheckThresholdMB'            = 'Max OneDrive size (MB) that auto-downloads without prompting (per-tenant subkey)'
    'DisableHydrationToast'                = 'Suppress notification asking users to open online-only files locally'
    'DisableOfflineMode'                   = 'Prevent users enabling offline access for SharePoint/Teams sites'
    'DisablePersonalSync'                  = 'Block personal OneDrive accounts; does not affect work/school accounts'
    'DisableTutorial'                      = 'Skip the first-run setup tutorial'
    'DownloadBandwidthLimit'               = 'Cap download speed (KB/s); 0 = unlimited'
    'EnableADAL'                           = 'Enable (1) or disable (0) ADAL modern auth; 0 forces legacy auth'
    'EnableAllOcsiClients'                 = 'Allow co-authoring in Office desktop apps via OneDrive'
    'EnableAutomaticUploadBandwidthManagement' = 'Let OneDrive dynamically throttle uploads based on available bandwidth'
    'EnableSyncAdminReports'               = 'Send sync health telemetry to the Microsoft 365 admin center'
    'FilesOnDemandEnabled'                 = 'Enable (1) or disable (0) Files On-Demand placeholder support'
    'KFMBlockOptIn'                        = '1 = block user KFM wizard only (does NOT suppress KFMSilentOptIn); 2 = reverse KFM and block all opt-in'
    'KFMBlockOptOut'                       = '1 = prevent users moving folders back to the device via tray icon'
    'KFMOptInWithWizard'                   = 'Show KFM wizard to prompt users to redirect folders (value = tenant GUID)'
    'KFMSilentOptIn'                       = 'Silently redirect Desktop, Documents & Pictures without user interaction (value = tenant GUID)'
    'KFMSilentOptInDesktop'                = '1 = silently redirect Desktop only'
    'KFMSilentOptInDocuments'              = '1 = silently redirect Documents only'
    'KFMSilentOptInPictures'               = '1 = silently redirect Pictures only'
    'KFMSilentOptInWithNotification'       = '1 = show toast notification to user after silent KFM completes'
    'LocalMassDeleteFileDeleteThreshold'   = 'Warn before deleting more than N files from OneDrive in one operation'
    'MinDiskSpaceLimitInMB'                = 'Pause sync when free local disk falls below this threshold (MB)'
    'OpenAtLogin'                          = '1 = start OneDrive automatically when the user signs in to Windows'
    'PreventNetworkTrafficPreUserSignIn'   = '1 = block all OneDrive network activity (incl. silent sign-in) until interactive sign-in'
    'SharePointOnPremFrontDoorUrl'         = 'SharePoint Server 2019 on-prem: site collection URL for hybrid integration'
    'SharePointOnPremPrioritization'       = 'SharePoint Server 2019 on-prem: 1 = prefer on-prem over cloud OneDrive'
    'SharePointOnPremTenantName'           = 'SharePoint Server 2019 on-prem: tenant name shown in sync client UI'
    'SilentAccountConfig'                  = '1 = silently sign in using Windows AAD/Hybrid join token; prerequisite for KFMSilentOptIn without user interaction'
    'UploadBandwidthLimit'                 = 'Cap upload speed (KB/s); 0 = unlimited'
    'WarningMinDiskSpaceLimitInMB'         = 'Show low-disk warning when free local space drops below this threshold (MB)'
}

# Module cache — populated lazily
$Script:SyncDiagLines = $null
$Script:CheckGroupMap = @{}
#endregion

# ============================================================================
#region HELPERS
# ============================================================================

function New-CheckResult {
    param(
        [string]$CheckName,
        [ValidateSet('Pass', 'Fail', 'Warning', 'Unknown', 'Info')]
        [string]$Status,
        [string]$Detail,
        [string]$RawValue = $null,
        [string]$Group = $null
    )
    [PSCustomObject]@{
        CheckName    = $CheckName
        Group        = $Group
        Status       = $Status
        Detail       = $Detail
        RawValue     = $RawValue
        ComputerName = $env:COMPUTERNAME
        UserName     = $env:USERNAME
        Timestamp    = (Get-Date -Format 'o')
        ScriptVer    = $SCRIPT_VERSION
    }
}

function Get-UserContext {
    # Returns identity info needed by HKCU- and SID-scoped checks. Wrapping
    # this in a function keeps the SYSTEM-context port (future) a one-line
    # change instead of a global hunt-and-replace.
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [PSCustomObject]@{
        UserName    = $env:USERNAME
        ProfilePath = $env:USERPROFILE
        RunningAs   = $Identity.Name
        SID         = $Identity.User.Value
        IsSystem    = $Identity.IsSystem
        IsElevated  = ([Security.Principal.WindowsPrincipal]$Identity).IsInRole(
                          [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Get-RegValueSafe {
    # StrictMode-safe registry value getter. Returns $null cleanly if either
    # the path or the value is absent. Get-Item + .GetValue() avoids the
    # Get-ItemProperty -Name exception that fires unpredictably under
    # StrictMode in PS 5.1.
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name
    )
    try {
        $Key = Get-Item -Path $Path -ErrorAction Stop
        return $Key.GetValue($Name)   # returns $null if value name not present
    }
    catch {
        return $null
    }
}

function Get-RegSubKeyValueNames {
    # Enumerate value names under a registry path. Used for AllowTenantList /
    # BlockTenantList where the value names ARE the tenant IDs.
    param([string]$Path)
    try {
        $Key = Get-Item -Path $Path -ErrorAction Stop
        return $Key.GetValueNames()
    }
    catch { return @() }
}

function Get-AllRegValues {
    # Enumerate every value under a key (name + data) for the configuration
    # snapshot. Returns array of PSCustomObject; empty if path missing.
    param([string]$Path, [string]$Scope)
    $Out = @()
    try {
        $Key = Get-Item -Path $Path -ErrorAction Stop
        foreach ($N in $Key.GetValueNames()) {
            $V = $Key.GetValue($N)
            $Out += [PSCustomObject]@{
                Scope = $Scope
                Path  = $Path
                Name  = $N
                Value = if ($null -eq $V) { '<null>' } else { "$V" }
                Kind  = $Key.GetValueKind($N).ToString()
            }
        }
        # Walk one level of subkeys (covers AllowTenantList, BlockTenantList,
        # DiskSpaceCheckThresholdMB subkey, etc.)
        foreach ($SubName in $Key.GetSubKeyNames()) {
            $SubPath = Join-Path $Path $SubName
            try {
                $Sub = Get-Item -Path $SubPath -ErrorAction Stop
                foreach ($N in $Sub.GetValueNames()) {
                    $V = $Sub.GetValue($N)
                    $Out += [PSCustomObject]@{
                        Scope = $Scope
                        Path  = $SubPath
                        Name  = $N
                        Value = if ($null -eq $V) { '<null>' } else { "$V" }
                        Kind  = $Sub.GetValueKind($N).ToString()
                    }
                }
            } catch { } # subkey unreadable — skip silently
        }
    }
    catch { } # root path absent — return empty
    return $Out
}

function Get-SyncDiagLines {
    # Reads SyncDiagnostics.log once, caches it. Three things this gets right
    # that the previous version did not:
    #   (1) BOM-aware decoding. The log is typically UTF-16 LE w/ BOM but
    #       OneDrive has flipped this in past versions; let StreamReader
    #       sniff the BOM rather than assuming.
    #   (2) FileShare.ReadWrite — OneDrive often holds the log open
    #       exclusively. Without this flag the read throws IOException.
    #   (3) Returns @() instead of $null on every failure path so callers
    #       don't need null-guards.
    if ($null -ne $Script:SyncDiagLines) { return $Script:SyncDiagLines }

    if (-not (Test-Path $SYNCDIAG_PATH)) {
        $Script:SyncDiagLines = @()
        return $Script:SyncDiagLines
    }

    try {
        $fs = [System.IO.File]::Open(
            $SYNCDIAG_PATH,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        try {
            # detectEncodingFromByteOrderMarks=$true honors UTF-8/16 BOM,
            # falling back to the default encoding if no BOM present.
            $reader = New-Object System.IO.StreamReader(
                $fs, [System.Text.Encoding]::Default, $true)
            try {
                $content = $reader.ReadToEnd()
                $Script:SyncDiagLines = $content -split "`r?`n"
            }
            finally { $reader.Dispose() }
        }
        finally { $fs.Dispose() }
    }
    catch {
        $Script:SyncDiagLines = @()
    }
    return $Script:SyncDiagLines
}

function Get-LastLogMatch {
    param([string]$Pattern)
    $Lines = Get-SyncDiagLines
    return ($Lines | Where-Object { $_ -like "*$Pattern*" } | Select-Object -Last 1)
}

function Get-LogMatchMap {
    # Single-pass scan over the log: returns hashtable Pattern -> last match.
    # Use this when checking many patterns at once (SyncDiagKFMState) instead
    # of scanning the log N times.
    param([string[]]$Patterns)
    $Result = @{}
    foreach ($P in $Patterns) { $Result[$P] = $null }
    foreach ($Line in (Get-SyncDiagLines)) {
        foreach ($P in $Patterns) {
            if ($Line -like "*$P*") { $Result[$P] = $Line }
        }
    }
    return $Result
}

function Get-FolderSizeGB {
    # -Force ensures hidden files (KFM marker desktop.ini files among them)
    # are counted. SilentlyContinue swallows access-denied on per-file basis.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0.0 }
    $Sum = (Get-ChildItem $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if (-not $Sum) { return 0.0 }
    return [Math]::Round(($Sum / 1GB), 2)
}

function Test-TCPPort {
    # Direct socket — Test-NetConnection produces noise and behaves
    # inconsistently across PS hosts. try/finally ensures the socket closes
    # even if EndConnect throws.
    param([string]$Hostname, [int]$Port, [int]$TimeoutMs = 3000)
    $Tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $Connect = $Tcp.BeginConnect($Hostname, $Port, $null, $null)
        if (-not $Connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $Tcp.EndConnect($Connect)
        return $true
    }
    catch { return $false }
    finally { $Tcp.Close() }
}

function Get-OneDriveExecutable {
    # Returns the first existing OneDrive.exe path, or $null. Per-user wins
    # because that's where the running process loads from when both exist.
    foreach ($Candidate in $OD_EXE_CANDIDATES) {
        if (Test-Path $Candidate) {
            return [PSCustomObject]@{
                Path        = $Candidate
                InstallType = if ($Candidate -like "$env:LOCALAPPDATA*") { 'Per-User' }
                              else                                       { 'Per-Machine' }
                Version     = (Get-Item $Candidate).VersionInfo.FileVersion
            }
        }
    }
    return $null
}

function ConvertTo-VersionSafe {
    # OneDrive version strings are dotted-quads; cast to [version] for
    # comparison. Returns $null if string doesn't parse.
    param([string]$VersionString)
    try { return [version]$VersionString } catch { return $null }
}
#endregion

# ============================================================================
#region CLIENT CHECKS
# ============================================================================

function Invoke-ODCheck_ClientInstalled {
    $CheckName = 'ClientInstalled'
    $Group     = 'Client'

    $Exe = Get-OneDriveExecutable
    if (-not $Exe) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'OneDrive.exe not found at any of the standard install paths (per-user or per-machine). Client is not installed.' `
            -RawValue ($OD_EXE_CANDIDATES -join ' | ')
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "OneDrive client is installed ($($Exe.InstallType)) at: $($Exe.Path)" `
        -RawValue $Exe.Path
}

function Invoke-ODCheck_ClientProcessRunning {
    $CheckName = 'ClientProcessRunning'
    $Group     = 'Client'

    $Procs = Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue
    if (-not $Procs) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'OneDrive.exe is not running. KFM cannot make progress and runtime checks will reflect stale state.' `
            -RawValue $null
    }
    $PidList = ($Procs | ForEach-Object { $_.Id }) -join ', '
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "OneDrive.exe is running (PID(s): $PidList)" -RawValue $PidList
}

function Invoke-ODCheck_ClientVersion {
    $CheckName = 'ClientVersion'
    $Group     = 'Client'

    $Exe = Get-OneDriveExecutable
    if (-not $Exe) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'Cannot evaluate version — OneDrive.exe not found' -RawValue $null
    }

    $Installed = ConvertTo-VersionSafe $Exe.Version
    $Min       = ConvertTo-VersionSafe $MinClientVersion

    if (-not $Installed) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail "Could not parse installed version string: $($Exe.Version)" -RawValue $Exe.Version
    }
    if (-not $Min) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail "Installed version: $Installed (MinClientVersion parameter '$MinClientVersion' did not parse, comparison skipped)" `
            -RawValue $Exe.Version
    }
    if ($Installed -lt $Min) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "OneDrive client $Installed is older than MinClientVersion $Min — recommend updating before relying on KFM behavior" `
            -RawValue $Exe.Version
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "OneDrive client version $Installed (>= $Min)" -RawValue $Exe.Version
}

function Invoke-ODCheck_InstallType {
    $CheckName = 'InstallType'
    $Group     = 'Client'

    # Per-machine installation (under Program Files) is recommended for managed
    # enterprise devices: it survives profile resets, updates run under SYSTEM
    # context, and the same binary is shared across all user sessions.
    # Per-user installs live under %LOCALAPPDATA% and update via the signed-in
    # user's OneDrive process — acceptable but requires the user to be active.
    $Exe = Get-OneDriveExecutable
    if (-not $Exe) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'Cannot evaluate install type — OneDrive.exe not found' -RawValue $null
    }

    # Expose the version alongside install path for full export visibility
    $RawDetail = "Type=$($Exe.InstallType) | Path=$($Exe.Path) | Version=$($Exe.Version)"

    if ($Exe.InstallType -eq 'Per-Machine') {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail "Per-machine installation — $($Exe.Path) (v$($Exe.Version)). Recommended for managed enterprise deployments." `
            -RawValue $RawDetail
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
        -Detail "Per-user installation — $($Exe.Path) (v$($Exe.Version)). Functional for KFM. For enterprise deployments consider per-machine (bootstrapper flag /allusers) so the client persists across profile resets and updates via SYSTEM context." `
        -RawValue $RawDetail
}
#endregion

# ============================================================================
#region POLICY CHECKS — COMPUTER CONFIGURATION (HKLM)
# ============================================================================

function Invoke-ODCheck_KFMPolicyPresent {
    $CheckName = 'KFMPolicyPresent'
    $Group     = 'Policy (Computer)'

    # Three valid KFM policy modes per Microsoft docs:
    #   A) KFMSilentOptIn               — silently moves all three folders;
    #                                     value = tenant GUID
    #   B) KFMOptInWithWizard           — prompts user via wizard; tenant GUID
    #   C) KFMSilentOptInDesktop / Documents / Pictures — per-folder DWORD 1
    #      (no GUID; can be combined with B; supersedes A when present)

    $SilentAll    = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptIn'
    $WizardTenant = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMOptInWithWizard'
    $PerDesktop   = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInDesktop'
    $PerDocuments = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInDocuments'
    $PerPictures  = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInPictures'

    $PerFolderNames = @(
        if ($PerDesktop   -eq 1) { 'Desktop'   }
        if ($PerDocuments -eq 1) { 'Documents' }
        if ($PerPictures  -eq 1) { 'Pictures'  }
    )
    $PerFolderCount = $PerFolderNames.Count

    if (-not $SilentAll -and -not $WizardTenant -and $PerFolderCount -eq 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'No KFM policy found under HKLM. KFMSilentOptIn, KFMOptInWithWizard, and all per-folder KFMSilentOptIn* values are absent.' `
            -RawValue $null
    }

    # Pick the GUID actually in play for tenant validation
    $TenantGuid = if ($WizardTenant) { $WizardTenant }
                  elseif ($SilentAll) { $SilentAll }
                  else                { $null }

    $Mode = @()
    if ($SilentAll)        { $Mode += "KFMSilentOptIn (tenant: $SilentAll)" }
    if ($WizardTenant)     { $Mode += "KFMOptInWithWizard (tenant: $WizardTenant)" }
    if ($PerFolderCount -gt 0) {
        $Mode += "Per-folder silent: $($PerFolderNames -join ', ')"
    }
    $ModeString = $Mode -join ' | '

    if ($ExpectedTenantId -and $TenantGuid -and
        ($TenantGuid.Trim().ToLower() -ne $ExpectedTenantId.Trim().ToLower())) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "KFM policy present but tenant GUID does not match ExpectedTenantId. Mode: $ModeString" `
            -RawValue $TenantGuid
    }

    if ($PerFolderCount -gt 0 -and $PerFolderCount -lt 3) {
        $Missing = @('Desktop','Documents','Pictures') |
                   Where-Object { $_ -notin $PerFolderNames }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "Per-folder KFM opt-in is partially configured — missing: $($Missing -join ', '). Mode: $ModeString" `
            -RawValue $ModeString
    }

    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "KFM policy present and configured. Mode: $ModeString" -RawValue $ModeString
}

function Invoke-ODCheck_KFMBlockOptIn {
    $CheckName = 'KFMBlockOptIn'
    $Group     = 'Policy (Computer)'

    # Per Microsoft documentation, KFMBlockOptIn has three meaningful states:
    #   absent / 0 — no block; KFM proceeds through any configured path
    #   1          — ONLY blocks the user-facing "Set up protection" wizard.
    #                Admin-deployed KFMSilentOptIn is NOT suppressed by value 1
    #                and will still execute normally. These two settings are
    #                independent. Source: aka.ms/knownfoldermove
    #   2          — Actively moves known folders BACK to the local device,
    #                reversing any prior KFM. This overrides KFMSilentOptIn.
    $Raw         = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMBlockOptIn'
    $SilentOptIn = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptIn'

    if ($null -eq $Raw -or $Raw -eq 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'KFMBlockOptIn absent or 0 — no KFM block policy in effect' `
            -RawValue "$Raw"
    }
    if ($Raw -eq 1) {
        # Value 1 disables only the user-initiated wizard; KFMSilentOptIn is unaffected.
        if ($SilentOptIn) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
                -Detail 'KFMBlockOptIn = 1 — user-facing KFM wizard ("Set up protection") is disabled. KFMSilentOptIn (admin-deployed silent redirect) is NOT suppressed by this value and will still execute normally. This is a supported and common configuration.' `
                -RawValue "$Raw"
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail 'KFMBlockOptIn = 1 — user-facing KFM wizard is disabled. No KFMSilentOptIn is deployed, so users cannot initiate KFM and no silent admin path exists. KFM will not progress unless KFMSilentOptIn or a per-folder policy is also configured.' `
            -RawValue "$Raw"
    }
    if ($Raw -eq 2) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'KFMBlockOptIn = 2 — known folders are being REDIRECTED BACK to the local device. Any prior KFM is being actively reversed. This DOES override KFMSilentOptIn. Remove this setting or set to 0 to allow KFM to proceed.' `
            -RawValue "$Raw"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
        -Detail "KFMBlockOptIn has unexpected value '$Raw'. Documented values: 0 (no block), 1 (block user wizard only, silent admin opt-in unaffected), 2 (reverse KFM and block all opt-in)." `
        -RawValue "$Raw"
}

function Invoke-ODCheck_KFMBlockOptOut {
    $CheckName = 'KFMBlockOptOut'
    $Group     = 'Policy (Computer)'

    $Raw = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMBlockOptOut'

    if ($Raw -eq 1) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'KFMBlockOptOut = 1 — users cannot reverse KFM via the OneDrive tray icon' `
            -RawValue "$Raw"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
        -Detail 'KFMBlockOptOut is not set — users can reverse KFM redirection from the OneDrive tray icon. Recommended for managed deployments.' `
        -RawValue "$Raw"
}

function Invoke-ODCheck_KFMNotificationConfig {
    $CheckName = 'KFMNotificationConfig'
    $Group     = 'Policy (Computer)'

    $Raw = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInWithNotification'

    if ($null -eq $Raw) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail 'KFMSilentOptInWithNotification not configured — silent KFM completes without user notification (default)' `
            -RawValue $null
    }
    if ($Raw -eq 1) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail 'KFMSilentOptInWithNotification = 1 — users will see a notification once KFM completes silently' `
            -RawValue "$Raw"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
        -Detail "KFMSilentOptInWithNotification = $Raw" -RawValue "$Raw"
}

function Invoke-ODCheck_TenantAllowList {
    $CheckName = 'TenantAllowList'
    $Group     = 'Policy (Computer)'

    # AllowTenantList and BlockTenantList are subkeys whose VALUE NAMES are
    # tenant GUIDs. If AllowTenantList is set and ExpectedTenantId is not
    # present in it, sign-in fails before KFM can run.
    $AllowKey  = Join-Path $OD_POLICY_HKLM 'AllowTenantList'
    $BlockKey  = Join-Path $OD_POLICY_HKLM 'BlockTenantList'

    $Allow = Get-RegSubKeyValueNames -Path $AllowKey
    $Block = Get-RegSubKeyValueNames -Path $BlockKey

    if (-not $Allow -and -not $Block) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'No AllowTenantList or BlockTenantList policy in effect' -RawValue $null
    }

    $Raw = "Allow=[$($Allow -join ', ')] Block=[$($Block -join ', ')]"

    if ($Allow -and $ExpectedTenantId -and
        ($Allow | ForEach-Object { $_.Trim().ToLower() }) -notcontains $ExpectedTenantId.Trim().ToLower()) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "AllowTenantList is set but ExpectedTenantId is NOT in the list. Sign-in to the expected tenant will be blocked." `
            -RawValue $Raw
    }
    if ($Block -and $ExpectedTenantId -and
        ($Block | ForEach-Object { $_.Trim().ToLower() }) -contains $ExpectedTenantId.Trim().ToLower()) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "BlockTenantList contains ExpectedTenantId. Sign-in to the expected tenant is explicitly blocked." `
            -RawValue $Raw
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "Tenant allow/block lists are configured and ExpectedTenantId is permitted" -RawValue $Raw
}

function Invoke-ODCheck_KFMPolicyInteraction {
    # Cross-reference every KFM-related policy value to determine the effective
    # KFM state and flag conflicts that individual per-value checks cannot catch.
    $CheckName = 'KFMPolicyInteraction'
    $Group     = 'Policy (Computer)'

    $SilentOptIn   = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptIn'
    $WizardOptIn   = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMOptInWithWizard'
    $BlockOptIn    = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMBlockOptIn'
    $BlockOptOut   = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMBlockOptOut'
    $PerDesktop    = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInDesktop'
    $PerDocuments  = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInDocuments'
    $PerPictures   = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptInPictures'
    $HasSilentPath = $SilentOptIn -or ($PerDesktop -eq 1) -or ($PerDocuments -eq 1) -or ($PerPictures -eq 1)
    $HasWizardPath = [bool]$WizardOptIn
    $IsBlocked     = ($BlockOptIn -eq 1)
    $IsReversed    = ($BlockOptIn -eq 2)
    $IsLocked      = ($BlockOptOut -eq 1)

    $Raw = "KFMSilentOptIn=$SilentOptIn | KFMOptInWithWizard=$WizardOptIn | KFMBlockOptIn=$BlockOptIn | KFMBlockOptOut=$BlockOptOut | PerDesktop=$PerDesktop | PerDocuments=$PerDocuments | PerPictures=$PerPictures"

    # Most severe: value 2 reverses KFM and beats everything else
    if ($IsReversed) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'CRITICAL CONFLICT: KFMBlockOptIn=2 is actively moving folders BACK to the device. This overrides KFMSilentOptIn, KFMOptInWithWizard, and all per-folder policies. Remove KFMBlockOptIn or set to 0 before deploying any opt-in policy.' `
            -RawValue $Raw
    }

    # No enable policy at all
    if (-not $HasSilentPath -and -not $HasWizardPath) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'No KFM enable policy found. Neither KFMSilentOptIn, KFMOptInWithWizard, nor any per-folder KFMSilentOptIn* value is configured. KFM cannot proceed.' `
            -RawValue $Raw
    }

    # Wizard-only + block wizard = dead-end; user has no path and no admin-silent path
    if ($IsBlocked -and $HasWizardPath -and -not $HasSilentPath) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'CONFLICT: KFMOptInWithWizard is the only configured KFM path, but KFMBlockOptIn=1 disables that wizard. No silent admin path (KFMSilentOptIn) exists. KFM will never run. Either add KFMSilentOptIn or remove KFMBlockOptIn.' `
            -RawValue $Raw
    }

    # Silent path + block wizard = valid and recommended for full admin control
    if ($HasSilentPath -and $IsBlocked) {
        $LockNote = if ($IsLocked) { ' KFMBlockOptOut=1 prevents user reversal — fully locked.' } else { ' KFMBlockOptOut is not set; users can still reverse KFM from the tray icon.' }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail "Effective KFM mode: Admin-driven silent opt-in (KFMSilentOptIn). User wizard disabled by KFMBlockOptIn=1 (does NOT suppress the silent path — this is correct per Microsoft docs).$LockNote" `
            -RawValue $Raw
    }

    # Silent path without opt-out lock — works but users can undo it
    if ($HasSilentPath -and -not $IsLocked) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail 'KFMSilentOptIn is configured and active. However, KFMBlockOptOut is not set — users can reverse the redirect via the OneDrive tray menu. Deploy KFMBlockOptOut=1 to enforce the redirect for managed devices.' `
            -RawValue $Raw
    }

    # All good: silent + locked
    if ($HasSilentPath -and $IsLocked) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'Effective KFM mode: Admin-driven silent opt-in with user reversal locked (KFMBlockOptOut=1). Configuration is correct for a fully managed deployment.' `
            -RawValue $Raw
    }

    # Wizard-only path — acceptable for user-consent models
    if ($HasWizardPath -and -not $IsBlocked) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail 'Effective KFM mode: User-consent wizard (KFMOptInWithWizard). KFM only runs if the user accepts the wizard prompt. Consider KFMSilentOptIn for admin-driven enforcement.' `
            -RawValue $Raw
    }

    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
        -Detail "KFM policy configuration evaluated — see RawValue for full state." -RawValue $Raw
}

function Invoke-ODCheck_SilentAccountConfigPolicy {
    $CheckName = 'SilentAccountConfigPolicy'
    $Group     = 'Policy (Computer)'

    # SilentAccountConfig (HKLM policy DWORD) instructs OneDrive to silently
    # sign in using the Windows AAD/Hybrid join token. This is a hard prerequisite
    # for KFMSilentOptIn to work without user interaction on Azure AD and Hybrid
    # Azure AD joined devices. Without it the user must manually sign in to
    # OneDrive before KFM can begin.
    $Raw         = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'SilentAccountConfig'
    $SilentOptIn = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptIn'

    if ($Raw -eq 1) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'SilentAccountConfig = 1 — OneDrive will silently sign in using the device AAD/Hybrid join token. This is required for KFMSilentOptIn to complete without user interaction.' `
            -RawValue "$Raw"
    }
    if ($null -eq $Raw -or $Raw -eq 0) {
        $Impact = if ($SilentOptIn) {
            'KFMSilentOptIn IS configured on this machine. Without SilentAccountConfig, OneDrive will wait for the user to sign in manually before KFM can proceed — silent deployment will not be fully silent.'
        } else {
            'KFMSilentOptIn is also not configured; this may be acceptable if using KFMOptInWithWizard only.'
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "SilentAccountConfig is not set or disabled. $Impact Deploy via GPO: Computer Config > Admin Templates > OneDrive > Silently sign in users to the OneDrive sync app." `
            -RawValue "$Raw"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
        -Detail "SilentAccountConfig = $Raw (unexpected value; expected 0 or 1)" -RawValue "$Raw"
}

function Invoke-ODCheck_FilesOnDemandPolicy {
    $CheckName = 'FilesOnDemandPolicy'
    $Group     = 'Policy (Computer)'

    # Files On Demand is enabled by default on Windows 10 1709+. Disabling it
    # forces OneDrive to download all files locally during KFM migration, which
    # can stall on low-disk-space machines and dramatically increases the sync
    # window. If explicitly disabled via policy, flag it.
    $Raw = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'FilesOnDemandEnabled'

    if ($null -eq $Raw) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail 'FilesOnDemandEnabled not configured via policy — client default applies (enabled on Windows 10 1709+). Files will sync as online-only placeholders, minimising local disk impact during KFM.' `
            -RawValue 'Not configured'
    }
    if ($Raw -eq 1) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'FilesOnDemandEnabled = 1 — Files On Demand explicitly enabled via policy. Files will appear as online-only placeholders during KFM, reducing local disk pressure.' `
            -RawValue "$Raw"
    }
    if ($Raw -eq 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail 'FilesOnDemandEnabled = 0 — Files On Demand explicitly DISABLED via policy. KFM will download all Desktop/Documents/Pictures files to local disk during migration. Ensure LocalDiskHeadroom is sufficient and expect a longer migration window.' `
            -RawValue "$Raw"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
        -Detail "FilesOnDemandEnabled = $Raw (unexpected value)" -RawValue "$Raw"
}

function Invoke-ODCheck_PreventNetworkTraffic {
    $CheckName = 'PreventNetworkTrafficPreSignIn'
    $Group     = 'Policy (Computer)'

    # PreventNetworkTrafficPreUserSignIn = 1 stops OneDrive from making any
    # network calls until the user has interactively signed in. On shared or
    # kiosk machines this is desirable; on standard managed desktops it delays
    # SilentAccountConfig and therefore delays KFM start.
    $Raw = Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'PreventNetworkTrafficPreUserSignIn'

    if ($Raw -eq 1) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail 'PreventNetworkTrafficPreUserSignIn = 1 — OneDrive will not attempt network calls (including silent sign-in and KFM) until the user has interactively signed in. This delays KFM on first logon. Acceptable for kiosk/shared devices; review if unexpected on standard managed workstations.' `
            -RawValue "$Raw"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail 'PreventNetworkTrafficPreUserSignIn not set or 0 — OneDrive may attempt silent sign-in and KFM immediately on startup without waiting for interactive sign-in.' `
        -RawValue "$Raw"
}

function Invoke-ODCheck_KFMGPOSource {
    $CheckName = 'KFMGPOSource'
    $Group     = 'Policy (Computer)'

    # Enumerate machine-scoped GPOs from the GP State registry. This helps
    # identify whether OneDrive KFM policy arrived via Group Policy or another
    # channel (Intune, startup script, direct registry write). The definitive
    # source is 'gpresult /scope computer /h gpresult.html'.
    $StatePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List'
    $GPONames  = @()

    try {
        $StateKey = Get-Item -Path $StatePath -ErrorAction Stop
        foreach ($SubName in $StateKey.GetSubKeyNames()) {
            $SubPath = Join-Path $StatePath $SubName
            try {
                $Sub     = Get-Item -Path $SubPath -ErrorAction Stop
                $GPOName = $Sub.GetValue('DisplayName')
                if ($GPOName) { $GPONames += $GPOName }
            } catch { }
        }
    } catch { }

    $HasKFMPolicy = [bool](Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMSilentOptIn') -or
                   [bool](Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMOptInWithWizard') -or
                   ($null -ne (Get-RegValueSafe -Path $OD_POLICY_HKLM -Name 'KFMBlockOptIn'))

    if ($GPONames.Count -eq 0) {
        $Detail = if ($HasKFMPolicy) {
            'KFM policy values are present under HKLM but no machine GPOs were found in the Group Policy State registry. The policy was likely deployed via Intune/MDM, a startup script, or a direct registry write — not via traditional Group Policy. Verify the delivery channel matches your intent.'
        } else {
            'No machine GPOs found in GP State registry and no KFM policy values present. Machine may not be domain-joined, GP has never run, or GPO scope/WMI filters are excluding this machine.'
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail $Detail -RawValue 'No GPOs found in GP State registry'
    }

    $Raw = $GPONames -join ' | '
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
        -Detail "Applied machine GPOs ($($GPONames.Count)): $Raw. Run 'gpresult /scope computer /h gpresult.html' to confirm which GPO delivers the OneDrive policy and verify WMI filters / security filtering are not excluding affected machines." `
        -RawValue $Raw
}

function Test-IntuneEnrolled {
    # Returns $true if an Intune/MDM DM Server enrollment is present in HKLM.
    try {
        return [bool](Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop |
            Where-Object { try { $_.GetValue('ProviderID') -eq 'MS DM Server' } catch { $false } })
    } catch { return $false }
}

function Invoke-ODCheck_GPOMachineLastApplied {
    param($UserContext)
    $CheckName = 'GPOMachineLastApplied'
    $Group     = 'Policy (Computer)'

    $Raw = Get-RegValueSafe -Path $GP_STATE_MACHINE -Name 'EndTime'
    if ($null -eq $Raw) {
        if (Test-IntuneEnrolled) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
                -Detail 'Machine GP State EndTime not present. Device is Intune/MDM-enrolled — policies delivered via MDM CSP do not populate the traditional GP refresh timestamp. Validate policy delivery via Intune portal sync status.' `
                -RawValue 'MDM-managed: GP EndTime not applicable'
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'Machine GP State EndTime not found and no MDM enrollment detected. GP may never have completed, or the device is not domain/MDM-joined.' `
            -RawValue $null
    }

    $GPOTime  = [DateTime]::FromFileTimeUtc($Raw)
    $AgeHours = [Math]::Round(((Get-Date).ToUniversalTime() - $GPOTime).TotalHours, 1)
    $ISOTime  = $GPOTime.ToString('o')
    if ($AgeHours -gt $FailHours) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "Last machine GP refresh was $AgeHours hours ago — exceeds $FailHours hr threshold" -RawValue $ISOTime
    }
    if ($AgeHours -gt $WarnHours) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "Last machine GP refresh was $AgeHours hours ago — exceeds $WarnHours hr warning threshold" -RawValue $ISOTime
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "Last machine GP refresh was $AgeHours hours ago" -RawValue $ISOTime
}
#endregion

# ============================================================================
#region POLICY CHECKS — USER CONFIGURATION (HKCU)
# ============================================================================

function Invoke-ODCheck_HKCUPolicyPresent {
    $CheckName = 'HKCUPolicyPresent'
    $Group     = 'Policy (User)'

    # KFM policies are documented as machine-scoped (HKLM), but tenants
    # sometimes deploy User Configuration GPOs that target HKCU\Policies\...\OneDrive
    # for non-KFM settings (DisablePersonalSync, DisableTutorial, etc.). This
    # check inventories what's there so the snapshot section has context.
    try {
        $Key = Get-Item -Path $OD_POLICY_HKCU -ErrorAction Stop
        $ValueCount = $Key.GetValueNames().Count
        if ($ValueCount -eq 0) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
                -Detail 'HKCU OneDrive policy key exists but contains no values' -RawValue $null
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail "HKCU OneDrive policy key exists with $ValueCount value(s) — see Configuration Snapshot for details" `
            -RawValue ($Key.GetValueNames() -join ', ')
    }
    catch {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'No HKCU User Configuration OneDrive policies in effect (HKCU policy key absent)' `
            -RawValue $null
    }
}

function Invoke-ODCheck_HKCUKFMConflict {
    $CheckName = 'HKCUKFMConflict'
    $Group     = 'Policy (User)'

    # If someone has accidentally deployed KFM* values via User Configuration
    # GPO (HKCU), they will be ignored at runtime — KFM only honors HKLM —
    # and the admin is left wondering why nothing happens.
    $KFMValueNames = @(
        'KFMSilentOptIn', 'KFMOptInWithWizard',
        'KFMSilentOptInDesktop', 'KFMSilentOptInDocuments', 'KFMSilentOptInPictures',
        'KFMBlockOptIn', 'KFMBlockOptOut'
    )
    $Found = @()
    foreach ($N in $KFMValueNames) {
        $V = Get-RegValueSafe -Path $OD_POLICY_HKCU -Name $N
        if ($null -ne $V) { $Found += "$N=$V" }
    }
    if ($Found.Count -eq 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'No KFM policy values found under HKCU (correct — KFM honors HKLM only)' -RawValue $null
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
        -Detail "KFM-related values found under HKCU (User Configuration GPO?) — these are IGNORED by OneDrive at runtime. Move to Computer Configuration: $($Found -join '; ')" `
        -RawValue ($Found -join ' | ')
}

function Invoke-ODCheck_GPOUserLastApplied {
    param($UserContext)
    $CheckName = 'GPOUserLastApplied'
    $Group     = 'Policy (User)'

    $UserStatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\$($UserContext.SID)\Extension-List\{00000000-0000-0000-0000-000000000000}"
    $Raw = Get-RegValueSafe -Path $UserStatePath -Name 'EndTime'
    if ($null -eq $Raw) {
        if (Test-IntuneEnrolled) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
                -Detail "User GP State EndTime not present. Device is Intune/MDM-enrolled — user-scoped GP timestamps are not written when policies are delivered via MDM CSP." `
                -RawValue 'MDM-managed: GP EndTime not applicable'
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail "User GP state EndTime not present. SID: $($UserContext.SID). GP may never have completed for this account or the device is not domain-joined." `
            -RawValue $UserStatePath
    }

    $GPOTime  = [DateTime]::FromFileTimeUtc($Raw)
    $AgeHours = [Math]::Round(((Get-Date).ToUniversalTime() - $GPOTime).TotalHours, 1)
    $ISOTime  = $GPOTime.ToString('o')

    if ($AgeHours -gt $FailHours) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "Last user GP refresh was $AgeHours hours ago — exceeds $FailHours hr threshold" -RawValue $ISOTime
    }
    if ($AgeHours -gt $WarnHours) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "Last user GP refresh was $AgeHours hours ago — exceeds $WarnHours hr warning threshold" `
            -RawValue $ISOTime
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "Last user GP refresh was $AgeHours hours ago" -RawValue $ISOTime
}
#endregion

# ============================================================================
#region PREREQUISITES
# ============================================================================

function Invoke-ODCheck_AccountSignedIn {
    $CheckName = 'AccountSignedIn'
    $Group     = 'Prerequisites'

    if (-not (Test-Path $OD_ACCOUNT_HKCU)) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'Business1 account key absent — OneDrive has not signed in to a work account on this machine' `
            -RawValue $null
    }

    $Email = Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'UserEmail'
    if (-not $Email) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'Business1 key exists but UserEmail is empty — account may be in a partial sign-in state' `
            -RawValue $null
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "OneDrive signed in as: $Email" -RawValue $Email
}

function Invoke-ODCheck_TenantMatch {
    $CheckName = 'TenantMatch'
    $Group     = 'Prerequisites'

    if (-not $ExpectedTenantId) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'ExpectedTenantId parameter not supplied — tenant match cannot be validated' `
            -RawValue $null
    }
    if (-not (Test-Path $OD_ACCOUNT_HKCU)) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'Business1 account key absent — account not signed in' -RawValue $null
    }

    # ConfiguredTenantId is the canonical value; ServiceEndpointUri is a
    # documented fallback (older builds populated only the URI).
    $TenantId = Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'ConfiguredTenantId'
    if (-not $TenantId) {
        $Uri = Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'ServiceEndpointUri'
        if ($Uri -and ($Uri -match '([a-f0-9\-]{36})')) {
            $TenantId = $Matches[1]
        }
    }

    if (-not $TenantId) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'Could not locate tenant GUID in Business1 key (checked ConfiguredTenantId, ServiceEndpointUri)' `
            -RawValue $null
    }

    if ($TenantId.Trim().ToLower() -ne $ExpectedTenantId.Trim().ToLower()) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "Signed-in tenant ($TenantId) does not match ExpectedTenantId. KFM will silently do nothing." `
            -RawValue $TenantId
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail 'Signed-in tenant matches ExpectedTenantId' -RawValue $TenantId
}

function Invoke-ODCheck_SilentSignInRuntimeStatus {
    # RUNTIME check — registry-primary. SilentBusinessConfigCompleted=1 (HKCU) is
    # written by OneDrive after a successful silent provisioning cycle and does not
    # rotate like log files. AzureAdPrt from dsregcmd confirms a live PRT exists.
    # Log patterns are supplementary: checked only when registry evidence is absent
    # and only to surface error codes that aid diagnosis.
    $CheckName  = 'SilentSignInRuntimeStatus'
    $Group      = 'Prerequisites'

    # --- Primary: registry flag written by OneDrive on completion ---
    $SilentDone    = Get-RegValueSafe -Path 'HKCU:\SOFTWARE\Microsoft\OneDrive' -Name 'SilentBusinessConfigCompleted'
    $AutoConfigured= Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'AutoConfigured'

    # --- PRT state from dsregcmd ---
    $HasPrt = $false; $PrtExpired = $false; $PrtExpiry = $null
    try {
        foreach ($Line in (& dsregcmd.exe /status 2>&1)) {
            if ($Line -match 'AzureAdPrt\s*:\s*(YES|NO)')   { $HasPrt = $Matches[1] -eq 'YES' }
            if ($Line -match 'PrtExpiryTime\s*:\s*(.+)')    { $PrtExpiry = $Matches[1].Trim() }
        }
        if ($PrtExpiry) {
            try { $PrtExpired = [datetime]::Parse($PrtExpiry) -lt (Get-Date) } catch { }
        }
    } catch { }

    $PrtStr  = if ($HasPrt -and -not $PrtExpired) { 'PRT=Valid' }
               elseif ($HasPrt -and $PrtExpired)  { "PRT=EXPIRED(expires=$PrtExpiry)" }
               else                               { 'PRT=None' }
    $AutoStr = if ($null -ne $AutoConfigured -and $AutoConfigured -ne 0) { "AutoConfigured=$AutoConfigured" } else { 'AutoConfigured=absent' }
    $RawBase = "SilentBusinessConfigCompleted=$SilentDone | $PrtStr | $AutoStr"

    if ($SilentDone -eq 1) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail "SilentBusinessConfigCompleted=1 — OneDrive completed silent sign-in provisioning. [$PrtStr | $AutoStr]" `
            -RawValue $RawBase
    }
    if ($null -ne $SilentDone) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "SilentBusinessConfigCompleted=$SilentDone — provisioning key exists but value is not 1; provisioning may be incomplete. [$PrtStr | $AutoStr]" `
            -RawValue $RawBase
    }

    # Key absent — cross-reference PRT and supplementary log error
    if (-not $HasPrt) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "SilentBusinessConfigCompleted absent AND $PrtStr. No Azure AD Primary Refresh Token — silent sign-in cannot complete. Verify the device is AAD or Hybrid AAD joined and the user has a current AAD session. [$AutoStr]" `
            -RawValue $RawBase
    }
    if ($PrtExpired) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "SilentBusinessConfigCompleted absent. $PrtStr — an expired PRT may block silent token acquisition. User re-authentication to AAD may be required. [$AutoStr]" `
            -RawValue $RawBase
    }

    # PRT valid, key absent — check log for an error code as supplementary context
    $ErrLine = Get-LastLogMatch -Pattern 'SilentAccountConfig - completed - error'
    if ($ErrLine) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "SilentBusinessConfigCompleted absent. $PrtStr. Log records sign-in error: '$($ErrLine.Trim())'. Possible Conditional Access policy, tenant mismatch, or proxy blocking token acquisition. [$AutoStr]" `
            -RawValue "$RawBase | LogError=$($ErrLine.Trim())"
    }

    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
        -Detail "SilentBusinessConfigCompleted absent. $PrtStr — silent sign-in provisioning has not completed. OneDrive may not have started yet, the policy may be newly applied, or PreventNetworkTrafficPreUserSignIn is delaying the attempt. [$AutoStr]" `
        -RawValue $RawBase
}

function Invoke-ODCheck_FolderRedirConflict {
    $CheckName = 'FolderRedirConflict'
    $Group     = 'Prerequisites'

    # Traditional GPO-based folder redirection (UNC paths) and KFM are mutually
    # exclusive for each affected folder. A folder already pointing at \\server\...
    # will not be touched by KFM for that specific folder; the other two folders
    # may still be redirected by KFM normally. Partial UNC redirection is a
    # Warning (common in staged migrations); full UNC on all three is a Fail.
    $Folders = @(
        [PSCustomObject]@{ Name = 'Desktop';   RegName = 'Desktop';     Path = (Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'Desktop')    }
        [PSCustomObject]@{ Name = 'Documents'; RegName = 'Personal';    Path = (Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'Personal')   }
        [PSCustomObject]@{ Name = 'Pictures';  RegName = 'My Pictures'; Path = (Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'My Pictures')}
    )

    $UNC     = @($Folders | Where-Object { $_.Path -and $_.Path -like '\\*' })
    $OneDrive= @($Folders | Where-Object { $_.Path -and $_.Path -like '*OneDrive*' })
    $Local   = @($Folders | Where-Object { $_.Path -and $_.Path -notlike '\\*' -and $_.Path -notlike '*OneDrive*' })

    $FolderSummary = ($Folders | ForEach-Object {
        $Tag = if ($_.Path -like '\\*')          { 'UNC'     }
               elseif ($_.Path -like '*OneDrive*'){ 'OneDrive'}
               elseif ($_.Path)                  { 'Local'   }
               else                              { 'Unresolved' }
        "$($_.Name)[$Tag]=$($_.Path)"
    }) -join ' | '

    if ($UNC.Count -eq 3) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "All three folders are redirected to UNC paths via traditional folder redirection. KFM cannot redirect any of them. To use KFM, the traditional redirection policy must be removed and each folder restored to a local path before OneDrive can take it over. Folders: $($UNC.Name -join ', ')" `
            -RawValue $FolderSummary
    }
    if ($UNC.Count -gt 0) {
        $UNCNames  = $UNC.Name -join ', '
        $FreeNames = (@($OneDrive) + @($Local) | ForEach-Object { $_.Name }) -join ', '
        $Detail    = "Traditional UNC folder redirection is active on $($UNC.Count) of 3 folders: $UNCNames. KFM will NOT redirect these specific folders — they remain UNC-redirected until the GPO is removed. " +
                     $(if ($FreeNames) { "Folders eligible for KFM: $FreeNames." } else { '' }) +
                     " Per-folder KFM opt-in policies (KFMSilentOptInDesktop/Documents/Pictures) can target only the non-UNC folders."
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail $Detail -RawValue $FolderSummary
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail 'No traditional UNC-based Folder Redirection detected. All three folders are eligible for KFM.' `
        -RawValue $FolderSummary
}

function Invoke-ODCheck_QuotaHeadroom {
    $CheckName = 'QuotaHeadroom'
    $Group     = 'Prerequisites'

    if (-not (Test-Path $OD_ACCOUNT_HKCU)) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'Business1 key absent — cannot read quota' -RawValue $null
    }
    $Available = Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'QuotaAvailable'
    $Total     = Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'QuotaTotal'

    if ($null -eq $Available -or $null -eq $Total) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail 'QuotaAvailable or QuotaTotal not present — OneDrive may not have synced quota data yet' `
            -RawValue $null
    }

    $AvailGB = [Math]::Round($Available / 1GB, 2)
    $TotalGB = [Math]::Round($Total / 1GB, 2)
    $Raw     = "Available: ${AvailGB}GB / Total: ${TotalGB}GB"

    if ($AvailGB -le $FailQuotaGB) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "Only ${AvailGB}GB free of ${TotalGB}GB — quota critically low. KFM may fail partway through migration." `
            -RawValue $Raw
    }
    if ($AvailGB -le $WarnQuotaGB) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "${AvailGB}GB free of ${TotalGB}GB — quota may be insufficient for large Desktop/Documents/Pictures folders" `
            -RawValue $Raw
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "${AvailGB}GB free of ${TotalGB}GB" -RawValue $Raw
}

function Invoke-ODCheck_LocalDiskHeadroom {
    $CheckName = 'LocalDiskHeadroom'
    $Group     = 'Prerequisites'

    # Local disk on the OneDrive root drive — separate from cloud quota.
    # KFM stalls (with cryptic errors) when local disk fills regardless of
    # how much OneDrive quota is left.
    $UserFolder = Get-RegValueSafe -Path $OD_ACCOUNT_HKCU -Name 'UserFolder'
    $Drive = if ($UserFolder) { Split-Path $UserFolder -Qualifier } else { (Split-Path $env:USERPROFILE -Qualifier) }

    try {
        $DriveInfo = New-Object System.IO.DriveInfo($Drive)
        $FreeGB    = [Math]::Round($DriveInfo.AvailableFreeSpace / 1GB, 2)
        $TotalGB   = [Math]::Round($DriveInfo.TotalSize / 1GB, 2)
        $Raw       = "Drive ${Drive} — Free: ${FreeGB}GB / Total: ${TotalGB}GB"

        if ($FreeGB -le $FailLocalDiskGB) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
                -Detail "Only ${FreeGB}GB free on $Drive (OneDrive root drive) — KFM will fail" -RawValue $Raw
        }
        if ($FreeGB -le $WarnLocalDiskGB) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
                -Detail "${FreeGB}GB free on $Drive — low local headroom for KFM staging" -RawValue $Raw
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail "${FreeGB}GB free on $Drive" -RawValue $Raw
    }
    catch {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail "Could not read disk info for drive '$Drive': $($_.Exception.Message)" -RawValue $null
    }
}

function Invoke-ODCheck_WindowsVersion {
    $CheckName = 'WindowsVersion'
    $Group     = 'Prerequisites'

    # Target baseline for this script is Windows 11 (build 22000+).
    # KFM absolute minimum is Windows 10 build 16299 (version 1709).
    # Windows 10 machines are flagged as Warning — functional but outside target.
    try {
        $OS      = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $Build   = [int]$OS.BuildNumber
        $Name    = $OS.Caption.Trim()
        $UBR     = Get-RegValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
        $Display = if ($UBR) { "$Name (Build $Build.$UBR)" } else { "$Name (Build $Build)" }
        $Raw     = $Display

        if ($Build -lt 16299) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
                -Detail "Build $Build is below the KFM absolute minimum (16299 / Windows 10 1709). KFM is not supported on this OS." `
                -RawValue $Raw
        }
        if ($Build -ge 22000) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
                -Detail "$Display — Windows 11 confirmed. Full KFM support." -RawValue $Raw
        }
        # Windows 10 — KFM works but outside the Windows 11 target baseline
        if ($Build -ge 19041) {
            return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
                -Detail "$Display — Windows 10 (meets KFM minimum, outside Windows 11 target baseline). KFM is functional; validate client behaviour matches your Windows 11 deployment expectations." `
                -RawValue $Raw
        }
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "$Display — Windows 10 below 20H2 (build 19041). KFM minimum met but client reliability improved substantially from 20H2 onward. Update recommended." `
            -RawValue $Raw
    }
    catch {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail "Could not determine Windows version: $($_.Exception.Message)" -RawValue $null
    }
}

function Invoke-ODCheck_DeviceJoinState {
    $CheckName = 'DeviceJoinState'
    $Group     = 'Prerequisites'

    # Device join state is authoritative from dsregcmd.exe. The join type
    # determines which silent sign-in mechanism is available and therefore
    # whether KFMSilentOptIn can complete without user interaction:
    #   Hybrid AAD Joined  — SilentAccountConfig works; fully silent KFM possible
    #   AAD Joined only    — SilentAccountConfig works; fully silent KFM possible
    #   Domain Joined only — SilentAccountConfig does NOT work; user must sign in manually
    #   Not joined         — No token for silent sign-in; KFM requires manual OneDrive sign-in
    $AzureAdJoined    = $false
    $DomainJoined     = $false
    $DeviceTenantId   = $null

    try {
        $dsreg = & dsregcmd.exe /status 2>&1
        foreach ($Line in $dsreg) {
            if ($Line -match 'AzureAdJoined\s*:\s*(YES|NO)')    { $AzureAdJoined  = $Matches[1] -eq 'YES' }
            if ($Line -match 'DomainJoined\s*:\s*(YES|NO)')     { $DomainJoined   = $Matches[1] -eq 'YES' }
            if ($Line -match 'TenantId\s*:\s*([a-f0-9\-]{36})') { $DeviceTenantId = $Matches[1] }
        }
    } catch { }

    $JoinType = if ($AzureAdJoined -and $DomainJoined) { 'Hybrid Azure AD Joined' }
                elseif ($AzureAdJoined)                 { 'Azure AD Joined (cloud-only)' }
                elseif ($DomainJoined)                  { 'Domain Joined Only (not AAD/Hybrid)' }
                else                                    { 'Not Joined' }

    $Raw = "JoinType=$JoinType | DeviceTenantId=$DeviceTenantId"

    if ($ExpectedTenantId -and $DeviceTenantId -and
        $DeviceTenantId.Trim().ToLower() -ne $ExpectedTenantId.Trim().ToLower()) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "$JoinType — device TenantId ($DeviceTenantId) does not match ExpectedTenantId. The AAD token issued for silent sign-in belongs to a different tenant; KFMSilentOptIn for the expected tenant will fail." `
            -RawValue $Raw
    }

    if ($AzureAdJoined) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail "$JoinType — SilentAccountConfig=1 will enable fully silent OneDrive sign-in and allow KFMSilentOptIn to complete without user interaction." `
            -RawValue $Raw
    }
    if ($DomainJoined -and -not $AzureAdJoined) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail 'Domain Joined Only — device does not have an Azure AD join token. SilentAccountConfig cannot silently sign in OneDrive. Users must sign in to OneDrive manually (or via ADFS/modern auth prompt) before KFMSilentOptIn will proceed. Consider Hybrid AAD Join to enable fully silent deployment.' `
            -RawValue $Raw
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
        -Detail 'Device does not appear to be domain or Azure AD joined. Could not determine join state from dsregcmd output. Verify manually.' `
        -RawValue $Raw
}
#endregion

# ============================================================================
#region RUNTIME STATE
# ============================================================================

function Get-ShellFolderRedirectStatus {
    param([string]$ValueName)
    $Path = Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name $ValueName
    if (-not $Path) { return $null }
    return @{
        Path       = $Path
        IsOneDrive = ($Path -like '*OneDrive*')
        IsUNC      = ($Path -like '\\*')
    }
}

function Get-ODShellFolderCheckResult {
    # Shared logic for Desktop/Documents/Pictures runtime checks
    param([string]$CheckName, [string]$ValueName, [string]$FriendlyName)
    $Group = 'Runtime'
    $Info  = Get-ShellFolderRedirectStatus -ValueName $ValueName
    if (-not $Info) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Unknown' `
            -Detail "Could not read $FriendlyName path from User Shell Folders" -RawValue $null
    }
    if ($Info.IsOneDrive) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail "$FriendlyName is redirected into OneDrive: $($Info.Path)" -RawValue $Info.Path
    }
    if ($Info.IsUNC) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "$FriendlyName points to a UNC path (traditional redirection): $($Info.Path)" -RawValue $Info.Path
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
        -Detail "$FriendlyName is NOT redirected into OneDrive. Current path: $($Info.Path)" -RawValue $Info.Path
}

function Invoke-ODCheck_DesktopRedirected   { Get-ODShellFolderCheckResult -CheckName 'DesktopRedirected'   -ValueName 'Desktop'     -FriendlyName 'Desktop' }
function Invoke-ODCheck_DocumentsRedirected { Get-ODShellFolderCheckResult -CheckName 'DocumentsRedirected' -ValueName 'Personal'    -FriendlyName 'Documents' }
function Invoke-ODCheck_PicturesRedirected  { Get-ODShellFolderCheckResult -CheckName 'PicturesRedirected'  -ValueName 'My Pictures' -FriendlyName 'Pictures' }

function Invoke-ODCheck_KFMCompletionFlags {
    $CheckName = 'KFMCompletionFlags'
    $Group     = 'Runtime'

    # OneDrive writes values into the KFM subkey when it successfully completes
    # a folder redirect. Exact value names vary by client version (e.g. "Desktop",
    # "DesktopMoved", "Desktop_Redirected") so we fuzzy-match by folder name.
    # Shell folder path is the authoritative redirect indicator; the KFM subkey
    # is OneDrive's own completion record. Discrepancies expose manual moves,
    # partial migration, or active KFM reversal.
    $ShellDesktop = Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'Desktop'
    $ShellDocs    = Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'Personal'
    $ShellPics    = Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'My Pictures'

    $KFMValues = @{}
    if (Test-Path $OD_KFM_HKCU) {
        try {
            $Key = Get-Item -Path $OD_KFM_HKCU -ErrorAction Stop
            foreach ($N in $Key.GetValueNames()) { $KFMValues[$N.ToLower()] = $Key.GetValue($N) }
        } catch { }
    }

    $PerFolder = foreach ($F in @(
        @{ Name = 'Desktop';   Shell = $ShellDesktop }
        @{ Name = 'Documents'; Shell = $ShellDocs    }
        @{ Name = 'Pictures';  Shell = $ShellPics    }
    )) {
        $InOD    = $F.Shell -like '*OneDrive*'
        $Low     = $F.Name.ToLower()
        $HasFlag = [bool]($KFMValues.Keys | Where-Object { $_ -like "*$Low*" })
        $State   = if ($InOD -and $HasFlag)  { 'Complete' }
                   elseif ($InOD)            { 'In-OneDrive-NoFlag' }
                   elseif ($HasFlag)         { 'FlagSet-NotRedirected' }
                   else                      { 'Not-Redirected' }
        [PSCustomObject]@{ Name = $F.Name; State = $State; Path = $F.Shell }
    }

    $Complete  = @($PerFolder | Where-Object State -eq 'Complete').Count
    $Anomalous = @($PerFolder | Where-Object State -eq 'FlagSet-NotRedirected')
    $NoFlag    = @($PerFolder | Where-Object State -eq 'In-OneDrive-NoFlag')
    $NotRedir  = @($PerFolder | Where-Object State -eq 'Not-Redirected')
    $Raw       = ($PerFolder | ForEach-Object { "$($_.Name)=$($_.State)[$($_.Path)]" }) -join ' | '

    if ($Complete -eq 3) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
            -Detail 'All 3 folders: OneDrive shell redirect confirmed and KFM completion flag present.' `
            -RawValue $Raw
    }

    $Issues = @()
    if ($Anomalous.Count) { $Issues += "KFM flag set but folder NOT in OneDrive ($($Anomalous.Name -join ', ')) — possible KFM reversal or stale flag" }
    if ($NoFlag.Count)    { $Issues += "In OneDrive but no KFM completion flag ($($NoFlag.Name -join ', ')) — likely moved manually, not via KFM" }
    if ($NotRedir.Count)  { $Issues += "Not redirected to OneDrive: $($NotRedir.Name -join ', ')" }

    $Status = if ($Anomalous.Count -gt 0) { 'Fail' } elseif ($Complete -gt 0) { 'Warning' } else { 'Warning' }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status $Status `
        -Detail "$Complete of 3 KFM-complete. $($Issues -join '; ')" -RawValue $Raw
}

function Invoke-ODCheck_SyncDiagKFMState {
    $CheckName = 'SyncDiagKFMState'
    $Group     = 'Runtime'

    # SOURCE: %LOCALAPPDATA%\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log
    # This is OneDrive's periodic diagnostic SNAPSHOT — a human-readable text file
    # updated by the sync client. It differs from registry checks as follows:
    #   Registry (KFMCompletionFlags, shell folders) = current authoritative state
    #   SyncDiagnostics.log                          = OneDrive's own narrative:
    #     error codes, redirect status strings, timestamps of last KFM attempt,
    #     conflict counts, and sync engine state not visible in the registry.
    # The rolling SyncEngine-*.log files may be binary in modern clients and are
    # not parsed here. SyncDiagnostics.log is the recommended diagnostic file.
    $Lines = Get-SyncDiagLines
    if ($Lines.Count -eq 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail "SyncDiagnostics.log not found or empty ($SYNCDIAG_PATH). Log-based KFM context unavailable. Registry and shell folder checks are authoritative." `
            -RawValue $null
    }

    # Conflict check — definitive blocker surfaced as Fail regardless of version
    $ConflictLine = Get-LastLogMatch 'too many conflicts'
    if (-not $ConflictLine) { $ConflictLine = Get-LastLogMatch 'KFM*conflict' }
    if ($ConflictLine) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail 'Conflict warning in SyncDiagnostics.log — too many file conflicts are preventing KFM completion. Resolve sync conflicts and restart OneDrive before re-evaluating.' `
            -RawValue $ConflictLine.Trim()
    }

    # Multi-version KFM pattern scan.
    # Older clients:  'KFM: Desktop - good', 'KFM: Desktop complete'
    # Newer clients:  'KFM Desktop Redirect Complete = 1', 'Desktop Redirect Status: Redirected'
    # All versions:   error codes like '0x8004de40' (sign-in required) or '0x80070005'
    $KFMLines = @($Lines | Where-Object {
        $_ -like '*KFM*' -or $_ -like '*Key Folder Move*' -or
        $_ -like '*KnownFolderMove*' -or $_ -like '*Redirect Status*' -or
        $_ -like '*RedirectState*' -or $_ -like '*RedirectComplete*'
    })

    if ($KFMLines.Count -eq 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Info' `
            -Detail "No KFM entries found in SyncDiagnostics.log ($($Lines.Count) lines scanned). Log may predate KFM activity or this client version uses a different format. See KFMCompletionFlags and folder redirect checks for authoritative state." `
            -RawValue "Lines scanned: $($Lines.Count)"
    }

    # Completion indicators across client versions
    $CompleteLines = @($KFMLines | Where-Object {
        $_ -like '*complete*' -or $_ -like '*RedirectCompleted*' -or
        $_ -like '*- good*' -or $_ -match 'Redirect.*=\s*1' -or
        $_ -like '*Redirected*'
    })

    # Error code extraction — lines with 0x hex codes near KFM context
    $ErrorLines = @($KFMLines | Where-Object { $_ -match '0x[0-9a-fA-F]{6,8}' })
    $ErrorDetail = if ($ErrorLines.Count -gt 0) {
        " Error codes found: $(($ErrorLines | ForEach-Object { if ($_ -match '(0x[0-9a-fA-F]{6,8})') { $Matches[1] } }) -join ', ')."
    } else { '' }

    $LastLine = ($KFMLines | Select-Object -Last 1).Trim()
    $Status   = if ($ErrorLines.Count -gt 0 -and $CompleteLines.Count -lt 3) { 'Warning' } else { 'Info' }

    return New-CheckResult -CheckName $CheckName -Group $Group -Status $Status `
        -Detail "SyncDiagnostics.log: $($KFMLines.Count) KFM-related entries; $($CompleteLines.Count) completion/redirected indicators.$ErrorDetail Log is supplementary to registry checks." `
        -RawValue "Last KFM entry: $LastLine"
}
#endregion

# ============================================================================
#region BLOCKERS
# ============================================================================


function Invoke-ODCheck_FolderSizes {
    $CheckName = 'FolderSizes'
    $Group     = 'Blockers'

    $Paths = @{
        Desktop   = (Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'Desktop')
        Documents = (Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'Personal')
        Pictures  = (Get-RegValueSafe -Path $SHELL_FOLDERS_HKCU -Name 'My Pictures')
    }
    $Sizes    = @{}
    $Warnings = @()
    foreach ($F in $Paths.Keys) {
        $P = $Paths[$F]
        if ($P -and (Test-Path $P)) {
            $S = Get-FolderSizeGB -Path $P
            $Sizes[$F] = $S
            if ($S -gt $LargeFolderThresholdGB) {
                $Warnings += "$F (${S}GB)"
            }
        } else {
            $Sizes[$F] = 'N/A'
        }
    }
    $Raw = ($Sizes.Keys | ForEach-Object { "$_=$($Sizes[$_])GB" }) -join ' | '

    if ($Warnings.Count -gt 0) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Warning' `
            -Detail "Large folders detected (>${LargeFolderThresholdGB}GB): $($Warnings -join ', ')" `
            -RawValue $Raw
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "No folders exceed ${LargeFolderThresholdGB}GB threshold" -RawValue $Raw
}

function Invoke-ODCheck_WNSConnectivity {
    $CheckName = 'WNSConnectivity'
    $Group     = 'Blockers'

    $Hostname = 'skydrive.wns.windows.com'
    $Port     = 443

    # DNS first — separates "DNS broken" from "firewall broken" remediation paths
    $DNSResolved = $false
    $ResolvedIP  = $null
    try {
        $DNS = [System.Net.Dns]::GetHostAddresses($Hostname)
        if ($DNS -and $DNS.Count -gt 0) {
            $DNSResolved = $true
            $ResolvedIP  = $DNS[0].IPAddressToString
        }
    } catch { }

    if (-not $DNSResolved) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "DNS resolution failed for $Hostname — endpoint unreachable. Check DNS / proxy." `
            -RawValue 'DNS:FAILED TCP:NOT_TESTED'
    }

    if (-not (Test-TCPPort -Hostname $Hostname -Port $Port -TimeoutMs 3000)) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "DNS resolved ($ResolvedIP) but TCP 443 to $Hostname blocked. KFM completion notifications won't reach the client." `
            -RawValue "DNS:$ResolvedIP TCP:BLOCKED"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "$Hostname reachable on TCP 443 (resolved to $ResolvedIP)" `
        -RawValue "DNS:$ResolvedIP TCP:OPEN"
}

function Invoke-ODCheck_AuthEndpointConnectivity {
    $CheckName = 'AuthEndpointConnectivity'
    $Group     = 'Blockers'

    # login.microsoftonline.com:443 is the authentication endpoint for all
    # Microsoft 365 sign-in flows including OneDrive SilentAccountConfig and
    # the interactive sign-in fallback. If this is unreachable, OneDrive cannot
    # obtain an access token and KFM will never start regardless of policy state.
    # A proxy or SSL-inspection appliance intercepting this endpoint is a common
    # cause of silent KFM failures — the connection appears open but the
    # certificate chain breaks modern auth. This check validates TCP reachability
    # only; SSL inspection failures require additional proxy bypass verification.
    $Hostname = 'login.microsoftonline.com'
    $Port     = 443

    $DNSResolved = $false
    $ResolvedIP  = $null
    try {
        $DNS = [System.Net.Dns]::GetHostAddresses($Hostname)
        if ($DNS -and $DNS.Count -gt 0) {
            $DNSResolved = $true
            $ResolvedIP  = $DNS[0].IPAddressToString
        }
    } catch { }

    if (-not $DNSResolved) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "DNS resolution failed for $Hostname. OneDrive cannot authenticate — SilentAccountConfig and KFM will not proceed. Verify DNS and proxy configuration." `
            -RawValue 'DNS:FAILED TCP:NOT_TESTED'
    }
    if (-not (Test-TCPPort -Hostname $Hostname -Port $Port -TimeoutMs 4000)) {
        return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Fail' `
            -Detail "DNS resolved ($ResolvedIP) but TCP 443 to $Hostname is blocked. Modern auth sign-in will fail and KFM cannot proceed. Check firewall / proxy bypass rules for M365 authentication endpoints." `
            -RawValue "DNS:$ResolvedIP TCP:BLOCKED"
    }
    return New-CheckResult -CheckName $CheckName -Group $Group -Status 'Pass' `
        -Detail "$Hostname reachable on TCP 443 (resolved to $ResolvedIP). Note: if SSL inspection is in place, verify $Hostname is excluded from certificate interception — OneDrive uses certificate pinning for auth flows." `
        -RawValue "DNS:$ResolvedIP TCP:OPEN"
}
#endregion

# ============================================================================
#region HTML REPORT
# ============================================================================

function Format-HtmlEncode {
    # Use System.Net.WebUtility (always available in mscorlib) instead of
    # System.Web (requires explicit Add-Type in PS 5.1).
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Export-ODHTMLReport {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [object]$UserContext,
        [object]$ClientInfo,
        [array]$PolicySnapshot,
        [string]$OutputFolder
    )

    $PassCount    = @($Results | Where-Object { $_.Status -eq 'Pass'    }).Count
    $FailCount    = @($Results | Where-Object { $_.Status -eq 'Fail'    }).Count
    $WarnCount    = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $UnknownCount = @($Results | Where-Object { $_.Status -eq 'Unknown' }).Count
    $InfoCount    = @($Results | Where-Object { $_.Status -eq 'Info'    }).Count
    $TotalChecks  = $Results.Count

    $OverallStatus = if ($FailCount -gt 0)    { 'FAIL'    }
                     elseif ($WarnCount -gt 0) { 'WARNING' }
                     elseif ($PassCount -gt 0) { 'PASS'    }
                     else                      { 'UNKNOWN' }

    $Groups = @($Results | Select-Object -ExpandProperty Group -Unique | Sort-Object)

    # Per-group sections
    $GroupHTML = foreach ($GroupName in $Groups) {
        $GroupChecks = $Results | Where-Object { $_.Group -eq $GroupName }
        $GroupFail   = @($GroupChecks | Where-Object { $_.Status -eq 'Fail'    }).Count
        $GroupWarn   = @($GroupChecks | Where-Object { $_.Status -eq 'Warning' }).Count
        $GroupPass   = @($GroupChecks | Where-Object { $_.Status -eq 'Pass'    }).Count

        $GroupBadge = if ($GroupFail -gt 0)    { '<span class="badge badge-fail">Issues Found</span>' }
                      elseif ($GroupWarn -gt 0) { '<span class="badge badge-warn">Warnings</span>' }
                      else                      { '<span class="badge badge-pass">Healthy</span>' }

        $Rows = foreach ($Check in $GroupChecks) {
            $StatusClass = switch ($Check.Status) {
                'Pass'    { 'status-pass' }
                'Fail'    { 'status-fail' }
                'Warning' { 'status-warn' }
                'Info'    { 'status-info' }
                default   { 'status-unknown' }
            }
            $StatusIcon = switch ($Check.Status) {
                'Pass'    { '&#10003;' }
                'Fail'    { '&#10007;' }
                'Warning' { '&#9651;' }
                'Info'    { '&#9432;' }
                default   { '?' }
            }
            $RawDisplay = if ($Check.RawValue) {
                "<div class='raw-value'>$(Format-HtmlEncode $Check.RawValue)</div>"
            } else { '' }

            "<tr>
                <td><span class='status-badge $StatusClass'>$StatusIcon $($Check.Status)</span></td>
                <td class='check-name'>$($Check.CheckName)</td>
                <td class='detail-cell'>$(Format-HtmlEncode $Check.Detail)$RawDisplay</td>
            </tr>"
        }

        "<section class='group-section'>
            <div class='group-header' onclick='toggleSection(this)'>
                <svg class='chevron' viewBox='0 0 16 16' fill='currentColor'><path d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/></svg>
                <h2>$GroupName</h2>
                $GroupBadge
                <span class='group-meta'>$GroupPass pass &nbsp;/&nbsp; $GroupWarn warn &nbsp;/&nbsp; $GroupFail fail</span>
            </div>
            <div class='group-body'><table class='check-table'>
                <thead><tr><th style='width:120px'>Status</th><th style='width:220px'>Check</th><th>Detail</th></tr></thead>
                <tbody>$($Rows -join '')</tbody>
            </table></div>
        </section>"
    }

    # Configuration Snapshot — configured values + "Not configured" placeholders
    # for all documented HKLM scalar policies from aka.ms/OneDriveGPO.
    $ConfiguredCnt = @($PolicySnapshot | Where-Object { $_.Value -ne '(Not configured)' }).Count
    $SnapshotRows = foreach ($Item in ($PolicySnapshot | Sort-Object Scope, Path, Name)) {
        $IsNotSet    = $Item.Value -eq '(Not configured)'
        $ValueClass  = if ($IsNotSet) { 'snap-notset' } else { 'snap-value' }
        $RowClass    = if ($IsNotSet) { ' class=''snap-row-notset''' } else { '' }
        $Desc        = if ($Script:OD_POLICY_DESCRIPTIONS.ContainsKey($Item.Name)) {
                           "<div class='snap-desc'>$(Format-HtmlEncode $Script:OD_POLICY_DESCRIPTIONS[$Item.Name])</div>"
                       } else { '' }
        "<tr$RowClass>
            <td>$(Format-HtmlEncode $Item.Scope)</td>
            <td class='snap-path'>$(Format-HtmlEncode $Item.Path)</td>
            <td class='snap-name'>$(Format-HtmlEncode $Item.Name)$Desc</td>
            <td class='snap-kind'>$(Format-HtmlEncode $Item.Kind)</td>
            <td class='$ValueClass'>$(Format-HtmlEncode $Item.Value)</td>
        </tr>"
    }
    $SnapshotHTML = "<section class='group-section'>
        <div class='group-header' onclick='toggleSection(this)'>
            <svg class='chevron' viewBox='0 0 16 16' fill='currentColor'><path d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/></svg>
            <h2>Configuration Snapshot — OneDrive Policies</h2>
            <span class='badge badge-info'>$ConfiguredCnt configured</span>
            <span class='group-meta'>HKLM (Computer Config) + HKCU (User Config) &nbsp;|&nbsp; all documented policies shown</span>
        </div>
        <div class='group-body'>$(if ($PolicySnapshot.Count -gt 0) {
            "<table class='check-table snapshot-table'>
                <thead><tr><th>Scope</th><th>Path</th><th>Name</th><th>Type</th><th>Value</th></tr></thead>
                <tbody>$($SnapshotRows -join '')</tbody>
            </table>"
        } else {
            "<div style='padding:18px 20px;color:#78716c;font-size:13px;'>No values found under <code>HKLM\SOFTWARE\Policies\Microsoft\OneDrive</code>.</div>"
        })</div>
    </section>"

    # Client info card
    $ClientCard = if ($ClientInfo) {
        "<div class='meta-item'><label>OneDrive Path</label><span>$(Format-HtmlEncode $ClientInfo.Path)</span></div>
         <div class='meta-item'><label>Install Type</label><span>$(Format-HtmlEncode $ClientInfo.InstallType)</span></div>
         <div class='meta-item'><label>Client Version</label><span>$(Format-HtmlEncode $ClientInfo.Version)</span></div>"
    } else {
        "<div class='meta-item'><label>OneDrive Client</label><span style='color:#b91c1c'>Not Installed</span></div>"
    }

    $OverallClass = switch ($OverallStatus) {
        'PASS'    { 'overall-pass' }
        'FAIL'    { 'overall-fail' }
        'WARNING' { 'overall-warn' }
        default   { 'overall-unknown' }
    }
    $TenantNote = if ($ExpectedTenantId) { Format-HtmlEncode $ExpectedTenantId } else { '<em>Not supplied</em>' }
    $RunTime    = Get-Date -Format 'dddd, MMMM d yyyy  HH:mm:ss'

    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OneDrive Health Check &mdash; $($env:COMPUTERNAME)</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#f2f1ed;--card:#fff;--bd:#e0ddd7;--bd2:#ebe8e2;
    --ink:#1c1917;--ink2:#44403c;--muted:#78716c;--accent:#d4622a;
    --f-sans:'Segoe UI Variable Text','Segoe UI',system-ui,sans-serif;
    --f-mono:'Cascadia Code','Cascadia Mono','Consolas',monospace;
    --p-bg:#f0fdf4;--p-bd:#6ee7b7;--p-t:#15803d;
    --f-bg:#fff5f5;--f-bd:#fca5a5;--f-t:#b91c1c;
    --w-bg:#fffbeb;--w-bd:#fcd34d;--w-t:#a16207;
    --i-bg:#eff6ff;--i-bd:#93c5fd;--i-t:#1d4ed8;
    --u-bg:#fafaf8;--u-bd:#d6d3d1;--u-t:#57534e;
  }
  body{font-family:var(--f-sans);background:var(--bg);color:var(--ink);font-size:14px;line-height:1.55}
  .page-header{background:#1c1917;color:#fafaf8;padding:26px 40px 22px;border-bottom:3px solid var(--accent)}
  .header-top{display:flex;align-items:center;gap:14px;margin-bottom:16px}
  .od-icon{width:38px;height:38px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
  .page-header h1{font-size:18px;font-weight:700;letter-spacing:-.3px}
  .page-header .subtitle{color:#a8a29e;font-size:12.5px;margin-top:2px}
  .meta-grid{display:flex;gap:28px;flex-wrap:wrap;padding-top:14px;border-top:1px solid #292524}
  .meta-item label{display:block;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#78716c;margin-bottom:3px;font-weight:600}
  .meta-item span{font-size:12.5px;color:#e7e5e4;font-family:var(--f-mono);word-break:break-all}
  .overall-banner{padding:14px 40px;display:flex;align-items:center;gap:18px;flex-wrap:wrap;border-bottom:1px solid var(--bd)}
  .overall-pass{background:var(--p-bg)}.overall-fail{background:var(--f-bg)}.overall-warn{background:var(--w-bg)}.overall-unknown{background:var(--u-bg)}
  .big-status{font-size:20px;font-weight:800;letter-spacing:2px;color:var(--ink)}
  .overall-pass .big-status{color:var(--p-t)}.overall-fail .big-status{color:var(--f-t)}.overall-warn .big-status{color:var(--w-t)}
  .overall-banner .subtext{font-size:13px;color:var(--muted)}
  .score-pills{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
  .score-pill{padding:3px 11px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid transparent}
  .pill-pass{background:var(--p-bg);color:var(--p-t);border-color:var(--p-bd)}.pill-fail{background:var(--f-bg);color:var(--f-t);border-color:var(--f-bd)}
  .pill-warn{background:var(--w-bg);color:var(--w-t);border-color:var(--w-bd)}.pill-info{background:var(--i-bg);color:var(--i-t);border-color:var(--i-bd)}
  .pill-unknown{background:var(--u-bg);color:var(--u-t);border-color:var(--u-bd)}
  .content{padding:26px 40px;max-width:1320px;margin:0 auto}
  .toolbar{display:flex;justify-content:flex-end;gap:8px;margin-bottom:14px}
  .toolbar button{font:12px/1 var(--f-sans);padding:5px 12px;border:1px solid var(--bd);border-radius:4px;background:var(--card);color:var(--ink2);cursor:pointer;transition:background .15s}
  .toolbar button:hover{background:var(--bd2)}
  .group-section{background:var(--card);border:1px solid var(--bd);border-radius:6px;margin-bottom:12px;overflow:hidden}
  .group-header{display:flex;align-items:center;gap:10px;padding:12px 18px;background:#faf9f7;border-bottom:1px solid var(--bd);cursor:pointer;user-select:none;-webkit-user-select:none}
  .group-section.collapsed>.group-header{border-bottom:none}
  .chevron{width:18px;height:18px;flex-shrink:0;transition:transform .2s ease;color:var(--muted)}
  .group-section.collapsed .chevron{transform:rotate(-90deg)}
  .group-header h2{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--ink)}
  .group-meta{margin-left:auto;font-size:11.5px;color:var(--muted)}
  .group-body{overflow:hidden;transition:max-height .25s ease;max-height:9999px}
  .group-section.collapsed .group-body{max-height:0}
  .badge{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:3px;border:1px solid transparent}
  .badge-pass{background:var(--p-bg);color:var(--p-t);border-color:var(--p-bd)}.badge-fail{background:var(--f-bg);color:var(--f-t);border-color:var(--f-bd)}
  .badge-warn{background:var(--w-bg);color:var(--w-t);border-color:var(--w-bd)}.badge-info{background:var(--i-bg);color:var(--i-t);border-color:var(--i-bd)}
  .check-table{width:100%;border-collapse:collapse}
  .check-table thead tr{background:#f6f5f1}
  .check-table th{padding:7px 16px;text-align:left;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);border-bottom:1px solid var(--bd)}
  .check-table td{padding:10px 16px;border-bottom:1px solid #f5f4f0;vertical-align:top}
  .check-table tbody tr:last-child td{border-bottom:none}.check-table tbody tr:nth-child(even) td{background:#fdfdfc}.check-table tbody tr:hover td{background:#f9f8f5}
  .check-name{font-family:var(--f-mono);font-size:12px;font-weight:500;color:var(--ink2);white-space:nowrap}
  .detail-cell{color:var(--ink2);font-size:13px;line-height:1.5}
  .raw-value{font-family:var(--f-mono);font-size:11px;color:var(--muted);background:#f9f8f6;border:1px solid var(--bd);border-radius:3px;padding:4px 8px;margin-top:6px;word-break:break-all}
  .status-badge{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:3px;white-space:nowrap;border:1px solid transparent}
  .status-pass{background:var(--p-bg);color:var(--p-t);border-color:var(--p-bd)}.status-fail{background:var(--f-bg);color:var(--f-t);border-color:var(--f-bd)}
  .status-warn{background:var(--w-bg);color:var(--w-t);border-color:var(--w-bd)}.status-info{background:var(--i-bg);color:var(--i-t);border-color:var(--i-bd)}
  .status-unknown{background:var(--u-bg);color:var(--u-t);border-color:var(--u-bd)}
  .snapshot-table td{padding:5px 14px;font-size:12px;font-family:var(--f-mono)}.snapshot-table th{font-size:10px;padding:6px 14px}
  .snap-path{color:var(--muted);font-size:11px}.snap-name{font-weight:600;color:var(--ink)}.snap-kind{color:#a8a29e;font-size:10.5px}
  .snap-value{color:var(--i-t);word-break:break-all;max-width:440px}.snap-notset{color:#c4b5a4;font-style:italic}.snap-row-notset td{opacity:.45}
  .snap-desc{color:#a8a29e;font-size:10px;font-style:italic;margin-top:2px;font-family:var(--f-sans);white-space:normal;line-height:1.4}
  .page-footer{text-align:center;padding:18px 40px;color:var(--muted);font-size:11.5px;border-top:1px solid var(--bd);margin-top:6px}
  code{font-family:var(--f-mono);background:#f5f4f0;padding:1px 5px;border-radius:3px;font-size:12px;color:var(--ink2)}
  @media print{body{background:#fff}.toolbar{display:none}.group-body{max-height:none!important}.group-section.collapsed .group-body{max-height:none!important}.overall-banner,.status-badge,.badge,.score-pill{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>

<header class="page-header">
  <div class="header-top">
    <div class="od-icon">&#9729;</div>
    <div>
      <h1>OneDrive Client Health Check</h1>
      <div class="subtitle">Computer + User configuration policy delivery, prerequisites, runtime state, and known blockers</div>
    </div>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><label>Computer</label><span>$($env:COMPUTERNAME)</span></div>
    <div class="meta-item"><label>User</label><span>$(Format-HtmlEncode $UserContext.RunningAs)</span></div>
    <div class="meta-item"><label>SID</label><span>$(Format-HtmlEncode $UserContext.SID)</span></div>
    $ClientCard
    <div class="meta-item"><label>Run Time</label><span>$RunTime</span></div>
    <div class="meta-item"><label>Expected Tenant ID</label><span>$TenantNote</span></div>
    <div class="meta-item"><label>Script Version</label><span>$SCRIPT_VERSION</span></div>
  </div>
</header>

<div class="overall-banner $OverallClass">
  <span class="big-status">$OverallStatus</span>
  <span class="subtext">$TotalChecks checks &nbsp;&bull;&nbsp; $($Groups.Count) groups</span>
  <div class="score-pills">
    <span class="score-pill pill-pass">&#10003; $PassCount Pass</span>
    <span class="score-pill pill-warn">&#9651; $WarnCount Warning</span>
    <span class="score-pill pill-fail">&#10007; $FailCount Fail</span>
    <span class="score-pill pill-info">&#9432; $InfoCount Info</span>
    <span class="score-pill pill-unknown">? $UnknownCount Unknown</span>
  </div>
</div>

<main class="content">
  <div class="toolbar"><button onclick="expandAll()">Expand All</button><button onclick="collapseAll()">Collapse All</button></div>
  $($GroupHTML -join "`n")
  $SnapshotHTML
</main>

<footer class="page-footer">
  Generated by Invoke-ODClientHealthCheck.ps1 v$SCRIPT_VERSION &nbsp;|&nbsp;
  $RunTime &nbsp;|&nbsp;
  $env:COMPUTERNAME / $env:USERNAME
</footer>

<script>
function toggleSection(h){h.closest('.group-section').classList.toggle('collapsed')}
function collapseAll(){document.querySelectorAll('.group-section').forEach(s=>s.classList.add('collapsed'))}
function expandAll(){document.querySelectorAll('.group-section').forEach(s=>s.classList.remove('collapsed'))}
document.querySelectorAll('.group-section').forEach(s=>{if(!s.querySelector('.status-fail,.status-warn'))s.classList.add('collapsed')})
</script>
</body>
</html>
"@

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }
    $FileName = "ODHealth_$($env:COMPUTERNAME)_$($env:USERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $FilePath = Join-Path $OutputFolder $FileName
    [System.IO.File]::WriteAllText($FilePath, $HTML, [System.Text.Encoding]::UTF8)
    return $FilePath
}
#endregion

# ============================================================================
#region MAIN ORCHESTRATION
# ============================================================================

# Each tuple: function name, group name (used for orchestrator error fallback)
$CheckRegistry = @(
    @{ Fn = 'Invoke-ODCheck_ClientInstalled';        Group = 'Client'             }
    @{ Fn = 'Invoke-ODCheck_ClientProcessRunning';   Group = 'Client'             }
    @{ Fn = 'Invoke-ODCheck_ClientVersion';          Group = 'Client'             }
    @{ Fn = 'Invoke-ODCheck_InstallType';            Group = 'Client'             }

    @{ Fn = 'Invoke-ODCheck_KFMPolicyPresent';          Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_KFMBlockOptIn';             Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_KFMBlockOptOut';            Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_KFMNotificationConfig';     Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_KFMPolicyInteraction';      Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_SilentAccountConfigPolicy'; Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_FilesOnDemandPolicy';       Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_PreventNetworkTraffic';     Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_TenantAllowList';           Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_KFMGPOSource';              Group = 'Policy (Computer)'  }
    @{ Fn = 'Invoke-ODCheck_GPOMachineLastApplied';     Group = 'Policy (Computer)'  }

    @{ Fn = 'Invoke-ODCheck_HKCUPolicyPresent';         Group = 'Policy (User)'      }
    @{ Fn = 'Invoke-ODCheck_HKCUKFMConflict';           Group = 'Policy (User)'      }
    @{ Fn = 'Invoke-ODCheck_GPOUserLastApplied';        Group = 'Policy (User)'      }

    @{ Fn = 'Invoke-ODCheck_WindowsVersion';            Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_DeviceJoinState';           Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_AccountSignedIn';           Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_TenantMatch';               Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_SilentSignInRuntimeStatus'; Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_FolderRedirConflict';       Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_QuotaHeadroom';             Group = 'Prerequisites'      }
    @{ Fn = 'Invoke-ODCheck_LocalDiskHeadroom';         Group = 'Prerequisites'      }

    @{ Fn = 'Invoke-ODCheck_DesktopRedirected';      Group = 'Runtime'            }
    @{ Fn = 'Invoke-ODCheck_DocumentsRedirected';    Group = 'Runtime'            }
    @{ Fn = 'Invoke-ODCheck_PicturesRedirected';     Group = 'Runtime'            }
    @{ Fn = 'Invoke-ODCheck_KFMCompletionFlags';     Group = 'Runtime'            }
    @{ Fn = 'Invoke-ODCheck_SyncDiagKFMState';       Group = 'Runtime'            }

    @{ Fn = 'Invoke-ODCheck_FolderSizes';                Group = 'Blockers'           }
    @{ Fn = 'Invoke-ODCheck_AuthEndpointConnectivity';   Group = 'Blockers'           }
    @{ Fn = 'Invoke-ODCheck_WNSConnectivity';            Group = 'Blockers'           }
)
# Build lookup for orchestrator-level error path (preserves group on throw)
foreach ($Item in $CheckRegistry) { $Script:CheckGroupMap[$Item.Fn] = $Item.Group }

$Results    = [System.Collections.Generic.List[object]]::new()
$ScriptFail = $false

# Pre-initialize so StrictMode is happy if the main try block fails early
$UserContext = $null
$ClientInfo  = $null
$Snapshot    = @()

try {
    $UserContext = Get-UserContext
    $ClientInfo  = Get-OneDriveExecutable

    Write-Host ''
    Write-Host "  OneDrive KFM Health Check v$SCRIPT_VERSION" -ForegroundColor Cyan
    Write-Host "  Machine: $env:COMPUTERNAME  |  User: $($UserContext.RunningAs)" -ForegroundColor DarkGray
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ''

    if ($UserContext.IsElevated) {
        Write-Warning 'Running elevated — HKCU points to the elevating account, not the interactive user. Re-run as a standard user for accurate results.'
    }

    $Total     = $CheckRegistry.Count
    $i         = 0
    $LastGroup = ''

    foreach ($Item in $CheckRegistry) {
        $Fn = $Item.Fn
        $i++
        if ($Item.Group -ne $LastGroup) {
            Write-Host "  ── $($Item.Group) ──" -ForegroundColor DarkCyan
            $LastGroup = $Item.Group
        }
        $ShortName = $Fn -replace '^Invoke-ODCheck_', ''
        Write-Host "    [$i/$Total] $ShortName" -NoNewline -ForegroundColor Gray
        try {
            $FnInfo = Get-Command $Fn
            $Params = @{}
            if ($FnInfo.Parameters.ContainsKey('UserContext')) { $Params['UserContext'] = $UserContext }
            $Result = & $Fn @Params
            if ($Result) {
                $Results.Add($Result)
                $Color = switch ($Result.Status) {
                    'Pass'    { 'Green'   }
                    'Fail'    { 'Red'     }
                    'Warning' { 'Yellow'  }
                    'Info'    { 'Cyan'    }
                    default   { 'DarkGray'}
                }
                Write-Host " → $($Result.Status)" -ForegroundColor $Color
            } else {
                Write-Host ' → (no result)' -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Host ' → ERROR' -ForegroundColor Red
            $Results.Add((New-CheckResult -CheckName $Fn -Group $Script:CheckGroupMap[$Fn] `
                -Status 'Unknown' -Detail "Check threw unhandled exception: $($_.Exception.Message)"))
        }
    }

    # Build Configuration Snapshot: actual values + "Not configured" placeholders
    # for all documented HKLM scalar policies so the report shows a complete picture.
    Write-Host ''
    Write-Host '  ── Configuration Snapshot ──' -ForegroundColor DarkCyan
    $Snapshot = @()
    $Snapshot += Get-AllRegValues -Path $OD_POLICY_HKLM -Scope 'HKLM (Computer Config)'
    $Snapshot += Get-AllRegValues -Path $OD_POLICY_HKCU -Scope 'HKCU (User Config)'

    $ConfiguredHKLM = @($Snapshot | Where-Object { $_.Scope -eq 'HKLM (Computer Config)' } |
                        Select-Object -ExpandProperty Name)
    foreach ($PolicyName in $Script:KnownODHKLMPolicies) {
        if ($PolicyName -notin $ConfiguredHKLM) {
            $Snapshot += [PSCustomObject]@{
                Scope = 'HKLM (Computer Config)'; Path = $OD_POLICY_HKLM
                Name  = $PolicyName; Value = '(Not configured)'; Kind = '-'
            }
        }
    }
    $ConfiguredCount = @($Snapshot | Where-Object { $_.Value -ne '(Not configured)' }).Count
    Write-Host "    Configured values: $ConfiguredCount  |  Known HKLM policies: $($Script:KnownODHKLMPolicies.Count)" -ForegroundColor Gray
}
catch {
    $ScriptFail = $true
    Write-Warning "Script-level exception: $($_.Exception.Message)"
}

try {
    $ReportPath = Export-ODHTMLReport `
        -Results $Results `
        -UserContext $UserContext `
        -ClientInfo $ClientInfo `
        -PolicySnapshot $Snapshot `
        -OutputFolder $OutputPath

    Write-Host ''
    Write-Host '  OneDrive client health check complete.' -ForegroundColor Cyan
    Write-Host "  Report: $ReportPath" -ForegroundColor Green
    Write-Host ''

    if (-not $NoOpen) {
        $IsInteractive = [Environment]::UserInteractive -and
                         ($Host.Name -notlike '*ISE*') -and
                         (-not [System.Console]::IsInputRedirected)
        if ($IsInteractive) { Start-Process $ReportPath }
    }
}
catch {
    Write-Warning "Failed to write HTML report: $($_.Exception.Message)"
    $ScriptFail = $true
}

if ($PassThru) { $Results }

# Exit codes for orchestrators (Intune Proactive Remediation, etc.)
#   0 = clean (Pass + Info, optional Warnings unless -StrictExit)
#   1 = at least one Fail (or Warning when -StrictExit)
#   2 = script-level exception
if ($ScriptFail) { exit 2 }
$HasFail = @($Results | Where-Object { $_.Status -eq 'Fail'    }).Count -gt 0
$HasWarn = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0
if ($HasFail)                  { exit 1 }
if ($HasWarn -and $StrictExit) { exit 1 }
exit 0
#endregion