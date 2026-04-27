# Technical Specification — Invoke-ODClientHealthCheck.ps1

**Version:** 4.0.0  
**Requires:** PowerShell 5.1 · Windows 10 build 16299+ · No external modules  
**Run context:** Signed-in interactive user (not SYSTEM, not elevated)  
**License:** MIT

---

## Purpose

`Invoke-ODClientHealthCheck.ps1` is a self-contained diagnostic script that evaluates the readiness and runtime state of the OneDrive sync client for **Known Folder Move (KFM)** deployments. It reads registry, WMI, and the OneDrive diagnostic log to produce a self-contained HTML report and an optional pipeline-friendly results object.

It is intentionally **read-only and non-remediating** — it surfaces problems; it does not fix them.

---

## Architecture

### Execution model

```
param block
  └─ constants / module-level state
       └─ helper functions
            └─ check functions (Invoke-ODCheck_*)
                 └─ orchestrator loop  →  HTML report + PassThru
```

All check functions return a `PSCustomObject` via `New-CheckResult`. The orchestrator collects results into a generic `List[object]`, then passes the list to `Export-ODHTMLReport`. No global state is mutated after the orchestrator starts.

### Module-level cache

| Variable | Purpose |
|---|---|
| `$Script:SyncDiagLines` | Lazily loaded SyncDiagnostics.log content (read once) |
| `$Script:CheckGroupMap` | `function-name → group-name` for orchestrator error fallback |

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ExpectedTenantId` | `string` | `''` | Azure AD tenant GUID. Used by tenant-match, KFM policy, tenant allow/block list, and device join checks. Omit to skip tenant validation — those checks return `Unknown`. |
| `OutputPath` | `string` | `$PSScriptRoot` | Folder for the HTML report. Override to a non-KFM-managed path (e.g. `$env:ProgramData\ODHealthCheck`) when running as a scheduled task or Intune remediation. |
| `WarnHours` | `int` | `24` | Group Policy refresh age (hours) that triggers a `Warning`. |
| `FailHours` | `int` | `48` | Group Policy refresh age (hours) that triggers a `Fail`. |
| `WarnQuotaGB` | `double` | `5` | OneDrive cloud quota free-space (GB) at which a `Warning` is issued. |
| `FailQuotaGB` | `double` | `1` | OneDrive cloud quota free-space (GB) at which a `Fail` is issued. |
| `WarnLocalDiskGB` | `double` | `10` | Local drive free space (GB) that triggers a `Warning`. |
| `FailLocalDiskGB` | `double` | `2` | Local drive free space (GB) that triggers a `Fail`. |
| `LargeFolderThresholdGB` | `int` | `50` | Per-folder size (GB) that triggers a large-folder `Warning`. |
| `MinClientVersion` | `string` | `'26.055.0323.0004'` | Minimum acceptable OneDrive client version. Parsed as a dotted-quad `[version]`; unparseable values emit `Info` and skip comparison. Update to match your approved floor. |
| `StrictExit` | `switch` | off | Promotes `Warning` conditions to exit code `1`. Use for Intune Proactive Remediation detection scripts. |
| `NoOpen` | `switch` | off | Suppress automatic launch of the HTML report after the run. |
| `PassThru` | `switch` | off | Emit the full `List[object]` results collection to the pipeline (in addition to writing the HTML report). |

---

## Check Catalog

### Group: Client (4 checks)

| Check | Pass condition | Fail/Warn condition |
|---|---|---|
| `ClientInstalled` | OneDrive.exe found at a standard install path | Not found at per-user or per-machine paths |
| `ClientProcessRunning` | `OneDrive.exe` is running | Process not running |
| `ClientVersion` | Installed version ≥ `MinClientVersion` | Older than minimum → `Warning` |
| `InstallType` | Per-machine installation | Per-user installation → `Warning` |

### Group: Policy (Computer) — HKLM (11 checks)

| Check | Notes |
|---|---|
| `KFMPolicyPresent` | Validates that at least one KFM enable policy exists (`KFMSilentOptIn`, `KFMOptInWithWizard`, or per-folder `KFMSilentOptIn*`). Checks tenant GUID match when `ExpectedTenantId` is supplied. |
| `KFMBlockOptIn` | Detects value `2` (active KFM reversal, overrides everything) vs. value `1` (wizard-only block, does NOT suppress `KFMSilentOptIn`). |
| `KFMBlockOptOut` | Warns when absent — users can reverse KFM from the tray icon. |
| `KFMNotificationConfig` | Reports `KFMSilentOptInWithNotification` state (`Info` only). |
| `KFMPolicyInteraction` | **Cross-reference check.** Evaluates the effective KFM mode by examining all KFM-related policy values together and flagging conflicts that per-value checks cannot catch. |
| `SilentAccountConfigPolicy` | Validates `SilentAccountConfig=1`. Prerequisite for silent sign-in and therefore for `KFMSilentOptIn` to complete without user interaction. |
| `FilesOnDemandPolicy` | Warns when `FilesOnDemandEnabled=0` — forced full download during KFM migration. |
| `PreventNetworkTrafficPreSignIn` | Warns when `PreventNetworkTrafficPreUserSignIn=1` — delays KFM on first logon. |
| `TenantAllowList` | Validates `AllowTenantList` and `BlockTenantList` subkeys against `ExpectedTenantId`. |
| `KFMGPOSource` | Enumerates applied machine GPOs from the GP State registry; distinguishes GP vs. Intune/MDM delivery. |
| `GPOMachineLastApplied` | Checks machine GP refresh age against `WarnHours`/`FailHours`. MDM-enrolled devices emit `Info` (timestamps not written via MDM CSP). |

### Group: Policy (User) — HKCU (3 checks)

| Check | Notes |
|---|---|
| `HKCUPolicyPresent` | Inventories any values under `HKCU\SOFTWARE\Policies\Microsoft\OneDrive`. |
| `HKCUKFMConflict` | Warns if KFM policy values are found under HKCU — they are ignored at runtime (KFM is HKLM-only). |
| `GPOUserLastApplied` | Checks user GP refresh age using SID-scoped GP State entry. MDM-enrolled devices emit `Info`. |

### Group: Prerequisites (8 checks)

| Check | Notes |
|---|---|
| `WindowsVersion` | Fails below build 16299. Warns on Windows 10. Passes on Windows 11 (build 22000+). |
| `DeviceJoinState` | Reads `dsregcmd /status`. Hybrid AAD and AAD-joined devices can use `SilentAccountConfig`; domain-only joined devices cannot. |
| `AccountSignedIn` | Validates `HKCU\SOFTWARE\Microsoft\OneDrive\Accounts\Business1` key and `UserEmail` value. |
| `TenantMatch` | Reads `ConfiguredTenantId` (falls back to `ServiceEndpointUri` regex) and compares to `ExpectedTenantId`. |
| `SilentSignInRuntimeStatus` | Registry-primary: checks `SilentBusinessConfigCompleted=1`. Supplementary: PRT validity from `dsregcmd`, error codes from SyncDiagnostics.log. |
| `FolderRedirConflict` | Detects traditional GPO-based UNC folder redirection (`\\server\...`) that blocks KFM for the affected folder. |
| `QuotaHeadroom` | Reads `QuotaAvailable`/`QuotaTotal` from the Business1 account key. |
| `LocalDiskHeadroom` | Checks free space on the drive hosting the OneDrive folder using `System.IO.DriveInfo`. |

### Group: Runtime (5 checks)

| Check | Notes |
|---|---|
| `DesktopRedirected` | Reads `HKCU\...\User Shell Folders\Desktop` — Pass if path contains `OneDrive`. |
| `DocumentsRedirected` | Reads `Personal` value — Pass if path contains `OneDrive`. |
| `PicturesRedirected` | Reads `My Pictures` value — Pass if path contains `OneDrive`. |
| `KFMCompletionFlags` | Cross-references shell folder paths with OneDrive's own KFM completion subkey (`HKCU\...\Accounts\Business1\KFM`). Detects partial migration, manual moves, and active reversal. |
| `SyncDiagKFMState` | Scans `SyncDiagnostics.log` (single-pass, cached). Reports KFM entries, completion indicators, and error codes (`0x...`). Conflict lines are surfaced as `Fail`. |

### Group: Blockers (3 checks)

| Check | Notes |
|---|---|
| `FolderSizes` | Walks Desktop, Documents, Pictures (via shell folder paths) and warns if any exceed `LargeFolderThresholdGB`. |
| `AuthEndpointConnectivity` | DNS + TCP 443 probe to `login.microsoftonline.com`. Notes SSL inspection risk. |
| `WNSConnectivity` | DNS + TCP 443 probe to `skydrive.wns.windows.com` (OneDrive WNS push channel). |

**Total: 34 checks across 6 groups.**

---

## Result Object Schema

Each check produces a `PSCustomObject` with these properties:

| Property | Type | Description |
|---|---|---|
| `CheckName` | string | Short check identifier (e.g. `KFMSilentOptIn`) |
| `Group` | string | Section name (e.g. `Policy (Computer)`) |
| `Status` | string | `Pass` · `Fail` · `Warning` · `Info` · `Unknown` |
| `Detail` | string | Human-readable explanation and remediation guidance |
| `RawValue` | string | Raw registry value, path, or diagnostic string |
| `ComputerName` | string | `$env:COMPUTERNAME` at run time |
| `UserName` | string | `$env:USERNAME` at run time |
| `Timestamp` | string | ISO 8601 run timestamp |
| `ScriptVer` | string | Script version string |

---

## Output

### HTML Report

A self-contained single-file HTML report is written to `OutputPath`. The filename encodes the machine name, username, and timestamp:

```
ODHealth_<COMPUTERNAME>_<USERNAME>_<yyyyMMdd_HHmmss>.html
```

**Report features:**
- Overall status banner (`PASS` / `WARNING` / `FAIL`)
- Score pills (pass / warning / fail / info / unknown counts)
- Collapsible group sections; sections with no issues auto-collapse on load
- Configuration Snapshot table — all documented HKLM policies, with `(Not configured)` placeholders for absent values and policy description tooltips
- Print-safe CSS (`@media print`)
- No external dependencies (no CDN, no web fonts — fully air-gap safe)

### Pipeline output (`-PassThru`)

When `-PassThru` is specified, the `List[object]` is emitted to the pipeline after the report is written:

```powershell
$r = .\Invoke-ODClientHealthCheck.ps1 -ExpectedTenantId '...' -NoOpen -PassThru
$r | Export-Csv '\\server\share\ODHealth.csv' -Append -NoTypeInformation
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks Pass or Info (Warnings included unless `-StrictExit`) |
| `1` | At least one `Fail` — or at least one `Warning` when `-StrictExit` is set |
| `2` | Script-level unhandled exception (report may be incomplete) |

---

## Integration Patterns

### Intune Proactive Remediation (detection script)

```powershell
.\Invoke-ODClientHealthCheck.ps1 `
    -ExpectedTenantId '<your-tenant-guid>' `
    -OutputPath "$env:ProgramData\ODHealthCheck" `
    -NoOpen `
    -StrictExit
```

Exit 0 = healthy (no remediation triggered). Exit 1 = issues detected (remediation script runs). Exit 2 = diagnostic failure.

### Remote on-demand via `Invoke-AsCurrentUser`

Deploy via a third-party tool (e.g. `Invoke-AsCurrentUser` from the PowerShell Gallery) to run in the signed-in user's session from a SYSTEM-context management agent:

```powershell
Invoke-AsCurrentUser -ScriptBlock {
    & 'C:\Windows\Temp\Invoke-ODClientHealthCheck.ps1' `
        -ExpectedTenantId '<guid>' `
        -OutputPath "$env:ProgramData\ODHealthCheck" `
        -NoOpen
}
```

### Scheduled task projection

Set `OutputPath` to a non-OneDrive path (`$env:ProgramData\ODHealthCheck`) so the report does not land inside a KFM-managed folder, which would cause a sync loop on machines where KFM is already active.

### Fleet aggregation

```powershell
$r = .\Invoke-ODClientHealthCheck.ps1 -NoOpen -PassThru
$r | Export-Csv '\\fileserver\logs\ODHealth.csv' -Append -NoTypeInformation
```

Each row in the CSV is one check result, with `ComputerName`, `UserName`, and `Timestamp` for fleet correlation.

---

## Key Registry Paths

| Constant | Path |
|---|---|
| `OD_POLICY_HKLM` | `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive` |
| `OD_POLICY_HKCU` | `HKCU:\SOFTWARE\Policies\Microsoft\OneDrive` |
| `OD_ACCOUNT_HKCU` | `HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1` |
| `OD_KFM_HKCU` | `HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\KFM` |
| `SHELL_FOLDERS_HKCU` | `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` |
| `GP_STATE_MACHINE` | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\...` |
| `SYNCDIAG_PATH` | `%LOCALAPPDATA%\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log` |

---

## Known Limitations

| Limitation | Detail |
|---|---|
| HKCU accuracy when elevated | Running as administrator maps HKCU to the elevating account. The script emits a warning but cannot correct for this. Re-run as a standard user. |
| SYSTEM context | Not supported. The script is designed for the signed-in interactive user context. Use `Invoke-AsCurrentUser` or a scheduled task for remote execution. |
| Multi-account OneDrive | Only the `Business1` account key is inspected. Devices with both a personal and a work account, or multiple work accounts, will only have the primary enterprise account evaluated. |
| `SyncDiagnostics.log` format | Log format varies across OneDrive client versions. The script uses multi-version pattern matching but log-based results are supplementary — registry and shell folder checks are authoritative. |
| SSL inspection | `AuthEndpointConnectivity` tests TCP reachability only. SSL/TLS certificate interception by a proxy is not detectable via a raw socket test and must be verified separately. |
| Connectivity timeouts | WNS endpoint: 3 s timeout. Auth endpoint: 4 s timeout. On high-latency or VPN-connected machines these may produce false `Fail` results. |

---

## Version History

| Version | Change |
|---|---|
| 4.0.0 | Public release. Renamed `_RedirectCheckResult` → `Get-ODShellFolderCheckResult`. Removed dead `ConflictWarning` stub. Updated `MinClientVersion` default to `26.055.0323.0004`. Added `.NOTES` / `.LINK` to comment-based help. |
| 3.0.0 | Added `KFMPolicyInteraction` cross-reference check, `SilentSignInRuntimeStatus` registry-primary approach, `KFMGPOSource` GPO enumeration, Configuration Snapshot with placeholder rows, BOM-aware `StreamReader` for log reads, `Get-LogMatchMap` single-pass scan. |
