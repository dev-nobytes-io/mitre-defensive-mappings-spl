# DC0048 Named Pipe Metadata

[ATT&CK](https://attack.mitre.org/datacomponents/DC0048) · version 2.0 · modified 2025-10-21 · ATT&CK release 20.1

Umbrella eventtype `mitre_dc0048_named_pipe_metadata` over 1 feed(s)

> Contextual data about a named pipe on a system, including pipe name and creating process (ex: Sysmon EIDs 17-18)  *Data Collection Measures:*  - Windows:     - Sysmon Event ID 17: Logs the creation of a named pipe.     - Sysmon Event ID 18: Logs connection attempts to a named pipe.     - Windows Security Event ID 5145: Logs access attempts to named pipes via SMB shares.     - ETW (Event Tracing for Windows): Provides deep telemetry into named pipe interactions. - Linux/macOS:     - AuditD (`mkfifo`, `open`, `read`, `write` syscalls): Tracks FIFO (named pipe) creation and usage.     - Lsof (`lsof -p <PID>` or `lsof | grep PIPE`): Lists active named pipes and associated processes.     - Strace (`strace -e open <process>`): Monitors named pipe interactions. - Endpoint Detection & Response (EDR):     - Capture named pipe events as part of process tracking. - Memory Forensics:     - Volatility Plugin (`pipescan`): Enumerates named pipes in system memory.     - Rekall Framework: Identifies active named pipes and associated processes.

## Why this component matters

Cobalt Strike, PsExec and many C2 frameworks use predictable pipe names. Sysmon EID 17/18 is the only practical source.

ATT&CK v20.1 has **4 analytics** across **4 detection strategies** that read this component, covering **4 techniques**. Tactics most dependent on it: execution (2), discovery (1), stealth (1), privilege-escalation (1).

Analytic references by platform: Windows 3, macOS 1

## Where it comes from

```mermaid
flowchart LR
  DC["DC0048 Named Pipe Metadata"]
  DC --> LS0["WinEventLog:Sysmon<br/>4 refs"]
  F_sysmon["Sysmon"]
  LS0 --> F_sysmon
  F_sysmon --> ET_sysmon[/"mitre_dc0048_named_pipe_metadata__sysmon"/]
```

## Requirements

Component specific:

- Sysmon PipeEvent (EID 17/18) must be enabled; it is excluded in some minimal configs.

Per feed (from `config/stack.yml` and `config/log_sources.yml`):

| Feed | Schedule | Sourcetype or source | Constraint | Origin | TA / collector |
|---|---|---|---|---|---|
| `sysmon` | scheduled | source=`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `EventCode IN (17, 18)` | defaults | Splunk Add-on for Sysmon (needs Splunk_TA_windows for XML parsing) |

Collection prerequisites:

- **sysmon**: Sysmon deployed with a maintained modular configuration (e.g. sysmon-modular or SwiftOnSecurity). Event IDs referenced by a data component only exist if the config includes that rule group (ProcessAccess=10, ImageLoad=7, DNS=22, FileDelete=23/26, ClipboardChange=24, ProcessTampering=25, FileBlock=27/28 are off in minimal configs).
- **sysmon**: Hashes configured (SHA256 at least, IMPHASH useful) for File/Process metadata components.

## Splunk

Eventtypes (literal constraints, see `dist/splunk/TA-mitre-attack-datacomponents/default/eventtypes.conf`):

```ini
[mitre_dc0048_named_pipe_metadata__sysmon]
search = index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (17, 18)

[mitre_dc0048_named_pipe_metadata]
search = eventtype=mitre_dc0048_named_pipe_metadata__sysmon
```

Macros for analytics: `` `mitre_dc0048` `` (umbrella), `` `mitre_dc0048_sysmon` ``, `` `mitre_dc0048_filter` `` (site exclusions).
CIM: no data model mapping; analytics on this component run as raw eventtype searches.

## Sigma

Generic logsource categories scoped by this component in `dist/sigma/pipelines/splunk_mitre_dc.yml`: product `windows`: `pipe_created`.

## Dependents

Top techniques detected through this component (of 4):

| Technique | Name | Tactics | Analytics using this DC |
|---|---|---|---|
| [T1055.001](https://attack.mitre.org/techniques/T1055/001) | Dynamic-link Library Injection | stealth, privilege-escalation | 1 |
| [T1135](https://attack.mitre.org/techniques/T1135) | Network Share Discovery | discovery | 1 |
| [T1559](https://attack.mitre.org/techniques/T1559) | Inter-Process Communication | execution | 1 |
| [T1559.003](https://attack.mitre.org/techniques/T1559/003) | XPC Services | execution | 1 |

Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `DC0048`.
