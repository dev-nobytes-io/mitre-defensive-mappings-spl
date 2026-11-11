# Analytics (ATT&CK v20.1)

18 of 1773 ATT&CK analytics are implemented as ES detections and Sigma rules; 511 are coverable by the feeds ticked in `config/stack.yml`. The rest are in the [backlog](backlog.md), ranked by technique prevalence.

```mermaid
pie showData
    title Implemented analytics by content type
    "TTP (finding + risk)" : 12
    "Anomaly (risk only)" : 6
    "Hunting (no action)" : 0
```

```mermaid
xychart-beta
    title "Implemented analytics by tactic"
    x-axis ["execution", "persistence", "privilege-escalation", "defense-impairment", "credential-access", "stealth", "command-and-control", "impact"]
    y-axis "analytics"
    bar [5, 5, 4, 3, 2, 2, 1, 1]
```

| Analytic | Detection | Type | Severity | Technique | Tactics | Data components | Feeds |
|---|---|---|---|---|---|---|---|
| AN0165 | [LOLBin or script process connected externally and dropped a file](AN0165-lolbin-or-script-process-connected-externally-and-dropped-a-.md) | anomaly | medium | T1105 Ingress Tool Transfer | command-and-control | DC0082, DC0039 | sysmon |
| AN0767 | [Built-in utility used to decode or reassemble a payload](AN0767-built-in-utility-used-to-decode-or-reassemble-a-payload.md) | ttp | medium | T1140 Deobfuscate/Decode Files or Information | stealth | DC0032 | sysmon, wineventlog |
| AN1252 | [PowerShell started with encoded, download or in-memory execution arguments](AN1252-powershell-started-with-encoded-download-or-in-memory-execut.md) | anomaly | medium | T1059.001 PowerShell | execution | DC0032 | sysmon, wineventlog |
| AN1032 | [Run key value pointing to a script or user-writable path](AN1032-run-key-value-pointing-to-a-script-or-user-writable-path.md) | anomaly | medium | T1547.001 Registry Run Keys / Startup Folder | persistence, privilege-escalation | DC0063 | sysmon |
| AN0819 | [Document or mail application spawned an interpreter or LOLBin](AN0819-document-or-mail-application-spawned-an-interpreter-or-lolbi.md) | ttp | high | T1204.002 Malicious File | execution | DC0032 | sysmon, wineventlog |
| AN1221 | [Scheduled task registered with an interpreter or user-writable action](AN1221-scheduled-task-registered-with-an-interpreter-or-user-writab.md) | anomaly | medium | T1053.005 Scheduled Task | execution, persistence, privilege-escalation | DC0001 | wineventlog |
| AN0781 | [Security-relevant registry value modified](AN0781-security-relevant-registry-value-modified.md) | ttp | medium | T1112 Modify Registry | defense-impairment, persistence | DC0063 | sysmon |
| AN0209 | [Script host chain from Office or into a second-stage interpreter](AN0209-script-host-chain-from-office-or-into-a-second-stage-interpr.md) | anomaly | medium | T1059.005 Visual Basic | execution | DC0032 | sysmon, wineventlog |
| AN1369 | [Security tooling disabled or tampered with](AN1369-security-tooling-disabled-or-tampered-with.md) | ttp | high | T1685 Disable or Modify Tools | defense-impairment | DC0063, DC0032 | sysmon |
| AN1527 | [Service installed with an interpreter or user-writable binary path](AN1527-service-installed-with-an-interpreter-or-user-writable-binar.md) | ttp | medium | T1543.003 Windows Service | persistence, privilege-escalation | DC0060 | wineventlog |
| AN1308 | [Rundll32 executing script, remote or user-writable payloads](AN1308-rundll32-executing-script-remote-or-user-writable-payloads.md) | ttp | medium | T1218.011 Rundll32 | stealth | DC0032 | sysmon, wineventlog |
| AN1030 | [LSASS memory access by an unexpected process](AN1030-lsass-memory-access-by-an-unexpected-process.md) | ttp | high | T1003.001 LSASS Memory | credential-access | DC0035 | sysmon |
| AN1108 | [Web server process spawned a shell or script interpreter](AN1108-web-server-process-spawned-a-shell-or-script-interpreter.md) | ttp | high | T1505.003 Web Shell | persistence | DC0032 | sysmon, wineventlog |
| AN1185 | [Service control manager started an unexpected binary](AN1185-service-control-manager-started-an-unexpected-binary.md) | anomaly | medium | T1569.002 Service Execution | execution | DC0032 | sysmon, wineventlog |
| AN1094 | [UAC bypass through auto-elevated binary hijack](AN1094-uac-bypass-through-auto-elevated-binary-hijack.md) | ttp | high | T1548.002 Bypass User Account Control | privilege-escalation | DC0063, DC0032 | sysmon |
| AN0933 | [Shadow copies, backups or boot recovery disabled with native utilities](AN0933-shadow-copies-backups-or-boot-recovery-disabled-with-native-.md) | ttp | high | T1490 Inhibit System Recovery | impact | DC0032 | sysmon, wineventlog |
| AN0235 | [SAM, SYSTEM or SECURITY hive dumped from the command line](AN0235-sam-system-or-security-hive-dumped-from-the-command-line.md) | ttp | high | T1003.002 Security Account Manager | credential-access | DC0032 | sysmon, wineventlog |
| AN1472 | [Windows event log cleared](AN1472-windows-event-log-cleared.md) | ttp | high | T1685.005 Clear Windows Event Logs | defense-impairment | DC0038, DC0032 | wineventlog, sysmon |

## Authoring

```bash
python -m mitremap new-analytic AN0123   # scaffold content/analytics/AN0123.yml with ATT&CK text and suggestions
# edit the curated block: status, title, content_type, spl, risk, tuning, sigma
make build && make test
```

Rules enforced by `mitremap validate`: the SPL uses a `mitre_dcXXXX` macro and the analytic's own `mitre_anXXXX_filter`, has no literal `index=`, references only macros and lookups that exist, and every risk field and message token appears in the search. Tests convert every Sigma rule through the data-component pipeline.
