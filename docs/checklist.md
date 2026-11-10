# Log source checklist

This is the checklist behind `config/stack.yml`. Tick `have: true` for what reaches Splunk, fix `index` and `sourcetypes`, rebuild. Nothing here is declared unavailable by the author; the ticks are yours.

| ✓ | Feed | What it is | Platforms | Index | Sourcetype(s) | Components | Analytics | Rendered |
|---|---|---|---|---|---|---|---|---|
| ☑ | `wineventlog` | Windows Event Logs | Windows | `wineventlog` | `XmlWinEventLog:{channel}` | 55 | 332 | yes |
| ☑ | `sysmon` | Sysmon (Microsoft-Windows-Sysmon/Operational) | Windows | `sysmon` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | 26 | 438 | yes |
| ☑ | `powershell_logging` | PowerShell Operational channel (4103/4104) - part of Windows Event Logs, listed separately because it needs its own GPO and input | Windows | `wineventlog` | `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | 4 | 67 | yes |
| ☐ | `windows_firewall_log` | Windows Firewall text log (pfirewall.log) | Windows | `wineventlog` | `WinFirewall` | 1 | 1 | yes |
| ☐ | `windows_perfmon` | Windows Performance counters | Windows | `perfmon` | `Perfmon:*` | 1 | 4 | yes |
| ☐ | `windows_dns_server` | Windows DNS Server analytical / debug log | Windows | `wineventlog` | `MSAD:NT6:DNS` | 2 | 2 | yes |
| ☐ | `windows_dhcp` | Windows DHCP server log | Windows | `wineventlog` | `DhcpSrvLog` | 0 | 1 | yes |
| ☐ | `iis` | IIS access and configuration logs | Windows | `web` | `ms:iis:auto` | 2 | 4 | yes |
| ☐ | `etw` | ETW providers not surfaced by Sysmon (Kernel-Process, Win32k, WinINet, RPC, DotNETRuntime, AMSI, Token...) | Windows | `etw` | `etw:json` | 6 | 28 | yes |
| ☐ | `windows_osquery` | osquery on Windows | Windows | `osquery` | `osquery:results` | 2 | 2 | yes |
| ☐ | `autoruns` | Sysinternals Autoruns scans | Windows | `wineventlog` | `autoruns` | 1 | 1 | yes |
| ☑ | `trellix_epo` | Trellix ePO events (ENS threat/AMSI/adaptive threat protection, ePO audit) | Windows, Linux | `epo` | `mcafee:epo` | 7 | 5 | yes |
| ☑ | `solidcore` | Trellix Application and Change Control (Solidcore) via ePO | Windows, Linux | `epo` | `mcafee:epo` | 10 | 4 | yes |
| ☐ | `edr_telemetry` | EDR raw telemetry (memory, hunting, script block, syscall) - e.g. Trellix EDR, Defender for Endpoint advanced hunting | Windows, Linux | `edr` | `edr:telemetry` | 8 | 14 | yes |
| ☑ | `corelight` | Corelight / Zeek network logs | Windows, Linux, macOS, ESXi, Network Devices, Containers | `corelight` | `corelight_{log}` | 15 | 284 | yes |
| ☑ | `palo_alto` | Palo Alto Networks PAN-OS (traffic, threat, URL, system, config, GlobalProtect) | Network Devices, Windows, Linux, ESXi, Containers | `pan_logs` | `pan:{log}` | 24 | 322 | yes |
| ☑ | `wireshark` | Wireshark / tshark packet captures (ad hoc) | Windows, Linux, Network Devices | `pcap` | `wireshark:json` | 2 | 3 | yes |
| ☐ | `netdev_syslog` | Router / switch / non-PAN firewall syslog, config change and AAA logs | Network Devices | `netops` | `cisco:ios`, `cisco:asa`, `syslog` | 6 | 72 | yes |
| ☐ | `snmp` | SNMP traps / polling | Network Devices | `netops` | `sc4snmp:event` | 1 | 10 | yes |
| ☐ | `netflow` | NetFlow / IPFIX (non-Zeek flow) | Network Devices, Linux, Containers | `netflow` | `stream:netflow` | 2 | 4 | yes |
| ☐ | `auditd` | Linux auditd (SYSCALL/EXECVE/PATH/CONFIG_CHANGE/USER_LOGIN...) | Linux, Containers | `linux` | `linux:audit` | 33 | 373 | yes |
| ☐ | `linux_syslog` | Linux syslog / journald (messages, secure/auth, cron, kernel, daemon) | Linux, Containers | `linux` | `linux_messages_syslog`, `linux_secure`, `syslog` | 16 | 109 | yes |
| ☐ | `linux_osquery` | osquery on Linux | Linux, Containers | `osquery` | `osquery:results` | 7 | 53 | yes |
| ☐ | `sysmon_linux` | Sysmon for Linux | Linux | `linux` | `sysmon:linux` | 5 | 11 | yes |
| ☐ | `iptables` | iptables / nftables LOG target via kernel syslog | Linux | `linux` | `syslog` | 1 | 4 | yes |
| ☐ | `ebpf` | eBPF runtime security (Falco, Tetragon, Tracee) | Linux, Containers | `linux` | `falco` | 8 | 9 | yes |
| ☐ | `azure_entra` | Microsoft Entra ID sign-in and audit logs | Identity Provider, IaaS, Office Suite, Windows | `azure` | `azure:aad:signin`, `azure:aad:audit` | 14 | 45 | yes |
| ☐ | `azure_activity` | Azure Activity Log (subscription control plane) and Azure Policy | IaaS | `azure` | `mscs:azure:audit` | 13 | 12 | yes |
| ☐ | `azure_resource` | Azure resource diagnostic logs (NSG flow, VM guest, Key Vault, Storage) | IaaS | `azure` | `mscs:azure:eventhub` | 1 | 2 | yes |
| ☐ | `m365_defender` | Microsoft Defender XDR / Defender for Identity alerts and Graph API logs | Windows, Identity Provider, Office Suite | `azure` | `ms:m365:defender:incident:alerts` | 0 | 4 | yes |
| ☐ | `kubernetes_audit` | Kubernetes API server audit log and cluster events | Containers | `k8s` | `kube:apiserver-audit`, `kube:objects:events` | 18 | 22 | yes |
| ☐ | `container_runtime` | Docker / containerd daemon and runtime events | Containers | `k8s` | `docker:events`, `docker:daemon`, `containerd:events` | 10 | 27 | yes |
| ☐ | `esxi_syslog` | ESXi host logs via remote syslog (hostd, vmkernel, shell, vobd, vpxa, auth, esxupdate) | ESXi | `vmware` | `vmware:esxlog:{log}` | 27 | 107 | yes |
| ☐ | `vcenter` | vCenter vpxd logs and events | ESXi | `vmware` | `vmware:vclog:vpxd` | 3 | 11 | yes |
| ☐ | `macos` | macOS unified log / Endpoint Security / osquery / FSEvents | macOS | `macos` | `macos:unifiedlog` | 37 | 354 | no |
| ☐ | `m365_unified` | Microsoft 365 unified audit log (Exchange, SharePoint, Teams, Purview) | Office Suite, SaaS, Identity Provider, Windows | `o365` | `o365:management:activity` | 28 | 103 | no |
| ☐ | `aws` | AWS CloudTrail / VPC Flow / CloudWatch / Bedrock | IaaS, SaaS, Containers | `aws` | `aws:cloudtrail`, `aws:cloudwatchlogs:vpcflow`, `aws:cloudwatchlogs` | 48 | 98 | no |
| ☐ | `gcp` | Google Cloud audit / VPC flow / Workspace admin | IaaS, SaaS, Identity Provider | `gcp` | `google:gcp:pubsub:message` | 21 | 18 | no |
| ☐ | `okta` | Okta System Log | Identity Provider, SaaS | `okta` | `OktaIM2:log` | 0 | 0 | no |
| ☐ | `saas` | SaaS application audit logs (GitHub, Slack, Salesforce, Zoom, Box, Confluence, Google Workspace...) | SaaS | `saas` | `saas:audit` | 20 | 57 | no |
| ☐ | `mobile` | Mobile EDR / MDM telemetry | — | `mobile` | `mobile:telemetry` | 17 | 0 | no |
| ☐ | `ot` | OT / ICS application and protocol logs | — | `ot` | `ot:applog` | 4 | 0 | no |
| ☐ | `threat_intel` | External reconnaissance sources (internet scan data, domain registration, malware repositories, persona monitoring) | PRE | `threatintel` | `ti:feed` | 9 | 39 | no |

## What each untapped feed would add

- **`windows_firewall_log`** — Host-level connection allow/drop for Network Connection Creation when Sysmon 3 is not deployed.
- **`windows_perfmon`** — Host Status (resource exhaustion, CPU/disk spikes) analytics - 4 references.
- **`windows_dns_server`** — Server-side DNS query logging; Sysmon EventCode 22 covers client-side queries and is preferred where deployed.
- **`windows_dhcp`** — Rogue DHCP / lease analytics (1 reference).
- **`iis`** — Web shell and IIS module persistence analytics (3 references).
- **`etw`** — OS API Execution, Process Modification and token-manipulation analytics that Sysmon cannot see (about 40 references). Most are also partially covered by Sysmon 10/8/25.
- **`windows_osquery`** — Scheduled snapshot queries for metadata components (services, drivers, autoruns).
- **`autoruns`** — Autostart persistence metadata comparisons (1 reference).
- **`edr_telemetry`** — EDR:memory, EDR:hunting, EDR:file, EDR:cli, EDR:scriptblock, M365Defender:DeviceNetworkEvents references (about 20).
- **`netdev_syslog`** — Network Devices platform components (Command Execution, File Modification on device, Logon Session, Firmware Modification) for non-Palo Alto gear - about 90 references.
- **`snmp`** — Firmware, device status and access analytics (about 8 references).
- **`netflow`** — Flow coverage where Corelight sensors are absent (cloud VPC flow, branch sites).
- **`auditd`** — The single largest Linux feed in ATT&CK v20 - 469 SYSCALL plus 46 EXECVE plus PATH/FILE/CONFIG_CHANGE references; Process Creation, Command Execution, File *, Network Connection Creation for Linux.
- **`linux_syslog`** — Application Log Content, Logon Session Creation (sshd/sudo), Service Creation (systemd), Scheduled Job Creation (cron) for Linux - about 100 references.
- **`linux_osquery`** — Metadata components (processes, listening ports, kernel modules, crontab, users) on a schedule - 48 references.
- **`sysmon_linux`** — Sysmon-style process/network/file telemetry on Linux (18 references).
- **`iptables`** — Host firewall allow/drop on Linux (about 6 references).
- **`ebpf`** — Syscall and tracepoint components inside containers (about 10 references).
- **`azure_entra`** — User Account Authentication, Logon Session Creation/Metadata, Active Directory Object Modification (cloud), Cloud Service Modification - about 110 references.
- **`azure_activity`** — Instance/Snapshot/Volume/Cloud Service components for Azure IaaS - about 35 references.
- **`azure_resource`** — azure:vpcflow, azure:vmguest, azure:resource references (3).
- **`m365_defender`** — m365:defender, Defender for Identity, Microsoft Graph API Logs references (about 12).
- **`kubernetes_audit`** — Container Creation/Start, Pod Creation/Enumeration, User Account Authentication (k8s), Cloud Service Enumeration - about 30 references.
- **`container_runtime`** — Container Creation/Start/Enumeration, Image Creation, Process Creation inside containers - about 40 references.
- **`esxi_syslog`** — The whole ESXi platform (107 analytics): Command Execution (shell.log), File *, Process Creation, Logon Session Creation, Service Modification on hypervisors.
- **`vcenter`** — esxi:vpxd references (about 14) - VM lifecycle, permission changes, host add/remove.
- **`macos`** — macOS platform (353 analytics). Out of scope for rendering in this release.
- **`m365_unified`** — Office Suite platform (57 analytics) plus mailbox/dirsync references used by a few Windows analytics.
- **`aws`** — AWS IaaS analytics (about 150 references). Not in scope this release.
- **`gcp`** — GCP references (about 50). Not in scope this release.
- **`okta`** — Non-Azure identity provider analytics (about 45 references).
- **`saas`** — SaaS platform (68 analytics). Not in scope this release.
- **`mobile`** — Mobile-domain log sources that leak into shared data components. Not applicable to Enterprise rendering.
- **`ot`** — ICS-domain log sources on shared data components. Not applicable to Enterprise rendering.
- **`threat_intel`** — PRE platform (97 analytics) - these are intelligence, not telemetry.
