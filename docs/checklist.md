# Log source checklist

Every feed the mappings know about. Check off what reaches your Splunk, then set `index` and `sourcetypes` for those feeds in `config/stack.yml` (or override eventtypes in the app's `local/`). The boxes are for you; the repository does not record what any site has.

GitHub shows checkboxes in repository files read-only. To tick them, paste this list into an issue or pull request in your own fork, or open the file in an editor that supports task lists. The [index by log source](by-log-source.md) lists the data components and analytics each feed supports.

## Windows endpoint

- [ ] **Windows Event Logs** (`wineventlog`) · index `wineventlog`, source `XmlWinEventLog:{channel}` · 55 data components, 332 ATT&CK analytics
  - Authentication, account management, privilege use, service install, scheduled tasks, PowerShell, AppLocker/CodeIntegrity, Defender, firewall and Windows-native object access telemetry.
- [ ] **Sysmon (Microsoft-Windows-Sysmon/Operational)** (`sysmon`) · index `sysmon`, source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` · 26 data components, 438 ATT&CK analytics
  - Process, image load, driver load, registry, file, named pipe, WMI, DNS and network-connection telemetry at process granularity; the single highest-yield Windows feed in ATT&CK v20 (861 analytic references).
- [ ] **PowerShell Operational channel (4103/4104) - part of Windows Event Logs, listed separately because it needs its own GPO and input** (`powershell_logging`) · index `wineventlog`, source `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` · 3 data components, 67 ATT&CK analytics
  - Script Execution and Command Execution components for Windows (65 analytics).
- [ ] **Windows Firewall text log (pfirewall.log)** (`windows_firewall_log`) · index `wineventlog`, sourcetype `WinFirewall` · 1 data components, 1 ATT&CK analytics
  - Host-level connection allow/drop for Network Connection Creation when Sysmon 3 is not deployed.
- [ ] **Windows Performance counters** (`windows_perfmon`) · index `perfmon`, sourcetype `Perfmon:*` · 1 data components, 4 ATT&CK analytics
  - Host Status (resource exhaustion, CPU/disk spikes) analytics - 4 references.
- [ ] **Windows DNS Server analytical / debug log** (`windows_dns_server`) · index `wineventlog`, sourcetype `MSAD:NT6:DNS` · 2 data components, 2 ATT&CK analytics
  - Server-side DNS query logging; Sysmon EventCode 22 covers client-side queries and is preferred where deployed.
- [ ] **Windows DHCP server log** (`windows_dhcp`) · index `wineventlog`, sourcetype `DhcpSrvLog` · 0 data components, 1 ATT&CK analytics
  - Rogue DHCP / lease analytics (1 reference).
- [ ] **IIS access and configuration logs** (`iis`) · index `web`, sourcetype `ms:iis:auto` · 2 data components, 4 ATT&CK analytics
  - Web shell and IIS module persistence analytics (3 references).
- [ ] **ETW providers not surfaced by Sysmon (Kernel-Process, Win32k, WinINet, RPC, DotNETRuntime, AMSI, Token...)** (`etw`) · index `etw`, sourcetype `etw:json` · 6 data components, 28 ATT&CK analytics
  - OS API Execution, Process Modification and token-manipulation analytics that Sysmon cannot see (about 40 references). Most are also partially covered by Sysmon 10/8/25.
- [ ] **osquery on Windows** (`windows_osquery`) · index `osquery`, sourcetype `osquery:results` · 2 data components, 2 ATT&CK analytics
  - Scheduled snapshot queries for metadata components (services, drivers, autoruns).
- [ ] **Sysinternals Autoruns scans** (`autoruns`) · index `wineventlog`, sourcetype `autoruns` · 1 data components, 1 ATT&CK analytics
  - Autostart persistence metadata comparisons (1 reference).

## Endpoint security

- [ ] **Trellix ePO events (ENS threat/AMSI/adaptive threat protection, ePO audit)** (`trellix_epo`) · index `epo`, sourcetype `mcafee:epo:syslog` · 7 data components, 5 ATT&CK analytics
  - Host Status (AV disabled/tamper), Malware Metadata, Application Log Content, and partial EDR:detection/EDR:AMSI references.
- [ ] **Trellix Application and Change Control (Solidcore) via ePO** (`solidcore`) · index `epo`, sourcetype `mcafee:epo:syslog` · 10 data components, 4 ATT&CK analytics
  - File Creation/Modification/Deletion, Windows Registry Key Creation/Modification, Module Load and Process Creation (denied executions) as an integrity-monitoring second source.
- [ ] **EDR raw telemetry (memory, hunting, script block, syscall) - e.g. Trellix EDR, Defender for Endpoint advanced hunting** (`edr_telemetry`) · index `edr`, sourcetype `edr:telemetry` · 8 data components, 14 ATT&CK analytics
  - EDR:memory, EDR:hunting, EDR:file, EDR:cli, EDR:scriptblock, M365Defender:DeviceNetworkEvents references (about 20).

## Network

- [ ] **Corelight / Zeek network logs** (`corelight`) · index `corelight`, sourcetype `corelight_{log}` · 15 data components, 284 ATT&CK analytics
  - Network Traffic Flow, Network Connection Creation, Network Traffic Content, Network Share Access, Active Directory credential/object telemetry over the wire (about 500 references across platforms).
- [ ] **Palo Alto Networks PAN-OS (traffic, threat, URL, system, config, GlobalProtect)** (`palo_alto`) · index `pan_logs`, sourcetype `pan:{log}` · 24 data components, 322 ATT&CK analytics
  - Firewall Rule Modification, Firewall Disable, Firewall Metadata/Enumeration, perimeter Network Traffic Flow/Content, web proxy style URL telemetry, VPN authentication (GlobalProtect), and the firewall's own config/CLI/auth audit trail for the Network Devices platform.
- [ ] **Wireshark / tshark packet captures (ad hoc)** (`wireshark`) · index `pcap`, sourcetype `wireshark:json` · 2 data components, 3 ATT&CK analytics
  - Network Traffic Content deep inspection for hunts and incident scoping. Not a scheduled detection source; eventtypes are generated disabled.
- [ ] **Router / switch / non-PAN firewall syslog, config change and AAA logs** (`netdev_syslog`) · index `netops`, sourcetype `cisco:ios`, `cisco:asa`, `syslog` · 6 data components, 72 ATT&CK analytics
  - Network Devices platform components (Command Execution, File Modification on device, Logon Session, Firmware Modification) for non-Palo Alto gear - about 90 references.
- [ ] **SNMP traps / polling** (`snmp`) · index `netops`, sourcetype `sc4snmp:event` · 1 data components, 10 ATT&CK analytics
  - Firmware, device status and access analytics (about 8 references).
- [ ] **NetFlow / IPFIX (non-Zeek flow)** (`netflow`) · index `netflow`, sourcetype `stream:netflow` · 2 data components, 4 ATT&CK analytics
  - Flow coverage where Corelight sensors are absent (cloud VPC flow, branch sites).

## Linux

- [ ] **Linux auditd (SYSCALL/EXECVE/PATH/CONFIG_CHANGE/USER_LOGIN...)** (`auditd`) · index `linux`, sourcetype `linux:audit` · 33 data components, 373 ATT&CK analytics
  - The single largest Linux feed in ATT&CK v20 - 469 SYSCALL plus 46 EXECVE plus PATH/FILE/CONFIG_CHANGE references; Process Creation, Command Execution, File *, Network Connection Creation for Linux.
- [ ] **Linux syslog / journald (messages, secure/auth, cron, kernel, daemon)** (`linux_syslog`) · index `linux`, sourcetype `linux_messages_syslog`, `linux_secure`, `syslog` · 16 data components, 109 ATT&CK analytics
  - Application Log Content, Logon Session Creation (sshd/sudo), Service Creation (systemd), Scheduled Job Creation (cron) for Linux - about 100 references.
- [ ] **osquery on Linux** (`linux_osquery`) · index `osquery`, sourcetype `osquery:results` · 7 data components, 53 ATT&CK analytics
  - Metadata components (processes, listening ports, kernel modules, crontab, users) on a schedule - 48 references.
- [ ] **Sysmon for Linux** (`sysmon_linux`) · index `linux`, sourcetype `sysmon:linux` · 5 data components, 11 ATT&CK analytics
  - Sysmon-style process/network/file telemetry on Linux (18 references).
- [ ] **iptables / nftables LOG target via kernel syslog** (`iptables`) · index `linux`, sourcetype `syslog` · 1 data components, 4 ATT&CK analytics
  - Host firewall allow/drop on Linux (about 6 references).
- [ ] **eBPF runtime security (Falco, Tetragon, Tracee)** (`ebpf`) · index `linux`, sourcetype `falco` · 8 data components, 9 ATT&CK analytics
  - Syscall and tracepoint components inside containers (about 10 references).

## Azure and identity

- [ ] **Microsoft Entra ID sign-in and audit logs** (`azure_entra`) · index `azure`, sourcetype `azure:aad:signin`, `azure:aad:audit` · 14 data components, 45 ATT&CK analytics
  - User Account Authentication, Logon Session Creation/Metadata, Active Directory Object Modification (cloud), Cloud Service Modification - about 110 references.
- [ ] **Azure Activity Log (subscription control plane) and Azure Policy** (`azure_activity`) · index `azure`, sourcetype `mscs:azure:audit` · 13 data components, 12 ATT&CK analytics
  - Instance/Snapshot/Volume/Cloud Service components for Azure IaaS - about 35 references.
- [ ] **Azure resource diagnostic logs (NSG flow, VM guest, Key Vault, Storage)** (`azure_resource`) · index `azure`, sourcetype `mscs:azure:eventhub` · 1 data components, 2 ATT&CK analytics
  - azure:vpcflow, azure:vmguest, azure:resource references (3).
- [ ] **Microsoft Defender XDR / Defender for Identity alerts and Graph API logs** (`m365_defender`) · index `azure`, sourcetype `ms:m365:defender:incident:alerts` · 0 data components, 4 ATT&CK analytics
  - m365:defender, Defender for Identity, Microsoft Graph API Logs references (about 12).

## Containers

- [ ] **Kubernetes API server audit log and cluster events** (`kubernetes_audit`) · index `k8s`, sourcetype `kube:apiserver-audit`, `kube:objects:events` · 18 data components, 22 ATT&CK analytics
  - Container Creation/Start, Pod Creation/Enumeration, User Account Authentication (k8s), Cloud Service Enumeration - about 30 references.
- [ ] **Docker / containerd daemon and runtime events** (`container_runtime`) · index `k8s`, sourcetype `docker:events`, `docker:daemon`, `containerd:events` · 10 data components, 27 ATT&CK analytics
  - Container Creation/Start/Enumeration, Image Creation, Process Creation inside containers - about 40 references.

## VMware ESXi

- [ ] **ESXi host logs via remote syslog (hostd, vmkernel, shell, vobd, vpxa, auth, esxupdate)** (`esxi_syslog`) · index `vmware`, sourcetype `vmware:esxlog:{log}` · 27 data components, 107 ATT&CK analytics
  - The whole ESXi platform (107 analytics): Command Execution (shell.log), File *, Process Creation, Logon Session Creation, Service Modification on hypervisors.
- [ ] **vCenter vpxd logs and events** (`vcenter`) · index `vmware`, sourcetype `vmware:vclog:vpxd` · 3 data components, 11 ATT&CK analytics
  - esxi:vpxd references (about 14) - VM lifecycle, permission changes, host add/remove.

## Not yet in scope

- [ ] **macOS unified log / Endpoint Security / osquery / FSEvents** (`macos`) · index `macos`, sourcetype `macos:unifiedlog` · 37 data components, 354 ATT&CK analytics (not rendered yet)
  - macOS platform (353 analytics). Out of scope for rendering in this release.
- [ ] **Microsoft 365 unified audit log (Exchange, SharePoint, Teams, Purview)** (`m365_unified`) · index `o365`, sourcetype `o365:management:activity` · 28 data components, 103 ATT&CK analytics (not rendered yet)
  - Office Suite platform (57 analytics) plus mailbox/dirsync references used by a few Windows analytics.
- [ ] **AWS CloudTrail / VPC Flow / CloudWatch / Bedrock** (`aws`) · index `aws`, sourcetype `aws:cloudtrail`, `aws:cloudwatchlogs:vpcflow`, `aws:cloudwatchlogs` · 48 data components, 98 ATT&CK analytics (not rendered yet)
  - AWS IaaS analytics (about 150 references). Not in scope this release.
- [ ] **Google Cloud audit / VPC flow / Workspace admin** (`gcp`) · index `gcp`, sourcetype `google:gcp:pubsub:message` · 21 data components, 18 ATT&CK analytics (not rendered yet)
  - GCP references (about 50). Not in scope this release.
- [ ] **Okta System Log** (`okta`) · index `okta`, sourcetype `OktaIM2:log` · 0 data components, 0 ATT&CK analytics (not rendered yet)
  - Non-Azure identity provider analytics (about 45 references).
- [ ] **SaaS application audit logs (GitHub, Slack, Salesforce, Zoom, Box, Confluence, Google Workspace...)** (`saas`) · index `saas`, sourcetype `saas:audit` · 20 data components, 57 ATT&CK analytics (not rendered yet)
  - SaaS platform (68 analytics). Not in scope this release.
- [ ] **Mobile EDR / MDM telemetry** (`mobile`) · index `mobile`, sourcetype `mobile:telemetry` · 17 data components, 0 ATT&CK analytics (not rendered yet)
  - Mobile-domain log sources that leak into shared data components. Not applicable to Enterprise rendering.
- [ ] **OT / ICS application and protocol logs** (`ot`) · index `ot`, sourcetype `ot:applog` · 4 data components, 0 ATT&CK analytics (not rendered yet)
  - ICS-domain log sources on shared data components. Not applicable to Enterprise rendering.
- [ ] **External reconnaissance sources (internet scan data, domain registration, malware repositories, persona monitoring)** (`threat_intel`) · index `threatintel`, sourcetype `ti:feed` · 9 data components, 39 ATT&CK analytics (not rendered yet)
  - PRE platform (97 analytics) - these are intelligence, not telemetry.
