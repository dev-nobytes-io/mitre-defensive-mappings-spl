# Content by log source (ATT&CK v20.1)

For each feed in `config/stack.yml`: the data components it provides, and the implemented analytics and strategy sequences that read it. Tick the feeds you have in `config/stack.yml` and rebuild; this page and the table in the README follow.

An analytic lists every feed its search reads. Searches over a CIM data model (most Windows process analytics) work with either Sysmon or Security 4688; raw searches that join two feeds need both.

| Category | Feeds |
|---|---|
| Windows endpoint | [☑ `wineventlog`](#wineventlog), [☑ `sysmon`](#sysmon), [☑ `powershell_logging`](#powershell_logging), [☐ `windows_firewall_log`](#windows_firewall_log), [☐ `windows_perfmon`](#windows_perfmon), [☐ `windows_dns_server`](#windows_dns_server), [☐ `windows_dhcp`](#windows_dhcp), [☐ `iis`](#iis), [☐ `etw`](#etw), [☐ `windows_osquery`](#windows_osquery), [☐ `autoruns`](#autoruns) |
| Endpoint security | [☑ `trellix_epo`](#trellix_epo), [☑ `solidcore`](#solidcore), [☐ `edr_telemetry`](#edr_telemetry) |
| Network | [☑ `corelight`](#corelight), [☑ `palo_alto`](#palo_alto), [☑ `wireshark`](#wireshark), [☐ `netdev_syslog`](#netdev_syslog), [☐ `snmp`](#snmp), [☐ `netflow`](#netflow) |
| Linux | [☐ `auditd`](#auditd), [☐ `linux_syslog`](#linux_syslog), [☐ `linux_osquery`](#linux_osquery), [☐ `sysmon_linux`](#sysmon_linux), [☐ `iptables`](#iptables), [☐ `ebpf`](#ebpf) |
| Azure and identity | [☐ `azure_entra`](#azure_entra), [☐ `azure_activity`](#azure_activity), [☐ `azure_resource`](#azure_resource), [☐ `m365_defender`](#m365_defender) |
| Containers | [☐ `kubernetes_audit`](#kubernetes_audit), [☐ `container_runtime`](#container_runtime) |
| VMware ESXi | [☐ `esxi_syslog`](#esxi_syslog), [☐ `vcenter`](#vcenter) |
| Not yet in scope | [☐ `macos`](#macos), [☐ `m365_unified`](#m365_unified), [☐ `aws`](#aws), [☐ `gcp`](#gcp), [☐ `okta`](#okta), [☐ `saas`](#saas), [☐ `mobile`](#mobile), [☐ `ot`](#ot), [☐ `threat_intel`](#threat_intel) |

## Windows endpoint

### wineventlog

☑ ticked · Windows Event Logs · index `wineventlog`

**Data components (55):** [DC0001 Scheduled Job Creation](data-components/DC0001-scheduled-job-creation.md), [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0003 Malware Metadata](data-components/DC0003-malware-metadata.md), [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md), [DC0005 Scheduled Job Metadata](data-components/DC0005-scheduled-job-metadata.md), [DC0006 Web Credential Creation](data-components/DC0006-web-credential-creation.md), [DC0008 WMI Creation](data-components/DC0008-wmi-creation.md), [DC0009 User Account Deletion](data-components/DC0009-user-account-deletion.md), [DC0010 User Account Modification](data-components/DC0010-user-account-modification.md), [DC0012 Scheduled Job Modification](data-components/DC0012-scheduled-job-modification.md), [DC0013 User Account Metadata](data-components/DC0013-user-account-metadata.md), [DC0014 User Account Creation](data-components/DC0014-user-account-creation.md), [DC0016 Module Load](data-components/DC0016-module-load.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0021 OS API Execution](data-components/DC0021-os-api-execution.md), [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md), [DC0035 Process Access](data-components/DC0035-process-access.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0039 File Creation](data-components/DC0039-file-creation.md), [DC0040 File Deletion](data-components/DC0040-file-deletion.md), [DC0041 Service Metadata](data-components/DC0041-service-metadata.md), [DC0042 Drive Creation](data-components/DC0042-drive-creation.md), [DC0043 Firewall Disable](data-components/DC0043-firewall-disable.md), [DC0044 Firewall Enumeration](data-components/DC0044-firewall-enumeration.md), [DC0045 Windows Registry Key Deletion](data-components/DC0045-windows-registry-key-deletion.md), [DC0046 Drive Modification](data-components/DC0046-drive-modification.md), [DC0050 Windows Registry Key Access](data-components/DC0050-windows-registry-key-access.md), [DC0051 Firewall Rule Modification](data-components/DC0051-firewall-rule-modification.md), [DC0053 Firewall Metadata](data-components/DC0053-firewall-metadata.md), [DC0055 File Access](data-components/DC0055-file-access.md), [DC0056 Windows Registry Key Creation](data-components/DC0056-windows-registry-key-creation.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0060 Service Creation](data-components/DC0060-service-creation.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0063 Windows Registry Key Modification](data-components/DC0063-windows-registry-key-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0065 Service Modification](data-components/DC0065-service-modification.md), [DC0066 Active Directory Object Modification](data-components/DC0066-active-directory-object-modification.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0068 Active Directory Object Deletion](data-components/DC0068-active-directory-object-deletion.md), [DC0071 Active Directory Object Access](data-components/DC0071-active-directory-object-access.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0079 Driver Load](data-components/DC0079-driver-load.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0084 Active Directory Credential Request](data-components/DC0084-active-directory-credential-request.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0087 Active Directory Object Creation](data-components/DC0087-active-directory-object-creation.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md), [DC0094 Group Modification](data-components/DC0094-group-modification.md), [DC0097 Volume Creation](data-components/DC0097-volume-creation.md), [DC0099 Group Enumeration](data-components/DC0099-group-enumeration.md), [DC0102 Network Share Access](data-components/DC0102-network-share-access.md), [DC0105 Group Metadata](data-components/DC0105-group-metadata.md).

**Analytics (47):**

| Analytic | Type | Technique | Other feeds it reads |
|---|---|---|---|
| [AN0048 Security software enumeration](analytics/AN0048-security-software-enumeration.md) | anomaly | T1518.001 Security Software Discovery | `sysmon` |
| [AN0061 Burst of service stop or disable commands](analytics/AN0061-burst-of-service-stop-or-disable-commands.md) | anomaly | T1489 Service Stop | `sysmon` |
| [AN0095 Process discovery commands](analytics/AN0095-process-discovery-commands.md) | hunting | T1057 Process Discovery | `sysmon` |
| [AN0105 Browser credential store read by a non-browser process](analytics/AN0105-browser-credential-store-read-by-a-non-browser-process.md) | ttp | T1555.003 Credentials from Web Browsers | none |
| [AN0209 Script host chain from Office or into a second-stage interpreter](analytics/AN0209-script-host-chain-from-office-or-into-a-second-stage-interpr.md) | anomaly | T1059.005 Visual Basic | `sysmon` |
| [AN0235 SAM, SYSTEM or SECURITY hive dumped from the command line](analytics/AN0235-sam-system-or-security-hive-dumped-from-the-command-line.md) | ttp | T1003.002 Security Account Manager | `sysmon` |
| [AN0254 User and session discovery commands](analytics/AN0254-user-and-session-discovery-commands.md) | hunting | T1033 System Owner/User Discovery | `sysmon` |
| [AN0324 Service or task named like system software but running an untrusted binary](analytics/AN0324-service-or-task-named-like-system-software-but-running-an-un.md) | anomaly | T1036.004 Masquerade Task or Service | none |
| [AN0360 Interpreter started with a hidden window](analytics/AN0360-interpreter-started-with-a-hidden-window.md) | anomaly | T1564.003 Hidden Window | `sysmon` |
| [AN0478 Burst of virtual-machine and sandbox detection checks](analytics/AN0478-burst-of-virtual-machine-and-sandbox-detection-checks.md) | anomaly | T1497.001 System Checks | `sysmon` |
| [AN0531 Bulk copy of user documents into a staging location](analytics/AN0531-bulk-copy-of-user-documents-into-a-staging-location.md) | anomaly | T1119 Automated Collection | `sysmon` |
| [AN0536 Local drive and volume enumeration commands](analytics/AN0536-local-drive-and-volume-enumeration-commands.md) | hunting | T1680 Local Storage Discovery | `sysmon` |
| [AN0559 Network configuration discovery commands](analytics/AN0559-network-configuration-discovery-commands.md) | hunting | T1016 System Network Configuration Discovery | `sysmon` |
| [AN0578 cmd.exe started by an unusual parent or running a batch file from a staging path](analytics/AN0578-cmd-exe-started-by-an-unusual-parent-or-running-a-batch-file.md) | anomaly | T1059.003 Windows Command Shell | `sysmon` |
| [AN0589 Registry queries for environment, software and security configuration](analytics/AN0589-registry-queries-for-environment-software-and-security-confi.md) | hunting | T1012 Query Registry | `sysmon` |
| [AN0590 One domain account logging on to many hosts in an hour](analytics/AN0590-one-domain-account-logging-on-to-many-hosts-in-an-hour.md) | anomaly | T1078.002 Domain Accounts | none |
| [AN0767 Built-in utility used to decode or reassemble a payload](analytics/AN0767-built-in-utility-used-to-decode-or-reassemble-a-payload.md) | ttp | T1140 Deobfuscate/Decode Files or Information | `sysmon` |
| [AN0819 Document or mail application spawned an interpreter or LOLBin](analytics/AN0819-document-or-mail-application-spawned-an-interpreter-or-lolbi.md) | ttp | T1204.002 Malicious File | `sysmon` |
| [AN0831 Archive created with a password, split volumes or a built-in packer](analytics/AN0831-archive-created-with-a-password-split-volumes-or-a-built-in-.md) | anomaly | T1560.001 Archive via Utility | `sysmon` |
| [AN0846 Local account and group enumeration commands](analytics/AN0846-local-account-and-group-enumeration-commands.md) | hunting | T1087.001 Local Account | `sysmon` |
| [AN0903 Network connection and session discovery commands](analytics/AN0903-network-connection-and-session-discovery-commands.md) | hunting | T1049 System Network Connections Discovery | `sysmon` |
| [AN0931 First-seen RDP logon for a user, source and destination](analytics/AN0931-first-seen-rdp-logon-for-a-user-source-and-destination.md) | anomaly | T1021.001 Remote Desktop Protocol | none |
| [AN0933 Shadow copies, backups or boot recovery disabled with native utilities](analytics/AN0933-shadow-copies-backups-or-boot-recovery-disabled-with-native-.md) | ttp | T1490 Inhibit System Recovery | `sysmon` |
| [AN0983 Windows system process name running from an unexpected directory](analytics/AN0983-windows-system-process-name-running-from-an-unexpected-direc.md) | ttp | T1036.005 Match Legitimate Resource Name or Location | `sysmon` |
| [AN1031 WMI used to create processes locally or on remote hosts](analytics/AN1031-wmi-used-to-create-processes-locally-or-on-remote-hosts.md) | anomaly | T1047 Windows Management Instrumentation | `sysmon` |
| [AN1040 Recursive file and directory enumeration commands](analytics/AN1040-recursive-file-and-directory-enumeration-commands.md) | hunting | T1083 File and Directory Discovery | `sysmon` |
| [AN1070 Search for credential files or sensitive document types](analytics/AN1070-search-for-credential-files-or-sensitive-document-types.md) | anomaly | T1005 Data from Local System | `sysmon` |
| [AN1100 Installed software enumeration](analytics/AN1100-installed-software-enumeration.md) | hunting | T1518 Software Discovery | `sysmon` |
| [AN1108 Web server process spawned a shell or script interpreter](analytics/AN1108-web-server-process-spawned-a-shell-or-script-interpreter.md) | ttp | T1505.003 Web Shell | `sysmon` |
| [AN1185 Service control manager started an unexpected binary](analytics/AN1185-service-control-manager-started-an-unexpected-binary.md) | anomaly | T1569.002 Service Execution | `sysmon` |
| [AN1221 Scheduled task registered with an interpreter or user-writable action](analytics/AN1221-scheduled-task-registered-with-an-interpreter-or-user-writab.md) | anomaly | T1053.005 Scheduled Task | none |
| [AN1235 Local account created on a host that is not a domain controller](analytics/AN1235-local-account-created-on-a-host-that-is-not-a-domain-control.md) | anomaly | T1136.001 Local Account | `sysmon` |
| [AN1252 PowerShell started with encoded, download or in-memory execution arguments](analytics/AN1252-powershell-started-with-encoded-download-or-in-memory-execut.md) | anomaly | T1059.001 PowerShell | `sysmon` |
| [AN1275 Many logon failures followed by a success for the same account and source](analytics/AN1275-many-logon-failures-followed-by-a-success-for-the-same-accou.md) | ttp | T1110 Brute Force | none |
| [AN1308 Rundll32 executing script, remote or user-writable payloads](analytics/AN1308-rundll32-executing-script-remote-or-user-writable-payloads.md) | ttp | T1218.011 Rundll32 | `sysmon` |
| [AN1325 Service enumeration commands](analytics/AN1325-service-enumeration-commands.md) | hunting | T1007 System Service Discovery | `sysmon` |
| [AN1353 Peripheral and USB device enumeration](analytics/AN1353-peripheral-and-usb-device-enumeration.md) | hunting | T1120 Peripheral Device Discovery | `sysmon` |
| [AN1394 Command line with obfuscation markers](analytics/AN1394-command-line-with-obfuscation-markers.md) | anomaly | T1027.010 Command Obfuscation | `sysmon` |
| [AN1428 Command interpreter used by a person outside working hours](analytics/AN1428-command-interpreter-used-by-a-person-outside-working-hours.md) | anomaly | T1059 Command and Scripting Interpreter | `sysmon` |
| [AN1452 System information discovery commands](analytics/AN1452-system-information-discovery-commands.md) | hunting | T1082 System Information Discovery | `sysmon` |
| [AN1468 Shell or LOLBin executed inside a network logon session](analytics/AN1468-shell-or-lolbin-executed-inside-a-network-logon-session.md) | anomaly | T1021.002 SMB/Windows Admin Shares | `sysmon` |
| [AN1472 Windows event log cleared](analytics/AN1472-windows-event-log-cleared.md) | ttp | T1685.005 Clear Windows Event Logs | `sysmon` |
| [AN1483 Port forwarding or tunnelling tool started](analytics/AN1483-port-forwarding-or-tunnelling-tool-started.md) | ttp | T1572 Protocol Tunneling | `sysmon` |
| [AN1527 Service installed with an interpreter or user-writable binary path](analytics/AN1527-service-installed-with-an-interpreter-or-user-writable-binar.md) | ttp | T1543.003 Windows Service | none |
| [AN1543 Interactive or remote logon by a service account](analytics/AN1543-interactive-or-remote-logon-by-a-service-account.md) | anomaly | T1078 Valid Accounts | none |
| [AN1583 Burst of remote system discovery commands](analytics/AN1583-burst-of-remote-system-discovery-commands.md) | anomaly | T1018 Remote System Discovery | `sysmon` |
| [AN1611 NTDS.dit extracted with ntdsutil, shadow copies or esentutl](analytics/AN1611-ntds-dit-extracted-with-ntdsutil-shadow-copies-or-esentutl.md) | ttp | T1003.003 NTDS | `sysmon` |

**Strategy sequences (2):** [DET0085 SYSTEM hive saved together with SAM or SECURITY](strategies/DET0085-system-hive-saved-together-with-sam-or-security.md), [DET0441 Suspicious scheduled task created and then run by Task Scheduler](strategies/DET0441-suspicious-scheduled-task-created-and-then-run-by-task-sched.md).

### sysmon

☑ ticked · Sysmon (Microsoft-Windows-Sysmon/Operational) · index `sysmon`

**Data components (26):** [DC0008 WMI Creation](data-components/DC0008-wmi-creation.md), [DC0016 Module Load](data-components/DC0016-module-load.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0020 Process Modification](data-components/DC0020-process-modification.md), [DC0021 OS API Execution](data-components/DC0021-os-api-execution.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0033 Process Termination](data-components/DC0033-process-termination.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md), [DC0035 Process Access](data-components/DC0035-process-access.md), [DC0039 File Creation](data-components/DC0039-file-creation.md), [DC0040 File Deletion](data-components/DC0040-file-deletion.md), [DC0041 Service Metadata](data-components/DC0041-service-metadata.md), [DC0045 Windows Registry Key Deletion](data-components/DC0045-windows-registry-key-deletion.md), [DC0046 Drive Modification](data-components/DC0046-drive-modification.md), [DC0048 Named Pipe Metadata](data-components/DC0048-named-pipe-metadata.md), [DC0054 Drive Access](data-components/DC0054-drive-access.md), [DC0056 Windows Registry Key Creation](data-components/DC0056-windows-registry-key-creation.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0063 Windows Registry Key Modification](data-components/DC0063-windows-registry-key-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0079 Driver Load](data-components/DC0079-driver-load.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0101 Domain Registration](data-components/DC0101-domain-registration.md).

**Analytics (66):**

| Analytic | Type | Technique | Other feeds it reads |
|---|---|---|---|
| [AN0048 Security software enumeration](analytics/AN0048-security-software-enumeration.md) | anomaly | T1518.001 Security Software Discovery | `wineventlog` |
| [AN0061 Burst of service stop or disable commands](analytics/AN0061-burst-of-service-stop-or-disable-commands.md) | anomaly | T1489 Service Stop | `wineventlog` |
| [AN0095 Process discovery commands](analytics/AN0095-process-discovery-commands.md) | hunting | T1057 Process Discovery | `wineventlog` |
| [AN0165 LOLBin or script process connected externally and dropped a file](analytics/AN0165-lolbin-or-script-process-connected-externally-and-dropped-a-.md) | anomaly | T1105 Ingress Tool Transfer | none |
| [AN0178 High-risk file type downloaded by a browser or mail client](analytics/AN0178-high-risk-file-type-downloaded-by-a-browser-or-mail-client.md) | anomaly | T1204.001 Malicious Link | none |
| [AN0209 Script host chain from Office or into a second-stage interpreter](analytics/AN0209-script-host-chain-from-office-or-into-a-second-stage-interpr.md) | anomaly | T1059.005 Visual Basic | `wineventlog` |
| [AN0235 SAM, SYSTEM or SECURITY hive dumped from the command line](analytics/AN0235-sam-system-or-security-hive-dumped-from-the-command-line.md) | ttp | T1003.002 Security Account Manager | `wineventlog` |
| [AN0237 Binary written by a decoding utility, then executed or loaded](analytics/AN0237-binary-written-by-a-decoding-utility-then-executed-or-loaded.md) | ttp | T1027.013 Encrypted/Encoded File | none |
| [AN0254 User and session discovery commands](analytics/AN0254-user-and-session-discovery-commands.md) | hunting | T1033 System Owner/User Discovery | `wineventlog` |
| [AN0355 Renamed system utility (file name does not match PE original name)](analytics/AN0355-renamed-system-utility-file-name-does-not-match-pe-original-.md) | ttp | T1036 Masquerading | none |
| [AN0360 Interpreter started with a hidden window](analytics/AN0360-interpreter-started-with-a-hidden-window.md) | anomaly | T1564.003 Hidden Window | `wineventlog` |
| [AN0363 Domain account enumeration from a non-domain-controller](analytics/AN0363-domain-account-enumeration-from-a-non-domain-controller.md) | anomaly | T1087.002 Domain Account | `powershell_logging` |
| [AN0392 Secure deletion, self-deletion or interpreter removing executables](analytics/AN0392-secure-deletion-self-deletion-or-interpreter-removing-execut.md) | anomaly | T1070.004 File Deletion | none |
| [AN0406 Windows Firewall disabled or its service stopped](analytics/AN0406-windows-firewall-disabled-or-its-service-stopped.md) | ttp | T1686 Disable or Modify System Firewall | none |
| [AN0478 Burst of virtual-machine and sandbox detection checks](analytics/AN0478-burst-of-virtual-machine-and-sandbox-detection-checks.md) | anomaly | T1497.001 System Checks | `wineventlog` |
| [AN0516 File written over SMB, then executed on the target](analytics/AN0516-file-written-over-smb-then-executed-on-the-target.md) | ttp | T1570 Lateral Tool Transfer | none |
| [AN0531 Bulk copy of user documents into a staging location](analytics/AN0531-bulk-copy-of-user-documents-into-a-staging-location.md) | anomaly | T1119 Automated Collection | `wineventlog` |
| [AN0536 Local drive and volume enumeration commands](analytics/AN0536-local-drive-and-volume-enumeration-commands.md) | hunting | T1680 Local Storage Discovery | `wineventlog` |
| [AN0559 Network configuration discovery commands](analytics/AN0559-network-configuration-discovery-commands.md) | hunting | T1016 System Network Configuration Discovery | `wineventlog` |
| [AN0577 Unsigned DLL loaded from a user-writable path by a trusted or relocated program](analytics/AN0577-unsigned-dll-loaded-from-a-user-writable-path-by-a-trusted-o.md) | anomaly | T1574.001 DLL | none |
| [AN0578 cmd.exe started by an unusual parent or running a batch file from a staging path](analytics/AN0578-cmd-exe-started-by-an-unusual-parent-or-running-a-batch-file.md) | anomaly | T1059.003 Windows Command Shell | `wineventlog` |
| [AN0589 Registry queries for environment, software and security configuration](analytics/AN0589-registry-queries-for-environment-software-and-security-confi.md) | hunting | T1012 Query Registry | `wineventlog` |
| [AN0602 Ransom-note style file dropped across many directories](analytics/AN0602-ransom-note-style-file-dropped-across-many-directories.md) | ttp | T1486 Data Encrypted for Impact | none |
| [AN0633 Office, script or proxy-execution process connecting out on a non-standard port](analytics/AN0633-office-script-or-proxy-execution-process-connecting-out-on-a.md) | anomaly | T1571 Non-Standard Port | none |
| [AN0643 Module with an expired, revoked or untrusted signature loaded](analytics/AN0643-module-with-an-expired-revoked-or-untrusted-signature-loaded.md) | anomaly | T1553.002 Code Signing | none |
| [AN0724 Many files written into a staging directory by one process](analytics/AN0724-many-files-written-into-a-staging-directory-by-one-process.md) | anomaly | T1074.001 Local Data Staging | none |
| [AN0767 Built-in utility used to decode or reassemble a payload](analytics/AN0767-built-in-utility-used-to-decode-or-reassemble-a-payload.md) | ttp | T1140 Deobfuscate/Decode Files or Information | `wineventlog` |
| [AN0781 Security-relevant registry value modified](analytics/AN0781-security-relevant-registry-value-modified.md) | ttp | T1112 Modify Registry | none |
| [AN0797 Client application crashed, then spawned a shell or LOLBin](analytics/AN0797-client-application-crashed-then-spawned-a-shell-or-lolbin.md) | ttp | T1203 Exploitation for Client Execution | none |
| [AN0819 Document or mail application spawned an interpreter or LOLBin](analytics/AN0819-document-or-mail-application-spawned-an-interpreter-or-lolbi.md) | ttp | T1204.002 Malicious File | `wineventlog` |
| [AN0831 Archive created with a password, split volumes or a built-in packer](analytics/AN0831-archive-created-with-a-password-split-volumes-or-a-built-in-.md) | anomaly | T1560.001 Archive via Utility | `wineventlog` |
| [AN0846 Local account and group enumeration commands](analytics/AN0846-local-account-and-group-enumeration-commands.md) | hunting | T1087.001 Local Account | `wineventlog` |
| [AN0903 Network connection and session discovery commands](analytics/AN0903-network-connection-and-session-discovery-commands.md) | hunting | T1049 System Network Connections Discovery | `wineventlog` |
| [AN0933 Shadow copies, backups or boot recovery disabled with native utilities](analytics/AN0933-shadow-copies-backups-or-boot-recovery-disabled-with-native-.md) | ttp | T1490 Inhibit System Recovery | `wineventlog` |
| [AN0980 Screenshot captured from a script or command-line tool](analytics/AN0980-screenshot-captured-from-a-script-or-command-line-tool.md) | anomaly | T1113 Screen Capture | none |
| [AN0983 Windows system process name running from an unexpected directory](analytics/AN0983-windows-system-process-name-running-from-an-unexpected-direc.md) | ttp | T1036.005 Match Legitimate Resource Name or Location | `wineventlog` |
| [AN1030 LSASS memory access by an unexpected process](analytics/AN1030-lsass-memory-access-by-an-unexpected-process.md) | ttp | T1003.001 LSASS Memory | none |
| [AN1031 WMI used to create processes locally or on remote hosts](analytics/AN1031-wmi-used-to-create-processes-locally-or-on-remote-hosts.md) | anomaly | T1047 Windows Management Instrumentation | `wineventlog` |
| [AN1032 Run key value pointing to a script or user-writable path](analytics/AN1032-run-key-value-pointing-to-a-script-or-user-writable-path.md) | anomaly | T1547.001 Registry Run Keys / Startup Folder | none |
| [AN1040 Recursive file and directory enumeration commands](analytics/AN1040-recursive-file-and-directory-enumeration-commands.md) | hunting | T1083 File and Directory Discovery | `wineventlog` |
| [AN1057 Process connecting to many hosts or ports in one minute](analytics/AN1057-process-connecting-to-many-hosts-or-ports-in-one-minute.md) | anomaly | T1046 Network Service Discovery | none |
| [AN1064 Script host or LOLBin writing an archive or encoded file to a staging path](analytics/AN1064-script-host-or-lolbin-writing-an-archive-or-encoded-file-to-.md) | anomaly | T1027 Obfuscated Files or Information | none |
| [AN1070 Search for credential files or sensitive document types](analytics/AN1070-search-for-credential-files-or-sensitive-document-types.md) | anomaly | T1005 Data from Local System | `wineventlog` |
| [AN1094 UAC bypass through auto-elevated binary hijack](analytics/AN1094-uac-bypass-through-auto-elevated-binary-hijack.md) | ttp | T1548.002 Bypass User Account Control | none |
| [AN1095 Process handle opened for injection from unbacked memory](analytics/AN1095-process-handle-opened-for-injection-from-unbacked-memory.md) | anomaly | T1055.001 Dynamic-link Library Injection | none |
| [AN1100 Installed software enumeration](analytics/AN1100-installed-software-enumeration.md) | hunting | T1518 Software Discovery | `wineventlog` |
| [AN1108 Web server process spawned a shell or script interpreter](analytics/AN1108-web-server-process-spawned-a-shell-or-script-interpreter.md) | ttp | T1505.003 Web Shell | `wineventlog` |
| [AN1121 DNS tunnelling pattern from a non-browser process](analytics/AN1121-dns-tunnelling-pattern-from-a-non-browser-process.md) | anomaly | T1071.004 DNS | none |
| [AN1185 Service control manager started an unexpected binary](analytics/AN1185-service-control-manager-started-an-unexpected-binary.md) | anomaly | T1569.002 Service Execution | `wineventlog` |
| [AN1229 Script host or LOLBin accepting inbound network connections](analytics/AN1229-script-host-or-lolbin-accepting-inbound-network-connections.md) | anomaly | T1090 Proxy | none |
| [AN1235 Local account created on a host that is not a domain controller](analytics/AN1235-local-account-created-on-a-host-that-is-not-a-domain-control.md) | anomaly | T1136.001 Local Account | `wineventlog` |
| [AN1252 PowerShell started with encoded, download or in-memory execution arguments](analytics/AN1252-powershell-started-with-encoded-download-or-in-memory-execut.md) | anomaly | T1059.001 PowerShell | `wineventlog` |
| [AN1254 UDP to the internet from a script host or LOLBin](analytics/AN1254-udp-to-the-internet-from-a-script-host-or-lolbin.md) | anomaly | T1095 Non-Application Layer Protocol | none |
| [AN1308 Rundll32 executing script, remote or user-writable payloads](analytics/AN1308-rundll32-executing-script-remote-or-user-writable-payloads.md) | ttp | T1218.011 Rundll32 | `wineventlog` |
| [AN1325 Service enumeration commands](analytics/AN1325-service-enumeration-commands.md) | hunting | T1007 System Service Discovery | `wineventlog` |
| [AN1353 Peripheral and USB device enumeration](analytics/AN1353-peripheral-and-usb-device-enumeration.md) | hunting | T1120 Peripheral Device Discovery | `wineventlog` |
| [AN1369 Security tooling disabled or tampered with](analytics/AN1369-security-tooling-disabled-or-tampered-with.md) | ttp | T1685 Disable or Modify Tools | none |
| [AN1394 Command line with obfuscation markers](analytics/AN1394-command-line-with-obfuscation-markers.md) | anomaly | T1027.010 Command Obfuscation | `wineventlog` |
| [AN1399 Remote thread created in a high-value process](analytics/AN1399-remote-thread-created-in-a-high-value-process.md) | anomaly | T1055 Process Injection | none |
| [AN1428 Command interpreter used by a person outside working hours](analytics/AN1428-command-interpreter-used-by-a-person-outside-working-hours.md) | anomaly | T1059 Command and Scripting Interpreter | `wineventlog` |
| [AN1452 System information discovery commands](analytics/AN1452-system-information-discovery-commands.md) | hunting | T1082 System Information Discovery | `wineventlog` |
| [AN1468 Shell or LOLBin executed inside a network logon session](analytics/AN1468-shell-or-lolbin-executed-inside-a-network-logon-session.md) | anomaly | T1021.002 SMB/Windows Admin Shares | `wineventlog` |
| [AN1472 Windows event log cleared](analytics/AN1472-windows-event-log-cleared.md) | ttp | T1685.005 Clear Windows Event Logs | `wineventlog` |
| [AN1483 Port forwarding or tunnelling tool started](analytics/AN1483-port-forwarding-or-tunnelling-tool-started.md) | ttp | T1572 Protocol Tunneling | `wineventlog` |
| [AN1583 Burst of remote system discovery commands](analytics/AN1583-burst-of-remote-system-discovery-commands.md) | anomaly | T1018 Remote System Discovery | `wineventlog` |
| [AN1611 NTDS.dit extracted with ntdsutil, shadow copies or esentutl](analytics/AN1611-ntds-dit-extracted-with-ntdsutil-shadow-copies-or-esentutl.md) | ttp | T1003.003 NTDS | `wineventlog` |

**Strategy sequences (8):** [DET0085 SYSTEM hive saved together with SAM or SECURITY](strategies/DET0085-system-hive-saved-together-with-sam-or-security.md), [DET0140 Binary or script run from a staging path, then deleted](strategies/DET0140-binary-or-script-run-from-a-staging-path-then-deleted.md), [DET0294 File written by a document or archive application, then executed](strategies/DET0294-file-written-by-a-document-or-archive-application-then-execu.md), [DET0363 LSASS memory read followed by a file write from the same process](strategies/DET0363-lsass-memory-read-followed-by-a-file-write-from-the-same-pro.md), [DET0364 Remote WMI process creation followed by execution on the target](strategies/DET0364-remote-wmi-process-creation-followed-by-execution-on-the-tar.md), [DET0365 Run key set to a user-writable binary that also executes](strategies/DET0365-run-key-set-to-a-user-writable-binary-that-also-executes.md), [DET0394 Script file dropped in a web root, then the web server spawned a shell](strategies/DET0394-script-file-dropped-in-a-web-root-then-the-web-server-spawne.md), [DET0441 Suspicious scheduled task created and then run by Task Scheduler](strategies/DET0441-suspicious-scheduled-task-created-and-then-run-by-task-sched.md).

### powershell_logging

☑ ticked · PowerShell Operational channel (4103/4104) - part of Windows Event Logs, listed separately because it needs its own GPO and input · index `wineventlog`

**Data components (3):** [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md).

**Analytics (1):**

| Analytic | Type | Technique | Other feeds it reads |
|---|---|---|---|
| [AN0363 Domain account enumeration from a non-domain-controller](analytics/AN0363-domain-account-enumeration-from-a-non-domain-controller.md) | anomaly | T1087.002 Domain Account | `sysmon` |

### windows_firewall_log

☐ not ticked · Windows Firewall text log (pfirewall.log) · index `wineventlog`

**Data components (1):** [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md).

### windows_perfmon

☐ not ticked · Windows Performance counters · index `perfmon`

**Data components (1):** [DC0018 Host Status](data-components/DC0018-host-status.md).

### windows_dns_server

☐ not ticked · Windows DNS Server analytical / debug log · index `wineventlog`

**Data components (2):** [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0101 Domain Registration](data-components/DC0101-domain-registration.md).

### windows_dhcp

☐ not ticked · Windows DHCP server log · index `wineventlog`

Nothing rendered for this feed yet.

### iis

☐ not ticked · IIS access and configuration logs · index `web`

**Data components (2):** [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md).

### etw

☐ not ticked · ETW providers not surfaced by Sysmon (Kernel-Process, Win32k, WinINet, RPC, DotNETRuntime, AMSI, Token...) · index `etw`

**Data components (6):** [DC0016 Module Load](data-components/DC0016-module-load.md), [DC0020 Process Modification](data-components/DC0020-process-modification.md), [DC0021 OS API Execution](data-components/DC0021-os-api-execution.md), [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md).

### windows_osquery

☐ not ticked · osquery on Windows · index `osquery`

**Data components (2):** [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md), [DC0013 User Account Metadata](data-components/DC0013-user-account-metadata.md).

### autoruns

☐ not ticked · Sysinternals Autoruns scans · index `wineventlog`

**Data components (1):** [DC0050 Windows Registry Key Access](data-components/DC0050-windows-registry-key-access.md).

## Endpoint security

### trellix_epo

☑ ticked · Trellix ePO events (ENS threat/AMSI/adaptive threat protection, ePO audit) · index `epo`

**Data components (7):** [DC0003 Malware Metadata](data-components/DC0003-malware-metadata.md), [DC0011 Malware Content](data-components/DC0011-malware-content.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md).

### solidcore

☑ ticked · Trellix Application and Change Control (Solidcore) via ePO · index `epo`

**Data components (10):** [DC0016 Module Load](data-components/DC0016-module-load.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0039 File Creation](data-components/DC0039-file-creation.md), [DC0040 File Deletion](data-components/DC0040-file-deletion.md), [DC0045 Windows Registry Key Deletion](data-components/DC0045-windows-registry-key-deletion.md), [DC0055 File Access](data-components/DC0055-file-access.md), [DC0056 Windows Registry Key Creation](data-components/DC0056-windows-registry-key-creation.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0063 Windows Registry Key Modification](data-components/DC0063-windows-registry-key-modification.md).

### edr_telemetry

☐ not ticked · EDR raw telemetry (memory, hunting, script block, syscall) - e.g. Trellix EDR, Defender for Endpoint advanced hunting · index `edr`

**Data components (8):** [DC0021 OS API Execution](data-components/DC0021-os-api-execution.md), [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md), [DC0035 Process Access](data-components/DC0035-process-access.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md).

## Network

### corelight

☑ ticked · Corelight / Zeek network logs · index `corelight`

**Data components (15):** [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0007 Web Credential Usage](data-components/DC0007-web-credential-usage.md), [DC0011 Malware Content](data-components/DC0011-malware-content.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0084 Active Directory Credential Request](data-components/DC0084-active-directory-credential-request.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md), [DC0101 Domain Registration](data-components/DC0101-domain-registration.md), [DC0102 Network Share Access](data-components/DC0102-network-share-access.md), [DC0104 Response Content](data-components/DC0104-response-content.md), [DC0106 Response Metadata](data-components/DC0106-response-metadata.md).

**Analytics (11):**

| Analytic | Type | Technique | Other feeds it reads |
|---|---|---|---|
| [AN0005 Publish/subscribe protocol to an external broker](analytics/AN0005-publish-subscribe-protocol-to-an-external-broker.md) | anomaly | T1071.005 Publish/Subscribe Protocols | none |
| [AN0075 HTTP to external hosts with a non-browser user agent](analytics/AN0075-http-to-external-hosts-with-a-non-browser-user-agent.md) | anomaly | T1071.001 Web Protocols | none |
| [AN0079 Repeated HTTP requests carrying long encoded tokens in the URI](analytics/AN0079-repeated-http-requests-carrying-long-encoded-tokens-in-the-u.md) | anomaly | T1071.001 Web Protocols | none |
| [AN0382 SMTP to the internet from a host that is not a mail server](analytics/AN0382-smtp-to-the-internet-from-a-host-that-is-not-a-mail-server.md) | anomaly | T1071.003 Mail Protocols | none |
| [AN0404 Long-lived or high-volume external session with no identified protocol](analytics/AN0404-long-lived-or-high-volume-external-session-with-no-identifie.md) | anomaly | T1573.001 Symmetric Cryptography | none |
| [AN0427 Large cleartext upload to an external host](analytics/AN0427-large-cleartext-upload-to-an-external-host.md) | anomaly | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | none |
| [AN1067 Executable transferred under a non-executable file name](analytics/AN1067-executable-transferred-under-a-non-executable-file-name.md) | ttp | T1027 Obfuscated Files or Information | none |
| [AN1124 DNS tunnelling pattern from a client (network view)](analytics/AN1124-dns-tunnelling-pattern-from-a-client-network-view.md) | anomaly | T1071.004 DNS | none |
| [AN1173 FTP or TFTP to the internet, or FTP on a non-standard port](analytics/AN1173-ftp-or-tftp-to-the-internet-or-ftp-on-a-non-standard-port.md) | anomaly | T1071.002 File Transfer Protocols | none |
| [AN1258 ICMP session with unusual volume or duration](analytics/AN1258-icmp-session-with-unusual-volume-or-duration.md) | anomaly | T1095 Non-Application Layer Protocol | none |
| [AN1500 TLS to an external host on an unusual port with an unvalidated certificate](analytics/AN1500-tls-to-an-external-host-on-an-unusual-port-with-an-unvalidat.md) | anomaly | T1573.002 Asymmetric Cryptography | none |

### palo_alto

☑ ticked · Palo Alto Networks PAN-OS (traffic, threat, URL, system, config, GlobalProtect) · index `pan_logs`

**Data components (24):** [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0003 Malware Metadata](data-components/DC0003-malware-metadata.md), [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md), [DC0007 Web Credential Usage](data-components/DC0007-web-credential-usage.md), [DC0011 Malware Content](data-components/DC0011-malware-content.md), [DC0014 User Account Creation](data-components/DC0014-user-account-creation.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0041 Service Metadata](data-components/DC0041-service-metadata.md), [DC0043 Firewall Disable](data-components/DC0043-firewall-disable.md), [DC0044 Firewall Enumeration](data-components/DC0044-firewall-enumeration.md), [DC0051 Firewall Rule Modification](data-components/DC0051-firewall-rule-modification.md), [DC0053 Firewall Metadata](data-components/DC0053-firewall-metadata.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md), [DC0102 Network Share Access](data-components/DC0102-network-share-access.md), [DC0104 Response Content](data-components/DC0104-response-content.md), [DC0106 Response Metadata](data-components/DC0106-response-metadata.md).

**Analytics (14):**

| Analytic | Type | Technique | Other feeds it reads |
|---|---|---|---|
| [AN0276 PAN-OS software installed, upgraded or downgraded](analytics/AN0276-pan-os-software-installed-upgraded-or-downgraded.md) | anomaly | T1542.001 System Firmware | none |
| [AN0354 SSH public key added to a firewall administrator](analytics/AN0354-ssh-public-key-added-to-a-firewall-administrator.md) | ttp | T1098.004 SSH Authorized Keys | none |
| [AN0410 Security rules deleted or default rules changed on the firewall](analytics/AN0410-security-rules-deleted-or-default-rules-changed-on-the-firew.md) | anomaly | T1686 Disable or Modify System Firewall | none |
| [AN0855 Bulk or API-driven security and NAT rule changes on the firewall](analytics/AN0855-bulk-or-api-driven-security-and-nat-rule-changes-on-the-fire.md) | anomaly | T1686.002 Network Device Firewall | none |
| [AN0926 Proxy-avoidance sites or anonymising proxy applications](analytics/AN0926-proxy-avoidance-sites-or-anonymising-proxy-applications.md) | anomaly | T1090.002 External Proxy | none |
| [AN1024 Tor or other onion-routing traffic through the firewall](analytics/AN1024-tor-or-other-onion-routing-traffic-through-the-firewall.md) | ttp | T1090.003 Multi-hop Proxy | none |
| [AN1233 NAT, port-forwarding or policy-based forwarding rule changed on the firewall](analytics/AN1233-nat-port-forwarding-or-policy-based-forwarding-rule-changed-.md) | anomaly | T1090 Proxy | none |
| [AN1240 Administrator account added on the firewall](analytics/AN1240-administrator-account-added-on-the-firewall.md) | ttp | T1136.001 Local Account | none |
| [AN1287 Login to the firewall with a default account name](analytics/AN1287-login-to-the-firewall-with-a-default-account-name.md) | anomaly | T1078.001 Default Accounts | none |
| [AN1340 One source failing to authenticate as many accounts on the firewall](analytics/AN1340-one-source-failing-to-authenticate-as-many-accounts-on-the-f.md) | anomaly | T1110.003 Password Spraying | none |
| [AN1374 Firewall logging or monitoring configuration changed](analytics/AN1374-firewall-logging-or-monitoring-configuration-changed.md) | ttp | T1685 Disable or Modify Tools | none |
| [AN1525 Repeated authentication failures for one account on the firewall](analytics/AN1525-repeated-authentication-failures-for-one-account-on-the-fire.md) | anomaly | T1110.001 Password Guessing | none |
| [AN1542 Firewall restart or shutdown](analytics/AN1542-firewall-restart-or-shutdown.md) | anomaly | T1529 System Shutdown/Reboot | none |
| [AN1571 Large upload to a cloud storage application](analytics/AN1571-large-upload-to-a-cloud-storage-application.md) | anomaly | T1567.002 Exfiltration to Cloud Storage | none |

### wireshark

☑ ticked · Wireshark / tshark packet captures (ad hoc) · index `pcap`

**Data components (2):** [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md).

### netdev_syslog

☐ not ticked · Router / switch / non-PAN firewall syslog, config change and AAA logs · index `netops`

**Data components (6):** [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md), [DC0051 Firewall Rule Modification](data-components/DC0051-firewall-rule-modification.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md).

### snmp

☐ not ticked · SNMP traps / polling · index `netops`

**Data components (1):** [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md).

### netflow

☐ not ticked · NetFlow / IPFIX (non-Zeek flow) · index `netflow`

**Data components (2):** [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md).

## Linux

### auditd

☐ not ticked · Linux auditd (SYSCALL/EXECVE/PATH/CONFIG_CHANGE/USER_LOGIN...) · index `linux`

**Data components (33):** [DC0001 Scheduled Job Creation](data-components/DC0001-scheduled-job-creation.md), [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md), [DC0010 User Account Modification](data-components/DC0010-user-account-modification.md), [DC0012 Scheduled Job Modification](data-components/DC0012-scheduled-job-modification.md), [DC0013 User Account Metadata](data-components/DC0013-user-account-metadata.md), [DC0014 User Account Creation](data-components/DC0014-user-account-creation.md), [DC0016 Module Load](data-components/DC0016-module-load.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0020 Process Modification](data-components/DC0020-process-modification.md), [DC0021 OS API Execution](data-components/DC0021-os-api-execution.md), [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0031 Kernel Module Load](data-components/DC0031-kernel-module-load.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0033 Process Termination](data-components/DC0033-process-termination.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md), [DC0035 Process Access](data-components/DC0035-process-access.md), [DC0039 File Creation](data-components/DC0039-file-creation.md), [DC0040 File Deletion](data-components/DC0040-file-deletion.md), [DC0041 Service Metadata](data-components/DC0041-service-metadata.md), [DC0042 Drive Creation](data-components/DC0042-drive-creation.md), [DC0054 Drive Access](data-components/DC0054-drive-access.md), [DC0055 File Access](data-components/DC0055-file-access.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0060 Service Creation](data-components/DC0060-service-creation.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0079 Driver Load](data-components/DC0079-driver-load.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md).

### linux_syslog

☐ not ticked · Linux syslog / journald (messages, secure/auth, cron, kernel, daemon) · index `linux`

**Data components (16):** [DC0001 Scheduled Job Creation](data-components/DC0001-scheduled-job-creation.md), [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0005 Scheduled Job Metadata](data-components/DC0005-scheduled-job-metadata.md), [DC0010 User Account Modification](data-components/DC0010-user-account-modification.md), [DC0014 User Account Creation](data-components/DC0014-user-account-creation.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0031 Kernel Module Load](data-components/DC0031-kernel-module-load.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0042 Drive Creation](data-components/DC0042-drive-creation.md), [DC0051 Firewall Rule Modification](data-components/DC0051-firewall-rule-modification.md), [DC0060 Service Creation](data-components/DC0060-service-creation.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0079 Driver Load](data-components/DC0079-driver-load.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md).

### linux_osquery

☐ not ticked · osquery on Linux · index `osquery`

**Data components (7):** [DC0004 Firmware Modification](data-components/DC0004-firmware-modification.md), [DC0013 User Account Metadata](data-components/DC0013-user-account-metadata.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0034 Process Metadata](data-components/DC0034-process-metadata.md), [DC0041 Service Metadata](data-components/DC0041-service-metadata.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md).

### sysmon_linux

☐ not ticked · Sysmon for Linux · index `linux`

**Data components (5):** [DC0016 Module Load](data-components/DC0016-module-load.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0039 File Creation](data-components/DC0039-file-creation.md), [DC0040 File Deletion](data-components/DC0040-file-deletion.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md).

### iptables

☐ not ticked · iptables / nftables LOG target via kernel syslog · index `linux`

**Data components (1):** [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md).

### ebpf

☐ not ticked · eBPF runtime security (Falco, Tetragon, Tracee) · index `linux`

**Data components (8):** [DC0020 Process Modification](data-components/DC0020-process-modification.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0055 File Access](data-components/DC0055-file-access.md), [DC0059 File Metadata](data-components/DC0059-file-metadata.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md).

## Azure and identity

### azure_entra

☐ not ticked · Microsoft Entra ID sign-in and audit logs · index `azure`

**Data components (14):** [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0006 Web Credential Creation](data-components/DC0006-web-credential-creation.md), [DC0007 Web Credential Usage](data-components/DC0007-web-credential-usage.md), [DC0010 User Account Modification](data-components/DC0010-user-account-modification.md), [DC0013 User Account Metadata](data-components/DC0013-user-account-metadata.md), [DC0014 User Account Creation](data-components/DC0014-user-account-creation.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0066 Active Directory Object Modification](data-components/DC0066-active-directory-object-modification.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0069 Cloud Service Modification](data-components/DC0069-cloud-service-modification.md), [DC0083 Cloud Service Enumeration](data-components/DC0083-cloud-service-enumeration.md), [DC0087 Active Directory Object Creation](data-components/DC0087-active-directory-object-creation.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md), [DC0099 Group Enumeration](data-components/DC0099-group-enumeration.md).

### azure_activity

☐ not ticked · Azure Activity Log (subscription control plane) and Azure Policy · index `azure`

**Data components (13):** [DC0010 User Account Modification](data-components/DC0010-user-account-modification.md), [DC0013 User Account Metadata](data-components/DC0013-user-account-metadata.md), [DC0017 Cloud Storage Enumeration](data-components/DC0017-cloud-storage-enumeration.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0049 Snapshot Deletion](data-components/DC0049-snapshot-deletion.md), [DC0057 Snapshot Creation](data-components/DC0057-snapshot-creation.md), [DC0069 Cloud Service Modification](data-components/DC0069-cloud-service-modification.md), [DC0073 Instance Modification](data-components/DC0073-instance-modification.md), [DC0075 Instance Enumeration](data-components/DC0075-instance-enumeration.md), [DC0076 Instance Creation](data-components/DC0076-instance-creation.md), [DC0081 Instance Deletion](data-components/DC0081-instance-deletion.md), [DC0083 Cloud Service Enumeration](data-components/DC0083-cloud-service-enumeration.md), [DC0090 Cloud Service Disable](data-components/DC0090-cloud-service-disable.md).

### azure_resource

☐ not ticked · Azure resource diagnostic logs (NSG flow, VM guest, Key Vault, Storage) · index `azure`

**Data components (1):** [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md).

### m365_defender

☐ not ticked · Microsoft Defender XDR / Defender for Identity alerts and Graph API logs · index `azure`

Nothing rendered for this feed yet.

## Containers

### kubernetes_audit

☐ not ticked · Kubernetes API server audit log and cluster events · index `k8s`

**Data components (18):** [DC0001 Scheduled Job Creation](data-components/DC0001-scheduled-job-creation.md), [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0010 User Account Modification](data-components/DC0010-user-account-modification.md), [DC0015 Image Creation](data-components/DC0015-image-creation.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0019 Pod Creation](data-components/DC0019-pod-creation.md), [DC0030 Pod Modification](data-components/DC0030-pod-modification.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0037 Pod Enumeration](data-components/DC0037-pod-enumeration.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0055 File Access](data-components/DC0055-file-access.md), [DC0060 Service Creation](data-components/DC0060-service-creation.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0072 Container Creation](data-components/DC0072-container-creation.md), [DC0077 Container Start](data-components/DC0077-container-start.md), [DC0085 Network Traffic Content](data-components/DC0085-network-traffic-content.md), [DC0092 Volume Modification](data-components/DC0092-volume-modification.md), [DC0097 Volume Creation](data-components/DC0097-volume-creation.md).

### container_runtime

☐ not ticked · Docker / containerd daemon and runtime events · index `k8s`

**Data components (10):** [DC0015 Image Creation](data-components/DC0015-image-creation.md), [DC0028 Image Metadata](data-components/DC0028-image-metadata.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0033 Process Termination](data-components/DC0033-process-termination.md), [DC0036 Image Modification](data-components/DC0036-image-modification.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0072 Container Creation](data-components/DC0072-container-creation.md), [DC0077 Container Start](data-components/DC0077-container-start.md), [DC0091 Container Enumeration](data-components/DC0091-container-enumeration.md).

## VMware ESXi

### esxi_syslog

☐ not ticked · ESXi host logs via remote syslog (hostd, vmkernel, shell, vobd, vpxa, auth, esxupdate) · index `vmware`

**Data components (27):** [DC0001 Scheduled Job Creation](data-components/DC0001-scheduled-job-creation.md), [DC0002 User Account Authentication](data-components/DC0002-user-account-authentication.md), [DC0005 Scheduled Job Metadata](data-components/DC0005-scheduled-job-metadata.md), [DC0009 User Account Deletion](data-components/DC0009-user-account-deletion.md), [DC0018 Host Status](data-components/DC0018-host-status.md), [DC0029 Script Execution](data-components/DC0029-script-execution.md), [DC0031 Kernel Module Load](data-components/DC0031-kernel-module-load.md), [DC0032 Process Creation](data-components/DC0032-process-creation.md), [DC0033 Process Termination](data-components/DC0033-process-termination.md), [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0039 File Creation](data-components/DC0039-file-creation.md), [DC0040 File Deletion](data-components/DC0040-file-deletion.md), [DC0041 Service Metadata](data-components/DC0041-service-metadata.md), [DC0043 Firewall Disable](data-components/DC0043-firewall-disable.md), [DC0049 Snapshot Deletion](data-components/DC0049-snapshot-deletion.md), [DC0051 Firewall Rule Modification](data-components/DC0051-firewall-rule-modification.md), [DC0055 File Access](data-components/DC0055-file-access.md), [DC0057 Snapshot Creation](data-components/DC0057-snapshot-creation.md), [DC0061 File Modification](data-components/DC0061-file-modification.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0065 Service Modification](data-components/DC0065-service-modification.md), [DC0067 Logon Session Creation](data-components/DC0067-logon-session-creation.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md), [DC0082 Network Connection Creation](data-components/DC0082-network-connection-creation.md), [DC0088 Logon Session Metadata](data-components/DC0088-logon-session-metadata.md), [DC0097 Volume Creation](data-components/DC0097-volume-creation.md), [DC0098 Volume Deletion](data-components/DC0098-volume-deletion.md).

### vcenter

☐ not ticked · vCenter vpxd logs and events · index `vmware`

**Data components (3):** [DC0038 Application Log Content](data-components/DC0038-application-log-content.md), [DC0064 Command Execution](data-components/DC0064-command-execution.md), [DC0078 Network Traffic Flow](data-components/DC0078-network-traffic-flow.md).

## Not yet in scope

### macos

☐ not ticked · macOS unified log / Endpoint Security / osquery / FSEvents · index `macos` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### m365_unified

☐ not ticked · Microsoft 365 unified audit log (Exchange, SharePoint, Teams, Purview) · index `o365` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### aws

☐ not ticked · AWS CloudTrail / VPC Flow / CloudWatch / Bedrock · index `aws` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### gcp

☐ not ticked · Google Cloud audit / VPC flow / Workspace admin · index `gcp` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### okta

☐ not ticked · Okta System Log · index `okta` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### saas

☐ not ticked · SaaS application audit logs (GitHub, Slack, Salesforce, Zoom, Box, Confluence, Google Workspace...) · index `saas` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### mobile

☐ not ticked · Mobile EDR / MDM telemetry · index `mobile` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### ot

☐ not ticked · OT / ICS application and protocol logs · index `ot` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).

### threat_intel

☐ not ticked · External reconnaissance sources (internet scan data, domain registration, malware repositories, persona monitoring) · index `threatintel` · not rendered in this release

Nothing rendered for this feed yet (platform not in scope).
