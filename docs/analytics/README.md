# Analytics (ATT&CK v20.1)

83 of 1773 ATT&CK analytics are implemented as ES detections and Sigma rules; 511 are coverable by the feeds ticked in `config/stack.yml`. The rest are in the [backlog](backlog.md), ranked by technique prevalence.

```mermaid
pie showData
    title Implemented analytics by content type
    "TTP (finding + risk)" : 24
    "Anomaly (risk only)" : 50
    "Hunting (no action)" : 9
```

```mermaid
xychart-beta
    title "Implemented analytics by tactic"
    x-axis ["stealth", "command-and-control", "discovery", "persistence", "privilege-escalation", "execution", "defense-impairment", "credential-access", "impact", "collection", "lateral-movement", "exfiltration", "initial-access"]
    y-axis "analytics"
    bar [17, 16, 13, 10, 9, 8, 6, 5, 4, 4, 3, 2, 2]
```

| Analytic | Detection | Type | Severity | Technique | Tactics | Data components | Feeds |
|---|---|---|---|---|---|---|---|
| AN0165 | [LOLBin or script process connected externally and dropped a file](AN0165-lolbin-or-script-process-connected-externally-and-dropped-a-.md) | anomaly | medium | T1105 Ingress Tool Transfer | command-and-control | DC0082, DC0039 | sysmon |
| AN1452 | [System information discovery commands](AN1452-system-information-discovery-commands.md) | hunting | informational | T1082 System Information Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN0075 | [HTTP to external hosts with a non-browser user agent](AN0075-http-to-external-hosts-with-a-non-browser-user-agent.md) | anomaly | medium | T1071.001 Web Protocols | command-and-control | DC0085 | corelight |
| AN0079 | [Repeated HTTP requests carrying long encoded tokens in the URI](AN0079-repeated-http-requests-carrying-long-encoded-tokens-in-the-u.md) | anomaly | low | T1071.001 Web Protocols | command-and-control | DC0085 | corelight |
| AN0578 | [cmd.exe started by an unusual parent or running a batch file from a staging path](AN0578-cmd-exe-started-by-an-unusual-parent-or-running-a-batch-file.md) | anomaly | low | T1059.003 Windows Command Shell | execution | DC0032 | sysmon, wineventlog |
| AN1040 | [Recursive file and directory enumeration commands](AN1040-recursive-file-and-directory-enumeration-commands.md) | hunting | informational | T1083 File and Directory Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN0767 | [Built-in utility used to decode or reassemble a payload](AN0767-built-in-utility-used-to-decode-or-reassemble-a-payload.md) | ttp | medium | T1140 Deobfuscate/Decode Files or Information | stealth | DC0032 | sysmon, wineventlog |
| AN0392 | [Secure deletion, self-deletion or interpreter removing executables](AN0392-secure-deletion-self-deletion-or-interpreter-removing-execut.md) | anomaly | medium | T1070.004 File Deletion | stealth | DC0032, DC0040 | sysmon |
| AN0095 | [Process discovery commands](AN0095-process-discovery-commands.md) | hunting | informational | T1057 Process Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN0559 | [Network configuration discovery commands](AN0559-network-configuration-discovery-commands.md) | hunting | informational | T1016 System Network Configuration Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN1252 | [PowerShell started with encoded, download or in-memory execution arguments](AN1252-powershell-started-with-encoded-download-or-in-memory-execut.md) | anomaly | medium | T1059.001 PowerShell | execution | DC0032 | sysmon, wineventlog |
| AN1032 | [Run key value pointing to a script or user-writable path](AN1032-run-key-value-pointing-to-a-script-or-user-writable-path.md) | anomaly | medium | T1547.001 Registry Run Keys / Startup Folder | persistence, privilege-escalation | DC0063 | sysmon |
| AN0237 | [Binary written by a decoding utility, then executed or loaded](AN0237-binary-written-by-a-decoding-utility-then-executed-or-loaded.md) | ttp | high | T1027.013 Encrypted/Encoded File | stealth | DC0039, DC0032, DC0016 | sysmon |
| AN0983 | [Windows system process name running from an unexpected directory](AN0983-windows-system-process-name-running-from-an-unexpected-direc.md) | ttp | medium | T1036.005 Match Legitimate Resource Name or Location | stealth | DC0032 | sysmon, wineventlog |
| AN0254 | [User and session discovery commands](AN0254-user-and-session-discovery-commands.md) | hunting | informational | T1033 System Owner/User Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN1070 | [Search for credential files or sensitive document types](AN1070-search-for-credential-files-or-sensitive-document-types.md) | anomaly | medium | T1005 Data from Local System | collection | DC0032 | sysmon, wineventlog |
| AN0819 | [Document or mail application spawned an interpreter or LOLBin](AN0819-document-or-mail-application-spawned-an-interpreter-or-lolbi.md) | ttp | high | T1204.002 Malicious File | execution | DC0032 | sysmon, wineventlog |
| AN1221 | [Scheduled task registered with an interpreter or user-writable action](AN1221-scheduled-task-registered-with-an-interpreter-or-user-writab.md) | anomaly | medium | T1053.005 Scheduled Task | execution, persistence, privilege-escalation | DC0001 | wineventlog |
| AN0781 | [Security-relevant registry value modified](AN0781-security-relevant-registry-value-modified.md) | ttp | medium | T1112 Modify Registry | defense-impairment, persistence | DC0063 | sysmon |
| AN1031 | [WMI used to create processes locally or on remote hosts](AN1031-wmi-used-to-create-processes-locally-or-on-remote-hosts.md) | anomaly | medium | T1047 Windows Management Instrumentation | execution | DC0032 | sysmon, wineventlog |
| AN0404 | [Long-lived or high-volume external session with no identified protocol](AN0404-long-lived-or-high-volume-external-session-with-no-identifie.md) | anomaly | low | T1573.001 Symmetric Cryptography | command-and-control | DC0078 | corelight |
| AN0209 | [Script host chain from Office or into a second-stage interpreter](AN0209-script-host-chain-from-office-or-into-a-second-stage-interpr.md) | anomaly | medium | T1059.005 Visual Basic | execution | DC0032 | sysmon, wineventlog |
| AN0980 | [Screenshot captured from a script or command-line tool](AN0980-screenshot-captured-from-a-script-or-command-line-tool.md) | anomaly | medium | T1113 Screen Capture | collection | DC0032, DC0039 | sysmon |
| AN1064 | [Script host or LOLBin writing an archive or encoded file to a staging path](AN1064-script-host-or-lolbin-writing-an-archive-or-encoded-file-to-.md) | anomaly | low | T1027 Obfuscated Files or Information | stealth | DC0039 | sysmon |
| AN1067 | [Executable transferred under a non-executable file name](AN1067-executable-transferred-under-a-non-executable-file-name.md) | ttp | medium | T1027 Obfuscated Files or Information | stealth | DC0085 | corelight |
| AN0724 | [Many files written into a staging directory by one process](AN0724-many-files-written-into-a-staging-directory-by-one-process.md) | anomaly | medium | T1074.001 Local Data Staging | collection | DC0039 | sysmon |
| AN1369 | [Security tooling disabled or tampered with](AN1369-security-tooling-disabled-or-tampered-with.md) | ttp | high | T1685 Disable or Modify Tools | defense-impairment | DC0063, DC0032 | sysmon |
| AN1374 | [Firewall logging or monitoring configuration changed](AN1374-firewall-logging-or-monitoring-configuration-changed.md) | ttp | medium | T1685 Disable or Modify Tools | defense-impairment | DC0041 | palo_alto |
| AN0048 | [Security software enumeration](AN0048-security-software-enumeration.md) | anomaly | low | T1518.001 Security Software Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN1527 | [Service installed with an interpreter or user-writable binary path](AN1527-service-installed-with-an-interpreter-or-user-writable-binar.md) | ttp | medium | T1543.003 Windows Service | persistence, privilege-escalation | DC0060 | wineventlog |
| AN0577 | [Unsigned DLL loaded from a user-writable path by a trusted or relocated program](AN0577-unsigned-dll-loaded-from-a-user-writable-path-by-a-trusted-o.md) | anomaly | medium | T1574.001 DLL | stealth, execution | DC0016 | sysmon |
| AN1583 | [Burst of remote system discovery commands](AN1583-burst-of-remote-system-discovery-commands.md) | anomaly | low | T1018 Remote System Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN0589 | [Registry queries for environment, software and security configuration](AN0589-registry-queries-for-environment-software-and-security-confi.md) | hunting | informational | T1012 Query Registry | discovery | DC0032 | sysmon, wineventlog |
| AN0831 | [Archive created with a password, split volumes or a built-in packer](AN0831-archive-created-with-a-password-split-volumes-or-a-built-in-.md) | anomaly | low | T1560.001 Archive via Utility | collection | DC0032 | sysmon, wineventlog |
| AN0903 | [Network connection and session discovery commands](AN0903-network-connection-and-session-discovery-commands.md) | hunting | informational | T1049 System Network Connections Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN1308 | [Rundll32 executing script, remote or user-writable payloads](AN1308-rundll32-executing-script-remote-or-user-writable-payloads.md) | ttp | medium | T1218.011 Rundll32 | stealth | DC0032 | sysmon, wineventlog |
| AN1030 | [LSASS memory access by an unexpected process](AN1030-lsass-memory-access-by-an-unexpected-process.md) | ttp | high | T1003.001 LSASS Memory | credential-access | DC0035 | sysmon |
| AN1258 | [ICMP session with unusual volume or duration](AN1258-icmp-session-with-unusual-volume-or-duration.md) | anomaly | medium | T1095 Non-Application Layer Protocol | command-and-control | DC0078 | corelight |
| AN1543 | [Interactive or remote logon by a service account](AN1543-interactive-or-remote-logon-by-a-service-account.md) | anomaly | medium | T1078 Valid Accounts | stealth, persistence, privilege-escalation, initial-access | DC0067 | wineventlog |
| AN0324 | [Service or task named like system software but running an untrusted binary](AN0324-service-or-task-named-like-system-software-but-running-an-un.md) | anomaly | medium | T1036.004 Masquerade Task or Service | stealth | DC0060, DC0001 | wineventlog |
| AN0105 | [Browser credential store read by a non-browser process](AN0105-browser-credential-store-read-by-a-non-browser-process.md) | ttp | high | T1555.003 Credentials from Web Browsers | credential-access | DC0055 | wineventlog |
| AN1057 | [Process connecting to many hosts or ports in one minute](AN1057-process-connecting-to-many-hosts-or-ports-in-one-minute.md) | anomaly | medium | T1046 Network Service Discovery | discovery | DC0082 | sysmon |
| AN1500 | [TLS to an external host on an unusual port with an unvalidated certificate](AN1500-tls-to-an-external-host-on-an-unusual-port-with-an-unvalidat.md) | anomaly | medium | T1573.002 Asymmetric Cryptography | command-and-control | DC0085 | corelight |
| AN0931 | [First-seen RDP logon for a user, source and destination](AN0931-first-seen-rdp-logon-for-a-user-source-and-destination.md) | anomaly | medium | T1021.001 Remote Desktop Protocol | lateral-movement | DC0067 | wineventlog |
| AN1108 | [Web server process spawned a shell or script interpreter](AN1108-web-server-process-spawned-a-shell-or-script-interpreter.md) | ttp | high | T1505.003 Web Shell | persistence | DC0032 | sysmon, wineventlog |
| AN1394 | [Command line with obfuscation markers](AN1394-command-line-with-obfuscation-markers.md) | anomaly | medium | T1027.010 Command Obfuscation | stealth | DC0032 | sysmon, wineventlog |
| AN0602 | [Ransom-note style file dropped across many directories](AN0602-ransom-note-style-file-dropped-across-many-directories.md) | ttp | critical | T1486 Data Encrypted for Impact | impact | DC0039 | sysmon |
| AN1399 | [Remote thread created in a high-value process](AN1399-remote-thread-created-in-a-high-value-process.md) | anomaly | medium | T1055 Process Injection | stealth, privilege-escalation | DC0035 | sysmon |
| AN1233 | [NAT, port-forwarding or policy-based forwarding rule changed on the firewall](AN1233-nat-port-forwarding-or-policy-based-forwarding-rule-changed-.md) | anomaly | medium | T1090 Proxy | command-and-control | DC0051 | palo_alto |
| AN1468 | [Shell or LOLBin executed inside a network logon session](AN1468-shell-or-lolbin-executed-inside-a-network-logon-session.md) | anomaly | medium | T1021.002 SMB/Windows Admin Shares | lateral-movement | DC0067, DC0032 | wineventlog, sysmon |
| AN0363 | [Domain account enumeration from a non-domain-controller](AN0363-domain-account-enumeration-from-a-non-domain-controller.md) | anomaly | low | T1087.002 Domain Account | discovery | DC0032, DC0064 | sysmon, powershell_logging |
| AN0633 | [Office, script or proxy-execution process connecting out on a non-standard port](AN0633-office-script-or-proxy-execution-process-connecting-out-on-a.md) | anomaly | low | T1571 Non-Standard Port | command-and-control | DC0082 | sysmon |
| AN1185 | [Service control manager started an unexpected binary](AN1185-service-control-manager-started-an-unexpected-binary.md) | anomaly | medium | T1569.002 Service Execution | execution | DC0032 | sysmon, wineventlog |
| AN0355 | [Renamed system utility (file name does not match PE original name)](AN0355-renamed-system-utility-file-name-does-not-match-pe-original-.md) | ttp | medium | T1036 Masquerading | stealth | DC0032 | sysmon |
| AN1325 | [Service enumeration commands](AN1325-service-enumeration-commands.md) | hunting | informational | T1007 System Service Discovery | discovery | DC0032 | sysmon, wineventlog |
| AN0846 | [Local account and group enumeration commands](AN0846-local-account-and-group-enumeration-commands.md) | hunting | informational | T1087.001 Local Account | discovery | DC0032 | sysmon, wineventlog |
| AN0516 | [File written over SMB, then executed on the target](AN0516-file-written-over-smb-then-executed-on-the-target.md) | ttp | high | T1570 Lateral Tool Transfer | lateral-movement | DC0039, DC0032 | sysmon |
| AN0360 | [Interpreter started with a hidden window](AN0360-interpreter-started-with-a-hidden-window.md) | anomaly | low | T1564.003 Hidden Window | stealth | DC0032 | sysmon, wineventlog |
| AN1095 | [Process handle opened for injection from unbacked memory](AN1095-process-handle-opened-for-injection-from-unbacked-memory.md) | anomaly | high | T1055.001 Dynamic-link Library Injection | stealth, privilege-escalation | DC0035 | sysmon |
| AN1094 | [UAC bypass through auto-elevated binary hijack](AN1094-uac-bypass-through-auto-elevated-binary-hijack.md) | ttp | high | T1548.002 Bypass User Account Control | privilege-escalation | DC0063, DC0032 | sysmon |
| AN1571 | [Large upload to a cloud storage application](AN1571-large-upload-to-a-cloud-storage-application.md) | anomaly | medium | T1567.002 Exfiltration to Cloud Storage | exfiltration | DC0082 | palo_alto |
| AN1121 | [DNS tunnelling pattern from a non-browser process](AN1121-dns-tunnelling-pattern-from-a-non-browser-process.md) | anomaly | medium | T1071.004 DNS | command-and-control | DC0085 | sysmon |
| AN1124 | [DNS tunnelling pattern from a client (network view)](AN1124-dns-tunnelling-pattern-from-a-client-network-view.md) | anomaly | medium | T1071.004 DNS | command-and-control | DC0085 | corelight |
| AN1483 | [Port forwarding or tunnelling tool started](AN1483-port-forwarding-or-tunnelling-tool-started.md) | ttp | medium | T1572 Protocol Tunneling | command-and-control | DC0032 | sysmon, wineventlog |
| AN0933 | [Shadow copies, backups or boot recovery disabled with native utilities](AN0933-shadow-copies-backups-or-boot-recovery-disabled-with-native-.md) | ttp | high | T1490 Inhibit System Recovery | impact | DC0032 | sysmon, wineventlog |
| AN1024 | [Tor or other onion-routing traffic through the firewall](AN1024-tor-or-other-onion-routing-traffic-through-the-firewall.md) | ttp | high | T1090.003 Multi-hop Proxy | command-and-control | DC0078 | palo_alto |
| AN0061 | [Burst of service stop or disable commands](AN0061-burst-of-service-stop-or-disable-commands.md) | anomaly | medium | T1489 Service Stop | impact | DC0032 | sysmon, wineventlog |
| AN0235 | [SAM, SYSTEM or SECURITY hive dumped from the command line](AN0235-sam-system-or-security-hive-dumped-from-the-command-line.md) | ttp | high | T1003.002 Security Account Manager | credential-access | DC0032 | sysmon, wineventlog |
| AN1472 | [Windows event log cleared](AN1472-windows-event-log-cleared.md) | ttp | high | T1685.005 Clear Windows Event Logs | defense-impairment | DC0038, DC0032 | wineventlog, sysmon |
| AN1240 | [Administrator account added on the firewall](AN1240-administrator-account-added-on-the-firewall.md) | ttp | medium | T1136.001 Local Account | persistence | DC0014 | palo_alto |
| AN0427 | [Large cleartext upload to an external host](AN0427-large-cleartext-upload-to-an-external-host.md) | anomaly | medium | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | DC0078 | corelight |
| AN0410 | [Security rules deleted or default rules changed on the firewall](AN0410-security-rules-deleted-or-default-rules-changed-on-the-firew.md) | anomaly | medium | T1686 Disable or Modify System Firewall | defense-impairment | DC0051 | palo_alto |
| AN0926 | [Proxy-avoidance sites or anonymising proxy applications](AN0926-proxy-avoidance-sites-or-anonymising-proxy-applications.md) | anomaly | medium | T1090.002 External Proxy | command-and-control | DC0085, DC0078 | palo_alto |
| AN1542 | [Firewall restart or shutdown](AN1542-firewall-restart-or-shutdown.md) | anomaly | medium | T1529 System Shutdown/Reboot | impact | DC0018 | palo_alto |
| AN1173 | [FTP or TFTP to the internet, or FTP on a non-standard port](AN1173-ftp-or-tftp-to-the-internet-or-ftp-on-a-non-standard-port.md) | anomaly | medium | T1071.002 File Transfer Protocols | command-and-control | DC0078 | corelight |
| AN1340 | [One source failing to authenticate as many accounts on the firewall](AN1340-one-source-failing-to-authenticate-as-many-accounts-on-the-f.md) | anomaly | high | T1110.003 Password Spraying | credential-access | DC0002 | palo_alto |
| AN0382 | [SMTP to the internet from a host that is not a mail server](AN0382-smtp-to-the-internet-from-a-host-that-is-not-a-mail-server.md) | anomaly | medium | T1071.003 Mail Protocols | command-and-control | DC0085 | corelight |
| AN1525 | [Repeated authentication failures for one account on the firewall](AN1525-repeated-authentication-failures-for-one-account-on-the-fire.md) | anomaly | medium | T1110.001 Password Guessing | credential-access | DC0002 | palo_alto |
| AN0354 | [SSH public key added to a firewall administrator](AN0354-ssh-public-key-added-to-a-firewall-administrator.md) | ttp | high | T1098.004 SSH Authorized Keys | persistence, privilege-escalation | DC0064 | palo_alto |
| AN1287 | [Login to the firewall with a default account name](AN1287-login-to-the-firewall-with-a-default-account-name.md) | anomaly | medium | T1078.001 Default Accounts | stealth, persistence, privilege-escalation, initial-access | DC0002 | palo_alto |
| AN0855 | [Bulk or API-driven security and NAT rule changes on the firewall](AN0855-bulk-or-api-driven-security-and-nat-rule-changes-on-the-fire.md) | anomaly | medium | T1686.002 Network Device Firewall | defense-impairment | DC0051 | palo_alto |
| AN0276 | [PAN-OS software installed, upgraded or downgraded](AN0276-pan-os-software-installed-upgraded-or-downgraded.md) | anomaly | medium | T1542.001 System Firmware | stealth, persistence | DC0004 | palo_alto |
| AN0005 | [Publish/subscribe protocol to an external broker](AN0005-publish-subscribe-protocol-to-an-external-broker.md) | anomaly | low | T1071.005 Publish/Subscribe Protocols | command-and-control | DC0078 | corelight |

## Authoring

```bash
python -m mitremap new-analytic AN0123   # scaffold content/analytics/AN0123.yml with ATT&CK text and suggestions
# edit the curated block: status, title, content_type, spl, risk, tuning, sigma
make build && make test
```

Rules enforced by `mitremap validate`: the SPL uses a `mitre_dcXXXX` macro and the analytic's own `mitre_anXXXX_filter`, has no literal `index=`, references only macros and lookups that exist, and every risk field and message token appears in the search. Tests convert every Sigma rule through the data-component pipeline.
