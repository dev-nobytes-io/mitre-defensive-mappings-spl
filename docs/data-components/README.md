# Data components (ATT&CK v20.1)

One page per component: justification, requirements per feed, rendered eventtypes, Sigma mapping, dependents.

| ID | Component | Feeds | Analytics | Techniques | CIM |
|---|---|---|---|---|---|
| DC0001 | [Scheduled Job Creation](DC0001-scheduled-job-creation.md) | auditd, esxi_syslog, kubernetes_audit, linux_syslog, wineventlog | 21 | 15 | Endpoint |
| DC0002 | [User Account Authentication](DC0002-user-account-authentication.md) | auditd, azure_entra, corelight, esxi_syslog, kubernetes_audit, linux_syslog, palo_alto, wineventlog | 112 | 55 | Authentication |
| DC0003 | [Malware Metadata](DC0003-malware-metadata.md) | palo_alto, trellix_epo, wineventlog | 7 | 7 | Malware |
| DC0004 | [Firmware Modification](DC0004-firmware-modification.md) | auditd, linux_osquery, netdev_syslog, palo_alto, snmp, windows_osquery, wineventlog | 15 | 10 |  |
| DC0005 | [Scheduled Job Metadata](DC0005-scheduled-job-metadata.md) | esxi_syslog, linux_syslog, wineventlog | 9 | 3 |  |
| DC0006 | [Web Credential Creation](DC0006-web-credential-creation.md) | azure_entra, wineventlog | 5 | 2 |  |
| DC0007 | [Web Credential Usage](DC0007-web-credential-usage.md) | azure_entra, corelight, palo_alto | 20 | 6 | Authentication |
| DC0008 | [WMI Creation](DC0008-wmi-creation.md) | sysmon, wineventlog | 7 | 7 |  |
| DC0009 | [User Account Deletion](DC0009-user-account-deletion.md) | esxi_syslog, wineventlog | 3 | 2 | Change |
| DC0010 | [User Account Modification](DC0010-user-account-modification.md) | auditd, azure_activity, azure_entra, kubernetes_audit, linux_syslog, wineventlog | 40 | 21 | Change |
| DC0011 | [Malware Content](DC0011-malware-content.md) | corelight, palo_alto, trellix_epo | 4 | 4 | Malware |
| DC0012 | [Scheduled Job Modification](DC0012-scheduled-job-modification.md) | auditd, wineventlog | 3 | 3 |  |
| DC0013 | [User Account Metadata](DC0013-user-account-metadata.md) | auditd, azure_activity, azure_entra, linux_osquery, windows_osquery, wineventlog | 33 | 20 | Change |
| DC0014 | [User Account Creation](DC0014-user-account-creation.md) | auditd, azure_entra, linux_syslog, palo_alto, wineventlog | 17 | 6 | Change |
| DC0015 | [Image Creation](DC0015-image-creation.md) | container_runtime, kubernetes_audit | 4 | 3 |  |
| DC0016 | [Module Load](DC0016-module-load.md) | auditd, etw, solidcore, sysmon, sysmon_linux, wineventlog | 130 | 110 | Endpoint |
| DC0017 | [Cloud Storage Enumeration](DC0017-cloud-storage-enumeration.md) | azure_activity | 3 | 3 |  |
| DC0018 | [Host Status](DC0018-host-status.md) | auditd, esxi_syslog, kubernetes_audit, linux_syslog, palo_alto, sysmon, trellix_epo, windows_perfmon, wineventlog | 36 | 14 | Endpoint |
| DC0019 | [Pod Creation](DC0019-pod-creation.md) | kubernetes_audit | 2 | 2 |  |
| DC0020 | [Process Modification](DC0020-process-modification.md) | auditd, ebpf, etw, sysmon | 29 | 24 |  |
| DC0021 | [OS API Execution](DC0021-os-api-execution.md) | auditd, edr_telemetry, etw, sysmon, wineventlog | 66 | 54 |  |
| DC0022 | [Cloud Storage Deletion](DC0022-cloud-storage-deletion.md) | out of scope | 2 | 2 |  |
| DC0023 | [Cloud Storage Modification](DC0023-cloud-storage-modification.md) | out of scope | 5 | 3 |  |
| DC0024 | [Cloud Storage Creation](DC0024-cloud-storage-creation.md) | out of scope | 1 | 1 |  |
| DC0025 | [Cloud Storage Access](DC0025-cloud-storage-access.md) | out of scope | 13 | 11 |  |
| DC0026 | [Image Deletion](DC0026-image-deletion.md) | out of scope | 0 | 0 |  |
| DC0027 | [Cloud Storage Metadata](DC0027-cloud-storage-metadata.md) | out of scope | 3 | 2 |  |
| DC0028 | [Image Metadata](DC0028-image-metadata.md) | container_runtime | 3 | 3 |  |
| DC0029 | [Script Execution](DC0029-script-execution.md) | auditd, edr_telemetry, esxi_syslog, etw, powershell_logging, trellix_epo, wineventlog | 36 | 30 | Endpoint |
| DC0030 | [Pod Modification](DC0030-pod-modification.md) | kubernetes_audit | 0 | 0 |  |
| DC0031 | [Kernel Module Load](DC0031-kernel-module-load.md) | auditd, esxi_syslog, linux_syslog | 2 | 2 |  |
| DC0032 | [Process Creation](DC0032-process-creation.md) | auditd, container_runtime, ebpf, esxi_syslog, etw, kubernetes_audit, linux_osquery, solidcore, sysmon, sysmon_linux, wineventlog | 860 | 456 | Endpoint |
| DC0033 | [Process Termination](DC0033-process-termination.md) | auditd, container_runtime, esxi_syslog, sysmon | 14 | 7 | Endpoint |
| DC0034 | [Process Metadata](DC0034-process-metadata.md) | auditd, edr_telemetry, etw, linux_osquery, powershell_logging, sysmon, wineventlog | 40 | 31 | Endpoint |
| DC0035 | [Process Access](DC0035-process-access.md) | auditd, edr_telemetry, sysmon, wineventlog | 93 | 77 | Endpoint |
| DC0036 | [Image Modification](DC0036-image-modification.md) | container_runtime | 2 | 1 |  |
| DC0037 | [Pod Enumeration](DC0037-pod-enumeration.md) | kubernetes_audit | 1 | 1 |  |
| DC0038 | [Application Log Content](DC0038-application-log-content.md) | azure_activity, azure_entra, container_runtime, corelight, esxi_syslog, iis, kubernetes_audit, linux_syslog, palo_alto, trellix_epo, vcenter, wineventlog | 209 | 104 |  |
| DC0039 | [File Creation](DC0039-file-creation.md) | auditd, esxi_syslog, solidcore, sysmon, sysmon_linux, wineventlog | 254 | 176 | Endpoint |
| DC0040 | [File Deletion](DC0040-file-deletion.md) | auditd, esxi_syslog, solidcore, sysmon, sysmon_linux, wineventlog | 29 | 12 | Endpoint |
| DC0041 | [Service Metadata](DC0041-service-metadata.md) | auditd, esxi_syslog, linux_osquery, palo_alto, sysmon, wineventlog | 22 | 13 | Endpoint |
| DC0042 | [Drive Creation](DC0042-drive-creation.md) | auditd, linux_syslog, wineventlog | 22 | 8 |  |
| DC0043 | [Firewall Disable](DC0043-firewall-disable.md) | esxi_syslog, palo_alto, wineventlog | 2 | 1 | Change |
| DC0044 | [Firewall Enumeration](DC0044-firewall-enumeration.md) | palo_alto, wineventlog | 0 | 0 |  |
| DC0045 | [Windows Registry Key Deletion](DC0045-windows-registry-key-deletion.md) | solidcore, sysmon, wineventlog | 0 | 0 | Endpoint |
| DC0046 | [Drive Modification](DC0046-drive-modification.md) | sysmon, wineventlog | 9 | 6 |  |
| DC0047 | [Snapshot Enumeration](DC0047-snapshot-enumeration.md) | out of scope | 0 | 0 |  |
| DC0048 | [Named Pipe Metadata](DC0048-named-pipe-metadata.md) | sysmon | 4 | 4 |  |
| DC0049 | [Snapshot Deletion](DC0049-snapshot-deletion.md) | azure_activity, esxi_syslog | 3 | 2 |  |
| DC0050 | [Windows Registry Key Access](DC0050-windows-registry-key-access.md) | autoruns, wineventlog | 6 | 6 | Endpoint |
| DC0051 | [Firewall Rule Modification](DC0051-firewall-rule-modification.md) | esxi_syslog, linux_syslog, netdev_syslog, palo_alto, wineventlog | 14 | 12 | Change |
| DC0052 | [Social Media](DC0052-social-media.md) | out of scope | 4 | 4 |  |
| DC0053 | [Firewall Metadata](DC0053-firewall-metadata.md) | palo_alto, wineventlog | 0 | 0 |  |
| DC0054 | [Drive Access](DC0054-drive-access.md) | auditd, sysmon | 10 | 8 |  |
| DC0055 | [File Access](DC0055-file-access.md) | auditd, ebpf, esxi_syslog, kubernetes_audit, solidcore, wineventlog | 168 | 94 | Endpoint |
| DC0056 | [Windows Registry Key Creation](DC0056-windows-registry-key-creation.md) | solidcore, sysmon, wineventlog | 12 | 11 | Endpoint |
| DC0057 | [Snapshot Creation](DC0057-snapshot-creation.md) | azure_activity, esxi_syslog | 4 | 4 |  |
| DC0058 | [Snapshot Modification](DC0058-snapshot-modification.md) | out of scope | 2 | 2 |  |
| DC0059 | [File Metadata](DC0059-file-metadata.md) | auditd, corelight, ebpf, edr_telemetry, linux_osquery, palo_alto, solidcore, sysmon, trellix_epo, wineventlog | 95 | 65 | Endpoint |
| DC0060 | [Service Creation](DC0060-service-creation.md) | auditd, kubernetes_audit, linux_syslog, wineventlog | 31 | 28 | Endpoint |
| DC0061 | [File Modification](DC0061-file-modification.md) | auditd, ebpf, esxi_syslog, linux_syslog, netdev_syslog, palo_alto, solidcore, sysmon, wineventlog | 179 | 116 | Endpoint |
| DC0062 | [Snapshot Metadata](DC0062-snapshot-metadata.md) | out of scope | 2 | 2 |  |
| DC0063 | [Windows Registry Key Modification](DC0063-windows-registry-key-modification.md) | solidcore, sysmon, wineventlog | 89 | 86 | Endpoint |
| DC0064 | [Command Execution](DC0064-command-execution.md) | auditd, container_runtime, ebpf, edr_telemetry, esxi_syslog, kubernetes_audit, netdev_syslog, palo_alto, powershell_logging, sysmon, trellix_epo, vcenter, wineventlog | 339 | 211 | Endpoint |
| DC0065 | [Service Modification](DC0065-service-modification.md) | esxi_syslog, wineventlog | 3 | 3 | Endpoint |
| DC0066 | [Active Directory Object Modification](DC0066-active-directory-object-modification.md) | azure_entra, wineventlog | 18 | 17 | Change |
| DC0067 | [Logon Session Creation](DC0067-logon-session-creation.md) | auditd, azure_entra, corelight, esxi_syslog, linux_syslog, palo_alto, wineventlog | 97 | 58 | Authentication |
| DC0068 | [Active Directory Object Deletion](DC0068-active-directory-object-deletion.md) | wineventlog | 1 | 1 | Change |
| DC0069 | [Cloud Service Modification](DC0069-cloud-service-modification.md) | azure_activity, azure_entra | 24 | 18 | Change |
| DC0070 | [Cloud Service Metadata](DC0070-cloud-service-metadata.md) | out of scope | 10 | 9 | Change |
| DC0071 | [Active Directory Object Access](DC0071-active-directory-object-access.md) | wineventlog | 6 | 6 | Change |
| DC0072 | [Container Creation](DC0072-container-creation.md) | container_runtime, kubernetes_audit | 8 | 8 |  |
| DC0073 | [Instance Modification](DC0073-instance-modification.md) | azure_activity | 2 | 2 |  |
| DC0074 | [Driver Metadata](DC0074-driver-metadata.md) | out of scope | 1 | 1 |  |
| DC0075 | [Instance Enumeration](DC0075-instance-enumeration.md) | azure_activity | 2 | 2 |  |
| DC0076 | [Instance Creation](DC0076-instance-creation.md) | azure_activity | 3 | 3 |  |
| DC0077 | [Container Start](DC0077-container-start.md) | container_runtime, kubernetes_audit | 4 | 4 |  |
| DC0078 | [Network Traffic Flow](DC0078-network-traffic-flow.md) | auditd, corelight, edr_telemetry, esxi_syslog, iptables, netdev_syslog, netflow, palo_alto, sysmon, vcenter, windows_firewall_log, wineventlog, wireshark | 176 | 92 | Network_Traffic |
| DC0079 | [Driver Load](DC0079-driver-load.md) | auditd, linux_syslog, sysmon, wineventlog | 16 | 15 | Endpoint |
| DC0080 | [Instance Start](DC0080-instance-start.md) | out of scope | 11 | 11 |  |
| DC0081 | [Instance Deletion](DC0081-instance-deletion.md) | azure_activity | 1 | 1 |  |
| DC0082 | [Network Connection Creation](DC0082-network-connection-creation.md) | auditd, corelight, ebpf, esxi_syslog, linux_osquery, netdev_syslog, netflow, palo_alto, sysmon, sysmon_linux, wineventlog | 246 | 155 | Network_Traffic |
| DC0083 | [Cloud Service Enumeration](DC0083-cloud-service-enumeration.md) | azure_activity, azure_entra | 10 | 6 | Change |
| DC0084 | [Active Directory Credential Request](DC0084-active-directory-credential-request.md) | corelight, wineventlog | 9 | 9 | Authentication |
| DC0085 | [Network Traffic Content](DC0085-network-traffic-content.md) | auditd, azure_resource, corelight, ebpf, edr_telemetry, iis, kubernetes_audit, linux_syslog, palo_alto, sysmon, windows_dns_server, wineventlog, wireshark | 253 | 140 | Web |
| DC0086 | [Instance Metadata](DC0086-instance-metadata.md) | out of scope | 3 | 3 |  |
| DC0087 | [Active Directory Object Creation](DC0087-active-directory-object-creation.md) | azure_entra, wineventlog | 4 | 3 | Change |
| DC0088 | [Logon Session Metadata](DC0088-logon-session-metadata.md) | auditd, azure_entra, corelight, esxi_syslog, linux_syslog, palo_alto, wineventlog | 47 | 30 | Authentication |
| DC0089 | [Instance Stop](DC0089-instance-stop.md) | out of scope | 4 | 4 |  |
| DC0090 | [Cloud Service Disable](DC0090-cloud-service-disable.md) | azure_activity | 4 | 2 | Change |
| DC0091 | [Container Enumeration](DC0091-container-enumeration.md) | container_runtime | 2 | 2 |  |
| DC0092 | [Volume Modification](DC0092-volume-modification.md) | kubernetes_audit | 2 | 2 |  |
| DC0093 | [Certificate Registration](DC0093-certificate-registration.md) | out of scope | 2 | 2 |  |
| DC0094 | [Group Modification](DC0094-group-modification.md) | wineventlog | 1 | 1 | Change |
| DC0095 | [Volume Enumeration](DC0095-volume-enumeration.md) | out of scope | 0 | 0 |  |
| DC0096 | [Passive DNS](DC0096-passive-dns.md) | out of scope | 5 | 5 |  |
| DC0097 | [Volume Creation](DC0097-volume-creation.md) | esxi_syslog, kubernetes_audit, wineventlog | 2 | 2 |  |
| DC0098 | [Volume Deletion](DC0098-volume-deletion.md) | esxi_syslog | 2 | 2 |  |
| DC0099 | [Group Enumeration](DC0099-group-enumeration.md) | azure_entra, wineventlog | 3 | 2 |  |
| DC0100 | [Volume Metadata](DC0100-volume-metadata.md) | out of scope | 0 | 0 |  |
| DC0101 | [Domain Registration](DC0101-domain-registration.md) | corelight, sysmon, windows_dns_server | 6 | 5 |  |
| DC0102 | [Network Share Access](DC0102-network-share-access.md) | corelight, palo_alto, wineventlog | 11 | 9 | Endpoint |
| DC0103 | [Active DNS](DC0103-active-dns.md) | out of scope | 5 | 5 |  |
| DC0104 | [Response Content](DC0104-response-content.md) | corelight, palo_alto | 28 | 28 |  |
| DC0105 | [Group Metadata](DC0105-group-metadata.md) | wineventlog | 1 | 1 |  |
| DC0106 | [Response Metadata](DC0106-response-metadata.md) | corelight, palo_alto | 7 | 7 |  |
