# Analytic backlog (ATT&CK v20.1)

Unimplemented analytics whose log sources are all on ticked feeds, ranked by technique prevalence (2 × groups + 2 × campaigns + software using the technique). The suggested content type is a heuristic starting point.

Live and unimplemented: **493**. Showing the top 150.

| # | Analytic | Platforms | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|---|
| 1 | [AN1452](https://attack.mitre.org/detectionstrategies/DET0525#AN1452) | Windows | T1082 System Information Discovery | discovery | 511 | hunting | DC0032, DC0063, DC0064 |
| 2 | [AN1457](https://attack.mitre.org/detectionstrategies/DET0525#AN1457) | Network Devices | T1082 System Information Discovery | discovery | 511 | hunting | DC0064 |
| 3 | [AN0075](https://attack.mitre.org/detectionstrategies/DET0027#AN0075) | Windows | T1071.001 Web Protocols | command-and-control | 510 | anomaly | DC0082, DC0085 |
| 4 | [AN0079](https://attack.mitre.org/detectionstrategies/DET0027#AN0079) | Network Devices | T1071.001 Web Protocols | command-and-control | 510 | ttp | DC0085 |
| 5 | [AN0578](https://attack.mitre.org/detectionstrategies/DET0202#AN0578) | Windows | T1059.003 Windows Command Shell | execution | 480 | anomaly | DC0016, DC0029, DC0032 |
| 6 | [AN1040](https://attack.mitre.org/detectionstrategies/DET0370#AN1040) | Windows | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0032, DC0039 |
| 7 | [AN1044](https://attack.mitre.org/detectionstrategies/DET0370#AN1044) | Network Devices | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0064 |
| 8 | [AN0392](https://attack.mitre.org/detectionstrategies/DET0140#AN0392) | Windows | T1070.004 File Deletion | stealth | 380 | anomaly | DC0040, DC0055, DC0064 |
| 9 | [AN0095](https://attack.mitre.org/detectionstrategies/DET0034#AN0095) | Windows | T1057 Process Discovery | discovery | 379 | hunting | DC0032, DC0035 |
| 10 | [AN0099](https://attack.mitre.org/detectionstrategies/DET0034#AN0099) | Network Devices | T1057 Process Discovery | discovery | 379 | hunting | DC0034, DC0064 |
| 11 | [AN0559](https://attack.mitre.org/detectionstrategies/DET0195#AN0559) | Windows | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0032, DC0064 |
| 12 | [AN0563](https://attack.mitre.org/detectionstrategies/DET0195#AN0563) | Network Devices | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0064 |
| 13 | [AN0237](https://attack.mitre.org/detectionstrategies/DET0087#AN0237) | Windows | T1027.013 Encrypted/Encoded File | stealth | 310 | ttp | DC0016, DC0032, DC0035 |
| 14 | [AN0983](https://attack.mitre.org/detectionstrategies/DET0347#AN0983) | Windows | T1036.005 Match Legitimate Resource Name or Location | stealth | 307 | ttp | DC0032, DC0039 |
| 15 | [AN0254](https://attack.mitre.org/detectionstrategies/DET0093#AN0254) | Windows | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0032, DC0064 |
| 16 | [AN0257](https://attack.mitre.org/detectionstrategies/DET0093#AN0257) | Network Devices | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0021, DC0064 |
| 17 | [AN1070](https://attack.mitre.org/detectionstrategies/DET0380#AN1070) | Windows | T1005 Data from Local System | collection | 298 | ttp | DC0032, DC0039 |
| 18 | [AN1073](https://attack.mitre.org/detectionstrategies/DET0380#AN1073) | Network Devices | T1005 Data from Local System | collection | 298 | ttp | DC0064 |
| 19 | [AN1465](https://attack.mitre.org/detectionstrategies/DET0529#AN1465) | Windows | T1106 Native API | execution | 262 | ttp | DC0016, DC0032, DC0035 |
| 20 | [AN0988](https://attack.mitre.org/detectionstrategies/DET0348#AN0988) | Windows | T1041 Exfiltration Over C2 Channel | exfiltration | 249 | ttp | DC0032, DC0055, DC0082, DC0085 |
| 21 | [AN1031](https://attack.mitre.org/detectionstrategies/DET0364#AN1031) | Windows | T1047 Windows Management Instrumentation | execution | 204 | anomaly | DC0008, DC0032, DC0082 |
| 22 | [AN0400](https://attack.mitre.org/detectionstrategies/DET0143#AN0400) | Windows | T1573.001 Symmetric Cryptography | command-and-control | 203 | anomaly | DC0016, DC0082 |
| 23 | [AN0404](https://attack.mitre.org/detectionstrategies/DET0143#AN0404) | Network Devices | T1573.001 Symmetric Cryptography | command-and-control | 203 | anomaly | DC0078, DC0085 |
| 24 | [AN0980](https://attack.mitre.org/detectionstrategies/DET0346#AN0980) | Windows | T1113 Screen Capture | collection | 192 | anomaly | DC0016, DC0032 |
| 25 | [AN1064](https://attack.mitre.org/detectionstrategies/DET0378#AN1064) | Windows | T1027 Obfuscated Files or Information | stealth | 188 | anomaly | DC0032, DC0039 |
| 26 | [AN1067](https://attack.mitre.org/detectionstrategies/DET0378#AN1067) | Network Devices | T1027 Obfuscated Files or Information | stealth | 188 | ttp | DC0085 |
| 27 | [AN0724](https://attack.mitre.org/detectionstrategies/DET0261#AN0724) | Windows | T1074.001 Local Data Staging | collection | 186 | ttp | DC0032, DC0039, DC0055 |
| 28 | [AN0243](https://attack.mitre.org/detectionstrategies/DET0089#AN0243) | Windows | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0035, DC0055, DC0060, DC0063 |
| 29 | [AN0246](https://attack.mitre.org/detectionstrategies/DET0089#AN0246) | Network Devices | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0004, DC0085 |
| 30 | [AN1374](https://attack.mitre.org/detectionstrategies/DET0497#AN1374) | Network Devices | T1685 Disable or Modify Tools | defense-impairment | 173 | ttp | DC0018, DC0041 |
| 31 | [AN0048](https://attack.mitre.org/detectionstrategies/DET0016#AN0048) | Windows | T1518.001 Security Software Discovery | discovery | 172 | hunting | DC0016, DC0032 |
| 32 | [AN0577](https://attack.mitre.org/detectionstrategies/DET0201#AN0577) | Windows | T1574.001 DLL | stealth, execution | 162 | anomaly | DC0016, DC0032, DC0039, DC0059, DC0063 |
| 33 | [AN1583](https://attack.mitre.org/detectionstrategies/DET0574#AN1583) | Windows | T1018 Remote System Discovery | discovery | 161 | hunting | DC0032, DC0082 |
| 34 | [AN1587](https://attack.mitre.org/detectionstrategies/DET0574#AN1587) | Network Devices | T1018 Remote System Discovery | discovery | 161 | hunting | DC0064 |
| 35 | [AN0178](https://attack.mitre.org/detectionstrategies/DET0066#AN0178) | Windows | T1204.001 Malicious Link | execution | 149 | ttp | DC0032, DC0039, DC0082, DC0085 |
| 36 | [AN0589](https://attack.mitre.org/detectionstrategies/DET0209#AN0589) | Windows | T1012 Query Registry | discovery | 141 | hunting | DC0032, DC0063, DC0064 |
| 37 | [AN0831](https://attack.mitre.org/detectionstrategies/DET0298#AN0831) | Windows | T1560.001 Archive via Utility | collection | 140 | anomaly | DC0016, DC0032, DC0039 |
| 38 | [AN0903](https://attack.mitre.org/detectionstrategies/DET0320#AN0903) | Windows | T1049 System Network Connections Discovery | discovery | 137 | hunting | DC0032, DC0064 |
| 39 | [AN0066](https://attack.mitre.org/detectionstrategies/DET0023#AN0066) | Windows | T1027.002 Software Packing | stealth | 136 | ttp | DC0032, DC0035 |
| 40 | [AN1254](https://attack.mitre.org/detectionstrategies/DET0457#AN1254) | Windows | T1095 Non-Application Layer Protocol | command-and-control | 130 | anomaly | DC0082, DC0085 |
| 41 | [AN1258](https://attack.mitre.org/detectionstrategies/DET0457#AN1258) | Network Devices | T1095 Non-Application Layer Protocol | command-and-control | 130 | anomaly | DC0078, DC0085 |
| 42 | [AN0643](https://attack.mitre.org/detectionstrategies/DET0230#AN0643) | Windows | T1553.002 Code Signing | defense-impairment | 129 | anomaly | DC0016, DC0032 |
| 43 | [AN1543](https://attack.mitre.org/detectionstrategies/DET0560#AN1543) | Windows | T1078 Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 129 | anomaly | DC0002, DC0032, DC0067 |
| 44 | [AN0324](https://attack.mitre.org/detectionstrategies/DET0117#AN0324) | Windows | T1036.004 Masquerade Task or Service | stealth | 126 | anomaly | DC0001, DC0032, DC0060 |
| 45 | [AN0434](https://attack.mitre.org/detectionstrategies/DET0151#AN0434) | Network Devices | T1124 System Time Discovery | discovery | 122 | hunting | DC0061, DC0064 |
| 46 | [AN0105](https://attack.mitre.org/detectionstrategies/DET0037#AN0105) | Windows | T1555.003 Credentials from Web Browsers | credential-access | 119 | ttp | DC0032, DC0035, DC0055 |
| 47 | [AN1057](https://attack.mitre.org/detectionstrategies/DET0376#AN1057) | Windows | T1046 Network Service Discovery | discovery | 118 | hunting | DC0032, DC0082 |
| 48 | [AN0536](https://attack.mitre.org/detectionstrategies/DET0188#AN0536) | Windows | T1680 Local Storage Discovery | discovery | 116 | hunting | DC0032 |
| 49 | [AN1496](https://attack.mitre.org/detectionstrategies/DET0543#AN1496) | Windows | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0016, DC0082 |
| 50 | [AN1500](https://attack.mitre.org/detectionstrategies/DET0543#AN1500) | Network Devices | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0078, DC0085 |
| 51 | [AN0931](https://attack.mitre.org/detectionstrategies/DET0327#AN0931) | Windows | T1021.001 Remote Desktop Protocol | lateral-movement | 114 | anomaly | DC0032, DC0067, DC0082, DC0088 |
| 52 | [AN1394](https://attack.mitre.org/detectionstrategies/DET0505#AN1394) | Windows | T1027.010 Command Obfuscation | stealth | 112 | anomaly | DC0032 |
| 53 | [AN0602](https://attack.mitre.org/detectionstrategies/DET0215#AN0602) | Windows | T1486 Data Encrypted for Impact | impact | 111 | anomaly | DC0032, DC0039, DC0061 |
| 54 | [AN1399](https://attack.mitre.org/detectionstrategies/DET0508#AN1399) | Windows | T1055 Process Injection | stealth, privilege-escalation | 110 | anomaly | DC0016, DC0021, DC0032, DC0035 |
| 55 | [AN0797](https://attack.mitre.org/detectionstrategies/DET0287#AN0797) | Windows | T1203 Exploitation for Client Execution | execution | 108 | anomaly | DC0032, DC0038, DC0039, DC0082 |
| 56 | [AN1229](https://attack.mitre.org/detectionstrategies/DET0445#AN1229) | Windows | T1090 Proxy | command-and-control | 108 | anomaly | DC0032, DC0078, DC0082 |
| 57 | [AN1233](https://attack.mitre.org/detectionstrategies/DET0445#AN1233) | Network Devices | T1090 Proxy | command-and-control | 108 | ttp | DC0051, DC0064, DC0078 |
| 58 | [AN0531](https://attack.mitre.org/detectionstrategies/DET0186#AN0531) | Windows | T1119 Automated Collection | collection | 106 | anomaly | DC0032, DC0039 |
| 59 | [AN1468](https://attack.mitre.org/detectionstrategies/DET0530#AN1468) | Windows | T1021.002 SMB/Windows Admin Shares | lateral-movement | 103 | ttp | DC0032, DC0067, DC0082 |
| 60 | [AN0363](https://attack.mitre.org/detectionstrategies/DET0129#AN0363) | Windows | T1087.002 Domain Account | discovery | 96 | hunting | DC0032, DC0064, DC0085 |
| 61 | [AN0633](https://attack.mitre.org/detectionstrategies/DET0227#AN0633) | Windows | T1571 Non-Standard Port | command-and-control | 95 | anomaly | DC0032, DC0082 |
| 62 | [AN1084](https://attack.mitre.org/detectionstrategies/DET0384#AN1084) | Network Devices | T1059.004 Unix Shell | execution | 90 | ttp | DC0064, DC0082 |
| 63 | [AN0355](https://attack.mitre.org/detectionstrategies/DET0127#AN0355) | Windows | T1036 Masquerading | stealth | 89 | ttp | DC0032, DC0060 |
| 64 | [AN1325](https://attack.mitre.org/detectionstrategies/DET0483#AN1325) | Windows | T1007 System Service Discovery | discovery | 88 | hunting | DC0032, DC0064 |
| 65 | [AN0846](https://attack.mitre.org/detectionstrategies/DET0303#AN0846) | Windows | T1087.001 Local Account | discovery | 87 | hunting | DC0032 |
| 66 | [AN0516](https://attack.mitre.org/detectionstrategies/DET0183#AN0516) | Windows | T1570 Lateral Tool Transfer | lateral-movement | 83 | ttp | DC0032, DC0039, DC0102 |
| 67 | [AN0360](https://attack.mitre.org/detectionstrategies/DET0128#AN0360) | Windows | T1564.003 Hidden Window | stealth | 81 | ttp | DC0032, DC0063 |
| 68 | [AN0478](https://attack.mitre.org/detectionstrategies/DET0168#AN0478) | Windows | T1497.001 System Checks | stealth, discovery | 81 | ttp | DC0016, DC0032, DC0035 |
| 69 | [AN1004](https://attack.mitre.org/detectionstrategies/DET0354#AN1004) | Windows | T1133 External Remote Services | persistence, initial-access | 81 | anomaly | DC0002, DC0038, DC0082 |
| 70 | [AN0498](https://attack.mitre.org/detectionstrategies/DET0176#AN0498) | Windows | T1189 Drive-by Compromise | initial-access | 79 | anomaly | DC0020, DC0032, DC0038, DC0039, DC0067, DC0082, DC0085 |
| 71 | [AN1095](https://attack.mitre.org/detectionstrategies/DET0389#AN1095) | Windows | T1055.001 Dynamic-link Library Injection | stealth, privilege-escalation | 78 | anomaly | DC0016, DC0032, DC0035, DC0048 |
| 72 | [AN0091](https://attack.mitre.org/detectionstrategies/DET0032#AN0091) | Windows | T1564.001 Hidden Files and Directories | stealth | 76 | ttp | DC0032, DC0039 |
| 73 | [AN1626](https://attack.mitre.org/detectionstrategies/DET0591#AN1626) | Windows | T1070.006 Timestomp | stealth | 74 | anomaly | DC0021, DC0055, DC0059 |
| 74 | [AN1571](https://attack.mitre.org/detectionstrategies/DET0570#AN1571) | Windows | T1567.002 Exfiltration to Cloud Storage | exfiltration | 72 | anomaly | DC0032, DC0055, DC0082 |
| 75 | [AN1189](https://attack.mitre.org/detectionstrategies/DET0425#AN1189) | Windows | T1102 Web Service | command-and-control | 71 | anomaly | DC0082, DC0085 |
| 76 | [AN1458](https://attack.mitre.org/detectionstrategies/DET0526#AN1458) | Windows | T1560 Archive Collected Data | collection | 70 | ttp | DC0016, DC0032, DC0039 |
| 77 | [AN1100](https://attack.mitre.org/detectionstrategies/DET0392#AN1100) | Windows | T1518 Software Discovery | discovery | 69 | hunting | DC0032, DC0064 |
| 78 | [AN1353](https://attack.mitre.org/detectionstrategies/DET0491#AN1353) | Windows | T1120 Peripheral Device Discovery | discovery | 69 | hunting | DC0032, DC0035 |
| 79 | [AN1419](https://attack.mitre.org/detectionstrategies/DET0514#AN1419) | Windows | T1068 Exploitation for Privilege Escalation | privilege-escalation | 69 | anomaly | DC0032, DC0079, DC0088 |
| 80 | [AN1121](https://attack.mitre.org/detectionstrategies/DET0400#AN1121) | Windows | T1071.004 DNS | command-and-control | 68 | anomaly | DC0082, DC0085 |
| 81 | [AN1124](https://attack.mitre.org/detectionstrategies/DET0400#AN1124) | Network Devices | T1071.004 DNS | command-and-control | 68 | anomaly | DC0085 |
| 82 | [AN0590](https://attack.mitre.org/detectionstrategies/DET0210#AN0590) | Windows | T1078.002 Domain Accounts | stealth, persistence, privilege-escalation, initial-access | 67 | anomaly | DC0032, DC0082, DC0088 |
| 83 | [AN1428](https://attack.mitre.org/detectionstrategies/DET0516#AN1428) | Windows | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0032 |
| 84 | [AN1432](https://attack.mitre.org/detectionstrategies/DET0516#AN1432) | Network Devices | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0002, DC0064 |
| 85 | [AN1483](https://attack.mitre.org/detectionstrategies/DET0538#AN1483) | Windows | T1572 Protocol Tunneling | command-and-control | 66 | anomaly | DC0032, DC0082 |
| 86 | [AN0936](https://attack.mitre.org/detectionstrategies/DET0329#AN0936) | Network Devices | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0064 |
| 87 | [AN1020](https://attack.mitre.org/detectionstrategies/DET0359#AN1020) | Windows | T1090.003 Multi-hop Proxy | command-and-control | 65 | ttp | DC0032, DC0078, DC0082 |
| 88 | [AN1024](https://attack.mitre.org/detectionstrategies/DET0359#AN1024) | Network Devices | T1090.003 Multi-hop Proxy | command-and-control | 65 | ttp | DC0004, DC0078, DC0085 |
| 89 | [AN0061](https://attack.mitre.org/detectionstrategies/DET0021#AN0061) | Windows | T1489 Service Stop | impact | 64 | ttp | DC0032, DC0041, DC0060, DC0088 |
| 90 | [AN1376](https://attack.mitre.org/detectionstrategies/DET0499#AN1376) | Windows | T1008 Fallback Channels | command-and-control | 64 | anomaly | DC0078, DC0082 |
| 91 | [AN0856](https://attack.mitre.org/detectionstrategies/DET0307#AN0856) | Windows | T1552.001 Credentials In Files | credential-access | 63 | ttp | DC0032, DC0039, DC0067 |
| 92 | [AN1198](https://attack.mitre.org/detectionstrategies/DET0430#AN1198) | Windows | T1555 Credentials from Password Stores | credential-access | 58 | ttp | DC0032, DC0035, DC0055 |
| 93 | [AN1551](https://attack.mitre.org/detectionstrategies/DET0562#AN1551) | Windows | T1480 Execution Guardrails | stealth | 58 | anomaly | DC0002, DC0008, DC0016, DC0020, DC0032, DC0039, DC0063, DC0064, DC0067, DC0082 |
| 94 | [AN1025](https://attack.mitre.org/detectionstrategies/DET0360#AN1025) | Windows | T1069.002 Domain Groups | discovery | 54 | hunting | DC0032, DC0064 |
| 95 | [AN0782](https://attack.mitre.org/detectionstrategies/DET0281#AN0782) | Windows | T1027.015 Compression | stealth | 52 | ttp | DC0032, DC0039 |
| 96 | [AN1076](https://attack.mitre.org/detectionstrategies/DET0382#AN1076) | Windows | T1055.012 Process Hollowing | stealth, privilege-escalation | 52 | anomaly | DC0020, DC0021, DC0032, DC0035 |
| 97 | [AN0396](https://attack.mitre.org/detectionstrategies/DET0141#AN0396) | Windows | T1497.003 Time Based Checks | stealth, discovery | 51 | ttp | DC0016, DC0032 |
| 98 | [AN0965](https://attack.mitre.org/detectionstrategies/DET0341#AN0965) | Windows | T1115 Clipboard Data | collection | 51 | ttp | DC0032, DC0035 |
| 99 | [AN0411](https://attack.mitre.org/detectionstrategies/DET0146#AN0411) | Windows | T1485 Data Destruction | impact | 50 | anomaly | DC0032, DC0039, DC0040 |
| 100 | [AN1611](https://attack.mitre.org/detectionstrategies/DET0586#AN1611) | Windows | T1003.003 NTDS | credential-access | 50 | ttp | DC0032, DC0039, DC0061, DC0097 |
| 101 | [AN0208](https://attack.mitre.org/detectionstrategies/DET0075#AN0208) | Network Devices | T1090.001 Internal Proxy | command-and-control | 49 | ttp | DC0051, DC0064, DC0078 |
| 102 | [AN0785](https://attack.mitre.org/detectionstrategies/DET0282#AN0785) | Windows | T1218.010 Regsvr32 | stealth | 49 | anomaly | DC0016, DC0032, DC0082 |
| 103 | [AN1235](https://attack.mitre.org/detectionstrategies/DET0447#AN1235) | Windows | T1136.001 Local Account | persistence | 49 | ttp | DC0014, DC0032 |
| 104 | [AN1240](https://attack.mitre.org/detectionstrategies/DET0447#AN1240) | Network Devices | T1136.001 Local Account | persistence | 49 | ttp | DC0014 |
| 105 | [AN1397](https://attack.mitre.org/detectionstrategies/DET0506#AN1397) | Windows | T1218.005 Mshta | stealth | 49 | anomaly | DC0032, DC0039, DC0082 |
| 106 | [AN0423](https://attack.mitre.org/detectionstrategies/DET0149#AN0423) | Windows | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 48 | anomaly | DC0032, DC0055, DC0082, DC0085 |
| 107 | [AN0427](https://attack.mitre.org/detectionstrategies/DET0149#AN0427) | Network Devices | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 48 | ttp | DC0064, DC0078, DC0085 |
| 108 | [AN1361](https://attack.mitre.org/detectionstrategies/DET0495#AN1361) | Windows | T1657 Financial Theft | impact | 48 | anomaly | DC0032, DC0067 |
| 109 | [AN0016](https://attack.mitre.org/detectionstrategies/DET0007#AN0016) | Windows | T1482 Domain Trust Discovery | discovery | 47 | hunting | DC0016, DC0032, DC0035, DC0064, DC0071 |
| 110 | [AN1213](https://attack.mitre.org/detectionstrategies/DET0438#AN1213) | Windows | T1560.003 Archive via Custom Method | collection | 47 | anomaly | DC0032, DC0035, DC0039 |
| 111 | [AN0406](https://attack.mitre.org/detectionstrategies/DET0145#AN0406) | Windows | T1686 Disable or Modify System Firewall | defense-impairment | 45 | ttp | DC0032, DC0063 |
| 112 | [AN0410](https://attack.mitre.org/detectionstrategies/DET0145#AN0410) | Network Devices | T1686 Disable or Modify System Firewall | defense-impairment | 45 | ttp | DC0051 |
| 113 | [AN1275](https://attack.mitre.org/detectionstrategies/DET0463#AN1275) | Windows | T1110 Brute Force | credential-access | 45 | anomaly | DC0002 |
| 114 | [AN0317](https://attack.mitre.org/detectionstrategies/DET0114#AN0317) | Windows | T1069.001 Local Groups | discovery | 43 | hunting | DC0032 |
| 115 | [AN0331](https://attack.mitre.org/detectionstrategies/DET0119#AN0331) | Windows | T1027.003 Steganography | stealth | 43 | ttp | DC0032, DC0055, DC0082 |
| 116 | [AN1113](https://attack.mitre.org/detectionstrategies/DET0397#AN1113) | Windows | T1020 Automated Exfiltration | exfiltration | 43 | ttp | DC0032, DC0082 |
| 117 | [AN1137](https://attack.mitre.org/detectionstrategies/DET0407#AN1137) | Windows | T1078.003 Local Accounts | stealth, persistence, privilege-escalation, initial-access | 43 | anomaly | DC0067, DC0088 |
| 118 | [AN0037](https://attack.mitre.org/detectionstrategies/DET0013#AN0037) | Windows | T1217 Browser Information Discovery | discovery | 42 | hunting | DC0032, DC0039, DC0064 |
| 119 | [AN1061](https://attack.mitre.org/detectionstrategies/DET0377#AN1061) | Windows | T1014 Rootkit | stealth | 42 | ttp | DC0039, DC0060, DC0079 |
| 120 | [AN0271](https://attack.mitre.org/detectionstrategies/DET0097#AN0271) | Windows | T1010 Application Window Discovery | discovery | 40 | hunting | DC0035, DC0064 |
| 121 | [AN0327](https://attack.mitre.org/detectionstrategies/DET0118#AN0327) | Windows | T1210 Exploitation of Remote Services | lateral-movement | 39 | anomaly | DC0016, DC0032, DC0035, DC0038, DC0039, DC0082, DC0085 |
| 122 | [AN0445](https://attack.mitre.org/detectionstrategies/DET0158#AN0445) | Windows | T1218.007 Msiexec | stealth | 39 | ttp | DC0016, DC0032, DC0082 |
| 123 | [AN0520](https://attack.mitre.org/detectionstrategies/DET0184#AN0520) | Windows | T1070 Indicator Removal | stealth | 39 | ttp | DC0038, DC0040, DC0063 |
| 124 | [AN0568](https://attack.mitre.org/detectionstrategies/DET0197#AN0568) | Windows | T1125 Video Capture | collection | 39 | anomaly | DC0016, DC0021, DC0032, DC0034, DC0039, DC0082 |
| 125 | [AN0875](https://attack.mitre.org/detectionstrategies/DET0314#AN0875) | Windows | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0032, DC0060 |
| 126 | [AN0879](https://attack.mitre.org/detectionstrategies/DET0314#AN0879) | Network Devices | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0002, DC0064, DC0085 |
| 127 | [AN0922](https://attack.mitre.org/detectionstrategies/DET0325#AN0922) | Windows | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0032, DC0082, DC0085 |
| 128 | [AN0926](https://attack.mitre.org/detectionstrategies/DET0325#AN0926) | Network Devices | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0051, DC0078, DC0082 |
| 129 | [AN1015](https://attack.mitre.org/detectionstrategies/DET0357#AN1015) | Windows | T1016.001 Internet Connection Discovery | discovery | 39 | hunting | DC0032, DC0064, DC0082 |
| 130 | [AN1402](https://attack.mitre.org/detectionstrategies/DET0509#AN1402) | Windows | T1539 Steal Web Session Cookie | credential-access | 39 | ttp | DC0032, DC0035, DC0061 |
| 131 | [AN1528](https://attack.mitre.org/detectionstrategies/DET0553#AN1528) | Windows | T1027.001 Binary Padding | stealth | 39 | anomaly | DC0032, DC0039, DC0055 |
| 132 | [AN0109](https://attack.mitre.org/detectionstrategies/DET0039#AN0109) | Windows | T1568 Dynamic Resolution | command-and-control | 38 | anomaly | DC0032, DC0082 |
| 133 | [AN1999](https://attack.mitre.org/detectionstrategies/DET0867#AN1999) | PRE | T1595.002 Vulnerability Scanning | reconnaissance | 38 | hunting | DC0078, DC0085 |
| 134 | [AN0236](https://attack.mitre.org/detectionstrategies/DET0086#AN0236) | Windows | T1546.003 Windows Management Instrumentation Event Subscription | privilege-escalation, persistence | 37 | anomaly | DC0008, DC0016, DC0032 |
| 135 | [AN1366](https://attack.mitre.org/detectionstrategies/DET0496#AN1366) | Windows | T1219 Remote Access Tools | command-and-control | 37 | ttp | DC0032, DC0039, DC0056, DC0060, DC0063, DC0082 |
| 136 | [AN1538](https://attack.mitre.org/detectionstrategies/DET0559#AN1538) | Windows | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0032 |
| 137 | [AN1542](https://attack.mitre.org/detectionstrategies/DET0559#AN1542) | Network Devices | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0064 |
| 138 | [AN0841](https://attack.mitre.org/detectionstrategies/DET0301#AN0841) | Windows | T1091 Replication Through Removable Media | lateral-movement, initial-access | 36 | anomaly | DC0032, DC0039, DC0042, DC0055 |
| 139 | [AN1144](https://attack.mitre.org/detectionstrategies/DET0409#AN1144) | Windows | T1550.002 Pass the Hash | lateral-movement | 36 | anomaly | DC0032, DC0067, DC0082, DC0084 |
| 140 | [AN1169](https://attack.mitre.org/detectionstrategies/DET0416#AN1169) | Windows | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0032, DC0082, DC0085 |
| 141 | [AN1173](https://attack.mitre.org/detectionstrategies/DET0416#AN1173) | Network Devices | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0085 |
| 142 | [AN1516](https://attack.mitre.org/detectionstrategies/DET0549#AN1516) | Windows | T1552.004 Private Keys | credential-access | 36 | ttp | DC0032, DC0039, DC0102 |
| 143 | [AN1519](https://attack.mitre.org/detectionstrategies/DET0549#AN1519) | Network Devices | T1552.004 Private Keys | credential-access | 36 | ttp | DC0064 |
| 144 | [AN0973](https://attack.mitre.org/detectionstrategies/DET0344#AN0973) | Windows | T1027.011 Fileless Storage | stealth | 35 | anomaly | DC0008, DC0063 |
| 145 | [AN0619](https://attack.mitre.org/detectionstrategies/DET0221#AN0619) | Windows | T1123 Audio Capture | collection | 34 | anomaly | DC0032, DC0035, DC0039 |
| 146 | [AN0913](https://attack.mitre.org/detectionstrategies/DET0322#AN0913) | Windows | T1027.016 Junk Code Insertion | stealth | 34 | anomaly | DC0032, DC0035, DC0039 |
| 147 | [AN1336](https://attack.mitre.org/detectionstrategies/DET0487#AN1336) | Windows | T1110.003 Password Spraying | credential-access | 34 | anomaly | DC0002 |
| 148 | [AN1340](https://attack.mitre.org/detectionstrategies/DET0487#AN1340) | Network Devices | T1110.003 Password Spraying | credential-access | 34 | ttp | DC0002 |
| 149 | [AN0320](https://attack.mitre.org/detectionstrategies/DET0115#AN0320) | Windows | T1566.003 Spearphishing via Service | initial-access | 33 | ttp | DC0032, DC0039, DC0082 |
| 150 | [AN0510](https://attack.mitre.org/detectionstrategies/DET0180#AN0510) | Windows | T1547.009 Shortcut Modification | persistence, privilege-escalation | 33 | anomaly | DC0032, DC0039, DC0059, DC0061 |

## Waiting on a feed

Analytics that become implementable when you tick the feeds in [gaps](../gaps.md):

| Platform | Analytics ready |
|---|---|
| Linux | 357 |
| ESXi | 107 |
| Containers | 35 |
| Windows | 32 |
| Identity Provider | 21 |
| Network Devices | 9 |
| Office Suite | 2 |
| SaaS | 1 |
