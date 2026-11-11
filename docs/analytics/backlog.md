# Analytic backlog (ATT&CK v20.1)

Unimplemented analytics whose log sources are all on ticked feeds, ranked by technique prevalence (2 × groups + 2 × campaigns + software using the technique). The suggested content type is a heuristic starting point.

Live and unimplemented: **479**. Showing the top 150.

| # | Analytic | Platforms | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|---|
| 1 | [AN1452](https://attack.mitre.org/detectionstrategies/DET0525#AN1452) | Windows | T1082 System Information Discovery | discovery | 511 | hunting | DC0032, DC0063, DC0064 |
| 2 | [AN1457](https://attack.mitre.org/detectionstrategies/DET0525#AN1457) | Network Devices | T1082 System Information Discovery | discovery | 511 | hunting | DC0064 |
| 3 | [AN0075](https://attack.mitre.org/detectionstrategies/DET0027#AN0075) | Windows | T1071.001 Web Protocols | command-and-control | 510 | anomaly | DC0082, DC0085 |
| 4 | [AN0079](https://attack.mitre.org/detectionstrategies/DET0027#AN0079) | Network Devices | T1071.001 Web Protocols | command-and-control | 510 | ttp | DC0085 |
| 5 | [AN1040](https://attack.mitre.org/detectionstrategies/DET0370#AN1040) | Windows | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0032, DC0039 |
| 6 | [AN1044](https://attack.mitre.org/detectionstrategies/DET0370#AN1044) | Network Devices | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0064 |
| 7 | [AN0392](https://attack.mitre.org/detectionstrategies/DET0140#AN0392) | Windows | T1070.004 File Deletion | stealth | 380 | anomaly | DC0040, DC0055, DC0064 |
| 8 | [AN0095](https://attack.mitre.org/detectionstrategies/DET0034#AN0095) | Windows | T1057 Process Discovery | discovery | 379 | hunting | DC0032, DC0035 |
| 9 | [AN0099](https://attack.mitre.org/detectionstrategies/DET0034#AN0099) | Network Devices | T1057 Process Discovery | discovery | 379 | hunting | DC0034, DC0064 |
| 10 | [AN0559](https://attack.mitre.org/detectionstrategies/DET0195#AN0559) | Windows | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0032, DC0064 |
| 11 | [AN0563](https://attack.mitre.org/detectionstrategies/DET0195#AN0563) | Network Devices | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0064 |
| 12 | [AN0237](https://attack.mitre.org/detectionstrategies/DET0087#AN0237) | Windows | T1027.013 Encrypted/Encoded File | stealth | 310 | ttp | DC0016, DC0032, DC0035 |
| 13 | [AN0254](https://attack.mitre.org/detectionstrategies/DET0093#AN0254) | Windows | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0032, DC0064 |
| 14 | [AN0257](https://attack.mitre.org/detectionstrategies/DET0093#AN0257) | Network Devices | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0021, DC0064 |
| 15 | [AN1070](https://attack.mitre.org/detectionstrategies/DET0380#AN1070) | Windows | T1005 Data from Local System | collection | 298 | ttp | DC0032, DC0039 |
| 16 | [AN1073](https://attack.mitre.org/detectionstrategies/DET0380#AN1073) | Network Devices | T1005 Data from Local System | collection | 298 | ttp | DC0064 |
| 17 | [AN1465](https://attack.mitre.org/detectionstrategies/DET0529#AN1465) | Windows | T1106 Native API | execution | 262 | ttp | DC0016, DC0032, DC0035 |
| 18 | [AN0988](https://attack.mitre.org/detectionstrategies/DET0348#AN0988) | Windows | T1041 Exfiltration Over C2 Channel | exfiltration | 249 | ttp | DC0032, DC0055, DC0082, DC0085 |
| 19 | [AN1031](https://attack.mitre.org/detectionstrategies/DET0364#AN1031) | Windows | T1047 Windows Management Instrumentation | execution | 204 | anomaly | DC0008, DC0032, DC0082 |
| 20 | [AN0400](https://attack.mitre.org/detectionstrategies/DET0143#AN0400) | Windows | T1573.001 Symmetric Cryptography | command-and-control | 203 | anomaly | DC0016, DC0082 |
| 21 | [AN0404](https://attack.mitre.org/detectionstrategies/DET0143#AN0404) | Network Devices | T1573.001 Symmetric Cryptography | command-and-control | 203 | anomaly | DC0078, DC0085 |
| 22 | [AN0980](https://attack.mitre.org/detectionstrategies/DET0346#AN0980) | Windows | T1113 Screen Capture | collection | 192 | anomaly | DC0016, DC0032 |
| 23 | [AN1064](https://attack.mitre.org/detectionstrategies/DET0378#AN1064) | Windows | T1027 Obfuscated Files or Information | stealth | 188 | anomaly | DC0032, DC0039 |
| 24 | [AN1067](https://attack.mitre.org/detectionstrategies/DET0378#AN1067) | Network Devices | T1027 Obfuscated Files or Information | stealth | 188 | ttp | DC0085 |
| 25 | [AN0724](https://attack.mitre.org/detectionstrategies/DET0261#AN0724) | Windows | T1074.001 Local Data Staging | collection | 186 | ttp | DC0032, DC0039, DC0055 |
| 26 | [AN0243](https://attack.mitre.org/detectionstrategies/DET0089#AN0243) | Windows | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0035, DC0055, DC0060, DC0063 |
| 27 | [AN0246](https://attack.mitre.org/detectionstrategies/DET0089#AN0246) | Network Devices | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0004, DC0085 |
| 28 | [AN1374](https://attack.mitre.org/detectionstrategies/DET0497#AN1374) | Network Devices | T1685 Disable or Modify Tools | defense-impairment | 173 | ttp | DC0018, DC0041 |
| 29 | [AN0048](https://attack.mitre.org/detectionstrategies/DET0016#AN0048) | Windows | T1518.001 Security Software Discovery | discovery | 172 | hunting | DC0016, DC0032 |
| 30 | [AN0577](https://attack.mitre.org/detectionstrategies/DET0201#AN0577) | Windows | T1574.001 DLL | stealth, execution | 162 | anomaly | DC0016, DC0032, DC0039, DC0059, DC0063 |
| 31 | [AN1583](https://attack.mitre.org/detectionstrategies/DET0574#AN1583) | Windows | T1018 Remote System Discovery | discovery | 161 | hunting | DC0032, DC0082 |
| 32 | [AN1587](https://attack.mitre.org/detectionstrategies/DET0574#AN1587) | Network Devices | T1018 Remote System Discovery | discovery | 161 | hunting | DC0064 |
| 33 | [AN0178](https://attack.mitre.org/detectionstrategies/DET0066#AN0178) | Windows | T1204.001 Malicious Link | execution | 149 | ttp | DC0032, DC0039, DC0082, DC0085 |
| 34 | [AN0589](https://attack.mitre.org/detectionstrategies/DET0209#AN0589) | Windows | T1012 Query Registry | discovery | 141 | hunting | DC0032, DC0063, DC0064 |
| 35 | [AN0903](https://attack.mitre.org/detectionstrategies/DET0320#AN0903) | Windows | T1049 System Network Connections Discovery | discovery | 137 | hunting | DC0032, DC0064 |
| 36 | [AN0066](https://attack.mitre.org/detectionstrategies/DET0023#AN0066) | Windows | T1027.002 Software Packing | stealth | 136 | ttp | DC0032, DC0035 |
| 37 | [AN1254](https://attack.mitre.org/detectionstrategies/DET0457#AN1254) | Windows | T1095 Non-Application Layer Protocol | command-and-control | 130 | anomaly | DC0082, DC0085 |
| 38 | [AN1258](https://attack.mitre.org/detectionstrategies/DET0457#AN1258) | Network Devices | T1095 Non-Application Layer Protocol | command-and-control | 130 | anomaly | DC0078, DC0085 |
| 39 | [AN0643](https://attack.mitre.org/detectionstrategies/DET0230#AN0643) | Windows | T1553.002 Code Signing | defense-impairment | 129 | anomaly | DC0016, DC0032 |
| 40 | [AN0324](https://attack.mitre.org/detectionstrategies/DET0117#AN0324) | Windows | T1036.004 Masquerade Task or Service | stealth | 126 | anomaly | DC0001, DC0032, DC0060 |
| 41 | [AN0434](https://attack.mitre.org/detectionstrategies/DET0151#AN0434) | Network Devices | T1124 System Time Discovery | discovery | 122 | hunting | DC0061, DC0064 |
| 42 | [AN1057](https://attack.mitre.org/detectionstrategies/DET0376#AN1057) | Windows | T1046 Network Service Discovery | discovery | 118 | hunting | DC0032, DC0082 |
| 43 | [AN0536](https://attack.mitre.org/detectionstrategies/DET0188#AN0536) | Windows | T1680 Local Storage Discovery | discovery | 116 | hunting | DC0032 |
| 44 | [AN1496](https://attack.mitre.org/detectionstrategies/DET0543#AN1496) | Windows | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0016, DC0082 |
| 45 | [AN1500](https://attack.mitre.org/detectionstrategies/DET0543#AN1500) | Network Devices | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0078, DC0085 |
| 46 | [AN0797](https://attack.mitre.org/detectionstrategies/DET0287#AN0797) | Windows | T1203 Exploitation for Client Execution | execution | 108 | anomaly | DC0032, DC0038, DC0039, DC0082 |
| 47 | [AN1229](https://attack.mitre.org/detectionstrategies/DET0445#AN1229) | Windows | T1090 Proxy | command-and-control | 108 | anomaly | DC0032, DC0078, DC0082 |
| 48 | [AN1233](https://attack.mitre.org/detectionstrategies/DET0445#AN1233) | Network Devices | T1090 Proxy | command-and-control | 108 | ttp | DC0051, DC0064, DC0078 |
| 49 | [AN0531](https://attack.mitre.org/detectionstrategies/DET0186#AN0531) | Windows | T1119 Automated Collection | collection | 106 | anomaly | DC0032, DC0039 |
| 50 | [AN0363](https://attack.mitre.org/detectionstrategies/DET0129#AN0363) | Windows | T1087.002 Domain Account | discovery | 96 | hunting | DC0032, DC0064, DC0085 |
| 51 | [AN0633](https://attack.mitre.org/detectionstrategies/DET0227#AN0633) | Windows | T1571 Non-Standard Port | command-and-control | 95 | anomaly | DC0032, DC0082 |
| 52 | [AN1084](https://attack.mitre.org/detectionstrategies/DET0384#AN1084) | Network Devices | T1059.004 Unix Shell | execution | 90 | ttp | DC0064, DC0082 |
| 53 | [AN1325](https://attack.mitre.org/detectionstrategies/DET0483#AN1325) | Windows | T1007 System Service Discovery | discovery | 88 | hunting | DC0032, DC0064 |
| 54 | [AN0846](https://attack.mitre.org/detectionstrategies/DET0303#AN0846) | Windows | T1087.001 Local Account | discovery | 87 | hunting | DC0032 |
| 55 | [AN0516](https://attack.mitre.org/detectionstrategies/DET0183#AN0516) | Windows | T1570 Lateral Tool Transfer | lateral-movement | 83 | ttp | DC0032, DC0039, DC0102 |
| 56 | [AN0478](https://attack.mitre.org/detectionstrategies/DET0168#AN0478) | Windows | T1497.001 System Checks | stealth, discovery | 81 | ttp | DC0016, DC0032, DC0035 |
| 57 | [AN1004](https://attack.mitre.org/detectionstrategies/DET0354#AN1004) | Windows | T1133 External Remote Services | persistence, initial-access | 81 | anomaly | DC0002, DC0038, DC0082 |
| 58 | [AN0498](https://attack.mitre.org/detectionstrategies/DET0176#AN0498) | Windows | T1189 Drive-by Compromise | initial-access | 79 | anomaly | DC0020, DC0032, DC0038, DC0039, DC0067, DC0082, DC0085 |
| 59 | [AN1095](https://attack.mitre.org/detectionstrategies/DET0389#AN1095) | Windows | T1055.001 Dynamic-link Library Injection | stealth, privilege-escalation | 78 | anomaly | DC0016, DC0032, DC0035, DC0048 |
| 60 | [AN0091](https://attack.mitre.org/detectionstrategies/DET0032#AN0091) | Windows | T1564.001 Hidden Files and Directories | stealth | 76 | ttp | DC0032, DC0039 |
| 61 | [AN1626](https://attack.mitre.org/detectionstrategies/DET0591#AN1626) | Windows | T1070.006 Timestomp | stealth | 74 | anomaly | DC0021, DC0055, DC0059 |
| 62 | [AN1571](https://attack.mitre.org/detectionstrategies/DET0570#AN1571) | Windows | T1567.002 Exfiltration to Cloud Storage | exfiltration | 72 | anomaly | DC0032, DC0055, DC0082 |
| 63 | [AN1189](https://attack.mitre.org/detectionstrategies/DET0425#AN1189) | Windows | T1102 Web Service | command-and-control | 71 | anomaly | DC0082, DC0085 |
| 64 | [AN1458](https://attack.mitre.org/detectionstrategies/DET0526#AN1458) | Windows | T1560 Archive Collected Data | collection | 70 | ttp | DC0016, DC0032, DC0039 |
| 65 | [AN1100](https://attack.mitre.org/detectionstrategies/DET0392#AN1100) | Windows | T1518 Software Discovery | discovery | 69 | hunting | DC0032, DC0064 |
| 66 | [AN1353](https://attack.mitre.org/detectionstrategies/DET0491#AN1353) | Windows | T1120 Peripheral Device Discovery | discovery | 69 | hunting | DC0032, DC0035 |
| 67 | [AN1419](https://attack.mitre.org/detectionstrategies/DET0514#AN1419) | Windows | T1068 Exploitation for Privilege Escalation | privilege-escalation | 69 | anomaly | DC0032, DC0079, DC0088 |
| 68 | [AN1121](https://attack.mitre.org/detectionstrategies/DET0400#AN1121) | Windows | T1071.004 DNS | command-and-control | 68 | anomaly | DC0082, DC0085 |
| 69 | [AN1124](https://attack.mitre.org/detectionstrategies/DET0400#AN1124) | Network Devices | T1071.004 DNS | command-and-control | 68 | anomaly | DC0085 |
| 70 | [AN0590](https://attack.mitre.org/detectionstrategies/DET0210#AN0590) | Windows | T1078.002 Domain Accounts | stealth, persistence, privilege-escalation, initial-access | 67 | anomaly | DC0032, DC0082, DC0088 |
| 71 | [AN1428](https://attack.mitre.org/detectionstrategies/DET0516#AN1428) | Windows | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0032 |
| 72 | [AN1432](https://attack.mitre.org/detectionstrategies/DET0516#AN1432) | Network Devices | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0002, DC0064 |
| 73 | [AN0936](https://attack.mitre.org/detectionstrategies/DET0329#AN0936) | Network Devices | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0064 |
| 74 | [AN1020](https://attack.mitre.org/detectionstrategies/DET0359#AN1020) | Windows | T1090.003 Multi-hop Proxy | command-and-control | 65 | ttp | DC0032, DC0078, DC0082 |
| 75 | [AN1024](https://attack.mitre.org/detectionstrategies/DET0359#AN1024) | Network Devices | T1090.003 Multi-hop Proxy | command-and-control | 65 | ttp | DC0004, DC0078, DC0085 |
| 76 | [AN1376](https://attack.mitre.org/detectionstrategies/DET0499#AN1376) | Windows | T1008 Fallback Channels | command-and-control | 64 | anomaly | DC0078, DC0082 |
| 77 | [AN0856](https://attack.mitre.org/detectionstrategies/DET0307#AN0856) | Windows | T1552.001 Credentials In Files | credential-access | 63 | ttp | DC0032, DC0039, DC0067 |
| 78 | [AN1198](https://attack.mitre.org/detectionstrategies/DET0430#AN1198) | Windows | T1555 Credentials from Password Stores | credential-access | 58 | ttp | DC0032, DC0035, DC0055 |
| 79 | [AN1551](https://attack.mitre.org/detectionstrategies/DET0562#AN1551) | Windows | T1480 Execution Guardrails | stealth | 58 | anomaly | DC0002, DC0008, DC0016, DC0020, DC0032, DC0039, DC0063, DC0064, DC0067, DC0082 |
| 80 | [AN1025](https://attack.mitre.org/detectionstrategies/DET0360#AN1025) | Windows | T1069.002 Domain Groups | discovery | 54 | hunting | DC0032, DC0064 |
| 81 | [AN0782](https://attack.mitre.org/detectionstrategies/DET0281#AN0782) | Windows | T1027.015 Compression | stealth | 52 | ttp | DC0032, DC0039 |
| 82 | [AN1076](https://attack.mitre.org/detectionstrategies/DET0382#AN1076) | Windows | T1055.012 Process Hollowing | stealth, privilege-escalation | 52 | anomaly | DC0020, DC0021, DC0032, DC0035 |
| 83 | [AN0396](https://attack.mitre.org/detectionstrategies/DET0141#AN0396) | Windows | T1497.003 Time Based Checks | stealth, discovery | 51 | ttp | DC0016, DC0032 |
| 84 | [AN0965](https://attack.mitre.org/detectionstrategies/DET0341#AN0965) | Windows | T1115 Clipboard Data | collection | 51 | ttp | DC0032, DC0035 |
| 85 | [AN0411](https://attack.mitre.org/detectionstrategies/DET0146#AN0411) | Windows | T1485 Data Destruction | impact | 50 | anomaly | DC0032, DC0039, DC0040 |
| 86 | [AN1611](https://attack.mitre.org/detectionstrategies/DET0586#AN1611) | Windows | T1003.003 NTDS | credential-access | 50 | ttp | DC0032, DC0039, DC0061, DC0097 |
| 87 | [AN0208](https://attack.mitre.org/detectionstrategies/DET0075#AN0208) | Network Devices | T1090.001 Internal Proxy | command-and-control | 49 | ttp | DC0051, DC0064, DC0078 |
| 88 | [AN0785](https://attack.mitre.org/detectionstrategies/DET0282#AN0785) | Windows | T1218.010 Regsvr32 | stealth | 49 | anomaly | DC0016, DC0032, DC0082 |
| 89 | [AN1235](https://attack.mitre.org/detectionstrategies/DET0447#AN1235) | Windows | T1136.001 Local Account | persistence | 49 | ttp | DC0014, DC0032 |
| 90 | [AN1240](https://attack.mitre.org/detectionstrategies/DET0447#AN1240) | Network Devices | T1136.001 Local Account | persistence | 49 | ttp | DC0014 |
| 91 | [AN1397](https://attack.mitre.org/detectionstrategies/DET0506#AN1397) | Windows | T1218.005 Mshta | stealth | 49 | anomaly | DC0032, DC0039, DC0082 |
| 92 | [AN0423](https://attack.mitre.org/detectionstrategies/DET0149#AN0423) | Windows | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 48 | anomaly | DC0032, DC0055, DC0082, DC0085 |
| 93 | [AN0427](https://attack.mitre.org/detectionstrategies/DET0149#AN0427) | Network Devices | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 48 | ttp | DC0064, DC0078, DC0085 |
| 94 | [AN1361](https://attack.mitre.org/detectionstrategies/DET0495#AN1361) | Windows | T1657 Financial Theft | impact | 48 | anomaly | DC0032, DC0067 |
| 95 | [AN0016](https://attack.mitre.org/detectionstrategies/DET0007#AN0016) | Windows | T1482 Domain Trust Discovery | discovery | 47 | hunting | DC0016, DC0032, DC0035, DC0064, DC0071 |
| 96 | [AN1213](https://attack.mitre.org/detectionstrategies/DET0438#AN1213) | Windows | T1560.003 Archive via Custom Method | collection | 47 | anomaly | DC0032, DC0035, DC0039 |
| 97 | [AN0406](https://attack.mitre.org/detectionstrategies/DET0145#AN0406) | Windows | T1686 Disable or Modify System Firewall | defense-impairment | 45 | ttp | DC0032, DC0063 |
| 98 | [AN0410](https://attack.mitre.org/detectionstrategies/DET0145#AN0410) | Network Devices | T1686 Disable or Modify System Firewall | defense-impairment | 45 | ttp | DC0051 |
| 99 | [AN1275](https://attack.mitre.org/detectionstrategies/DET0463#AN1275) | Windows | T1110 Brute Force | credential-access | 45 | anomaly | DC0002 |
| 100 | [AN0317](https://attack.mitre.org/detectionstrategies/DET0114#AN0317) | Windows | T1069.001 Local Groups | discovery | 43 | hunting | DC0032 |
| 101 | [AN0331](https://attack.mitre.org/detectionstrategies/DET0119#AN0331) | Windows | T1027.003 Steganography | stealth | 43 | ttp | DC0032, DC0055, DC0082 |
| 102 | [AN1113](https://attack.mitre.org/detectionstrategies/DET0397#AN1113) | Windows | T1020 Automated Exfiltration | exfiltration | 43 | ttp | DC0032, DC0082 |
| 103 | [AN1137](https://attack.mitre.org/detectionstrategies/DET0407#AN1137) | Windows | T1078.003 Local Accounts | stealth, persistence, privilege-escalation, initial-access | 43 | anomaly | DC0067, DC0088 |
| 104 | [AN0037](https://attack.mitre.org/detectionstrategies/DET0013#AN0037) | Windows | T1217 Browser Information Discovery | discovery | 42 | hunting | DC0032, DC0039, DC0064 |
| 105 | [AN1061](https://attack.mitre.org/detectionstrategies/DET0377#AN1061) | Windows | T1014 Rootkit | stealth | 42 | ttp | DC0039, DC0060, DC0079 |
| 106 | [AN0271](https://attack.mitre.org/detectionstrategies/DET0097#AN0271) | Windows | T1010 Application Window Discovery | discovery | 40 | hunting | DC0035, DC0064 |
| 107 | [AN0327](https://attack.mitre.org/detectionstrategies/DET0118#AN0327) | Windows | T1210 Exploitation of Remote Services | lateral-movement | 39 | anomaly | DC0016, DC0032, DC0035, DC0038, DC0039, DC0082, DC0085 |
| 108 | [AN0445](https://attack.mitre.org/detectionstrategies/DET0158#AN0445) | Windows | T1218.007 Msiexec | stealth | 39 | ttp | DC0016, DC0032, DC0082 |
| 109 | [AN0520](https://attack.mitre.org/detectionstrategies/DET0184#AN0520) | Windows | T1070 Indicator Removal | stealth | 39 | ttp | DC0038, DC0040, DC0063 |
| 110 | [AN0568](https://attack.mitre.org/detectionstrategies/DET0197#AN0568) | Windows | T1125 Video Capture | collection | 39 | anomaly | DC0016, DC0021, DC0032, DC0034, DC0039, DC0082 |
| 111 | [AN0875](https://attack.mitre.org/detectionstrategies/DET0314#AN0875) | Windows | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0032, DC0060 |
| 112 | [AN0879](https://attack.mitre.org/detectionstrategies/DET0314#AN0879) | Network Devices | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0002, DC0064, DC0085 |
| 113 | [AN0922](https://attack.mitre.org/detectionstrategies/DET0325#AN0922) | Windows | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0032, DC0082, DC0085 |
| 114 | [AN0926](https://attack.mitre.org/detectionstrategies/DET0325#AN0926) | Network Devices | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0051, DC0078, DC0082 |
| 115 | [AN1015](https://attack.mitre.org/detectionstrategies/DET0357#AN1015) | Windows | T1016.001 Internet Connection Discovery | discovery | 39 | hunting | DC0032, DC0064, DC0082 |
| 116 | [AN1402](https://attack.mitre.org/detectionstrategies/DET0509#AN1402) | Windows | T1539 Steal Web Session Cookie | credential-access | 39 | ttp | DC0032, DC0035, DC0061 |
| 117 | [AN1528](https://attack.mitre.org/detectionstrategies/DET0553#AN1528) | Windows | T1027.001 Binary Padding | stealth | 39 | anomaly | DC0032, DC0039, DC0055 |
| 118 | [AN0109](https://attack.mitre.org/detectionstrategies/DET0039#AN0109) | Windows | T1568 Dynamic Resolution | command-and-control | 38 | anomaly | DC0032, DC0082 |
| 119 | [AN1999](https://attack.mitre.org/detectionstrategies/DET0867#AN1999) | PRE | T1595.002 Vulnerability Scanning | reconnaissance | 38 | hunting | DC0078, DC0085 |
| 120 | [AN0236](https://attack.mitre.org/detectionstrategies/DET0086#AN0236) | Windows | T1546.003 Windows Management Instrumentation Event Subscription | privilege-escalation, persistence | 37 | anomaly | DC0008, DC0016, DC0032 |
| 121 | [AN1366](https://attack.mitre.org/detectionstrategies/DET0496#AN1366) | Windows | T1219 Remote Access Tools | command-and-control | 37 | ttp | DC0032, DC0039, DC0056, DC0060, DC0063, DC0082 |
| 122 | [AN1538](https://attack.mitre.org/detectionstrategies/DET0559#AN1538) | Windows | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0032 |
| 123 | [AN1542](https://attack.mitre.org/detectionstrategies/DET0559#AN1542) | Network Devices | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0064 |
| 124 | [AN0841](https://attack.mitre.org/detectionstrategies/DET0301#AN0841) | Windows | T1091 Replication Through Removable Media | lateral-movement, initial-access | 36 | anomaly | DC0032, DC0039, DC0042, DC0055 |
| 125 | [AN1144](https://attack.mitre.org/detectionstrategies/DET0409#AN1144) | Windows | T1550.002 Pass the Hash | lateral-movement | 36 | anomaly | DC0032, DC0067, DC0082, DC0084 |
| 126 | [AN1169](https://attack.mitre.org/detectionstrategies/DET0416#AN1169) | Windows | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0032, DC0082, DC0085 |
| 127 | [AN1173](https://attack.mitre.org/detectionstrategies/DET0416#AN1173) | Network Devices | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0085 |
| 128 | [AN1516](https://attack.mitre.org/detectionstrategies/DET0549#AN1516) | Windows | T1552.004 Private Keys | credential-access | 36 | ttp | DC0032, DC0039, DC0102 |
| 129 | [AN1519](https://attack.mitre.org/detectionstrategies/DET0549#AN1519) | Network Devices | T1552.004 Private Keys | credential-access | 36 | ttp | DC0064 |
| 130 | [AN0973](https://attack.mitre.org/detectionstrategies/DET0344#AN0973) | Windows | T1027.011 Fileless Storage | stealth | 35 | anomaly | DC0008, DC0063 |
| 131 | [AN0619](https://attack.mitre.org/detectionstrategies/DET0221#AN0619) | Windows | T1123 Audio Capture | collection | 34 | anomaly | DC0032, DC0035, DC0039 |
| 132 | [AN0913](https://attack.mitre.org/detectionstrategies/DET0322#AN0913) | Windows | T1027.016 Junk Code Insertion | stealth | 34 | anomaly | DC0032, DC0035, DC0039 |
| 133 | [AN1336](https://attack.mitre.org/detectionstrategies/DET0487#AN1336) | Windows | T1110.003 Password Spraying | credential-access | 34 | anomaly | DC0002 |
| 134 | [AN1340](https://attack.mitre.org/detectionstrategies/DET0487#AN1340) | Network Devices | T1110.003 Password Spraying | credential-access | 34 | ttp | DC0002 |
| 135 | [AN0320](https://attack.mitre.org/detectionstrategies/DET0115#AN0320) | Windows | T1566.003 Spearphishing via Service | initial-access | 33 | ttp | DC0032, DC0039, DC0082 |
| 136 | [AN0510](https://attack.mitre.org/detectionstrategies/DET0180#AN0510) | Windows | T1547.009 Shortcut Modification | persistence, privilege-escalation | 33 | anomaly | DC0032, DC0039, DC0059, DC0061 |
| 137 | [AN0648](https://attack.mitre.org/detectionstrategies/DET0234#AN0648) | Windows | T1003 OS Credential Dumping | credential-access | 33 | ttp | DC0032, DC0035, DC0055, DC0071 |
| 138 | [AN1946](https://attack.mitre.org/detectionstrategies/DET0814#AN1946) | PRE | T1589.002 Email Addresses | reconnaissance | 33 | hunting | DC0085 |
| 139 | [AN0379](https://attack.mitre.org/detectionstrategies/DET0135#AN0379) | Windows | T1071.003 Mail Protocols | command-and-control | 32 | ttp | DC0032, DC0082, DC0085 |
| 140 | [AN0382](https://attack.mitre.org/detectionstrategies/DET0135#AN0382) | Network Devices | T1071.003 Mail Protocols | command-and-control | 32 | ttp | DC0085 |
| 141 | [AN1393](https://attack.mitre.org/detectionstrategies/DET0504#AN1393) | Windows | T1559.002 Dynamic Data Exchange | execution | 32 | anomaly | DC0016, DC0032, DC0050 |
| 142 | [AN0127](https://attack.mitre.org/detectionstrategies/DET0046#AN0127) | Windows | T1497 Virtualization/Sandbox Evasion | stealth, discovery | 31 | ttp | DC0016, DC0032 |
| 143 | [AN0130](https://attack.mitre.org/detectionstrategies/DET0047#AN0130) | Windows | T1114.001 Local Email Collection | collection | 31 | ttp | DC0032, DC0039, DC0055, DC0082 |
| 144 | [AN0714](https://attack.mitre.org/detectionstrategies/DET0259#AN0714) | Windows | T1219.002 Remote Desktop Software | command-and-control | 31 | ttp | DC0039, DC0051, DC0082 |
| 145 | [AN0949](https://attack.mitre.org/detectionstrategies/DET0336#AN0949) | Windows | T1554 Compromise Host Software Binary | persistence | 31 | anomaly | DC0032, DC0039, DC0061 |
| 146 | [AN1212](https://attack.mitre.org/detectionstrategies/DET0437#AN1212) | Windows | T1003.004 LSA Secrets | credential-access | 31 | ttp | DC0016, DC0032, DC0035, DC0061 |
| 147 | [AN1048](https://attack.mitre.org/detectionstrategies/DET0372#AN1048) | Windows | T1678 Delay Execution | stealth | 30 | ttp | DC0016, DC0032 |
| 148 | [AN1344](https://attack.mitre.org/detectionstrategies/DET0488#AN1344) | Windows | T1199 Trusted Relationship | initial-access | 30 | ttp | DC0038, DC0067, DC0082, DC0088 |
| 149 | [AN0599](https://attack.mitre.org/detectionstrategies/DET0214#AN0599) | Windows | T1027.009 Embedded Payloads | stealth | 29 | anomaly | DC0032, DC0039, DC0059 |
| 150 | [AN0630](https://attack.mitre.org/detectionstrategies/DET0226#AN0630) | Windows | T1036.008 Masquerade File Type | stealth | 29 | anomaly | DC0032, DC0039 |

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
