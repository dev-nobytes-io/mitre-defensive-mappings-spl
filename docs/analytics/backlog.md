# Analytic backlog (ATT&CK v20.1)

Unimplemented analytics whose log sources are all on ticked feeds, ranked by technique prevalence (2 × groups + 2 × campaigns + software using the technique). The suggested content type is a heuristic starting point.

Live and unimplemented: **392**. Showing the top 150.

| # | Analytic | Platforms | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|---|
| 1 | [AN1457](https://attack.mitre.org/detectionstrategies/DET0525#AN1457) | Network Devices | T1082 System Information Discovery | discovery | 511 | hunting | DC0064 |
| 2 | [AN1044](https://attack.mitre.org/detectionstrategies/DET0370#AN1044) | Network Devices | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0064 |
| 3 | [AN0099](https://attack.mitre.org/detectionstrategies/DET0034#AN0099) | Network Devices | T1057 Process Discovery | discovery | 379 | hunting | DC0034, DC0064 |
| 4 | [AN0563](https://attack.mitre.org/detectionstrategies/DET0195#AN0563) | Network Devices | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0064 |
| 5 | [AN0257](https://attack.mitre.org/detectionstrategies/DET0093#AN0257) | Network Devices | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0021, DC0064 |
| 6 | [AN1073](https://attack.mitre.org/detectionstrategies/DET0380#AN1073) | Network Devices | T1005 Data from Local System | collection | 298 | ttp | DC0064 |
| 7 | [AN1465](https://attack.mitre.org/detectionstrategies/DET0529#AN1465) | Windows | T1106 Native API | execution | 262 | ttp | DC0016, DC0032, DC0035 |
| 8 | [AN0988](https://attack.mitre.org/detectionstrategies/DET0348#AN0988) | Windows | T1041 Exfiltration Over C2 Channel | exfiltration | 249 | ttp | DC0032, DC0055, DC0082, DC0085 |
| 9 | [AN0400](https://attack.mitre.org/detectionstrategies/DET0143#AN0400) | Windows | T1573.001 Symmetric Cryptography | command-and-control | 203 | anomaly | DC0016, DC0082 |
| 10 | [AN0243](https://attack.mitre.org/detectionstrategies/DET0089#AN0243) | Windows | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0035, DC0055, DC0060, DC0063 |
| 11 | [AN0246](https://attack.mitre.org/detectionstrategies/DET0089#AN0246) | Network Devices | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0004, DC0085 |
| 12 | [AN1587](https://attack.mitre.org/detectionstrategies/DET0574#AN1587) | Network Devices | T1018 Remote System Discovery | discovery | 161 | hunting | DC0064 |
| 13 | [AN0066](https://attack.mitre.org/detectionstrategies/DET0023#AN0066) | Windows | T1027.002 Software Packing | stealth | 136 | ttp | DC0032, DC0035 |
| 14 | [AN0434](https://attack.mitre.org/detectionstrategies/DET0151#AN0434) | Network Devices | T1124 System Time Discovery | discovery | 122 | hunting | DC0061, DC0064 |
| 15 | [AN1496](https://attack.mitre.org/detectionstrategies/DET0543#AN1496) | Windows | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0016, DC0082 |
| 16 | [AN1084](https://attack.mitre.org/detectionstrategies/DET0384#AN1084) | Network Devices | T1059.004 Unix Shell | execution | 90 | ttp | DC0064, DC0082 |
| 17 | [AN1004](https://attack.mitre.org/detectionstrategies/DET0354#AN1004) | Windows | T1133 External Remote Services | persistence, initial-access | 81 | anomaly | DC0002, DC0038, DC0082 |
| 18 | [AN0498](https://attack.mitre.org/detectionstrategies/DET0176#AN0498) | Windows | T1189 Drive-by Compromise | initial-access | 79 | anomaly | DC0020, DC0032, DC0038, DC0039, DC0067, DC0082, DC0085 |
| 19 | [AN1432](https://attack.mitre.org/detectionstrategies/DET0516#AN1432) | Network Devices | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0002, DC0064 |
| 20 | [AN0936](https://attack.mitre.org/detectionstrategies/DET0329#AN0936) | Network Devices | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0064 |
| 21 | [AN0208](https://attack.mitre.org/detectionstrategies/DET0075#AN0208) | Network Devices | T1090.001 Internal Proxy | command-and-control | 49 | ttp | DC0051, DC0064, DC0078 |
| 22 | [AN1361](https://attack.mitre.org/detectionstrategies/DET0495#AN1361) | Windows | T1657 Financial Theft | impact | 48 | anomaly | DC0032, DC0067 |
| 23 | [AN1213](https://attack.mitre.org/detectionstrategies/DET0438#AN1213) | Windows | T1560.003 Archive via Custom Method | collection | 47 | anomaly | DC0032, DC0035, DC0039 |
| 24 | [AN0317](https://attack.mitre.org/detectionstrategies/DET0114#AN0317) | Windows | T1069.001 Local Groups | discovery | 43 | hunting | DC0032 |
| 25 | [AN0331](https://attack.mitre.org/detectionstrategies/DET0119#AN0331) | Windows | T1027.003 Steganography | stealth | 43 | ttp | DC0032, DC0055, DC0082 |
| 26 | [AN1113](https://attack.mitre.org/detectionstrategies/DET0397#AN1113) | Windows | T1020 Automated Exfiltration | exfiltration | 43 | ttp | DC0032, DC0082 |
| 27 | [AN1137](https://attack.mitre.org/detectionstrategies/DET0407#AN1137) | Windows | T1078.003 Local Accounts | stealth, persistence, privilege-escalation, initial-access | 43 | anomaly | DC0067, DC0088 |
| 28 | [AN0037](https://attack.mitre.org/detectionstrategies/DET0013#AN0037) | Windows | T1217 Browser Information Discovery | discovery | 42 | hunting | DC0032, DC0039, DC0064 |
| 29 | [AN1061](https://attack.mitre.org/detectionstrategies/DET0377#AN1061) | Windows | T1014 Rootkit | stealth | 42 | ttp | DC0039, DC0060, DC0079 |
| 30 | [AN0271](https://attack.mitre.org/detectionstrategies/DET0097#AN0271) | Windows | T1010 Application Window Discovery | discovery | 40 | hunting | DC0035, DC0064 |
| 31 | [AN0327](https://attack.mitre.org/detectionstrategies/DET0118#AN0327) | Windows | T1210 Exploitation of Remote Services | lateral-movement | 39 | anomaly | DC0016, DC0032, DC0035, DC0038, DC0039, DC0082, DC0085 |
| 32 | [AN0445](https://attack.mitre.org/detectionstrategies/DET0158#AN0445) | Windows | T1218.007 Msiexec | stealth | 39 | ttp | DC0016, DC0032, DC0082 |
| 33 | [AN0520](https://attack.mitre.org/detectionstrategies/DET0184#AN0520) | Windows | T1070 Indicator Removal | stealth | 39 | ttp | DC0038, DC0040, DC0063 |
| 34 | [AN0568](https://attack.mitre.org/detectionstrategies/DET0197#AN0568) | Windows | T1125 Video Capture | collection | 39 | anomaly | DC0016, DC0021, DC0032, DC0034, DC0039, DC0082 |
| 35 | [AN0875](https://attack.mitre.org/detectionstrategies/DET0314#AN0875) | Windows | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0032, DC0060 |
| 36 | [AN0879](https://attack.mitre.org/detectionstrategies/DET0314#AN0879) | Network Devices | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0002, DC0064, DC0085 |
| 37 | [AN0922](https://attack.mitre.org/detectionstrategies/DET0325#AN0922) | Windows | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0032, DC0082, DC0085 |
| 38 | [AN1015](https://attack.mitre.org/detectionstrategies/DET0357#AN1015) | Windows | T1016.001 Internet Connection Discovery | discovery | 39 | hunting | DC0032, DC0064, DC0082 |
| 39 | [AN1402](https://attack.mitre.org/detectionstrategies/DET0509#AN1402) | Windows | T1539 Steal Web Session Cookie | credential-access | 39 | ttp | DC0032, DC0035, DC0061 |
| 40 | [AN1528](https://attack.mitre.org/detectionstrategies/DET0553#AN1528) | Windows | T1027.001 Binary Padding | stealth | 39 | anomaly | DC0032, DC0039, DC0055 |
| 41 | [AN0109](https://attack.mitre.org/detectionstrategies/DET0039#AN0109) | Windows | T1568 Dynamic Resolution | command-and-control | 38 | anomaly | DC0032, DC0082 |
| 42 | [AN1999](https://attack.mitre.org/detectionstrategies/DET0867#AN1999) | PRE | T1595.002 Vulnerability Scanning | reconnaissance | 38 | hunting | DC0078, DC0085 |
| 43 | [AN0236](https://attack.mitre.org/detectionstrategies/DET0086#AN0236) | Windows | T1546.003 Windows Management Instrumentation Event Subscription | privilege-escalation, persistence | 37 | anomaly | DC0008, DC0016, DC0032 |
| 44 | [AN1366](https://attack.mitre.org/detectionstrategies/DET0496#AN1366) | Windows | T1219 Remote Access Tools | command-and-control | 37 | ttp | DC0032, DC0039, DC0056, DC0060, DC0063, DC0082 |
| 45 | [AN1538](https://attack.mitre.org/detectionstrategies/DET0559#AN1538) | Windows | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0032 |
| 46 | [AN0841](https://attack.mitre.org/detectionstrategies/DET0301#AN0841) | Windows | T1091 Replication Through Removable Media | lateral-movement, initial-access | 36 | anomaly | DC0032, DC0039, DC0042, DC0055 |
| 47 | [AN1144](https://attack.mitre.org/detectionstrategies/DET0409#AN1144) | Windows | T1550.002 Pass the Hash | lateral-movement | 36 | anomaly | DC0032, DC0067, DC0082, DC0084 |
| 48 | [AN1169](https://attack.mitre.org/detectionstrategies/DET0416#AN1169) | Windows | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0032, DC0082, DC0085 |
| 49 | [AN1516](https://attack.mitre.org/detectionstrategies/DET0549#AN1516) | Windows | T1552.004 Private Keys | credential-access | 36 | ttp | DC0032, DC0039, DC0102 |
| 50 | [AN1519](https://attack.mitre.org/detectionstrategies/DET0549#AN1519) | Network Devices | T1552.004 Private Keys | credential-access | 36 | ttp | DC0064 |
| 51 | [AN0973](https://attack.mitre.org/detectionstrategies/DET0344#AN0973) | Windows | T1027.011 Fileless Storage | stealth | 35 | anomaly | DC0008, DC0063 |
| 52 | [AN0619](https://attack.mitre.org/detectionstrategies/DET0221#AN0619) | Windows | T1123 Audio Capture | collection | 34 | anomaly | DC0032, DC0035, DC0039 |
| 53 | [AN0913](https://attack.mitre.org/detectionstrategies/DET0322#AN0913) | Windows | T1027.016 Junk Code Insertion | stealth | 34 | anomaly | DC0032, DC0035, DC0039 |
| 54 | [AN1336](https://attack.mitre.org/detectionstrategies/DET0487#AN1336) | Windows | T1110.003 Password Spraying | credential-access | 34 | anomaly | DC0002 |
| 55 | [AN0320](https://attack.mitre.org/detectionstrategies/DET0115#AN0320) | Windows | T1566.003 Spearphishing via Service | initial-access | 33 | ttp | DC0032, DC0039, DC0082 |
| 56 | [AN0510](https://attack.mitre.org/detectionstrategies/DET0180#AN0510) | Windows | T1547.009 Shortcut Modification | persistence, privilege-escalation | 33 | anomaly | DC0032, DC0039, DC0059, DC0061 |
| 57 | [AN0648](https://attack.mitre.org/detectionstrategies/DET0234#AN0648) | Windows | T1003 OS Credential Dumping | credential-access | 33 | ttp | DC0032, DC0035, DC0055, DC0071 |
| 58 | [AN1946](https://attack.mitre.org/detectionstrategies/DET0814#AN1946) | PRE | T1589.002 Email Addresses | reconnaissance | 33 | hunting | DC0085 |
| 59 | [AN0379](https://attack.mitre.org/detectionstrategies/DET0135#AN0379) | Windows | T1071.003 Mail Protocols | command-and-control | 32 | ttp | DC0032, DC0082, DC0085 |
| 60 | [AN1393](https://attack.mitre.org/detectionstrategies/DET0504#AN1393) | Windows | T1559.002 Dynamic Data Exchange | execution | 32 | anomaly | DC0016, DC0032, DC0050 |
| 61 | [AN0127](https://attack.mitre.org/detectionstrategies/DET0046#AN0127) | Windows | T1497 Virtualization/Sandbox Evasion | stealth, discovery | 31 | ttp | DC0016, DC0032 |
| 62 | [AN0130](https://attack.mitre.org/detectionstrategies/DET0047#AN0130) | Windows | T1114.001 Local Email Collection | collection | 31 | ttp | DC0032, DC0039, DC0055, DC0082 |
| 63 | [AN0714](https://attack.mitre.org/detectionstrategies/DET0259#AN0714) | Windows | T1219.002 Remote Desktop Software | command-and-control | 31 | ttp | DC0039, DC0051, DC0082 |
| 64 | [AN0949](https://attack.mitre.org/detectionstrategies/DET0336#AN0949) | Windows | T1554 Compromise Host Software Binary | persistence | 31 | anomaly | DC0032, DC0039, DC0061 |
| 65 | [AN1212](https://attack.mitre.org/detectionstrategies/DET0437#AN1212) | Windows | T1003.004 LSA Secrets | credential-access | 31 | ttp | DC0016, DC0032, DC0035, DC0061 |
| 66 | [AN1048](https://attack.mitre.org/detectionstrategies/DET0372#AN1048) | Windows | T1678 Delay Execution | stealth | 30 | ttp | DC0016, DC0032 |
| 67 | [AN1344](https://attack.mitre.org/detectionstrategies/DET0488#AN1344) | Windows | T1199 Trusted Relationship | initial-access | 30 | ttp | DC0038, DC0067, DC0082, DC0088 |
| 68 | [AN0599](https://attack.mitre.org/detectionstrategies/DET0214#AN0599) | Windows | T1027.009 Embedded Payloads | stealth | 29 | anomaly | DC0032, DC0039, DC0059 |
| 69 | [AN0630](https://attack.mitre.org/detectionstrategies/DET0226#AN0630) | Windows | T1036.008 Masquerade File Type | stealth | 29 | anomaly | DC0032, DC0039 |
| 70 | [AN1045](https://attack.mitre.org/detectionstrategies/DET0371#AN1045) | Windows | T1622 Debugger Evasion | stealth, discovery | 29 | ttp | DC0021, DC0032 |
| 71 | [AN0540](https://attack.mitre.org/detectionstrategies/DET0189#AN0540) | Windows | T1027.005 Indicator Removal from Tools | stealth | 28 | anomaly | DC0032, DC0038, DC0039 |
| 72 | [AN0596](https://attack.mitre.org/detectionstrategies/DET0213#AN0596) | Windows | T1030 Data Transfer Size Limits | exfiltration | 28 | anomaly | DC0078, DC0082 |
| 73 | [AN1410](https://attack.mitre.org/detectionstrategies/DET0511#AN1410) | Windows | T1025 Data from Removable Media | collection | 28 | anomaly | DC0032, DC0042, DC0055 |
| 74 | [AN1448](https://attack.mitre.org/detectionstrategies/DET0524#AN1448) | Windows | T1205 Traffic Signaling | stealth, persistence, command-and-control | 28 | anomaly | DC0032, DC0064, DC0078, DC0082 |
| 75 | [AN1451](https://attack.mitre.org/detectionstrategies/DET0524#AN1451) | Network Devices | T1205 Traffic Signaling | stealth, persistence, command-and-control | 28 | ttp | DC0078, DC0082 |
| 76 | [AN1511](https://attack.mitre.org/detectionstrategies/DET0548#AN1511) | Windows | T1567 Exfiltration Over Web Service | exfiltration | 28 | anomaly | DC0032, DC0039, DC0082 |
| 77 | [AN0194](https://attack.mitre.org/detectionstrategies/DET0071#AN0194) | Windows | T1074.002 Remote Data Staging | collection | 27 | ttp | DC0039, DC0064, DC0102 |
| 78 | [AN0827](https://attack.mitre.org/detectionstrategies/DET0297#AN0827) | Windows | T1561.002 Disk Structure Wipe | impact | 27 | ttp | DC0013, DC0046, DC0079 |
| 79 | [AN0830](https://attack.mitre.org/detectionstrategies/DET0297#AN0830) | Network Devices | T1561.002 Disk Structure Wipe | impact | 27 | ttp | DC0002, DC0064 |
| 80 | [AN1294](https://attack.mitre.org/detectionstrategies/DET0470#AN1294) | Windows | T1001.003 Protocol or Service Impersonation | command-and-control | 27 | ttp | DC0082, DC0085 |
| 81 | [AN0628](https://attack.mitre.org/detectionstrategies/DET0224#AN0628) | Windows | T1559.001 Component Object Model | execution | 26 | anomaly | DC0016, DC0032, DC0050 |
| 82 | [AN1178](https://attack.mitre.org/detectionstrategies/DET0419#AN1178) | Windows | T1568.002 Domain Generation Algorithms | command-and-control | 26 | anomaly | DC0032, DC0082 |
| 83 | [AN2043](https://attack.mitre.org/detectionstrategies/DET0901#AN2043) | Windows | T1686.003 Windows Host Firewall | defense-impairment | 26 | anomaly | DC0032, DC0056, DC0060, DC0063, DC0082 |
| 84 | [AN0854](https://attack.mitre.org/detectionstrategies/DET0305#AN0854) | Windows | T1484.001 Group Policy Modification | defense-impairment, privilege-escalation | 25 | ttp | DC0010, DC0032, DC0039, DC0061, DC0066 |
| 85 | [AN0862](https://attack.mitre.org/detectionstrategies/DET0309#AN0862) | Windows | T1195.002 Compromise Software Supply Chain | initial-access | 25 | anomaly | DC0016, DC0032, DC0039, DC0059, DC0063, DC0078, DC0079, DC0082 |
| 86 | [AN0052](https://attack.mitre.org/detectionstrategies/DET0018#AN0052) | Windows | T1129 Shared Modules | execution | 24 | anomaly | DC0016, DC0032, DC0034, DC0039, DC0082 |
| 87 | [AN0250](https://attack.mitre.org/detectionstrategies/DET0091#AN0250) | Windows | T1027.007 Dynamic API Resolution | stealth | 24 | anomaly | DC0016, DC0021, DC0032 |
| 88 | [AN0469](https://attack.mitre.org/detectionstrategies/DET0165#AN0469) | Windows | T1070.003 Clear Command History | stealth | 24 | ttp | DC0040, DC0061, DC0064 |
| 89 | [AN0471](https://attack.mitre.org/detectionstrategies/DET0165#AN0471) | Network Devices | T1070.003 Clear Command History | stealth | 24 | ttp | DC0064 |
| 90 | [AN0677](https://attack.mitre.org/detectionstrategies/DET0242#AN0677) | Windows | T1213.006 Databases | collection | 24 | ttp | DC0032, DC0039, DC0082 |
| 91 | [AN1145](https://attack.mitre.org/detectionstrategies/DET0410#AN1145) | Windows | T1039 Data from Network Shared Drive | collection | 24 | anomaly | DC0039, DC0102 |
| 92 | [AN1225](https://attack.mitre.org/detectionstrategies/DET0444#AN1225) | Windows | T1071 Application Layer Protocol | command-and-control | 24 | ttp | DC0082, DC0085 |
| 93 | [AN1228](https://attack.mitre.org/detectionstrategies/DET0444#AN1228) | Network Devices | T1071 Application Layer Protocol | command-and-control | 24 | ttp | DC0085 |
| 94 | [AN1973](https://attack.mitre.org/detectionstrategies/DET0841#AN1973) | PRE | T1589 Gather Victim Identity Information | reconnaissance | 24 | hunting | DC0085 |
| 95 | [AN0623](https://attack.mitre.org/detectionstrategies/DET0223#AN0623) | Windows | T1072 Software Deployment Tools | execution, lateral-movement | 23 | anomaly | DC0032, DC0038 |
| 96 | [AN0627](https://attack.mitre.org/detectionstrategies/DET0223#AN0627) | Network Devices | T1072 Software Deployment Tools | execution, lateral-movement | 23 | ttp | DC0038, DC0078 |
| 97 | [AN0759](https://attack.mitre.org/detectionstrategies/DET0273#AN0759) | Windows | T1573 Encrypted Channel | command-and-control | 23 | anomaly | DC0016, DC0082 |
| 98 | [AN0763](https://attack.mitre.org/detectionstrategies/DET0273#AN0763) | Network Devices | T1573 Encrypted Channel | command-and-control | 23 | anomaly | DC0078, DC0085 |
| 99 | [AN0372](https://attack.mitre.org/detectionstrategies/DET0132#AN0372) | Windows | T1480.002 Mutual Exclusion | stealth | 22 | anomaly | DC0032, DC0039 |
| 100 | [AN0882](https://attack.mitre.org/detectionstrategies/DET0316#AN0882) | Windows | T1561.001 Disk Content Wipe | impact | 22 | ttp | DC0013, DC0046, DC0079 |
| 101 | [AN0885](https://attack.mitre.org/detectionstrategies/DET0316#AN0885) | Network Devices | T1561.001 Disk Content Wipe | impact | 22 | ttp | DC0002, DC0064 |
| 102 | [AN1564](https://attack.mitre.org/detectionstrategies/DET0566#AN1564) | Windows | T1221 Template Injection | stealth | 22 | anomaly | DC0032, DC0082 |
| 103 | [AN0641](https://attack.mitre.org/detectionstrategies/DET0229#AN0641) | Windows | T1087.003 Email Account | discovery | 21 | hunting | DC0032, DC0064 |
| 104 | [AN1357](https://attack.mitre.org/detectionstrategies/DET0493#AN1357) | Windows | T1559 Inter-Process Communication | execution | 21 | anomaly | DC0035, DC0048 |
| 105 | [AN1641](https://attack.mitre.org/detectionstrategies/DET0597#AN1641) | Windows | T1555.005 Password Managers | credential-access | 21 | ttp | DC0032, DC0035, DC0059 |
| 106 | [AN0229](https://attack.mitre.org/detectionstrategies/DET0082#AN0229) | Windows | T1491.001 Internal Defacement | impact | 20 | ttp | DC0032, DC0039, DC0055, DC0061 |
| 107 | [AN0444](https://attack.mitre.org/detectionstrategies/DET0157#AN0444) | Windows | T1558.003 Kerberoasting | credential-access | 20 | anomaly | DC0035, DC0067, DC0084, DC0088 |
| 108 | [AN0507](https://attack.mitre.org/detectionstrategies/DET0179#AN0507) | Windows | T1069 Permission Groups Discovery | discovery | 20 | hunting | DC0032, DC0064 |
| 109 | [AN0637](https://attack.mitre.org/detectionstrategies/DET0228#AN0637) | Windows | T1104 Multi-Stage Channels | command-and-control | 20 | ttp | DC0032, DC0082 |
| 110 | [AN1440](https://attack.mitre.org/detectionstrategies/DET0521#AN1440) | Windows | T1056.002 GUI Input Capture | collection, credential-access | 20 | ttp | DC0032, DC0064 |
| 111 | [AN1632](https://attack.mitre.org/detectionstrategies/DET0594#AN1632) | Windows | T1003.006 DCSync | credential-access | 20 | ttp | DC0068, DC0071, DC0085 |
| 112 | [AN0030](https://attack.mitre.org/detectionstrategies/DET0011#AN0030) | Windows | T1001.001 Junk Data | command-and-control | 19 | anomaly | DC0035, DC0082, DC0085 |
| 113 | [AN0378](https://attack.mitre.org/detectionstrategies/DET0134#AN0378) | Windows | T1555.004 Windows Credential Manager | credential-access | 19 | anomaly | DC0032, DC0035, DC0059 |
| 114 | [AN0747](https://attack.mitre.org/detectionstrategies/DET0268#AN0747) | Windows | T1560.002 Archive via Library | collection | 19 | ttp | DC0016, DC0032, DC0039 |
| 115 | [AN1118](https://attack.mitre.org/detectionstrategies/DET0399#AN1118) | Windows | T1029 Scheduled Transfer | exfiltration | 19 | anomaly | DC0005, DC0032, DC0082 |
| 116 | [AN1489](https://attack.mitre.org/detectionstrategies/DET0540#AN1489) | Windows | T1496.001 Compute Hijacking | impact | 19 | ttp | DC0001, DC0032, DC0082 |
| 117 | [AN1557](https://attack.mitre.org/detectionstrategies/DET0563#AN1557) | Windows | T1690 Prevent Command History Logging | defense-impairment | 19 | ttp | DC0032, DC0064 |
| 118 | [AN1559](https://attack.mitre.org/detectionstrategies/DET0563#AN1559) | Network Devices | T1690 Prevent Command History Logging | defense-impairment | 19 | ttp | DC0064 |
| 119 | [AN0006](https://attack.mitre.org/detectionstrategies/DET0003#AN0006) | Windows | T1136.002 Domain Account | persistence | 18 | ttp | DC0014, DC0032 |
| 120 | [AN0113](https://attack.mitre.org/detectionstrategies/DET0040#AN0113) | Windows | T1070.009 Clear Persistence | stealth | 18 | ttp | DC0001, DC0009, DC0032, DC0063 |
| 121 | [AN0274](https://attack.mitre.org/detectionstrategies/DET0098#AN0274) | Windows | T1197 BITS Jobs | stealth, persistence, execution | 18 | anomaly | DC0032, DC0060, DC0064, DC0082 |
| 122 | [AN0297](https://attack.mitre.org/detectionstrategies/DET0106#AN0297) | Windows | T1055.002 Portable Executable Injection | stealth, privilege-escalation | 18 | anomaly | DC0020, DC0032, DC0035, DC0039 |
| 123 | [AN0865](https://attack.mitre.org/detectionstrategies/DET0310#AN0865) | Windows | T1098.007 Additional Local or Domain Groups | persistence, privilege-escalation | 18 | ttp | DC0010 |
| 124 | [AN0012](https://attack.mitre.org/detectionstrategies/DET0005#AN0012) | Windows | T1036.003 Rename Legitimate Utilities | stealth | 17 | ttp | DC0032, DC0039, DC0064 |
| 125 | [AN0144](https://attack.mitre.org/detectionstrategies/DET0053#AN0144) | Windows | T1001 Data Obfuscation | command-and-control | 17 | anomaly | DC0085 |
| 126 | [AN0265](https://attack.mitre.org/detectionstrategies/DET0096#AN0265) | Windows | T1098 Account Manipulation | persistence, privilege-escalation | 17 | anomaly | DC0010, DC0032 |
| 127 | [AN0282](https://attack.mitre.org/detectionstrategies/DET0102#AN0282) | Windows | T1056 Input Capture | collection, credential-access | 17 | ttp | DC0035, DC0055 |
| 128 | [AN0285](https://attack.mitre.org/detectionstrategies/DET0102#AN0285) | Network Devices | T1056 Input Capture | collection, credential-access | 17 | ttp | DC0082, DC0085 |
| 129 | [AN1298](https://attack.mitre.org/detectionstrategies/DET0471#AN1298) | Windows | T1080 Taint Shared Content | lateral-movement | 17 | ttp | DC0039, DC0102 |
| 130 | [AN1313](https://attack.mitre.org/detectionstrategies/DET0477#AN1313) | Windows | T1021.006 Windows Remote Management | lateral-movement | 17 | ttp | DC0032, DC0041, DC0067, DC0078 |
| 131 | [AN1398](https://attack.mitre.org/detectionstrategies/DET0507#AN1398) | Windows | T1185 Browser Session Hijacking | collection | 17 | ttp | DC0013, DC0016, DC0020, DC0035, DC0067, DC0082, DC0088 |
| 132 | [AN1521](https://attack.mitre.org/detectionstrategies/DET0551#AN1521) | Windows | T1110.001 Password Guessing | credential-access | 17 | anomaly | DC0002 |
| 133 | [AN1612](https://attack.mitre.org/detectionstrategies/DET0587#AN1612) | Windows | T1087 Account Discovery | discovery | 17 | hunting | DC0032, DC0099 |
| 134 | [AN0040](https://attack.mitre.org/detectionstrategies/DET0014#AN0040) | Windows | T1074 Data Staged | collection | 16 | ttp | DC0032, DC0039, DC0055 |
| 135 | [AN0089](https://attack.mitre.org/detectionstrategies/DET0031#AN0089) | Windows | T1036.001 Invalid Code Signature | stealth | 16 | ttp | DC0032, DC0059, DC0064 |
| 136 | [AN1177](https://attack.mitre.org/detectionstrategies/DET0418#AN1177) | Windows | T1222.001 Windows Permissions | defense-impairment | 16 | anomaly | DC0008, DC0032, DC0039, DC0059, DC0064, DC0066 |
| 137 | [AN1253](https://attack.mitre.org/detectionstrategies/DET0456#AN1253) | Windows | T1134.002 Create Process with Token | stealth, privilege-escalation | 16 | ttp | DC0021, DC0032, DC0035, DC0066, DC0088 |
| 138 | [AN0292](https://attack.mitre.org/detectionstrategies/DET0105#AN0292) | Windows | T1110.002 Password Cracking | credential-access | 15 | ttp | DC0032, DC0035, DC0039, DC0055 |
| 139 | [AN0296](https://attack.mitre.org/detectionstrategies/DET0105#AN0296) | Network Devices | T1110.002 Password Cracking | credential-access | 15 | ttp | DC0002 |
| 140 | [AN0504](https://attack.mitre.org/detectionstrategies/DET0178#AN0504) | Windows | T1021.005 VNC | lateral-movement | 15 | ttp | DC0032, DC0067, DC0078 |
| 141 | [AN0651](https://attack.mitre.org/detectionstrategies/DET0235#AN0651) | Windows | T1001.002 Steganography | command-and-control | 15 | anomaly | DC0032, DC0039, DC0082, DC0085 |
| 142 | [AN0687](https://attack.mitre.org/detectionstrategies/DET0246#AN0687) | Windows | T1111 Multi-Factor Authentication Interception | credential-access | 15 | ttp | DC0035, DC0063, DC0067 |
| 143 | [AN0705](https://attack.mitre.org/detectionstrategies/DET0255#AN0705) | Windows | T1654 Log Enumeration | discovery | 15 | hunting | DC0032, DC0055 |
| 144 | [AN1413](https://attack.mitre.org/detectionstrategies/DET0512#AN1413) | Windows | T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | exfiltration | 15 | ttp | DC0032, DC0055, DC0082, DC0085 |
| 145 | [AN0182](https://attack.mitre.org/detectionstrategies/DET0067#AN0182) | Windows | T1564.011 Ignore Process Interrupts | stealth | 14 | ttp | DC0032, DC0064 |
| 146 | [AN0277](https://attack.mitre.org/detectionstrategies/DET0100#AN0277) | Windows | T1055.004 Asynchronous Procedure Call | stealth, privilege-escalation | 14 | anomaly | DC0020, DC0021, DC0032, DC0035 |
| 147 | [AN1381](https://attack.mitre.org/detectionstrategies/DET0501#AN1381) | Windows | T1027.004 Compile After Delivery | stealth | 14 | ttp | DC0032, DC0039, DC0082 |
| 148 | [AN1417](https://attack.mitre.org/detectionstrategies/DET0513#AN1417) | Windows | T1003.005 Cached Domain Credentials | credential-access | 14 | ttp | DC0032, DC0035, DC0055 |
| 149 | [AN0021](https://attack.mitre.org/detectionstrategies/DET0009#AN0021) | Windows | T1195.001 Compromise Software Dependencies and Development Tools | initial-access | 13 | ttp | DC0016, DC0032, DC0039, DC0059, DC0063, DC0078 |
| 150 | [AN0094](https://attack.mitre.org/detectionstrategies/DET0033#AN0094) | Windows | T1546.008 Accessibility Features | privilege-escalation, persistence | 13 | anomaly | DC0032, DC0039, DC0059, DC0063 |

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
