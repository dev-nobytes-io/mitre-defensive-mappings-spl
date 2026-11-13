# Analytic backlog (ATT&CK v20.1)

Unimplemented analytics whose log sources are all on ticked feeds, ranked by technique prevalence (2 × groups + 2 × campaigns + software using the technique). The suggested content type is a heuristic starting point.

Live and unimplemented: **428**. Showing the top 150.

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
| 13 | [AN0178](https://attack.mitre.org/detectionstrategies/DET0066#AN0178) | Windows | T1204.001 Malicious Link | execution | 149 | ttp | DC0032, DC0039, DC0082, DC0085 |
| 14 | [AN0066](https://attack.mitre.org/detectionstrategies/DET0023#AN0066) | Windows | T1027.002 Software Packing | stealth | 136 | ttp | DC0032, DC0035 |
| 15 | [AN1254](https://attack.mitre.org/detectionstrategies/DET0457#AN1254) | Windows | T1095 Non-Application Layer Protocol | command-and-control | 130 | anomaly | DC0082, DC0085 |
| 16 | [AN0643](https://attack.mitre.org/detectionstrategies/DET0230#AN0643) | Windows | T1553.002 Code Signing | defense-impairment | 129 | anomaly | DC0016, DC0032 |
| 17 | [AN0434](https://attack.mitre.org/detectionstrategies/DET0151#AN0434) | Network Devices | T1124 System Time Discovery | discovery | 122 | hunting | DC0061, DC0064 |
| 18 | [AN0536](https://attack.mitre.org/detectionstrategies/DET0188#AN0536) | Windows | T1680 Local Storage Discovery | discovery | 116 | hunting | DC0032 |
| 19 | [AN1496](https://attack.mitre.org/detectionstrategies/DET0543#AN1496) | Windows | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0016, DC0082 |
| 20 | [AN0797](https://attack.mitre.org/detectionstrategies/DET0287#AN0797) | Windows | T1203 Exploitation for Client Execution | execution | 108 | anomaly | DC0032, DC0038, DC0039, DC0082 |
| 21 | [AN1229](https://attack.mitre.org/detectionstrategies/DET0445#AN1229) | Windows | T1090 Proxy | command-and-control | 108 | anomaly | DC0032, DC0078, DC0082 |
| 22 | [AN0531](https://attack.mitre.org/detectionstrategies/DET0186#AN0531) | Windows | T1119 Automated Collection | collection | 106 | anomaly | DC0032, DC0039 |
| 23 | [AN1084](https://attack.mitre.org/detectionstrategies/DET0384#AN1084) | Network Devices | T1059.004 Unix Shell | execution | 90 | ttp | DC0064, DC0082 |
| 24 | [AN0478](https://attack.mitre.org/detectionstrategies/DET0168#AN0478) | Windows | T1497.001 System Checks | stealth, discovery | 81 | ttp | DC0016, DC0032, DC0035 |
| 25 | [AN1004](https://attack.mitre.org/detectionstrategies/DET0354#AN1004) | Windows | T1133 External Remote Services | persistence, initial-access | 81 | anomaly | DC0002, DC0038, DC0082 |
| 26 | [AN0498](https://attack.mitre.org/detectionstrategies/DET0176#AN0498) | Windows | T1189 Drive-by Compromise | initial-access | 79 | anomaly | DC0020, DC0032, DC0038, DC0039, DC0067, DC0082, DC0085 |
| 27 | [AN0091](https://attack.mitre.org/detectionstrategies/DET0032#AN0091) | Windows | T1564.001 Hidden Files and Directories | stealth | 76 | ttp | DC0032, DC0039 |
| 28 | [AN1626](https://attack.mitre.org/detectionstrategies/DET0591#AN1626) | Windows | T1070.006 Timestomp | stealth | 74 | anomaly | DC0021, DC0055, DC0059 |
| 29 | [AN1189](https://attack.mitre.org/detectionstrategies/DET0425#AN1189) | Windows | T1102 Web Service | command-and-control | 71 | anomaly | DC0082, DC0085 |
| 30 | [AN1458](https://attack.mitre.org/detectionstrategies/DET0526#AN1458) | Windows | T1560 Archive Collected Data | collection | 70 | ttp | DC0016, DC0032, DC0039 |
| 31 | [AN1100](https://attack.mitre.org/detectionstrategies/DET0392#AN1100) | Windows | T1518 Software Discovery | discovery | 69 | hunting | DC0032, DC0064 |
| 32 | [AN1353](https://attack.mitre.org/detectionstrategies/DET0491#AN1353) | Windows | T1120 Peripheral Device Discovery | discovery | 69 | hunting | DC0032, DC0035 |
| 33 | [AN1419](https://attack.mitre.org/detectionstrategies/DET0514#AN1419) | Windows | T1068 Exploitation for Privilege Escalation | privilege-escalation | 69 | anomaly | DC0032, DC0079, DC0088 |
| 34 | [AN0590](https://attack.mitre.org/detectionstrategies/DET0210#AN0590) | Windows | T1078.002 Domain Accounts | stealth, persistence, privilege-escalation, initial-access | 67 | anomaly | DC0032, DC0082, DC0088 |
| 35 | [AN1428](https://attack.mitre.org/detectionstrategies/DET0516#AN1428) | Windows | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0032 |
| 36 | [AN1432](https://attack.mitre.org/detectionstrategies/DET0516#AN1432) | Network Devices | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0002, DC0064 |
| 37 | [AN0936](https://attack.mitre.org/detectionstrategies/DET0329#AN0936) | Network Devices | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0064 |
| 38 | [AN1020](https://attack.mitre.org/detectionstrategies/DET0359#AN1020) | Windows | T1090.003 Multi-hop Proxy | command-and-control | 65 | ttp | DC0032, DC0078, DC0082 |
| 39 | [AN1376](https://attack.mitre.org/detectionstrategies/DET0499#AN1376) | Windows | T1008 Fallback Channels | command-and-control | 64 | anomaly | DC0078, DC0082 |
| 40 | [AN0856](https://attack.mitre.org/detectionstrategies/DET0307#AN0856) | Windows | T1552.001 Credentials In Files | credential-access | 63 | ttp | DC0032, DC0039, DC0067 |
| 41 | [AN1198](https://attack.mitre.org/detectionstrategies/DET0430#AN1198) | Windows | T1555 Credentials from Password Stores | credential-access | 58 | ttp | DC0032, DC0035, DC0055 |
| 42 | [AN1551](https://attack.mitre.org/detectionstrategies/DET0562#AN1551) | Windows | T1480 Execution Guardrails | stealth | 58 | anomaly | DC0002, DC0008, DC0016, DC0020, DC0032, DC0039, DC0063, DC0064, DC0067, DC0082 |
| 43 | [AN1025](https://attack.mitre.org/detectionstrategies/DET0360#AN1025) | Windows | T1069.002 Domain Groups | discovery | 54 | hunting | DC0032, DC0064 |
| 44 | [AN0782](https://attack.mitre.org/detectionstrategies/DET0281#AN0782) | Windows | T1027.015 Compression | stealth | 52 | ttp | DC0032, DC0039 |
| 45 | [AN1076](https://attack.mitre.org/detectionstrategies/DET0382#AN1076) | Windows | T1055.012 Process Hollowing | stealth, privilege-escalation | 52 | anomaly | DC0020, DC0021, DC0032, DC0035 |
| 46 | [AN0396](https://attack.mitre.org/detectionstrategies/DET0141#AN0396) | Windows | T1497.003 Time Based Checks | stealth, discovery | 51 | ttp | DC0016, DC0032 |
| 47 | [AN0965](https://attack.mitre.org/detectionstrategies/DET0341#AN0965) | Windows | T1115 Clipboard Data | collection | 51 | ttp | DC0032, DC0035 |
| 48 | [AN0411](https://attack.mitre.org/detectionstrategies/DET0146#AN0411) | Windows | T1485 Data Destruction | impact | 50 | anomaly | DC0032, DC0039, DC0040 |
| 49 | [AN1611](https://attack.mitre.org/detectionstrategies/DET0586#AN1611) | Windows | T1003.003 NTDS | credential-access | 50 | ttp | DC0032, DC0039, DC0061, DC0097 |
| 50 | [AN0208](https://attack.mitre.org/detectionstrategies/DET0075#AN0208) | Network Devices | T1090.001 Internal Proxy | command-and-control | 49 | ttp | DC0051, DC0064, DC0078 |
| 51 | [AN0785](https://attack.mitre.org/detectionstrategies/DET0282#AN0785) | Windows | T1218.010 Regsvr32 | stealth | 49 | anomaly | DC0016, DC0032, DC0082 |
| 52 | [AN1235](https://attack.mitre.org/detectionstrategies/DET0447#AN1235) | Windows | T1136.001 Local Account | persistence | 49 | ttp | DC0014, DC0032 |
| 53 | [AN1397](https://attack.mitre.org/detectionstrategies/DET0506#AN1397) | Windows | T1218.005 Mshta | stealth | 49 | anomaly | DC0032, DC0039, DC0082 |
| 54 | [AN0423](https://attack.mitre.org/detectionstrategies/DET0149#AN0423) | Windows | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 48 | anomaly | DC0032, DC0055, DC0082, DC0085 |
| 55 | [AN1361](https://attack.mitre.org/detectionstrategies/DET0495#AN1361) | Windows | T1657 Financial Theft | impact | 48 | anomaly | DC0032, DC0067 |
| 56 | [AN0016](https://attack.mitre.org/detectionstrategies/DET0007#AN0016) | Windows | T1482 Domain Trust Discovery | discovery | 47 | hunting | DC0016, DC0032, DC0035, DC0064, DC0071 |
| 57 | [AN1213](https://attack.mitre.org/detectionstrategies/DET0438#AN1213) | Windows | T1560.003 Archive via Custom Method | collection | 47 | anomaly | DC0032, DC0035, DC0039 |
| 58 | [AN0406](https://attack.mitre.org/detectionstrategies/DET0145#AN0406) | Windows | T1686 Disable or Modify System Firewall | defense-impairment | 45 | ttp | DC0032, DC0063 |
| 59 | [AN1275](https://attack.mitre.org/detectionstrategies/DET0463#AN1275) | Windows | T1110 Brute Force | credential-access | 45 | anomaly | DC0002 |
| 60 | [AN0317](https://attack.mitre.org/detectionstrategies/DET0114#AN0317) | Windows | T1069.001 Local Groups | discovery | 43 | hunting | DC0032 |
| 61 | [AN0331](https://attack.mitre.org/detectionstrategies/DET0119#AN0331) | Windows | T1027.003 Steganography | stealth | 43 | ttp | DC0032, DC0055, DC0082 |
| 62 | [AN1113](https://attack.mitre.org/detectionstrategies/DET0397#AN1113) | Windows | T1020 Automated Exfiltration | exfiltration | 43 | ttp | DC0032, DC0082 |
| 63 | [AN1137](https://attack.mitre.org/detectionstrategies/DET0407#AN1137) | Windows | T1078.003 Local Accounts | stealth, persistence, privilege-escalation, initial-access | 43 | anomaly | DC0067, DC0088 |
| 64 | [AN0037](https://attack.mitre.org/detectionstrategies/DET0013#AN0037) | Windows | T1217 Browser Information Discovery | discovery | 42 | hunting | DC0032, DC0039, DC0064 |
| 65 | [AN1061](https://attack.mitre.org/detectionstrategies/DET0377#AN1061) | Windows | T1014 Rootkit | stealth | 42 | ttp | DC0039, DC0060, DC0079 |
| 66 | [AN0271](https://attack.mitre.org/detectionstrategies/DET0097#AN0271) | Windows | T1010 Application Window Discovery | discovery | 40 | hunting | DC0035, DC0064 |
| 67 | [AN0327](https://attack.mitre.org/detectionstrategies/DET0118#AN0327) | Windows | T1210 Exploitation of Remote Services | lateral-movement | 39 | anomaly | DC0016, DC0032, DC0035, DC0038, DC0039, DC0082, DC0085 |
| 68 | [AN0445](https://attack.mitre.org/detectionstrategies/DET0158#AN0445) | Windows | T1218.007 Msiexec | stealth | 39 | ttp | DC0016, DC0032, DC0082 |
| 69 | [AN0520](https://attack.mitre.org/detectionstrategies/DET0184#AN0520) | Windows | T1070 Indicator Removal | stealth | 39 | ttp | DC0038, DC0040, DC0063 |
| 70 | [AN0568](https://attack.mitre.org/detectionstrategies/DET0197#AN0568) | Windows | T1125 Video Capture | collection | 39 | anomaly | DC0016, DC0021, DC0032, DC0034, DC0039, DC0082 |
| 71 | [AN0875](https://attack.mitre.org/detectionstrategies/DET0314#AN0875) | Windows | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0032, DC0060 |
| 72 | [AN0879](https://attack.mitre.org/detectionstrategies/DET0314#AN0879) | Network Devices | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0002, DC0064, DC0085 |
| 73 | [AN0922](https://attack.mitre.org/detectionstrategies/DET0325#AN0922) | Windows | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0032, DC0082, DC0085 |
| 74 | [AN1015](https://attack.mitre.org/detectionstrategies/DET0357#AN1015) | Windows | T1016.001 Internet Connection Discovery | discovery | 39 | hunting | DC0032, DC0064, DC0082 |
| 75 | [AN1402](https://attack.mitre.org/detectionstrategies/DET0509#AN1402) | Windows | T1539 Steal Web Session Cookie | credential-access | 39 | ttp | DC0032, DC0035, DC0061 |
| 76 | [AN1528](https://attack.mitre.org/detectionstrategies/DET0553#AN1528) | Windows | T1027.001 Binary Padding | stealth | 39 | anomaly | DC0032, DC0039, DC0055 |
| 77 | [AN0109](https://attack.mitre.org/detectionstrategies/DET0039#AN0109) | Windows | T1568 Dynamic Resolution | command-and-control | 38 | anomaly | DC0032, DC0082 |
| 78 | [AN1999](https://attack.mitre.org/detectionstrategies/DET0867#AN1999) | PRE | T1595.002 Vulnerability Scanning | reconnaissance | 38 | hunting | DC0078, DC0085 |
| 79 | [AN0236](https://attack.mitre.org/detectionstrategies/DET0086#AN0236) | Windows | T1546.003 Windows Management Instrumentation Event Subscription | privilege-escalation, persistence | 37 | anomaly | DC0008, DC0016, DC0032 |
| 80 | [AN1366](https://attack.mitre.org/detectionstrategies/DET0496#AN1366) | Windows | T1219 Remote Access Tools | command-and-control | 37 | ttp | DC0032, DC0039, DC0056, DC0060, DC0063, DC0082 |
| 81 | [AN1538](https://attack.mitre.org/detectionstrategies/DET0559#AN1538) | Windows | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0032 |
| 82 | [AN0841](https://attack.mitre.org/detectionstrategies/DET0301#AN0841) | Windows | T1091 Replication Through Removable Media | lateral-movement, initial-access | 36 | anomaly | DC0032, DC0039, DC0042, DC0055 |
| 83 | [AN1144](https://attack.mitre.org/detectionstrategies/DET0409#AN1144) | Windows | T1550.002 Pass the Hash | lateral-movement | 36 | anomaly | DC0032, DC0067, DC0082, DC0084 |
| 84 | [AN1169](https://attack.mitre.org/detectionstrategies/DET0416#AN1169) | Windows | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0032, DC0082, DC0085 |
| 85 | [AN1516](https://attack.mitre.org/detectionstrategies/DET0549#AN1516) | Windows | T1552.004 Private Keys | credential-access | 36 | ttp | DC0032, DC0039, DC0102 |
| 86 | [AN1519](https://attack.mitre.org/detectionstrategies/DET0549#AN1519) | Network Devices | T1552.004 Private Keys | credential-access | 36 | ttp | DC0064 |
| 87 | [AN0973](https://attack.mitre.org/detectionstrategies/DET0344#AN0973) | Windows | T1027.011 Fileless Storage | stealth | 35 | anomaly | DC0008, DC0063 |
| 88 | [AN0619](https://attack.mitre.org/detectionstrategies/DET0221#AN0619) | Windows | T1123 Audio Capture | collection | 34 | anomaly | DC0032, DC0035, DC0039 |
| 89 | [AN0913](https://attack.mitre.org/detectionstrategies/DET0322#AN0913) | Windows | T1027.016 Junk Code Insertion | stealth | 34 | anomaly | DC0032, DC0035, DC0039 |
| 90 | [AN1336](https://attack.mitre.org/detectionstrategies/DET0487#AN1336) | Windows | T1110.003 Password Spraying | credential-access | 34 | anomaly | DC0002 |
| 91 | [AN0320](https://attack.mitre.org/detectionstrategies/DET0115#AN0320) | Windows | T1566.003 Spearphishing via Service | initial-access | 33 | ttp | DC0032, DC0039, DC0082 |
| 92 | [AN0510](https://attack.mitre.org/detectionstrategies/DET0180#AN0510) | Windows | T1547.009 Shortcut Modification | persistence, privilege-escalation | 33 | anomaly | DC0032, DC0039, DC0059, DC0061 |
| 93 | [AN0648](https://attack.mitre.org/detectionstrategies/DET0234#AN0648) | Windows | T1003 OS Credential Dumping | credential-access | 33 | ttp | DC0032, DC0035, DC0055, DC0071 |
| 94 | [AN1946](https://attack.mitre.org/detectionstrategies/DET0814#AN1946) | PRE | T1589.002 Email Addresses | reconnaissance | 33 | hunting | DC0085 |
| 95 | [AN0379](https://attack.mitre.org/detectionstrategies/DET0135#AN0379) | Windows | T1071.003 Mail Protocols | command-and-control | 32 | ttp | DC0032, DC0082, DC0085 |
| 96 | [AN1393](https://attack.mitre.org/detectionstrategies/DET0504#AN1393) | Windows | T1559.002 Dynamic Data Exchange | execution | 32 | anomaly | DC0016, DC0032, DC0050 |
| 97 | [AN0127](https://attack.mitre.org/detectionstrategies/DET0046#AN0127) | Windows | T1497 Virtualization/Sandbox Evasion | stealth, discovery | 31 | ttp | DC0016, DC0032 |
| 98 | [AN0130](https://attack.mitre.org/detectionstrategies/DET0047#AN0130) | Windows | T1114.001 Local Email Collection | collection | 31 | ttp | DC0032, DC0039, DC0055, DC0082 |
| 99 | [AN0714](https://attack.mitre.org/detectionstrategies/DET0259#AN0714) | Windows | T1219.002 Remote Desktop Software | command-and-control | 31 | ttp | DC0039, DC0051, DC0082 |
| 100 | [AN0949](https://attack.mitre.org/detectionstrategies/DET0336#AN0949) | Windows | T1554 Compromise Host Software Binary | persistence | 31 | anomaly | DC0032, DC0039, DC0061 |
| 101 | [AN1212](https://attack.mitre.org/detectionstrategies/DET0437#AN1212) | Windows | T1003.004 LSA Secrets | credential-access | 31 | ttp | DC0016, DC0032, DC0035, DC0061 |
| 102 | [AN1048](https://attack.mitre.org/detectionstrategies/DET0372#AN1048) | Windows | T1678 Delay Execution | stealth | 30 | ttp | DC0016, DC0032 |
| 103 | [AN1344](https://attack.mitre.org/detectionstrategies/DET0488#AN1344) | Windows | T1199 Trusted Relationship | initial-access | 30 | ttp | DC0038, DC0067, DC0082, DC0088 |
| 104 | [AN0599](https://attack.mitre.org/detectionstrategies/DET0214#AN0599) | Windows | T1027.009 Embedded Payloads | stealth | 29 | anomaly | DC0032, DC0039, DC0059 |
| 105 | [AN0630](https://attack.mitre.org/detectionstrategies/DET0226#AN0630) | Windows | T1036.008 Masquerade File Type | stealth | 29 | anomaly | DC0032, DC0039 |
| 106 | [AN1045](https://attack.mitre.org/detectionstrategies/DET0371#AN1045) | Windows | T1622 Debugger Evasion | stealth, discovery | 29 | ttp | DC0021, DC0032 |
| 107 | [AN0540](https://attack.mitre.org/detectionstrategies/DET0189#AN0540) | Windows | T1027.005 Indicator Removal from Tools | stealth | 28 | anomaly | DC0032, DC0038, DC0039 |
| 108 | [AN0596](https://attack.mitre.org/detectionstrategies/DET0213#AN0596) | Windows | T1030 Data Transfer Size Limits | exfiltration | 28 | anomaly | DC0078, DC0082 |
| 109 | [AN1410](https://attack.mitre.org/detectionstrategies/DET0511#AN1410) | Windows | T1025 Data from Removable Media | collection | 28 | anomaly | DC0032, DC0042, DC0055 |
| 110 | [AN1448](https://attack.mitre.org/detectionstrategies/DET0524#AN1448) | Windows | T1205 Traffic Signaling | stealth, persistence, command-and-control | 28 | anomaly | DC0032, DC0064, DC0078, DC0082 |
| 111 | [AN1451](https://attack.mitre.org/detectionstrategies/DET0524#AN1451) | Network Devices | T1205 Traffic Signaling | stealth, persistence, command-and-control | 28 | ttp | DC0078, DC0082 |
| 112 | [AN1511](https://attack.mitre.org/detectionstrategies/DET0548#AN1511) | Windows | T1567 Exfiltration Over Web Service | exfiltration | 28 | anomaly | DC0032, DC0039, DC0082 |
| 113 | [AN0194](https://attack.mitre.org/detectionstrategies/DET0071#AN0194) | Windows | T1074.002 Remote Data Staging | collection | 27 | ttp | DC0039, DC0064, DC0102 |
| 114 | [AN0827](https://attack.mitre.org/detectionstrategies/DET0297#AN0827) | Windows | T1561.002 Disk Structure Wipe | impact | 27 | ttp | DC0013, DC0046, DC0079 |
| 115 | [AN0830](https://attack.mitre.org/detectionstrategies/DET0297#AN0830) | Network Devices | T1561.002 Disk Structure Wipe | impact | 27 | ttp | DC0002, DC0064 |
| 116 | [AN1294](https://attack.mitre.org/detectionstrategies/DET0470#AN1294) | Windows | T1001.003 Protocol or Service Impersonation | command-and-control | 27 | ttp | DC0082, DC0085 |
| 117 | [AN0628](https://attack.mitre.org/detectionstrategies/DET0224#AN0628) | Windows | T1559.001 Component Object Model | execution | 26 | anomaly | DC0016, DC0032, DC0050 |
| 118 | [AN1178](https://attack.mitre.org/detectionstrategies/DET0419#AN1178) | Windows | T1568.002 Domain Generation Algorithms | command-and-control | 26 | anomaly | DC0032, DC0082 |
| 119 | [AN2043](https://attack.mitre.org/detectionstrategies/DET0901#AN2043) | Windows | T1686.003 Windows Host Firewall | defense-impairment | 26 | anomaly | DC0032, DC0056, DC0060, DC0063, DC0082 |
| 120 | [AN0854](https://attack.mitre.org/detectionstrategies/DET0305#AN0854) | Windows | T1484.001 Group Policy Modification | defense-impairment, privilege-escalation | 25 | ttp | DC0010, DC0032, DC0039, DC0061, DC0066 |
| 121 | [AN0862](https://attack.mitre.org/detectionstrategies/DET0309#AN0862) | Windows | T1195.002 Compromise Software Supply Chain | initial-access | 25 | anomaly | DC0016, DC0032, DC0039, DC0059, DC0063, DC0078, DC0079, DC0082 |
| 122 | [AN0052](https://attack.mitre.org/detectionstrategies/DET0018#AN0052) | Windows | T1129 Shared Modules | execution | 24 | anomaly | DC0016, DC0032, DC0034, DC0039, DC0082 |
| 123 | [AN0250](https://attack.mitre.org/detectionstrategies/DET0091#AN0250) | Windows | T1027.007 Dynamic API Resolution | stealth | 24 | anomaly | DC0016, DC0021, DC0032 |
| 124 | [AN0469](https://attack.mitre.org/detectionstrategies/DET0165#AN0469) | Windows | T1070.003 Clear Command History | stealth | 24 | ttp | DC0040, DC0061, DC0064 |
| 125 | [AN0471](https://attack.mitre.org/detectionstrategies/DET0165#AN0471) | Network Devices | T1070.003 Clear Command History | stealth | 24 | ttp | DC0064 |
| 126 | [AN0677](https://attack.mitre.org/detectionstrategies/DET0242#AN0677) | Windows | T1213.006 Databases | collection | 24 | ttp | DC0032, DC0039, DC0082 |
| 127 | [AN1145](https://attack.mitre.org/detectionstrategies/DET0410#AN1145) | Windows | T1039 Data from Network Shared Drive | collection | 24 | anomaly | DC0039, DC0102 |
| 128 | [AN1225](https://attack.mitre.org/detectionstrategies/DET0444#AN1225) | Windows | T1071 Application Layer Protocol | command-and-control | 24 | ttp | DC0082, DC0085 |
| 129 | [AN1228](https://attack.mitre.org/detectionstrategies/DET0444#AN1228) | Network Devices | T1071 Application Layer Protocol | command-and-control | 24 | ttp | DC0085 |
| 130 | [AN1973](https://attack.mitre.org/detectionstrategies/DET0841#AN1973) | PRE | T1589 Gather Victim Identity Information | reconnaissance | 24 | hunting | DC0085 |
| 131 | [AN0623](https://attack.mitre.org/detectionstrategies/DET0223#AN0623) | Windows | T1072 Software Deployment Tools | execution, lateral-movement | 23 | anomaly | DC0032, DC0038 |
| 132 | [AN0627](https://attack.mitre.org/detectionstrategies/DET0223#AN0627) | Network Devices | T1072 Software Deployment Tools | execution, lateral-movement | 23 | ttp | DC0038, DC0078 |
| 133 | [AN0759](https://attack.mitre.org/detectionstrategies/DET0273#AN0759) | Windows | T1573 Encrypted Channel | command-and-control | 23 | anomaly | DC0016, DC0082 |
| 134 | [AN0763](https://attack.mitre.org/detectionstrategies/DET0273#AN0763) | Network Devices | T1573 Encrypted Channel | command-and-control | 23 | anomaly | DC0078, DC0085 |
| 135 | [AN0372](https://attack.mitre.org/detectionstrategies/DET0132#AN0372) | Windows | T1480.002 Mutual Exclusion | stealth | 22 | anomaly | DC0032, DC0039 |
| 136 | [AN0882](https://attack.mitre.org/detectionstrategies/DET0316#AN0882) | Windows | T1561.001 Disk Content Wipe | impact | 22 | ttp | DC0013, DC0046, DC0079 |
| 137 | [AN0885](https://attack.mitre.org/detectionstrategies/DET0316#AN0885) | Network Devices | T1561.001 Disk Content Wipe | impact | 22 | ttp | DC0002, DC0064 |
| 138 | [AN1564](https://attack.mitre.org/detectionstrategies/DET0566#AN1564) | Windows | T1221 Template Injection | stealth | 22 | anomaly | DC0032, DC0082 |
| 139 | [AN0641](https://attack.mitre.org/detectionstrategies/DET0229#AN0641) | Windows | T1087.003 Email Account | discovery | 21 | hunting | DC0032, DC0064 |
| 140 | [AN1357](https://attack.mitre.org/detectionstrategies/DET0493#AN1357) | Windows | T1559 Inter-Process Communication | execution | 21 | anomaly | DC0035, DC0048 |
| 141 | [AN1641](https://attack.mitre.org/detectionstrategies/DET0597#AN1641) | Windows | T1555.005 Password Managers | credential-access | 21 | ttp | DC0032, DC0035, DC0059 |
| 142 | [AN0229](https://attack.mitre.org/detectionstrategies/DET0082#AN0229) | Windows | T1491.001 Internal Defacement | impact | 20 | ttp | DC0032, DC0039, DC0055, DC0061 |
| 143 | [AN0444](https://attack.mitre.org/detectionstrategies/DET0157#AN0444) | Windows | T1558.003 Kerberoasting | credential-access | 20 | anomaly | DC0035, DC0067, DC0084, DC0088 |
| 144 | [AN0507](https://attack.mitre.org/detectionstrategies/DET0179#AN0507) | Windows | T1069 Permission Groups Discovery | discovery | 20 | hunting | DC0032, DC0064 |
| 145 | [AN0637](https://attack.mitre.org/detectionstrategies/DET0228#AN0637) | Windows | T1104 Multi-Stage Channels | command-and-control | 20 | ttp | DC0032, DC0082 |
| 146 | [AN1440](https://attack.mitre.org/detectionstrategies/DET0521#AN1440) | Windows | T1056.002 GUI Input Capture | collection, credential-access | 20 | ttp | DC0032, DC0064 |
| 147 | [AN1632](https://attack.mitre.org/detectionstrategies/DET0594#AN1632) | Windows | T1003.006 DCSync | credential-access | 20 | ttp | DC0068, DC0071, DC0085 |
| 148 | [AN0030](https://attack.mitre.org/detectionstrategies/DET0011#AN0030) | Windows | T1001.001 Junk Data | command-and-control | 19 | anomaly | DC0035, DC0082, DC0085 |
| 149 | [AN0378](https://attack.mitre.org/detectionstrategies/DET0134#AN0378) | Windows | T1555.004 Windows Credential Manager | credential-access | 19 | anomaly | DC0032, DC0035, DC0059 |
| 150 | [AN0747](https://attack.mitre.org/detectionstrategies/DET0268#AN0747) | Windows | T1560.002 Archive via Library | collection | 19 | ttp | DC0016, DC0032, DC0039 |

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
