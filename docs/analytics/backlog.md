# Analytic backlog (ATT&CK v20.1)

Unimplemented analytics whose log sources all map to feeds on in-scope platforms, per platform, ranked by technique prevalence (2 × groups + 2 × campaigns + software using the technique). The suggested content type is a heuristic starting point. Whether an analytic is runnable at your site depends on the feeds you collect; see the [log source checklist](../checklist.md).

Mapped and unimplemented: **956**. Showing the top 75 per platform.

| Platform | Mapped and unimplemented |
|---|---|
| [Windows](#windows) | 362 |
| [Linux](#linux) | 358 |
| [Network Devices](#network-devices) | 63 |
| [ESXi](#esxi) | 107 |
| [Containers](#containers) | 35 |
| [IaaS](#iaas) | 0 |
| [Identity Provider](#identity-provider) | 21 |

## Windows

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|
| 1 | [AN1465](https://attack.mitre.org/detectionstrategies/DET0529#AN1465) | T1106 Native API | execution | 262 | ttp | DC0016, DC0032, DC0035 |
| 2 | [AN0988](https://attack.mitre.org/detectionstrategies/DET0348#AN0988) | T1041 Exfiltration Over C2 Channel | exfiltration | 249 | ttp | DC0032, DC0055, DC0082, DC0085 |
| 3 | [AN0400](https://attack.mitre.org/detectionstrategies/DET0143#AN0400) | T1573.001 Symmetric Cryptography | command-and-control | 203 | anomaly | DC0016, DC0082 |
| 4 | [AN0243](https://attack.mitre.org/detectionstrategies/DET0089#AN0243) | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0035, DC0055, DC0060, DC0063 |
| 5 | [AN0219](https://attack.mitre.org/detectionstrategies/DET0080#AN0219) | T1190 Exploit Public-Facing Application | initial-access | 146 | anomaly | DC0016, DC0032, DC0038, DC0082 |
| 6 | [AN0345](https://attack.mitre.org/detectionstrategies/DET0124#AN0345) | T1132.001 Standard Encoding | command-and-control | 145 | anomaly | DC0029, DC0032, DC0078, DC0082 |
| 7 | [AN0066](https://attack.mitre.org/detectionstrategies/DET0023#AN0066) | T1027.002 Software Packing | stealth | 136 | ttp | DC0032, DC0035 |
| 8 | [AN0430](https://attack.mitre.org/detectionstrategies/DET0151#AN0430) | T1124 System Time Discovery | discovery | 122 | hunting | DC0001, DC0005, DC0016, DC0021, DC0032, DC0034, DC0035, DC0039, DC0064 |
| 9 | [AN1496](https://attack.mitre.org/detectionstrategies/DET0543#AN1496) | T1573.002 Asymmetric Cryptography | command-and-control | 116 | ttp | DC0016, DC0082 |
| 10 | [AN0733](https://attack.mitre.org/detectionstrategies/DET0264#AN0733) | T1059.007 JavaScript | execution | 113 | anomaly | DC0016, DC0029, DC0032 |
| 11 | [AN0513](https://attack.mitre.org/detectionstrategies/DET0182#AN0513) | T1135 Network Share Discovery | discovery | 99 | hunting | DC0021, DC0032, DC0048, DC0064, DC0082 |
| 12 | [AN0172](https://attack.mitre.org/detectionstrategies/DET0063#AN0172) | T1059.006 Python | execution | 92 | anomaly | DC0032, DC0085 |
| 13 | [AN1004](https://attack.mitre.org/detectionstrategies/DET0354#AN1004) | T1133 External Remote Services | persistence, initial-access | 81 | anomaly | DC0002, DC0038, DC0082 |
| 14 | [AN0498](https://attack.mitre.org/detectionstrategies/DET0176#AN0498) | T1189 Drive-by Compromise | initial-access | 79 | anomaly | DC0020, DC0032, DC0038, DC0039, DC0067, DC0082, DC0085 |
| 15 | [AN0100](https://attack.mitre.org/detectionstrategies/DET0035#AN0100) | T1102.002 Bidirectional Communication | command-and-control | 74 | anomaly | DC0032, DC0082, DC0085 |
| 16 | [AN0204](https://attack.mitre.org/detectionstrategies/DET0075#AN0204) | T1090.001 Internal Proxy | command-and-control | 49 | anomaly | DC0032, DC0078, DC0082 |
| 17 | [AN1561](https://attack.mitre.org/detectionstrategies/DET0565#AN1561) | T1614.001 System Language Discovery | discovery | 49 | hunting | DC0021, DC0032, DC0050 |
| 18 | [AN1361](https://attack.mitre.org/detectionstrategies/DET0495#AN1361) | T1657 Financial Theft | impact | 48 | anomaly | DC0032, DC0067 |
| 19 | [AN1213](https://attack.mitre.org/detectionstrategies/DET0438#AN1213) | T1560.003 Archive via Custom Method | collection | 47 | anomaly | DC0032, DC0035, DC0039 |
| 20 | [AN0317](https://attack.mitre.org/detectionstrategies/DET0114#AN0317) | T1069.001 Local Groups | discovery | 43 | hunting | DC0032 |
| 21 | [AN0331](https://attack.mitre.org/detectionstrategies/DET0119#AN0331) | T1027.003 Steganography | stealth | 43 | ttp | DC0032, DC0055, DC0082 |
| 22 | [AN1113](https://attack.mitre.org/detectionstrategies/DET0397#AN1113) | T1020 Automated Exfiltration | exfiltration | 43 | ttp | DC0032, DC0082 |
| 23 | [AN1137](https://attack.mitre.org/detectionstrategies/DET0407#AN1137) | T1078.003 Local Accounts | stealth, persistence, privilege-escalation, initial-access | 43 | anomaly | DC0067, DC0088 |
| 24 | [AN0037](https://attack.mitre.org/detectionstrategies/DET0013#AN0037) | T1217 Browser Information Discovery | discovery | 42 | hunting | DC0032, DC0039, DC0064 |
| 25 | [AN1061](https://attack.mitre.org/detectionstrategies/DET0377#AN1061) | T1014 Rootkit | stealth | 42 | ttp | DC0039, DC0060, DC0079 |
| 26 | [AN0271](https://attack.mitre.org/detectionstrategies/DET0097#AN0271) | T1010 Application Window Discovery | discovery | 40 | hunting | DC0035, DC0064 |
| 27 | [AN0838](https://attack.mitre.org/detectionstrategies/DET0300#AN0838) | T1620 Reflective Code Loading | stealth | 40 | ttp | DC0016, DC0021, DC0029, DC0032, DC0035 |
| 28 | [AN0327](https://attack.mitre.org/detectionstrategies/DET0118#AN0327) | T1210 Exploitation of Remote Services | lateral-movement | 39 | anomaly | DC0016, DC0032, DC0035, DC0038, DC0039, DC0082, DC0085 |
| 29 | [AN0445](https://attack.mitre.org/detectionstrategies/DET0158#AN0445) | T1218.007 Msiexec | stealth | 39 | ttp | DC0016, DC0032, DC0082 |
| 30 | [AN0520](https://attack.mitre.org/detectionstrategies/DET0184#AN0520) | T1070 Indicator Removal | stealth | 39 | ttp | DC0038, DC0040, DC0063 |
| 31 | [AN0568](https://attack.mitre.org/detectionstrategies/DET0197#AN0568) | T1125 Video Capture | collection | 39 | anomaly | DC0016, DC0021, DC0032, DC0034, DC0039, DC0082 |
| 32 | [AN0875](https://attack.mitre.org/detectionstrategies/DET0314#AN0875) | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0032, DC0060 |
| 33 | [AN0922](https://attack.mitre.org/detectionstrategies/DET0325#AN0922) | T1090.002 External Proxy | command-and-control | 39 | anomaly | DC0032, DC0082, DC0085 |
| 34 | [AN1015](https://attack.mitre.org/detectionstrategies/DET0357#AN1015) | T1016.001 Internet Connection Discovery | discovery | 39 | hunting | DC0032, DC0064, DC0082 |
| 35 | [AN1402](https://attack.mitre.org/detectionstrategies/DET0509#AN1402) | T1539 Steal Web Session Cookie | credential-access | 39 | ttp | DC0032, DC0035, DC0061 |
| 36 | [AN1528](https://attack.mitre.org/detectionstrategies/DET0553#AN1528) | T1027.001 Binary Padding | stealth | 39 | anomaly | DC0032, DC0039, DC0055 |
| 37 | [AN0109](https://attack.mitre.org/detectionstrategies/DET0039#AN0109) | T1568 Dynamic Resolution | command-and-control | 38 | anomaly | DC0032, DC0082 |
| 38 | [AN0236](https://attack.mitre.org/detectionstrategies/DET0086#AN0236) | T1546.003 Windows Management Instrumentation Event Subscription | privilege-escalation, persistence | 37 | anomaly | DC0008, DC0016, DC0032 |
| 39 | [AN1366](https://attack.mitre.org/detectionstrategies/DET0496#AN1366) | T1219 Remote Access Tools | command-and-control | 37 | ttp | DC0032, DC0039, DC0056, DC0060, DC0063, DC0082 |
| 40 | [AN1538](https://attack.mitre.org/detectionstrategies/DET0559#AN1538) | T1529 System Shutdown/Reboot | impact | 37 | ttp | DC0018, DC0032 |
| 41 | [AN0158](https://attack.mitre.org/detectionstrategies/DET0058#AN0158) | T1102.001 Dead Drop Resolver | command-and-control | 36 | ttp | DC0082, DC0085 |
| 42 | [AN0841](https://attack.mitre.org/detectionstrategies/DET0301#AN0841) | T1091 Replication Through Removable Media | lateral-movement, initial-access | 36 | anomaly | DC0032, DC0039, DC0042, DC0055 |
| 43 | [AN1144](https://attack.mitre.org/detectionstrategies/DET0409#AN1144) | T1550.002 Pass the Hash | lateral-movement | 36 | anomaly | DC0032, DC0067, DC0082, DC0084 |
| 44 | [AN1169](https://attack.mitre.org/detectionstrategies/DET0416#AN1169) | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0032, DC0082, DC0085 |
| 45 | [AN1516](https://attack.mitre.org/detectionstrategies/DET0549#AN1516) | T1552.004 Private Keys | credential-access | 36 | ttp | DC0032, DC0039, DC0102 |
| 46 | [AN0973](https://attack.mitre.org/detectionstrategies/DET0344#AN0973) | T1027.011 Fileless Storage | stealth | 35 | anomaly | DC0008, DC0063 |
| 47 | [AN0619](https://attack.mitre.org/detectionstrategies/DET0221#AN0619) | T1123 Audio Capture | collection | 34 | anomaly | DC0032, DC0035, DC0039 |
| 48 | [AN0913](https://attack.mitre.org/detectionstrategies/DET0322#AN0913) | T1027.016 Junk Code Insertion | stealth | 34 | anomaly | DC0032, DC0035, DC0039 |
| 49 | [AN1336](https://attack.mitre.org/detectionstrategies/DET0487#AN1336) | T1110.003 Password Spraying | credential-access | 34 | anomaly | DC0002 |
| 50 | [AN0320](https://attack.mitre.org/detectionstrategies/DET0115#AN0320) | T1566.003 Spearphishing via Service | initial-access | 33 | ttp | DC0032, DC0039, DC0082 |
| 51 | [AN0510](https://attack.mitre.org/detectionstrategies/DET0180#AN0510) | T1547.009 Shortcut Modification | persistence, privilege-escalation | 33 | anomaly | DC0032, DC0039, DC0059, DC0061 |
| 52 | [AN0648](https://attack.mitre.org/detectionstrategies/DET0234#AN0648) | T1003 OS Credential Dumping | credential-access | 33 | ttp | DC0032, DC0035, DC0055, DC0071 |
| 53 | [AN0379](https://attack.mitre.org/detectionstrategies/DET0135#AN0379) | T1071.003 Mail Protocols | command-and-control | 32 | ttp | DC0032, DC0082, DC0085 |
| 54 | [AN1393](https://attack.mitre.org/detectionstrategies/DET0504#AN1393) | T1559.002 Dynamic Data Exchange | execution | 32 | anomaly | DC0016, DC0032, DC0050 |
| 55 | [AN0127](https://attack.mitre.org/detectionstrategies/DET0046#AN0127) | T1497 Virtualization/Sandbox Evasion | stealth, discovery | 31 | ttp | DC0016, DC0032 |
| 56 | [AN0130](https://attack.mitre.org/detectionstrategies/DET0047#AN0130) | T1114.001 Local Email Collection | collection | 31 | ttp | DC0032, DC0039, DC0055, DC0082 |
| 57 | [AN0714](https://attack.mitre.org/detectionstrategies/DET0259#AN0714) | T1219.002 Remote Desktop Software | command-and-control | 31 | ttp | DC0039, DC0051, DC0082 |
| 58 | [AN0949](https://attack.mitre.org/detectionstrategies/DET0336#AN0949) | T1554 Compromise Host Software Binary | persistence | 31 | anomaly | DC0032, DC0039, DC0061 |
| 59 | [AN1212](https://attack.mitre.org/detectionstrategies/DET0437#AN1212) | T1003.004 LSA Secrets | credential-access | 31 | ttp | DC0016, DC0032, DC0035, DC0061 |
| 60 | [AN0119](https://attack.mitre.org/detectionstrategies/DET0043#AN0119) | T1614 System Location Discovery | discovery | 30 | hunting | DC0021, DC0032 |
| 61 | [AN1048](https://attack.mitre.org/detectionstrategies/DET0372#AN1048) | T1678 Delay Execution | stealth | 30 | ttp | DC0016, DC0032 |
| 62 | [AN1344](https://attack.mitre.org/detectionstrategies/DET0488#AN1344) | T1199 Trusted Relationship | initial-access | 30 | ttp | DC0038, DC0067, DC0082, DC0088 |
| 63 | [AN0599](https://attack.mitre.org/detectionstrategies/DET0214#AN0599) | T1027.009 Embedded Payloads | stealth | 29 | anomaly | DC0032, DC0039, DC0059 |
| 64 | [AN0630](https://attack.mitre.org/detectionstrategies/DET0226#AN0630) | T1036.008 Masquerade File Type | stealth | 29 | anomaly | DC0032, DC0039 |
| 65 | [AN1045](https://attack.mitre.org/detectionstrategies/DET0371#AN1045) | T1622 Debugger Evasion | stealth, discovery | 29 | ttp | DC0021, DC0032 |
| 66 | [AN0540](https://attack.mitre.org/detectionstrategies/DET0189#AN0540) | T1027.005 Indicator Removal from Tools | stealth | 28 | anomaly | DC0032, DC0038, DC0039 |
| 67 | [AN0596](https://attack.mitre.org/detectionstrategies/DET0213#AN0596) | T1030 Data Transfer Size Limits | exfiltration | 28 | anomaly | DC0078, DC0082 |
| 68 | [AN1410](https://attack.mitre.org/detectionstrategies/DET0511#AN1410) | T1025 Data from Removable Media | collection | 28 | anomaly | DC0032, DC0042, DC0055 |
| 69 | [AN1448](https://attack.mitre.org/detectionstrategies/DET0524#AN1448) | T1205 Traffic Signaling | stealth, persistence, command-and-control | 28 | anomaly | DC0032, DC0064, DC0078, DC0082 |
| 70 | [AN1511](https://attack.mitre.org/detectionstrategies/DET0548#AN1511) | T1567 Exfiltration Over Web Service | exfiltration | 28 | anomaly | DC0032, DC0039, DC0082 |
| 71 | [AN0194](https://attack.mitre.org/detectionstrategies/DET0071#AN0194) | T1074.002 Remote Data Staging | collection | 27 | ttp | DC0039, DC0064, DC0102 |
| 72 | [AN0786](https://attack.mitre.org/detectionstrategies/DET0283#AN0786) | T1134 Access Token Manipulation | stealth, privilege-escalation | 27 | anomaly | DC0021, DC0032, DC0035, DC0066, DC0088 |
| 73 | [AN0827](https://attack.mitre.org/detectionstrategies/DET0297#AN0827) | T1561.002 Disk Structure Wipe | impact | 27 | ttp | DC0013, DC0046, DC0079 |
| 74 | [AN1294](https://attack.mitre.org/detectionstrategies/DET0470#AN1294) | T1001.003 Protocol or Service Impersonation | command-and-control | 27 | ttp | DC0082, DC0085 |
| 75 | [AN0628](https://attack.mitre.org/detectionstrategies/DET0224#AN0628) | T1559.001 Component Object Model | execution | 26 | anomaly | DC0016, DC0032, DC0050 |
| … | 287 more | | | | | |

## Linux

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|
| 1 | [AN0166](https://attack.mitre.org/detectionstrategies/DET0060#AN0166) | T1105 Ingress Tool Transfer | command-and-control | 651 | ttp | DC0039, DC0064, DC0078 |
| 2 | [AN1453](https://attack.mitre.org/detectionstrategies/DET0525#AN1453) | T1082 System Information Discovery | discovery | 511 | hunting | DC0032 |
| 3 | [AN0076](https://attack.mitre.org/detectionstrategies/DET0027#AN0076) | T1071.001 Web Protocols | command-and-control | 510 | anomaly | DC0032, DC0085 |
| 4 | [AN1041](https://attack.mitre.org/detectionstrategies/DET0370#AN1041) | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0032, DC0055 |
| 5 | [AN0768](https://attack.mitre.org/detectionstrategies/DET0275#AN0768) | T1140 Deobfuscate/Decode Files or Information | stealth | 410 | ttp | DC0064 |
| 6 | [AN0393](https://attack.mitre.org/detectionstrategies/DET0140#AN0393) | T1070.004 File Deletion | stealth | 380 | ttp | DC0032, DC0040 |
| 7 | [AN0096](https://attack.mitre.org/detectionstrategies/DET0034#AN0096) | T1057 Process Discovery | discovery | 379 | hunting | DC0032, DC0035, DC0055 |
| 8 | [AN0560](https://attack.mitre.org/detectionstrategies/DET0195#AN0560) | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0032 |
| 9 | [AN0238](https://attack.mitre.org/detectionstrategies/DET0087#AN0238) | T1027.013 Encrypted/Encoded File | stealth | 310 | ttp | DC0032, DC0082 |
| 10 | [AN0984](https://attack.mitre.org/detectionstrategies/DET0347#AN0984) | T1036.005 Match Legitimate Resource Name or Location | stealth | 307 | ttp | DC0020, DC0032, DC0055, DC0059 |
| 11 | [AN0255](https://attack.mitre.org/detectionstrategies/DET0093#AN0255) | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0032 |
| 12 | [AN1071](https://attack.mitre.org/detectionstrategies/DET0380#AN1071) | T1005 Data from Local System | collection | 298 | ttp | DC0032, DC0055 |
| 13 | [AN0821](https://attack.mitre.org/detectionstrategies/DET0294#AN0821) | T1204.002 Malicious File | execution | 296 | anomaly | DC0032, DC0039 |
| 14 | [AN1466](https://attack.mitre.org/detectionstrategies/DET0529#AN1466) | T1106 Native API | execution | 262 | ttp | DC0016, DC0035 |
| 15 | [AN0989](https://attack.mitre.org/detectionstrategies/DET0348#AN0989) | T1041 Exfiltration Over C2 Channel | exfiltration | 249 | anomaly | DC0032, DC0078, DC0082, DC0085 |
| 16 | [AN0656](https://attack.mitre.org/detectionstrategies/DET0236#AN0656) | T1566.001 Spearphishing Attachment | initial-access | 240 | ttp | DC0032, DC0038, DC0078 |
| 17 | [AN0401](https://attack.mitre.org/detectionstrategies/DET0143#AN0401) | T1573.001 Symmetric Cryptography | command-and-control | 203 | ttp | DC0016, DC0032, DC0038 |
| 18 | [AN0211](https://attack.mitre.org/detectionstrategies/DET0076#AN0211) | T1059.005 Visual Basic | execution | 193 | ttp | DC0029, DC0032 |
| 19 | [AN0982](https://attack.mitre.org/detectionstrategies/DET0346#AN0982) | T1113 Screen Capture | collection | 192 | ttp | DC0032 |
| 20 | [AN1065](https://attack.mitre.org/detectionstrategies/DET0378#AN1065) | T1027 Obfuscated Files or Information | stealth | 188 | ttp | DC0032, DC0061, DC0064 |
| 21 | [AN0725](https://attack.mitre.org/detectionstrategies/DET0261#AN0725) | T1074.001 Local Data Staging | collection | 186 | ttp | DC0032, DC0055 |
| 22 | [AN0244](https://attack.mitre.org/detectionstrategies/DET0089#AN0244) | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0021, DC0055 |
| 23 | [AN1370](https://attack.mitre.org/detectionstrategies/DET0497#AN1370) | T1685 Disable or Modify Tools | defense-impairment | 173 | ttp | DC0032, DC0041 |
| 24 | [AN0049](https://attack.mitre.org/detectionstrategies/DET0016#AN0049) | T1518.001 Security Software Discovery | discovery | 172 | hunting | DC0032 |
| 25 | [AN1584](https://attack.mitre.org/detectionstrategies/DET0574#AN1584) | T1018 Remote System Discovery | discovery | 161 | hunting | DC0032, DC0082 |
| 26 | [AN0179](https://attack.mitre.org/detectionstrategies/DET0066#AN0179) | T1204.001 Malicious Link | execution | 149 | ttp | DC0039, DC0082, DC0085 |
| 27 | [AN0220](https://attack.mitre.org/detectionstrategies/DET0080#AN0220) | T1190 Exploit Public-Facing Application | initial-access | 146 | anomaly | DC0032, DC0038, DC0085 |
| 28 | [AN0299](https://attack.mitre.org/detectionstrategies/DET0107#AN0299) | T1566.002 Spearphishing Link | initial-access | 146 | ttp | DC0032, DC0038, DC0078 |
| 29 | [AN0346](https://attack.mitre.org/detectionstrategies/DET0124#AN0346) | T1132.001 Standard Encoding | command-and-control | 145 | anomaly | DC0032, DC0082, DC0085 |
| 30 | [AN0832](https://attack.mitre.org/detectionstrategies/DET0298#AN0832) | T1560.001 Archive via Utility | collection | 140 | ttp | DC0039, DC0064 |
| 31 | [AN0904](https://attack.mitre.org/detectionstrategies/DET0320#AN0904) | T1049 System Network Connections Discovery | discovery | 137 | hunting | DC0032, DC0064 |
| 32 | [AN0067](https://attack.mitre.org/detectionstrategies/DET0023#AN0067) | T1027.002 Software Packing | stealth | 136 | anomaly | DC0020, DC0032 |
| 33 | [AN1255](https://attack.mitre.org/detectionstrategies/DET0457#AN1255) | T1095 Non-Application Layer Protocol | command-and-control | 130 | ttp | DC0082, DC0085 |
| 34 | [AN1544](https://attack.mitre.org/detectionstrategies/DET0560#AN1544) | T1078 Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 129 | anomaly | DC0002, DC0032 |
| 35 | [AN0325](https://attack.mitre.org/detectionstrategies/DET0117#AN0325) | T1036.004 Masquerade Task or Service | stealth | 126 | ttp | DC0005, DC0012, DC0041 |
| 36 | [AN0431](https://attack.mitre.org/detectionstrategies/DET0151#AN0431) | T1124 System Time Discovery | discovery | 122 | hunting | DC0002, DC0005, DC0021, DC0032 |
| 37 | [AN0106](https://attack.mitre.org/detectionstrategies/DET0037#AN0106) | T1555.003 Credentials from Web Browsers | credential-access | 119 | ttp | DC0035, DC0055 |
| 38 | [AN1058](https://attack.mitre.org/detectionstrategies/DET0376#AN1058) | T1046 Network Service Discovery | discovery | 118 | hunting | DC0032, DC0078 |
| 39 | [AN0537](https://attack.mitre.org/detectionstrategies/DET0188#AN0537) | T1680 Local Storage Discovery | discovery | 116 | hunting | DC0032, DC0064 |
| 40 | [AN1497](https://attack.mitre.org/detectionstrategies/DET0543#AN1497) | T1573.002 Asymmetric Cryptography | command-and-control | 116 | anomaly | DC0016, DC0032, DC0038 |
| 41 | [AN0735](https://attack.mitre.org/detectionstrategies/DET0264#AN0735) | T1059.007 JavaScript | execution | 113 | ttp | DC0029, DC0032 |
| 42 | [AN1109](https://attack.mitre.org/detectionstrategies/DET0394#AN1109) | T1505.003 Web Shell | persistence | 112 | anomaly | DC0032, DC0039, DC0085 |
| 43 | [AN1395](https://attack.mitre.org/detectionstrategies/DET0505#AN1395) | T1027.010 Command Obfuscation | stealth | 112 | anomaly | DC0032, DC0064 |
| 44 | [AN0603](https://attack.mitre.org/detectionstrategies/DET0215#AN0603) | T1486 Data Encrypted for Impact | impact | 111 | ttp | DC0032, DC0061 |
| 45 | [AN1400](https://attack.mitre.org/detectionstrategies/DET0508#AN1400) | T1055 Process Injection | stealth, privilege-escalation | 110 | anomaly | DC0020, DC0021, DC0055 |
| 46 | [AN0798](https://attack.mitre.org/detectionstrategies/DET0287#AN0798) | T1203 Exploitation for Client Execution | execution | 108 | ttp | DC0032, DC0038, DC0039, DC0055, DC0061, DC0078 |
| 47 | [AN1230](https://attack.mitre.org/detectionstrategies/DET0445#AN1230) | T1090 Proxy | command-and-control | 108 | ttp | DC0032, DC0078 |
| 48 | [AN0532](https://attack.mitre.org/detectionstrategies/DET0186#AN0532) | T1119 Automated Collection | collection | 106 | ttp | DC0032, DC0055 |
| 49 | [AN0514](https://attack.mitre.org/detectionstrategies/DET0182#AN0514) | T1135 Network Share Discovery | discovery | 99 | hunting | DC0021, DC0032, DC0082 |
| 50 | [AN0364](https://attack.mitre.org/detectionstrategies/DET0129#AN0364) | T1087.002 Domain Account | discovery | 96 | hunting | DC0032, DC0064, DC0085 |
| 51 | [AN0634](https://attack.mitre.org/detectionstrategies/DET0227#AN0634) | T1571 Non-Standard Port | command-and-control | 95 | anomaly | DC0032, DC0038, DC0078 |
| 52 | [AN0174](https://attack.mitre.org/detectionstrategies/DET0063#AN0174) | T1059.006 Python | execution | 92 | ttp | DC0029, DC0032 |
| 53 | [AN1081](https://attack.mitre.org/detectionstrategies/DET0384#AN1081) | T1059.004 Unix Shell | execution | 90 | ttp | DC0032, DC0067, DC0078 |
| 54 | [AN0356](https://attack.mitre.org/detectionstrategies/DET0127#AN0356) | T1036 Masquerading | stealth | 89 | anomaly | DC0032, DC0059, DC0061 |
| 55 | [AN1326](https://attack.mitre.org/detectionstrategies/DET0483#AN1326) | T1007 System Service Discovery | discovery | 88 | hunting | DC0032 |
| 56 | [AN0847](https://attack.mitre.org/detectionstrategies/DET0303#AN0847) | T1087.001 Local Account | discovery | 87 | hunting | DC0032, DC0055 |
| 57 | [AN0517](https://attack.mitre.org/detectionstrategies/DET0183#AN0517) | T1570 Lateral Tool Transfer | lateral-movement | 83 | ttp | DC0039, DC0064 |
| 58 | [AN0361](https://attack.mitre.org/detectionstrategies/DET0128#AN0361) | T1564.003 Hidden Window | stealth | 81 | ttp | DC0034, DC0064 |
| 59 | [AN0479](https://attack.mitre.org/detectionstrategies/DET0168#AN0479) | T1497.001 System Checks | stealth, discovery | 81 | ttp | DC0032 |
| 60 | [AN1005](https://attack.mitre.org/detectionstrategies/DET0354#AN1005) | T1133 External Remote Services | persistence, initial-access | 81 | anomaly | DC0038, DC0082, DC0088 |
| 61 | [AN0499](https://attack.mitre.org/detectionstrategies/DET0176#AN0499) | T1189 Drive-by Compromise | initial-access | 79 | anomaly | DC0032, DC0038, DC0039, DC0082, DC0085 |
| 62 | [AN0092](https://attack.mitre.org/detectionstrategies/DET0032#AN0092) | T1564.001 Hidden Files and Directories | stealth | 76 | ttp | DC0039, DC0064 |
| 63 | [AN0101](https://attack.mitre.org/detectionstrategies/DET0035#AN0101) | T1102.002 Bidirectional Communication | command-and-control | 74 | ttp | DC0032, DC0078, DC0085 |
| 64 | [AN1627](https://attack.mitre.org/detectionstrategies/DET0591#AN1627) | T1070.006 Timestomp | stealth | 74 | anomaly | DC0032, DC0059 |
| 65 | [AN1572](https://attack.mitre.org/detectionstrategies/DET0570#AN1572) | T1567.002 Exfiltration to Cloud Storage | exfiltration | 72 | ttp | DC0055, DC0064, DC0078 |
| 66 | [AN1190](https://attack.mitre.org/detectionstrategies/DET0425#AN1190) | T1102 Web Service | command-and-control | 71 | anomaly | DC0082, DC0085 |
| 67 | [AN1459](https://attack.mitre.org/detectionstrategies/DET0526#AN1459) | T1560 Archive Collected Data | collection | 70 | anomaly | DC0039, DC0064 |
| 68 | [AN1101](https://attack.mitre.org/detectionstrategies/DET0392#AN1101) | T1518 Software Discovery | discovery | 69 | hunting | DC0032, DC0064 |
| 69 | [AN1354](https://attack.mitre.org/detectionstrategies/DET0491#AN1354) | T1120 Peripheral Device Discovery | discovery | 69 | hunting | DC0032, DC0054, DC0055 |
| 70 | [AN1420](https://attack.mitre.org/detectionstrategies/DET0514#AN1420) | T1068 Exploitation for Privilege Escalation | privilege-escalation | 69 | anomaly | DC0016, DC0032, DC0035 |
| 71 | [AN1122](https://attack.mitre.org/detectionstrategies/DET0400#AN1122) | T1071.004 DNS | command-and-control | 68 | ttp | DC0032, DC0085 |
| 72 | [AN0591](https://attack.mitre.org/detectionstrategies/DET0210#AN0591) | T1078.002 Domain Accounts | stealth, persistence, privilege-escalation, initial-access | 67 | ttp | DC0002, DC0088 |
| 73 | [AN1429](https://attack.mitre.org/detectionstrategies/DET0516#AN1429) | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0032 |
| 74 | [AN1484](https://attack.mitre.org/detectionstrategies/DET0538#AN1484) | T1572 Protocol Tunneling | command-and-control | 66 | ttp | DC0032, DC0038, DC0082 |
| 75 | [AN0934](https://attack.mitre.org/detectionstrategies/DET0329#AN0934) | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0040, DC0064 |
| … | 283 more | | | | | |

## Network Devices

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|
| 1 | [AN0169](https://attack.mitre.org/detectionstrategies/DET0060#AN0169) | T1105 Ingress Tool Transfer | command-and-control | 651 | anomaly | DC0039, DC0078 |
| 2 | [AN1457](https://attack.mitre.org/detectionstrategies/DET0525#AN1457) | T1082 System Information Discovery | discovery | 511 | hunting | DC0064 |
| 3 | [AN1044](https://attack.mitre.org/detectionstrategies/DET0370#AN1044) | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0064 |
| 4 | [AN0099](https://attack.mitre.org/detectionstrategies/DET0034#AN0099) | T1057 Process Discovery | discovery | 379 | hunting | DC0034, DC0064 |
| 5 | [AN0563](https://attack.mitre.org/detectionstrategies/DET0195#AN0563) | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0064 |
| 6 | [AN0257](https://attack.mitre.org/detectionstrategies/DET0093#AN0257) | T1033 System Owner/User Discovery | discovery | 300 | hunting | DC0021, DC0064 |
| 7 | [AN1073](https://attack.mitre.org/detectionstrategies/DET0380#AN1073) | T1005 Data from Local System | collection | 298 | ttp | DC0064 |
| 8 | [AN0246](https://attack.mitre.org/detectionstrategies/DET0089#AN0246) | T1056.001 Keylogging | collection, credential-access | 184 | ttp | DC0004, DC0085 |
| 9 | [AN1587](https://attack.mitre.org/detectionstrategies/DET0574#AN1587) | T1018 Remote System Discovery | discovery | 161 | hunting | DC0064 |
| 10 | [AN0225](https://attack.mitre.org/detectionstrategies/DET0080#AN0225) | T1190 Exploit Public-Facing Application | initial-access | 146 | ttp | DC0038, DC0085 |
| 11 | [AN0907](https://attack.mitre.org/detectionstrategies/DET0320#AN0907) | T1049 System Network Connections Discovery | discovery | 137 | hunting | DC0021, DC0064 |
| 12 | [AN0434](https://attack.mitre.org/detectionstrategies/DET0151#AN0434) | T1124 System Time Discovery | discovery | 122 | hunting | DC0061, DC0064 |
| 13 | [AN1084](https://attack.mitre.org/detectionstrategies/DET0384#AN1084) | T1059.004 Unix Shell | execution | 90 | ttp | DC0064, DC0082 |
| 14 | [AN1432](https://attack.mitre.org/detectionstrategies/DET0516#AN1432) | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0002, DC0064 |
| 15 | [AN0936](https://attack.mitre.org/detectionstrategies/DET0329#AN0936) | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0064 |
| 16 | [AN0208](https://attack.mitre.org/detectionstrategies/DET0075#AN0208) | T1090.001 Internal Proxy | command-and-control | 49 | ttp | DC0051, DC0064, DC0078 |
| 17 | [AN0879](https://attack.mitre.org/detectionstrategies/DET0314#AN0879) | T1040 Network Sniffing | credential-access, discovery | 39 | ttp | DC0002, DC0064, DC0085 |
| 18 | [AN1519](https://attack.mitre.org/detectionstrategies/DET0549#AN1519) | T1552.004 Private Keys | credential-access | 36 | ttp | DC0064 |
| 19 | [AN1451](https://attack.mitre.org/detectionstrategies/DET0524#AN1451) | T1205 Traffic Signaling | stealth, persistence, command-and-control | 28 | ttp | DC0078, DC0082 |
| 20 | [AN0830](https://attack.mitre.org/detectionstrategies/DET0297#AN0830) | T1561.002 Disk Structure Wipe | impact | 27 | ttp | DC0002, DC0064 |
| 21 | [AN0471](https://attack.mitre.org/detectionstrategies/DET0165#AN0471) | T1070.003 Clear Command History | stealth | 24 | ttp | DC0064 |
| 22 | [AN1228](https://attack.mitre.org/detectionstrategies/DET0444#AN1228) | T1071 Application Layer Protocol | command-and-control | 24 | ttp | DC0085 |
| 23 | [AN0627](https://attack.mitre.org/detectionstrategies/DET0223#AN0627) | T1072 Software Deployment Tools | execution, lateral-movement | 23 | ttp | DC0038, DC0078 |
| 24 | [AN0763](https://attack.mitre.org/detectionstrategies/DET0273#AN0763) | T1573 Encrypted Channel | command-and-control | 23 | anomaly | DC0078, DC0085 |
| 25 | [AN0885](https://attack.mitre.org/detectionstrategies/DET0316#AN0885) | T1561.001 Disk Content Wipe | impact | 22 | ttp | DC0002, DC0064 |
| 26 | [AN1559](https://attack.mitre.org/detectionstrategies/DET0563#AN1559) | T1690 Prevent Command History Logging | defense-impairment | 19 | ttp | DC0064 |
| 27 | [AN0285](https://attack.mitre.org/detectionstrategies/DET0102#AN0285) | T1056 Input Capture | collection, credential-access | 17 | ttp | DC0082, DC0085 |
| 28 | [AN0296](https://attack.mitre.org/detectionstrategies/DET0105#AN0296) | T1110.002 Password Cracking | credential-access | 15 | ttp | DC0002 |
| 29 | [AN0315](https://attack.mitre.org/detectionstrategies/DET0112#AN0315) | T1037 Boot or Logon Initialization Scripts | persistence, privilege-escalation | 13 | ttp | DC0061 |
| 30 | [AN0826](https://attack.mitre.org/detectionstrategies/DET0296#AN0826) | T1557 Adversary-in-the-Middle | credential-access, collection | 13 | ttp | DC0061, DC0078 |
| 31 | [AN1151](https://attack.mitre.org/detectionstrategies/DET0411#AN1151) | T1665 Hide Infrastructure | command-and-control | 13 | ttp | DC0085 |
| 32 | [AN0136](https://attack.mitre.org/detectionstrategies/DET0049#AN0136) | T1070.007 Clear Network Connection History and Configurations | stealth | 12 | ttp | DC0064, DC0085 |
| 33 | [AN0461](https://attack.mitre.org/detectionstrategies/DET0161#AN0461) | T1201 Password Policy Discovery | discovery | 12 | hunting | DC0064 |
| 34 | [AN0661](https://attack.mitre.org/detectionstrategies/DET0237#AN0661) | T1037.004 RC Scripts | persistence, privilege-escalation | 12 | ttp | DC0061, DC0064 |
| 35 | [AN1159](https://attack.mitre.org/detectionstrategies/DET0412#AN1159) | T1552 Unsecured Credentials | credential-access | 12 | ttp | DC0064, DC0085 |
| 36 | [AN0399](https://attack.mitre.org/detectionstrategies/DET0142#AN0399) | T1059.008 Network Device CLI | execution | 9 | anomaly | DC0002, DC0064, DC0085 |
| 37 | [AN1194](https://attack.mitre.org/detectionstrategies/DET0426#AN1194) | T1006 Direct Volume Access | stealth | 9 | ttp | DC0064 |
| 38 | [AN0845](https://attack.mitre.org/detectionstrategies/DET0302#AN0845) | T1205.001 Port Knocking | stealth, persistence, command-and-control | 8 | ttp | DC0078, DC0082 |
| 39 | [AN0015](https://attack.mitre.org/detectionstrategies/DET0006#AN0015) | T1599 Network Boundary Bridging | defense-impairment | 6 | anomaly | DC0078, DC0085 |
| 40 | [AN0281](https://attack.mitre.org/detectionstrategies/DET0101#AN0281) | T1059.011 Lua | execution | 5 | ttp | DC0029 |
| 41 | [AN0647](https://attack.mitre.org/detectionstrategies/DET0233#AN0647) | T1602.002 Network Device Configuration Dump | collection | 5 | anomaly | DC0002, DC0064, DC0082, DC0085 |
| 42 | [AN1267](https://attack.mitre.org/detectionstrategies/DET0460#AN1267) | T1110.004 Credential Stuffing | credential-access | 5 | ttp | DC0002 |
| 43 | [AN0477](https://attack.mitre.org/detectionstrategies/DET0167#AN0477) | T1495 Firmware Corruption | impact | 4 | anomaly | DC0004, DC0085 |
| 44 | [AN1479](https://attack.mitre.org/detectionstrategies/DET0536#AN1479) | T1669 Wi-Fi Networks | initial-access | 4 | ttp | DC0051, DC0085 |
| 45 | [AN0758](https://attack.mitre.org/detectionstrategies/DET0272#AN0758) | T1556.004 Network Device Authentication | defense-impairment, persistence, credential-access | 3 | anomaly | DC0002, DC0061 |
| 46 | [AN0058](https://attack.mitre.org/detectionstrategies/DET0019#AN0058) | T1027.008 Stripped Payloads | stealth | 2 | ttp | DC0085 |
| 47 | [AN1069](https://attack.mitre.org/detectionstrategies/DET0379#AN1069) | T1557.004 Evil Twin | credential-access, collection | 2 | anomaly | DC0038, DC0078, DC0085 |
| 48 | [AN1132](https://attack.mitre.org/detectionstrategies/DET0403#AN1132) | T1020.001 Traffic Duplication | exfiltration | 2 | ttp | DC0078, DC0082 |
| 49 | [AN1249](https://attack.mitre.org/detectionstrategies/DET0453#AN1249) | T1602.001 SNMP (MIB Dump) | collection | 2 | anomaly | DC0061, DC0082, DC0085 |
| 50 | [AN0482](https://attack.mitre.org/detectionstrategies/DET0170#AN0482) | T1601 Modify System Image | defense-impairment | 1 | anomaly | DC0061, DC0064 |
| 51 | [AN1219](https://attack.mitre.org/detectionstrategies/DET0439#AN1219) | T1070.010 Relocate Malware | stealth | 1 | ttp | DC0064 |
| 52 | [AN1293](https://attack.mitre.org/detectionstrategies/DET0469#AN1293) | T1601.001 Patch System Image | defense-impairment | 1 | anomaly | DC0004, DC0061, DC0064 |
| 53 | [AN0387](https://attack.mitre.org/detectionstrategies/DET0137#AN0387) | T1561 Disk Wipe | impact | 0 | ttp | DC0002, DC0064 |
| 54 | [AN0465](https://attack.mitre.org/detectionstrategies/DET0163#AN0465) | T1599.001 Network Address Translation Traversal | defense-impairment | 0 | anomaly | DC0078, DC0085 |
| 55 | [AN0497](https://attack.mitre.org/detectionstrategies/DET0175#AN0497) | T1542.004 ROMMONkit | stealth, persistence | 0 | anomaly | DC0004, DC0021, DC0082 |
| 56 | [AN0681](https://attack.mitre.org/detectionstrategies/DET0243#AN0681) | T1600.001 Reduce Key Space | defense-impairment | 0 | anomaly | DC0061, DC0064, DC0085 |
| 57 | [AN0777](https://attack.mitre.org/detectionstrategies/DET0278#AN0777) | T1542 Pre-OS Boot | stealth, persistence | 0 | anomaly | DC0004, DC0046 |
| 58 | [AN0893](https://attack.mitre.org/detectionstrategies/DET0317#AN0893) |   |  | 0 | ttp | DC0064 |
| 59 | [AN0961](https://attack.mitre.org/detectionstrategies/DET0339#AN0961) | T1600 Weaken Encryption | defense-impairment | 0 | anomaly | DC0016, DC0061, DC0085 |
| 60 | [AN1360](https://attack.mitre.org/detectionstrategies/DET0494#AN1360) | T1600.002 Disable Crypto Hardware | defense-impairment | 0 | anomaly | DC0061, DC0064, DC0085 |
| 61 | [AN1570](https://attack.mitre.org/detectionstrategies/DET0569#AN1570) | T1601.002 Downgrade System Image | defense-impairment | 0 | anomaly | DC0059, DC0061, DC0064 |
| 62 | [AN1603](https://attack.mitre.org/detectionstrategies/DET0582#AN1603) | T1542.005 TFTP Boot | stealth, persistence | 0 | anomaly | DC0004, DC0064, DC0082 |
| 63 | [AN1630](https://attack.mitre.org/detectionstrategies/DET0592#AN1630) | T1602 Data from Configuration Repository | collection | 0 | anomaly | DC0082, DC0085 |

## ESXi

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|
| 1 | [AN0168](https://attack.mitre.org/detectionstrategies/DET0060#AN0168) | T1105 Ingress Tool Transfer | command-and-control | 651 | ttp | DC0039, DC0064 |
| 2 | [AN1455](https://attack.mitre.org/detectionstrategies/DET0525#AN1455) | T1082 System Information Discovery | discovery | 511 | hunting | DC0064 |
| 3 | [AN0078](https://attack.mitre.org/detectionstrategies/DET0027#AN0078) | T1071.001 Web Protocols | command-and-control | 510 | ttp | DC0032, DC0085 |
| 4 | [AN1043](https://attack.mitre.org/detectionstrategies/DET0370#AN1043) | T1083 File and Directory Discovery | discovery | 447 | hunting | DC0055, DC0064 |
| 5 | [AN0395](https://attack.mitre.org/detectionstrategies/DET0140#AN0395) | T1070.004 File Deletion | stealth | 380 | ttp | DC0040 |
| 6 | [AN0098](https://attack.mitre.org/detectionstrategies/DET0034#AN0098) | T1057 Process Discovery | discovery | 379 | hunting | DC0034, DC0064 |
| 7 | [AN0562](https://attack.mitre.org/detectionstrategies/DET0195#AN0562) | T1016 System Network Configuration Discovery | discovery | 351 | hunting | DC0064 |
| 8 | [AN0987](https://attack.mitre.org/detectionstrategies/DET0347#AN0987) | T1036.005 Match Legitimate Resource Name or Location | stealth | 307 | anomaly | DC0001, DC0016, DC0032, DC0041 |
| 9 | [AN1074](https://attack.mitre.org/detectionstrategies/DET0380#AN1074) | T1005 Data from Local System | collection | 298 | ttp | DC0055, DC0064 |
| 10 | [AN0991](https://attack.mitre.org/detectionstrategies/DET0348#AN0991) | T1041 Exfiltration Over C2 Channel | exfiltration | 249 | ttp | DC0055, DC0078, DC0085 |
| 11 | [AN0403](https://attack.mitre.org/detectionstrategies/DET0143#AN0403) | T1573.001 Symmetric Cryptography | command-and-control | 203 | ttp | DC0038, DC0085 |
| 12 | [AN1068](https://attack.mitre.org/detectionstrategies/DET0378#AN1068) | T1027 Obfuscated Files or Information | stealth | 188 | ttp | DC0021, DC0059 |
| 13 | [AN0727](https://attack.mitre.org/detectionstrategies/DET0261#AN0727) | T1074.001 Local Data Staging | collection | 186 | anomaly | DC0057, DC0064 |
| 14 | [AN2044](https://attack.mitre.org/detectionstrategies/DET0497#AN2044) | T1685 Disable or Modify Tools | defense-impairment | 173 | ttp | DC0064, DC0065 |
| 15 | [AN1586](https://attack.mitre.org/detectionstrategies/DET0574#AN1586) | T1018 Remote System Discovery | discovery | 161 | hunting | DC0064 |
| 16 | [AN0224](https://attack.mitre.org/detectionstrategies/DET0080#AN0224) | T1190 Exploit Public-Facing Application | initial-access | 146 | ttp | DC0038, DC0085 |
| 17 | [AN0348](https://attack.mitre.org/detectionstrategies/DET0124#AN0348) | T1132.001 Standard Encoding | command-and-control | 145 | anomaly | DC0032, DC0038, DC0078, DC0085 |
| 18 | [AN0906](https://attack.mitre.org/detectionstrategies/DET0320#AN0906) | T1049 System Network Connections Discovery | discovery | 137 | hunting | DC0064 |
| 19 | [AN1257](https://attack.mitre.org/detectionstrategies/DET0457#AN1257) | T1095 Non-Application Layer Protocol | command-and-control | 130 | ttp | DC0085 |
| 20 | [AN0433](https://attack.mitre.org/detectionstrategies/DET0151#AN0433) | T1124 System Time Discovery | discovery | 122 | hunting | DC0005, DC0034, DC0064 |
| 21 | [AN0539](https://attack.mitre.org/detectionstrategies/DET0188#AN0539) | T1680 Local Storage Discovery | discovery | 116 | hunting | DC0002, DC0032 |
| 22 | [AN1499](https://attack.mitre.org/detectionstrategies/DET0543#AN1499) | T1573.002 Asymmetric Cryptography | command-and-control | 116 | anomaly | DC0038, DC0085 |
| 23 | [AN0605](https://attack.mitre.org/detectionstrategies/DET0215#AN0605) | T1486 Data Encrypted for Impact | impact | 111 | ttp | DC0061, DC0064 |
| 24 | [AN1232](https://attack.mitre.org/detectionstrategies/DET0445#AN1232) | T1090 Proxy | command-and-control | 108 | ttp | DC0064, DC0078, DC0082 |
| 25 | [AN0636](https://attack.mitre.org/detectionstrategies/DET0227#AN0636) | T1571 Non-Standard Port | command-and-control | 95 | ttp | DC0078, DC0085 |
| 26 | [AN0175](https://attack.mitre.org/detectionstrategies/DET0063#AN0175) | T1059.006 Python | execution | 92 | ttp | DC0032, DC0064 |
| 27 | [AN1083](https://attack.mitre.org/detectionstrategies/DET0384#AN1083) | T1059.004 Unix Shell | execution | 90 | ttp | DC0064, DC0067 |
| 28 | [AN0359](https://attack.mitre.org/detectionstrategies/DET0127#AN0359) | T1036 Masquerading | stealth | 89 | ttp | DC0041, DC0064 |
| 29 | [AN0849](https://attack.mitre.org/detectionstrategies/DET0303#AN0849) | T1087.001 Local Account | discovery | 87 | hunting | DC0013, DC0032 |
| 30 | [AN0519](https://attack.mitre.org/detectionstrategies/DET0183#AN0519) | T1570 Lateral Tool Transfer | lateral-movement | 83 | ttp | DC0059, DC0064 |
| 31 | [AN1629](https://attack.mitre.org/detectionstrategies/DET0591#AN1629) | T1070.006 Timestomp | stealth | 74 | ttp | DC0061 |
| 32 | [AN1574](https://attack.mitre.org/detectionstrategies/DET0570#AN1574) | T1567.002 Exfiltration to Cloud Storage | exfiltration | 72 | anomaly | DC0055, DC0078 |
| 33 | [AN1192](https://attack.mitre.org/detectionstrategies/DET0425#AN1192) | T1102 Web Service | command-and-control | 71 | ttp | DC0078, DC0082 |
| 34 | [AN1104](https://attack.mitre.org/detectionstrategies/DET0392#AN1104) | T1518 Software Discovery | discovery | 69 | hunting | DC0038, DC0064 |
| 35 | [AN1125](https://attack.mitre.org/detectionstrategies/DET0400#AN1125) | T1071.004 DNS | command-and-control | 68 | anomaly | DC0078, DC0085 |
| 36 | [AN0593](https://attack.mitre.org/detectionstrategies/DET0210#AN0593) | T1078.002 Domain Accounts | stealth, persistence, privilege-escalation, initial-access | 67 | ttp | DC0002, DC0088 |
| 37 | [AN1431](https://attack.mitre.org/detectionstrategies/DET0516#AN1431) | T1059 Command and Scripting Interpreter | execution | 67 | ttp | DC0064 |
| 38 | [AN1486](https://attack.mitre.org/detectionstrategies/DET0538#AN1486) | T1572 Protocol Tunneling | command-and-control | 66 | ttp | DC0078, DC0085 |
| 39 | [AN0935](https://attack.mitre.org/detectionstrategies/DET0329#AN0935) | T1490 Inhibit System Recovery | impact | 65 | ttp | DC0049 |
| 40 | [AN1023](https://attack.mitre.org/detectionstrategies/DET0359#AN1023) | T1090.003 Multi-hop Proxy | command-and-control | 65 | ttp | DC0078, DC0082, DC0085 |
| 41 | [AN0064](https://attack.mitre.org/detectionstrategies/DET0021#AN0064) | T1489 Service Stop | impact | 64 | ttp | DC0033, DC0041 |
| 42 | [AN1379](https://attack.mitre.org/detectionstrategies/DET0499#AN1379) | T1008 Fallback Channels | command-and-control | 64 | ttp | DC0078, DC0082 |
| 43 | [AN1554](https://attack.mitre.org/detectionstrategies/DET0562#AN1554) | T1480 Execution Guardrails | stealth | 58 | anomaly | DC0032, DC0064 |
| 44 | [AN1640](https://attack.mitre.org/detectionstrategies/DET0596#AN1640) | T1021.004 SSH | lateral-movement | 51 | ttp | DC0064, DC0078, DC0088 |
| 45 | [AN0415](https://attack.mitre.org/detectionstrategies/DET0146#AN0415) | T1485 Data Destruction | impact | 50 | ttp | DC0098 |
| 46 | [AN0207](https://attack.mitre.org/detectionstrategies/DET0075#AN0207) | T1090.001 Internal Proxy | command-and-control | 49 | ttp | DC0032, DC0078, DC0082 |
| 47 | [AN1238](https://attack.mitre.org/detectionstrategies/DET0447#AN1238) | T1136.001 Local Account | persistence | 49 | ttp | DC0064 |
| 48 | [AN0426](https://attack.mitre.org/detectionstrategies/DET0149#AN0426) | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 48 | ttp | DC0064, DC0078, DC0085 |
| 49 | [AN0409](https://attack.mitre.org/detectionstrategies/DET0145#AN0409) | T1686 Disable or Modify System Firewall | defense-impairment | 45 | ttp | DC0051, DC0064 |
| 50 | [AN0329](https://attack.mitre.org/detectionstrategies/DET0118#AN0329) | T1210 Exploitation of Remote Services | lateral-movement | 39 | ttp | DC0038, DC0085 |
| 51 | [AN0524](https://attack.mitre.org/detectionstrategies/DET0184#AN0524) | T1070 Indicator Removal | stealth | 39 | ttp | DC0040 |
| 52 | [AN0925](https://attack.mitre.org/detectionstrategies/DET0325#AN0925) | T1090.002 External Proxy | command-and-control | 39 | ttp | DC0032, DC0078, DC0082 |
| 53 | [AN1018](https://attack.mitre.org/detectionstrategies/DET0357#AN1018) | T1016.001 Internet Connection Discovery | discovery | 39 | hunting | DC0029, DC0032 |
| 54 | [AN0112](https://attack.mitre.org/detectionstrategies/DET0039#AN0112) | T1568 Dynamic Resolution | command-and-control | 38 | ttp | DC0078 |
| 55 | [AN1541](https://attack.mitre.org/detectionstrategies/DET0559#AN1541) | T1529 System Shutdown/Reboot | impact | 37 | anomaly | DC0018, DC0064 |
| 56 | [AN0161](https://attack.mitre.org/detectionstrategies/DET0058#AN0161) | T1102.001 Dead Drop Resolver | command-and-control | 36 | ttp | DC0078, DC0082 |
| 57 | [AN1172](https://attack.mitre.org/detectionstrategies/DET0416#AN1172) | T1071.002 File Transfer Protocols | command-and-control | 36 | ttp | DC0064, DC0085 |
| 58 | [AN0952](https://attack.mitre.org/detectionstrategies/DET0336#AN0952) | T1554 Compromise Host Software Binary | persistence | 31 | ttp | DC0016, DC0061 |
| 59 | [AN1515](https://attack.mitre.org/detectionstrategies/DET0548#AN1515) | T1567 Exfiltration Over Web Service | exfiltration | 28 | ttp | DC0055, DC0082 |
| 60 | [AN0197](https://attack.mitre.org/detectionstrategies/DET0071#AN0197) | T1074.002 Remote Data Staging | collection | 27 | anomaly | DC0039, DC0064, DC0085 |
| 61 | [AN1297](https://attack.mitre.org/detectionstrategies/DET0470#AN1297) | T1001.003 Protocol or Service Impersonation | command-and-control | 27 | ttp | DC0082, DC0085 |
| 62 | [AN1181](https://attack.mitre.org/detectionstrategies/DET0419#AN1181) | T1568.002 Domain Generation Algorithms | command-and-control | 26 | anomaly | DC0078 |
| 63 | [AN0470](https://attack.mitre.org/detectionstrategies/DET0165#AN0470) | T1070.003 Clear Command History | stealth | 24 | ttp | DC0040 |
| 64 | [AN0807](https://attack.mitre.org/detectionstrategies/DET0290#AN0807) | T1053.003 Cron | execution, persistence, privilege-escalation | 24 | ttp | DC0001, DC0032, DC0061 |
| 65 | [AN0762](https://attack.mitre.org/detectionstrategies/DET0273#AN0762) | T1573 Encrypted Channel | command-and-control | 23 | ttp | DC0078, DC0085 |
| 66 | [AN0232](https://attack.mitre.org/detectionstrategies/DET0082#AN0232) | T1491.001 Internal Defacement | impact | 20 | ttp | DC0061, DC0064 |
| 67 | [AN0640](https://attack.mitre.org/detectionstrategies/DET0228#AN0640) | T1104 Multi-Stage Channels | command-and-control | 20 | ttp | DC0032, DC0078 |
| 68 | [AN0033](https://attack.mitre.org/detectionstrategies/DET0011#AN0033) | T1001.001 Junk Data | command-and-control | 19 | ttp | DC0082, DC0085 |
| 69 | [AN0930](https://attack.mitre.org/detectionstrategies/DET0326#AN0930) | T1132.002 Non-Standard Encoding | command-and-control | 19 | anomaly | DC0032, DC0038, DC0078, DC0085 |
| 70 | [AN1558](https://attack.mitre.org/detectionstrategies/DET0563#AN1558) | T1690 Prevent Command History Logging | defense-impairment | 19 | ttp | DC0064 |
| 71 | [AN0116](https://attack.mitre.org/detectionstrategies/DET0040#AN0116) | T1070.009 Clear Persistence | stealth | 18 | ttp | DC0040, DC0064 |
| 72 | [AN0269](https://attack.mitre.org/detectionstrategies/DET0096#AN0269) | T1098 Account Manipulation | persistence, privilege-escalation | 17 | ttp | DC0066 |
| 73 | [AN1617](https://attack.mitre.org/detectionstrategies/DET0587#AN1617) | T1087 Account Discovery | discovery | 17 | hunting | DC0064 |
| 74 | [AN0044](https://attack.mitre.org/detectionstrategies/DET0014#AN0044) | T1074 Data Staged | collection | 16 | ttp | DC0055, DC0064 |
| 75 | [AN0654](https://attack.mitre.org/detectionstrategies/DET0235#AN0654) | T1001.002 Steganography | command-and-control | 15 | ttp | DC0059, DC0082, DC0085 |
| … | 32 more | | | | | |

## Containers

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|
| 1 | [AN0986](https://attack.mitre.org/detectionstrategies/DET0347#AN0986) | T1036.005 Match Legitimate Resource Name or Location | stealth | 307 | ttp | DC0028, DC0034 |
| 2 | [AN1373](https://attack.mitre.org/detectionstrategies/DET0497#AN1373) | T1685 Disable or Modify Tools | defense-impairment | 173 | ttp | DC0041 |
| 3 | [AN0222](https://attack.mitre.org/detectionstrategies/DET0080#AN0222) | T1190 Exploit Public-Facing Application | initial-access | 146 | ttp | DC0032, DC0038, DC0085 |
| 4 | [AN1547](https://attack.mitre.org/detectionstrategies/DET0560#AN1547) | T1078 Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 129 | ttp | DC0002 |
| 5 | [AN1060](https://attack.mitre.org/detectionstrategies/DET0376#AN1060) | T1046 Network Service Discovery | discovery | 118 | hunting | DC0032, DC0078, DC0082 |
| 6 | [AN0358](https://attack.mitre.org/detectionstrategies/DET0127#AN0358) | T1036 Masquerading | stealth | 89 | ttp | DC0028, DC0032, DC0061 |
| 7 | [AN1007](https://attack.mitre.org/detectionstrategies/DET0354#AN1007) | T1133 External Remote Services | persistence, initial-access | 81 | ttp | DC0038, DC0082, DC0088 |
| 8 | [AN1422](https://attack.mitre.org/detectionstrategies/DET0514#AN1422) | T1068 Exploitation for Privilege Escalation | privilege-escalation | 69 | ttp | DC0067, DC0091 |
| 9 | [AN0859](https://attack.mitre.org/detectionstrategies/DET0307#AN0859) | T1552.001 Credentials In Files | credential-access | 63 | ttp | DC0055, DC0064, DC0082 |
| 10 | [AN0416](https://attack.mitre.org/detectionstrategies/DET0146#AN0416) | T1485 Data Destruction | impact | 50 | ttp | DC0040, DC0064 |
| 11 | [AN1239](https://attack.mitre.org/detectionstrategies/DET0447#AN1239) | T1136.001 Local Account | persistence | 49 | ttp | DC0064 |
| 12 | [AN0523](https://attack.mitre.org/detectionstrategies/DET0184#AN0523) | T1070 Indicator Removal | stealth | 39 | ttp | DC0040, DC0059 |
| 13 | [AN1341](https://attack.mitre.org/detectionstrategies/DET0487#AN1341) | T1110.003 Password Spraying | credential-access | 34 | anomaly | DC0002 |
| 14 | [AN1423](https://attack.mitre.org/detectionstrategies/DET0515#AN1423) | T1528 Steal Application Access Token | credential-access | 19 | ttp | DC0055 |
| 15 | [AN1492](https://attack.mitre.org/detectionstrategies/DET0540#AN1492) | T1496.001 Compute Hijacking | impact | 19 | ttp | DC0032, DC0072, DC0078 |
| 16 | [AN1080](https://attack.mitre.org/detectionstrategies/DET0383#AN1080) | T1036.010 Masquerade Account Name | stealth | 12 | ttp | DC0014 |
| 17 | [AN1158](https://attack.mitre.org/detectionstrategies/DET0412#AN1158) | T1552 Unsecured Credentials | credential-access | 12 | ttp | DC0032, DC0055 |
| 18 | [AN0177](https://attack.mitre.org/detectionstrategies/DET0065#AN0177) | T1609 Container Administration Command | execution | 10 | anomaly | DC0032, DC0064 |
| 19 | [AN0693](https://attack.mitre.org/detectionstrategies/DET0249#AN0693) | T1610 Deploy Container | execution | 10 | anomaly | DC0032, DC0038, DC0077, DC0085 |
| 20 | [AN1578](https://attack.mitre.org/detectionstrategies/DET0571#AN1578) | T1543 Create or Modify System Process | persistence, privilege-escalation | 9 | ttp | DC0061, DC0072 |
| 21 | [AN1317](https://attack.mitre.org/detectionstrategies/DET0478#AN1317) | T1204 User Execution | execution | 8 | ttp | DC0072, DC0077, DC0085 |
| 22 | [AN0612](https://attack.mitre.org/detectionstrategies/DET0219#AN0612) | T1611 Escape to Host | privilege-escalation | 6 | anomaly | DC0072, DC0092 |
| 23 | [AN1352](https://attack.mitre.org/detectionstrategies/DET0490#AN1352) | T1613 Container and Resource Discovery | discovery | 6 | hunting | DC0037, DC0091 |
| 24 | [AN1268](https://attack.mitre.org/detectionstrategies/DET0460#AN1268) | T1110.004 Credential Stuffing | credential-access | 5 | ttp | DC0002 |
| 25 | [AN0588](https://attack.mitre.org/detectionstrategies/DET0208#AN0588) | T1499 Endpoint Denial of Service | impact | 4 | anomaly | DC0018, DC0038 |
| 26 | [AN0261](https://attack.mitre.org/detectionstrategies/DET0094#AN0261) | T1053 Scheduled Task/Job | execution, persistence, privilege-escalation | 3 | anomaly | DC0032, DC0061 |
| 27 | [AN0571](https://attack.mitre.org/detectionstrategies/DET0198#AN0571) | T1552.007 Container API | credential-access | 3 | anomaly | DC0002, DC0032, DC0038, DC0064 |
| 28 | [AN1304](https://attack.mitre.org/detectionstrategies/DET0473#AN1304) | T1543.005 Container Service | persistence, privilege-escalation | 2 | ttp | DC0019, DC0032, DC0060, DC0072 |
| 29 | [AN0083](https://attack.mitre.org/detectionstrategies/DET0028#AN0083) | T1496.002 Bandwidth Hijacking | impact | 0 | anomaly | DC0032, DC0085 |
| 30 | [AN0582](https://attack.mitre.org/detectionstrategies/DET0206#AN0582) | T1053.007 Container Orchestration Job | execution, persistence, privilege-escalation | 0 | ttp | DC0001, DC0072, DC0085 |
| 31 | [AN0745](https://attack.mitre.org/detectionstrategies/DET0267#AN0745) | T1496 Resource Hijacking | impact | 0 | ttp | DC0018, DC0032, DC0078 |
| 32 | [AN0889](https://attack.mitre.org/detectionstrategies/DET0317#AN0889) |   |  | 0 | ttp | DC0033, DC0041 |
| 33 | [AN0946](https://attack.mitre.org/detectionstrategies/DET0334#AN0946) | T1525 Implant Internal Image | persistence | 0 | ttp | DC0015, DC0036 |
| 34 | [AN1261](https://attack.mitre.org/detectionstrategies/DET0459#AN1261) | T1612 Build Image on Host | stealth | 0 | anomaly | DC0015, DC0082 |
| 35 | [AN1579](https://attack.mitre.org/detectionstrategies/DET0572#AN1579) | T1098.006 Additional Container Cluster Roles | persistence, privilege-escalation | 0 | ttp | DC0010 |

## IaaS

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|

## Identity Provider

| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |
|---|---|---|---|---|---|---|
| 1 | [AN0301](https://attack.mitre.org/detectionstrategies/DET0107#AN0301) | T1566.002 Spearphishing Link | initial-access | 146 | ttp | DC0038 |
| 2 | [AN1277](https://attack.mitre.org/detectionstrategies/DET0463#AN1277) | T1110 Brute Force | credential-access | 45 | ttp | DC0002 |
| 3 | [AN1339](https://attack.mitre.org/detectionstrategies/DET0487#AN1339) | T1110.003 Password Spraying | credential-access | 34 | ttp | DC0002 |
| 4 | [AN0192](https://attack.mitre.org/detectionstrategies/DET0070#AN0192) | T1566 Phishing | initial-access | 19 | anomaly | DC0067 |
| 5 | [AN1425](https://attack.mitre.org/detectionstrategies/DET0515#AN1425) | T1528 Steal Application Access Token | credential-access | 19 | anomaly | DC0038 |
| 6 | [AN1524](https://attack.mitre.org/detectionstrategies/DET0551#AN1524) | T1110.001 Password Guessing | credential-access | 17 | ttp | DC0002 |
| 7 | [AN0295](https://attack.mitre.org/detectionstrategies/DET0105#AN0295) | T1110.002 Password Cracking | credential-access | 15 | ttp | DC0002 |
| 8 | [AN0459](https://attack.mitre.org/detectionstrategies/DET0161#AN0459) | T1201 Password Policy Discovery | discovery | 12 | hunting | DC0013 |
| 9 | [AN1087](https://attack.mitre.org/detectionstrategies/DET0386#AN1087) | T1087.004 Cloud Account | discovery | 10 | hunting | DC0002, DC0013, DC0064 |
| 10 | [AN1128](https://attack.mitre.org/detectionstrategies/DET0402#AN1128) | T1526 Cloud Service Discovery | discovery | 9 | hunting | DC0067, DC0083 |
| 11 | [AN1607](https://attack.mitre.org/detectionstrategies/DET0583#AN1607) | T1136 Create Account | persistence | 9 | ttp | DC0014 |
| 12 | [AN0449](https://attack.mitre.org/detectionstrategies/DET0160#AN0449) | T1621 Multi-Factor Authentication Request Generation | credential-access | 8 | anomaly | DC0002, DC0038 |
| 13 | [AN0103](https://attack.mitre.org/detectionstrategies/DET0036#AN0103) | T1098.005 Device Registration | persistence, privilege-escalation | 7 | ttp | DC0010, DC0038, DC0087 |
| 14 | [AN1469](https://attack.mitre.org/detectionstrategies/DET0531#AN1469) | T1098.001 Additional Cloud Credentials | persistence, privilege-escalation | 7 | ttp | DC0010 |
| 15 | [AN0899](https://attack.mitre.org/detectionstrategies/DET0319#AN0899) | T1136.003 Cloud Account | persistence | 5 | ttp | DC0002, DC0010, DC0014 |
| 16 | [AN1265](https://attack.mitre.org/detectionstrategies/DET0460#AN1265) | T1110.004 Credential Stuffing | credential-access | 5 | ttp | DC0002 |
| 17 | [AN0418](https://attack.mitre.org/detectionstrategies/DET0148#AN0418) | T1606.002 SAML Tokens | credential-access | 3 | anomaly | DC0002, DC0088 |
| 18 | [AN0802](https://attack.mitre.org/detectionstrategies/DET0289#AN0802) | T1685.002 Disable or Modify Cloud Log | defense-impairment | 3 | ttp | DC0069 |
| 19 | [AN0978](https://attack.mitre.org/detectionstrategies/DET0345#AN0978) | T1548 Abuse Elevation Control Mechanism | privilege-escalation | 3 | ttp | DC0010 |
| 20 | [AN0718](https://attack.mitre.org/detectionstrategies/DET0260#AN0718) | T1606 Forge Web Credentials | credential-access | 0 | anomaly | DC0006, DC0007 |
| 21 | [AN0892](https://attack.mitre.org/detectionstrategies/DET0317#AN0892) |   |  | 0 | ttp | DC0010 |
