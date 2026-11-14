# DC0103 Active DNS

[ATT&CK](https://attack.mitre.org/datacomponents/DC0103) · version 2.0 · modified 2025-10-21 · ATT&CK release 20.1

**Out of scope** for the current platform set

> "Domain Name: Active DNS" data component captures queried DNS registry data that highlights current domain-to-IP address resolutions. This data includes both direct queries to DNS servers and records that provide mappings between domain names and associated IP addresses. It serves as a critical resource for tracking active infrastructure and understanding the network footprint of an organization or adversary. Examples:   - DNS Query Example: `nslookup example.com`, `dig example.com A` - PTR Record Example: `dig -x 192.168.1.1` - Tracking Malicious Domains: DNS logs reveal repeated queries to suspicious domains like malicious-site.com. The IPs resolved by these domains may be indicators of compromise (IOCs). - DNS Record Types     - A/AAAA Record: Maps domain names to IP addresses (IPv4/IPv6).     - CNAME Record: Canonical name records, often used for redirects.     - MX Record: Mail exchange records, used to route emails.     - TXT Record: Can include security information like SPF or DKIM policies.     - SOA Record: Start of authority record for domain management.     - NS Record: Lists authoritative name servers for the domain.  This data component can be collected through the following measures:  - System Utilities: Use built-in tools like `nslookup`, `dig`, or host on Linux, macOS, and Windows to perform active DNS queries. - DNS Logging     - Windows DNS Server: Enable DNS Analytical Logging to capture DNS queries and responses.     - Bind DNS: Enable query logging in the named.conf file. - Cloud Provider DNS Logging     - AWS Route 53: Enable query logging through CloudWatch or S3:     - Google Cloud DNS: Enable logging for Cloud DNS queries through Google Cloud Logging. - Network Traffic Monitoring: Use tools like Wireshark or Zeek to analyze DNS queries within network traffic. - Security Information and Event Management (SIEM) Integration: Aggregate DNS logs in a SIEM like Splunk to create alerts and monitor patterns. - Public OSINT Tools: Use OSINT platforms like VirusTotal, or PassiveTotal to collect information on domains and their associated IP addresses.

## Why this component matters

ATT&CK v20.1 has **5 analytics** across **5 detection strategies** that read this component, covering **5 techniques**. Tactics most dependent on it: resource-development (5).

Analytic references by platform: PRE 5

## Where it comes from

```mermaid
flowchart LR
  DC["DC0103 Active DNS"]
```

## Requirements

Per feed (from `config/stack.yml` and `config/log_sources.yml`):

| Feed | Schedule | Sourcetype or source | Constraint | Origin | TA / collector |
|---|---|---|---|---|---|

## Splunk

No eventtypes rendered: none of this component's log sources belong to an in-scope platform feed. See [gaps](../gaps.md).

## Sigma

No generic Sigma category maps to this component; rules use `product`/`service` logsources, which the pipeline maps to index and sourcetype.

## Dependents

Top techniques detected through this component (of 5):

| Technique | Name | Tactics | Analytics using this DC |
|---|---|---|---|
| [T1583](https://attack.mitre.org/techniques/T1583) | Acquire Infrastructure | resource-development | 1 |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001) | Domains | resource-development | 1 |
| [T1584](https://attack.mitre.org/techniques/T1584) | Compromise Infrastructure | resource-development | 1 |
| [T1584.001](https://attack.mitre.org/techniques/T1584/001) | Domains | resource-development | 1 |
| [T1584.002](https://attack.mitre.org/techniques/T1584/002) | DNS Server | resource-development | 1 |

Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `DC0103`.
