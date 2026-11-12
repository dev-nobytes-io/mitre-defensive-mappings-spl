# DC0096 Passive DNS

[ATT&CK](https://attack.mitre.org/datacomponents/DC0096) · version 2.0 · modified 2025-10-21 · ATT&CK release 20.1

Status: **Out of scope** for the current platform set

> "Domain Name: Passive DNS" captures logged historical and real-time domain name system (DNS) data. This includes records of domain-to-IP address resolutions over time, enabling analysts to track the evolution of domain infrastructure, uncover historical patterns of use, and detect malicious activities tied to domains and their associated IP addresses. Examples:   - Historical Resolutions - Shared IP Usage - Temporal Patterns - Malicious Domain Clustering - Historical Lookback  This data component can be collected through the following measures:  - Passive DNS Platforms: Use platforms that specialize in passive DNS collection and analysis:    - Tools: Farsight DNSDB, RiskIQ PassiveTotal, PassiveDNS. - Threat Intelligence Feeds: Integrate passive DNS data from commercial or open-source threat intelligence providers. - Custom DNS Collectors: Deploy custom tools to capture DNS traffic at the network level for analysis. - Cloud DNS Services: Leverage cloud DNS services (e.g., AWS Route 53, Azure DNS) that maintain DNS query logs.

## Why this component matters

ATT&CK v20.1 has **5 analytics** across **5 detection strategies** that read this component, covering **5 techniques**. Tactics most dependent on it: resource-development (5).

Analytic references by platform: PRE 5

## Where it comes from

```mermaid
flowchart LR
  DC["DC0096 Passive DNS"]
  classDef live fill:#d4edda,stroke:#2e7d32,color:#1b1b1b
  classDef ready fill:#fff3cd,stroke:#b26a00,color:#1b1b1b
```

## Requirements

Per feed (from `config/stack.yml` and `config/log_sources.yml`):

| Feed | Status | Sourcetype or source | Constraint | Origin | TA / collector |
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

Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `DC0096`.
