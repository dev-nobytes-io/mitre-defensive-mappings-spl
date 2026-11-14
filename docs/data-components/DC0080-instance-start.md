# DC0080 Instance Start

[ATT&CK](https://attack.mitre.org/datacomponents/DC0080) · version 2.0 · modified 2025-11-12 · ATT&CK release 20.1

**Out of scope** for the current platform set

> The initiation or activation of a virtual machine instance within a cloud infrastructure. This action typically involves starting an existing instance that had been stopped or paused, allowing it to resume operation. Examples:   - Google Cloud Platform (GCP): Starting an instance through `instance.start` API activity. - AWS: Logging of `StartInstances` in AWS CloudTrail for EC2 instances. - Azure: `Microsoft.Compute/virtualMachines/start` entries indicate a VM instance being started.

## Why this component matters

ATT&CK v20.1 has **11 analytics** across **11 detection strategies** that read this component, covering **11 techniques**. Tactics most dependent on it: impact (4), defense-impairment (3), execution (2), stealth (1).

Analytic references by platform: IaaS 10, Windows 1

## Where it comes from

```mermaid
flowchart LR
  DC["DC0080 Instance Start"]
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

Top techniques detected through this component (of 11):

| Technique | Name | Tactics | Analytics using this DC |
|---|---|---|---|
| [T1204](https://attack.mitre.org/techniques/T1204) | User Execution | execution | 1 |
| [T1204.003](https://attack.mitre.org/techniques/T1204/003) | Malicious Image | execution | 1 |
| [T1496](https://attack.mitre.org/techniques/T1496) | Resource Hijacking | impact | 1 |
| [T1496.001](https://attack.mitre.org/techniques/T1496/001) | Compute Hijacking | impact | 1 |
| [T1496.002](https://attack.mitre.org/techniques/T1496/002) | Bandwidth Hijacking | impact | 1 |
| [T1499](https://attack.mitre.org/techniques/T1499) | Endpoint Denial of Service | impact | 1 |
| [T1525](https://attack.mitre.org/techniques/T1525) | Implant Internal Image | persistence | 1 |
| [T1535](https://attack.mitre.org/techniques/T1535) | Unused/Unsupported Cloud Regions | stealth | 1 |
| [T1578](https://attack.mitre.org/techniques/T1578) | Modify Cloud Compute Infrastructure | defense-impairment | 1 |
| [T1578.002](https://attack.mitre.org/techniques/T1578/002) | Create Cloud Instance | defense-impairment | 1 |
| [T1578.004](https://attack.mitre.org/techniques/T1578/004) | Revert Cloud Instance | defense-impairment | 1 |

Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `DC0080`.
