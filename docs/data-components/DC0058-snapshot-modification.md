# DC0058 Snapshot Modification

[ATT&CK](https://attack.mitre.org/datacomponents/DC0058) · version 2.0 · modified 2025-10-21 · ATT&CK release 20.1

**Out of scope** for the current platform set

> Changes made to a cloud snapshot's metadata, attributes, or control settings. These modifications may involve adjusting access permissions, changing retention policies, or altering encryption settings.   *Data Collection Measures:*  - AWS CloudTrail     - Tracks API calls such as `ModifySnapshotAttribute`, `ResetSnapshotAttribute`, and `ModifySnapshotTier`. - Azure Monitor Logs     - Logs changes via `Microsoft.Compute/snapshots/write`. - Google Cloud Logging     - Captures modifications through `compute.snapshots.setIamPolicy` and `compute.snapshots.patch`.

## Why this component matters

ATT&CK v20.1 has **2 analytics** across **2 detection strategies** that read this component, covering **2 techniques**. Tactics most dependent on it: exfiltration (1), defense-impairment (1).

Analytic references by platform: IaaS 2

## Where it comes from

```mermaid
flowchart LR
  DC["DC0058 Snapshot Modification"]
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

Top techniques detected through this component (of 2):

| Technique | Name | Tactics | Analytics using this DC |
|---|---|---|---|
| [T1537](https://attack.mitre.org/techniques/T1537) | Transfer Data to Cloud Account | exfiltration | 1 |
| [T1578](https://attack.mitre.org/techniques/T1578) | Modify Cloud Compute Infrastructure | defense-impairment | 1 |

Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `DC0058`.
