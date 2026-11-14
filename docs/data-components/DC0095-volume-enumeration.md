# DC0095 Volume Enumeration

[ATT&CK](https://attack.mitre.org/datacomponents/DC0095) · version 2.0 · modified 2025-10-21 · ATT&CK release 20.1

**Out of scope** for the current platform set

> An extracted list of available volumes within a cloud environment (ex: AWS describe-volumes)

## Why this component matters

ATT&CK v20.1 has **0 analytics** across **0 detection strategies** that read this component, covering **0 techniques**. Tactics most dependent on it: none.

## Where it comes from

```mermaid
flowchart LR
  DC["DC0095 Volume Enumeration"]
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

Top techniques detected through this component (of 0):

| Technique | Name | Tactics | Analytics using this DC |
|---|---|---|---|

Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `DC0095`.
