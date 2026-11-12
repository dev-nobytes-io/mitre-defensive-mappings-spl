# DET0327 One source opening first-seen RDP sessions to several hosts

[ATT&CK detection strategy](https://attack.mitre.org/detectionstrategies/DET0327) · Multi-event Detection Strategy for RDP-Based Remote Logins and Post-Access Activity · [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) · tactics: lateral-movement

**Shape:** risk rule: over the Risk data model → finding only · **Severity:** high · **Status:** implemented

The same source address is the threat object on AN0931 risk events (an RDP logon for a user, source and destination combination not seen in 30 days) for three or more distinct hosts within an hour.

```mermaid
flowchart LR
  AN0931["AN0931"] -- risk --> R
  R[("Risk data model<br/>by threat_object<br/>window 1h")] --> COND{{"distinct_risk_objects >= 3"}}
  COND --> F["finding"]
```

## Analytics in this strategy

| Analytic | Platforms | Status | Type |
|---|---|---|---|
| [AN0931](../analytics/AN0931-first-seen-rdp-logon-for-a-user-source-and-destination.md) | Windows | implemented | anomaly |

**Not covered:** Post-logon activity on each host is left to the cross-strategy correlations.

## Tuning

| Macro | Default | Purpose |
|---|---|---|
| `mitre_det0327_filter` | `search *` | Exclusions for DET0327 One source opening first-seen RDP sessions to several hosts. |
| `mitre_det0327_condition` | `distinct_risk_objects >= 3` | Firing condition for DET0327. Fields: risk_score, risk_events, distinct_analytics, distinct_strategies, distinct_tactics, distinct_techniques, distinct_risk_objects. |

## Splunk

Stanza `[MITRE - DET0327 - One source opening first-seen RDP sessions to several hosts - Rule]` in `DA-ESS-mitre-attack-detections`. Schedule `9-59/15 * * * *`, window `-1h` to `now`. Ships disabled.

Generated from the parameters below; edit the YAML, not the search. Scope: `source IN ("MITRE - AN0931 - *") All_Risk.risk_object_type IN ("system") All_Risk.threat_object_type IN ("ip_address")`.

| Parameter | Value |
|---|---|
| group_by | threat_object |
| window | 1h |
| condition | `distinct_risk_objects >= 3` |

```spl
| tstats `mitre_summariesonly` min(_time) as firstTime max(_time) as lastTime sum(All_Risk.calculated_risk_score) as risk_score count as risk_events
    from datamodel=Risk.All_Risk where source IN ("MITRE - AN0931 - *") All_Risk.risk_object_type IN ("system") All_Risk.threat_object_type IN ("ip_address")
    by All_Risk.threat_object All_Risk.threat_object_type All_Risk.risk_object All_Risk.risk_object_type source
| `drop_dm_object_name(All_Risk)`
| rex field=source "^MITRE - (?<mitre_id>(AN|DET)\d{4}) - "
| lookup mitre_attack_analytics an_id AS mitre_id OUTPUT det_id AS an_det_id tactics AS an_tactics technique_id AS an_technique_id
| lookup mitre_attack_detection_strategies det_id AS mitre_id OUTPUT tactics AS det_tactics technique_id AS det_technique_id
| eval det_id=coalesce(an_det_id, if(match(mitre_id, "^DET"), mitre_id, null())), tactic=split(coalesce(an_tactics, det_tactics), "|"), technique_id=coalesce(an_technique_id, det_technique_id)
| stats min(firstTime) as firstTime max(lastTime) as lastTime sum(risk_score) as risk_score sum(risk_events) as risk_events dc(mitre_id) as distinct_analytics dc(det_id) as distinct_strategies dc(tactic) as distinct_tactics dc(technique_id) as distinct_techniques dc(risk_object) as distinct_risk_objects values(risk_object) as risk_object values(mitre_id) as mitre_ids values(technique_id) as technique_ids values(tactic) as tactics values(source) as source by threat_object threat_object_type
| where `mitre_det0327_condition`
| `mitre_ctime(firstTime)` | `mitre_ctime(lastTime)`
| `mitre_det0327_filter`
```

## Sigma

Not expressed in Sigma: Operates on Enterprise Security risk events and on the AN0931 first-seen baseline, neither of which Sigma models.

## Known false positives

- New jump hosts and administrators onboarding to a set of servers.
