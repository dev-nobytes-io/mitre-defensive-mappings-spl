# DA-ESS-mitre-attack-detections

ATT&CK v20.1 analytics implemented as Splunk Enterprise Security 8 detections.
Requires `TA-mitre-attack-datacomponents` (eventtypes, macros, lookups) and Splunk_SA_CIM (ships with ES).

| Content type | Count | Adaptive response |
|---|---|---|
| TTP | 12 | finding (notable) + risk |
| Anomaly | 6 | risk only (intermediate finding) |
| Hunting | 0 | none; run on demand or schedule for a dashboard |
| Baselines | 0 | write a lookup that an analytic reads |

## Enabling

1. Every detection ships `disabled = true`. Enable from ES > Content Management, or set `disabled = false` in `local/savedsearches.conf`.
2. Before enabling one, run its search over 7 days, then add exclusions to its `mitre_anXXXX_filter` macro or the shared allowlist lookups. Do not edit the search.
3. Analytics that read a baseline lookup need the baseline enabled first and one full run.
4. Detections on data models use `mitre_summariesonly`; set it to `summariesonly=true` once the models are accelerated.

## Annotations

`action.correlationsearch.annotations` carries `mitre_attack` (technique), `mitre_det`, `mitre_an`, `mitre_dc` and `attack_version`, so risk events and findings can be grouped by any layer of the ATT&CK detection model.
