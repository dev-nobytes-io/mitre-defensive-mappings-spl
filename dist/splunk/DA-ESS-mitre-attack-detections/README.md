# DA-ESS-mitre-attack-detections

ATT&CK v20.1 analytics implemented as Splunk Enterprise Security 8 detections.
Requires `TA-mitre-attack-datacomponents` (eventtypes, macros, lookups) and Splunk_SA_CIM (ships with ES).

| Content type | Count | Adaptive response |
|---|---|---|
| TTP | 33 | finding (notable) + risk |
| Anomaly | 73 | risk only (intermediate finding) |
| Hunting | 13 | none; run on demand or schedule for a dashboard |
| Baselines | 1 | write a lookup that an analytic reads |
| Strategy sequences | 8 | finding + risk; raw-event chains joined on a key |
| Strategy risk rules | 4 | finding only; over the Risk data model, scoped to one strategy |
| Cross-strategy risk correlations | 3 | finding only; over the Risk data model |

## Enabling

1. Every detection ships `disabled = true`. Enable from ES > Content Management, or set `disabled = false` in `local/savedsearches.conf`.
2. Before enabling one, run its search over 7 days, then add exclusions to its `mitre_anXXXX_filter` macro or the shared allowlist lookups. Do not edit the search.
3. Analytics that read a baseline lookup need the baseline enabled first and one full run.
4. Detections on data models use `mitre_summariesonly`; set it to `summariesonly=true` once the models are accelerated.

## Risk-based rules depend on asset and identity correlation

Endpoint analytics raise risk on host names (`dest` from Sysmon `Computer`), network analytics on IP addresses (`src` from Corelight and Palo Alto). The risk rules group by `risk_object`, so a host and its IP only meet if ES Asset and Identity management maps them (an asset lookup carrying both `ip` and `nt_host`/`dns`). Without that, cross-feed correlation silently fragments.

## Annotations

`action.correlationsearch.annotations` carries `mitre_attack` (technique), `mitre_det`, `mitre_an`, `mitre_dc` and `attack_version`, so risk events and findings can be grouped by any layer of the ATT&CK detection model.
