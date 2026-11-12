# Roadmap

## Phase 1 (this release): data components

Done: feed checklist, log-source normalisation, per-component eventtypes/tags/macros/lookups, Sigma logsource pipeline, per-component docs, coverage/gaps/checklist, changelog tooling, CI.

## Phase 2 (in progress): analytics as ES detections

Done: analytic schema and scaffolding (`new-analytic`), validation, ES 8 detections app, Sigma rule rendering with correlation support, per-analytic docs, prioritised backlog, and 49 implemented analytics (18 TTP, 27 Anomaly, 4 Hunting, 1 baseline) across Windows endpoint, Corelight and Palo Alto feeds.

The schema, as implemented (`content/analytics/ANxxxx.yml`, `curated` block):

```yaml
status: implemented            # scaffold | implemented | reviewed
title: LSASS memory access by an unexpected process
content_type: ttp              # ttp | anomaly | hunting
severity: high
summary: what this search detects
gaps: what ATT&CK's text asks for that this does not cover
data_components: [DC0035]
feeds: [sysmon]
tuning:                        # one entry per ATT&CK mutable element that is bound
  - {element: AccessMask, bind: macro, name: mitre_an1030_access_mask, default: 'GrantedAccess IN (...)'}
  - {element: ParentProcessName, bind: lookup, name: mitre_allowlist_processes}
spl: |                         # uses mitre_dcXXXX macros and ends with mitre_anXXXX_filter
risk: {message: "...", objects: [{field: dest, type: system, score: 70}], threat_objects: [...]}
schedule: {cron, earliest, latest}     # optional; default every 15 minutes with a per-analytic offset
throttle: {fields: [dest], period: 3600s}
baselines: [{name, lookup, fields, search, cron, earliest}]
sigma: {logsource, detection}  # or rules: [...] + correlation: {...}, or not_expressible: reason
```

Remaining:

* Work down [the backlog](analytics/backlog.md): about 460 more analytics are coverable by the ticked feeds.
* Promote `implemented` to `reviewed` after each detection has run against production data for a tuning period.
* Analytics for Linux, ESXi, containers and Azure once those feeds are ticked (564 are waiting on a feed).
* Optional consolidation of same-shape analytics (the discovery set) into one scheduled search per data component where search concurrency is tight.

## Phase 3 (in progress): detection strategies

Done: strategy and correlation schema (`content/detection_strategies/`, `content/correlations/`), `new-strategy` scaffolding, generated risk rules over the Risk data model, sequence validation, Sigma correlation rules for sequences, docs per strategy, and the first set: 6 sequences (DET0363 LSASS access then dump, DET0085 SYSTEM plus SAM hive save, DET0294 document write then execute, DET0394 web-root write then web shell, DET0365 Run key then execution, DET0441 task creation then Task Scheduler launch), 4 strategy risk rules (DET0530 and DET0327 spread from one source, DET0027 spread to one domain, DET0400 endpoint and network DNS agreement) and 3 cross-strategy correlations (RISK0001 breadth, RISK0002 score, RISK0003 ransomware precursors).

Remaining:

* Sequences for the other strategies whose analytics name a chain (`gaps` on each analytic page lists them).
* A data-check correlation per data component: no events from a ticked feed in 24 hours raises Host Status risk.
* Tune RISK0001/RISK0002 thresholds against a month of production risk data before enabling.

## Phase 4: more languages and platforms

* KQL renderer (Sentinel / Defender advanced hunting tables already noted per log source as `kql.table`; Kibana KQL variant).
* ES|QL renderer (`elastic.dataset` per log source).
* Bring macOS, M365/Office, AWS, GCP, Okta, SaaS into scope by editing `config/platforms.yml` and `render` flags.
* ICS and Mobile ATT&CK domains (same STIX layout; `fetch --domain ics-attack`).

## Operational

* Data-check analytic per component (missing telemetry alert) under Host Status.
* A Splunk dashboard built on the `mitre_attack_*` lookups for coverage by tactic/technique/feed.
* Mermaid parse check in CI once a headless mermaid parser is wired in (Node + jsdom).
