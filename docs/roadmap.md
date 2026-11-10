# Roadmap

## Phase 1 (this release): data components

Done: feed checklist, log-source normalisation, per-component eventtypes/tags/macros/lookups, Sigma logsource pipeline, per-component docs, coverage/gaps/checklist, changelog tooling, CI.

## Phase 2: analytics as ES detections

One YAML per analytic in `content/analytics/ANxxxx.yml`:

```yaml
id: AN0110
detection_strategy: DET0039
technique: T1071.004
platforms: [Linux]
attack: {description, log_source_references, mutable_elements}   # derived, regenerated
status: scaffold | implemented | reviewed
content_type: ttp | anomaly | hunting | baseline                  # inferred default, overridable
data_components: [DC0032, DC0082]                                 # derived
tuning:                                                           # one entry per ATT&CK mutable element
  TimeWindow:        {bind: macro,  name: mitre_time_window, default: 15m}
  ProcessWhitelist:  {bind: lookup, name: mitre_allowlist_processes}
  UserContext:       {bind: lookup, name: mitre_account_roles}
spl:
  search: |                                                       # uses `mitre_dcXXXX*` macros, CIM fields, tstats where the DC has a _dm macro
  risk:   {score: 25, objects: [{field: dest, type: system}, {field: user, type: user}]}   # for anomaly/ttp
  notable: {title: ..., severity: medium}                                                  # for ttp
  schedule: {cron: "*/15 * * * *", earliest: -20m@m, latest: now}
sigma:
  rule: {detection: ..., falsepositives: ...}                     # logsource derived from the DC mapping
kql: null
esql: null
```

Renderer: `savedsearches.conf` into `DA-ESS-mitre-attack-detections` with `action.correlationsearch.annotations` carrying `mitre_attack`, `mitre_det`, `mitre_an`, `mitre_dc`; action by content type (see [splunk-implementation.md](splunk-implementation.md)); disabled by default; one Sigma rule per analytic; pySigma used to validate Sigma and to draft SPL for scaffold-status analytics (hand-written SPL wins when present).

Prioritisation: rank techniques by group/software/campaign usage from the STIX `uses` relationships and implement analytics for the top techniques on Windows and network platforms first.

## Phase 3: detection strategies

`content/detection_strategies/DETxxxx.yml` with `shape: risk_incident | correlation | notable`, the analytics it combines and the window. Rendered as ES risk incident rules (count distinct `mitre_an` within `mitre_det` per risk object) or correlation searches, plus Sigma correlation rules.

## Phase 4: more languages and platforms

* KQL renderer (Sentinel / Defender advanced hunting tables already noted per log source as `kql.table`; Kibana KQL variant).
* ES|QL renderer (`elastic.dataset` per log source).
* Bring macOS, M365/Office, AWS, GCP, Okta, SaaS into scope by editing `config/platforms.yml` and `render` flags.
* ICS and Mobile ATT&CK domains (same STIX layout; `fetch --domain ics-attack`).

## Operational

* Data-check analytic per component (missing telemetry alert) under Host Status.
* A Splunk dashboard built on the `mitre_attack_*` lookups for coverage by tactic/technique/feed.
* Mermaid parse check in CI once a headless mermaid parser is wired in (Node + jsdom).
