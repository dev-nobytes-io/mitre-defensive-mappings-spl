# Implementing this in Splunk well

Opinions, with reasons. They shape how the phase-2 and phase-3 content will be rendered.

## 1. Data components are eventtypes; tuning lives in macros and lookups

Eventtypes describe *what an event is*. They cannot carry environment specifics (macros, lookups, subsearches are not allowed inside them), and they should not: the moment an eventtype says `NOT dest=scanner01` it stops being a portable definition of the data component. So:

* `eventtypes.conf` holds only literal `index`, `sourcetype` and event-level filters (EventCode, auditd type/syscall, k8s verb, Zeek log). Change indexes in `config/stack.yml` and rebuild, or override in `local/eventtypes.conf`.
* `macros.conf` is the tuning surface. Every component gets `mitre_dcXXXX` (umbrella), `mitre_dcXXXX_<feed>` and `mitre_dcXXXX_filter` (site exclusions, default `search *`). Environment macros (`mitre_time_window(1)`, `mitre_is_internal(1)`, `mitre_hosts_with_role(1)`, `mitre_not_allowlisted_process`...) correspond to the most common ATT&CK mutable elements.
* Tuning lookups ship with headers and seed rows (`mitre_allowlist_processes`, `mitre_allowlist_users`, `mitre_allowlist_hosts`, `mitre_allowlist_domains`, `mitre_allowlist_ips`, `mitre_asset_roles`, `mitre_account_roles`, `mitre_lolbins`, `mitre_sensitive_paths`, `mitre_internal_networks`). A rebuild never overwrites them. Rows carry `dc_id`/`an_id`/`reason`/`expires` so an exclusion is traceable to the analytic that needed it.

Phase-2 analytics will bind each ATT&CK mutable element to one of these: `TimeWindow` → `mitre_time_window(1)`, `ProcessWhitelist` → `mitre_allowlist_processes`, `UserContext` → `mitre_account_roles`, and so on. No literal thresholds in SPL.

## 2. Pick the content type per detection; RBA is one option

ATT&CK analytics vary from "process X spawned by Y" (a specific behaviour) to "unusual volume of Z within a window" (an anomaly that means little alone). ES 8 has the content types for this; use them deliberately:

| Content type | What it is | ES action | When |
|---|---|---|---|
| **TTP** | High-fidelity behaviour; an alert a human should see | `action.notable` (+ optional `action.risk`) | The analytic describes a specific, rarely-benign sequence |
| **Anomaly** | Interesting but noisy; only meaningful aggregated | `action.risk` only, no notable | Analytics with thresholds, `TimeWindow`, rarity ("unusual", "first time", "spike") |
| **Hunting** | Pivot material for an analyst | scheduled search, no adaptive response; dashboard panel | Enumeration analytics, context collection, anything with "monitor for" and no decision boundary |
| **Baseline** | Produces reference data others consume | summary index or `outputlookup` | Analytics whose mutable element is a learned set (known parents, normal hours, normal volumes) |

Default content type will be inferred from the analytic text (specific image/parent/command → TTP; TimeWindow/threshold language → Anomaly; "enumerate"/"inventory" → Hunting) and is overridable per analytic. Detection strategies (phase 3) then pick their own shape: a **risk incident rule** when the DET's analytics are anomalies (count distinct `mitre_an` per risk object within the DET over a window), a plain **correlation search / notable** when one TTP analytic is sufficient on its own.

Custom annotation frameworks make this work: every detection will carry `action.correlationsearch.annotations = {"mitre_attack": ["T1059.001"], "mitre_det": ["DET0039"], "mitre_an": ["AN0110"], "mitre_dc": ["DC0032"]}`, so the Risk data model and the ES Detections page can group and filter by any layer.

## 3. Volume: tstats where it matters

860 analytics read Process Creation. If each becomes a scheduled raw search over Sysmon EID 1 the search head dies. Rules of thumb for the renderer:

* Components with a CIM model get `mitre_dcXXXX_dm` and `mitre_dcXXXX_dm_where` macros. Analytics on Process Creation, File *, Registry *, Network Connection/Traffic, Authentication and Change should be written as `| tstats ... from datamodel=Endpoint.Processes where nodename=Processes ...` using those macros, with CIM field names.
* Raw eventtype searches are for low-volume components (WMI Creation, Named Pipe Metadata, Driver Load, Service Creation) and for fields CIM does not normalise.
* Where many analytics share a component and shape, consolidate into one scheduled search that emits several risk events (`| eval analytic_id=case(...)`), rather than N near-identical searches.
* Disabled by default; enable by tier. Schedule with jittered cron and `realtime_schedule = 0`.

## 4. CIM tags, carefully

The TAs (Splunk_TA_windows, TA-microsoft-sysmon, Corelight, Palo Alto) already tag their events for CIM. Adding CIM tags to our eventtypes is harmless where the TA is CIM compliant for that model and misleading where it is not (tagging ePO events `process` would feed the Endpoint.Processes model events that lack `process_name`). So `config/cim.yml` lists `compliant_feeds` per component and tags are emitted only for those pairs. `mitre_attack`, `dcXXXX` and `mitre_feed_<feed>` tags are always emitted.

## 5. Collection prerequisites are part of coverage

An eventtype with no events is false comfort. Each component page lists what has to be true at the source: audit subcategories and the 4688 command-line GPO, PowerShell Script Block Logging, SACLs for 4663/4657, Sysmon rule groups (ProcessAccess, ImageLoad, DNS, FileDelete are off in minimal configs), Corelight log set and sensor placement, PAN-OS log forwarding profiles on every rule, ePO event forwarding, auditd rule sets and ENRICHED format, ESXi remote syslog, Kubernetes audit policy, Entra diagnostic settings. Treat the list as the acceptance test when you tick a feed.

Phase-2 analytics should include a *data check* search per component (`| tstats count where eventtype=... by sourcetype` over 24h) so missing telemetry is itself alerted on, with Host Status (DC0018) as the home for it.

## 6. Packaging and versioning

* Two apps: this TA (knowledge objects, no inputs, no props) and, in phase 2, a `DA-ESS-mitre-attack-detections` app with `savedsearches.conf` that ES Content Management imports. Keep them separate so the TA can live on any search head.
* `attack_version` is in `app.conf`, in every lookup row and in the `mitre_attack_version` macro. ES 8 detection versioning will track content changes; the ATT&CK version is tracked here.
* Splunk's `contentctl` is an alternative authoring format for the detections app (it already knows RBA fields, `data_source`, `mitre_attack_id`, tests). It is Splunk-only, so it is a possible *export* from the neutral YAML here, not the source of truth.

## 7. Known trade-offs

* Eventtypes evaluate at search time on the search head; hundreds of eventtypes with `eventtype=` nesting add a little parsing cost to every search that references them. Negligible next to the raw search, but do not use `eventtype=*mitre*` wildcards in analytics.
* `index=` is literal in eventtypes. If you split Sysmon across indexes, list them in `stack.yml` as `index: sysmon OR index=sysmon_dmz` is not supported; use one index per feed or override stanzas locally.
* Sigma field names differ from Splunk's. The shipped pipeline only scopes by eventtype/sourcetype; chain it after `sysmon` and `splunk_windows` (or a CIM pipeline) for field mapping.
