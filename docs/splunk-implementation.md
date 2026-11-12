# Implementing this in Splunk well

Opinions, with reasons. They shape how the phase-2 and phase-3 content will be rendered.

## 1. Data components are eventtypes; tuning lives in macros and lookups

Eventtypes describe *what an event is*. They cannot carry environment specifics (macros, lookups, subsearches are not allowed inside them), and they should not: the moment an eventtype says `NOT dest=scanner01` it stops being a portable definition of the data component. So:

* `eventtypes.conf` holds only literal `index`, `sourcetype` and event-level filters (EventCode, auditd type/syscall, k8s verb, Zeek log). Change indexes in `config/stack.yml` and rebuild, or override in `local/eventtypes.conf`.
* `macros.conf` is the tuning surface. Every component gets `mitre_dcXXXX` (umbrella), `mitre_dcXXXX_<feed>` and `mitre_dcXXXX_filter` (site exclusions, default `search *`). Environment macros (`mitre_time_window(1)`, `mitre_is_internal(1)`, `mitre_hosts_with_role(1)`, `mitre_not_allowlisted_process`...) correspond to the most common ATT&CK mutable elements.
* Tuning lookups ship with headers and seed rows (`mitre_allowlist_processes`, `mitre_allowlist_users`, `mitre_allowlist_hosts`, `mitre_allowlist_domains`, `mitre_allowlist_ips`, `mitre_asset_roles`, `mitre_account_roles`, `mitre_lolbins`, `mitre_sensitive_paths`, `mitre_internal_networks`). A rebuild never overwrites them. Rows carry `dc_id`/`an_id`/`reason`/`expires` so an exclusion is traceable to the analytic that needed it.

Analytics bind each ATT&CK mutable element to one of these, or to a macro of their own (`mitre_an0061_threshold`, `mitre_an1030_access_mask`), or leave it to their `mitre_anXXXX_filter` macro; the analytic's page lists every element and where it landed. `mitremap validate` rejects an analytic whose declared binding is never used by the search.

## 2b. Detection strategies: sequences, risk rules, delegation

Because a strategy's analytics are platform variants, "correlating the analytics of a strategy" is rarely what you want. Each strategy takes one of three shapes:

* **Delegated** (default, 52 strategies): the analytics' own findings and risk events are the strategy's output. Nothing extra runs.
* **Sequence** (6): a hand-written search over raw events that implements the chain the single-leg analytic left in its `gaps` field, joined on a real key: Sysmon process GUID for LSASS access then dump write, host and file path for document write then execution, host and task command for task creation then Task Scheduler launch. Sequences write a finding and risk, like a TTP analytic.
* **Risk rule** (4 strategy-scoped, 3 cross-strategy): generated from parameters (scope, `group_by` risk or threat object, window, condition) over the Risk data model. They write a finding only, never risk, so no rule reads its own output. Strategy-scoped rules look for spread (one source address on three hosts); cross-strategy rules look for breadth (three strategies or tactics on one object) or a named precursor set (ransomware).

Risk rules recover the analytic or strategy id from the rule name in `source` and enrich it from the TA's ATT&CK lookups. That avoids depending on how custom annotation frameworks are flattened into risk-event fields, which differs between ES versions.

**Asset and identity correlation is a prerequisite for the risk layer.** Endpoint analytics raise risk on host names, network analytics on IP addresses. Unless ES Asset and Identity management maps a host's IPs to its name, a host's endpoint and network risk land on two different risk objects and cross-feed rules (DET0400, RISK0001) undercount. Populate the asset lookup with `ip`, `nt_host` and `dns` before enabling them.

A starter is shipped: the supporting search **ASSET0001** (disabled, daily) writes `mitre_asset_ip_map` (`nt_host`, `dns`, `ip`, `mac`) from the source address of outbound Sysmon connections and Corelight DHCP leases, keeping 30 days. To use it:

1. Enable `MITRE - ASSET0001 - Host to IP map from Sysmon connections and Corelight DHCP` and let it run once.
2. In ES, Configure → Data Enrichment → Asset and Identity Management → Asset Lookup Configuration, add `mitre_asset_ip_map` as a new asset source. Field names already match the ES asset schema; add `priority`, `bunit` and `category` from your CMDB when you have them.
3. Check that a host's risk merges: `| from datamodel:Risk.All_Risk | search risk_object=<host> | stats values(risk_object_type) values(source)` should show both endpoint and network sources once the merge has run.

The map is a starting point, not a CMDB: hosts with several interfaces get one row per address, and DHCP churn means old addresses linger for up to 30 days.

Two conventions keep the searches portable:

* **Per-log sourcetype macros.** Feeds that ship several logs get `mitre_st_<feed>_<log>` (`mitre_st_corelight_http`, `mitre_st_palo_alto_config`), generated from `stack.yml`, so an analytic writes `` `mitre_dc0085_corelight` `mitre_st_corelight_http` `` and never a sourcetype name.
* **Normalisers.** `mitre_normalize_host`, `mitre_normalize_zeek`, `mitre_normalize_zeek_http` and `mitre_normalize_pan` coalesce the field names different TAs use. If a detection returns nothing on data you know is there, these four macros are the first place to look.

## 2. Pick the content type per detection; RBA is one option

ATT&CK analytics vary from "process X spawned by Y" (a specific behaviour) to "unusual volume of Z within a window" (an anomaly that means little alone). ES 8 has the content types for this; use them deliberately:

| Content type | What it is | ES action | When |
|---|---|---|---|
| **TTP** | High-fidelity behaviour; an alert a human should see | `action.notable` (+ optional `action.risk`) | The analytic describes a specific, rarely-benign sequence |
| **Anomaly** | Interesting but noisy; only meaningful aggregated | `action.risk` only, no notable | Analytics with thresholds, `TimeWindow`, rarity ("unusual", "first time", "spike") |
| **Hunting** | Pivot material for an analyst | scheduled search, no adaptive response; dashboard panel | Enumeration analytics, context collection, anything with "monitor for" and no decision boundary |
| **Baseline** | Produces reference data others consume | `outputlookup` on a daily schedule | Attached to an analytic whose mutable element is a learned set (first-seen pairs, known parents, normal volumes); not a content type of its own |

A content type is suggested from the analytic text (discovery-only tactics → Hunting; threshold, window and rarity language → Anomaly; otherwise TTP) and shown in the backlog, but the author decides. In the implemented set the split is 20 TTP, 36 Anomaly, 9 Hunting, with one baseline (first-seen RDP pairs for AN0931). Detection strategies (phase 3) then pick their own shape: a **risk incident rule** when the DET's analytics are anomalies (count distinct `mitre_an` per risk object within the DET over a window), a plain **correlation search / notable** when one TTP analytic is sufficient on its own.

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

Two generated health detections close this gap ([telemetry health](health.md)): HEALTH0001 lists every index and sourcetype or source a live eventtype depends on that has not arrived in 7 days or has gone silent, and HEALTH0002 flags hosts that stopped sending Sysmon or Security events and raises Host Status risk on them.

## 6. Packaging and versioning

* Two apps: the TA (knowledge objects, no inputs, no props) and `DA-ESS-mitre-attack-detections` (`savedsearches.conf`, per-analytic macros, baseline lookups) that ES picks up as detections. Keep them separate so the TA can live on any search head.
* The detection stanzas follow the shape Splunk's contentctl emits for ES 8 (`action.correlationsearch.detection_type = ebd`, annotations JSON, `action.risk.param._risk`). They have not been loaded into an ES instance from this repo; validate one in a test search head before a bulk import.
* `attack_version` is in `app.conf`, in every lookup row and in the `mitre_attack_version` macro. ES 8 detection versioning will track content changes; the ATT&CK version is tracked here.
* Splunk's `contentctl` is an alternative authoring format for the detections app (it already knows RBA fields, `data_source`, `mitre_attack_id`, tests). It is Splunk-only, so it is a possible *export* from the neutral YAML here, not the source of truth.

## 7. Known trade-offs

* Eventtypes evaluate at search time on the search head; hundreds of eventtypes with `eventtype=` nesting add a little parsing cost to every search that references them. Negligible next to the raw search, but do not use `eventtype=*mitre*` wildcards in analytics.
* `index=` is literal in eventtypes. If you split Sysmon across indexes, list them in `stack.yml` as `index: sysmon OR index=sysmon_dmz` is not supported; use one index per feed or override stanzas locally.
* Sigma field names differ from Splunk's. The shipped pipeline only scopes by eventtype, index and sourcetype (source for the Windows event log feeds); chain it after `sysmon` for Sysmon rules. Do not chain `splunk_windows`: it adds a classic `source="WinEventLog:<channel>"` that contradicts XML collection.
