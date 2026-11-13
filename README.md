# MITRE ATT&CK v20 defensive mappings for Splunk and Sigma

ATT&CK v18+ models detection as a chain: **Detection Strategy → Analytic → Data Component → Log Source**. This repo pins the current Enterprise release (**v20.1**, 2026-11-05), maps every data component onto a concrete log stack, and renders the result as Splunk knowledge objects, a Sigma/pySigma pipeline, and documentation with mermaid diagrams. KQL and ES|QL renderers are stubbed for a later phase.

```mermaid
flowchart LR
  T["Technique<br/>706"] -- detects --> DET["Detection Strategy<br/>706 (1:1 with techniques)"]
  DET -- analytic_refs --> AN["Analytic<br/>1773, per platform"]
  AN -- log_source_references --> DC["Data Component<br/>106"]
  DC -- log_sources --> LS["Log source<br/>name:channel, ~400 names"]
  LS --> FEED["Feed in your stack<br/>config/stack.yml"]
  FEED --> ET["Splunk eventtype<br/>mitre_dcXXXX_name__feed"]
  ET --> UMB["Umbrella eventtype<br/>mitre_dcXXXX_name"]
  UMB --> RULE["Analytic as ES detection + Sigma rule<br/>TTP / Anomaly / Hunting (+ baselines)<br/>99 implemented"]
  UMB --> SEQ["Strategy sequence<br/>raw-event chain, 8"]
  RULE -- "risk events" --> RISK[("Risk data model")]
  SEQ -- "risk events" --> RISK
  RISK --> CORR["Strategy risk rules (4) and<br/>cross-strategy correlations (3)"]
  classDef done fill:#d4edda,stroke:#2e7d32,color:#1b1b1b
  classDef part fill:#fff3cd,stroke:#b26a00,color:#1b1b1b
  class DC,LS,FEED,ET,UMB done
  class RULE,SEQ,CORR part
```

Green is complete for every data component. Amber is in progress: 99 analytics, chosen by technique prevalence on the ticked feeds ([backlog](docs/analytics/backlog.md) for the rest), and a detection-strategy layer of 8 sequences, 4 strategy risk rules and 3 cross-strategy correlations ([strategies](docs/strategies/README.md)).

**Resuming work?** [TODO.md](TODO.md) has the current state, conventions and the ordered next steps; [docs/roadmap.md](docs/roadmap.md) has the phased map.

## Content by log source

What you can run with the logs you have. Generated from `config/stack.yml` on every build; do not edit between the markers.

<!-- BEGIN mitremap:log-sources -->

With the feeds ticked in `config/stack.yml`: **64** data components live, **99** analytics and **8** strategy sequences runnable. Each count links to the full list in [docs/by-log-source.md](docs/by-log-source.md).

| Category | Feed | Have | Data components | Analytics | Sequences |
|---|---|---|---|---|---|
| Windows endpoint | [`wineventlog`](docs/by-log-source.md#wineventlog) | ☑ | [55](docs/by-log-source.md#wineventlog) | [47](docs/by-log-source.md#wineventlog) | [2](docs/by-log-source.md#wineventlog) |
|  | [`sysmon`](docs/by-log-source.md#sysmon) | ☑ | [26](docs/by-log-source.md#sysmon) | [66](docs/by-log-source.md#sysmon) | [8](docs/by-log-source.md#sysmon) |
|  | [`powershell_logging`](docs/by-log-source.md#powershell_logging) | ☑ | [3](docs/by-log-source.md#powershell_logging) | [1](docs/by-log-source.md#powershell_logging) | 0 |
|  | [`windows_firewall_log`](docs/by-log-source.md#windows_firewall_log) | ☐ | [1](docs/by-log-source.md#windows_firewall_log) | 0 | 0 |
|  | [`windows_perfmon`](docs/by-log-source.md#windows_perfmon) | ☐ | [1](docs/by-log-source.md#windows_perfmon) | 0 | 0 |
|  | [`windows_dns_server`](docs/by-log-source.md#windows_dns_server) | ☐ | [2](docs/by-log-source.md#windows_dns_server) | 0 | 0 |
|  | [`windows_dhcp`](docs/by-log-source.md#windows_dhcp) | ☐ | 0 | 0 | 0 |
|  | [`iis`](docs/by-log-source.md#iis) | ☐ | [2](docs/by-log-source.md#iis) | 0 | 0 |
|  | [`etw`](docs/by-log-source.md#etw) | ☐ | [6](docs/by-log-source.md#etw) | 0 | 0 |
|  | [`windows_osquery`](docs/by-log-source.md#windows_osquery) | ☐ | [2](docs/by-log-source.md#windows_osquery) | 0 | 0 |
|  | [`autoruns`](docs/by-log-source.md#autoruns) | ☐ | [1](docs/by-log-source.md#autoruns) | 0 | 0 |
| Endpoint security | [`trellix_epo`](docs/by-log-source.md#trellix_epo) | ☑ | [7](docs/by-log-source.md#trellix_epo) | 0 | 0 |
|  | [`solidcore`](docs/by-log-source.md#solidcore) | ☑ | [10](docs/by-log-source.md#solidcore) | 0 | 0 |
|  | [`edr_telemetry`](docs/by-log-source.md#edr_telemetry) | ☐ | [8](docs/by-log-source.md#edr_telemetry) | 0 | 0 |
| Network | [`corelight`](docs/by-log-source.md#corelight) | ☑ | [15](docs/by-log-source.md#corelight) | [11](docs/by-log-source.md#corelight) | 0 |
|  | [`palo_alto`](docs/by-log-source.md#palo_alto) | ☑ | [24](docs/by-log-source.md#palo_alto) | [14](docs/by-log-source.md#palo_alto) | 0 |
|  | [`wireshark`](docs/by-log-source.md#wireshark) | ☑ | [2](docs/by-log-source.md#wireshark) | 0 | 0 |
|  | [`netdev_syslog`](docs/by-log-source.md#netdev_syslog) | ☐ | [6](docs/by-log-source.md#netdev_syslog) | 0 | 0 |
|  | [`snmp`](docs/by-log-source.md#snmp) | ☐ | [1](docs/by-log-source.md#snmp) | 0 | 0 |
|  | [`netflow`](docs/by-log-source.md#netflow) | ☐ | [2](docs/by-log-source.md#netflow) | 0 | 0 |
| Linux | [`auditd`](docs/by-log-source.md#auditd) | ☐ | [33](docs/by-log-source.md#auditd) | 0 | 0 |
|  | [`linux_syslog`](docs/by-log-source.md#linux_syslog) | ☐ | [16](docs/by-log-source.md#linux_syslog) | 0 | 0 |
|  | [`linux_osquery`](docs/by-log-source.md#linux_osquery) | ☐ | [7](docs/by-log-source.md#linux_osquery) | 0 | 0 |
|  | [`sysmon_linux`](docs/by-log-source.md#sysmon_linux) | ☐ | [5](docs/by-log-source.md#sysmon_linux) | 0 | 0 |
|  | [`iptables`](docs/by-log-source.md#iptables) | ☐ | [1](docs/by-log-source.md#iptables) | 0 | 0 |
|  | [`ebpf`](docs/by-log-source.md#ebpf) | ☐ | [8](docs/by-log-source.md#ebpf) | 0 | 0 |
| Azure and identity | [`azure_entra`](docs/by-log-source.md#azure_entra) | ☐ | [14](docs/by-log-source.md#azure_entra) | 0 | 0 |
|  | [`azure_activity`](docs/by-log-source.md#azure_activity) | ☐ | [13](docs/by-log-source.md#azure_activity) | 0 | 0 |
|  | [`azure_resource`](docs/by-log-source.md#azure_resource) | ☐ | [1](docs/by-log-source.md#azure_resource) | 0 | 0 |
|  | [`m365_defender`](docs/by-log-source.md#m365_defender) | ☐ | 0 | 0 | 0 |
| Containers | [`kubernetes_audit`](docs/by-log-source.md#kubernetes_audit) | ☐ | [18](docs/by-log-source.md#kubernetes_audit) | 0 | 0 |
|  | [`container_runtime`](docs/by-log-source.md#container_runtime) | ☐ | [10](docs/by-log-source.md#container_runtime) | 0 | 0 |
| VMware ESXi | [`esxi_syslog`](docs/by-log-source.md#esxi_syslog) | ☐ | [27](docs/by-log-source.md#esxi_syslog) | 0 | 0 |
|  | [`vcenter`](docs/by-log-source.md#vcenter) | ☐ | [3](docs/by-log-source.md#vcenter) | 0 | 0 |

Feeds for platforms not yet in scope (macOS, Microsoft 365, AWS, GCP, Okta, SaaS) are listed in the [full index](docs/by-log-source.md#not-yet-in-scope).

<!-- END mitremap:log-sources -->

## What you get

| Output | Where | Notes |
|---|---|---|
| Splunk TA | `dist/splunk/TA-mitre-attack-datacomponents/` | `eventtypes.conf` (one per component per feed, plus umbrella), `tags.conf` (ATT&CK tags + CIM tags where safe), `macros.conf` (index, per-component, `_dm`, `_filter`, environment tunables), `transforms.conf` + `lookups/` (ATT&CK metadata, tuning allowlists with seed rows). |
| Detections app | `dist/splunk/DA-ESS-mitre-attack-detections/` | One ES 8 detection per implemented analytic, strategy sequence, strategy risk rule and cross-strategy correlation, all disabled. Content type decides the action: TTP → finding + risk, Anomaly → risk only, Hunting → none. Per-analytic `mitre_anXXXX_filter` macro and tunables bound to ATT&CK mutable elements; baseline searches and their lookups. |
| Sigma | `dist/sigma/` | `logsources.yml` (component ↔ Sigma logsource), `pipelines/splunk_mitre_dc.yml` (pySigma pipeline that scopes converted rules with the component eventtypes) and `rules/` (one file per implemented analytic, with correlation rules where needed). |
| Docs | `docs/` | One page per component ([index](docs/data-components/README.md)) per analytic ([index](docs/analytics/README.md), [backlog](docs/analytics/backlog.md)) and per strategy ([index](docs/strategies/README.md)), [coverage](docs/coverage.md), [gaps](docs/gaps.md), [telemetry health](docs/health.md), [checklist](docs/checklist.md), [model](docs/model.md), [Splunk implementation guidance](docs/splunk-implementation.md), [data sources](docs/data-sources.md), [roadmap](docs/roadmap.md), [changelog 20.0→20.1](docs/changelog/attack-20.0-to-20.1.md). |
| Content | `content/data_components/`, `content/analytics/`, `content/detection_strategies/`, `content/correlations/` | One YAML per component, implemented analytic, implemented strategy and cross-strategy correlation: regenerated ATT&CK blocks plus a hand-written `curated` block. |

## The checklist

`config/stack.yml` is a checklist of 44 feeds. Tick `have: true` on what reaches Splunk, set `index` and `sourcetypes`, rebuild. Pre-ticked from the brief: Windows Event Logs, PowerShell logging, Sysmon, Corelight, Palo Alto, Trellix ePO, Solidcore, Wireshark (hunt-only). Everything else is listed with what ticking it unlocks; see [docs/checklist.md](docs/checklist.md) and [docs/gaps.md](docs/gaps.md). Nothing is declared unavailable by the author.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[sigma,dev]"
make build      # scaffold -> render -> validate (idempotent; CI fails on drift)
make test
make diff FROM=20.0 TO=20.1
python -m mitremap new-analytic AN0123   # scaffold the next analytic from the backlog
python -m mitremap new-strategy DET0123  # scaffold a strategy sequence or risk rule
```

To move to a new ATT&CK release: `python -m mitremap fetch --version 20.2`, then `make build`, review `docs/changelog/` and the `derived` diffs in `content/`.

## Precedence of constraints

For each (component, feed) eventtype the search constraint comes from, in order: `curated.overrides.feeds` in the component YAML → `config/dc_defaults.yml` → the union of what the channel parser extracted from ATT&CK's free-text channels. Each component page shows the origin so review effort goes where it is needed.

## Layout

```
attack/        manifest + slim gzipped STIX extract (pinned 20.1)
config/        stack.yml (checklist), log_sources.yml (name -> feeds), dc_defaults.yml, cim.yml, sigma.yml, platforms.yml
content/       data_components/, analytics/, detection_strategies/, correlations/ (curated + regenerated ATT&CK blocks)
src/mitremap/  fetch, model, logsources (resolver + channel parsers), build, scaffold, analytics, strategies, render/{splunk,detections,sigma,docs,docs_analytics,docs_strategies,kql,esql}, validate, diff, cli
dist/          rendered Splunk apps (TA + detections), Sigma pipeline and rules (committed)
docs/          rendered + hand-written documentation
tests/         pytest
```
