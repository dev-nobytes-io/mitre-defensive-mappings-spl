# TODO and resume guide

The single place to pick this project up again. Read **Where things stand**, run **Resume in five minutes**, then take the first unchecked item in **Next up**. Tick items in the same PR that does them. The phased view is in [docs/roadmap.md](docs/roadmap.md).

## Where things stand

| Layer | State | Where |
|---|---|---|
| ATT&CK data | Enterprise v20.1 pinned (slim extract, sha256 in manifest); 20.0 to 20.1 changelog generated | `attack/`, `docs/changelog/` |
| Feed checklist | 44 feeds; 8 ticked (Windows Event Logs, PowerShell, Sysmon, Corelight, Palo Alto, Trellix ePO, Solidcore, Wireshark hunt-only) | `config/stack.yml`, `docs/checklist.md` |
| Data components | All 106 mapped; 372 eventtypes, tags, macros, metadata and tuning lookups | `content/data_components/`, `dist/splunk/TA-mitre-attack-datacomponents/` |
| Analytics | 49 of 1773 implemented (18 TTP, 27 anomaly, 4 hunting, 1 baseline); 462 more coverable by ticked feeds | `content/analytics/`, `docs/analytics/backlog.md` |
| Detection strategies | 6 sequences, 4 strategy risk rules, 3 cross-strategy correlations; 36 strategies delegated | `content/detection_strategies/`, `content/correlations/` |
| Sigma | Data-component pipeline; one rule file per analytic and per sequence strategy | `dist/sigma/` |
| KQL / ES\|QL | Renderer stubs and config keys only | `src/mitremap/render/{kql,esql}.py` |
| Validation | `mitremap validate` plus pytest; CI rebuilds and fails on drift | `tests/`, `.github/workflows/ci.yml` |
| Real Splunk | **Never run.** Nothing has been loaded into a search head or ES | — |

PRs so far: #1 data components, #2 analytics, #3 detection strategies (all merged).

## Resume in five minutes

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[sigma,dev]"
make fetch                   # only if attack/raw/ is empty and you need diff or a re-slim; build works from the committed slim file
make build                   # scaffold -> render -> validate; must end with "validate: ok"
.venv/bin/python -m pytest -q
git status                   # a second `make build` must leave no changes (CI enforces this)
```

Work on a branch, open a draft PR, keep `make build` idempotent and the tests green. Never edit generated files under `dist/` or `docs/` (except the hand-written docs listed in `CLAUDE.md`); change `config/` or `content/` and rebuild.

## Conventions that the validator enforces

* Only the `curated` block of content YAML is hand-written; `attack`/`derived` are regenerated.
* Eventtypes carry literal constraints only (no macros, pipes, lookups).
* Analytic and sequence SPL: starts from a `mitre_dcXXXX*` macro, ends with its own `mitre_anXXXX_filter` / `mitre_detXXXX_filter`, has no literal `index=`, and uses only macros and lookups that exist. Every risk field and `$token$` in the risk message appears in the search. Every declared tuning binding is used.
* Content type decides the ES action: TTP gets a finding and risk, Anomaly gets risk only, Hunting gets no action. Sequences get a finding and risk. Risk rules get a finding only and never write risk.
* Every analytic and sequence has Sigma, or `sigma.not_expressible` with a reason. Every Sigma file must convert through `dist/sigma/pipelines/splunk_mitre_dc.yml` with the Splunk backend.
* Tunables live in macros or lookups, bound to the ATT&CK mutable element they implement. Thresholds are never literals in SPL.

## Next up (in order)

### P0: correctness before anyone enables anything

- [ ] **Windows feeds match on `source`, not `sourcetype`.** Splunk Add-on for Windows 5.0+ and the current Sysmon add-on use `sourcetype=XmlWinEventLog` with the channel in `source=XmlWinEventLog:<channel>`. The eventtypes use `sourcetype=XmlWinEventLog:<channel>`, which only matches pre-5.0 add-ons. Fix: per-feed `constraint_field: source` for wineventlog, sysmon and powershell_logging; matching on source works for old and new add-on versions. Done when the eventtypes, Sigma pipeline, docs and tests use `source=` for these feeds.
- [ ] **Sigma chain drops `splunk_windows`.** That pipeline adds `source="WinEventLog:<channel>"` (classic rendering), which contradicts XML collection. Our pipeline should emit the XML `source` itself; tests and docs should chain `sysmon` plus ours only.
- [ ] **Verify remaining sourcetype names** against installed add-ons and record the result in `config/stack.yml`: Trellix ePO (`mcafee:epo` from DB pull vs `mcafee:epo:syslog`), the Solidcore event-name field (`threat_name` vs `event_description`), Kubernetes audit (`kube:apiserver-audit` depends on the collector), container runtime.

### P1: operational safety net

- [ ] **Telemetry health detection.** A generated lookup of every (index, sourcetype or source) that a live eventtype depends on, and a detection that reports which are never seen in 7 days (configuration gap: the eventtype gives false coverage) and which went silent in the last N hours (outage). Thresholds in macros.
- [ ] **Per-host feed dropout.** Hosts that sent Sysmon (or Security) in the previous 7 days but nothing in the last 4 hours; the usual sign of a stopped or tampered agent. Raise Host Status risk so it feeds the correlations.
- [ ] **Asset and identity starter.** Document, or generate a template for, the ES asset lookup (`ip`, `nt_host`, `dns`) the cross-feed risk rules depend on. Add a check that risk objects from Corelight and Palo Alto resolve to assets.

### P2: content growth (Windows and network, feeds already ticked)

- [ ] **Analytics, next batch** (backlog order, Windows): AN1040 file and directory discovery, AN0392 file deletion, AN0237 encoded file decode-and-run, AN1070 local data collection, AN1031 WMI execution, AN0980 screen capture, AN1064 obfuscated files, AN0724 local staging, AN0577 DLL hijack, AN0903 netstat, AN0589 registry query, AN0324 masqueraded task or service, AN0516 lateral tool transfer, AN1325 service discovery, AN0846 local account discovery, AN1095 DLL injection.
- [ ] **Analytics needing care:** AN1465 native API, AN0400/AN1496 crypto library loads, AN0066 packing, AN0243 keylogging. These depend on Sysmon ImageLoad (EventCode 7) volume; decide the Sysmon config scope first.
- [ ] **Network-device CLI analytics** (AN1457, AN1044, AN0099, AN0563, AN0257, AN1073, AN1587, AN0434): need PAN-OS administrator activity audit logs. Confirm that the log exists and its sourcetype, then implement as hunting.
- [ ] **More sequences** where an implemented analytic's `gaps` names a chain: DET0530 (5145 ADMIN$ write, then service or process on the target), DET0140 file deletion after execution (after AN0392), DET0364 WMI process create plus remote connection (after AN1031), DET0215 ransom notes plus mass rename.
- [ ] **Consolidate hunting searches** (AN1452, AN0095, AN0559, AN0254 and future discovery hunts) into one dashboard with a panel per analytic.

### P3: validation against real data

- [ ] Stand up a test search head with both apps, the CIM add-on and ES. Load `attack_data` samples or Atomic Red Team runs for the implemented techniques, and record per detection whether it fired (`docs/validation.md`).
- [ ] Run AppInspect on both apps in CI and fix findings.
- [ ] After a 7-day tuning run in production, promote analytics from `implemented` to `reviewed`.

### P4: more platforms (tick the feed first, then implement)

- [ ] Linux (auditd, syslog): 357 analytics ready; the auditd rule set is the prerequisite.
- [ ] ESXi (remote syslog): 107 ready.
- [ ] Containers (Kubernetes audit, runtime): 35 ready.
- [ ] Azure / Entra: 21 identity-provider analytics ready; the IaaS ones need `config/platforms.yml` scope review.

### P5: more query languages

- [ ] KQL renderer (Sentinel / Defender tables are already in `kql.table` per log source).
- [ ] ES|QL renderer (`elastic.dataset` per log source).

### P6: maintenance

- [ ] Each ATT&CK release: `python -m mitremap fetch --version <new>`, `make diff FROM=<old> TO=<new>`, `make build`; review `derived` diffs and analytics whose ATT&CK text changed.
- [ ] Optional: export to Splunk `contentctl` format for teams that author ESCU-style content.

## Decisions already made (do not re-litigate without a reason)

* Data components are eventtypes. Macros and lookups are the tuning surface, kept separate because eventtypes cannot use them.
* Not everything is risk-based: the content type decides the action per detection.
* A strategy's analytics are per-platform variants in ATT&CK v18+, so strategies are delegated, sequences or risk rules (see `docs/strategies/README.md`).
* Risk rules recover analytic ids from the rule name (`source`), not from custom annotation field paths.
* Everything ships disabled.
* The feed checklist is the user's to tick; nothing is labelled unavailable by the author.

## Known limitations

* No Splunk instance has run any of this. SPL is linted and cross-referenced only.
* Field names depend on the installed add-ons; the `mitre_normalize_*` macros are the adaptation point.
* Sigma sequences use unordered `temporal` correlations because the Splunk backend lacks `temporal_ordered`; the SPL enforces order.
* Endpoint risk lands on host names and network risk on IPs; cross-feed correlation needs asset and identity mapping.
