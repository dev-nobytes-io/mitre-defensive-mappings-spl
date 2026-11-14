# TA-mitre-attack-datacomponents

ATT&CK v20.1 Enterprise data components rendered as Splunk knowledge objects.

| Object | File | Purpose |
|---|---|---|
| Eventtypes | `default/eventtypes.conf` | One per (data component, feed) plus an umbrella per data component. Literal `index`/`sourcetype`/`EventCode` constraints. |
| Tags | `default/tags.conf` | `mitre_attack`, `dcXXXX`, `mitre_feed_<feed>` on every eventtype; CIM tags only where the feed's TA is CIM compliant for that model. |
| Macros | `default/macros.conf` | Index macros, per-component `mitre_dcXXXX*` macros (umbrella, per feed, `_filter`, `_dm`, `_dm_where`) and environment macros. For analytics, not eventtypes. |
| Lookups | `lookups/mitre_attack_*.csv` | ATT&CK metadata (components, log sources, analytics, detection strategies, techniques, feeds). |
| Tuning lookups | `lookups/mitre_allowlist_*.csv`, `mitre_asset_roles.csv`, ... | Seed rows only. Analytics reference these by name; edit them in place (they are never overwritten by a rebuild). |

Components with at least one feed on an in-scope platform: 86 of 106.

## Install

1. Edit `config/stack.yml` in the repo: set `index` and `sourcetypes` to match your environment, rebuild (`make build`).
   Or install as is and override stanzas in `local/eventtypes.conf`. Eventtypes for feeds you do not collect match nothing; disable them in `local/` if you prefer.
2. Copy this directory to `$SPLUNK_HOME/etc/apps/` on search heads (and on ES search heads for the analytics phase). Restart or debug/refresh.
3. Check: `| inputlookup mitre_attack_feeds.csv | where render=1 | table feed index sourcetypes` against `| eventcount summarize=false index=*`, then `eventtype=mitre_dc0032_process_creation | stats count by eventtype`.
4. Scope the telemetry health search to the feeds you collect: set the `mitre_health_feeds` macro (for example `feed IN (sysmon, wineventlog)`).

## Notes

* Windows event log, Sysmon and PowerShell eventtypes match on `source=XmlWinEventLog:<channel>`, which is correct for Splunk_TA_windows 5.0+ (sourcetype `XmlWinEventLog`) and for older versions alike.
* `wireshark` eventtypes are hunt-only and disabled.
* Eventtypes are not usable with `tstats`. For high-volume components use the `mitre_dcXXXX_dm` / `_dm_where` macros against accelerated CIM data models.
* No `props.conf`: field extraction is the job of the source TAs listed in `lookups/mitre_attack_feeds.csv`.
