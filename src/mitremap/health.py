"""Telemetry health: is the data every live eventtype depends on actually arriving?

Generated, not hand-written: everything derives from config/stack.yml and the data
component views.

  TA lookup  mitre_expected_telemetry.csv   one row per (index, field, value) a ticked
                                            feed's eventtypes match on, with the data
                                            components that depend on it
  TA macros  mitre_health_index_scope       index IN (...) of ticked feeds
             mitre_health_host_scope        host-reporting feeds (stack.yml host_feed)
             mitre_health_silence_hours     outage threshold
             mitre_health_host_silence_hours
  Detections HEALTH0001  expected telemetry never seen in 7 days, or silent
             HEALTH0002  host stopped sending a host-reporting feed (risk, T1685)
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict

from . import config
from .build import DCView, constraint_field

WILDCARD = ("*", "?")


@dataclass
class ExpectedRow:
    feed: str
    have: bool
    index: str
    field: str
    value: str
    data_components: list[str]
    eventtypes: int


def expected_telemetry(views: list[DCView]) -> list[ExpectedRow]:
    acc: dict[tuple, dict] = defaultdict(lambda: {"dcs": set(), "ets": 0})
    for v in views:
        for f in v.feeds:
            feed = config.feed(f.feed)
            if not f.in_scope or f.hunt_only or not feed.get("index"):
                continue
            for val in f.sourcetypes:
                if any(w in val for w in WILDCARD):
                    continue
                k = (f.feed, feed["index"], constraint_field(f.feed), val)
                acc[k]["dcs"].add(v.dc.id)
                acc[k]["ets"] += 1
    rows = [ExpectedRow(feed, bool(config.feed(feed).get("have")), idx, fld, val, sorted(a["dcs"]), a["ets"])
            for (feed, idx, fld, val), a in acc.items()]
    return sorted(rows, key=lambda r: (not r.have, r.feed, r.field, r.value))


def index_scope() -> str:
    idx = sorted({f["index"] for f in config.stack().values() if f.get("have") and f.get("index") and not f.get("hunt_only")})
    return "index IN (" + ", ".join(idx) + ")"


def host_scope() -> str:
    parts = []
    for name, f in config.stack().items():
        if not (f.get("have") and f.get("host_feed")):
            continue
        fld = f.get("constraint_field", "sourcetype")
        val = f.get("host_feed_value") or f.get("sourcetype")
        parts.append(f'(index={f["index"]} {fld}="{val}")')
    return "(" + " OR ".join(parts) + ")" if parts else "(index=__no_host_feeds_ticked__)"


def ta_macros() -> list[tuple[str, str, str]]:
    return [
        ("mitre_health_index_scope", index_scope(), "Indexes of ticked feeds (generated from config/stack.yml)."),
        ("mitre_health_host_scope", host_scope(), "Feeds that report per endpoint (stack.yml host_feed), for per-host dropout checks."),
        ("mitre_health_silence_hours", "4", "Hours without events before expected telemetry counts as silent (HEALTH0001)."),
        ("mitre_health_host_silence_hours", "4", "Hours without events before a host counts as having stopped reporting (HEALTH0002)."),
    ]


HEALTH0001_SPL = """| inputlookup mitre_expected_telemetry where have=1
| eval key=index."|".field."|".value
| join type=left max=1 key
    [| tstats count as event_count latest(_time) as last_seen where `mitre_health_index_scope` earliest=-7d by index sourcetype source
     | eval key=mvappend(index."|sourcetype|".sourcetype, index."|source|".source)
     | mvexpand key
     | stats sum(event_count) as event_count max(last_seen) as last_seen by key]
| eval event_count=coalesce(event_count, 0), hours_since=if(isnotnull(last_seen), round((now() - last_seen) / 3600, 1), null())
| eval status=case(event_count == 0, "not_seen_7d", hours_since > `mitre_health_silence_hours`, "silent", true(), "ok")
| where status!="ok"
| eval data_component_count=mvcount(split(data_components, "|")), last_seen=if(isnotnull(last_seen), strftime(last_seen, "%Y-%m-%dT%H:%M:%S"), "never")
| table status feed index field value data_component_count data_components eventtypes last_seen hours_since
| `mitre_health0001_filter`"""

HEALTH0002_SPL = """| tstats count latest(_time) as last_seen where `mitre_health_host_scope` earliest=-7d by index host
| eval hours_since=round((now() - last_seen) / 3600, 1), dest=host
| where hours_since > `mitre_health_host_silence_hours`
| search `mitre_not_allowlisted_dest`
| stats max(last_seen) as lastTime max(hours_since) as hours_since values(index) as silent_index by dest
| `mitre_ctime(lastTime)`
| `mitre_health0002_filter`"""


@dataclass
class HealthRule:
    id: str
    title: str
    summary: str
    spl: str
    severity: str
    cron: str
    earliest: str
    risk: dict | None
    technique: str | None
    notable_fields: list[str]


def rules() -> list[HealthRule]:
    return [
        HealthRule(
            "HEALTH0001", "Telemetry an eventtype depends on is missing or silent",
            "Compares every index and sourcetype or source that a ticked feed's eventtypes match on with what arrived in the last 7 days. "
            "not_seen_7d means a data component looks covered but has no data (a configuration gap: wrong sourcetype, channel not collected, audit policy off). "
            "silent means it arrived earlier in the week but not in the last few hours (an outage).",
            HEALTH0001_SPL, "medium", "37 */4 * * *", "-15m", None, None, ["feed", "value"]),
        HealthRule(
            "HEALTH0002", "Host stopped sending endpoint telemetry",
            "A host that sent Sysmon or Security events in the last 7 days has sent none for several hours. Agents stopped by an attacker look like this, "
            "so it raises Host Status risk on the host as well as a finding. Uses the indexed host field: with Windows Event Forwarding the host is the "
            "collector unless props set host from Computer.",
            HEALTH0002_SPL, "low", "47 * * * *", "-15m",
            {"message": "$dest$ stopped sending endpoint telemetry for $hours_since$ hours", "objects": [{"field": "dest", "type": "system", "score": 25}]},
            "T1685", ["dest"]),
    ]


def filter_macros() -> list[tuple[str, str, str]]:
    return [(f"mitre_{r.id.lower()}_filter", "search *", f"Exclusions for {r.id} {r.title}.") for r in rules()]
