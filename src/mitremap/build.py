"""Compute the per-data-component view shared by the scaffolder and renderers."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import config
from .logsources import Provider, ResolvedSource, parse_channel, resolve, sourcetypes_for
from .model import AttackModel, DataComponent

MAX_CHANNELS_LISTED = 12


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def eventtype_base(dc: DataComponent) -> str:
    return f"mitre_{dc.id.lower()}_{slug(dc.name)}"


def feed_in_scope(feed_name: str) -> bool:
    f = config.feed(feed_name)
    if f.get("virtual") or f.get("render") is False:
        return False
    scope = config.platforms()
    restrict = scope.get("restrict_platform_to_feeds", {})
    for p in f.get("platforms", []):
        if p not in scope["in_scope"]:
            continue
        if p in restrict and feed_name not in restrict[p]:
            continue
        return True
    return False


@dataclass
class SourceView:
    """One canonical ATT&CK log source as used by one data component."""
    canonical: str
    raw_names: set[str]
    refs: int
    platforms: Counter
    channels: Counter
    resolved: ResolvedSource
    parsed: dict                 # union of parsed channel constraints
    unparsed_channels: int       # channels that yielded no constraint (documentation only)


@dataclass
class FeedView:
    """One feed's contribution to a data component -> one per-feed eventtype."""
    feed: str
    have: bool
    in_scope: bool
    hunt_only: bool
    sources: list[str]                       # canonical names
    sourcetypes: list[str]
    event_codes: list[int]
    syscalls: list[str]
    record_types: list[str]
    verbs: list[str]
    filters: list[str]
    unfiltered: bool                         # no narrowing at all: eventtype is the whole feed
    broad_refs: int                          # ATT&CK references to this feed that carried no usable filter
    origin: str                              # "curated" | "defaults" | "derived"
    eventtype: str
    cim_compliant: bool


@dataclass
class DCView:
    dc: DataComponent
    platforms: dict[str, int]
    sources: list[SourceView]
    feeds: list[FeedView]
    analytics: int
    detection_strategies: list[str]
    techniques: list[str]
    tactics: Counter
    cim: dict | None
    eventtype: str
    in_scope: bool

    @property
    def live_feeds(self) -> list[FeedView]:
        return [f for f in self.feeds if f.in_scope and f.have]

    @property
    def ready_feeds(self) -> list[FeedView]:
        return [f for f in self.feeds if f.in_scope and not f.have]


def _constraint_parts(fv: FeedView) -> list[str]:
    parts: list[str] = []
    if fv.sourcetypes:
        parts.append("sourcetype=" + fv.sourcetypes[0] if len(fv.sourcetypes) == 1 else "sourcetype IN (" + ", ".join(_q(s) for s in fv.sourcetypes) + ")")
    if fv.event_codes:
        parts.append("EventCode IN (" + ", ".join(str(c) for c in fv.event_codes) + ")")
    if fv.record_types:
        parts.append("type IN (" + ", ".join(fv.record_types) + ")")
    if fv.syscalls:
        parts.append("(syscall IN (" + ", ".join(fv.syscalls) + ") OR SYSCALL IN (" + ", ".join(fv.syscalls) + "))")
    if fv.verbs:
        parts.append("verb IN (" + ", ".join(fv.verbs) + ")")
    if len(fv.filters) == 1:
        parts.append(f"({fv.filters[0]})")
    elif fv.filters:
        parts.append("(" + " OR ".join(f"({f})" for f in fv.filters) + ")")
    return parts


def _q(s: str) -> str:
    return f'"{s}"' if re.search(r"[\s:/*]", s) else s


def eventtype_search(fv: FeedView) -> str:
    f = config.feed(fv.feed)
    parts = [f"index={f['index']}"] if f.get("index") else []
    parts += _constraint_parts(fv)
    if f.get("filter"):
        parts.append(f"({f['filter']})")
    return " ".join(parts)


def build_dc_view(m: AttackModel, dc: DataComponent, curated_overrides: dict | None = None) -> DCView:
    # ---- gather references grouped by canonical source
    groups: dict[str, dict] = {}
    for ref in dc.log_sources:
        rs = resolve(ref.name)
        g = groups.setdefault(rs.canonical, {"raw": set(), "refs": 0, "plats": Counter(), "chan": Counter(), "rs": rs})
        g["raw"].add(ref.name); g["refs"] += 1; g["chan"][ref.channel] += 1
    for an in m.analytics_for_dc(dc.id):
        for ref in an.log_source_refs:
            if ref.dc_id != dc.id:
                continue
            rs = resolve(ref.name)
            g = groups.setdefault(rs.canonical, {"raw": set(), "refs": 0, "plats": Counter(), "chan": Counter(), "rs": rs})
            g["raw"].add(ref.name); g["refs"] += 1; g["chan"][ref.channel] += 1
            for p in an.platforms:
                g["plats"][p] += 1

    sources: list[SourceView] = []
    for canon, g in sorted(groups.items(), key=lambda kv: -kv[1]["refs"]):
        rs: ResolvedSource = g["rs"]
        parsed: dict = defaultdict(set)
        unparsed = 0
        for ch, n in g["chan"].items():
            pc = parse_channel(rs.parser, ch)
            if not pc:
                unparsed += n
            for k, v in pc.items():
                parsed[k].update(v)
        sources.append(SourceView(canon, g["raw"], g["refs"], g["plats"], g["chan"], rs, {k: sorted(v) for k, v in parsed.items()}, unparsed))

    # ---- fold sources into feeds (derived union)
    feeds: dict[str, dict] = {}
    for sv in sources:
        for p in sv.resolved.providers:
            fd = feeds.setdefault(p.feed, {"sources": [], "sourcetypes": set(), "codes": set(), "syscalls": set(), "rts": set(), "verbs": set(), "filters": set(), "broad": 0})
            fd["sources"].append(sv.canonical)
            fd["sourcetypes"].update(sourcetypes_for(p, sv.parsed))
            codes = set(p.event_codes) | set(sv.parsed.get("event_codes", []))
            narrowed = False
            if codes:
                fd["codes"].update(codes); narrowed = True
            if p.record_type:
                fd["rts"].add(p.record_type); narrowed = True
            if sv.parsed.get("syscalls"):
                fd["syscalls"].update(sv.parsed["syscalls"]); narrowed = True
            if sv.parsed.get("verbs"):
                fd["verbs"].update(sv.parsed["verbs"]); narrowed = True
            if p.filter:
                fd["filters"].add(p.filter); narrowed = True
            if sv.parsed.get("zeek_logs") or p.logs:
                narrowed = True
            if not narrowed:
                fd["broad"] += sv.unparsed_channels or sv.refs

    # ---- apply defaults (config/dc_defaults.yml) and curated overrides (content YAML)
    defaults = (config.load("dc_defaults").get("defaults") or {}).get(dc.name, {}) or {}
    cur = curated_overrides or {}
    excluded = set(defaults.get("exclude", []) or []) | set(cur.get("exclude_feeds", []) or [])
    cur_feeds = cur.get("feeds") or {}

    # a feed named in defaults/curated but absent from ATT&CK's log sources is an added provider
    for name, spec in list(defaults.items()) + list(cur_feeds.items()):
        if name == "exclude" or name in feeds or name in excluded or spec is None or name not in config.stack():
            continue
        feeds[name] = {"sources": ["(added by dc_defaults/curated)"], "sourcetypes": set(), "codes": set(), "syscalls": set(), "rts": set(), "verbs": set(), "filters": set(), "broad": 0}

    cim_spec = config.cim().get(dc.name)
    cur_cim = cur.get("cim")
    if cur_cim:
        cim_spec = cur_cim
    base = eventtype_base(dc)
    feed_views: list[FeedView] = []
    for name, fd in feeds.items():
        f = config.feed(name)
        if f.get("virtual") or name in excluded:
            continue
        spec = None; origin = "derived"
        if name in cur_feeds and cur_feeds[name] is not None:
            spec, origin = cur_feeds[name], "curated"
        elif name in defaults and name != "exclude":
            spec, origin = defaults[name] or {}, "defaults"
        if spec is not None:
            sourcetypes = list(spec.get("sourcetypes") or fd["sourcetypes"] or sourcetypes_for(Provider(feed=name), {}))
            codes = list(spec.get("event_codes") or [])
            syscalls = list(spec.get("syscalls") or [])
            rts = list(spec.get("record_types") or [])
            verbs = list(spec.get("verbs") or [])
            filters = [spec["filter"]] if spec.get("filter") else []
        else:
            sourcetypes, codes, syscalls, rts, verbs, filters = (sorted(fd["sourcetypes"]), sorted(fd["codes"]), sorted(fd["syscalls"]), sorted(fd["rts"]), sorted(fd["verbs"]), sorted(fd["filters"]))
        unfiltered = not (codes or syscalls or rts or verbs or filters)
        feed_views.append(FeedView(
            feed=name, have=bool(f.get("have")), in_scope=feed_in_scope(name), hunt_only=bool(f.get("hunt_only")),
            sources=sorted(set(fd["sources"])), sourcetypes=sorted(sourcetypes),
            event_codes=sorted(codes), syscalls=sorted(syscalls), record_types=sorted(rts),
            verbs=sorted(verbs), filters=sorted(filters), unfiltered=unfiltered, broad_refs=fd["broad"], origin=origin,
            eventtype=f"{base}__{name}",
            cim_compliant=bool(cim_spec and cim_spec.get("datamodel") and name in (cim_spec.get("compliant_feeds") or [])),
        ))
    feed_views.sort(key=lambda fv: (not fv.in_scope, not fv.have, fv.feed))

    # ---- dependents
    dets, techs, tactics = set(), set(), Counter()
    for an in m.analytics_for_dc(dc.id):
        if an.det_id:
            dets.add(an.det_id)
            te = m.technique_for_analytic(an)
            if te:
                techs.add(te.id)
                for t in te.tactics:
                    tactics[t] += 1

    return DCView(
        dc=dc, platforms=m.dc_platforms(dc.id), sources=sources, feeds=feed_views,
        analytics=len(dc.analytic_ids), detection_strategies=sorted(dets), techniques=sorted(techs), tactics=tactics,
        cim=cim_spec if cim_spec and cim_spec.get("datamodel") else None, eventtype=base,
        in_scope=any(fv.in_scope for fv in feed_views),
    )


def load_curated(dc_id: str) -> dict:
    """Read the curated block of content/data_components/<dc_id>.yml if present."""
    import yaml
    from . import CONTENT_DIR
    p = CONTENT_DIR / "data_components" / f"{dc_id}.yml"
    if not p.exists():
        return {}
    return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("curated") or {}


def build_all(m: AttackModel) -> list[DCView]:
    return [build_dc_view(m, dc, load_curated(dc.id).get("overrides")) for dc in sorted(m.data_components.values(), key=lambda d: d.id)]
