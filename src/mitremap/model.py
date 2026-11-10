"""Typed view over the slim ATT&CK bundle.

Objects (ATT&CK v18+ detection model):
    Technique  <-detects-  DetectionStrategy  -analytic_refs->  Analytic  -log_source_references->  DataComponent
    DataComponent.log_sources: [{name, channel}]   (name is e.g. "WinEventLog:Sysmon", channel is free text)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .fetch import load_manifest, load_slim


def _ext_id(o: dict) -> str:
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id", "")
    return ""


def _ext_url(o: dict) -> str:
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("url", "")
    return ""


def _active(o: dict) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


@dataclass
class LogSourceRef:
    name: str          # raw ATT&CK name, e.g. "WinEventLog:Sysmon"
    channel: str       # raw channel text, e.g. "EventCode=1"
    dc_id: str = ""    # DCxxxx (only set on analytic references)


@dataclass
class Tactic:
    stix_id: str
    id: str
    name: str
    shortname: str


@dataclass
class Technique:
    stix_id: str
    id: str
    name: str
    url: str
    platforms: list[str]
    tactics: list[str]            # kill-chain shortnames
    parent_id: str | None = None  # for sub-techniques
    det_ids: list[str] = field(default_factory=list)


@dataclass
class DataComponent:
    stix_id: str
    id: str
    name: str
    url: str
    description: str
    version: str
    modified: str
    domains: list[str]
    log_sources: list[LogSourceRef]
    analytic_ids: list[str] = field(default_factory=list)


@dataclass
class Analytic:
    stix_id: str
    id: str
    name: str
    url: str
    description: str
    platforms: list[str]
    log_source_refs: list[LogSourceRef]
    mutable_elements: list[dict]
    det_id: str = ""


@dataclass
class DetectionStrategy:
    stix_id: str
    id: str
    name: str
    url: str
    analytic_ids: list[str]
    technique_id: str = ""


class AttackModel:
    def __init__(self, bundle: dict, version: str):
        self.version = version
        self.tactics: dict[str, Tactic] = {}
        self.techniques: dict[str, Technique] = {}
        self.data_components: dict[str, DataComponent] = {}
        self.analytics: dict[str, Analytic] = {}
        self.detection_strategies: dict[str, DetectionStrategy] = {}
        self._by_stix: dict[str, object] = {}
        self._load(bundle)

    # ------------------------------------------------------------------ load
    def _load(self, bundle: dict) -> None:
        objs = [o for o in bundle["objects"] if _active(o)]
        for o in objs:
            t = o["type"]
            if t == "x-mitre-tactic":
                tac = Tactic(o["id"], _ext_id(o), o["name"], o["x_mitre_shortname"])
                self.tactics[tac.id] = tac
                self._by_stix[o["id"]] = tac
            elif t == "attack-pattern":
                te = Technique(
                    o["id"], _ext_id(o), o["name"], _ext_url(o),
                    list(o.get("x_mitre_platforms", [])),
                    [k["phase_name"] for k in o.get("kill_chain_phases", []) if k.get("kill_chain_name") == "mitre-attack"],
                )
                self.techniques[te.id] = te
                self._by_stix[o["id"]] = te
            elif t == "x-mitre-data-component":
                dc = DataComponent(
                    o["id"], _ext_id(o), o["name"], _ext_url(o), o.get("description", "").strip(),
                    o.get("x_mitre_version", ""), o.get("modified", ""), list(o.get("x_mitre_domains", [])),
                    [LogSourceRef(l.get("name", ""), str(l.get("channel", "") or "")) for l in o.get("x_mitre_log_sources", [])],
                )
                self.data_components[dc.id] = dc
                self._by_stix[o["id"]] = dc
            elif t == "x-mitre-analytic":
                an = Analytic(
                    o["id"], _ext_id(o), o["name"], _ext_url(o), o.get("description", "").strip(),
                    list(o.get("x_mitre_platforms", [])),
                    [LogSourceRef(r.get("name", ""), str(r.get("channel", "") or ""), r.get("x_mitre_data_component_ref", ""))
                     for r in o.get("x_mitre_log_source_references", [])],
                    list(o.get("x_mitre_mutable_elements", [])),
                )
                self.analytics[an.id] = an
                self._by_stix[o["id"]] = an
            elif t == "x-mitre-detection-strategy":
                ds = DetectionStrategy(o["id"], _ext_id(o), o["name"], _ext_url(o), list(o.get("x_mitre_analytic_refs", [])))
                self.detection_strategies[ds.id] = ds
                self._by_stix[o["id"]] = ds

        # resolve stix refs -> ATT&CK ids
        for an in self.analytics.values():
            for ref in an.log_source_refs:
                dc = self._by_stix.get(ref.dc_id)
                ref.dc_id = dc.id if isinstance(dc, DataComponent) else ""
                if isinstance(dc, DataComponent) and an.id not in dc.analytic_ids:
                    dc.analytic_ids.append(an.id)
        for ds in self.detection_strategies.values():
            ids = []
            for ref in ds.analytic_ids:
                an = self._by_stix.get(ref)
                if isinstance(an, Analytic):
                    ids.append(an.id)
                    an.det_id = ds.id
            ds.analytic_ids = ids
        for o in objs:
            if o["type"] != "relationship":
                continue
            src, tgt = self._by_stix.get(o["source_ref"]), self._by_stix.get(o["target_ref"])
            if o["relationship_type"] == "detects" and isinstance(src, DetectionStrategy) and isinstance(tgt, Technique):
                src.technique_id = tgt.id
                tgt.det_ids.append(src.id)
            elif o["relationship_type"] == "subtechnique-of" and isinstance(src, Technique) and isinstance(tgt, Technique):
                src.parent_id = tgt.id

    # --------------------------------------------------------------- helpers
    def tactic_by_shortname(self, short: str) -> Tactic | None:
        return next((t for t in self.tactics.values() if t.shortname == short), None)

    def analytics_for_dc(self, dc_id: str) -> list[Analytic]:
        return [self.analytics[a] for a in self.data_components[dc_id].analytic_ids]

    def technique_for_analytic(self, an: Analytic) -> Technique | None:
        ds = self.detection_strategies.get(an.det_id)
        return self.techniques.get(ds.technique_id) if ds else None

    def dc_platforms(self, dc_id: str) -> dict[str, int]:
        """Platforms of the analytics that reference this DC, with counts."""
        c: dict[str, int] = defaultdict(int)
        for an in self.analytics_for_dc(dc_id):
            for p in an.platforms:
                c[p] += 1
        return dict(sorted(c.items(), key=lambda x: -x[1]))

    def dc_log_source_refs(self, dc_id: str) -> list[LogSourceRef]:
        """Union of the DC's own log sources and every analytic reference to it."""
        out = list(self.data_components[dc_id].log_sources)
        for an in self.analytics_for_dc(dc_id):
            for ref in an.log_source_refs:
                if ref.dc_id == dc_id:
                    out.append(ref)
        return out


def load_model(version: str | None = None, domain: str = "enterprise-attack") -> AttackModel:
    version = version or load_manifest()["version"]
    return AttackModel(load_slim(domain, version), version)
