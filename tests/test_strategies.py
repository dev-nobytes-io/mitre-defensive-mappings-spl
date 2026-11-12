"""Checks on the detection strategy layer (sequences, strategy risk rules, cross-strategy correlations)."""
import json
import re

import pytest
import yaml

from mitremap import DIST_DIR
from mitremap.strategies import (RISK_FIELDS, StrategyView, all_strategies, implemented_strategies, risk_scope_clause,
                                 risk_threshold_spl, validate_strategies)

DA = DIST_DIR / "splunk" / "DA-ESS-mitre-attack-detections"
RULES = DIST_DIR / "sigma" / "rules"


def _stanzas():
    text = (DA / "default" / "savedsearches.conf").read_text()
    return {m.group(1): m.group(2) for m in re.finditer(r"^\[(.+?)\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)}


def test_validate_strategies_clean(model):
    assert validate_strategies(model) == []


def test_every_det_with_implemented_analytics_is_listed(model):
    svs = {s.id: s for s in all_strategies(model) if s.kind == "strategy"}
    from mitremap.analytics import implemented_views
    for v in implemented_views(model):
        assert v.an.det_id in svs
    delegated = [s for s in svs.values() if not s.implemented]
    assert delegated and all(s.shape == "delegated" for s in delegated)


def test_scope_clause_and_filters():
    s = StrategyView("RISK9999", "correlation", {"scope": "all", "risk_object_types": ["system"]})
    assert risk_scope_clause(s) == 'source IN ("MITRE - AN* - Rule", "MITRE - DET* - Rule") All_Risk.risk_object_type IN ("system")'
    s = StrategyView("RISK9998", "correlation", {"scope": ["AN0001", "AN0002"], "group_by": "threat_object", "threat_object_types": ["ip_address"], "condition": "distinct_risk_objects >= 3"})
    assert 'source IN ("MITRE - AN0001 - *", "MITRE - AN0002 - *")' in risk_scope_clause(s)
    spl = risk_threshold_spl(s)
    assert "by All_Risk.threat_object" in spl and "dc(risk_object) as distinct_risk_objects" in spl
    assert spl.rstrip().endswith("`mitre_risk9998_filter`")
    assert "`mitre_risk9998_condition`" in spl
    for f in RISK_FIELDS:
        assert f" as {f}" in spl


def test_rendered_actions_by_shape(model):
    stanzas = _stanzas()
    for s in implemented_strategies(model):
        body = stanzas[s.stanza]
        assert "disabled = true" in body and "action.notable = 1" in body
        ann = json.loads(re.search(r"^action\.correlationsearch\.annotations = (.+)$", body, re.M).group(1))
        if s.kind == "strategy":
            assert ann["mitre_det"] == [s.id] and ann["mitre_attack"] == [s.technique.id]
        if s.shape == "sequence":
            assert "action.risk = 1" in body, s.id
            assert ann["mitre_an"] == s.curated["extends"]
        else:
            assert "action.risk = 1" not in body, f"{s.id}: risk rules must not write risk (feedback loop)"
            assert re.search(r"^action\.notable\.param\.rule_title = RBA: ", body, re.M)
            assert "from datamodel=Risk.All_Risk" in body


def test_risk_rules_never_read_their_own_output(model):
    """A risk rule's scope may include sequences (which write risk) but never another risk rule."""
    risk_rules = {s.id for s in implemented_strategies(model) if s.shape == "risk_threshold"}
    for s in implemented_strategies(model):
        if s.shape == "risk_threshold" and s.scope != "all":
            assert not (set(s.scope) & risk_rules), s.id


def test_strategy_sigma_converts(model):
    pytest.importorskip("sigma")
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.processing.pipeline import ProcessingPipeline
    ours = ProcessingPipeline.from_yaml((DIST_DIR / "sigma" / "pipelines" / "splunk_mitre_dc.yml").read_text())
    expected = {s.id.lower() for s in implemented_strategies(model) if not (s.curated.get("sigma") or {}).get("not_expressible")}
    seen = set()
    for p in sorted(RULES.glob("det*.yml")) + sorted(RULES.glob("risk*.yml")):
        seen.add(p.name.split("_")[0])
        docs = [d for d in yaml.safe_load_all(p.read_text()) if d]
        assert docs[-1].get("correlation"), p.name
        assert all(d.get("mitre_detection_strategy") for d in docs), p.name
        out = SplunkBackend(processing_pipeline=sysmon_pipeline() + ours).convert(SigmaCollection.from_yaml(p.read_text()))
        corr = out[-1]
        assert "| multisearch" in corr or "| stats" in corr, p.name
        assert "index=" in corr, p.name
    assert seen == expected
