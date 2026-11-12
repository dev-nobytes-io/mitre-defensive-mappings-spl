"""Checks on the analytics layer (content/analytics -> detections app + Sigma rules)."""
import json
import re

import pytest
import yaml

from mitremap import DIST_DIR
from mitremap.analytics import (CONTENT_TYPES, all_views, coverage, flatten_spl, implemented_views, lint_spl, macros_used,
                                suggest_content_type, suggest_tuning, validate_analytics)

DA = DIST_DIR / "splunk" / "DA-ESS-mitre-attack-detections"
RULES = DIST_DIR / "sigma" / "rules"


def test_lint_catches_common_mistakes():
    assert lint_spl('search a="b" | stats count') == []
    assert "unbalanced parentheses" in lint_spl("search (a=b | stats count")
    assert "unbalanced double quotes" in lint_spl('search a="b | stats count')
    assert "unbalanced backticks" in lint_spl("`macro | stats count")
    assert any("index=" in e for e in lint_spl("index=main foo"))
    assert lint_spl('eval x=replace(Image, "^.*\\\\\\\\", "")') == []


def test_macros_used_counts_arguments():
    assert macros_used("`a` | `b(x)` | `c(x, y)`") == [("a", 0), ("b", 1), ("c", 2)]


def test_coverage_and_suggestions(model):
    views = all_views(model)
    assert {v.coverage for v in views} <= {"live", "ready", "gap", "no-log-source"}
    assert all(v.suggested_content_type in CONTENT_TYPES for v in views)
    an = model.analytics["AN1030"]
    assert coverage(an) == "live"
    assert {t["element"] for t in suggest_tuning(an)} == {me["field"] for me in an.mutable_elements}
    assert suggest_content_type(an, model.technique_for_analytic(an)) in CONTENT_TYPES


def test_validate_analytics_clean(model):
    assert validate_analytics(model) == []


def test_every_implemented_analytic_is_rendered(model):
    text = (DA / "default" / "savedsearches.conf").read_text()
    macros = (DA / "default" / "macros.conf").read_text()
    for v in implemented_views(model):
        assert f"[{v.stanza}]" in text, v.id
        assert f"[{v.filter_macro}]" in macros, v.id
        assert flatten_spl(v.curated["spl"]) in text, v.id


def test_content_type_drives_actions(model):
    text = (DA / "default" / "savedsearches.conf").read_text()
    stanzas = {m.group(1): m.group(2) for m in re.finditer(r"^\[(.+?)\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)}
    for v in implemented_views(model):
        body = stanzas[v.stanza]
        assert "disabled = true" in body
        ann = json.loads(re.search(r"^action\.correlationsearch\.annotations = (.+)$", body, re.M).group(1))
        assert ann["mitre_an"] == [v.id] and ann["mitre_det"] == [v.det.id] and ann["mitre_attack"] == [v.technique.id]
        has_notable, has_risk = "action.notable = 1" in body, "action.risk = 1" in body
        if v.content_type == "ttp":
            assert has_notable and has_risk, v.id
        elif v.content_type == "anomaly":
            assert has_risk and not has_notable, v.id
        else:
            assert not has_risk and not has_notable, v.id
        if has_risk:
            json.loads(re.search(r"^action\.risk\.param\._risk = (.+)$", body, re.M).group(1))


def test_sigma_rules_parse_and_convert(model):
    pytest.importorskip("sigma")
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.processing.pipeline import ProcessingPipeline
    ours = ProcessingPipeline.from_yaml((DIST_DIR / "sigma" / "pipelines" / "splunk_mitre_dc.yml").read_text())
    expected = {v.id.lower() for v in implemented_views(model) if (v.curated.get("sigma") or {}) and not v.curated["sigma"].get("not_expressible")}
    seen = set()
    for p in sorted(RULES.glob("an*.yml")):
        seen.add(p.name.split("_")[0])
        docs = [d for d in yaml.safe_load_all(p.read_text()) if d]
        assert all(d.get("mitre_analytic") for d in docs), p.name
        coll = SigmaCollection.from_yaml(p.read_text())
        assert not coll.errors, (p.name, coll.errors)
        backend = SplunkBackend(processing_pipeline=sysmon_pipeline() + ours)
        out = backend.convert(coll)
        assert out and all(isinstance(q, str) and q.strip() and q.strip() != "*" for q in out), p.name
        for q in out:
            assert "index=" in q or "eventtype" in q, f"{p.name}: converted query is not scoped to a feed or data component: {q[:120]}"
            assert 'source="WinEventLog:' not in q, f"{p.name}: classic WinEventLog source contradicts XML collection"
            assert "EventID=" not in q and "EventID IN" not in q, f"{p.name}: Splunk_TA_windows field is EventCode, not EventID"
    assert seen == expected
