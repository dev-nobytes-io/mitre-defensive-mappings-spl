"""Checks on committed, rendered output (run `make build` first)."""
import configparser
import re
from pathlib import Path

import pytest

from mitremap import DIST_DIR, DOCS_DIR
from mitremap.validate import validate

APP = DIST_DIR / "splunk" / "TA-mitre-attack-datacomponents"


def _conf(p: Path):
    cp = configparser.RawConfigParser(strict=False, allow_no_value=True, interpolation=None, delimiters=("=",), comment_prefixes=("#",))
    cp.optionxform = str
    cp.read(p, encoding="utf-8")
    return cp


def test_validate_clean(model):
    assert validate(model) == []


def test_promised_feeds_have_eventtypes():
    names = set(_conf(APP / "default" / "eventtypes.conf").sections())
    for feed in ["sysmon", "wineventlog", "powershell_logging", "corelight", "palo_alto", "trellix_epo", "solidcore", "auditd", "esxi_syslog", "kubernetes_audit", "azure_entra", "azure_activity", "container_runtime", "netdev_syslog"]:
        assert any(n.endswith(f"__{feed}") for n in names), feed


def test_tuning_lookups_have_headers_and_seed_rows():
    for name in ["mitre_allowlist_processes", "mitre_allowlist_users", "mitre_allowlist_hosts", "mitre_allowlist_domains", "mitre_allowlist_ips", "mitre_asset_roles", "mitre_account_roles", "mitre_lolbins", "mitre_sensitive_paths", "mitre_internal_networks"]:
        lines = (APP / "lookups" / f"{name}.csv").read_text().splitlines()
        assert len(lines) >= 2, name
        assert "," in lines[0]


def test_macros_reference_only_known_eventtypes():
    names = set(_conf(APP / "default" / "eventtypes.conf").sections())
    macros = _conf(APP / "default" / "macros.conf")
    for sec in macros.sections():
        for ref in re.findall(r"eventtype=(\S+)", macros.get(sec, "definition")):
            assert ref in names


def test_mermaid_blocks_balanced():
    for p in DOCS_DIR.rglob("*.md"):
        text = p.read_text(encoding="utf-8")
        assert text.count("```mermaid") <= text.count("```") // 2, p


def test_sigma_pipeline_loads_and_converts():
    sigma = pytest.importorskip("sigma")
    from sigma.processing.pipeline import ProcessingPipeline
    pipe = ProcessingPipeline.from_yaml((DIST_DIR / "sigma" / "pipelines" / "splunk_mitre_dc.yml").read_text())
    assert pipe.items
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.collection import SigmaCollection
    except ImportError:
        pytest.skip("pysigma-backend-splunk not installed")
    rule = SigmaCollection.from_yaml("""
title: t
status: test
logsource: {product: windows, category: process_creation}
detection:
  sel: {Image|endswith: '\\\\certutil.exe'}
  condition: sel
""")
    out = SplunkBackend(processing_pipeline=pipe).convert(rule)[0]
    assert "mitre_dc0032_process_creation__sysmon" in out


def test_log_source_index(model):
    """README block and docs/by-log-source.md list every feed, with working anchors."""
    from mitremap import ROOT, config
    readme = (ROOT / "README.md").read_text()
    assert "<!-- BEGIN mitremap:log-sources -->" in readme and "<!-- END mitremap:log-sources -->" in readme
    block = readme.split("<!-- BEGIN mitremap:log-sources -->")[1].split("<!-- END mitremap:log-sources -->")[0]
    page = (DOCS_DIR / "by-log-source.md").read_text()
    headings = set(re.findall(r"^### (\S+)$", page, re.M))
    for name, f in config.stack().items():
        if f.get("virtual"):
            continue
        assert name in headings, name
        if f.get("render") is not False:
            assert f"docs/by-log-source.md#{name})" in block, name
    for target in re.findall(r"\]\(((?:analytics|data-components|strategies)/[^)#]+)\)", page):
        assert (DOCS_DIR / target).exists(), target
