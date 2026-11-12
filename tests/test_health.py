"""Telemetry health: expected-telemetry lookup and the two health detections."""
import csv
import json
import re

from mitremap import DIST_DIR
from mitremap.build import build_all
from mitremap.health import expected_telemetry, host_scope, index_scope, rules

TA = DIST_DIR / "splunk" / "TA-mitre-attack-datacomponents"
DA = DIST_DIR / "splunk" / "DA-ESS-mitre-attack-detections"


def test_expected_telemetry_covers_windows_on_source(model):
    rows = expected_telemetry(build_all(model))
    sysmon = [r for r in rows if r.feed == "sysmon"]
    assert sysmon and all(r.field == "source" for r in sysmon)
    assert any(r.value == "XmlWinEventLog:Security" and r.field == "source" for r in rows if r.feed == "wineventlog")
    assert all("*" not in r.value for r in rows)
    assert not any(r.feed == "wireshark" for r in rows), "hunt-only feeds are not health-checked"


def test_lookup_matches_generator(model):
    with (TA / "lookups" / "mitre_expected_telemetry.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(expected_telemetry(build_all(model)))
    assert {"feed", "have", "index", "field", "value", "data_components", "eventtypes"} <= set(rows[0])


def test_scopes():
    assert index_scope().startswith("index IN (") and "sysmon" in index_scope()
    hs = host_scope()
    assert 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"' in hs and 'source="XmlWinEventLog:Security"' in hs


def test_health_stanzas_rendered():
    text = (DA / "default" / "savedsearches.conf").read_text()
    for r in rules():
        m = re.search(rf"^\[MITRE - {r.id} - .*?\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
        assert m, r.id
        body = m.group(1)
        assert "disabled = true" in body and "action.notable = 1" in body
        assert ("action.risk = 1" in body) == bool(r.risk)
        json.loads(re.search(r"^action\.correlationsearch\.annotations = (.+)$", body, re.M).group(1))


def test_asset_map_support_search():
    from mitremap.health import support_searches
    text = (DA / "default" / "savedsearches.conf").read_text()
    transforms = (DA / "default" / "transforms.conf").read_text()
    for sp in support_searches():
        m = re.search(rf"^\[MITRE - {sp.id} - .*?\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
        assert m and "action.notable" not in m.group(1) and "action.risk" not in m.group(1)
        assert f"[{sp.lookup}]" in transforms
        header = (DA / "lookups" / f"{sp.lookup}.csv").read_text().splitlines()[0].split(",")
        assert header == sp.fields
        assert {"nt_host", "dns", "ip"} <= set(header), "ES asset lookups key on these fields"
