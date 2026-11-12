"""Consistency checks across config, content and rendered output."""
from __future__ import annotations

import configparser
import csv
import re
from pathlib import Path

import yaml

from . import CONTENT_DIR, DIST_DIR, DOCS_DIR, config
from .build import build_all, feed_in_scope
from .logsources import resolve
from .model import AttackModel
from .render.splunk import APP


def _conf(path: Path) -> configparser.RawConfigParser:
    cp = configparser.RawConfigParser(strict=False, allow_no_value=True, interpolation=None, delimiters=("=",), comment_prefixes=("#",))
    cp.optionxform = str  # keep case
    cp.read(path, encoding="utf-8")
    return cp


def validate(m: AttackModel) -> list[str]:
    errors: list[str] = []
    views = build_all(m)
    stack = config.stack()

    # ---- every ATT&CK log-source name resolves
    names = {r.name for dc in m.data_components.values() for r in dc.log_sources} | {r.name for an in m.analytics.values() for r in an.log_source_refs}
    for n in sorted(names):
        try:
            rs = resolve(n)
        except LookupError as e:
            errors.append(str(e)); continue
        for p in rs.providers:
            if p.feed not in stack:
                errors.append(f"log source {n!r} -> unknown feed {p.feed!r}")

    # ---- config cross references
    for dc_name in config.cim():
        if dc_name not in {d.name for d in m.data_components.values()}:
            errors.append(f"cim.yml names unknown data component {dc_name!r}")
    for dc_name, spec in (config.load("dc_defaults").get("defaults") or {}).items():
        if dc_name not in {d.name for d in m.data_components.values()}:
            errors.append(f"dc_defaults.yml names unknown data component {dc_name!r}")
        for feed in (spec or {}):
            if feed == "exclude":
                for f in spec["exclude"] or []:
                    if f not in stack:
                        errors.append(f"dc_defaults.yml {dc_name!r} excludes unknown feed {f!r}")
            elif feed not in stack:
                errors.append(f"dc_defaults.yml {dc_name!r} references unknown feed {feed!r}")
    for cat, per in config.sigma()["categories"].items():
        for product, names_ in per.items():
            for n in names_:
                if n not in {d.name for d in m.data_components.values()}:
                    errors.append(f"sigma.yml category {cat}/{product} names unknown data component {n!r}")
    for feed in config.sigma()["products"]:
        if feed not in stack:
            errors.append(f"sigma.yml products names unknown feed {feed!r}")

    # ---- content files
    dc_dir = CONTENT_DIR / "data_components"
    for dc in m.data_components.values():
        p = dc_dir / f"{dc.id}.yml"
        if not p.exists():
            errors.append(f"missing content file {p}"); continue
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if doc.get("id") != dc.id:
            errors.append(f"{p}: id mismatch")
        cur = doc.get("curated") or {}
        for feed in (cur.get("overrides") or {}).get("feeds") or {}:
            if feed not in stack:
                errors.append(f"{p}: curated override for unknown feed {feed!r}")
        for feed in (cur.get("overrides") or {}).get("exclude_feeds") or []:
            if feed not in stack:
                errors.append(f"{p}: curated exclude of unknown feed {feed!r}")

    # ---- rendered splunk app
    app = DIST_DIR / "splunk" / APP
    et = _conf(app / "default" / "eventtypes.conf")
    tags = _conf(app / "default" / "tags.conf")
    macros = _conf(app / "default" / "macros.conf")
    transforms = _conf(app / "default" / "transforms.conf")
    et_names = set(et.sections())
    for v in views:
        if not v.in_scope:
            if v.eventtype in et_names:
                errors.append(f"{v.dc.id} is out of scope but has eventtypes")
            continue
        if v.eventtype not in et_names:
            errors.append(f"missing umbrella eventtype {v.eventtype}")
        for f in v.feeds:
            if f.in_scope and f.eventtype not in et_names:
                errors.append(f"missing eventtype {f.eventtype}")
            if not f.in_scope and f.eventtype in et_names:
                errors.append(f"out-of-scope feed eventtype rendered: {f.eventtype}")
    for name in et.sections():
        search = et.get(name, "search", fallback="")
        if "`" in search or "|" in search:
            errors.append(f"eventtype {name} contains a macro or pipe: {search}")
        for ref in re.findall(r"eventtype=(\S+)", search):
            if ref not in et_names:
                errors.append(f"eventtype {name} references unknown eventtype {ref}")
        if len(name) > 255:
            errors.append(f"eventtype name too long: {name}")
    for sec in tags.sections():
        mm = re.match(r"eventtype=(.+)", sec)
        if not mm or mm.group(1) not in et_names:
            errors.append(f"tags.conf stanza for unknown eventtype: {sec}")
    for sec in macros.sections():
        d = macros.get(sec, "definition", fallback=None)
        if d is None:
            errors.append(f"macro {sec} has no definition")
        for ref in re.findall(r"eventtype=(\S+)", d or ""):
            if ref not in et_names:
                errors.append(f"macro {sec} references unknown eventtype {ref}")
    for sec in transforms.sections():
        fn = transforms.get(sec, "filename", fallback=None)
        if not fn or not (app / "lookups" / fn).exists():
            errors.append(f"transforms.conf {sec}: lookup file missing {fn}")
        else:
            with (app / "lookups" / fn).open(encoding="utf-8") as fh:
                rows = list(csv.reader(fh))
            if len(rows) < 2:
                errors.append(f"lookup {fn} has no rows")
            mt = transforms.get(sec, "match_type", fallback="")
            for field in re.findall(r"\((\w+)\)", mt):
                if field not in rows[0]:
                    errors.append(f"lookup {fn}: match_type field {field} not in header")

    # ---- feeds we promised eventtypes for
    for feed in ["sysmon", "wineventlog", "corelight", "palo_alto", "auditd", "esxi_syslog", "kubernetes_audit", "azure_entra"]:
        if not any(n.endswith(f"__{feed}") for n in et_names):
            errors.append(f"no eventtype rendered for feed {feed}")

    # ---- sigma pipeline loads with pySigma if available
    try:
        from sigma.processing.pipeline import ProcessingPipeline  # type: ignore
        ProcessingPipeline.from_yaml((DIST_DIR / "sigma" / "pipelines" / "splunk_mitre_dc.yml").read_text(encoding="utf-8"))
    except ImportError:
        pass
    except Exception as e:  # pragma: no cover
        errors.append(f"sigma pipeline failed to load: {e}")

    # ---- analytics
    from .analytics import validate_analytics
    errors += validate_analytics(m)
    from .strategies import validate_strategies
    errors += validate_strategies(m)
    errors += _validate_health(views)

    # ---- docs exist
    for v in views:
        from .render.docs import dc_page_name
        if not (DOCS_DIR / "data-components" / dc_page_name(v)).exists():
            errors.append(f"missing doc page for {v.dc.id}")
    return errors


def _validate_health(views) -> list[str]:
    from .analytics import EXTERNAL_MACROS, _conf_sections, _macro_index, lint_spl, lookups_used, macros_used
    from .health import expected_telemetry, rules
    errs = []
    ta = DIST_DIR / "splunk" / APP / "default"
    da = DIST_DIR / "splunk" / "DA-ESS-mitre-attack-detections" / "default"
    macros = _macro_index(_conf_sections(ta / "macros.conf") | _conf_sections(da / "macros.conf"))
    lookups = _conf_sections(ta / "transforms.conf") | _conf_sections(da / "transforms.conf")
    stanzas = _conf_sections(da / "savedsearches.conf")
    for r in rules():
        for e in lint_spl(r.spl):
            errs.append(f"{r.id}: spl: {e}")
        for name, n in macros_used(r.spl):
            if name not in macros and name not in EXTERNAL_MACROS:
                errs.append(f"{r.id}: unknown macro `{name}`")
        for lk in lookups_used(r.spl):
            if lk not in lookups:
                errs.append(f"{r.id}: unknown lookup {lk}")
        if f"MITRE - {r.id} - {r.title} - Rule" not in stanzas:
            errs.append(f"{r.id}: stanza missing from savedsearches.conf")
    rows = expected_telemetry(views)
    for feed, f in config.stack().items():
        if f.get("have") and not f.get("hunt_only") and not f.get("virtual") and f.get("render") is not False:
            if not any(r.feed == feed for r in rows):
                errs.append(f"expected telemetry has no row for ticked feed {feed}")
    return errs
