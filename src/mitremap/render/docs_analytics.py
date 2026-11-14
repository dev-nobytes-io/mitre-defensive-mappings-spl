"""Render documentation for the analytics layer: index, one page per implemented analytic, backlog."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from .. import DOCS_DIR, config
from ..analytics import AnalyticView, all_views, flatten_spl
from ..build import DCView, slug
from ..model import AttackModel
from .detections import default_schedule, risk_param, schedule, tunable_macros
from .docs import dc_page_name

AN_DOCS = DOCS_DIR / "analytics"
ACTION = {"ttp": "finding (notable) + risk", "anomaly": "risk event only", "hunting": "no action (hunt / dashboard)"}


def page_name(v: AnalyticView) -> str:
    return f"{v.id}-{slug(v.title)[:60].replace('_', '-')}.md"


def _esc(s: str) -> str:
    return s.replace('"', "'").replace("[", "(").replace("]", ")").replace("|", "/").replace("{", "(").replace("}", ")")


class AnalyticsDocsRenderer:
    name = "docs_analytics"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        AN_DOCS.mkdir(parents=True, exist_ok=True)
        dc_views = {v.dc.id: v for v in views}
        avs = all_views(m)
        impl = [v for v in avs if v.implemented]
        keep = {"README.md", "backlog.md"}
        out = []
        for v in impl:
            out.append(self._page(m, v, dc_views))
            keep.add(page_name(v))
        for stale in AN_DOCS.glob("*.md"):
            if stale.name not in keep:
                stale.unlink()
        out.append(self._index(m, avs, impl))
        out.append(self._backlog(m, avs))
        return out

    # ------------------------------------------------------------------ page
    def _page(self, m: AttackModel, v: AnalyticView, dc_views: dict[str, DCView]) -> Path:
        c, an, te, det = v.curated, v.an, v.technique, v.det
        ctype = v.content_type
        L = [f"# {v.id} {v.title}", "",
             f"[ATT&CK analytic]({an.url}) · {det.id if det else ''} {det.name if det else ''} · "
             f"[{te.id} {te.name}]({te.url}) · tactics: {', '.join(te.tactics)} · platforms: {', '.join(an.platforms)}", "",
             f"**Content type:** {ctype} → {ACTION[ctype]} · **Severity:** {c.get('severity')} · **Status:** {c.get('status')} · "
             f"**Technique prevalence score:** {v.priority}", "",
             c.get("summary", "").strip(), ""]

        # diagram
        L += ["```mermaid", "flowchart LR"]
        feeds = c.get("feeds") or []
        for dc in c.get("data_components") or []:
            dv = dc_views.get(dc)
            L.append(f'  {dc}["{dc} {_esc(dv.dc.name) if dv else ""}"] --> AN')
            for f in (dv.feeds if dv else []):
                if f.feed in feeds:
                    L.append(f'  F_{f.feed}(["{_esc(config.feed(f.feed)["label"].split(" (")[0])}"]) --> {dc}')
        for b in c.get("baselines") or []:
            L.append(f'  BL[("{_esc(b["lookup"])}")] --> AN')
        baseline_lookups = {b["lookup"] for b in c.get("baselines") or []}
        for t in c.get("tuning") or []:
            if t.get("bind") == "lookup" and t["name"] not in baseline_lookups:
                L.append(f'  LK_{slug(t["name"])}[("{_esc(t["name"])}")] -.-> AN')
        L.append(f'  AN["{v.id}<br/>{_esc(v.title)}"] --> ACT{{{{"{ACTION[ctype]}"}}}}')
        if det and te:
            L.append(f'  AN -.-> DET["{det.id}"] -.-> T["{te.id} {_esc(te.name)}"]')
        L += ["  classDef an fill:#dbeafe,stroke:#1d4ed8,color:#1b1b1b", "  class AN an", "```", ""]

        # ATT&CK text and gaps
        L += ["## What ATT&CK asks for", "", "> " + an.description.replace("\n", " "), ""]
        L += ["## What this implementation detects", "", c.get("summary", "").strip(), ""]
        if (c.get("gaps") or "").strip():
            L += ["**Not covered:** " + c["gaps"].strip(), ""]

        # tuning
        L += ["## Tuning", "", "ATT&CK mutable elements and where each is bound. Edit macros in `local/macros.conf` and lookups in place; do not edit the search.", "",
              "| Mutable element | ATT&CK guidance | Bound to | Default |", "|---|---|---|---|"]
        bound = {t.get("element"): t for t in c.get("tuning") or []}
        for me in an.mutable_elements:
            t = bound.pop(me.get("field"), None)
            if t:
                kind = {"macro": "macro", "lookup": "lookup", "filter": "filter macro"}[t["bind"]]
                L.append(f"| {me.get('field')} | {me.get('description', '').replace('|', '/')} | {kind} `{t['name']}`{(' — ' + t['note']) if t.get('note') else ''} | {('`' + str(t['default']).replace('|', '¦') + '`') if t.get('default') not in (None, '') else ''} |")
            else:
                L.append(f"| {me.get('field')} | {me.get('description', '').replace('|', '/')} | filter macro `{v.filter_macro}` (not bound separately) | `search *` |")
        for el, t in bound.items():
            L.append(f"| {el} *(implementation)* | {t.get('note', '')} | {t['bind']} `{t['name']}` | {('`' + str(t['default']).replace('|', '¦') + '`') if t.get('default') not in (None, '') else ''} |")
        L.append("")

        # SPL
        sch = schedule(v)
        L += ["## Splunk", "", f"Stanza `[{v.stanza}]` in `DA-ESS-mitre-attack-detections`. Schedule `{sch['cron']}`, window `{sch['earliest']}` to `{sch['latest']}`. Ships disabled.", "",
              "```spl", (c.get("spl") or "").strip(), "```", ""]
        rp = risk_param(v)
        if ctype != "hunting" and rp:
            L += ["Risk: " + ", ".join(f"`{r['risk_object_field']}` ({r['risk_object_type']}, {r['risk_score']})" for r in rp if "risk_object_field" in r)
                  + (". Threat objects: " + ", ".join(f"`{r['threat_object_field']}`" for r in rp if "threat_object_field" in r) if any("threat_object_field" in r for r in rp) else "")
                  + f". Message: {(c.get('risk') or {}).get('message', '')}", ""]
        th = c.get("throttle") or {}
        if th.get("fields"):
            L += [f"Throttle: {', '.join(th['fields'])} for {th.get('period', '3600s')}.", ""]
        for b in c.get("baselines") or []:
            L += [f"### Baseline: {b['name']}", "", f"{b.get('description', '').strip()} Writes `{b['lookup']}`; schedule `{b.get('cron', '17 3 * * *')}` over `{b.get('earliest', '-30d@d')}`. Enable and run it before the detection.", "",
                  "```spl", b["search"].strip(), "```", ""]
        dcs = c.get("data_components") or []
        L += ["Data components: " + ", ".join(f"[{dc}](../data-components/{dc_page_name(dc_views[dc])})" for dc in dcs if dc in dc_views) + ".", ""]

        # Sigma
        sg = c.get("sigma") or {}
        L += ["## Sigma", ""]
        if sg.get("not_expressible"):
            L += [f"Not expressed in Sigma: {sg['not_expressible']}", ""]
        else:
            L += [f"Rule file: `dist/sigma/rules/{v.id.lower()}_{slug(v.title)[:60]}.yml`"
                  + (" (base rule plus a correlation rule)." if sg.get("correlation") else "."), ""]
            if sg.get("note"):
                L += [sg["note"].strip(), ""]
        fps = c.get("false_positives") or []
        if fps:
            L += ["## Known false positives", ""] + [f"- {f}" for f in fps] + [""]
        p = AN_DOCS / page_name(v)
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ index
    def _index(self, m: AttackModel, avs: list[AnalyticView], impl: list[AnalyticView]) -> Path:
        ct = Counter(v.content_type for v in impl)
        mapped = [v for v in avs if v.coverage == "mapped"]
        tac = Counter(t for v in impl if v.technique for t in v.technique.tactics)
        L = [f"# Analytics (ATT&CK v{m.version})", "",
             f"{len(impl)} of {len(m.analytics)} ATT&CK analytics are implemented as ES detections and Sigma rules; "
             f"{len(mapped)} map entirely to feeds on in-scope platforms. The rest are in the [backlog](backlog.md), ranked by technique prevalence.", "",
             "```mermaid", "pie showData", "    title Implemented analytics by content type",
             f'    "TTP (finding + risk)" : {ct["ttp"]}', f'    "Anomaly (risk only)" : {ct["anomaly"]}', f'    "Hunting (no action)" : {ct["hunting"]}', "```", ""]
        if tac:
            order = [t for t, _ in tac.most_common()]
            L += ["```mermaid", "xychart-beta", '    title "Implemented analytics by tactic"',
                  "    x-axis [" + ", ".join(f'"{t}"' for t in order) + "]", '    y-axis "analytics"',
                  "    bar [" + ", ".join(str(tac[t]) for t in order) + "]", "```", ""]
        L += ["| Analytic | Detection | Type | Severity | Technique | Tactics | Data components | Feeds |", "|---|---|---|---|---|---|---|---|"]
        for v in sorted(impl, key=lambda v: (-v.priority, v.id)):
            te = v.technique
            L.append(f"| {v.id} | [{v.title}]({page_name(v)}) | {v.content_type} | {v.curated.get('severity')} | {te.id if te else ''} {te.name if te else ''} | "
                     f"{', '.join(te.tactics) if te else ''} | {', '.join(v.curated.get('data_components') or [])} | {', '.join(v.curated.get('feeds') or [])} |")
        L += ["", "## Authoring", "",
              "```bash", "python -m mitremap new-analytic AN0123   # scaffold content/analytics/AN0123.yml with ATT&CK text and suggestions",
              "# edit the curated block: status, title, content_type, spl, risk, tuning, sigma", "make build && make test", "```", "",
              "Rules enforced by `mitremap validate`: the SPL uses a `mitre_dcXXXX` macro and the analytic's own `mitre_anXXXX_filter`, has no literal `index=`, "
              "references only macros and lookups that exist, and every risk field and message token appears in the search. Tests convert every Sigma rule through the data-component pipeline.", ""]
        p = AN_DOCS / "README.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ backlog
    def _backlog(self, m: AttackModel, avs: list[AnalyticView]) -> Path:
        from .. import config
        todo = sorted([v for v in avs if not v.implemented and v.coverage == "mapped"], key=lambda v: (-v.priority, v.id))
        scope = config.platforms()["in_scope"]
        per_plat: dict[str, list] = {p: [v for v in todo if p in v.an.platforms] for p in scope}
        top = 75
        L = [f"# Analytic backlog (ATT&CK v{m.version})", "",
             "Unimplemented analytics whose log sources all map to feeds on in-scope platforms, per platform, ranked by technique prevalence "
             "(2 × groups + 2 × campaigns + software using the technique). The suggested content type is a heuristic starting point. "
             "Whether an analytic is runnable at your site depends on the feeds you collect; see the [log source checklist](../checklist.md).", "",
             f"Mapped and unimplemented: **{len(todo)}**. Showing the top {top} per platform.", "",
             "| Platform | Mapped and unimplemented |", "|---|---|"]
        L += [f"| [{p}](#{p.lower().replace(' ', '-')}) | {len(vs)} |" for p, vs in per_plat.items()]
        L.append("")
        for p, vs in per_plat.items():
            L += [f"## {p}", "",
                  "| # | Analytic | Technique | Tactics | Score | Suggested type | Data components |", "|---|---|---|---|---|---|---|"]
            for i, v in enumerate(vs[:top], 1):
                te = v.technique
                dcs = sorted({r.dc_id for r in v.an.log_source_refs if r.dc_id})
                L.append(f"| {i} | [{v.id}]({v.an.url}) | {te.id if te else ''} {te.name if te else ''} | {', '.join(te.tactics) if te else ''} | {v.priority} | {v.suggested_content_type} | {', '.join(dcs)} |")
            if len(vs) > top:
                L.append(f"| … | {len(vs) - top} more | | | | | |")
            L.append("")
        p = AN_DOCS / "backlog.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p
