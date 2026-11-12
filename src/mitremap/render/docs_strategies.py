"""Render documentation for detection strategies and cross-strategy correlations."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .. import DOCS_DIR
from ..build import DCView, slug
from ..model import AttackModel
from ..strategies import StrategyView, all_strategies, risk_scope_clause, schedule_for, spl_for, strategy_macros
from .docs import dc_page_name
from .docs_analytics import page_name as an_page_name

ST_DOCS = DOCS_DIR / "strategies"
SHAPE_TEXT = {
    "sequence": "sequence: raw-event chain joined on a key → finding + risk",
    "risk_threshold": "risk rule: over the Risk data model → finding only",
    "delegated": "delegated: the analytics' own findings and risk events are the output",
}


def page_name(s: StrategyView) -> str:
    return f"{s.id}-{slug(s.title)[:60].replace('_', '-')}.md"


def _esc(t: str) -> str:
    return t.replace('"', "'").replace("[", "(").replace("]", ")").replace("|", "/").replace("{", "(").replace("}", ")")


class StrategiesDocsRenderer:
    name = "docs_strategies"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        ST_DOCS.mkdir(parents=True, exist_ok=True)
        dc_views = {v.dc.id: v for v in views}
        svs = all_strategies(m)
        keep, out = {"README.md"}, []
        for s in svs:
            if s.implemented:
                out.append(self._page(m, s, dc_views))
                keep.add(page_name(s))
        for stale in ST_DOCS.glob("*.md"):
            if stale.name not in keep:
                stale.unlink()
        out.append(self._index(m, svs))
        return out

    def _page(self, m: AttackModel, s: StrategyView, dc_views: dict[str, DCView]) -> Path:
        c, te = s.curated, s.technique
        L = [f"# {s.id} {s.title}", ""]
        if s.kind == "strategy":
            L += [f"[ATT&CK detection strategy]({s.url}) · {s.det.name} · [{te.id} {te.name}]({te.url}) · tactics: {', '.join(te.tactics)}", ""]
        else:
            L += ["Cross-strategy risk correlation (not an ATT&CK object).", ""]
        L += [f"**Shape:** {SHAPE_TEXT[s.shape]} · **Severity:** {c.get('severity')} · **Status:** {c.get('status')}", "",
              c.get("summary", "").strip(), ""]

        # diagram
        L += ["```mermaid", "flowchart LR"]
        if s.shape == "risk_threshold":
            scope = s.scope
            if scope == "all":
                L.append('  SRC["All MITRE analytics and sequences<br/>(risk events)"] --> R')
            else:
                for a in scope:
                    L.append(f'  {a}["{a}"] -- risk --> R')
            by = c.get("group_by", "risk_object")
            L.append(f'  R[("Risk data model<br/>by {by}<br/>window {c.get("window", "24h")}")] --> COND{{{{"{_esc(c.get("condition", ""))}"}}}}')
            L.append('  COND --> F["finding"]')
        else:
            for dc in c.get("data_components") or []:
                dv = dc_views.get(dc)
                L.append(f'  {dc}["{dc} {_esc(dv.dc.name) if dv else ""}"] --> J')
            L.append(f'  J{{{{"join on {_esc(c.get("join_key", "key"))}<br/>within {_esc(c.get("window", ""))}"}}}} --> F["finding + risk"]')
            for a in c.get("extends") or []:
                L.append(f'  {a}["{a} (single-leg analytic)"] -. extended by .-> J')
        L += ["```", ""]

        if s.kind == "strategy" and s.det:
            L += ["## Analytics in this strategy", "", "| Analytic | Platforms | Status | Type |", "|---|---|---|---|"]
            impl = {a.id: a for a in s.analytics}
            for a in s.det.analytic_ids:
                an = m.analytics.get(a)
                if not an:
                    continue
                v = impl.get(a)
                link = f"[{a}](../analytics/{an_page_name(v)})" if v else f"[{a}]({an.url})"
                L.append(f"| {link} | {', '.join(an.platforms)} | {'implemented' if v else 'backlog'} | {v.content_type if v else ''} |")
            L.append("")
        if (c.get("gaps") or "").strip():
            L += ["**Not covered:** " + c["gaps"].strip(), ""]

        L += ["## Tuning", "", "| Macro | Default | Purpose |", "|---|---|---|"]
        for stanza, definition, desc in strategy_macros(s):
            L.append(f"| `{stanza}` | `{definition.replace('|', '¦')}` | {desc.replace('|', '/')} |")
        for t in c.get("tuning") or []:
            if t.get("bind") == "lookup":
                L.append(f"| lookup `{t['name']}` | | {t.get('element', '')}: {t.get('note', '')} |")
        L.append("")

        sch = schedule_for(s)
        L += ["## Splunk", "", f"Stanza `[{s.stanza}]` in `DA-ESS-mitre-attack-detections`. Schedule `{sch['cron']}`, window `{sch['earliest']}` to `{sch['latest']}`. Ships disabled.", ""]
        if s.shape == "risk_threshold":
            L += [f"Generated from the parameters below; edit the YAML, not the search. Scope: `{risk_scope_clause(s)}`.", "",
                  "| Parameter | Value |", "|---|---|",
                  f"| group_by | {c.get('group_by', 'risk_object')} |", f"| window | {c.get('window', '24h')} |", f"| condition | `{c.get('condition', '')}` |", ""]
        L += ["```spl", spl_for(s).strip(), "```", ""]
        if s.shape == "sequence":
            r = c.get("risk") or {}
            L += ["Risk: " + ", ".join(f"`{o['field']}` ({o.get('type')}, {o.get('score')})" for o in r.get("objects") or []) + f". Message: {r.get('message', '')}", ""]

        sg = c.get("sigma") or {}
        L += ["## Sigma", ""]
        if sg.get("not_expressible"):
            L += [f"Not expressed in Sigma: {sg['not_expressible']}", ""]
        else:
            L += [f"Rule file: `dist/sigma/rules/{s.id.lower()}_{slug(s.title)[:60]}.yml` (base rules plus a `{sg['correlation'].get('type')}` correlation).", ""]
            if sg.get("note"):
                L += [sg["note"].strip(), ""]
        if c.get("false_positives"):
            L += ["## Known false positives", ""] + [f"- {f}" for f in c["false_positives"]] + [""]
        p = ST_DOCS / page_name(s)
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    def _index(self, m: AttackModel, svs: list[StrategyView]) -> Path:
        strategies = [s for s in svs if s.kind == "strategy"]
        corr = [s for s in svs if s.kind == "correlation" and s.implemented]
        shapes = Counter((s.shape if s.implemented else "delegated") for s in strategies)
        L = [f"# Detection strategies (ATT&CK v{m.version})", "",
             "In ATT&CK v18+ a detection strategy's analytics are per-platform variants; the multi-event chain is described inside each analytic. "
             "So this layer correlates in two places: **sequences** implement, for one strategy, the chain its analytic left out, joining raw events on a key; "
             "**risk rules** read the Risk data model, either scoped to one strategy (for example one source hitting many hosts) or across strategies. "
             "A strategy with implemented analytics and no file of its own is **delegated**: its analytics' findings and risk events are its output.", "",
             "```mermaid", "flowchart LR",
             '  DC["Data components<br/>(eventtypes)"] --> AN["Analytics<br/>TTP / Anomaly / Hunting"]',
             '  AN -- "risk events" --> RISK[("Risk data model")]',
             '  AN -- "TTP findings" --> F["Findings"]',
             '  DC --> SEQ["Strategy sequences<br/>(raw-event chains)"]',
             '  SEQ -- "findings + risk" --> F',
             '  SEQ -- "risk events" --> RISK',
             '  RISK --> RBS["Strategy risk rules<br/>(one DET)"]',
             '  RISK --> RBC["Cross-strategy correlations"]',
             '  RBS --> F', '  RBC --> F', "```", "",
             "```mermaid", "pie showData", "    title Strategies with implemented analytics, by shape"]
        for k in ("sequence", "risk_threshold", "delegated"):
            L.append(f'    "{k}" : {shapes[k]}')
        L += ["```", "", "## Cross-strategy correlations", "", "| Id | Correlation | Scope | Group by | Window | Condition | Severity |", "|---|---|---|---|---|---|---|"]
        for s in corr:
            c = s.curated
            scope = "all MITRE content" if s.scope == "all" else ", ".join(s.scope)
            L.append(f"| {s.id} | [{s.title}]({page_name(s)}) | {scope} | {c.get('group_by', 'risk_object')} | {c.get('window', '24h')} | `{c.get('condition', '')}` | {c.get('severity')} |")
        L += ["", "## Strategies", "", "| Strategy | Technique | Tactics | Shape | Implemented analytics | Detection |", "|---|---|---|---|---|---|"]
        for s in sorted(strategies, key=lambda s: (s.shape == "delegated" or not s.implemented, -(s.technique.usage_score if s.technique else 0))):
            te = s.technique
            shape = s.shape if s.implemented else "delegated"
            det = f"[{s.title}]({page_name(s)})" if s.implemented else ""
            ans = ", ".join(f"[{a.id}](../analytics/{an_page_name(a)}) ({a.content_type})" for a in s.analytics)
            L.append(f"| [{s.id}]({s.url}) {s.det.name if s.det else ''} | {te.id if te else ''} {te.name if te else ''} | {', '.join(te.tactics) if te else ''} | {shape} | {ans} | {det} |")
        L += ["", "## Authoring", "", "```bash",
              "python -m mitremap new-strategy DET0363   # scaffold content/detection_strategies/DET0363.yml",
              "# curated: shape sequence (hand-written spl joining raw events) or risk_threshold (scope, group_by, window, condition)",
              "make build && make test", "```", "",
              "Cross-strategy correlations live in `content/correlations/RISKxxxx.yml` with the same risk_threshold fields; `scope: all` covers every MITRE analytic and sequence.", ""]
        p = ST_DOCS / "README.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p
