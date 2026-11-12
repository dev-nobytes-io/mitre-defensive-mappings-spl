"""Render markdown documentation with mermaid diagrams."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from .. import DOCS_DIR, config
from ..build import DCView, eventtype_search, feed_in_scope, load_curated, slug
from ..logsources import resolve
from ..model import AttackModel

DC_DOCS = DOCS_DIR / "data-components"


def _mm_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def _esc(s: str) -> str:
    return s.replace('"', "'").replace("[", "(").replace("]", ")").replace("|", "/")


def _badge(f) -> str:
    if f.hunt_only:
        return "hunt-only"
    return "live" if f.have else "ready (tick in stack.yml)"


def dc_page_name(v: DCView) -> str:
    return f"{v.dc.id}-{slug(v.dc.name).replace('_', '-')}.md"


# --------------------------------------------------------------------------- analytic coverage
def analytic_status(m: AttackModel, an) -> str:
    """live: every log-source reference has a ticked feed; ready: all in scope; gap: otherwise."""
    if not an.log_source_refs:
        return "no-log-source"
    statuses = []
    for ref in an.log_source_refs:
        provs = [p for p in resolve(ref.name).providers if not p.virtual]
        if any(p.have for p in provs):
            statuses.append("live")
        elif any(feed_in_scope(p.feed) for p in provs):
            statuses.append("ready")
        else:
            statuses.append("gap")
    if all(s == "live" for s in statuses):
        return "live"
    if all(s in ("live", "ready") for s in statuses):
        return "ready"
    return "gap"


class DocsRenderer:
    name = "docs"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        DC_DOCS.mkdir(parents=True, exist_ok=True)
        out = []
        for v in views:
            out.append(self._dc_page(m, v))
        out.append(self._dc_index(m, views))
        out.append(self._coverage(m, views))
        out.append(self._gaps(m, views))
        out.append(self._checklist(m, views))
        return out

    # ------------------------------------------------------------------ per DC
    def _dc_page(self, m: AttackModel, v: DCView) -> Path:
        cur = load_curated(v.dc.id)
        in_scope = [f for f in v.feeds if f.in_scope]
        live = [f for f in in_scope if f.have]
        ready = [f for f in in_scope if not f.have]
        L: list[str] = []
        L.append(f"# {v.dc.id} {v.dc.name}")
        L.append("")
        L.append(f"[ATT&CK]({v.dc.url}) · version {v.dc.version} · modified {v.dc.modified[:10]} · ATT&CK release {m.version}")
        L.append("")
        status = "**Live**" if live else ("**Ready** (needs a feed you have not ticked)" if ready else "**Out of scope** for the current platform set")
        L.append(f"Status: {status} · umbrella eventtype `{v.eventtype}`" if v.in_scope else f"Status: {status}")
        L.append("")
        L.append("> " + v.dc.description.replace("\n", " "))
        L.append("")

        # ---- justification
        L.append("## Why this component matters")
        L.append("")
        if cur.get("justification"):
            L.append(cur["justification"].strip())
            L.append("")
        top_tactics = ", ".join(f"{t} ({n})" for t, n in v.tactics.most_common(4))
        L.append(f"ATT&CK v{m.version} has **{v.analytics} analytics** across **{len(v.detection_strategies)} detection strategies** that read this component, "
                 f"covering **{len(v.techniques)} techniques**. Tactics most dependent on it: {top_tactics or 'none'}.")
        if v.platforms:
            L.append("")
            L.append("Analytic references by platform: " + ", ".join(f"{p} {n}" for p, n in v.platforms.items()))
        L.append("")

        # ---- diagram
        L.append("## Where it comes from")
        L.append("")
        L.append("```mermaid")
        L.append("flowchart LR")
        L.append(f'  DC["{_esc(v.dc.id + " " + v.dc.name)}"]')
        shown = [s for s in v.sources if any(feed_in_scope(p.feed) for p in s.resolved.providers)][:10]
        hidden = len([s for s in v.sources if any(feed_in_scope(p.feed) for p in s.resolved.providers)]) - len(shown)
        feed_nodes = set()
        for i, s in enumerate(shown):
            sid = f"LS{i}"
            L.append(f'  DC --> {sid}["{_esc(s.canonical)}<br/>{s.refs} refs"]')
            for p in s.resolved.providers:
                if not feed_in_scope(p.feed):
                    continue
                fid = "F_" + _mm_id(p.feed)
                if fid not in feed_nodes:
                    feed_nodes.add(fid)
                    label = config.feed(p.feed)["label"].split(" (")[0]
                    L.append(f'  {fid}["{_esc(label)}"]')
                L.append(f"  {sid} --> {fid}")
        if hidden > 0:
            L.append(f'  DC --> MORE["... {hidden} more log sources"]')
        for f in in_scope:
            fid = "F_" + _mm_id(f.feed)
            if fid in feed_nodes:
                L.append(f"  {fid} --> ET_{_mm_id(f.feed)}[/\"{_esc(f.eventtype)}\"/]")
                L.append(f"  class {fid} {'live' if f.have else 'ready'}")
        L.append("  classDef live fill:#d4edda,stroke:#2e7d32,color:#1b1b1b")
        L.append("  classDef ready fill:#fff3cd,stroke:#b26a00,color:#1b1b1b")
        L.append("```")
        L.append("")

        # ---- requirements
        L.append("## Requirements")
        L.append("")
        if cur.get("requirements"):
            L.append("Component specific:")
            L.append("")
            for r in cur["requirements"]:
                L.append(f"- {r}")
            L.append("")
        L.append("Per feed (from `config/stack.yml` and `config/log_sources.yml`):")
        L.append("")
        L.append("| Feed | Status | Sourcetype or source | Constraint | Origin | TA / collector |")
        L.append("|---|---|---|---|---|---|")
        for f in in_scope:
            fd = config.feed(f.feed)
            cons = eventtype_search(f).replace(f"index={fd.get('index')} ", "", 1) if fd.get("index") else eventtype_search(f)
            cons = re.sub(r"(?:sourcetype|source)(=(?:\"[^\"]*\"|\S+)|\s+IN \([^)]*\))\s*", "", cons, count=1).strip() or "(whole feed)"
            fld = config.feed(f.feed).get("constraint_field", "sourcetype")
            L.append(f"| `{f.feed}` | {_badge(f)} | {', '.join(f'{fld}=`{s}`' for s in f.sourcetypes) or '—'} | `{cons}` | {f.origin} | {fd.get('ta', '')} |")
        L.append("")
        prereqs: list[tuple[str, str]] = []
        for f in in_scope:
            for pr in config.feed(f.feed).get("prerequisites", []) or []:
                prereqs.append((f.feed, pr))
            for s in v.sources:
                if any(p.feed == f.feed for p in s.resolved.providers):
                    for pr in s.resolved.prerequisites:
                        prereqs.append((f.feed, pr))
        if prereqs:
            L.append("Collection prerequisites:")
            L.append("")
            seen = set()
            for feed, pr in prereqs:
                if (feed, pr) in seen:
                    continue
                seen.add((feed, pr))
                L.append(f"- **{feed}**: {pr}")
            L.append("")
        broad = [f for f in in_scope if f.broad_refs]
        if broad:
            L.append("Review notes: " + "; ".join(f"`{f.feed}` has {f.broad_refs} ATT&CK reference(s) with no usable event filter (prose channel), constraint origin is *{f.origin}*" for f in broad) + ".")
            L.append("")

        # ---- splunk
        L.append("## Splunk")
        L.append("")
        if v.in_scope:
            L.append("Eventtypes (literal constraints, see `dist/splunk/TA-mitre-attack-datacomponents/default/eventtypes.conf`):")
            L.append("")
            L.append("```ini")
            for f in in_scope:
                L.append(f"[{f.eventtype}]")
                L.append(f"search = {eventtype_search(f)}")
                if f.hunt_only or not f.have:
                    L.append("disabled = 1")
                L.append("")
            L.append(f"[{v.eventtype}]")
            L.append("search = " + " OR ".join(f"eventtype={f.eventtype}" for f in in_scope))
            L.append("```")
            L.append("")
            dcid = v.dc.id.lower()
            L.append(f"Macros for analytics: `` `mitre_{dcid}` `` (umbrella), " + ", ".join(f"`` `mitre_{dcid}_{f.feed}` ``" for f in in_scope) + f", `` `mitre_{dcid}_filter` `` (site exclusions).")
            if v.cim:
                dm = f"{v.cim['datamodel']}.{v.cim.get('dataset') or ''}".rstrip(".")
                L.append(f"CIM: `{dm}` via `` `mitre_{dcid}_dm` `` / `` `mitre_{dcid}_dm_where` `` for `tstats`. CIM tags emitted for: "
                         + (", ".join(f"`{f.feed}`" for f in in_scope if f.cim_compliant) or "none (no feed is known CIM-compliant for this model)") + ".")
            else:
                L.append("CIM: no data model mapping; analytics on this component run as raw eventtype searches.")
            L.append("")
        else:
            L.append("No eventtypes rendered: none of this component's log sources belong to an in-scope platform feed. See [gaps](../gaps.md).")
            L.append("")

        # ---- sigma
        L.append("## Sigma")
        L.append("")
        sig = config.sigma()
        cats = defaultdict(list)
        for cat, per in sig["categories"].items():
            for product, names in per.items():
                if v.dc.name in names:
                    cats[product].append(cat)
        if cats:
            L.append("Generic logsource categories scoped by this component in `dist/sigma/pipelines/splunk_mitre_dc.yml`: "
                     + "; ".join(f"product `{p}`: " + ", ".join(f"`{c}`" for c in cs) for p, cs in cats.items()) + ".")
        else:
            L.append("No generic Sigma category maps to this component; rules use `product`/`service` logsources, which the pipeline maps to index and sourcetype.")
        L.append("")

        # ---- dependents
        L.append("## Dependents")
        L.append("")
        tech_rows = []
        for tid in v.techniques:
            te = m.techniques.get(tid)
            if te:
                n_an = sum(1 for an in m.analytics_for_dc(v.dc.id) if (m.technique_for_analytic(an) or te).id == tid)
                tech_rows.append((n_an, te))
        tech_rows.sort(key=lambda x: (-x[0], x[1].id))
        L.append(f"Top techniques detected through this component (of {len(tech_rows)}):")
        L.append("")
        L.append("| Technique | Name | Tactics | Analytics using this DC |")
        L.append("|---|---|---|---|")
        for n_an, te in tech_rows[:15]:
            L.append(f"| [{te.id}]({te.url}) | {te.name} | {', '.join(te.tactics)} | {n_an} |")
        if len(tech_rows) > 15:
            L.append(f"| … | {len(tech_rows) - 15} more | | |")
        L.append("")
        L.append(f"Full list: `lookups/mitre_attack_analytics.csv` filtered on `dc_ids` containing `{v.dc.id}`.")
        L.append("")
        if cur.get("notes"):
            L.append("## Notes")
            L.append("")
            for n in cur["notes"]:
                L.append(f"- {n}")
            L.append("")
        p = DC_DOCS / dc_page_name(v)
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    def _dc_index(self, m: AttackModel, views: list[DCView]) -> Path:
        L = [f"# Data components (ATT&CK v{m.version})", "",
             "One page per component: justification, requirements per feed, rendered eventtypes, Sigma mapping, dependents.", "",
             "| ID | Component | Status | Live feeds | Ready feeds | Analytics | Techniques | CIM |", "|---|---|---|---|---|---|---|---|"]
        for v in views:
            st = "live" if v.live_feeds else ("ready" if v.in_scope else "out of scope")
            L.append(f"| {v.dc.id} | [{v.dc.name}]({dc_page_name(v)}) | {st} | {', '.join(f.feed for f in v.live_feeds)} | {', '.join(f.feed for f in v.ready_feeds)} | {v.analytics} | {len(v.techniques)} | {v.cim['datamodel'] if v.cim else ''} |")
        p = DC_DOCS / "README.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    # ------------------------------------------------------------------ coverage
    def _coverage(self, m: AttackModel, views: list[DCView]) -> Path:
        live = [v for v in views if v.live_feeds]
        ready = [v for v in views if v.in_scope and not v.live_feeds]
        oos = [v for v in views if not v.in_scope]
        scope = config.platforms()["in_scope"]
        L = [f"# Coverage (ATT&CK v{m.version})", "",
             "Generated from `config/stack.yml` ticks. *Live* = at least one ticked feed provides the component; *ready* = mapped to an in-scope feed you have not ticked; *gap* = needs a source outside the current platform scope.", "",
             "## Data components", "", "```mermaid", "pie showData", '    title Data components by status',
             f'    "Live" : {len(live)}', f'    "Ready" : {len(ready)}', f'    "Out of scope" : {len(oos)}', "```", ""]
        # analytics per platform
        L += ["## Analytics by platform", "",
              "An analytic is *live* when every log source it references has a ticked feed, *ready* when all are mapped to in-scope feeds, otherwise *gap*.", ""]
        per_plat: dict[str, Counter] = defaultdict(Counter)
        for an in m.analytics.values():
            st = analytic_status(m, an)
            for p in an.platforms:
                per_plat[p][st] += 1
        plats = [p for p in scope if p in per_plat] + sorted(p for p in per_plat if p not in scope)
        L += ["```mermaid", "xychart-beta", '    title "Analytics: live vs ready vs gap"',
              "    x-axis [" + ", ".join(f'"{p}"' for p in plats) + "]", "    y-axis \"analytics\"",
              "    bar [" + ", ".join(str(per_plat[p]["live"]) for p in plats) + "]",
              "    bar [" + ", ".join(str(per_plat[p]["live"] + per_plat[p]["ready"]) for p in plats) + "]",
              "    bar [" + ", ".join(str(sum(per_plat[p].values())) for p in plats) + "]", "```", "",
              "Series: live (inner), live+ready (middle), total (outer).", "",
              "| Platform | In scope | Live | Ready | Gap | Total |", "|---|---|---|---|---|---|"]
        for p in plats:
            c = per_plat[p]
            L.append(f"| {p} | {'yes' if p in scope else 'no'} | {c['live']} | {c['ready']} | {c['gap'] + c['no-log-source']} | {sum(c.values())} |")
        L.append("")
        # per tactic
        L += ["## Detection strategies by tactic", "", "A detection strategy counts as *live* if at least one of its analytics is live.", "",
              "| Tactic | DETs | Live | Ready | Gap |", "|---|---|---|---|---|"]
        tac: dict[str, Counter] = defaultdict(Counter)
        for ds in m.detection_strategies.values():
            sts = [analytic_status(m, m.analytics[a]) for a in ds.analytic_ids if a in m.analytics]
            st = "live" if "live" in sts else ("ready" if "ready" in sts else "gap")
            te = m.techniques.get(ds.technique_id)
            for t in (te.tactics if te else ["unknown"]):
                tac[t][st] += 1
                tac[t]["total"] += 1
        for t in sorted(tac, key=lambda t: -tac[t]["total"]):
            c = tac[t]
            L.append(f"| {t} | {c['total']} | {c['live']} | {c['ready']} | {c['gap']} |")
        L.append("")
        L += ["## Components by platform", "", "Live feeds per component, for in-scope platforms.", "",
              "| Component | " + " | ".join(scope) + " |", "|---|" + "---|" * len(scope)]
        for v in views:
            if not v.in_scope:
                continue
            cells = []
            for p in scope:
                feeds = [f.feed for f in v.feeds if f.in_scope and f.have and p in config.feed(f.feed).get("platforms", [])]
                readyf = [f.feed for f in v.feeds if f.in_scope and not f.have and p in config.feed(f.feed).get("platforms", [])]
                cells.append(("✅ " + ", ".join(feeds)) if feeds else (("⏳ " + ", ".join(readyf)) if readyf else ""))
            L.append(f"| [{v.dc.id}](data-components/{dc_page_name(v)}) {v.dc.name} | " + " | ".join(cells) + " |")
        L.append("")
        p = DOCS_DIR / "coverage.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ gaps
    def _gaps(self, m: AttackModel, views: list[DCView]) -> Path:
        feeds = config.stack()
        unlock_dc: dict[str, set] = defaultdict(set)
        unlock_an: dict[str, set] = defaultdict(set)
        for v in views:
            for f in v.feeds:
                if not f.have:
                    unlock_dc[f.feed].add(v.dc.id)
        for an in m.analytics.values():
            if analytic_status(m, an) == "live":
                continue
            for ref in an.log_source_refs:
                for p in resolve(ref.name).providers:
                    if not p.have and not p.virtual:
                        unlock_an[p.feed].add(an.id)
        L = [f"# Gaps (ATT&CK v{m.version})", "",
             "Feeds you have **not** ticked in `config/stack.yml`, ranked by what ticking them would unlock. "
             "*Analytics* counts analytics that are not yet live and reference the feed; *components* counts data components that would gain a provider.", "",
             "## In-scope platforms", "", "| Feed | Platforms | Analytics unlocked | Components | What it is | TA / collector |", "|---|---|---|---|---|---|"]
        rows = []
        for name, f in feeds.items():
            if f.get("have") or f.get("virtual") or f.get("render") is False:
                continue
            rows.append((len(unlock_an[name]), len(unlock_dc[name]), name, f))
        for n_an, n_dc, name, f in sorted(rows, key=lambda r: (-r[0], -r[1])):
            L.append(f"| `{name}` | {', '.join(f.get('platforms', []))} | {n_an} | {n_dc} | {f['label']} | {f.get('ta', '')} |")
        L.append("")
        L += ["```mermaid", "xychart-beta", '    title "Analytics unlocked per untapped feed (in-scope platforms)"',
              "    x-axis [" + ", ".join(f'"{r[2]}"' for r in sorted(rows, key=lambda r: -r[0])[:12]) + "]", '    y-axis "analytics"',
              "    bar [" + ", ".join(str(r[0]) for r in sorted(rows, key=lambda r: -r[0])[:12]) + "]", "```", ""]
        L += ["## Out-of-scope platforms", "", "Listed so the checklist is complete; rendering for these platforms is a later phase.", "",
              "| Feed | Platforms | Analytics referencing it | What it is |", "|---|---|---|---|"]
        for name, f in feeds.items():
            if f.get("render") is False and not f.get("virtual"):
                L.append(f"| `{name}` | {', '.join(f.get('platforms', [])) or '—'} | {len(unlock_an[name])} | {f['label']} |")
        L.append("")
        L += ["## Components with no in-scope provider", "", "| Component | Analytics | Log sources named by ATT&CK |", "|---|---|---|"]
        for v in views:
            if not v.in_scope:
                L.append(f"| [{v.dc.id}](data-components/{dc_page_name(v)}) {v.dc.name} | {v.analytics} | {', '.join(s.canonical for s in v.sources[:6])}{' …' if len(v.sources) > 6 else ''} |")
        L.append("")
        p = DOCS_DIR / "gaps.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ checklist
    def _checklist(self, m: AttackModel, views: list[DCView]) -> Path:
        feeds = config.stack()
        dc_count = Counter()
        for v in views:
            for f in v.feeds:
                dc_count[f.feed] += 1
        an_count = Counter()
        for an in m.analytics.values():
            seen = set()
            for ref in an.log_source_refs:
                for p in resolve(ref.name).providers:
                    if p.feed not in seen:
                        seen.add(p.feed)
                        an_count[p.feed] += 1
        L = ["# Log source checklist", "",
             "This is the checklist behind `config/stack.yml`. Tick `have: true` for what reaches Splunk, fix `index` and `sourcetypes`, rebuild. "
             "Nothing here is declared unavailable by the author; the ticks are yours.", "",
             "| ✓ | Feed | What it is | Platforms | Index | Sourcetype(s) | Components | Analytics | Rendered |", "|---|---|---|---|---|---|---|---|---|"]
        for name, f in feeds.items():
            if f.get("virtual"):
                continue
            sts = f.get("sourcetypes") or ([f["sourcetype"]] if f.get("sourcetype") else []) or ([f["sourcetype_template"]] if f.get("sourcetype_template") else [])
            L.append(f"| {'☑' if f.get('have') else '☐'} | `{name}` | {f['label']} | {', '.join(f.get('platforms', [])) or '—'} | `{f.get('index', '')}` | {', '.join(f'`{s}`' for s in sts)} | {dc_count[name]} | {an_count[name]} | {'no' if f.get('render') is False else 'yes'} |")
        L.append("")
        L += ["## What each untapped feed would add", ""]
        for name, f in feeds.items():
            if f.get("have") or f.get("virtual"):
                continue
            L.append(f"- **`{name}`** — {f.get('unlocks', '')}")
        L.append("")
        p = DOCS_DIR / "checklist.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p
