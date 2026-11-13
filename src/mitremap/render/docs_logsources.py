"""Index of content by log source: which data components, analytics and sequences each feed supports.

Writes docs/by-log-source.md and refreshes the generated block in README.md between
<!-- BEGIN mitremap:log-sources --> and <!-- END mitremap:log-sources -->.
"""
from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

from .. import DOCS_DIR, ROOT, config
from ..analytics import all_views
from ..build import DCView
from ..model import AttackModel
from ..strategies import all_strategies
from .docs import dc_page_name
from .docs_analytics import page_name as an_page_name
from .docs_strategies import page_name as st_page_name

BEGIN = "<!-- BEGIN mitremap:log-sources -->"
END = "<!-- END mitremap:log-sources -->"
CATEGORY_ORDER = ["Windows endpoint", "Endpoint security", "Network", "Linux", "Azure and identity", "Containers", "VMware ESXi", "Not yet in scope"]


def _feeds_by_category() -> "OrderedDict[str, list[str]]":
    groups: "OrderedDict[str, list[str]]" = OrderedDict((c, []) for c in CATEGORY_ORDER)
    for name, f in config.stack().items():
        if f.get("virtual"):
            continue
        groups.setdefault(f.get("category", "Other"), []).append(name)
    return OrderedDict((c, fs) for c, fs in groups.items() if fs)


class LogSourcesDocsRenderer:
    name = "docs_logsources"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        stack = config.stack()
        impl = [v for v in all_views(m) if v.implemented]
        seqs = [s for s in all_strategies(m) if s.implemented and s.shape == "sequence"]
        ticked = {n for n, f in stack.items() if f.get("have")}

        dcs_by_feed = {n: [] for n in stack}
        for v in views:
            for f in v.feeds:
                if f.in_scope:
                    dcs_by_feed[f.feed].append((v, f))
        an_by_feed = {n: [a for a in impl if n in (a.curated.get("feeds") or [])] for n in stack}
        seq_by_feed = {n: [s for s in seqs if n in (s.curated.get("feeds") or [])] for n in stack}
        runnable = [a for a in impl if set(a.curated.get("feeds") or []) <= ticked]
        runnable_seq = [s for s in seqs if set(s.curated.get("feeds") or []) <= ticked]
        live_dcs = [v for v in views if v.live_feeds]

        out = [self._page(m, stack, ticked, dcs_by_feed, an_by_feed, seq_by_feed)]
        self._readme_block(stack, ticked, dcs_by_feed, an_by_feed, seq_by_feed, len(live_dcs), len(runnable), len(runnable_seq))
        out.append(ROOT / "README.md")
        return out

    # ------------------------------------------------------------------ page
    def _page(self, m, stack, ticked, dcs_by_feed, an_by_feed, seq_by_feed) -> Path:
        L = [f"# Content by log source (ATT&CK v{m.version})", "",
             "For each feed in `config/stack.yml`: the data components it provides, and the implemented analytics and "
             "strategy sequences that read it. Tick the feeds you have in `config/stack.yml` and rebuild; this page and the "
             "table in the README follow.", "",
             "An analytic lists every feed its search reads. Searches over a CIM data model (most Windows process analytics) "
             "work with either Sysmon or Security 4688; raw searches that join two feeds need both.", ""]
        L += ["| Category | Feeds |", "|---|---|"]
        for cat, feeds in _feeds_by_category().items():
            L.append(f"| {cat} | " + ", ".join(f"[{'☑' if f in ticked else '☐'} `{f}`](#{f})" for f in feeds) + " |")
        L.append("")
        for cat, feeds in _feeds_by_category().items():
            L += [f"## {cat}", ""]
            for feed in feeds:
                f = stack[feed]
                L += [f"### {feed}", "",
                      f"{'☑ ticked' if feed in ticked else '☐ not ticked'} · {f['label']} · index `{f.get('index', '')}`"
                      + (" · not rendered in this release" if f.get("render") is False else ""), ""]
                dcs = sorted(dcs_by_feed.get(feed, []), key=lambda x: x[0].dc.id)
                if dcs:
                    L.append(f"**Data components ({len(dcs)}):** " + ", ".join(
                        f"[{v.dc.id} {v.dc.name}](data-components/{dc_page_name(v)})" for v, _ in dcs) + ".")
                    L.append("")
                ans = sorted(an_by_feed.get(feed, []), key=lambda a: a.id)
                if ans:
                    L += [f"**Analytics ({len(ans)}):**", "", "| Analytic | Type | Technique | Other feeds it reads |", "|---|---|---|---|"]
                    for a in ans:
                        others = [o for o in (a.curated.get("feeds") or []) if o != feed]
                        L.append(f"| [{a.id} {a.title}](analytics/{an_page_name(a)}) | {a.content_type} | {a.technique.id} {a.technique.name} | "
                                 + (", ".join(f"`{o}`{'' if o in ticked else ' (not ticked)'}" for o in others) or "none") + " |")
                    L.append("")
                sq = sorted(seq_by_feed.get(feed, []), key=lambda s: s.id)
                if sq:
                    L.append(f"**Strategy sequences ({len(sq)}):** " + ", ".join(f"[{s.id} {s.title}](strategies/{st_page_name(s)})" for s in sq) + ".")
                    L.append("")
                if not (dcs or ans or sq):
                    L += ["Nothing rendered for this feed yet" + (" (platform not in scope)." if f.get("render") is False else "."), ""]
        p = DOCS_DIR / "by-log-source.md"
        p.write_text("\n".join(L), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ README block
    def _readme_block(self, stack, ticked, dcs_by_feed, an_by_feed, seq_by_feed, n_live_dcs, n_runnable, n_runnable_seq) -> None:
        readme = ROOT / "README.md"
        text = readme.read_text(encoding="utf-8")
        if BEGIN not in text or END not in text:
            return
        L = [BEGIN, "",
             f"With the feeds ticked in `config/stack.yml`: **{n_live_dcs}** data components live, **{n_runnable}** analytics and "
             f"**{n_runnable_seq}** strategy sequences runnable. Each count links to the full list in [docs/by-log-source.md](docs/by-log-source.md).", "",
             "| Category | Feed | Have | Data components | Analytics | Sequences |", "|---|---|---|---|---|---|"]
        for cat, feeds in _feeds_by_category().items():
            if cat == "Not yet in scope":
                continue
            for i, feed in enumerate(feeds):
                anchor = f"docs/by-log-source.md#{feed}"
                n_dc, n_an, n_sq = len(dcs_by_feed.get(feed, [])), len(an_by_feed.get(feed, [])), len(seq_by_feed.get(feed, []))
                cell = lambda n: f"[{n}]({anchor})" if n else "0"
                L.append(f"| {cat if i == 0 else ''} | [`{feed}`]({anchor}) | {'☑' if feed in ticked else '☐'} | {cell(n_dc)} | {cell(n_an)} | {cell(n_sq)} |")
        L += ["", "Feeds for platforms not yet in scope (macOS, Microsoft 365, AWS, GCP, Okta, SaaS) are listed in the [full index](docs/by-log-source.md#not-yet-in-scope).", "", END]
        new = text[:text.index(BEGIN)] + "\n".join(L) + text[text.index(END) + len(END):]
        if new != text:
            readme.write_text(new, encoding="utf-8")
