"""mitremap command line: fetch | scaffold | new-analytic | render | validate | build | diff."""
from __future__ import annotations

import argparse
import sys

from .model import load_model


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mitremap", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="download the pinned ATT&CK release and write the slim extract")
    f.add_argument("--version", default=None)
    f.add_argument("--no-pin", action="store_true")
    sub.add_parser("scaffold", help="create/refresh content/data_components/*.yml and refresh content/analytics/*.yml")
    na = sub.add_parser("new-analytic", help="scaffold content/analytics/<AN id>.yml for an ATT&CK analytic")
    na.add_argument("an_id", nargs="+")
    ns = sub.add_parser("new-strategy", help="scaffold content/detection_strategies/<DET id>.yml for an ATT&CK detection strategy")
    ns.add_argument("det_id", nargs="+")
    r = sub.add_parser("render", help="render Splunk, Sigma and docs")
    r.add_argument("--target", action="append", choices=["splunk", "detections", "sigma", "docs", "docs_analytics", "docs_strategies", "kql", "esql"], help="restrict to a renderer (repeatable)")
    sub.add_parser("validate", help="consistency checks")
    sub.add_parser("build", help="scaffold + render + validate")
    d = sub.add_parser("diff", help="changelog between two ATT&CK versions")
    d.add_argument("old"); d.add_argument("new")
    a = ap.parse_args(argv)

    if a.cmd == "fetch":
        from .fetch import fetch
        fetch(a.version, pin=not a.no_pin)
        return 0
    if a.cmd == "diff":
        from .diff import diff
        print(diff(a.old, a.new))
        return 0

    m = load_model()
    if a.cmd == "new-analytic":
        from .analytics import new_analytic
        for an_id in a.an_id:
            print(new_analytic(m, an_id.upper()))
        return 0
    if a.cmd == "new-strategy":
        from .strategies import new_strategy
        for det_id in a.det_id:
            print(new_strategy(m, det_id.upper()))
        return 0
    if a.cmd in ("scaffold", "build"):
        from .analytics import scaffold_analytics
        from .scaffold import scaffold
        from .strategies import scaffold_strategies
        print(f"scaffold: {scaffold(m)} data component files, {scaffold_analytics(m)} analytic files, {scaffold_strategies(m)} strategy files")
    if a.cmd in ("render", "build"):
        from .build import build_all
        from .render import all_renderers
        views = build_all(m)
        targets = getattr(a, "target", None) or ["splunk", "detections", "sigma", "docs", "docs_analytics", "docs_strategies"]
        for name, r in all_renderers().items():
            if name not in targets:
                continue
            try:
                paths = r.render(m, views)
                print(f"render[{name}]: {len(paths)} files")
            except NotImplementedError as e:
                print(f"render[{name}]: skipped ({e})")
    if a.cmd in ("validate", "build"):
        from .validate import validate
        errs = validate(m)
        if errs:
            print(f"validate: {len(errs)} problem(s)", file=sys.stderr)
            for e in errs:
                print("  - " + e, file=sys.stderr)
            return 1
        print("validate: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
