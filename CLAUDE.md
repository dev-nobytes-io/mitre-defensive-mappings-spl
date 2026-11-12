# Working on this repository

MITRE ATT&CK (pinned Enterprise release) mapped onto a Splunk log stack: data components → eventtypes, analytics → ES detections + Sigma, detection strategies → sequences and risk rules. Python package `mitremap` generates everything under `dist/` and most of `docs/`.

**Start here:** read [TODO.md](TODO.md) (state, conventions, ordered next steps), then `make build && .venv/bin/python -m pytest -q`.

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[sigma,dev]"
make build                                    # scaffold + render + validate
.venv/bin/python -m pytest -q
python -m mitremap new-analytic AN0123        # scaffold an analytic (PYTHONPATH=src or installed package)
python -m mitremap new-strategy DET0123       # scaffold a detection strategy
make diff FROM=20.0 TO=20.1                   # ATT&CK changelog
```

## What you edit, what you don't

* Edit: `config/*.yml`, the `curated` block of `content/**/*.yml`, `src/mitremap/`, `tests/`, and the hand-written docs (`README.md`, `TODO.md`, `docs/model.md`, `docs/splunk-implementation.md`, `docs/data-sources.md`, `docs/roadmap.md`, the READMEs under `content/`).
* Never hand-edit: `dist/**`, `docs/data-components/**`, `docs/analytics/**`, `docs/strategies/**`, `docs/coverage.md`, `docs/gaps.md`, `docs/checklist.md`, `docs/changelog/**`, or the `attack`/`derived` blocks of content YAML. Rebuild instead.
* `make build` must be idempotent: run it twice and `git status` must show no change (CI checks this).

## Rules the validator enforces

See "Conventions that the validator enforces" in TODO.md. In short: SPL goes through `mitre_dc*` macros and ends with its own filter macro, has no literal `index=`, references only existing macros and lookups; risk fields and message tokens appear in the search; the content type decides the ES action; every analytic has Sigma or a stated reason.

## Workflow

Branch, small commits, draft PR, CI green. Update the checkboxes in TODO.md in the same PR as the work.
