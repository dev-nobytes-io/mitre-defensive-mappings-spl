# Analytics

One YAML per ATT&CK analytic that has been started. `attack` and `derived` are regenerated from the STIX data and config; `curated` is hand-written and preserved.

```bash
python -m mitremap new-analytic AN0123    # scaffold with ATT&CK text, coverage, suggested content type and tuning bindings
make build && make test                   # render detections, Sigma rules and docs; validate
```

Schema and conventions: [docs/roadmap.md](../../docs/roadmap.md) and [docs/splunk-implementation.md](../../docs/splunk-implementation.md). Rendered output: `dist/splunk/DA-ESS-mitre-attack-detections/`, `dist/sigma/rules/`, [docs/analytics/](../../docs/analytics/README.md).

Only `status: implemented` or `reviewed` analytics are rendered. What to pick next: [docs/analytics/backlog.md](../../docs/analytics/backlog.md).
