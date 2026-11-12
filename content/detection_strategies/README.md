# Detection strategies

One YAML per ATT&CK detection strategy that does more than delegate to its analytics. `attack` is regenerated; `curated` is hand-written.

* `shape: sequence` — hand-written SPL joining raw events on a key, implementing the chain the strategy's analytic left in its `gaps` field. Writes a finding and risk. Needs `spl`, `risk`, `data_components`, `extends` (the single-leg analytics it builds on), and Sigma `rules` + `correlation`.
* `shape: risk_threshold` — generated SPL over the Risk data model. Needs `group_by` (`risk_object` or `threat_object`), `window`, `condition` over the computed fields (risk_score, risk_events, distinct_analytics, distinct_strategies, distinct_tactics, distinct_techniques, distinct_risk_objects), optional `scope`, `risk_object_types`, `threat_object_types`. Writes a finding only.

Strategies with implemented analytics and no file here are delegated. Index: [docs/strategies/](../../docs/strategies/README.md).

```bash
python -m mitremap new-strategy DET0123
make build && make test
```
