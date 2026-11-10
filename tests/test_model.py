def test_counts(model):
    assert len(model.data_components) == 106
    assert len(model.analytics) > 1700
    assert len(model.detection_strategies) == len(model.techniques) == 706


def test_det_technique_one_to_one(model):
    assert all(ds.technique_id for ds in model.detection_strategies.values())
    assert all(len(t.det_ids) == 1 for t in model.techniques.values())


def test_analytics_link_back(model):
    an = next(a for a in model.analytics.values() if a.log_source_refs)
    assert an.det_id in model.detection_strategies
    dc_id = an.log_source_refs[0].dc_id
    assert an.id in model.data_components[dc_id].analytic_ids


def test_every_log_source_resolves(model):
    from mitremap.logsources import resolve
    names = {r.name for dc in model.data_components.values() for r in dc.log_sources}
    names |= {r.name for an in model.analytics.values() for r in an.log_source_refs}
    for n in names:
        resolve(n)
