from mitremap.build import build_all, eventtype_search


def test_process_creation_constraints(model):
    v = next(v for v in build_all(model) if v.dc.id == "DC0032")
    feeds = {f.feed: f for f in v.feeds}
    assert feeds["sysmon"].event_codes == [1]
    assert feeds["wineventlog"].event_codes == [4688]
    assert feeds["auditd"].syscalls == ["execve", "execveat"]
    assert "azure_resource" not in feeds  # excluded by dc_defaults
    assert eventtype_search(feeds["sysmon"]).startswith("index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")


def test_out_of_scope_feeds_not_rendered(model):
    for v in build_all(model):
        for f in v.feeds:
            assert f.feed not in {"macos", "aws", "gcp", "saas", "m365_unified", "okta"} or not f.in_scope


def test_no_macro_or_pipe_in_eventtype_search(model):
    for v in build_all(model):
        for f in v.feeds:
            s = eventtype_search(f)
            assert "`" not in s and "|" not in s, s
