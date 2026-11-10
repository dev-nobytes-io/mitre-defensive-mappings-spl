import pytest

from mitremap.logsources import canonicalize, parse_channel, resolve


@pytest.mark.parametrize("channel,expected", [
    ("EventCode=1", [1]),
    ("EventCode=4103, 4104, 4105, 4106", [4103, 4104, 4105, 4106]),
    ("4624, 4648", [4624, 4648]),
    ("Event ID 7045 or 4697", [4697, 7045]),
    ("EventCode=1; process lineage and command line", [1]),
    ("None", None),
    ("process creation with suspicious parent", None),
])
def test_eventcode_parser(channel, expected):
    out = parse_channel("eventcode", channel)
    assert out.get("event_codes") == expected


@pytest.mark.parametrize("channel,expected", [
    ("execve", ["execve"]),
    ("open, write", ["open", "write"]),
    ("socket/connect", ["connect", "socket"]),
    ("Processes launched with LD_PRELOAD", None),
])
def test_auditd_parser(channel, expected):
    assert parse_channel("auditd", channel).get("syscalls") == expected


@pytest.mark.parametrize("channel,expected", [
    ("conn.log", ["conn"]),
    ("http.log, ftp.log", ["ftp", "http"]),
    ("Inbound HTTP POST with suspicious payload size", ["http"]),
    ("Outbound Connections", None),
])
def test_zeek_parser(channel, expected):
    assert parse_channel("zeek", channel).get("zeek_logs") == expected


def test_k8s_parser():
    assert parse_channel("k8s", "create: Pod/Container created")["verbs"] == ["create"]
    assert parse_channel("k8s", "Failed login") == {}


def test_aliases_collapse_typos():
    assert canonicalize("NSM:FLow") == "NSM:Flow"
    assert canonicalize("WinEventLog:Sysmon ") == "WinEventLog:Sysmon"
    assert canonicalize("esxis:vmkernel") == "esxi:vmkernel"


def test_resolve_multi_provider():
    rs = resolve("NSM:Flow")
    assert {p.feed for p in rs.providers} == {"corelight", "palo_alto"}


def test_resolve_rule_fallback():
    rs = resolve("WinEventLog:Microsoft-Windows-Bits-Client/Operational")
    assert rs.via_rule and rs.providers[0].feed == "wineventlog"
    assert rs.providers[0].channel == "Microsoft-Windows-Bits-Client/Operational"


def test_unknown_name_raises():
    with pytest.raises(LookupError):
        resolve("definitely:not-a-thing")
