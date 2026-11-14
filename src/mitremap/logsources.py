"""Resolve ATT&CK log-source names to feeds and parse free-text channels.

    resolve("WinEventLog:Sysmon ")  -> ResolvedSource(canonical="WinEventLog:Sysmon", feeds=[Provider(feed="sysmon"...)])
    parse_channel("eventcode", "EventCode=4103, 4104") -> {"event_codes": [4103, 4104]}
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import config

# --------------------------------------------------------------------------- parsers

_EVENTCODE_RE = re.compile(r"(?:EventCode|EventID|Event\s*ID|EID|ID)s?\s*[=:]?\s*((?:\d{1,5}\s*(?:,|/|\bor\b|\band\b)?\s*)+)", re.I)
_BARE_CODES_RE = re.compile(r"^\s*(\d{1,5}(?:\s*(?:,|/|\bor\b)\s*\d{1,5})*)\s*$", re.I)

_SYSCALLS = {
    "execve", "execveat", "open", "openat", "openat2", "creat", "read", "write", "pread", "pwrite", "close",
    "connect", "socket", "bind", "listen", "accept", "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "ptrace", "process_vm_writev", "process_vm_readv", "mmap", "mprotect", "memfd_create", "clone", "clone3", "fork", "vfork",
    "kill", "tkill", "tgkill", "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown",
    "rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "link", "linkat", "symlink", "symlinkat",
    "truncate", "ftruncate", "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setfsuid", "capset",
    "mount", "umount", "umount2", "init_module", "finit_module", "delete_module", "ioctl", "prctl", "setns", "unshare",
    "chroot", "pivot_root", "keyctl", "add_key", "request_key", "reboot", "bpf", "perf_event_open", "io_uring_setup",
    "setxattr", "lsetxattr", "fsetxattr", "removexattr", "utimes", "utimensat", "futimesat", "setsockopt", "getsockopt",
    "readlink", "readlinkat", "stat", "lstat", "fstat", "newfstatat", "statx", "access", "faccessat", "dup", "dup2", "dup3",
    "pipe", "pipe2", "splice", "sendfile", "copy_file_range", "fallocate", "sync", "fsync", "msync", "madvise",
    "sched_setaffinity", "setrlimit", "prlimit64", "seccomp", "userfaultfd", "uselib", "personality", "modify_ldt",
}

_ZEEK_LOGS = {
    "conn", "dns", "http", "ssl", "x509", "files", "smb_files", "smb_mapping", "smb_cmd", "dce_rpc", "kerberos", "ntlm", "rdp",
    "ssh", "smtp", "ftp", "notice", "weird", "software", "dhcp", "ldap", "ldap_search", "pe", "irc", "sip", "snmp", "radius",
    "modbus", "dnp3", "s7comm", "tunnel", "intel", "known_services", "known_hosts", "known_certs", "ntp", "mysql", "rfb", "socks",
    "syslog", "tftp", "websocket", "quic", "suricata_corelight",
}
_ZEEK_RE = re.compile(r"\b([a-z0-9_]+)\.log\b", re.I)

_K8S_VERBS = {"create", "get", "list", "watch", "delete", "deletecollection", "patch", "update", "exec", "attach", "portforward", "proxy", "impersonate", "bind", "escalate"}


def parse_channel(parser: str, channel: str) -> dict:
    """Turn a free-text ATT&CK channel into structured constraints."""
    channel = (channel or "").strip()
    out: dict = {}
    if not channel or channel.lower() in {"none", "n/a", "any", "all"}:
        return out
    if parser == "eventcode":
        codes: list[int] = []
        m = _BARE_CODES_RE.match(channel)
        if m:
            codes = [int(x) for x in re.findall(r"\d{1,5}", m.group(1))]
        else:
            for m in _EVENTCODE_RE.finditer(channel):
                codes += [int(x) for x in re.findall(r"\d{1,5}", m.group(1))]
        codes = sorted({c for c in codes if 0 < c < 65536})
        if codes:
            out["event_codes"] = codes
    elif parser == "auditd":
        words = {w.lower() for w in re.findall(r"[a-z_0-9]+", channel, re.I)}
        sc = sorted(words & _SYSCALLS)
        if sc:
            out["syscalls"] = sc
    elif parser == "zeek":
        logs = {m.group(1).lower() for m in _ZEEK_RE.finditer(channel)}
        logs |= {w for w in re.findall(r"[a-z0-9_]+", channel.lower()) if w in _ZEEK_LOGS and w not in {"files", "software", "notice", "syslog"}}
        logs = {l for l in logs if l in _ZEEK_LOGS}
        if logs:
            out["zeek_logs"] = sorted(logs)
    elif parser == "k8s":
        first = re.split(r"[\s:,/]+", channel.lower(), maxsplit=1)[0]
        if first in _K8S_VERBS:
            out["verbs"] = [first]
    # esxi / none: the channel is documentation only
    return out


# --------------------------------------------------------------------------- resolution

@dataclass
class Provider:
    feed: str
    channel: str | None = None          # Windows channel name for sourcetype_template
    logs: list[str] = field(default_factory=list)          # fixed Zeek/PAN/ESXi logs
    logs_default: list[str] = field(default_factory=list)  # used when the channel names none
    sourcetypes: list[str] = field(default_factory=list)   # explicit override
    event_codes: list[int] = field(default_factory=list)   # fixed EventCode constraint
    record_type: str | None = None      # auditd
    filter: str | None = None           # extra literal SPL constraint

    @property
    def virtual(self) -> bool:
        return bool(config.feed(self.feed).get("virtual"))


@dataclass
class ResolvedSource:
    raw: str
    canonical: str
    parser: str
    providers: list[Provider]
    sigma: dict
    kql: dict | None
    elastic: dict | None
    prerequisites: list[str]
    via_rule: bool = False


_RULES_COMPILED: list[tuple[re.Pattern, dict]] | None = None


def _rules() -> list[tuple[re.Pattern, dict]]:
    global _RULES_COMPILED
    if _RULES_COMPILED is None:
        _RULES_COMPILED = [(re.compile(r["match"]), r) for r in config.log_sources().get("rules", [])]
    return _RULES_COMPILED


def canonicalize(raw: str) -> str:
    aliases = config.log_sources().get("aliases", {})
    name = raw.strip()
    name = aliases.get(raw, aliases.get(name, name))
    return name.strip()


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _providers(spec_list: list[dict], groups: dict) -> list[Provider]:
    out = []
    for p in spec_list:
        p = {k: (v.format(**groups, channel_slug=_slug(groups.get("channel", ""))) if isinstance(v, str) else v) for k, v in p.items()}
        out.append(Provider(**p))
    return out


def resolve(raw: str) -> ResolvedSource:
    canonical = canonicalize(raw)
    sources = config.log_sources().get("sources", {})
    spec = sources.get(canonical)
    if spec is not None:
        return ResolvedSource(
            raw=raw, canonical=canonical, parser=spec.get("parser", "none"),
            providers=_providers(spec.get("providers", []), {}),
            sigma=spec.get("sigma", {}), kql=spec.get("kql"), elastic=spec.get("elastic"),
            prerequisites=list(spec.get("prerequisites", [])),
        )
    for rx, rule in _rules():
        m = rx.search(canonical)
        if m:
            groups = {k: (v or "") for k, v in m.groupdict().items()}
            sigma = {k: (v.format(**groups, channel_slug=_slug(groups.get("channel", ""))) if isinstance(v, str) else v) for k, v in rule.get("sigma", {}).items()}
            return ResolvedSource(
                raw=raw, canonical=canonical, parser=rule.get("parser", "none"),
                providers=_providers(rule.get("providers", []), groups),
                sigma=sigma, kql=None, elastic=None, prerequisites=[], via_rule=True,
            )
    raise LookupError(f"log source {raw!r} (canonical {canonical!r}) is not mapped in config/log_sources.yml")


def sourcetypes_for(p: Provider, parsed: dict) -> list[str]:
    """Literal sourcetype(s) a provider contributes, given parsed channel info."""
    f = config.feed(p.feed)
    if p.sourcetypes:
        return list(p.sourcetypes)
    tmpl = f.get("sourcetype_template")
    if tmpl and "{channel}" in tmpl:
        return [tmpl.format(channel=p.channel or f.get("default_channels", ["Security"])[0])]
    if tmpl and "{log}" in tmpl:
        logs = p.logs or parsed.get("zeek_logs") or p.logs_default or f.get("default_logs", [])
        # Only logs the feed actually ships (Palo Alto has no dns log, etc.)
        allowed = set(f.get("default_logs", [])) or set(logs)
        logs = [l for l in logs if l in allowed] or (p.logs_default if p.logs_default else [])
        return [tmpl.format(log=l) for l in logs]
    if f.get("sourcetypes"):
        return list(f["sourcetypes"])
    st = f.get("sourcetype")
    return [st] if st else []
