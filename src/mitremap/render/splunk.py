"""Render the Splunk technology add-on: eventtypes, tags, macros, lookups."""
from __future__ import annotations

import csv
from pathlib import Path

from .. import DIST_DIR, config
from ..build import DCView, eventtype_search
from ..model import AttackModel

APP = "TA-mitre-attack-datacomponents"

TUNING_LOOKUPS: dict[str, tuple[list[str], list[list[str]], dict]] = {
    # name: (header, seed rows, transforms options)
    "mitre_allowlist_processes": (
        ["process_name", "parent_process_name", "process_path", "user", "dc_id", "an_id", "reason", "expires"],
        [["MsMpEng.exe", "", "C:\\ProgramData\\Microsoft\\Windows Defender\\*", "", "", "", "seed: Defender engine", ""]],
        {"case_sensitive_match": "false", "match_type": "WILDCARD(process_path)"},
    ),
    "mitre_allowlist_users": (
        ["user", "dc_id", "an_id", "reason", "expires"],
        [["svc_backup", "", "", "seed: backup service account", ""]],
        {"case_sensitive_match": "false"},
    ),
    "mitre_allowlist_hosts": (
        ["dest", "dc_id", "an_id", "reason", "expires"],
        [["scanner01", "", "", "seed: vulnerability scanner", ""]],
        {"case_sensitive_match": "false"},
    ),
    "mitre_allowlist_domains": (
        ["domain", "dc_id", "an_id", "reason", "expires"],
        [["*.windowsupdate.com", "", "", "seed: Windows Update", ""]],
        {"case_sensitive_match": "false", "match_type": "WILDCARD(domain)"},
    ),
    "mitre_allowlist_ips": (
        ["cidr", "dc_id", "an_id", "reason", "expires"],
        [["203.0.113.0/24", "", "", "seed: example documentation range", ""]],
        {"match_type": "CIDR(cidr)"},
    ),
    "mitre_internal_networks": (
        ["cidr", "description"],
        [["10.0.0.0/8", "RFC1918"], ["172.16.0.0/12", "RFC1918"], ["192.168.0.0/16", "RFC1918"]],
        {"match_type": "CIDR(cidr)"},
    ),
    "mitre_asset_roles": (
        ["dest", "role", "owner", "notes"],
        [["dc01", "domain_controller", "", "seed"], ["jump01", "jump_host", "", "seed"]],
        {"case_sensitive_match": "false"},
    ),
    "mitre_account_roles": (
        ["user", "role", "notes"],
        [["Administrator", "admin", "seed"], ["svc_sql", "service", "seed"]],
        {"case_sensitive_match": "false"},
    ),
    "mitre_lolbins": (
        ["process_name", "category", "reference"],
        [[p, "lolbas", "https://lolbas-project.github.io/"] for p in ["certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe", "bitsadmin.exe", "wmic.exe", "cscript.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "pcalua.exe", "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe", "makecab.exe", "replace.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe", "reg.exe", "wevtutil.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "curl.exe", "mavinject.exe", "odbcconf.exe", "control.exe", "ieexec.exe", "presentationhost.exe", "scriptrunner.exe", "syncappvpublishingserver.exe", "xwizard.exe", "wsreset.exe"]],
        {"case_sensitive_match": "false"},
    ),
    "mitre_sensitive_paths": (
        ["path", "category", "platform"],
        [["C:\\Windows\\System32\\config\\SAM", "credential_store", "Windows"], ["C:\\Windows\\NTDS\\ntds.dit", "credential_store", "Windows"],
         ["/etc/shadow", "credential_store", "Linux"], ["/etc/passwd", "account_db", "Linux"], ["/etc/sudoers", "privilege", "Linux"],
         ["/etc/cron.d/*", "persistence", "Linux"], ["/etc/systemd/system/*", "persistence", "Linux"], ["/root/.ssh/*", "credential_store", "Linux"],
         ["C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*", "persistence", "Windows"],
         ["/etc/vmware/*", "config", "ESXi"], ["/vmfs/volumes/*", "datastore", "ESXi"], ["/var/run/secrets/kubernetes.io/*", "credential_store", "Containers"]],
        {"case_sensitive_match": "false", "match_type": "WILDCARD(path)"},
    ),
}

ENV_MACROS: list[tuple[str, str, str]] = [
    # (stanza, definition, description)
    ("mitre_time_window(1)", '_time>=relative_time(now(), "-$span$")', "Where-clause fragment for the ATT&CK TimeWindow mutable element, e.g. `| where `mitre_time_window(15m)``. Args: span."),
    ("mitre_is_internal(1)", '(cidrmatch("10.0.0.0/8", $ip$) OR cidrmatch("172.16.0.0/12", $ip$) OR cidrmatch("192.168.0.0/16", $ip$))', "Boolean for RFC1918 space; edit to match your address plan, or use the mitre_internal_networks lookup. Args: ip."),
    ("mitre_hosts_with_role(1)", '[| inputlookup mitre_asset_roles where role="$role$" | fields dest | format]', "Subsearch yielding dest values of a role (domain_controller, jump_host, ...). Args: role."),
    ("mitre_accounts_with_role(1)", '[| inputlookup mitre_account_roles where role="$role$" | fields user | format]', "Subsearch yielding user values of a role (admin, service, ...). Args: role."),
    ("mitre_not_allowlisted_process", "NOT [| inputlookup mitre_allowlist_processes | fields process_name | format]", "Exclude allow-listed process names (CIM process_name)."),
    ("mitre_not_allowlisted_user", "NOT [| inputlookup mitre_allowlist_users | fields user | format]", "Exclude allow-listed users (CIM user)."),
    ("mitre_not_allowlisted_dest", "NOT [| inputlookup mitre_allowlist_hosts | fields dest | format]", "Exclude allow-listed hosts (CIM dest)."),
    ("mitre_lolbin_processes", "[| inputlookup mitre_lolbins | fields process_name | format]", "Subsearch of LOLBAS process names."),
    ("mitre_powershell_processes", '(process_name IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe"))', "PowerShell host process names."),
    ("mitre_script_interpreters", '(process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "python.exe", "python3.exe", "perl.exe", "ruby.exe", "node.exe", "bash", "sh", "zsh", "python", "python3", "perl"))', "Script interpreter process names across Windows and Linux."),
    ("mitre_shells", '(process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "zsh", "dash", "ksh", "fish"))', "Interactive shell process names."),
    ("mitre_attack_version", '"20.1"', "ATT&CK release this content was generated from."),
    ("mitre_summariesonly", "summariesonly=false allow_old_summaries=true", "tstats arguments for data model searches. Set summariesonly=true once the Endpoint, Network_Traffic, Authentication and Change models are accelerated."),
    ("mitre_ctime(1)", 'convert timeformat="%Y-%m-%dT%H:%M:%S" ctime($field$)', "Render an epoch field as a timestamp. Args: field."),
    ("mitre_normalize_host", "eval dest=coalesce(dest, Computer, dvc, host), user=coalesce(user, User, SubjectUserName, TargetUserName)", "Normalise host and user for raw Windows/Sysmon searches when the source TA has not aliased them. Edit to match your field extractions."),
    ("mitre_normalize_zeek", "eval src=coalesce(src, src_ip, 'id.orig_h'), dest=coalesce(dest, dest_ip, 'id.resp_h'), dest_port=coalesce(dest_port, 'id.resp_p'), bytes_out=coalesce(bytes_out, orig_bytes, orig_ip_bytes), bytes_in=coalesce(bytes_in, resp_bytes, resp_ip_bytes)", "Normalise Corelight/Zeek connection fields to CIM names whichever TA is installed."),
    ("mitre_normalize_zeek_http", "eval http_user_agent=coalesce(http_user_agent, user_agent), http_host=coalesce(http_host, url_domain, dest_host, site), uri=coalesce(uri, uri_path, url)", "Normalise Corelight/Zeek HTTP fields. The Zeek 'host' header collides with Splunk's host field; point http_host at whatever your TA extracts it as."),
    ("mitre_normalize_pan", "eval src=coalesce(src, src_ip), dest=coalesce(dest, dest_ip), user=coalesce(user, src_user, admin)", "Normalise Palo Alto fields to CIM names."),
]


def _q(s: str) -> str:
    return s.replace("\n", " ")


class SplunkRenderer:
    name = "splunk"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        root = DIST_DIR / "splunk" / APP
        default = root / "default"
        lookups = root / "lookups"
        default.mkdir(parents=True, exist_ok=True)
        lookups.mkdir(parents=True, exist_ok=True)
        out = []
        out.append(self._eventtypes(default / "eventtypes.conf", views, m))
        out.append(self._tags(default / "tags.conf", views))
        out.append(self._macros(default / "macros.conf", views, m))
        out.append(self._transforms(default / "transforms.conf"))
        out.append(self._app_conf(default / "app.conf", m))
        out += self._metadata_lookups(lookups, views, m)
        out.append(self._expected_telemetry(lookups, views))
        out += self._tuning_lookups(lookups)
        out.append(self._readme(root / "README.md", m, views))
        (root / "metadata").mkdir(exist_ok=True)
        out.append(self._default_meta(root / "metadata" / "default.meta"))
        return out

    # ------------------------------------------------------------------ conf files
    def _eventtypes(self, path: Path, views: list[DCView], m: AttackModel) -> Path:
        lines = [
            f"# Generated by mitremap from ATT&CK v{m.version}. Do not edit; override in local/eventtypes.conf.",
            "# One eventtype per (data component, feed). The umbrella eventtype per data component ORs its feeds.",
            "# Eventtypes cannot expand macros or run subsearches: index and sourcetype values are literal, from config/stack.yml.",
            "",
        ]
        for v in views:
            if not v.in_scope:
                continue
            in_scope = [f for f in v.feeds if f.in_scope]
            lines.append(f"# ---- {v.dc.id} {v.dc.name} ({v.dc.url})")
            for f in in_scope:
                lines.append(f"[{f.eventtype}]")
                lines.append(f"search = {eventtype_search(f)}")
                feed = config.feed(f.feed)
                desc = f"ATT&CK {v.dc.id} {v.dc.name} via {feed['label']}. Sources: {', '.join(f.sources)}."
                if f.unfiltered:
                    desc += " No event-level filter: ATT&CK references this feed as a whole for this component."
                lines.append(f"description = {_q(desc)}")
                if f.hunt_only:
                    lines.append("disabled = 1")
                    lines.append("# hunt-only feed: enable when a capture is loaded")
                elif not f.have:
                    lines.append("disabled = 1")
                    lines.append(f"# feed '{f.feed}' is not ticked in config/stack.yml; enable when it is forwarded")
                lines.append("")
            lines.append(f"[{v.eventtype}]")
            lines.append("search = " + " OR ".join(f"eventtype={f.eventtype}" for f in in_scope))
            lines.append(f"description = ATT&CK {v.dc.id} {v.dc.name} (umbrella over {len(in_scope)} feeds). {_q(v.dc.description[:200])}")
            lines.append("priority = 5")
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _tags(self, path: Path, views: list[DCView]) -> Path:
        lines = ["# Generated by mitremap. mitre_attack / mitre_dcXXXX tags on every eventtype;",
                 "# CIM tags only where the feed's TA is known to populate that data model's fields.", ""]
        for v in views:
            if not v.in_scope:
                continue
            for f in [f for f in v.feeds if f.in_scope]:
                lines.append(f"[eventtype={f.eventtype}]")
                lines.append("mitre_attack = enabled")
                lines.append(f"{v.dc.id.lower()} = enabled")
                lines.append(f"mitre_feed_{f.feed} = enabled")
                if f.cim_compliant and v.cim:
                    for t in v.cim.get("tags", []):
                        lines.append(f"{t} = enabled")
                lines.append("")
            lines.append(f"[eventtype={v.eventtype}]")
            lines.append("mitre_attack = enabled")
            lines.append(f"{v.dc.id.lower()} = enabled")
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _macros(self, path: Path, views: list[DCView], m: AttackModel) -> Path:
        lines = ["# Generated by mitremap. Macros are the tuning surface for analytics (phase 2).",
                 "# They are deliberately separate from eventtypes, which cannot expand macros.", "",
                 "# ---- index macros (one per feed in config/stack.yml)"]
        for name, f in config.stack().items():
            if f.get("virtual") or not f.get("index"):
                continue
            lines += [f"[mitre_idx_{name}]", f"definition = index={f['index']}", f"description = Index for feed {name}: {f['label']}", ""]
        lines.append("# ---- sourcetype macros for feeds that ship several logs (so analytics do not hard-code sourcetype names)")
        for name, f in config.stack().items():
            tmpl = f.get("sourcetype_template")
            if not tmpl or "{log}" not in tmpl or f.get("render") is False:
                continue
            for log in f.get("default_logs", []):
                lines += [f"[mitre_st_{name}_{log}]", f'definition = sourcetype="{tmpl.format(log=log)}"', f"description = {f['label'].split(' (')[0]}: {log} log", ""]
        from ..health import ta_macros
        lines.append("# ---- telemetry health (generated from config/stack.yml)")
        for stanza, definition, desc in ta_macros():
            lines += [f"[{stanza}]", f"definition = {definition}", f"description = {desc}", "iseval = 0", ""]
        lines.append("# ---- environment / tuning macros")
        for stanza, definition, desc in ENV_MACROS:
            lines.append(f"[{stanza}]")
            if "(" in stanza:
                n = int(stanza[stanza.index("(") + 1:-1])
                args = {"mitre_time_window(1)": "span", "mitre_is_internal(1)": "ip", "mitre_hosts_with_role(1)": "role", "mitre_accounts_with_role(1)": "role", "mitre_ctime(1)": "field"}.get(stanza)
                if args:
                    lines.append(f"args = {args}")
            lines += [f"definition = {definition}", f"description = {desc}", "iseval = 0", ""]
        lines.append("# ---- per data component")
        for v in views:
            if not v.in_scope:
                continue
            dcid = v.dc.id.lower()
            lines += [f"[mitre_{dcid}]", f"definition = eventtype={v.eventtype}", f"description = ATT&CK {v.dc.id} {v.dc.name}: all feeds", ""]
            for f in [f for f in v.feeds if f.in_scope]:
                lines += [f"[mitre_{dcid}_{f.feed}]", f"definition = eventtype={f.eventtype}", f"description = ATT&CK {v.dc.id} {v.dc.name} via {f.feed}", ""]
            lines += [f"[mitre_{dcid}_filter]", "definition = search *", f"description = Site-wide exclusions for {v.dc.id} {v.dc.name}; analytics append this. Edit in local/macros.conf, e.g. search NOT dest=scanner01", ""]
            if v.cim:
                dm, ds = v.cim["datamodel"], v.cim.get("dataset") or v.cim["datamodel"]
                where = v.cim.get("where") or ""
                lines += [f"[mitre_{dcid}_dm]", f"definition = datamodel={dm}.{ds}", f"description = CIM data model for {v.dc.id} {v.dc.name}; use with tstats: | tstats count from `mitre_{dcid}_dm` where `mitre_{dcid}_dm_where` by ...", ""]
                lines += [f"[mitre_{dcid}_dm_where]", f"definition = nodename={ds}" + (f" {where}" if where else ""), f"description = tstats where-clause for {v.dc.id} ({dm}.{ds})", ""]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _transforms(self, path: Path) -> Path:
        lines = ["# Generated by mitremap. Lookup definitions: ATT&CK metadata + tuning allowlists.", ""]
        for name in ["mitre_attack_data_components", "mitre_attack_log_sources", "mitre_attack_analytics", "mitre_attack_detection_strategies", "mitre_attack_techniques", "mitre_attack_feeds", "mitre_expected_telemetry"]:
            lines += [f"[{name}]", f"filename = {name}.csv", "case_sensitive_match = false", ""]
        for name, (_, _, opts) in TUNING_LOOKUPS.items():
            lines += [f"[{name}]", f"filename = {name}.csv"]
            lines += [f"{k} = {v}" for k, v in opts.items()]
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _app_conf(self, path: Path, m: AttackModel) -> Path:
        path.write_text(
            "[install]\nis_configured = 1\nstate = enabled\n\n"
            "[ui]\nis_visible = 0\nlabel = MITRE ATT&CK Data Components\n\n"
            f"[launcher]\nauthor = mitremap\ndescription = ATT&CK v{m.version} data components as eventtypes, tags, macros and lookups\nversion = 0.1.0\n\n"
            "[package]\nid = TA-mitre-attack-datacomponents\ncheck_for_updates = 0\n",
            encoding="utf-8",
        )
        return path

    def _default_meta(self, path: Path) -> Path:
        path.write_text("[]\naccess = read : [ * ], write : [ admin, sc_admin ]\nexport = system\n", encoding="utf-8")
        return path

    # ------------------------------------------------------------------ lookups
    def _metadata_lookups(self, lookups: Path, views: list[DCView], m: AttackModel) -> list[Path]:
        out = []
        p = lookups / "mitre_attack_data_components.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["dc_id", "dc_name", "eventtype", "in_scope", "live_feeds", "ready_feeds", "cim_datamodel", "analytics", "detection_strategies", "techniques", "attack_version", "url"])
            for v in views:
                w.writerow([v.dc.id, v.dc.name, v.eventtype if v.in_scope else "", int(v.in_scope),
                            "|".join(f.feed for f in v.live_feeds), "|".join(f.feed for f in v.ready_feeds),
                            f"{v.cim['datamodel']}.{v.cim.get('dataset','')}" if v.cim else "", v.analytics, len(v.detection_strategies), len(v.techniques), m.version, v.dc.url])
        out.append(p)
        p = lookups / "mitre_attack_log_sources.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["dc_id", "dc_name", "log_source", "refs", "feed", "have", "in_scope", "eventtype", "sourcetypes", "constraint_origin"])
            for v in views:
                for f in v.feeds:
                    for src in f.sources:
                        sv = next((s for s in v.sources if s.canonical == src), None)
                        w.writerow([v.dc.id, v.dc.name, src, sv.refs if sv else "", f.feed, int(f.have), int(f.in_scope), f.eventtype if f.in_scope else "", "|".join(f.sourcetypes), f.origin])
        out.append(p)
        p = lookups / "mitre_attack_analytics.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            from ..analytics import all_views
            w.writerow(["an_id", "an_name", "det_id", "technique_id", "technique_name", "tactics", "platforms", "dc_ids", "log_sources", "mutable_elements",
                        "coverage", "status", "content_type", "suggested_content_type", "detection_title", "technique_usage_score", "url"])
            for v in all_views(m):
                an, te = v.an, v.technique
                w.writerow([an.id, an.name, an.det_id, te.id if te else "", te.name if te else "", "|".join(te.tactics) if te else "",
                            "|".join(an.platforms), "|".join(sorted({r.dc_id for r in an.log_source_refs if r.dc_id})),
                            "|".join(sorted({r.name.strip() for r in an.log_source_refs})), "|".join(me.get("field", "") for me in an.mutable_elements),
                            v.coverage, v.status if v.status != "none" else "backlog", v.content_type if v.implemented else "", v.suggested_content_type,
                            v.title if v.implemented else "", v.priority, an.url])
        out.append(p)
        p = lookups / "mitre_attack_detection_strategies.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["det_id", "det_name", "technique_id", "technique_name", "tactics", "an_ids", "analytics", "url"])
            for ds in sorted(m.detection_strategies.values(), key=lambda d: d.id):
                te = m.techniques.get(ds.technique_id)
                w.writerow([ds.id, ds.name, ds.technique_id, te.name if te else "", "|".join(te.tactics) if te else "", "|".join(ds.analytic_ids), len(ds.analytic_ids), ds.url])
        out.append(p)
        p = lookups / "mitre_attack_techniques.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["technique_id", "technique_name", "parent_id", "tactics", "platforms", "det_ids", "url"])
            for te in sorted(m.techniques.values(), key=lambda t: t.id):
                w.writerow([te.id, te.name, te.parent_id or "", "|".join(te.tactics), "|".join(te.platforms), "|".join(te.det_ids), te.url])
        out.append(p)
        p = lookups / "mitre_attack_feeds.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["feed", "label", "have", "render", "platforms", "index", "constraint_field", "sourcetypes", "ta"])
            for name, f in config.stack().items():
                sts = f.get("sourcetypes") or ([f["sourcetype"]] if f.get("sourcetype") else []) or ([f["sourcetype_template"]] if f.get("sourcetype_template") else [])
                w.writerow([name, f["label"], int(bool(f.get("have"))), int(f.get("render", True) is not False), "|".join(f.get("platforms", [])), f.get("index", ""), f.get("constraint_field", "sourcetype"), "|".join(sts), f.get("ta", "")])
        out.append(p)
        return out

    def _expected_telemetry(self, lookups: Path, views: list[DCView]) -> Path:
        from ..health import expected_telemetry
        p = lookups / "mitre_expected_telemetry.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["feed", "have", "index", "field", "value", "data_components", "eventtypes"])
            for r in expected_telemetry(views):
                w.writerow([r.feed, int(r.have), r.index, r.field, r.value, "|".join(r.data_components), r.eventtypes])
        return p

    def _tuning_lookups(self, lookups: Path) -> list[Path]:
        out = []
        for name, (header, rows, _) in TUNING_LOOKUPS.items():
            p = lookups / f"{name}.csv"
            if p.exists():
                # never clobber a tuned lookup; only (re)create missing ones
                out.append(p)
                continue
            with p.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(header)
                w.writerows(rows)
            out.append(p)
        return out

    def _readme(self, path: Path, m: AttackModel, views: list[DCView]) -> Path:
        live = sum(1 for v in views if v.live_feeds)
        ready = sum(1 for v in views if v.in_scope and not v.live_feeds)
        text = f"""# {APP}

ATT&CK v{m.version} Enterprise data components rendered as Splunk knowledge objects.

| Object | File | Purpose |
|---|---|---|
| Eventtypes | `default/eventtypes.conf` | One per (data component, feed) plus an umbrella per data component. Literal `index`/`sourcetype`/`EventCode` constraints. |
| Tags | `default/tags.conf` | `mitre_attack`, `dcXXXX`, `mitre_feed_<feed>` on every eventtype; CIM tags only where the feed's TA is CIM compliant for that model. |
| Macros | `default/macros.conf` | Index macros, per-component `mitre_dcXXXX*` macros (umbrella, per feed, `_filter`, `_dm`, `_dm_where`) and environment macros. For analytics, not eventtypes. |
| Lookups | `lookups/mitre_attack_*.csv` | ATT&CK metadata (components, log sources, analytics, detection strategies, techniques, feeds). |
| Tuning lookups | `lookups/mitre_allowlist_*.csv`, `mitre_asset_roles.csv`, ... | Seed rows only. Analytics reference these by name; edit them in place (they are never overwritten by a rebuild). |

Components with at least one live feed: {live}. In scope but waiting on a feed you have not ticked: {ready}. Total: {len(views)}.

## Install

1. Edit `config/stack.yml` in the repo: tick `have: true` on the feeds you forward, set `index` and `sourcetypes` to match your environment, rebuild (`make build`).
   Or install as is and override stanzas in `local/eventtypes.conf`.
2. Copy this directory to `$SPLUNK_HOME/etc/apps/` on search heads (and on ES search heads for the analytics phase). Restart or debug/refresh.
3. Check: `| eventcount summarize=false index=* | search index IN (sysmon, wineventlog, corelight, pan_logs, epo)` then `eventtype=mitre_dc0032_process_creation | stats count by eventtype`.

## Notes

* Eventtypes for feeds not ticked are shipped `disabled = 1`; enable when the feed arrives.
* Windows event log, Sysmon and PowerShell eventtypes match on `source=XmlWinEventLog:<channel>`, which is correct for Splunk_TA_windows 5.0+ (sourcetype `XmlWinEventLog`) and for older versions alike.
* `wireshark` eventtypes are hunt-only and disabled.
* Eventtypes are not usable with `tstats`. For high-volume components use the `mitre_dcXXXX_dm` / `_dm_where` macros against accelerated CIM data models.
* No `props.conf`: field extraction is the job of the source TAs listed in `lookups/mitre_attack_feeds.csv`.
"""
        path.write_text(text, encoding="utf-8")
        return path
