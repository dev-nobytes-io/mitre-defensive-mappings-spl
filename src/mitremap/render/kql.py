"""KQL renderer stub (Microsoft Sentinel / Defender advanced hunting, and Kibana KQL).

Config already carries `kql.table` per log source in config/log_sources.yml and a
`kql` slot in each content/data_components/*.yml. Implementing this renderer means
emitting, per data component, a KQL `let` function or a watchlist-backed union over
the mapped tables, analogous to the Splunk umbrella eventtype.
"""
from __future__ import annotations

from pathlib import Path

from ..build import DCView
from ..model import AttackModel


class KqlRenderer:
    name = "kql"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        raise NotImplementedError("KQL rendering is reserved for a later phase; see docs/roadmap.md")
