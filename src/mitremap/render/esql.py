"""ES|QL renderer stub (Elastic).

Config already carries `elastic.dataset` per log source. Implementing this renderer
means emitting, per data component, an ES|QL `FROM <indices> | WHERE ...` prefix (or a
saved query) scoped the same way as the Splunk umbrella eventtype.
"""
from __future__ import annotations

from pathlib import Path

from ..build import DCView
from ..model import AttackModel


class EsqlRenderer:
    name = "esql"

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]:
        raise NotImplementedError("ES|QL rendering is reserved for a later phase; see docs/roadmap.md")
