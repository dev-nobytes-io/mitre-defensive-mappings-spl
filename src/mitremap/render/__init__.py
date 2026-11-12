"""Renderers turn DCViews into platform content.

Each renderer implements `render(model, views) -> list[Path]`. Splunk and Sigma are
implemented; KQL and ES|QL are stubs that keep the interface and config keys so the
next phase can fill them in without restructuring.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..build import DCView
from ..model import AttackModel


class Renderer(Protocol):
    name: str

    def render(self, m: AttackModel, views: list[DCView]) -> list[Path]: ...


def all_renderers() -> dict[str, "Renderer"]:
    from . import detections, docs, docs_analytics, docs_strategies, esql, kql, sigma, splunk
    return {r.name: r for r in (splunk.SplunkRenderer(), detections.DetectionsRenderer(), sigma.SigmaRenderer(), kql.KqlRenderer(), esql.EsqlRenderer(),
                                docs.DocsRenderer(), docs_analytics.AnalyticsDocsRenderer(), docs_strategies.StrategiesDocsRenderer())}
