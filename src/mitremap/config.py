"""Load the YAML configuration files under config/."""
from __future__ import annotations

from functools import lru_cache

import yaml

from . import CONFIG_DIR


@lru_cache(maxsize=None)
def load(name: str) -> dict:
    with (CONFIG_DIR / f"{name}.yml").open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def stack() -> dict:
    return load("stack")["feeds"]


def log_sources() -> dict:
    return load("log_sources")


def cim() -> dict:
    return load("cim")["components"]


def sigma() -> dict:
    return load("sigma")


def platforms() -> dict:
    return load("platforms")


def feed(name: str) -> dict:
    try:
        return stack()[name]
    except KeyError as e:
        raise KeyError(f"feed {name!r} is not defined in config/stack.yml") from e
