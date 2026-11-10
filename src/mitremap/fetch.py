"""Download a pinned ATT&CK STIX release and write a slim, gzipped extract.

The full Enterprise bundle is ~55 MB; we commit only the objects the detection
model needs (data components, analytics, detection strategies, techniques,
tactics, and the relationships that tie them together).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from . import ATTACK_DIR

BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
MANIFEST = ATTACK_DIR / "manifest.json"

SLIM_TYPES = {
    "x-mitre-data-component",
    "x-mitre-analytic",
    "x-mitre-detection-strategy",
    "attack-pattern",
    "x-mitre-tactic",
    "x-mitre-matrix",
    "x-mitre-collection",
}
SLIM_RELATIONSHIPS = {"detects", "subtechnique-of", "revoked-by"}
# Fields that are large and irrelevant to detection engineering.
DROP_FIELDS = {"x_mitre_contributors", "object_marking_refs", "created_by_ref", "x_mitre_modified_by_ref"}


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def save_manifest(m: dict) -> None:
    MANIFEST.write_text(json.dumps(m, indent=2) + "\n")


def raw_path(domain: str, version: str) -> Path:
    return ATTACK_DIR / "raw" / f"{domain}-{version}.json"


def slim_path(domain: str, version: str) -> Path:
    return ATTACK_DIR / f"{domain}-{version}.slim.json.gz"


def download(domain: str, version: str, expected_sha256: str | None = None) -> Path:
    url = f"{BASE_URL}/{domain}/{domain}-{version}.json"
    dest = raw_path(domain, version)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        print(f"fetching {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=120) as r, dest.open("wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise SystemExit(f"sha256 mismatch for {dest}: {digest} != {expected_sha256}")
    return dest


def slim(bundle: dict) -> dict:
    out = []
    for o in bundle["objects"]:
        t = o["type"]
        if t in SLIM_TYPES or (t == "relationship" and o.get("relationship_type") in SLIM_RELATIONSHIPS):
            out.append({k: v for k, v in o.items() if k not in DROP_FIELDS})
    return {"type": "bundle", "id": bundle["id"], "spec_version": bundle.get("spec_version", "2.1"), "objects": out}


def write_slim(domain: str, version: str) -> Path:
    raw = json.loads(raw_path(domain, version).read_text())
    dest = slim_path(domain, version)
    with gzip.open(dest, "wt", encoding="utf-8", compresslevel=9) as f:
        json.dump(slim(raw), f, separators=(",", ":"))
    return dest


def load_slim(domain: str, version: str) -> dict:
    with gzip.open(slim_path(domain, version), "rt", encoding="utf-8") as f:
        return json.load(f)


def fetch(version: str | None = None, domain: str = "enterprise-attack", pin: bool = True) -> None:
    m = load_manifest()
    version = version or m["version"]
    expected = m.get("sha256", {}).get(f"{domain}-{version}")
    raw = download(domain, version, expected)
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    dest = write_slim(domain, version)
    if pin:
        m.setdefault("sha256", {})[f"{domain}-{version}"] = digest
        m["version"] = version
        save_manifest(m)
    print(f"wrote {dest} ({dest.stat().st_size/1e6:.1f} MB) sha256(raw)={digest}")
