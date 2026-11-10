"""mitremap: MITRE ATT&CK v20 detection model mapped onto Splunk and Sigma."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ATTACK_DIR = ROOT / "attack"
CONFIG_DIR = ROOT / "config"
CONTENT_DIR = ROOT / "content"
DIST_DIR = ROOT / "dist"
DOCS_DIR = ROOT / "docs"

__all__ = ["ROOT", "ATTACK_DIR", "CONFIG_DIR", "CONTENT_DIR", "DIST_DIR", "DOCS_DIR"]
