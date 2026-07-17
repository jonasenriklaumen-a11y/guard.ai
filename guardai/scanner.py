"""Repo-Scanner: prueft Abhaengigkeiten gegen OSV.dev.

Akzeptiert einen lokalen Pfad oder eine GitHub-URL (wird geklont, sofern
`git` verfuegbar ist).
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import feeds, manifests


@dataclass
class Finding:
    ecosystem: str
    package: str
    version: str | None
    vuln_id: str
    severity: str | None
    summary: str
    refs: list[str] = field(default_factory=list)


def _is_github_url(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@")) and "github" in target


def _clone(url: str, dest: Path) -> Path:
    """Klont ein GitHub-Repo flach. Erfordert `git` im PATH."""
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def scan_path(root: Path) -> list[Finding]:
    """Findet Abhaengigkeiten unter `root` und fragt OSV.dev pro Paket ab."""
    findings: list[Finding] = []
    deps = manifests.discover(root)
    for ecosystem, name, version in deps:
        try:
            vulns = feeds.query_osv(name, version, ecosystem)
        except Exception:
            continue  # Netzwerkfehler pro Paket tolerieren
        for v in vulns:
            findings.append(
                Finding(
                    ecosystem=ecosystem,
                    package=name,
                    version=version,
                    vuln_id=v["id"],
                    severity=v.get("severity"),
                    summary=v.get("summary") or "",
                    refs=v.get("refs", []),
                )
            )
    return findings


def scan(target: str) -> list[Finding]:
    """Scannt einen lokalen Pfad oder eine GitHub-URL."""
    if _is_github_url(target):
        with tempfile.TemporaryDirectory(prefix="guardai_") as tmp:
            root = _clone(target, Path(tmp) / "repo")
            return scan_path(root)
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"Pfad nicht gefunden: {target}")
    return scan_path(root)
