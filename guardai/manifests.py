"""Erkennt und parst Abhaengigkeits-Manifeste verschiedener Oekosysteme.

Bewusst leichtgewichtig gehalten (keine externen Parser): deckt die
haeufigsten Faelle ab. Rueckgabe je Fund: (ecosystem, name, version).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# OSV.dev-Oekosystem-Namen: https://ossf.github.io/osv-schema/#defined-ecosystems
_PY_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")


def _parse_requirements(path: Path) -> list[tuple[str, str, str | None]]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PY_LINE.match(line)
        if m:
            out.append(("PyPI", m.group(1), m.group(2)))
        else:
            # Paket ohne feste Version - trotzdem melden (Version unbekannt).
            name = re.split(r"[<>=!~\s\[]", line, 1)[0].strip()
            if name:
                out.append(("PyPI", name, None))
    return out


def _parse_package_json(path: Path) -> list[tuple[str, str, str | None]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            clean = re.sub(r"^[\^~>=<\s]+", "", str(ver)).split(" ")[0] or None
            out.append(("npm", name, clean))
    return out


def _parse_package_lock(path: Path) -> list[tuple[str, str, str | None]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    out = []
    for name, info in (data.get("packages") or {}).items():
        if name and isinstance(info, dict) and info.get("version"):
            pkg = name.split("node_modules/")[-1]
            out.append(("npm", pkg, info["version"]))
    return out


def _parse_cargo(path: Path) -> list[tuple[str, str, str | None]]:
    out, in_deps = [], False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("["):
            in_deps = "dependencies" in s
            continue
        if in_deps and "=" in s:
            name = s.split("=", 1)[0].strip().strip('"')
            m = re.search(r'"([0-9][^"]*)"', s)
            out.append(("crates.io", name, m.group(1) if m else None))
    return out


def _parse_go_mod(path: Path) -> list[tuple[str, str, str | None]]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = re.match(r"\s*([\w./\-]+)\s+v([\w.\-]+)", line)
        if m and "module " not in line and "go 1" not in line:
            out.append(("Go", m.group(1), "v" + m.group(2)))
    return out


_HANDLERS = {
    "requirements.txt": _parse_requirements,
    "package-lock.json": _parse_package_lock,
    "package.json": _parse_package_json,
    "Cargo.toml": _parse_cargo,
    "go.mod": _parse_go_mod,
}

# Verzeichnisse, die beim Durchlauf ignoriert werden.
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def discover(root: Path) -> list[tuple[str, str, str | None]]:
    """Durchsucht ein Verzeichnis nach Manifesten und sammelt Abhaengigkeiten.

    Deduplizieren: package-lock.json hat Vorrang vor package.json (praezisere
    Versionen), daher wird package.json uebersprungen, wenn ein Lock existiert.
    """
    found: list[tuple[str, str, str | None]] = []
    has_lock = any(root.rglob("package-lock.json"))
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        handler = _HANDLERS.get(path.name)
        if not handler:
            continue
        if path.name == "package.json" and has_lock:
            continue
        try:
            found.extend(handler(path))
        except Exception:
            continue  # kaputte/ungewoehnliche Manifeste ueberspringen, nicht abbrechen
    # Duplikate entfernen.
    return sorted(set(found))
