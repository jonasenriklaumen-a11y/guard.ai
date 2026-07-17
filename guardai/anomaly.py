"""Unueberwachte Anomalieerkennung fuer Quelldateien.

Idee: Statt nach bekannten Signaturen zu suchen, lernt das Modell die "Norm"
eines Projekts (typische Groesse, Entropie, Zeilenlaenge, Anteil verdaechtiger
Muster) und markiert Dateien, die stark davon abweichen - etwa eingeschmuggelte,
verschleierte oder minimierte Payloads.

Nutzt sklearn.IsolationForest, wenn verfuegbar; sonst einen robusten
Fallback ueber den modifizierten Z-Score (Median/MAD).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

from . import config

try:  # ML optional halten
    import numpy as np
    from sklearn.ensemble import IsolationForest

    _HAS_SKLEARN = True
except Exception:  # pragma: no cover
    _HAS_SKLEARN = False

# Muster, die haeufig in verschleiertem/boesartigem Code auftauchen.
_SUSPICIOUS = [
    re.compile(r"eval\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"base64|b64decode|atob|fromCharCode", re.I),
    re.compile(r"(child_process|os\.system|subprocess|Runtime\.getRuntime)"),
    re.compile(r"(curl|wget|Invoke-WebRequest|powershell\s+-e)", re.I),
    re.compile(r"\\x[0-9a-fA-F]{2}"),
]

_TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php", ".go",
    ".rs", ".c", ".cpp", ".h", ".sh", ".ps1", ".pl", ".lua", ".sql",
}
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

_FEATURE_NAMES = ["size", "entropy", "max_line", "avg_line", "nonascii_ratio", "suspicious"]


@dataclass
class Anomaly:
    path: str
    score: float          # hoeher = auffaelliger
    reasons: list[str]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def extract_features(path: Path) -> tuple[list[float], list[str]] | None:
    """Berechnet Merkmale einer Datei. None bei nicht-analysierbaren Dateien."""
    try:
        raw = path.read_bytes()
    except Exception:
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines() or [""]
    line_lengths = [len(ln) for ln in lines]
    nonascii = sum(1 for ch in text if ord(ch) > 127)

    reasons: list[str] = []
    entropy = _shannon_entropy(raw)
    max_line = max(line_lengths)
    nonascii_ratio = nonascii / max(len(text), 1)

    suspicious = 0
    for pat in _SUSPICIOUS:
        if pat.search(text):
            suspicious += 1
            reasons.append(f"Muster: {pat.pattern}")
    if entropy > 5.8:
        reasons.append(f"hohe Entropie ({entropy:.2f})")
    if max_line > 2000:
        reasons.append(f"sehr lange Zeile ({max_line} Zeichen, evtl. minifiziert/Payload)")
    if nonascii_ratio > 0.3:
        reasons.append(f"viele Nicht-ASCII-Zeichen ({nonascii_ratio:.0%})")

    features = [
        float(len(raw)),
        entropy,
        float(max_line),
        sum(line_lengths) / len(line_lengths),
        nonascii_ratio,
        float(suspicious),
    ]
    return features, reasons


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES:
            yield path


def scan(root: Path, top: int = 20) -> list[Anomaly]:
    """Analysiert alle Quelldateien unter `root` und liefert die auffaelligsten."""
    samples: list[tuple[Path, list[float], list[str]]] = []
    for path in _iter_files(root):
        feat = extract_features(path)
        if feat:
            samples.append((path, feat[0], feat[1]))
    if not samples:
        return []

    if _HAS_SKLEARN and len(samples) >= 8:
        scores = _score_isolation_forest([s[1] for s in samples])
    else:
        scores = _score_zscore([s[1] for s in samples])

    results = [
        Anomaly(path=str(p), score=round(sc, 4), reasons=reasons)
        for (p, _feat, reasons), sc in zip(samples, scores)
    ]
    # Auch Dateien mit konkreten Regel-Treffern nach oben ziehen.
    results.sort(key=lambda a: (a.score, len(a.reasons)), reverse=True)
    return results[:top]


def _score_isolation_forest(feats: list[list[float]]) -> list[float]:
    X = np.array(feats, dtype=float)
    # Log-Skalierung fuer Groessen-Merkmale daempft Ausreisser-Dominanz.
    X[:, 0] = np.log1p(X[:, 0])
    X[:, 2] = np.log1p(X[:, 2])
    model = IsolationForest(
        contamination=config.ANOMALY_CONTAMINATION,
        random_state=42,
        n_estimators=200,
    )
    model.fit(X)
    # score_samples: niedriger = anomaler -> invertieren, damit hoeher = auffaelliger.
    raw = -model.score_samples(X)
    return raw.tolist()


def _score_zscore(feats: list[list[float]]) -> list[float]:
    """Fallback ohne sklearn: robuster Z-Score ueber Median/MAD, aggregiert."""
    cols = list(zip(*feats))
    scores = [0.0] * len(feats)
    for col in cols:
        med = sorted(col)[len(col) // 2]
        mad = sorted(abs(x - med) for x in col)[len(col) // 2] or 1.0
        for i, x in enumerate(col):
            scores[i] += abs(0.6745 * (x - med) / mad)
    return [s / len(cols) for s in scores]
