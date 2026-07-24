"""Lokale SQLite-Ablage der Schwachstellen-Definitionen."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Iterable, Iterator

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id            TEXT PRIMARY KEY,      -- z.B. CVE-2024-1234
    published     TEXT,
    modified      TEXT,
    severity      TEXT,                  -- LOW/MEDIUM/HIGH/CRITICAL
    cvss          REAL,
    summary       TEXT,
    refs          TEXT                   -- JSON-Liste von URLs
);
CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(modified);
CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(id, summary);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    with connect() as conn:
        conn.executescript(_SCHEMA)


def upsert_cves(rows: Iterable[dict]) -> int:
    """Speichert/aktualisiert CVE-Datensaetze. Gibt Anzahl geschriebener Zeilen zurueck."""
    count = 0
    with connect() as conn:
        for r in rows:
            conn.execute(
                """INSERT INTO cves(id, published, modified, severity, cvss, summary, refs)
                   VALUES(:id, :published, :modified, :severity, :cvss, :summary, :refs)
                   ON CONFLICT(id) DO UPDATE SET
                     modified=excluded.modified, severity=excluded.severity,
                     cvss=excluded.cvss, summary=excluded.summary, refs=excluded.refs""",
                {
                    "id": r["id"],
                    "published": r.get("published"),
                    "modified": r.get("modified"),
                    "severity": r.get("severity"),
                    "cvss": r.get("cvss"),
                    "summary": r.get("summary", ""),
                    "refs": json.dumps(r.get("refs", [])),
                },
            )
            # FTS-Spiegelung fuer Volltextsuche.
            conn.execute("DELETE FROM cves_fts WHERE id = ?", (r["id"],))
            conn.execute(
                "INSERT INTO cves_fts(id, summary) VALUES(?, ?)",
                (r["id"], r.get("summary", "")),
            )
            count += 1
    return count


def search(keyword: str, limit: int = 25) -> list[sqlite3.Row]:
    """Volltextsuche in den CVE-Zusammenfassungen."""
    # Als Phrase quoten: Zeichen wie '-' oder '.' sind sonst FTS5-Syntaxfehler.
    query = '"' + keyword.replace('"', '""') + '"'
    with connect() as conn:
        return conn.execute(
            """SELECT c.* FROM cves_fts f JOIN cves c ON c.id = f.id
               WHERE cves_fts MATCH ? ORDER BY c.cvss DESC LIMIT ?""",
            (query, limit),
        ).fetchall()


def count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]


def set_meta(key: str, value: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def get_meta(key: str) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None
