"""Automatische Aktualisierung der lokalen CVE-Wissensbasis."""
from __future__ import annotations

import datetime as dt

from . import config, database, feeds

_LAST_UPDATE_KEY = "last_nvd_update"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def last_update() -> dt.datetime | None:
    raw = database.get_meta(_LAST_UPDATE_KEY)
    return dt.datetime.fromisoformat(raw) if raw else None


def is_due() -> bool:
    """True, wenn seit dem letzten Update mehr als das Intervall vergangen ist."""
    last = last_update()
    if last is None:
        return True
    age = _now() - last
    return age.total_seconds() > config.UPDATE_INTERVAL_HOURS * 3600


def update(days: int = 7, force: bool = False) -> int:
    """Holt aktuelle CVEs vom NVD und schreibt sie in die lokale DB.

    Gibt die Anzahl aktualisierter Datensaetze zurueck. Bei `force=False`
    passiert nichts, wenn noch kein Update faellig ist (ideal fuer Auto-Runs).
    """
    database.init()
    if not force and not is_due():
        return 0
    written = database.upsert_cves(feeds.fetch_nvd_recent(days=days))
    database.set_meta(_LAST_UPDATE_KEY, _now().isoformat())
    return written


def auto_update() -> int:
    """Fuehrt ein Update nur aus, wenn faellig - fuer Aufruf vor jedem Scan."""
    try:
        return update(force=False)
    except Exception:
        # Ein fehlgeschlagenes Auto-Update darf einen Scan nie blockieren.
        return 0
