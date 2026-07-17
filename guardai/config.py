"""Zentrale Konfiguration und Pfade."""
from __future__ import annotations

import os
from pathlib import Path

# Datenverzeichnis (ueberschreibbar per Umgebungsvariable, praktisch fuer CI).
DATA_DIR = Path(os.environ.get("GUARDAI_HOME", Path.home() / ".guardai"))
DB_PATH = DATA_DIR / "vulns.sqlite3"
MODEL_PATH = DATA_DIR / "anomaly_model.joblib"
STATE_PATH = DATA_DIR / "state.json"

# Oeffentliche Feeds (kein API-Key noetig).
# NVD 2.0 REST API - Rueckgabe der zuletzt geaenderten CVEs.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# OSV.dev - Abfrage von Schwachstellen pro Paket/Oekosystem.
OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"

# Wie oft (Stunden) die lokale CVE-DB automatisch aktualisiert wird.
UPDATE_INTERVAL_HOURS = int(os.environ.get("GUARDAI_UPDATE_HOURS", "12"))

# Schwellenwert fuer die Anomalieerkennung (Anteil erwarteter Ausreisser).
ANOMALY_CONTAMINATION = float(os.environ.get("GUARDAI_CONTAMINATION", "0.05"))

# HTTP-Timeout in Sekunden.
HTTP_TIMEOUT = 30


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
