"""Abruf oeffentlicher Schwachstellen-Feeds.

- NVD 2.0: allgemeine CVE-Definitionen (fuer die lokale Wissensbasis).
- OSV.dev: praezise Abfrage pro Paket/Version (fuer das Repo-Scanning).
"""
from __future__ import annotations

import datetime as dt
import time
from typing import Iterable

import requests

from . import config


def _severity_from_metrics(metrics: dict) -> tuple[str | None, float | None]:
    """Extrahiert Basis-Severity und CVSS-Score aus dem NVD-Metrics-Block."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return sev, score
    return None, None


def fetch_nvd_recent(days: int = 7, page_size: int = 200) -> Iterable[dict]:
    """Holt CVEs, die in den letzten `days` Tagen geaendert wurden.

    Nutzt die NVD-2.0-API mit Zeitfenster. Ohne API-Key gilt ein Rate-Limit
    (ca. 5 Anfragen / 30 s), daher pausieren wir zwischen den Seiten.
    """
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=days)
    start_idx = 0
    while True:
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": page_size,
            "startIndex": start_idx,
        }
        resp = requests.get(config.NVD_API, params=params, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            descs = cve.get("descriptions", [])
            summary = next(
                (d["value"] for d in descs if d.get("lang") == "en"),
                descs[0]["value"] if descs else "",
            )
            sev, score = _severity_from_metrics(cve.get("metrics", {}))
            refs = [r["url"] for r in cve.get("references", [])]
            yield {
                "id": cve["id"],
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
                "severity": sev,
                "cvss": score,
                "summary": summary,
                "refs": refs,
            }

        total = data.get("totalResults", 0)
        start_idx += page_size
        if start_idx >= total:
            break
        time.sleep(6)  # freundlich zum oeffentlichen NVD-Rate-Limit bleiben


def query_osv(package: str, version: str | None, ecosystem: str) -> list[dict]:
    """Fragt OSV.dev nach Schwachstellen fuer ein konkretes Paket.

    Rueckgabe: Liste von {id, summary, severity, refs}.
    """
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    resp = requests.post(config.OSV_API, json=payload, timeout=config.HTTP_TIMEOUT)
    resp.raise_for_status()
    vulns = resp.json().get("vulns", [])
    out = []
    for v in vulns:
        sev = None
        for s in v.get("severity", []):
            sev = s.get("score")  # CVSS-Vektor als String
        out.append(
            {
                "id": v.get("id"),
                "summary": v.get("summary") or v.get("details", "")[:200],
                "severity": sev,
                "refs": [r.get("url") for r in v.get("references", [])],
                "aliases": v.get("aliases", []),
            }
        )
    return out
