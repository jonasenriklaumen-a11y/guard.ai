"""Kommandozeilen-Schnittstelle fuer guardai."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, anomaly, database, scanner, updater

# Severity-Rang fuer Exit-Code-Entscheidung / Sortierung.
# MODERATE: so nennen OSV/GHSA-Advisories die Stufe MEDIUM.
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1, None: 0}


def _sev_rank(sev: str | None) -> int:
    if not sev:
        return 0
    up = sev.upper()
    for name, rank in _SEV_RANK.items():
        if name and name in up:
            return rank
    # CVSS-Vektor-String (z.B. "CVSS:3.1/AV:N/..."): keine Stufe ablesbar,
    # aber ein Fund mit Vektor ist ernst zu nehmen -> konservativ als HIGH werten.
    if up.startswith("CVSS:"):
        return _SEV_RANK["HIGH"]
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    print("Aktualisiere CVE-Wissensbasis vom NVD ...", file=sys.stderr)
    n = updater.update(days=args.days, force=True)
    print(f"{n} CVE-Datensaetze aktualisiert. Gesamt in DB: {database.count()}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if args.auto_update:
        updater.auto_update()
    findings = scanner.scan(args.target)
    findings.sort(key=lambda f: _sev_rank(f.severity), reverse=True)

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2, ensure_ascii=False))
    else:
        if not findings:
            print("Keine bekannten verwundbaren Abhaengigkeiten gefunden.")
        for f in findings:
            print(f"[{f.severity or '?':>8}] {f.package} {f.version or ''} "
                  f"-> {f.vuln_id}")
            if f.summary:
                print(f"           {f.summary[:100]}")
            if f.refs:
                print(f"           {f.refs[0]}")
        print(f"\n{len(findings)} Fund(e).", file=sys.stderr)

    # Exit-Code fuer CI: !=0, wenn Funde >= Schwellenwert-Severity.
    threshold = _SEV_RANK.get(args.fail_on.upper())
    if threshold and any(_sev_rank(f.severity) >= threshold for f in findings):
        return 2
    return 0


def cmd_anomaly(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"Pfad nicht gefunden: {root}", file=sys.stderr)
        return 1
    results = anomaly.scan(root, top=args.top)
    if args.json:
        print(json.dumps([a.__dict__ for a in results], indent=2, ensure_ascii=False))
    else:
        if not results:
            print("Keine analysierbaren Dateien gefunden.")
        for a in results:
            print(f"score={a.score:6.3f}  {a.path}")
            for r in a.reasons:
                print(f"           - {r}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    rows = database.search(args.keyword, limit=args.limit)
    for r in rows:
        print(f"{r['id']}  cvss={r['cvss']}  {r['severity']}")
        print(f"    {r['summary'][:120]}")
    if not rows:
        print("Nichts gefunden. Ggf. zuerst 'guardai update' ausfuehren.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="guardai",
        description="Defensiver Schwachstellen- und Anomalie-Scanner.",
    )
    p.add_argument("--version", action="version", version=f"guardai {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    up = sub.add_parser("update", help="CVE-Wissensbasis vom NVD aktualisieren")
    up.add_argument("--days", type=int, default=7, help="Zeitfenster in Tagen")
    up.set_defaults(func=cmd_update)

    sc = sub.add_parser("scan", help="Repo/Pfad auf verwundbare Abhaengigkeiten pruefen")
    sc.add_argument("target", help="Lokaler Pfad oder GitHub-URL")
    sc.add_argument("--json", action="store_true", help="Ausgabe als JSON")
    sc.add_argument("--no-auto-update", dest="auto_update", action="store_false",
                    help="Automatisches Update vor dem Scan deaktivieren")
    sc.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high", "critical"],
                    help="Ab welcher Severity Exit-Code 2 zurueckgegeben wird (fuer CI)")
    sc.set_defaults(func=cmd_scan)

    an = sub.add_parser("anomaly", help="Dateien per ML auf Auffaelligkeiten pruefen")
    an.add_argument("path", help="Zu analysierendes Verzeichnis")
    an.add_argument("--top", type=int, default=20, help="Anzahl auffaelligster Dateien")
    an.add_argument("--json", action="store_true", help="Ausgabe als JSON")
    an.set_defaults(func=cmd_anomaly)

    se = sub.add_parser("search", help="Lokale CVE-DB per Volltext durchsuchen")
    se.add_argument("keyword")
    se.add_argument("--limit", type=int, default=25)
    se.set_defaults(func=cmd_search)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    database.init()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
