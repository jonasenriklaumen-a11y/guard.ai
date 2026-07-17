# guardai

Defensiver Schwachstellen- und Anomalie-Scanner. Zieht seine Informationen aus
öffentlichen Feeds ([NVD/CVE](https://nvd.nist.gov/) und
[OSV.dev](https://osv.dev/)), prüft Repos gegen bekannte Schwachstellen,
aktualisiert seine Definitionen automatisch und markiert mit einem ML-Modell
auffällige Dateien. Läuft lokal oder als GitHub-Action.

## Ehrlicher Hinweis zu „Zero-Days"

Ein echter Zero-Day steht per Definition in **keiner** Datenbank – kein Tool
lädt dafür fertige Signaturen. `guardai` macht stattdessen das, was real
funktioniert:

1. **Bekannte Schwachstellen (n-days)** aus NVD/OSV sofort nach Veröffentlichung
   gegen deine Abhängigkeiten prüfen.
2. **Unbekannte Auffälligkeiten** per unüberwachtem ML-Modell (Isolation Forest)
   erkennen – z. B. eingeschleuste, verschleierte oder minifizierte Payloads,
   die von der Norm des Projekts abweichen.

Das ersetzt kein Endpoint-AV mit Kernel-Zugriff, ist aber ein sinnvoller,
ehrlicher Schutz auf Repo-/Supply-Chain-Ebene.

## Installation

```bash
pip install -r requirements.txt   # oder: pip install ".[ml]"
```

`scikit-learn`/`numpy` sind optional. Fehlen sie, nutzt die Anomalieerkennung
einen statistischen Fallback (Median/MAD-Z-Score).

### Linux (empfohlen)

Ein-Zeilen-Setup inkl. venv, `guardai`-Kommando im PATH und optionalem
systemd-Timer für tägliche Updates:

```bash
chmod +x install.sh
./install.sh
```

Der Installer legt eine venv unter `~/.local/share/guardai/venv` an, verlinkt
`guardai` nach `~/.local/bin` und aktiviert – falls `systemctl` vorhanden – den
User-Timer `guardai-update.timer`. Steuerung per Umgebungsvariablen:

| Variable | Wirkung |
|---|---|
| `PYTHON=python3.12` | Interpreter für die venv wählen |
| `GUARDAI_VENV=/pfad` | venv-Zielverzeichnis überschreiben |
| `GUARDAI_NO_TIMER=1` | systemd-Timer nicht einrichten |

Timer prüfen bzw. sofort auslösen:

```bash
systemctl --user status guardai-update.timer
systemctl --user start  guardai-update.service   # manueller Lauf
journalctl --user -u guardai-update.service      # Logs
```

Daten liegen unter `~/.guardai` (via `Path.home()`, also z. B.
`/home/<user>/.guardai`). `git` wird nur für `guardai scan <github-url>`
benötigt (`sudo apt install git`).

## Nutzung

```bash
# Definitionen aktualisieren (holt aktuelle CVEs vom NVD)
python -m guardai update

# Lokales Projekt auf verwundbare Abhängigkeiten prüfen
python -m guardai scan .

# Direkt ein GitHub-Repo scannen (benötigt git im PATH)
python -m guardai scan https://github.com/user/repo

# ML-Anomalieerkennung über ein Verzeichnis
python -m guardai anomaly . --top 15

# Lokale CVE-Datenbank durchsuchen
python -m guardai search "openssl"
```

Unterstützte Manifeste: `requirements.txt`, `package.json`,
`package-lock.json`, `Cargo.toml`, `go.mod`.

## Automatische Updates

`scan` ruft vor jedem Lauf `auto_update()` auf: liegt das letzte Update länger
als `GUARDAI_UPDATE_HOURS` (Standard 12 h) zurück, werden die Definitionen
frisch geholt. Erzwingen mit `guardai update`, deaktivieren mit
`scan --no-auto-update`.

## GitHub-Integration

Kopiere [`.github/workflows/guardai.yml`](.github/workflows/guardai.yml) in das
zu schützende Repo. Der Workflow scannt bei jedem Push/PR und täglich per Cron.
`scan --fail-on high` gibt Exit-Code 2 zurück, sobald eine Schwachstelle der
Stufe HIGH oder höher gefunden wird – so schlägt die CI fehl.

## Konfiguration (Umgebungsvariablen)

| Variable | Standard | Bedeutung |
|---|---|---|
| `GUARDAI_HOME` | `~/.guardai` | Datenverzeichnis (DB, Modell, State) |
| `GUARDAI_UPDATE_HOURS` | `12` | Intervall des Auto-Updates |
| `GUARDAI_CONTAMINATION` | `0.05` | erwarteter Ausreißer-Anteil (Isolation Forest) |

## Tests

```bash
python -m pytest tests/        # oder: python tests/test_core.py
```

Die Tests laufen komplett offline.

## Architektur

| Modul | Aufgabe |
|---|---|
| `feeds.py` | Abruf von NVD- und OSV-Daten |
| `database.py` | lokale SQLite-Ablage inkl. Volltextsuche |
| `manifests.py` | Parsen der Abhängigkeits-Manifeste |
| `scanner.py` | Repo-Scan (lokal oder GitHub) gegen OSV |
| `anomaly.py` | ML-Anomalieerkennung über Quelldateien |
| `updater.py` | automatische Aktualisierung der Definitionen |
| `cli.py` | Kommandozeile |
