#!/usr/bin/env bash
# guardai-Installer fuer Linux.
# Legt eine venv an, installiert guardai (mit ML-Extras) und richtet optional
# einen systemd-User-Timer fuer automatische CVE-Updates ein.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${GUARDAI_VENV:-$HOME/.local/share/guardai/venv}"
PY="${PYTHON:-python3}"

echo ">> guardai wird nach $VENV_DIR installiert"
"$PY" -m venv "$VENV_DIR"
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
pip install -e "$REPO_DIR[ml]"

# Symlink nach ~/.local/bin, damit `guardai` im PATH ist.
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$VENV_DIR/bin/guardai" "$BIN_DIR/guardai"
echo ">> Symlink: $BIN_DIR/guardai -> $VENV_DIR/bin/guardai"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "   Hinweis: $BIN_DIR liegt nicht im PATH. Ergaenze es in ~/.bashrc:"
     echo "            export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# git wird nur fuer das direkte Klonen von GitHub-URLs benoetigt.
if ! command -v git >/dev/null 2>&1; then
  echo "   Hinweis: 'git' fehlt - fuer 'guardai scan <github-url>' bitte installieren"
  echo "            (z.B. sudo apt install git)."
fi

# Optional: systemd-User-Timer fuer taegliche Updates einrichten.
if command -v systemctl >/dev/null 2>&1 && [ "${GUARDAI_NO_TIMER:-0}" != "1" ]; then
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  sed "s#@GUARDAI@#$VENV_DIR/bin/guardai#g" \
      "$REPO_DIR/systemd/guardai-update.service" > "$UNIT_DIR/guardai-update.service"
  cp "$REPO_DIR/systemd/guardai-update.timer" "$UNIT_DIR/guardai-update.timer"
  systemctl --user daemon-reload
  systemctl --user enable --now guardai-update.timer
  echo ">> systemd-User-Timer 'guardai-update.timer' aktiviert (taeglich)."
  echo "   Status: systemctl --user status guardai-update.timer"
else
  echo ">> systemd uebersprungen (nicht verfuegbar oder GUARDAI_NO_TIMER=1)."
fi

echo ">> Fertig. Teste mit:  guardai --version  &&  guardai scan ."
