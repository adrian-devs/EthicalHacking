#!/usr/bin/env bash
# Construye el historial del repo con las tres versiones de la app, guarda las
# salidas en bruto de los escaneres junto a cada version y crea las etiquetas
# v0-ai-baseline y v1-remediated.
#
# Uso:  scripts/build_history.sh BASE.zip FINAL.zip [INTERMEDIA.zip]
#   BASE.zip        music-manager.zip           (version original generada por IA)
#   FINAL.zip       music-manager-seguro-v3.zip (remediacion final)
#   INTERMEDIA.zip  opcional: primera remediacion, se guarda como commit "intermediate"
# Variables opcionales:
#   ZAP=1   en cada version pausa para que arranques la app y corre ZAP baseline con Docker
set -euo pipefail

{ [ $# -eq 2 ] || [ $# -eq 3 ]; } || { sed -n '2,13p' "$0"; exit 1; }
BASE=$(realpath "$1"); FINAL=$(realpath "$2"); MID=""; [ $# -eq 3 ] && MID=$(realpath "$3")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

[ -d .git ] || git init -q -b main
git config user.name  >/dev/null || git config user.name  "Estudiante"
git config user.email >/dev/null || git config user.email "estudiante@example.com"

# Archivos de gestion que se anaden en el commit final
HOLD=$(mktemp -d)
for f in findings.csv docs; do [ -e "$f" ] && mv "$f" "$HOLD/"; done

extract() {   # extract ZIP -> app/
  rm -rf app; mkdir app
  local tmp; tmp=$(mktemp -d)
  unzip -q "$1" -d "$tmp"
  rm -rf "$tmp/__MACOSX"
  if [ "$(ls -A "$tmp" | wc -l)" -eq 1 ] && [ -d "$tmp/$(ls "$tmp")" ]; then
    cp -a "$tmp/$(ls "$tmp")/." app/
  else cp -a "$tmp/." app/; fi
  rm -rf "$tmp"
  find app -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
  find app -name '*.db' -delete 2>/dev/null || true
}

scan() {      # scan STAGE -> scans/STAGE/*
  local out="scans/$1"; mkdir -p "$out"
  local reqs; reqs=$(find app -maxdepth 1 -name 'requirements*.txt' | sort || true)
  if command -v bandit >/dev/null; then
    bandit -r app -x app/tests -f json -o "$out/bandit.json" >/dev/null 2>"$out/bandit.stderr" || true
    bandit -r app -x app/tests -f txt  -o "$out/bandit.txt"  >/dev/null 2>&1 || true
  else echo "bandit no instalado" > "$out/bandit.SKIPPED"; fi
  if command -v pip-audit >/dev/null && [ -n "$reqs" ]; then
    for r in $reqs; do
      pip-audit -r "$r" -f json -o "$out/pip-audit-$(basename "$r" .txt).json" 2>"$out/pip-audit-$(basename "$r" .txt).stderr" || true
    done
  else echo "pip-audit no instalado o sin requirements.txt" > "$out/pip-audit.SKIPPED"; fi
  if command -v detect-secrets >/dev/null; then
    detect-secrets scan app > "$out/detect-secrets.json" 2>"$out/detect-secrets.stderr" || true
  else echo "detect-secrets no instalado" > "$out/detect-secrets.SKIPPED"; fi
  if [ "${ZAP:-0}" = "1" ]; then
    read -r -p "Arranca la app de '$1' (http://127.0.0.1:5000) en otra terminal y pulsa Enter... "
    docker run --rm --network host -v "$ROOT/$out":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
      zap-baseline.py -t http://127.0.0.1:5000 -J zap-baseline.json -r zap-baseline.html -I \
      > "$out/zap-baseline.log" 2>&1 || true
  elif [ -d "extra_scans/$1" ]; then cp -a "extra_scans/$1/." "$out/";   # salidas de ZAP ya generadas
  else echo "ZAP no ejecutado (usa ZAP=1)" > "$out/zap.SKIPPED"; fi
}

commit() { git add -A; git commit -q -m "$1"; }

# 0) Metadatos iniciales
git add PROMPTS.md README.md scripts .gitignore 2>/dev/null || true
git diff --cached --quiet || git commit -q -m "docs: PROMPTS.md, README y scripts"

# 1) Baseline
extract "$BASE"; scan v0-ai-baseline
commit "v0: aplicacion generada por IA (sin remediar) + escaneos en bruto"
git tag -f v0-ai-baseline >/dev/null

# 2) Intermedia (opcional)
if [ -n "$MID" ]; then
  extract "$MID"; scan intermediate
  commit "intermediate: primera remediacion + escaneos en bruto"
fi

# 3) Final
extract "$FINAL"; scan v1-remediated
for f in findings.csv docs; do [ -e "$HOLD/$f" ] && mv "$HOLD/$f" .; done
commit "v1-remediated: remediacion final, findings.csv, informe y escaneos en bruto"
git tag -f v1-remediated >/dev/null

echo; git log --oneline --decorate
echo; echo "Siguiente paso:  git remote add origin <URL>  &&  git push -u origin main --tags"
