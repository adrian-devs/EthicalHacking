#!/usr/bin/env bash
# Comprueba la exposición de red de Music Manager (ejecutar en el servidor).
set -u
echo "== Sockets en escucha (la app debe estar SOLO en 127.0.0.1) =="
ss -tlnH | awk '{print $4}' | sort -u
bad=$(ss -tlnH | awk '{print $4}' | grep -E '(^|:)(5000|8000)$' | grep -vE '^(127\.0\.0\.1|\[::1\]):' || true)
if [ -n "$bad" ]; then echo "FALLO: la app escucha en una interfaz pública: $bad"; exit 1
else echo "OK: ningún puerto de la app (5000/8000) escucha fuera de localhost."; fi
echo; echo "== Estado de UFW =="
if command -v ufw >/dev/null 2>&1; then ufw status verbose; else echo "ufw no instalado"; fi
