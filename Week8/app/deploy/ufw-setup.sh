#!/usr/bin/env bash
# Capa de red con UFW para Music Manager.
# Uso:   sudo ADMIN_IP=203.0.113.10 ./ufw-setup.sh        (SSH solo desde tu IP; recomendado)
#        sudo ./ufw-setup.sh                               (SSH abierto pero con límite de intentos)
#        DRY_RUN=1 sudo ./ufw-setup.sh                     (muestra qué haría, sin aplicar)
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
ADMIN_IP="${ADMIN_IP:-}"
DRY_RUN="${DRY_RUN:-0}"

[ "$(id -u)" -eq 0 ] || { echo "Ejecuta como root (sudo)." >&2; exit 1; }
command -v ufw >/dev/null 2>&1 || { echo "Instala ufw primero: apt install ufw" >&2; exit 1; }
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || { echo "SSH_PORT debe ser numérico." >&2; exit 1; }

UFW=(ufw)
[ "$DRY_RUN" = "1" ] && UFW=(ufw --dry-run)

# 1) Política por defecto: todo lo entrante se bloquea.
"${UFW[@]}" default deny incoming
"${UFW[@]}" default allow outgoing
"${UFW[@]}" default deny routed

# 2) SSH ANTES de activar el firewall, para no quedarte fuera del servidor.
if [ -n "$ADMIN_IP" ]; then
  "${UFW[@]}" allow from "$ADMIN_IP" to any port "$SSH_PORT" proto tcp comment 'SSH solo admin'
else
  "${UFW[@]}" limit "$SSH_PORT"/tcp comment 'SSH con limite de intentos'
fi

# 3) Solo el proxy inverso (nginx) es público.
"${UFW[@]}" allow 80/tcp  comment 'HTTP (redirige a HTTPS)'
"${UFW[@]}" allow 443/tcp comment 'HTTPS'

# 4) La app (gunicorn 8000 / Flask 5000) nunca debe ser alcanzable desde fuera.
"${UFW[@]}" deny 5000/tcp comment 'Flask desarrollo'
"${UFW[@]}" deny 8000/tcp comment 'gunicorn interno'

# 5) Registro de paquetes bloqueados.
"${UFW[@]}" logging medium

"${UFW[@]}" --force enable
"${UFW[@]}" status verbose
echo "Listo. Comprueba desde OTRA máquina:  nmap -Pn -p 22,80,443,5000,8000 <IP-del-servidor>"
