# Music Manager (versión 3, endurecida)

Administrador personal de música escuchada con Flask. Incorpora las correcciones de dos
rondas de evaluación (CVE / CWE / CVSS / OWASP Top 10:2025). Resultados y pruebas en
`INFORME_SEGURIDAD.md`.

## Puesta en marcha (desarrollo)

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements.txt
python app.py                        # http://127.0.0.1:5000
```

Abre `/register`, crea tu cuenta (contraseña de 10 a 128 caracteres, no predecible: usa una
frase larga) y empieza. Cada usuario solo ve sus canciones.

> **Si vienes de la versión 1 o 2:** la tabla `user` ahora tiene `session_token` y `song` tiene
> `user_id`. `create_all()` no altera tablas existentes: borra `instance/music.db` (o `music.db`).

## Configuración (variables de entorno o `.env`, ver `.env.example`)

| Variable | Uso |
|---|---|
| `APP_ENV` | `production` exige `SECRET_KEY`, activa cookie `Secure`, HTTPS forzado y HSTS |
| `SECRET_KEY` | Clave de sesión (`python -c "import secrets; print(secrets.token_hex(32))"`) |
| `ALLOWED_HOSTS` | Hosts permitidos en la cabecera `Host` |
| `REGISTRATION_CODE` | Código de invitación para crear cuentas |
| `ALLOW_REGISTRATION` | `0` cierra el registro |
| `IDLE_TIMEOUT_MINUTES` | Cierre de sesión por inactividad (30 por defecto) |
| `TRUSTED_PROXY_COUNT` | Nº de proxies inversos de confianza (1 con nginx) |
| `RATELIMIT_STORAGE_URI` | `redis://...` si usas varios procesos |

## Producción: defensa en capas

```
Internet → UFW (solo 80/443 + SSH) → nginx (TLS, límites) → gunicorn 127.0.0.1:8000 → app → SQLite (0600)
```

Los archivos están en `deploy/`:

| Archivo | Función |
|---|---|
| `ufw-setup.sh` | Firewall: deniega todo lo entrante, abre 80/443, SSH limitado o solo desde tu IP, bloquea 5000/8000 |
| `verify-network.sh` | Comprueba que la app solo escucha en localhost y muestra el estado de UFW |
| `nginx-music-manager.conf` + `music-manager-proxy.conf` | TLS, redirección a HTTPS, límite en `/login`, tamaño máximo |
| `music-manager.service` + `music-manager.env.example` | Servicio systemd con sandboxing y secretos fuera del código |

```bash
sudo DRY_RUN=1 ADMIN_IP=<tu-IP> deploy/ufw-setup.sh   # revisa las reglas sin aplicarlas
sudo ADMIN_IP=<tu-IP> deploy/ufw-setup.sh             # aplica (el SSH se permite ANTES de activar)
pip install --require-hashes -r requirements-prod.txt  # incluye gunicorn
```

Advertencias: no cierres tu sesión SSH hasta confirmar que puedes entrar de nuevo; UFW no
controla los puertos publicados por Docker.

## Verificación

```bash
pip install -r requirements-dev.in
pytest -q                                          # 31 pruebas, una o más por hallazgo
bandit -r app.py                                   # SAST
pip-audit -r requirements.txt --require-hashes     # SCA
```

Dependencias: edita `requirements.in` y regenera con
`pip-compile --generate-hashes --strip-extras requirements.in` (generado con Python 3.12).
