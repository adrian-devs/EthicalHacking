# Informe de seguridad: Music Manager

Alcance: SCA (CVE), SAST y escaneo de secretos (CWE), escaneo pasivo con OWASP ZAP, revisión
manual OWASP Top 10:2025, puntuación CVSS 3.1 con EPSS/KEV, correcciones con re-escaneo y capa
de red con UFW. Versiones comparadas: **v1** (original), **v2** (primera versión segura), **v3** (esta).

Los puntajes CVSS se calcularon a mano con la fórmula de CVSS 3.1: verifícalos en la calculadora
del NVD. El mapeo a OWASP es orientativo.

## 1. Hallazgos ordenados por CVSS 3.1

EPSS y KEV solo existen para CVE. Los hallazgos de código propio no tienen CVE, por lo que
muestran n/a.

| # | Hallazgo | CWE | OWASP 2025 | CVSS | Vector | EPSS / KEV | Estado en v3 | Prueba del re-escaneo |
|---|---|---|---|---|---|---|---|---|
| 1 | `debug=True` y consola del depurador | 489, 94, 532 | A02 | 8.1 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | n/a | Corregido | Bandit 2 → 0; `/console` 200 → 404 |
| 2 | Sin autenticación ni autorización | 306, 862, 639 | A01 | 7.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L | n/a | Corregido | Rutas redirigen a `/login`; datos ajenos dan 404 |
| 3 | Sin protección CSRF | 352 | A01 | 5.4 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L | n/a | Corregido | ZAP: "Absence of Anti-CSRF Tokens" ×30 → 0; POST sin token da 400 |
| 4 | Sin límites de tamaño ni de peticiones | 20, 770, 307 | A06 | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | n/a | Corregido | 413 / 429 verificados |
| 5 | Contraseñas predecibles aceptadas | 521 | A07 | 4.8 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | n/a | Corregido | 5 de 5 rechazadas |
| 6 | `SECRET_KEY` fija en el código | 798, 259 | A02 | 4.8 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | n/a | Corregido | Bandit B105 → 0; la app no arranca sin clave en producción |
| 7 | Sin cabeceras de seguridad | 693, 1021 | A02 | 4.3 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | n/a | Corregido | ZAP: CSP, clickjacking y nosniff ausentes → 0 |
| 8 | Error 500 con enteros enormes | 20, 190 | A10 | 4.3 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L | n/a | Corregido | 3 respuestas 500 → 0 (404 / 200) |
| 9 | La sesión sigue válida tras cerrar sesión | 613 | A07 | 4.2 | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N | n/a | Corregido | Cookie vieja: 200 → 302 |
| 10 | Enumeración de usuarios en el registro | 204 | A07 | 3.7 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N | n/a | **Mitigado** (código de invitación opcional) | Con código, no se revela |
| 11 | Cookie sin `SameSite` ni `Secure` | 614, 1275 | A02 | 3.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | n/a | Corregido | ZAP: "Cookie without SameSite" ×6 → 0 |
| 12 | Usuario tecleado en el log de fallos | 532 | A09 | 2.3 | AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N | n/a | Corregido | El log guarda solo una etiqueta HMAC |
| 13 | Dependencias con rangos abiertos | 1104, 1357 | A03 | n/a | n/a | Ver sección 2 | Corregido | Versiones y hashes fijados |
| 14 | Recurso externo sin SRI (Google Fonts) | 345, 829 | A03 / A08 | Baja | n/a | n/a | Corregido | ZAP: "Sub Resource Integrity Missing" ×11 → 0 |
| 15 | Versión del servidor en cabecera `Server` | 497 | A02 | Info | n/a | n/a | Corregido | ZAP: ×29 → 0 |

## 2. SCA: dependencias y CVE

- **pip-audit (fuente PyPI):** sin vulnerabilidades conocidas en `requirements.txt` ni en `requirements-prod.txt`.
- **Fuente OSV:** no se pudo consultar (`api.osv.dev` no es alcanzable desde el entorno de pruebas). Repite `pip-audit -s osv` en tu equipo.
- **SBOM:** `pip-audit -f cyclonedx-json` genera el inventario. Hay 21 paquetes con versiones exactas y hashes.
- **Flask-WTF** se actualizó de 1.2.2 a 1.3.0 y las 31 pruebas pasan.
- **Poco mantenimiento (informativo):** Flask-Login 0.6.3 (octubre de 2023), Flask-Talisman 1.1.0 (agosto de 2023), ordered-set 4.1.0 (enero de 2022).

**CVE de referencia: CVE-2024-34069 (Werkzeug, depurador, corregido en 3.0.3)**

| Dato | Valor |
|---|---|
| CVSS 3.1 | 7.5 Alta, `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| EPSS | aprox. 0.44 (percentil 97), según una captura de mayo de 2026 |
| KEV | No aparece, según una fuente consultada |
| Exploit | Existe un módulo público de Metasploit |
| Versiones instaladas (Werkzeug 3.1.9) | **No afectadas** |

Verifica EPSS y KEV en first.org y cisa.gov antes de entregar: son datos que cambian.

## 3. SAST y secretos

- **Bandit:** v1 con 2 hallazgos (B201 alta, B105 baja) → v3 con 0 (507 líneas).
- **detect-secrets:** 3 alertas de entropía en `app.py` (líneas 78 y 79). Son las secuencias de teclado y alfabeto de la política de contraseñas, es decir, falsos positivos revisados a mano.
- Sin secretos literales en el código ni en `deploy/`.

## 4. Escaneo pasivo con OWASP ZAP 2.17.0

Daemon con 61 reglas pasivas. Tráfico: navegación sin sesión y con sesión (registro, alta, edición, búsqueda, paginación, cierre de sesión) a través del proxy de ZAP, más el spider. **No se ejecutó escaneo activo.**

| Versión | URLs | Medium | Low | Informativas |
|---|---|---|---|---|
| v1 | 32 | 4 (CSRF, CSP, clickjacking, SRI) | 3 (SameSite, Server, nosniff) | 3 |
| v2 | 23 | 0 | 0 | 3 |
| v3 | 23 | 0 | 0 | 3 |

Las 3 informativas son "Authentication Request Identified", "Session Management Response Identified" y "User Controllable HTML Element Attribute (Potential XSS)". La última es un falso positivo: el valor reflejado se escapa (probado con `<img onerror>`). v3 no produjo respuestas 5xx durante el escaneo. El limitador de peticiones se desactivó solo durante el escaneo para no cortar el spider.

## 5. Revisión manual OWASP Top 10:2025

| Categoría | v1 | v3 | Evidencia y riesgo residual |
|---|---|---|---|
| A01 Broken Access Control | Falla | Cumple | `login_required`, filtro por dueño, 404 ante ids ajenos. No hay peticiones salientes (sin SSRF). |
| A02 Security Misconfiguration | Falla | Cumple | Debug apagado, cabeceras, `TRUSTED_HOSTS`, cookies, sin banner de versión. |
| A03 Software Supply Chain Failures | Falla | Cumple | Hashes, `pip-audit`, SBOM. Residual: 3 paquetes con poco mantenimiento y OSV sin consultar. |
| A04 Cryptographic Failures | Parcial | Cumple | Contraseñas con scrypt (`scrypt:32768:8:1`), TLS y HSTS vía nginx. Residual: SQLite sin cifrar en reposo. |
| A05 Injection | Cumple | Cumple | ORM parametrizado, comodines escapados, autoescape de Jinja y CSP sin `unsafe-inline`. |
| A06 Insecure Design | Falla | Parcial | Límites, registro por invitación, caducidad por inactividad. Falta MFA y recuperación de contraseña. |
| A07 Authentication Failures | Falla | Parcial | Hash fuerte, mensaje genérico, tiempos igualados, sesión revocable, política de contraseñas. Falta MFA. |
| A08 Software or Data Integrity Failures | Falla | Cumple | Dependencias con hash, cookie firmada, sin deserialización, sin scripts externos. |
| A09 Logging & Alerting Failures | Falla | Parcial | Registro `AUDIT` sin datos sensibles. No hay alertas automáticas. |
| A10 Mishandling of Exceptional Conditions | Falla | Cumple | Manejadores genéricos, 413 y 429 controlados, enteros enormes validados, fallo cerrado en autenticación. |

## 6. Capa de red con UFW (`deploy/`)

```
Internet → UFW (80/443 + SSH) → nginx (TLS, límite en /login) → gunicorn 127.0.0.1:8000 → app
```

Reglas que genera `ufw-setup.sh` (verificadas con `ufw --dry-run`):

```
default deny incoming | default allow outgoing | default deny routed
allow tcp 22 desde <ADMIN_IP>   (o: limit 22/tcp si no defines ADMIN_IP)
allow tcp 80   · allow tcp 443
deny  tcp 5000 · deny tcp 8000
logging medium
```

| Verificación | Resultado |
|---|---|
| `ufw --dry-run` | Reglas generadas correctamente, con y sin `ADMIN_IP` |
| `nginx -t` (nginx 1.24) | Sintaxis válida. Encontró y corrigió `http2 on;`, que no existe en nginx < 1.25.1 |
| Exposición real de la app | Escucha solo en `127.0.0.1:5000`. Por la IP no-loopback: conexión rechazada |
| `verify-network.sh` | OK: ningún puerto 5000 u 8000 fuera de localhost |

**No verificado:** UFW no se aplicó de verdad (el entorno de pruebas no permite netfilter; el estado fue `inactive`). Aplícalo en tu servidor con `DRY_RUN=1` primero y comprueba con `nmap` desde otra máquina.

## 7. Riesgo residual

- Sin MFA ni recuperación de contraseña. Un ataque de fuerza bruta distribuido no lo frena el límite por IP.
- Registro abierto por defecto (se mitiga con `REGISTRATION_CODE` o `ALLOW_REGISTRATION=0`).
- SQLite sin cifrado en reposo. El límite de peticiones en memoria cuenta por proceso: usa Redis con varios procesos.
- No hay alertas automáticas sobre el registro `AUDIT`.
- Pendiente: ZAP activo, OSV, Semgrep, Trivy (no ejecutables en el entorno de pruebas), historial de git, y las versiones de Python y SQLite de tu equipo.
