# Music Manager - Auditoria de una app generada con IA

Repositorio de la practica de Hacking Etico (Week 8, AI App Audit).

## Estructura

| Ruta | Contenido |
|------|-----------|
| `app/` | Codigo de la aplicacion; cambia en cada commit de version |
| `PROMPTS.md` | Prompts usados para generar y auditar la app |
| `findings.csv` | Hallazgos con CWE, CVSS 3.1, EPSS/KEV (si aplica), correccion y estado |
| `scans/<version>/` | Salidas en bruto de Bandit, pip-audit, detect-secrets y ZAP |
| `docs/` | Informe PDF |
| `scripts/build_history.sh` | Construye el historial y las etiquetas |

## Etiquetas

| Etiqueta | Contenido |
|----------|-----------|
| `v0-ai-baseline` | App tal como la genero la IA, sin remediar |
| `v1-remediated` | App con todas las correcciones (version final "v3") |

El historial tiene un commit por version: `v0` (base) y `v1-remediated` (final), mas el commit inicial con la documentacion.

## Comparar versiones

```bash
git diff v0-ai-baseline v1-remediated --stat -- app
```

## Resumen de escaneos (salidas en bruto en `scans/`)

| Herramienta | v0-ai-baseline | v1-remediated |
|-------------|----------------|---------------|
| Bandit (sin tests/) | B201 alta, B105 baja | 0 hallazgos |
| pip-audit | 0 CVE (10 paquetes, versiones sin fijar) | 0 CVE (20 y 21 paquetes, con hashes) |
| detect-secrets | 0 | 3 alertas de entropia en app.py (secuencias de teclado de la politica de contrasenas, falsos positivos) |
| ZAP pasivo 2.17.0 | 4 tipos Medium y 3 Low (81 alertas) | 3 tipos informativos (30 alertas) |

## Limitaciones

- Semgrep, Trivy y OSV no se ejecutaron; ZAP se uso solo en modo pasivo.
- UFW solo se valido con `--dry-run`; aplicalo en el servidor y confirma con nmap.
- Los puntajes CVSS se calcularon a mano; verificar en la calculadora del NVD.
- Los EPSS/KEV de `findings.csv` deben reconsultarse en first.org y cisa.gov.
