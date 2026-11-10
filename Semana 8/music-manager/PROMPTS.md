# PROMPTS.md

Registro de los prompts usados para generar y auditar Music Manager con IA.

- Modelo (generación y auditoría): Claude Sonnet 5.5, en claude.ai
- Generación de la app (v0): viernes 30 de octubre de 2026, 16:20
- Auditoría y remediación: sábado 7 de noviembre de 2026, 15:30

Los prompts están copiados tal como se escribieron (incluidos errores de ortografía), porque el registro debe ser fiel al original.

| # | Propósito | Resultado | Commit / etiqueta |
|---|-----------|-----------|-------------------|
| 1 | Generar la app | `app/` de la versión base | `v0-ai-baseline` |
| 2 | Auditoría inicial (CVE, CWE, CVSS) | Hallazgos v0, `scans/v0-ai-baseline/` | `v0-ai-baseline` |
| 3 | Ampliar a runtime, DAST, secretos, STRIDE | Tabla de capas, DAST manual | `v0-ai-baseline` |
| 4 | Lista de mejoras | 17 mejoras priorizadas | - |
| 5 | Aplicar mejoras y entregar zip | Versión intermedia | commit `intermediate` |
| 6 | Auditar la versión segura | 5 hallazgos nuevos | `scans/intermediate/` |
| 7 | Requisitos completos de la práctica (SCA, SAST, ZAP, OWASP, CVSS+EPSS/KEV, UFW) | Versión final, informe | `v1-remediated` |
| 8 | Informe PDF | Se entrega aparte | - |

---

## Prompt 1 - Generación de la aplicación (v0)

```text
Desarrolla una aplicación web sencilla llamada Music Manager, un administrador personal de música escuchada, utilizando Python y Flask.
La aplicación debe permitir:

* Registrar canciones con título, artista, álbum, género y fecha de escucha.
* Mostrar todas las canciones registradas en una tabla.
* Agregar, editar y eliminar canciones.
* Buscar canciones por título o artista.
* Filtrar canciones por género musical.
* Mostrar estadísticas básicas: total de canciones, artistas y géneros.

Crea una interfaz moderna, sencilla y agradable, con temática musical y colores oscuros.
Organiza el proyecto con una estructura sencilla, separando las plantillas HTML, los archivos CSS y el código Python.
Incluye los archivos necesarios, la creación automática de la base de datos y un archivo `requirements.txt`.
La aplicación debe ser funcional y fácil de ejecutar localmente. Proporciona el código completo de cada archivo y las instrucciones para instalar las dependencias y ejecutar el proyecto.
```

## Prompt 2 - Auditoría inicial

```text
Practica de la materia de hacking etico, esta pratica consite que de este sistema  vamos a relaizar las siguientes pruebas de seguridada.
CVE, CWE, CVSS
Aqui en el archivo zip esta todo lo correspondiente a la aplicacion a la cual vas a realizar esta evaluacion.
No solo evalues las lineas de codigos, evalua las librerias, dependencias entre mas aspecto que esta evaluacion con las Caracteristicas mencionadas CVE, CWE, CVSS
```

## Prompt 3 - Ampliación del análisis

```text
apartes de las librerias que demas con esas 3 s epuede analizar
```
```text
haz un analisis con esos tambien
```

## Prompt 4 - Lista de mejoras

```text
Perfecto, ahora lista las mejoras que se deben realizar a traves de la evaluacion realizada
```

## Prompt 5 - Aplicar las correcciones

```text
Ahora que sabes las correciones a realizar, dame este proyecto en un archivo zip con todas las correciones hechas
```

## Prompt 6 - Auditoría de la versión corregida

```text
Ahora aplica un analisis a esta version segura que me brindastes
```

## Prompt 7 - Requisitos completos de la práctica

```text
Esto tambien me pide en el analisis:
ind vulnerable dependencies (CVEs) with SCA, find weaknesses in the generated code (CWEs) with SAST and secret scanning, test the running app with a passive ZAP scan and a manual OWASP Top 10 check, score and rank every finding with CVSS 3.1 + EPSS/KEV, fix the top findings with AI and prove each fix with a re-scan, and add a UFW network layer.
```
```text
Continuar
```

## Prompt 8 - Informe

```text
Con este analisis que se realizo en una aplicacion propia, deseo que crees lo siguiente:
un PDF (3–5 páginas) nombrado `Week8_AIAppAudit_<surname>.pdf`,
```

---

## Notas de verificación humana

- Los puntajes CVSS 3.1 se calcularon a mano; verificar en la calculadora del NVD.
- EPSS y KEV de CVE-2024-34069 vienen de fuentes secundarias; reconsultar en first.org y cisa.gov.
- Semgrep, Trivy, OSV y UFW real no se ejecutaron en el entorno de la IA (ver README).
