# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Irene Yago Soriano
- **Repositorio:** https://github.com/Ireneyss/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04.5 LTS (WSL2 sobre Windows) · Python 3.12.3

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41–42 | Inyección SQL: el nombre del cliente se concatena dentro de la consulta | Parámetro `cliente` de `/reportes?cliente=` (`servicio.py`) | `cursor.execute(query)` |
| 2 | `convertir_a_pdf` | 50–51 | Inyección de comandos: el nombre de archivo se concatena en una orden de la shell | Parámetro `archivo` de `/convertir?archivo=` (`servicio.py`) | `os.system(comando)` |
| 3 | `cargar_configuracion` | 33 | Deserialización insegura: `yaml.Loader` puede construir objetos de Python | Contenido de `config.yaml` | `yaml.load(f, Loader=yaml.Loader)` |
| 4 | `hash_password_legacy` | 57 | Hash débil: MD5 sin sal para contraseñas | Contraseña del cliente (`password`) | `hashlib.md5(...)` |
| 5 | Constantes del módulo | 21–22 | Credenciales escritas en el código (clave de API y contraseña SMTP) | — (valor fijo en el código) | Repositorio público y todo su historial de Git |

**Impacto en el negocio:**
1. Un atacante podría leer o borrar los reportes de auditoría de todos los clientes, no solo los suyos.
2. Ejecución de órdenes arbitrarias en el servidor: control total de la máquina que aloja ReportAudit.
3. Quien pueda modificar la configuración podría ejecutar código al arrancar el servicio.
4. Si se filtra la base de datos, las contraseñas MD5 se recuperan en segundos con fuerza bruta o tablas precalculadas.
5. Cualquiera que vea el repositorio puede usar la API de notificaciones y el correo SMTP en nombre de ReportAudit.

**Síntoma observado (paso C.2):** `/reportes?cliente=acme_corp` → HTTP 200; `/reportes?cliente=o'brien_ltd` → HTTP 500 con `sqlite3.OperationalError: near "brien_ltd": syntax error`. El apóstrofo cierra la cadena SQL antes de tiempo: el dato cambia la estructura de la orden, que es exactamente una inyección SQL.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | ✗ | ✗ | ✓ pythonsecurity:S3649 | ✓ py/sql-injection | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ | ✗ | ✓ pythonsecurity:S2076 | ✓ py/command-line-injection | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ avoid-pyyaml-load | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ python:S4790 | ✓ python:S4790 | ✓ python:S4790 | ✓ py/weak-sensitive-data-hashing | ✓ insecure-hash-algorithm-md5, md5-used-as-password | n/a |
| H5 Clave de API escrita en el código | ✓ | ✗ | ✗ | ✗ | ✗ (solo py/clear-text-logging-sensitive-data, L62, al imprimirla) | ✗ | ✗ |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ python:S2068 | ✓ python:S2068, secrets:S7552 | ✓ python:S2068, secrets:S7552 | ✗ | ✗ | ✗ |

Con Connected Mode, el editor pasa de 2 a 3 hallazgos: añade secrets:S7552 (contraseña SMTP), una regla del servidor que sin conexión no se aplica. Las inyecciones (H1, H2) no aparecen en el editor: son taint vulnerabilities que calcula SonarQube Cloud siguiendo el dato de servicio.py a reporte_auditoria.py, y solo se ven en el panel de la nube.

Hallazgo adicional no previsto en la auditoría manual: SonarQube Cloud marca python:S4502 (protección CSRF desactivada) en `servicio.py`, línea 25.

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué te dice eso sobre depender de una sola herramienta?
Ninguna herramienta detectó los seis hallazgos: CodeQL y SonarQube Cloud encuentran las inyecciones (H1, H2) por análisis de contaminación pero no el YAML; Semgrep encuentra el YAML y el MD5 pero no las inyecciones; la clave de API (H5) solo la detectó la revisión manual. Trivy resultó ser muy eficaz detectando vulnerabilidades en dependencias públicas y CVEs conocidos en requirements.txt, pero falló (falso negativo) al detectar contraseñas hardcodeadas (H5 y H6). Esto demuestra que depender de una sola herramienta de propósito general es insuficiente; se requiere un enfoque de "defensa en profundidad" combinando escáneres SCA (Trivy/Grype) con herramientas especializadas en secretos (Gitleaks) y código estático (Semgrep/CodeQL).
---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2 (`flask` y `pyyaml`). |
| Componentes Python en el SBOM | 9 paquetes Python (blinker, click, colorama, flask, itsdangerous, jinja2, markupsafe, pyyaml, werkzeug). |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 GitHub Actions (actions/checkout, SonarSource/sonarqube-scan-action, y github/codeql-action/init y analyze). Salen de nuestros flujos de CI/CD. |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | `bomFormat`: CycloneDX · `specVersion`: 1.7 (JSON, generado con Syft `-o cyclonedx-json`). |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| jinja2 | 3.1.2 | # via flask | GHSA-gmj6-6f8f-6699 | Medium | 3.1.5 | No: afecta al sandbox de plantillas de Jinja2. ReportAudit no renderiza plantillas, solo responde con jsonify (ver app/servicio.py) | Actualizar con el PR de Dependabot (coste bajo). |
|flask|3.0.0|Directa (en requirements.txt)|CVE-2026-27205|Low|3.1.3|Probablemente no: requiere un mal uso del almacenamiento en caché de sesiones, y ReportAudit es una API que no gestiona sesiones complejas.|Forzar salto menor manual a 3.1.3 en requirements.txt.|

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica cualquier diferencia.
Las alertas de Dependabot coincidieron exactamente con los hallazgos de Grype y Trivy (13 vulnerabilidades en total), ya que ambos consultan bases de datos de vulnerabilidades (NVD/GHSA) similares, demostrando consistencia en el diagnóstico.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.
El archivo reportaudit.openvex.json ha sido completado y se encuentra en docs/evidencias/. Justificamos el estado not_affected indicando que el código vulnerable (el motor de plantillas de Jinja2) no está en el flujo de ejecución de la aplicación, ya que esta solo devuelve respuestas JSON.
---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 | 0 |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 | 0 (las 4 cerradas como Fixed) |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 | 0 (CSRF de servicio.py valorado y aceptado con justificación) |
| Security Hotspots por revisar en SonarQube Cloud | 0 | 0 |
| Vulnerabilidades de Grype sobre el SBOM | 13 | 0 |
| Alertas abiertas de Dependabot | 13 | 1 (alerta desfasada de flask: requirements.txt ya fija 3.1.3, versión que la corrige) |

Medidas adicionales y evidencias (`docs/evidencias/`):

- Trivy sobre dependencias: 13 vulnerabilidades antes (`trivy-antes.txt`, reconstruido escaneando el commit de importación `f02ea94`) → 0 después (`trivy-despues.txt`).
- SBOM: `sbom.cyclonedx.json` (antes) y `sbom-despues.cyclonedx.json` (después, 14 componentes); Grype: `grype-antes.txt` (13) → `grype-despues.txt` (0, base de datos actualizada el 2026-11-25).
- En el PR de auditoría (#20), SonarQube Cloud detectó además una inyección de argumentos en la primera versión de la corrección (la lista blanca solo validaba el nombre final del archivo); se corrigió validando el nombre completo y pasando `./nombre` a `wkhtmltopdf`.

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
