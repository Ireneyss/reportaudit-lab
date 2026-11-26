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
| Alertas abiertas de Dependabot | 13 | 0 (la de flask era una lectura desfasada del grafo de dependencias, que seguía registrando 3.0.0 aunque requirements.txt fija 3.1.3: descartada como «Inaccurate» con justificación) |

Medidas adicionales y evidencias (`docs/evidencias/`):

- Trivy sobre dependencias: 13 vulnerabilidades antes (`trivy-antes.txt`, reconstruido escaneando el commit de importación `f02ea94`) → 0 después (`trivy-despues.txt`).
- SBOM: `sbom.cyclonedx.json` (antes) y `sbom-despues.cyclonedx.json` (después, 14 componentes); Grype: `grype-antes.txt` (13) → `grype-despues.txt` (0, base de datos actualizada el 2026-11-25).
- En el PR de auditoría (#20), SonarQube Cloud detectó además una inyección de argumentos en la primera versión de la corrección (la lista blanca solo validaba el nombre final del archivo); se corrigió validando el nombre completo y pasando `./nombre` a `wkhtmltopdf`.

---

## Preguntas de comprobación (Sección 7 de la guía)

1. **Windows:** VS Code (solo la interfaz y la extensión WSL), el navegador (GitHub, SonarQube Cloud, scorecard.dev) y el documento Word de capturas. **Ubuntu (WSL2):** el proyecto en `~/reportaudit-lab`, Python y el `venv`, Git, `gh`, pre-commit con Semgrep, las herramientas verificadas de `tools/` (Syft, Grype, Trivy, Gitleaks) y las extensiones de VS Code instaladas «in WSL». **GitHub:** el repositorio, los Issues y PRs, la protección de `main`, Actions (SonarQube Cloud, CodeQL, pip-audit, Gitleaks, Scorecard y la publicación firmada), Dependabot, Security y la Release v1.0.0. Se trabaja en Ubuntu porque es el mismo sistema que el runner de CI (`ubuntu-latest`): lo que funciona en local funciona en el pipeline, las herramientas son nativas de Linux y el disco de Ubuntu es mucho más rápido que `/mnt/c`.

2. Una dependencia **directa** es la que declara el proyecto: en `requirements.in` solo hay dos, `flask` y `pyyaml`. Una **transitiva** llega porque la necesita otra: en `requirements.txt`, `werkzeug` lleva `# via flask`, y `markupsafe` lleva `# via flask, jinja2, werkzeug`. El SBOM (`sbom.cyclonedx.json`) lista 9 paquetes de Python sin distinguir unos de otros: de 2 directas salen 9 componentes. Ese es el iceberg, y la mayoría de las 13 vulnerabilidades iniciales estaban en la parte sumergida (werkzeug y jinja2).

3. El **source** es el punto por donde entra un dato que controla el usuario; el **sink**, la función que se vuelve peligrosa si recibe ese dato sin tratar. Ejemplo real: `request.args.get("cliente")` en `servicio.py` (source) pasa a `buscar_reportes_cliente()` en `reporte_auditoria.py` y acaba en `cursor.execute(query)` (sink). Igual con `archivo` → `convertir_a_pdf()` → `os.system()`. Por eso CodeQL y SonarQube Cloud las detectan con análisis de contaminación (*taint*) entre los dos archivos, y Semgrep, que mira patrones dentro de un archivo, no.

4. La consulta se construía concatenando: `... WHERE cliente = '` + nombre + `'`. El apóstrofo de `o'brien_ltd` cerraba la cadena SQL antes de tiempo y `brien_ltd'` quedaba como sintaxis SQL, de ahí `sqlite3.OperationalError: near "brien_ltd": syntax error` y el HTTP 500. Demuestra la inyección porque un dato del usuario ha cambiado la estructura de la orden: si un apóstrofo la rompe, un atacante puede escribir uno que la reescriba (por ejemplo `' OR '1'='1`). Con la consulta parametrizada, `o'brien_ltd` devuelve su reporte con HTTP 200.

5. El hook actúa **en mi equipo y antes de que el commit exista**: en segundos, sin depender de la nube, bloqueó el commit de prueba con MD5 y `yaml.load`. Es el punto más «a la izquierda». Solo no basta porque es voluntario y local (hay que instalarlo con `pre-commit install`, y se puede saltar con `--no-verify`) y porque sus reglas no siguen el dato entre archivos: no detectó las dos inyecciones. La garantía real son los checks del servidor, obligatorios en `main`, que nadie puede saltarse.

6. No es un error: cada herramienta tiene un método y un juego de reglas distinto. En mi matriz, CodeQL y SonarQube Cloud detectan H1 y H2 por *taint*; Semgrep detecta H3 (YAML) y H4 (MD5), pero no las inyecciones; SonarQube detecta la contraseña SMTP (S2068, S7552) pero no la clave de API; CodeQL solo vio la clave al imprimirse en un log; Trivy no detectó ninguna credencial porque solo reconoce formatos de proveedores conocidos. La clave de API (H5) solo la encontró la revisión manual (y después Gitleaks). Por eso se combinan: defensa en profundidad, y la auditoría manual sigue siendo necesaria.

7. Porque miran cosas distintas. CodeQL (SAST) analiza **nuestro código** en `app/`; Dependabot (SCA) analiza **las versiones de las dependencias** de terceros en `requirements.txt`. Parametrizar una consulta no cambia la versión de werkzeug, y subir werkzeug no cambia una consulta. Cada alerta se cierra cuando desaparece su causa en su propio ámbito: SAST con el PR #20, SCA con los PRs de dependencias (#7, #21 y #25).

8. Borrarlo del código solo cambia la última versión: el secreto sigue en el historial de Git (commit `f02ea94`) y en cualquier copia, como la que acabó en mi `gitleaks-reporte.json` de octubre (commit `bdcb176`, guardado sin `--redact`). Sigue funcionando para quien lo haya copiado. Corregirlo de verdad es **rotarlo** en el proveedor (la credencial filtrada deja de valer), leer la nueva del entorno (`os.environ.get`) e impedir que vuelva a pasar: regla propia de Gitleaks, check obligatorio en `main` y push protection.

9. «Ignorar la alerta» no deja constancia de por qué, de quién lo decidió ni de a qué producto afecta, y nadie más puede comprobarlo. Un **VEX** es un documento estándar y legible por máquinas que declara, por vulnerabilidad y producto, el estado y su justificación, para que clientes y herramientas lo consuman. Mi VEX (`reportaudit.openvex.json`) declara GHSA-gmj6-6f8f-6699 en `jinja2@3.1.2` como `not_affected` con la justificación `vulnerable_code_not_in_execute_path`: el fallo está en el sandbox de plantillas de Jinja2 y ReportAudit no renderiza plantillas, solo responde con `jsonify`. Aun así, después se actualizó jinja2 a 3.1.6.

10. Fija una **versión concreta** de cada herramienta y comprueba que la **huella SHA-256** de lo descargado coincide con la publicada por el proyecto antes de ejecutarlo (yo hice lo mismo con Gitleaks 8.30.1: `OK`). Eso detecta descargas corruptas o alteradas por el camino. No garantiza que la publicación oficial sea legítima: en el caso Trivy de 2026 los atacantes reescribieron 76 de las 77 etiquetas de versión, así que la huella publicada habría coincidido con el binario malicioso. Por eso se usan versiones concretas y revisadas (nunca «la última»), se verifican firmas y procedencia (Sigstore) y, en Actions, se fijan las acciones por hash (Pinned-Dependencies de Scorecard).

11. El código actual está limpio porque en la Parte M las constantes se sustituyeron por `os.environ.get(...)`: `gitleaks dir app` da 0. El historial no, porque Git guarda todas las versiones: el commit de importación `f02ea94` contiene la clave de API (L21) y la contraseña SMTP (L22), y `bdcb176` una copia de la clave en el informe antiguo. Lo que cierra el riesgo es la **rotación**: las credenciales filtradas dejan de servir. El `.gitleaksignore` solo registra que esos tres hallazgos concretos ya están tratados; la regla propia y el check obligatorio impiden que entren secretos nuevos.

12. *Ratchet* (trinquete): la exigencia solo sube, y cada puerta se añade cuando el proyecto ya puede cumplirla. Si pip-audit hubiera sido obligatorio en la Parte G, todos los PRs (incluida la propia corrección) habrían quedado bloqueados por las 13 vulnerabilidades heredadas. Se añadió tras limpiar las dependencias, y aun así su primera ejecución (PR #24) falló: detectó que `requirements.txt` no se podía instalar (flask 3.1.3 con blinker 1.7.0 e itsdangerous 2.1.2, cambiado a mano en octubre). Se regeneró con `pip-compile` (PR #25) y solo entonces se hizo obligatorio (P.4). Desde ese clic, ninguna regresión entra: el PR de prueba #26 quedó bloqueado.

13. Una **alerta de Dependabot** es informativa: vive en Security, describe el estado de `main` y no bloquea nada; incluso puede quedar desfasada (la de flask seguía abierta porque el grafo de dependencias de GitHub registraba 3.0.0 cuando `requirements.txt` ya fijaba 3.1.3, y hubo que descartarla como «Inaccurate» con justificación). El check **SCA - pip-audit** se ejecuta en cada PR sobre los archivos de ese PR y, al ser obligatorio, impide fusionar: con werkzeug 3.1.3 (PR #26) encontró 7 vulnerabilidades y bloqueó el merge. Una avisa; el otro impide.

14. Demuestra que ese archivo (su hash `sha256:49d5…`) lo produjo el workflow `publicar-version.yml` del repositorio `Ireneyss/reportaudit-lab` desde `refs/tags/v1.0.0`, firmado con la identidad OIDC de GitHub (Sigstore), y que nadie lo ha modificado: `alterado.tar.gz` no tiene atestación y la verificación falla. No demuestra que el código sea seguro (eso lo dicen los checks y el SBOM) ni que el workflow no esté comprometido: solo dice la verdad sobre quién y desde dónde lo construyó. `SHA256SUMS` no basta porque quien sustituya el archivo en la Release puede sustituir también `SHA256SUMS`; la firma no la puede falsificar sin la identidad del workflow.

15. Un Issue es público: revelaría el fallo a cualquier atacante antes de que exista corrección. El canal privado (*Report a vulnerability*) permite corregir, acordar la fecha, publicar el aviso con la versión corregida y dar crédito al investigador, como en el simulacro (GHSA-qvf8-6vhr-4gj5, reportado por AlbertoConesaAyala2003). `SECURITY.md` es el contrato público: dice dónde y cómo reportar, en qué plazos se responde, qué versiones tienen soporte (1.x hasta 2031-10-31), el *safe harbour* y cómo verificar las releases. Scorecard le da un 10 (Security-Policy).

16. No. Maintained mide antigüedad y actividad sostenida: da 0 porque el repositorio tiene menos de 90 días, aunque ReportAudit tenga 0 vulnerabilidades, releases firmadas y cuatro puertas obligatorias. Enseña que una métrica mide una práctica, no la seguridad: hay que leer el motivo de cada nota, combinarla con las demás y con el contexto. Un 6.9 global no es un certificado; sirve para priorizar mejoras (la útil aquí es Pinned-Dependencies).

17. En la B5 de la Práctica 2 relacioné en teoría los requisitos del Anexo I con prácticas y herramientas. Ahora **existe de verdad**: análisis SAST y SCA obligatorios en cada PR, el SBOM CycloneDX atestado en la Release, la release firmada y verificable por un tercero, `SECURITY.md` con periodo de soporte, el canal privado con un borrador de aviso real, Dependabot y Scorecard semanal, y la trazabilidad Issue → PR revisado. **Sigue sin existir**: la evaluación de riesgos documentada, la documentación técnica completa del Anexo VII, la declaración UE de conformidad y el marcado CE, el procedimiento de notificación a ENISA de vulnerabilidades explotadas (art. 14), un aviso de seguridad publicado de verdad (el simulacro se quedó en borrador) y la garantía de que el soporte se cumplirá durante cinco años.

---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 | — |
| Historial, reglas por defecto | `gitleaks git .` | 2 (`generic-api-key`: solo la clave de API; la contraseña SMTP no se detecta) | `f02ea94` (importación, `app/reporte_auditoria.py` L21) y `bdcb176` (copia de la clave en el antiguo `docs/evidencias/gitleaks-reporte.json`, guardado sin `--redact`) |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 3 (`reportaudit-hardcoded-credential` ×2 + `generic-api-key` ×1) | `f02ea94` (L21 clave de API y L22 contraseña SMTP) y `bdcb176` (copia en el informe antiguo) |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 | — (los 3 registrados en la baseline por su Fingerprint) |

¿Por qué el código actual está limpio y el historial no? ¿Qué medida de la Parte M cierra el riesgo
y cuál no lo cierra?

El código actual está limpio porque la Parte M sustituyó las credenciales por variables de entorno; el historial no, porque Git conserva el commit de importación `f02ea94` (y la copia de `bdcb176`). La medida de la Parte M que cierra el riesgo es la **rotación** de las dos credenciales; sacarlas del código **no** lo cierra por sí sola, porque las antiguas siguen en el historial público (ver pregunta 11).

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | Sí | ✓ pass (el código no cambia) |
| SAST - CodeQL | Sí | ✓ pass (el código no cambia) |
| SCA - pip-audit | Sí | ✗ fail: 7 vulnerabilidades conocidas en werkzeug 3.1.3 (PYSEC-2026-2046, -2044, -2320, -4312; corregidas en 3.1.4–3.1.9). PR #26 cerrado sin fusionar |
| Secretos - Gitleaks | Sí | ✓ pass (ningún secreto en el commit de prueba) |

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub): AlbertoConesaAyala2003 (compañero revisor), por el canal privado *Report a vulnerability*
- Identificador del borrador de aviso (GHSA-…): GHSA-qvf8-6vhr-4gj5 (borrador; sin CVE ni publicación, por ser un simulacro)
- Severidad y vector CVSS: Critical 9.1 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (por red, sin privilegios ni interacción; lectura y borrado de los reportes de todos los clientes)
- CWE: CWE-89 (SQL Injection)
- Versiones afectadas / versión corregida: reportaudit (pip) < 1.0.0 / 1.0.0
- Papel de investigadora: informe enviado al repositorio de AlbertoConesaAyala2003 por su canal privado (GHSA-hh77-gff8-wmjr, en Triage; crédito como Reporter aceptado)

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | OK en `reportaudit-1.0.0.tar.gz` y `reportaudit-sbom.cdx.json` |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo …` | ✓ Verification succeeded! (predicado slsa.dev/provenance/v1; build y signer: `Ireneyss/reportaudit-lab`, `.github/workflows/publicar-version.yml@refs/tags/v1.0.0`) |
| SBOM atestado | `gh attestation verify … --predicate-type https://cyclonedx.org/bom` | ✓ Verification succeeded! (mismo workflow y etiqueta) |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo …` | ✗ Falla (salida 1): huella sha256:cb64… distinta de la publicada (sha256:49d5…) y sin ninguna atestación en GitHub (HTTP 404) |

Nota: la verificación requirió actualizar `gh` (la 2.45 de Ubuntu no trae `gh attestation`; se instaló la 2.106 desde el repositorio oficial cli.github.com).

### S. Madurez (OpenSSF Scorecard)

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | 6.9 | Análisis del 2026-11-26 sobre el commit `8909da4` (tras la Release v1.0.0) |
| Maintained | 0 | El repositorio tiene menos de 90 días: mide antigüedad y actividad sostenida, no seguridad |
| Pinned-Dependencies | 0 | Las acciones se fijan por etiqueta (`@v7`, `@v4`…), no por hash de commit: una etiqueta se puede mover. Es el único 0 que señala un riesgo real de cadena de suministro (reto S.3) |
| License | 0 | No hay archivo LICENSE: sin licencia, nadie puede reutilizar legalmente el código. No afecta a la seguridad, sí a la adopción |
| CII-Best-Practices | 0 | No se ha solicitado la insignia de buenas prácticas de la OpenSSF (es un trámite voluntario) |
| Fuzzing | 0 | No hay pruebas de fuzzing integradas (p. ej. ClusterFuzzLite); fuera del alcance del laboratorio |

Otras notas: Contributors también da 0 (ningún contribuidor pertenece a una empresa u organización). Code-Review = 7 (10 de 13 cambios aprobados): los 3 sin aprobar son los commits directos a `main` anteriores a proteger la rama (importación y los de octubre), justo lo que la protección de la Parte G evita ahora. Signed-Releases = 8: reconoce los `.sigstore.json` de la Release v1.0.0; probablemente no llega a 10 porque espera la procedencia en formato `.intoto.jsonl`. Branch-Protection sale sin datos: con reglas clásicas Scorecard necesita un token de administrador, que no se crea a propósito. Packaging tampoco aplica (no se publica en PyPI).

Punto de control S: el check más útil para elegir una dependencia es **Vulnerabilities** (junto con Code-Review y Security-Policy), porque dice si hoy hay fallos conocidos sin corregir y si el proyecto revisa sus cambios y tiene un canal para reportar. El más engañoso sin contexto es **Maintained**: a ReportAudit le pone un 0 solo por ser nuevo, aunque tenga 0 vulnerabilidades, releases firmadas y todas las puertas activas.

### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`.

Compara el expediente con tu respuesta B5 de la Práctica 2: ¿qué evidencia imaginaste que ahora
existe de verdad, y cuál sigue sin existir?
