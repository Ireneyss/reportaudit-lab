# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Irene Yago Soriano
- **Repositorio:** https://github.com/Ireneyss/reportaudit-lab
- **Sistema operativo y versión de Python usados:**

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 |  |  |  |  |  |
| 2 |  |  |  |  |  |
| 3 |  |  |  |  |  |
| 4 |  |  |  |  |  |
| 5 |  |  |  |  |  |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` |  |  |  |  |  |  | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` |  |  |  |  |  |  | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` |  |  |  |  |  |  | n/a |
| H4 Hash MD5 en `hash_password_legacy` |  |  |  |  |  |  | n/a |
| H5 Clave de API escrita en el código |  |  |  |  |  |  | ✗ |
| H6 Contraseña SMTP escrita en el código |  |  |  |  |  |  | ✗ |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué te dice eso sobre depender de una sola herramienta?
Trivy resultó ser muy eficaz detectando vulnerabilidades en dependencias públicas y CVEs conocidos en requirements.txt, pero falló (falso negativo) al detectar contraseñas hardcodeadas (H5 y H6). Esto demuestra que depender de una sola herramienta de propósito general es insuficiente; se requiere un enfoque de "defensa en profundidad" combinando escáneres SCA (Trivy/Grype) con herramientas especializadas en secretos (Gitleaks) y código estático (Semgrep/CodeQL).
---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | (Revisa tu archivo requirements.in local, normalmente son 3 o 4 librerías principales como flask o pyyaml). |
| Componentes Python en el SBOM | 9 paquetes Python (blinker, click, colorama, flask, itsdangerous, jinja2, markupsafe, pyyaml, werkzeug). |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 GitHub Actions (actions/checkout, SonarSource/sonarqube-scan-action, y github/codeql-action/init y analyze). Salen de nuestros flujos de CI/CD. |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | CycloneDX JSON (formato definido al ejecutar Syft con -o cyclonedx-json). |

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
| Hallazgos de Semgrep en `app/` | 3 |  |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 |  |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM | 12 |  |
| Alertas abiertas de Dependabot |  |  |

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
