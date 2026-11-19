# Madurez inicial del proceso de seguridad — OWASP SAMM v2 (Fase 0)

| Campo | Valor |
|---|---|
| Proyecto | Desarrollo Seguro de una Aplicación (SSDLC) — OWASP WebGoat |
| Aplicación auditada | Fork de OWASP WebGoat `2026.6-SNAPSHOT` (Java 25 / Spring Boot 4.1.2) |
| Responsable | Pablo Siquinajay — Fases 0 y 1 |
| Fecha de evaluación | 18 de noviembre de 2026 |
| Nivel objetivo | 2 de diciembre de 2026 (entrega final) |
| Marco de referencia | [OWASP SAMM v2.0](https://owaspsamm.org/) |

## 1. Metodología

La evaluación sigue el modelo **OWASP SAMM v2.0**: 5 funciones de negocio, 3 prácticas por función (15 prácticas en total) y 3 niveles de madurez por práctica.

| Nivel | Significado |
|---|---|
| **0** | La práctica no existe o es puramente ad hoc. |
| **1** | La práctica existe de forma básica e informal; se aplica en algunos casos sin proceso definido. |
| **2** | La práctica está definida, documentada y se aplica de forma consistente en el equipo/proyecto. |
| **3** | La práctica se mide, se revisa y se mejora continuamente (optimizada). |

**Alcance temporal.** Se evalúa el **estado inicial del fork recién clonado**, antes de los aportes del equipo (pipeline CI/CD, SBOM, Dependabot, VEX). En la sección 4 se documenta, como evidencia complementaria, el avance ya incorporado a la rama `main` durante la Fase 3 y la Fase 4.

**Fuentes de evidencia utilizadas**

- `pom.xml` — stack, dependencias, plugins de calidad (Spotless, Checkstyle, PMD).
- `Dockerfile` y `Dockerfile_desktop` — despliegue y endurecimiento de imagen.
- `src/main/resources/application-webgoat.properties` y `application-webwolf.properties` — configuración de seguridad, sesión, base de datos y actuator.
- `src/main/java/org/owasp/webgoat/container/` — autenticación (`WebSecurityConfig`), usuarios, progreso, mailbox.
- `src/test/java/` y `src/it/java/` — pruebas unitarias, de integración REST y Playwright.
- `.github/workflows/devsecops.yml` y `.github/dependabot.yml` — automatización existente al momento de la evaluación.
- Inspección manual del código y de la aplicación en ejecución (`docker run ... webgoat/webgoat`).

> **Nota ética y de alcance:** WebGoat es una aplicación *intencionadamente vulnerable* para formación. Los hallazgos de seguridad del código de las lecciones **no se corrigen en esta fase** (eso corresponde a la Fase 7); esta evaluación mide la madurez del *proceso* de desarrollo seguro del equipo, no el número de vulnerabilidades de las lecciones.

## 2. Evaluación de las 15 prácticas SAMM

| Función | Práctica (SAMM) | Nivel actual | Justificación / evidencia | Nivel objetivo (2-dic) |
|---|---|:---:|---|:---:|
| **Gobernanza** | Estrategia y métricas (SM) | **0** | No existen objetivos de seguridad ni métricas definidas en el repositorio. El README describe cómo ejecutar la app, no una estrategia de seguridad. | **1** |
| **Gobernanza** | Política y cumplimiento (PC) | **1** | El `pom.xml` declara licencia GPL-2.0 y organización OWASP, pero no hay política de seguridad, proceso de revisión legal ni mapeo normativo. | **2** |
| **Gobernanza** | Educación y guía (EG) | **0** | No hay guía de codificación segura para colaboradores; las lecciones son material didáctico, no formación interna del equipo. | **1** |
| **Diseño** | Evaluación de amenazas (TA) | **0** | No existe modelo de amenazas, DFD formal ni registro de riesgos. Se abordará en la Fase 2 con STRIDE. | **2** |
| **Diseño** | Requisitos de seguridad (SR) | **0** | No hay requisitos de seguridad ni criterios de aceptación verificables. Se formalizan en `security/diseño/requisitos-asvs.md` (Fase 1). | **2** |
| **Diseño** | Arquitectura segura (SA) | **0** | La arquitectura no está documentada y el diseño es inseguro por propósito (CSRF y cabeceras de seguridad deshabilitadas en `WebSecurityConfig`). Se documenta en esta fase y se endurece el despliegue en la Fase 5. | **1** |
| **Implementación** | Construcción segura (SB) | **1** | Build reproducible con Maven Wrapper 3.9.9, versiones fijadas en `pom.xml` y controles de calidad (Spotless, Checkstyle, PMD). No había SBOM ni escaneo de dependencias al clonar. | **2** |
| **Implementación** | Despliegue seguro (SD) | **1** | Existe `Dockerfile` con usuario no root (`USER webgoat`) e imagen base fijada por etiqueta; pero usa un JDK completo, no fija digest, no gestiona secretos y la app escucha en `0.0.0.0` dentro del contenedor. | **2** |
| **Implementación** | Gestión de defectos (DM) | **0** | No hay proceso de triaje, severidad, propietario ni seguimiento de hallazgos; los issues de GitHub no se usan de forma sistemática. | **1** |
| **Verificación** | Evaluación de arquitectura (AA) | **0** | No se realiza revisión formal de arquitectura ni de cambios de diseño. | **1** |
| **Verificación** | Pruebas guiadas por requisitos (RT) | **1** | Hay pruebas JUnit/Spring, integración REST (REST Assured) y UI (Playwright), pero no están ligadas a requisitos de seguridad ni cubren casos de abuso. | **2** |
| **Verificación** | Pruebas de seguridad (ST) | **0** | Al clonar no había SAST, SCA ni DAST en el pipeline. | **2** |
| **Operaciones** | Gestión de incidentes (IM) | **0** | No existe procedimiento de respuesta a incidentes, contacto ni playbook. | **1** |
| **Operaciones** | Gestión de entornos (EM) | **1** | Entorno local reproducible con Docker y propiedades separadas por aplicación (`application-webgoat.properties`, `application-webwolf.properties`). Sin IaC ni endurecimiento. | **2** |
| **Operaciones** | Gestión operativa (OM) | **1** | Actuator expone `health`, `env` y `configprops`; hay logging configurado, pero no alertas, respaldos ni retención definida. | **1** |

## 3. Resumen de madurez

| Función | Nivel actual (suma de 3 prácticas) | Nivel objetivo (suma) |
|---|:---:|:---:|
| Gobernanza | 1 / 9 | 4 / 9 |
| Diseño | 0 / 9 | 5 / 9 |
| Implementación | 2 / 9 | 5 / 9 |
| Verificación | 1 / 9 | 5 / 9 |
| Operaciones | 2 / 9 | 4 / 9 |
| **Total** | **6 / 45** | **23 / 45** |

**Lectura del resultado.** La línea base es baja (mayoría de prácticas en nivel 0 o 1), lo que es coherente con un proyecto open source de formación que no sigue un SSDLC formal. El objetivo para el 2 de diciembre no es alcanzar nivel 2 en todo, sino **demostrar un salto verificable y sostenible**: diseño documentado, modelo de amenazas, pipeline con gates reales, SBOM/SCA, DAST y un proceso de remediación con evidencia.

## 4. Evidencia del avance ya incorporado (Fases 3 y 4)

Estos aportes **no forman parte de la línea base**; se registran para que la comparación final (Fase 8) sea trazable.

| Evidencia en `main` | Práctica SAMM impactada | Efecto |
|---|---|---|
| `.github/workflows/devsecops.yml` con job `sca` (Syft + Grype, umbral *critical*, sin `|| true`) | ST, SB | Inicia la automatización de pruebas de seguridad y del inventario de componentes. |
| `.github/dependabot.yml` (Maven y GitHub Actions) | SB, ST | Automatiza la actualización de dependencias y acciones. |
| `security/sbom/sbom-webgoat.cdx.json` (CycloneDX) | SB | Inventario de componentes generado y versionado. |
| `security/dtrack/`, `security/sca-priorizacion.md`, `security/vex/` | ST, DM | Publicación en Dependency-Track, priorización CVSS/EPSS/KEV y declaración VEX. |
| Jobs `secretos` y `sast` (Semgrep + SARIF) | ST | **Pendientes de merge** al cierre de esta evaluación (responsabilidad de Ana Lopez). |

## 5. Acciones priorizadas hacia la entrega final

| Prioridad | Acción | Fase | Práctica SAMM |
|:---:|---|---|---|
| 1 | Completar jobs `secretos` y `sast` con SARIF y gate documentado | 3 | ST, SB |
| 2 | Modelo de amenazas STRIDE (≥12 amenazas) con trazabilidad ASVS/controles | 2 | TA, SR |
| 3 | DAST con ZAP baseline en cada PR y un escaneo autenticado | 6 | ST, RT |
| 4 | IaC endurecida (Dockerfile mínimo, no root, digest fijo) + Checkov/Trivy | 5 | SD, EM |
| 5 | Política de bloqueo y protección de rama con checks obligatorios | 7 | PC, DM |
| 6 | Remediación de ≥5 hallazgos vía PR y centralización en DefectDojo | 7 | DM, IM |
| 7 | Repetir esta evaluación y comparar (madurez final) | 8 | Todas |

## 6. Cómo repetir la evaluación (Fase 8)

1. Reutilizar esta misma tabla y escala para evitar sesgos.
2. Recolectar evidencia del repositorio: workflow completo, SARIF, SBOM, reportes ZAP, PRs de remediación y política de bloqueo.
3. Puntuar cada práctica con al menos una evidencia enlazable por fila.
4. Registrar la diferencia **antes/después** y justificar los niveles que no se alcanzaron.

---

**Documentos relacionados:** [`diseño/arquitectura.md`](diseño/arquitectura.md) · [`diseño/dfd.md`](diseño/dfd.md) · [`diseño/clasificacion-datos.md`](diseño/clasificacion-datos.md) · [`diseño/requisitos-asvs.md`](diseño/requisitos-asvs.md)
