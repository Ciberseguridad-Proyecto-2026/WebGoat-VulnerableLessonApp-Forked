# Priorización de hallazgos SCA (Fase 4, paso C.4)

**Responsable:** Estudiante C · **Fecha de corte:** 17-nov-2026
**Insumos:** SBOM [`sbom/sbom-webgoat.cdx.json`](sbom/sbom-webgoat.cdx.json) (Syft 1.57.2), Grype 0.122.0 (BD del 17-nov-2026),
Dependency-Track 4.14.6 (NVD vía API + OSV + EPSS), FIRST EPSS API y catálogo CISA KEV `2026.11.17` (1 782 entradas).

## 1. Panorama general

| Fuente | Total | Critical | High | Medium | Low | Componentes vulnerables |
|---|---:|---:|---:|---:|---:|---|
| Grype (local y CI) | 37 | 1 | 22 | 14 | 0 | `xstream 1.4.5`, `commons-lang3 3.14.0` |
| Dependency-Track | 37 | 1 | 22 | 14 | 0 | idem (1 violación **FAIL** + 1 **WARN**) |

- **Dónde se concentra el riesgo:** 36 de los 37 hallazgos son de **XStream 1.4.5**, una librería que WebGoat incluye
  **a propósito** para la lección *Vulnerable Components*.
- **Librerías que la guía sugería revisar** (Spring, Jackson, HSQLDB, Log4j/Commons): ninguna tiene CVEs conocidos en
  las versiones de este fork. Spring Framework 7.0.10 / Spring Boot 4.1.2, Jackson 2.21.7 y 3.1.7, HSQLDB 2.7.3,
  Log4j API 2.25.5 y Tomcat 11.0.27 salen limpios. De la familia Commons, solo `commons-lang3` aparece.
- **Por qué no aparece `commons-collections 3.2.1`:** está en `dependencyManagement`, pero **no se empaqueta** en el
  JAR (no figura en `dependency:tree`). Por eso no es un riesgo de ejecución.

## 2. Método de priorización

Las cinco señales se combinan en este orden. Cada señal descarta o sube una prioridad, no se suman a ciegas.

1. **CISA KEV:** si hay explotación activa conocida, la prioridad mínima es **P1**.
2. **Alcanzabilidad:** se revisa si WebGoat ejecuta la función vulnerable con datos que controla el usuario. Se
   comprobó en el código fuente y buscando referencias en todas las clases del JAR. Si **no** es alcanzable, el
   hallazgo baja a **P4** y se documenta con VEX `not_affected`.
3. **EPSS:** probabilidad de explotación en los próximos 30 días (FIRST, 17-nov-2026). Con EPSS ≥ 0,5 se sube un nivel.
4. **CVSS v3.1 (NVD):** mide el impacto técnico (RCE frente a DoS).
5. **Contexto WebGoat:** si la vulnerabilidad es intencional, se mitiga con aislamiento del despliegue y no se
   "parchea" (regla del proyecto y nota de la guía: la corrección es de la Fase 7).

| Prioridad | Criterio | SLA propuesto |
|---|---|---|
| **P1** | KEV, o RCE alcanzable con EPSS ≥ 0,5 | Mitigar de inmediato (aislamiento) y decidir en Fase 7 |
| **P2** | RCE/DoS alcanzable con EPSS ≥ 0,5, sin KEV | Próxima iteración |
| **P3** | Alcanzable con EPSS < 0,5 | Backlog con fecha |
| **P4** | No alcanzable (VEX `not_affected`) | Actualizar en mantenimiento normal |

## 3. Tabla de priorización (8 CVEs)

| # | CVE (alias) · librería | CVSS v3.1 (NVD) | EPSS (percentil) | CISA KEV | Alcanzabilidad en WebGoat | Prioridad |
|---|---|---|---|---|---|---|
| 1 | **CVE-2021-39144** (GHSA-j9h8-phrw-h4fh) · `xstream 1.4.5` | **8.5** High `AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` | **0,981** (99,9 %) | **Sí** (desde 10-mar-2023) | **Sí.** `POST /WebGoat/VulnerableComponents/attack1` llama a `XStream.fromXML(payload)` con el parámetro del usuario. XStream 1.4.5 no tiene *security framework* ni allow-list de tipos. La cadena de *gadgets* concreta usa clases internas del JDK y no se reprodujo en JDK 25. | **P1** |
| 2 | **CVE-2013-7285** (GHSA-f554-x222-wgf7) · `xstream 1.4.5` | **9.8** Critical `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **0,844** (99,7 %) | No | **Sí, confirmada.** Es la CVE que la lección enseña a explotar (proxy dinámico + `java.beans.EventHandler`). El `Dockerfile` abre `java.desktop/java.beans` con `--add-opens`, lo que habilita la cadena. En la práctica requiere sesión, pero el registro de usuarios es libre. | **P1** (dispara el gate) |
| 3 | **CVE-2020-26217** (GHSA-mw36-7c6c-q4q2) · `xstream 1.4.5` | 8.8 High `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 0,850 (99,7 %) | No | **Sí.** Mismo punto de entrada `fromXML`, RCE por manipulación del stream de entrada. | **P2** |
| 4 | **CVE-2021-29505** (GHSA-7chv-rrw6-w6fc) · `xstream 1.4.5` | 8.8 High `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 0,772 (99,6 %) | No | **Sí.** Mismo punto de entrada, RCE. | **P2** |
| 5 | **CVE-2021-21341** (GHSA-2p3x-qw9c-25hh) · `xstream 1.4.5` | 7.5 High `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 0,778 (99,6 %) | No | **Sí.** DoS (bucle infinito / CPU) con un XML manipulado en el mismo endpoint. Afecta a toda la instancia compartida de la clase. | **P2** |
| 6 | **CVE-2022-41966** (GHSA-j563-grx4-pjpv) · `xstream 1.4.5` | 7.5 High `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 0,093 (95,5 %) | No | **Sí.** DoS por *stack overflow* con colecciones recursivas en `fromXML`. | **P3** |
| 7 | **CVE-2024-47072** (GHSA-hfq9-hggm-c56q) · `xstream 1.4.5` | 7.5 High `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 0,020 (81,1 %) | No | **No.** Solo afecta a `BinaryStreamDriver`. WebGoat usa `new XStream()` (driver XML `XppDriver`) y ninguna clase fuera de xstream referencia `BinaryStreamDriver`. | **P4**, VEX `not_affected` |
| 8 | **CVE-2025-48924** (GHSA-j288-q9x7-2f5v) · `commons-lang3 3.14.0` | 5.3 Medium `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (CNA Apache) · 6.5 (GHSA) | 0,026 (85,8 %) | No | **No.** WebGoat no invoca `ClassUtils.getClass(...)`. El único llamador en el JAR es `commons-text` `ConstantStringLookup` (`${const:…}`), y WebGoat no usa `StringSubstitutor` ni `StringLookupFactory`: de commons-text solo usa `StringEscapeUtils`. | **P4**, VEX `not_affected` |

### Evidencia de alcanzabilidad

- **Punto de entrada de XStream:** `src/main/java/org/owasp/webgoat/lessons/vulnerablecomponents/VulnerableComponentsLesson.java`.
  El `@PostMapping("/VulnerableComponents/attack1")` crea `new XStream()` y llama a `xstream.fromXML(payload)` sobre
  `@RequestParam String payload`. Es la única instancia de XStream en el código.
- **`ClassUtils` y `BinaryStreamDriver`:** se recorrieron todas las clases de `BOOT-INF/classes` y de cada JAR de
  `BOOT-INF/lib` buscando las referencias `org/apache/commons/lang3/ClassUtils` y `BinaryStreamDriver`.
  - Resultado: una sola referencia a `ClassUtils`, en `commons-text-1.15.0.jar` (`org/apache/commons/text/lookup/ConstantStringLookup.class`).
  - Ninguna referencia a `BinaryStreamDriver` fuera de xstream.
- **Uso de commons-text en WebGoat:** solo `StringEscapeUtils.escapeHtml4`
  (`lessons/httpparameterpollution/ParameterPollutionObservation.java`) y `StringEscapeUtils.escapeJson`
  (`container/assignments/AttackResult.java`).

## 4. Decisiones y plan de acción

| Prioridad | CVEs | Decisión |
|---|---|---|
| **P1** | CVE-2021-39144, CVE-2013-7285 | **Riesgo aceptado con controles compensatorios** (VEX `affected`). Es la vulnerabilidad didáctica y `pom.xml` marca XStream como `do not update necessary for lesson`. Controles: desplegar solo en `127.0.0.1` o en una red Docker aislada, sin datos reales; el gate de CI la **bloquea y la hace visible** en cada PR; Dependabot la ignora a propósito. La Fase 7 decidirá si se actualiza a ≥ 1.4.20 con allow-list (rompería la lección). |
| **P2 / P3** | CVE-2020-26217, CVE-2021-29505, CVE-2021-21341, CVE-2022-41966 | Mismo componente y mismo punto de entrada. Se cubren con la misma decisión de P1. Se siguen en Dependency-Track como *In Triage*. |
| **P4** | CVE-2024-47072, CVE-2025-48924 | **No afectados** (VEX `not_affected` / `vulnerable_code_not_in_execute_path`). Aun así, `commons-lang3` **no** es una dependencia de lección: en la Fase 7 se subirá `commons-lang3.version` a ≥ 3.18.0 (Dependabot lo propondrá). |

## 5. Declaración VEX

Archivo: [`vex/vex-webgoat.json`](vex/vex-webgoat.json) (formato **OpenVEX v0.2.0**), con 4 declaraciones:

| CVE | Estado VEX | Justificación |
|---|---|---|
| CVE-2025-48924 | `not_affected` | `vulnerable_code_not_in_execute_path`: WebGoat no llama a `ClassUtils.getClass` |
| CVE-2024-47072 | `not_affected` | `vulnerable_code_not_in_execute_path`: no se usa `BinaryStreamDriver` |
| CVE-2013-7285 | `affected` | Vulnerabilidad intencional de la lección; mitigación por aislamiento |
| CVE-2021-39144 | `affected` | Mismo punto de entrada; KEV; mitigación por aislamiento |

Para comprobar que Grype respeta el VEX (los `not_affected` dejan de contarse):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v grype-db:/.cache/grype anchore/grype:latest \
  sbom:/src/security/sbom/sbom-webgoat.cdx.json --vex /src/security/vex/vex-webgoat.json
```
