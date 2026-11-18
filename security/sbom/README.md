# SBOM y escaneo SCA local: Syft + Grype (Fase 4, paso C.2)

**Responsable:** Estudiante C · **Fecha de generación:** 17-nov-2026

## Contenido de la carpeta

| Archivo | Qué es | Cómo se generó |
|---|---|---|
| `sbom-webgoat.cdx.json` | SBOM **CycloneDX 1.7 (JSON)** de WebGoat `2026.6-SNAPSHOT`: 239 componentes Maven, directos y transitivos. | Syft 1.57.2 sobre el JAR ejecutable |
| `grype-report.txt` | Reporte de vulnerabilidades en formato tabla (37 hallazgos). | Grype 0.122.0 sobre el SBOM (base de datos del 17-nov-2026) |
| `dependency-tree.txt` | Salida de `mvn dependency:tree` que verifica que las dependencias Java resuelven bien. | Maven 3.9 + JDK 25 (Temurin) |

## Por qué el SBOM se genera desde el JAR y no desde el código fuente

La guía sugiere `syft /src`. Sobre el código fuente, Syft solo lee `pom.xml`, así que obtiene las dependencias **directas**.
No resuelve las transitivas, que Maven calcula al construir. WebGoat se distribuye como un *fat JAR* de Spring Boot
(`BOOT-INF/lib/*.jar`). Escanear ese JAR describe **exactamente lo que se ejecuta** en producción o en Docker,
incluidos Spring Framework, Tomcat embebido, Jackson, HSQLDB, etc. El job `sca` de CI usa el mismo criterio.

## Comandos (Git Bash en Windows, raíz del repositorio)

```bash
# 0. Verificar que Maven resuelve las dependencias (JDK 25 + Maven 3.9 en contenedor,
#    porque el proyecto compila con Java 25)
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v webgoat-m2:/root/.m2 -w /src \
  maven:3.9-eclipse-temurin-25 mvn -B -q dependency:tree -DoutputFile=security/sbom/dependency-tree.txt

# 1. Construir el JAR ejecutable (sin tests ni linters: solo interesa el inventario)
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v webgoat-m2:/root/.m2 -w /src \
  maven:3.9-eclipse-temurin-25 mvn -B -DskipTests -Dspotless.check.skip=true -Dcheckstyle.skip -Dpmd.skip package

# 2. SBOM CycloneDX con Syft
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src anchore/syft:latest \
  /src/target/webgoat-2026.6-SNAPSHOT.jar \
  --source-name OWASP-WebGoat --source-version 2026.6-SNAPSHOT \
  -o cyclonedx-json > security/sbom/sbom-webgoat.cdx.json

# 3. Escaneo con Grype (la caché de la BD se guarda en un volumen para no descargarla cada vez)
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v grype-db:/.cache/grype anchore/grype:latest \
  sbom:/src/security/sbom/sbom-webgoat.cdx.json -o table > security/sbom/grype-report.txt

# 4. Mismo umbral que el gate de CI: código de salida 1 si hay algún hallazgo Critical
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v grype-db:/.cache/grype anchore/grype:latest \
  sbom:/src/security/sbom/sbom-webgoat.cdx.json --fail-on critical
```

> `MSYS_NO_PATHCONV=1` evita que Git Bash convierta `/src` en una ruta de Windows.

## Resumen de resultados (17-nov-2026)

| Severidad | Hallazgos | Componentes |
|---|---:|---|
| Critical | 1 | `xstream 1.4.5` (CVE-2013-7285) |
| High | 22 | `xstream 1.4.5` |
| Medium | 14 | `xstream 1.4.5` (13), `commons-lang3 3.14.0` (1, CVE-2025-48924) |
| **Total** | **37** | 2 componentes vulnerables de 239 |

- **El gate falla, como se esperaba.** `--fail-on critical` devuelve código 1 por CVE-2013-7285 (XStream). Esa es
  justamente la vulnerabilidad que enseña la lección *Vulnerable Components*.
- **XStream 1.4.5 es intencional.** `pom.xml` lo marca como `do not update necessary for lesson`. No se corrige en
  esta fase (ver la nota del plan: la corrección pertenece a la Fase 7). Dependabot está configurado para ignorarlo.
- **El resto del stack no tiene CVEs conocidos** a la fecha del escaneo. Esto incluye Spring Boot 4.1.2 / Spring
  Framework 7.0.10, Tomcat 11.0.27, Jackson 2.21.7 / 3.1.7, HSQLDB 2.7.3, Log4j API 2.25.5, BouncyCastle 1.85 y
  SnakeYAML 2.6.
- **Dependency-Track da el mismo resultado:** 37 hallazgos (1/22/14) y la política de bloqueo disparada. Ver
  [`../dtrack/README.md`](../dtrack/README.md).
- **La priorización y el VEX** están en [`../sca-priorizacion.md`](../sca-priorizacion.md) y
  [`../vex/vex-webgoat.json`](../vex/vex-webgoat.json).
