# Requisitos de seguridad — OWASP ASVS 4.0.3 (Fase 1)

| Campo | Valor |
|---|---|
| Proyecto | Desarrollo Seguro de una Aplicación (SSDLC) — OWASP WebGoat |
| Versión analizada | Fork `2026.6-SNAPSHOT` |
| Responsable | Pablo Siquinajay — Fase 1 (diseño) |
| Fecha | 18 de noviembre de 2026 |
| Estándar | [OWASP ASVS 4.0.3](https://github.com/OWASP/ASVS/tree/v4.0.3), niveles 1 y 2 |
| Base | [`arquitectura.md`](arquitectura.md) · [`dfd.md`](dfd.md) · [`clasificacion-datos.md`](clasificacion-datos.md) |

## 1. Método

Se seleccionaron **24 requisitos ASVS 4.0.3** (19 de nivel 1 y 5 de nivel 2) aplicables a WebGoat. Cada fila indica el componente real afectado, cómo se verificará y el estado actual. Las descripciones son una síntesis en español; el texto normativo exacto está en el ASVS oficial.

**Estados utilizados**

- **Cumple** — el control existe y es verificable.
- **Parcial** — existe parcialmente o solo en algunos flujos.
- **No cumple** — no existe o el comportamiento lo contradice.
- **En progreso** — control planificado o en implementación durante el proyecto.

> **Vulnerabilidades intencionales.** WebGoat es una aplicación de formación vulnerable por diseño. Los requisitos marcados como *«excepción de lección»* **no se corrigen en esta fase**; se documentan como riesgo aceptado y se gestionan en la Fase 7 con VEX y política de bloqueo. El objetivo del proyecto es proteger el **contenedor, la cadena de suministro y el pipeline**, no “arreglar” las lecciones.

## 2. Tabla de requisitos

| ID ASVS | Nivel | Requisito (síntesis) | Componente WebGoat afectado | Verificación | Estado |
|---|:---:|---|---|---|---|
| **V1.1.4** | L2 | Documentar y justificar límites de confianza, componentes y flujos de datos significativos. | `security/diseño/` (arquitectura, DFD, este paquete) | Revisión manual en la entrega | **Cumple** (Fase 1) |
| **V2.1.1** | L1 | Contraseñas de al menos 12 caracteres. | `container/users/UserForm.java` (`@Size(min=6, max=10)`) | Prueba unitaria + revisión | **No cumple** |
| **V2.1.7** | L1 | Verificar contraseñas contra listas de filtradas (top 10.000 o API). | Registro y login (`RegistrationController`, `WebSecurityConfig`) | Prueba manual + unitaria | **No cumple** |
| **V2.2.1** | L1 | Controles anti-automatización (bloqueo suave, rate limiting, CAPTCHA); máx. 100 fallos/hora por cuenta. | Form login y registro | Prueba manual / DAST | **No cumple** |
| **V2.4.1** | L2 | Almacenar contraseñas con sal y función de hash aprobada (bcrypt, Argon2, PBKDF2…). | `container/WebSecurityConfig.java` (`NoOpPasswordEncoder`), `users/UserService.java`, tabla `web_goat_user` | SAST + revisión de código | **No cumple** (crítico) |
| **V3.2.1** | L1 | Generar un nuevo token de sesión al autenticarse. | Spring Security (`changeSessionId` por defecto) | Prueba de integración (cookie antes/después) | **Cumple** |
| **V3.3.1** | L1 | Logout y expiración invalidan el token de sesión. | `WebSecurityConfig.java` (`invalidateHttpSession(true)`, `deleteCookies("JSESSIONID")`) | Prueba de integración | **Cumple** |
| **V3.4.1** | L1 | Cookie de sesión con atributo `Secure`. | `application-webgoat.properties` (`server.ssl.enabled=false` por defecto) | Revisión de configuración + DAST | **No cumple** (HTTP local; excepción documentada) |
| **V3.4.2** | L1 | Cookie de sesión con atributo `HttpOnly`. | Tomcat/Spring Boot (por defecto `HttpOnly=true`) | Inspección de `Set-Cookie` en ejecución | **Cumple** |
| **V3.4.3** | L1 | Cookie de sesión con atributo `SameSite`. | No configurado explícitamente | Revisión de configuración + DAST | **Parcial** |
| **V4.1.1** | L1 | Aplicar control de acceso en una capa de servicio confiable. | `WebSecurityConfig.java`; matcher `/service/admin/**` → `WEBGOAT_ADMIN` | Prueba de integración + SAST | **Parcial** (actuator y `POST /mail` públicos; IDOR en lecciones) |
| **V4.2.1** | L1 | Protección contra IDOR en lectura/escritura de registros. | `lessons/idor/IDORViewOtherProfile.java`, `IDOREditOtherProfile.java`, `UserProfile.java` | Prueba de integración | **No cumple** (excepción de lección) |
| **V5.1.3** | L1 | Validación positiva (listas permitidas) de toda entrada. | `UserForm.java` (regex de usuario); resto de lecciones aceptan payloads | Pruebas unitarias + SAST | **Parcial** (excepción de lecciones) |
| **V5.3.3** | L1 | Escape de salida contextual contra XSS reflejado, almacenado y DOM. | Thymeleaf escapa por defecto; `lessons/xss/`, `lessons/htmltampering/` vulnerables por diseño | SAST + DAST (ZAP) | **Parcial** (excepción de lecciones) |
| **V5.3.4** | L1 | Consultas SQL/HQL/ORM parametrizadas o protegidas contra inyección. | `lessons/sqlinjection/introduction/SqlInjectionLesson*.java` (concatenación); contenedor usa JPA/JdbcTemplate | SAST (Semgrep) + revisión | **No cumple** (lecciones); contenedor cumple |
| **V5.5.1** | L1 | Objetos serializados con controles de integridad. | `lessons/deserialization/` | SAST + revisión | **No cumple** (excepción de lección) |
| **V6.2.5** | L2 | No usar algoritmos débiles (MD5, SHA1) ni modos inseguros (ECB) salvo compatibilidad justificada. | `lessons/cryptography/HashingAssignment.java`, `CryptoUtil.java` | SAST + revisión | **No cumple** (excepción de lección) |
| **V7.1.1** | L1 | No registrar credenciales ni datos de pago; tokens solo de forma irreversible. | Revisión de `log.*` en `container/users/`, `container/mailbox/` | SAST + revisión manual | **Parcial** (no se observan contraseñas en logs; faltan pruebas) |
| **V7.2.1** | L2 | Registrar todas las decisiones de autenticación con metadatos útiles. | No existe log de auditoría dedicado; solo logging de framework | Revisión + DAST | **No cumple** |
| **V7.4.1** | L1 | Mensaje genérico ante errores inesperados o sensibles. | `application-webgoat.properties` (`include-stacktrace=always`), `application-webwolf.properties` | Revisión de configuración + DAST | **No cumple** |
| **V8.3.1** | L1 | Datos sensibles en cuerpo/cabeceras, nunca en la cadena de consulta. | Login por POST; enlaces de reset con token en URL (`lessons/passwordreset/resetlink/`) | Revisión + DAST | **Parcial** |
| **V10.1.1** | L2 | Usar una herramienta de análisis de código que detecte código potencialmente malicioso. | CI: Semgrep/CodeQL en `.github/workflows/devsecops.yml` | Pipeline (job `sast`) | **En progreso** (job pendiente, Ana Lopez) |
| **V14.2.1** | L1 | Mantener componentes actualizados con verificación de dependencias en el build. | `.github/workflows/devsecops.yml` (Syft + Grype), `.github/dependabot.yml` | Pipeline (job `sca`) | **Parcial** (gate `sca` mergeado; Dependabot con PR pendientes) |
| **V14.5.1** | L1 | Aceptar solo métodos HTTP usados por la aplicación y alertar de los inválidos. | Mapeos MVC de lecciones; actuator expuesto | DAST + revisión | **Parcial** |

## 3. Resumen

| Estado | Cantidad | Requisitos |
|---|:---:|---|
| Cumple | **4** | V1.1.4, V3.2.1, V3.3.1, V3.4.2 |
| Parcial | **8** | V3.4.3, V4.1.1, V5.1.3, V5.3.3, V7.1.1, V8.3.1, V14.2.1, V14.5.1 |
| No cumple | **11** | V2.1.1, V2.1.7, V2.2.1, V2.4.1, V3.4.1, V4.2.1, V5.3.4, V5.5.1, V6.2.5, V7.2.1, V7.4.1 |
| En progreso | **1** | V10.1.1 |
| **Total** | **24** | 19 de nivel 1 · 5 de nivel 2 |

De los 11 incumplimientos, **4 son vulnerabilidades intencionales de lecciones** (V4.2.1, V5.3.4, V5.5.1, V6.2.5) y **7 son de la plataforma/contenedor** (autenticación, sesión, logging y errores), que sí deben corregirse o justificarse en la Fase 7.

## 4. Trazabilidad requisito → control → fase

| Requisito | Control que lo verificará | Fase |
|---|---|---|
| V2.x, V3.x, V4.x, V5.x, V7.x | **SAST** (Semgrep: `p/java`, `p/owasp-top-ten`, reglas propias) + pruebas de integración | 3 y 7 |
| V1.1.4, V5.1.3, V5.3.3, V4.1.1 | **DAST** (ZAP baseline y escaneo autenticado) | 6 |
| V14.2.1 | **SCA** (Syft + Grype + Dependency-Track + Dependabot) | 4 |
| V14.5.1, V7.4.1 | **DAST** + revisión de configuración (Trivy config / Checkov sobre IaC) | 5 y 6 |
| Excepciones de lección (IDOR, SQLi, XSS, crypto, deserialization) | **VEX** + política de bloqueo + revisión manual | 7 |
| V10.1.1 | Job `sast` con SARIF y extensión SAST en VS Code | 3 |

## 5. Notas de aceptación y excepciones

1. **V2.4.1 (contraseñas en texto plano)** es el hallazgo de mayor severidad de la plataforma: cualquier lectura de la BD expone credenciales. Se corregirá en la Fase 7 con un `PasswordEncoder` fuerte y migración de usuarios de prueba.
2. **V3.4.1 (`Secure`)** no puede cumplirse mientras el laboratorio use HTTP en loopback; se documentará como excepción de entorno y se reevaluará si se habilita TLS (`WEBGOAT_SSLENABLED=true`).
3. Las lecciones con vulnerabilidades intencionales se declaran como **riesgo aceptado** con justificación pedagógica, alcance (solo instancia local) y VEX (`security/vex/`).
4. Cada requisito debe tener evidencia enlazable (reporte SARIF, log de pipeline, prueba automatizada o captura) para la defensa final.
