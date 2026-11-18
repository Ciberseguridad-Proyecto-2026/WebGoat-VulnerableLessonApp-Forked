# Clasificación de datos (Fase 1)

| Campo | Valor |
|---|---|
| Proyecto | Desarrollo Seguro de una Aplicación (SSDLC) — OWASP WebGoat |
| Versión analizada | Fork `2026.6-SNAPSHOT` |
| Responsable | Estudiante A — Fase 1 (diseño) |
| Fecha | 18 de noviembre de 2026 |
| Base | [`arquitectura.md`](arquitectura.md) · [`dfd.md`](dfd.md) |

## 1. Objetivo y método

Identificar **qué información maneja WebGoat/WebWolf, dónde vive y qué nivel de protección exige**, para derivar requisitos ASVS y priorizar controles. La clasificación usa tres niveles:

| Nivel | Criterio | Ejemplos |
|---|---|---|
| **Alta** | Compromiso permite suplantación, acceso a cuentas o datos personales; requiere cifrado en tránsito/reposo y control de acceso estricto. | Credenciales, cookies de sesión, tokens OAuth2/JWT reales |
| **Media** | Compromiso afecta privacidad o integridad del progreso; requiere control de acceso y minimización. | Progreso, correo interno, payloads, archivos subidos |
| **Baja** | Información pública o didáctica sin impacto directo. | Contenido de lecciones, recursos estáticos |

> **Contexto de uso:** la instancia es de laboratorio y debe contener **solo datos de prueba**. Nunca deben introducirse credenciales reales ni datos personales de terceros. Aun así, se clasifican como si fueran reales porque el proceso SSDLC debe enseñar el tratamiento correcto y porque las lecciones simulan flujos reales (reset de contraseña, JWT, subida de archivos).

## 2. Inventario de datos

| # | Dato | Ejemplo / contenido | Dónde reside | Sensibilidad | Justificación |
|---|---|---|---|---|---|
| 1 | Credenciales WebGoat/WebWolf | `username`, `password`, `role` | `CONTAINER.web_goat_user` (HSQLDB); WebWolf reutiliza la misma tabla (`webwolf/user/WebWolfUser.java`) | **Alta** | Contraseñas almacenadas en texto plano (`NoOpPasswordEncoder`); reutilización de contraseñas entre servicios |
| 2 | Sesión WebGoat | `JSESSIONID` | Cookie del navegador + memoria del servidor | **Alta** | Secuestro de sesión → suplantación completa |
| 3 | Sesión WebWolf | `WEBWOLFSESSION` | Cookie + memoria del servidor | **Alta** | Acceso al buzón de archivos y al catcher |
| 4 | Tokens OAuth2 | Código/token de GitHub | Flujo OAuth2; memoria y sesión | **Alta** | Acceso a la identidad del usuario; secretos por defecto `dummy` |
| 5 | Token CSRF | — | **Deshabilitado** globalmente (`csrf.disable()` en `WebSecurityConfig`) | **Media** | Su ausencia habilita CSRF en lecciones y formularios |
| 6 | JWT de lecciones | Tokens HS256 y secretos de ejemplo | `lessons/jwt/JWTSecretKeyEndpoint.java` (`SECRETS`, `JWT_SECRET`) | **Media** | Secretos hardcodeados de entrenamiento; no deben reutilizarse |
| 7 | Progreso de lecciones | Intentos, asignaciones resueltas, versión | `user_progress`, `lesson_progress`, `assignment_progress` | **Media** | Integridad del progreso; datos por usuario |
| 8 | Correo interno | Bienvenida, enlaces de reset, códigos | `CONTAINER.email` (`sender`, `recipient`, `title`, `contents`) | **Media** | Puede contener tokens de reset y datos del usuario |
| 9 | Payloads de usuario | Cadenas de ataque, parámetros, cuerpos JSON | Memoria, esquemas por usuario (`CREATE SCHEMA <username>`) | **Media** | Pueden contener PII o credenciales introducidas por el alumno |
| 10 | Archivos subidos a WebWolf | Documentos, imágenes, malware de práctica | `/tmp/webwolf-fileserver/<usuario>` | **Media-Alta** | Contenido no confiable; riesgo de XSS/malware si se sirve |
| 11 | Trazas del Request Catcher | Peticiones capturadas, cabeceras y cookies | Memoria de WebWolf (`WebWolfTraceRepository`) | **Media-Alta** | En ejercicios se exfiltran cookies de sesión reales del laboratorio |
| 12 | Logs y errores | Trazas, SQL, rutas, versiones | `stdout` del contenedor | **Media** | `spring.web.error.include-stacktrace=always` expone detalles internos |
| 13 | Configuración y secretos | Contraseña del keystore (`password`), OAuth `dummy` | `application-*.properties` | **Alta** si fueran reales; **Baja** en el laboratorio | Deben gestionarse por variables de entorno/secretos del CI |
| 14 | Datos estáticos de lecciones | HTML, AsciiDoc, imágenes, i18n | `src/main/resources/lessons/`, `webgoat/`, `webwolf/` | **Baja** | Contenido público del proyecto |

## 3. Ciclo de vida y ubicación

| Dato | Creación | Uso | Almacenamiento | Eliminación |
|---|---|---|---|---|
| Credenciales | Registro (`/register.mvc`) o usuario por defecto | Login form/OAuth2 | Tabla HSQLDB en archivo | Borrado del contenedor o de la BD |
| Sesiones | Login correcto | Cada petición autenticada | Memoria + cookie | Logout (`invalidateHttpSession`, borrado de cookie) o expiración |
| Progreso | Cada `AttackResult` | Menú, reporte de progreso | Tablas HSQLDB | Borrado de usuario/BD |
| Correo | Registro y lecciones | Lectura en `/mail` | Tabla `email` | Borrado de la BD |
| Archivos | `POST /files` (WebWolf) | Descarga y lecciones | Filesystem del contenedor | Borrado manual o del contenedor |
| Logs | Toda la ejecución | Diagnóstico | `stdout` (Docker) | Rotación del runtime de Docker |

## 4. Cruces con límites de confianza (DFD)

| Flujo (DFD) | Dato clasificado | Límite | Nivel |
|---|---|---|---|
| D1 | Credenciales | TB0 (navegador → contenedor) | Alta |
| D2/D3 | Sesión y payloads | TB0 → TB1 | Alta / Media |
| D5 | Peticiones capturadas (cookies) | TB2 (WebWolf) | Alta |
| D6/D12 | Archivos subidos | TB2 → TB3 (filesystem) | Media-Alta |
| D8/D13 | Usuarios y roles | TB1 ↔ TB3 (BD) | Alta |
| D10/D11 | Progreso y correo | TB1 ↔ TB3 | Media |
| D14 | Logs y trazas | TB1 → TB3 | Media |

## 5. Controles actuales y brechas

| Dato | Control actual | Brecha | Requisito ASVS |
|---|---|---|---|
| Credenciales | Form login de Spring Security | Texto plano (`NoOpPasswordEncoder`), longitud máxima 10, sin verificación de filtradas | V2.1.1, V2.1.7, V2.4.1 |
| Sesión | `JSESSIONID`, logout invalida sesión | Sin `Secure` por defecto (HTTP), `SameSite` no explícito | V3.3.1, V3.4.1, V3.4.3 |
| CSRF | Deshabilitado (necesario para lecciones) | Sin compensación ni alcance documentado | V4.1.1 (revisión), política de excepción |
| JWT | Lección didáctica | Secretos hardcodeados | V3.5.3, V6.2.5 (excepción de lección) |
| Progreso | Control por usuario en sesión | Sin cifrado en reposo ni auditoría de cambios | V7.2.1, V8.3.1 |
| Correo | Buzón interno | Tokens de reset en enlaces/URL | V8.3.1 |
| Archivos | Límite de 1 MB, directorio por usuario | Sin validación de tipo/contenido; se sirven desde el mismo host | V12.2.1, V12.4.1 (Fase 7) |
| Logs | Logging de Spring | Trazas completas al cliente | V7.1.1, V7.4.1 |
| Secretos | Propiedades con valores por defecto | Sin gestión de secretos | V6.4.1 (Fase 5), secretos del CI |

## 6. Reglas de tratamiento derivadas

1. **Nunca** usar credenciales reales en el laboratorio; solo cuentas de prueba desechables.
2. La instancia se publica únicamente en `127.0.0.1` (ver [`arquitectura.md`](arquitectura.md) §5.2).
3. Los archivos subidos se consideran **no confiables** y no deben abrirse fuera del contenedor.
4. Los datos del contenedor se destruyen al terminar la práctica (`docker rm -f webgoat`), salvo capturas de evidencia.
5. Cualquier secreto real (token de GitHub, NVD API key) se inyecta por variables de entorno o secretos del CI, nunca en el repositorio.

---

**Trazabilidad:** los requisitos ASVS que protegen cada dato están en [`requisitos-asvs.md`](requisitos-asvs.md); los flujos y límites, en [`dfd.md`](dfd.md).
