# Guía de Arquitectura y Operación — Obscura Caido Auditor

**Responsable Técnico:** Security Analyst  
**Proyecto:** `Obscura_Caido_Auditor`  
**Fecha:** 30-10-2026  

---

## 1. Alcance y Filosofía de Diseño

El sistema fue diseñado para auditar aplicaciones web autorizadas sin degradar la disponibilidad ni generar ataques de denegación de servicio (DoS).

### Principios Fundamentales:
1. **Scope Enforcement:** Todo objetivo debe pertenecer a la lista de hosts/dominios explícitamente permitidos antes de enviar cualquier paquete.
2. **Cero Alucinaciones:** Las vulnerabilidades identificadas deben estar respaldadas por evidencias fehacientes en cabeceras o cuerpo de respuesta HTTP/S.
3. **Agrupación Inteligente:** Múltiples peticiones a rutas o recursos estáticos que compartan la misma debilidad estructural se consolidan en un único hallazgo.
4. **PoC Segura:** Las verificaciones se limitan a comprobaciones de solo lectura (`curl -I` o consultas específicas de cabecera).
5. **Compuerta HITL:** Capacidad de detener la ejecución y solicitar confirmación humana previa a cualquier interacción activa.

