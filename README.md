# Obscura & Caido Web Security Auditor

Sistema de análisis de seguridad web que combina navegación sin cabeza (headless) de alta fidelidad mediante Obscura con captura e inspección de tráfico HTTP en el proxy Caido.

---

## Arquitectura y Componentes

- **Rastreo web:** Binario Obscura para renderizado completo de JavaScript y extracción de endpoints.
- **Proxy:** Enrutamiento a través de Caido Proxy para interceptar peticiones y respuestas.
- **Análisis:** Scripts en Python para correlacionar cabeceras de seguridad y debilidades OWASP.

---

## Instrucciones de Uso

```bash
# Ejecución de auditoría pasiva sobre URL objetivo
python orquestador_auditoria.py --target https://ejemplo.local --proxy http://localhost:8080
```

---

## Consideraciones de Seguridad

- Este repositorio almacena código fuente, utilitarios de prueba y documentación técnica de ingeniería.
- Todas las credenciales, llaves privadas y variables de entorno deben suministrarse de forma local mediante archivos no versionados.
- Las herramientas de auditoría contenidas deben utilizarse exclusivamente en entornos autorizados y laboratorios de prueba.

---

**Autor:** Security Analyst  
**Licencia:** Uso Privado / Propietario
