"""
# Tool: analizador_vulnerabilidades_llm.py

## Metadata
- Nombre: analizador_vulnerabilidades_llm.py
- Versión: 1.1
- Lenguaje: Python
- Creada en proyecto: Obscura_Caido_Auditor
- Fecha de creación: 2026-10-30
- Responsable: Security Analyst
- Descripción: Analizador heurístico de tráfico HTTP/HTTPS capturado por Caido. Realiza inferencia pasiva mediante LLMs locales (Ollama / LM Studio) o motor de reglas WSTG, agrupa hallazgos consolidados evitando redundancia por assets estáticos, correlaciona con OWASP, MITRE CWE, calcula métricas CVSS v4/v3 y genera comandos PoC no destructivos.
- Parámetros: --input-traffic, --llm-provider (ollama, lmstudio, local-rules), --model, --out-findings
- Dependencias: requests
"""

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    import requests
except ImportError:
    requests = None


SYSTEM_PROMPT_AUDITOR = """Eres un Auditor de Seguridad Web y Arquitecto Senior de Pentesting.
Tu misión es analizar transacciones HTTP/S capturadas por un proxy interceptor para identificar vulnerabilidades y malas configuraciones de seguridad según el estándar OWASP WSTG v4.2.

REGLAS ESTRICTAS:
1. Nunca inventes vulnerabilidades. Si no hay evidencia fehaciente en las cabeceras o cuerpo, no reportes nada.
2. Agrupa los endpoints afectados en un único hallazgo consolidado por tipo de vulnerabilidad.
3. Cada hallazgo debe incluir:
   - title: Título conciso del hallazgo.
   - owasp_category: Categoría OWASP WSTG (ej. WSTG-CONF-07).
   - cwe_id: Identificador MITRE CWE (ej. CWE-693).
   - severity: Informational | Low | Medium | High | Critical.
   - cvss_v31: Vector CVSS v3.1 y puntuación base estimada.
   - description: Mecánica técnica del fallo observado.
   - evidence: Cabecera, valor o fragmento exacto que demuestra el problema.
   - poc_command: Comando curl no destructivo para verificar la vulnerabilidad.
   - remediation: Solución técnica precisa para mitigar la falla.
4. Responde ÚNICAMENTE en formato JSON válido con la clave raíz "findings": [...]
"""


class VulnerabilityAnalyzer:
    """Motor de análisis de vulnerabilidades sobre tráfico web pasivo."""

    def __init__(self, provider: str = "ollama", model: str = "llama3.1:8b-instruct", endpoint: Optional[str] = None):
        self.provider = provider.lower()
        self.model = model
        if endpoint:
            self.endpoint = endpoint
        elif self.provider == "ollama":
            self.endpoint = "http://localhost:11434/api/generate"
        elif self.provider == "lmstudio":
            self.endpoint = "http://localhost:1234/v1/chat/completions"
        else:
            self.endpoint = None

    def _decode_raw(self, raw_str: str) -> str:
        if not raw_str:
            return ""
        try:
            decoded = base64.b64decode(raw_str).decode('utf-8', errors='replace')
            return decoded
        except Exception:
            return raw_str

    def analyze_heuristics(self, traffic_item: Dict) -> List[Dict]:
        """Análisis estático determinista según OWASP WSTG v4.2 sin alucinaciones."""
        findings = []
        host = traffic_item.get("host", "")
        port = traffic_item.get("port", 80)
        path = traffic_item.get("path", "/")
        status = traffic_item.get("status_code", 0)

        # Omitir assets estáticos repetitivos en el análisis individual (agrupar en raíz)
        is_static_asset = any(path.lower().endswith(ext) for ext in [".svg", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".ttf"])
        
        raw_res = self._decode_raw(traffic_item.get("response_raw", ""))
        target_url = f"http://{host}:{port}{path}" if port != 443 else f"https://{host}{path}"

        headers_res = {}
        for line in raw_res.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers_res[k.strip().lower()] = v.strip()

        # 1. Ausencia de HSTS en conexiones HTTPS
        if port == 443 and "strict-transport-security" not in headers_res and not is_static_asset:
            findings.append({
                "title": "Ausencia de Cabecera HTTP Strict Transport Security (HSTS)",
                "owasp_category": "WSTG-CONF-07",
                "cwe_id": "CWE-523",
                "severity": "Low",
                "cvss_v31": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N (3.1)",
                "description": "El servidor no instruye a los navegadores a forzar conexiones HTTPS mediante HSTS, exponiendo al usuario a ataques de degradación TLS y SSL Stripping.",
                "evidence": "Falta cabecera 'Strict-Transport-Security'",
                "poc_command": f"curl.exe -I -s {target_url}",
                "remediation": "Configurar la cabecera 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' en el servidor web.",
                "url": target_url,
                "check_header": "strict-transport-security",
                "expect_missing": True
            })

        # 2. Ausencia de Content-Security-Policy (CSP)
        if status in [200, 301, 302] and "content-security-policy" not in headers_res and not is_static_asset:
            findings.append({
                "title": "Falta de Política de Seguridad de Contenido (Content Security Policy)",
                "owasp_category": "WSTG-CONF-07",
                "cwe_id": "CWE-693",
                "severity": "Low",
                "cvss_v31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)",
                "description": "La aplicación no implementa una cabecera CSP restrictiva, aumentando la superficie de exposición ante ataques de Cross-Site Scripting (XSS) e inyección de datos.",
                "evidence": "Falta cabecera 'Content-Security-Policy'",
                "poc_command": f"curl.exe -I -s {target_url}",
                "remediation": "Definir directivas estrictas de orígenes permitidos en la cabecera 'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\''.",
                "url": target_url,
                "check_header": "content-security-policy",
                "expect_missing": True
            })

        # 3. Protección contra Clickjacking (X-Frame-Options)
        if "x-frame-options" not in headers_res and "content-security-policy" not in headers_res and not is_static_asset:
            findings.append({
                "title": "Ausencia de Protección contra Clickjacking (X-Frame-Options)",
                "owasp_category": "WSTG-CONF-07",
                "cwe_id": "CWE-1021",
                "severity": "Low",
                "cvss_v31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N (4.3)",
                "description": "La respuesta no restringe la incrustación del sitio dentro de elementos iframe o frame en dominios de terceros.",
                "evidence": "Falta cabecera 'X-Frame-Options'",
                "poc_command": f"curl.exe -I -s {target_url}",
                "remediation": "Añadir la cabecera 'X-Frame-Options: SAMEORIGIN' o la directiva CSP 'frame-ancestors \\'self\\''.",
                "url": target_url,
                "check_header": "x-frame-options",
                "expect_missing": True
            })

        # 4. Fuga de versión de servidor (Information Disclosure)
        server_header = headers_res.get("server") or headers_res.get("x-powered-by")
        if server_header and re.search(r'\d+\.\d+', server_header) and not is_static_asset:
            findings.append({
                "title": "Divulgación de Versión del Servidor Web (Information Disclosure)",
                "owasp_category": "WSTG-INFO-02",
                "cwe_id": "CWE-200",
                "severity": "Informational",
                "cvss_v31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)",
                "description": "El servidor web expone su versión exacta en las cabeceras HTTP, facilitando el reconocimiento a potenciales atacantes.",
                "evidence": f"Cabecera Server/X-Powered-By: {server_header}",
                "poc_command": f"curl.exe -I -s {target_url}",
                "remediation": "Ocultar la versión del banner en la configuración del servidor web (ej. 'server_tokens off;' en Nginx o 'ServerTokens Prod' en Apache).",
                "url": target_url,
                "check_header": "server",
                "expect_missing": False
            })

        # 5. Mala configuración CORS (Access-Control-Allow-Origin: *)
        cors_origin = headers_res.get("access-control-allow-origin")
        if cors_origin == "*" and not is_static_asset:
            findings.append({
                "title": "Política CORS Excesivamente Permisiva (Wildcard Origin)",
                "owasp_category": "WSTG-CONF-05",
                "cwe_id": "CWE-942",
                "severity": "Low",
                "cvss_v31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N (4.3)",
                "description": "La aplicación define 'Access-Control-Allow-Origin: *', permitiendo que cualquier origen externo realice consultas asíncronas y lea datos si no requiere credenciales.",
                "evidence": f"Access-Control-Allow-Origin: {cors_origin}",
                "poc_command": f"curl.exe -H \"Origin: https://evil.com\" -I -s {target_url}",
                "remediation": "Restringir el origen permitido a dominios de confianza explícitos en lugar del comodín '*'.",
                "url": target_url,
                "check_header": "access-control-allow-origin",
                "expect_missing": False
            })

        return findings

    def query_local_llm(self, traffic_item: Dict) -> List[Dict]:
        """Consulta el modelo local (Ollama o LM Studio) para análisis profundo si está disponible."""
        if not requests or not self.endpoint:
            return []

        raw_req = self._decode_raw(traffic_item.get("request_raw", ""))
        raw_res = self._decode_raw(traffic_item.get("response_raw", ""))

        prompt_user = f"""Analiza la siguiente transacción HTTP y extrae hallazgos según OWASP WSTG v4.2:
URL: http://{traffic_item.get('host')}:{traffic_item.get('port')}{traffic_item.get('path')}
Método: {traffic_item.get('method')}
Código HTTP: {traffic_item.get('status_code')}

PETICIÓN:
{raw_req[:1500]}

RESPUESTA:
{raw_res[:2000]}
"""

        try:
            if self.provider == "ollama":
                payload = {
                    "model": self.model,
                    "prompt": f"{SYSTEM_PROMPT_AUDITOR}\n\n{prompt_user}",
                    "stream": False,
                    "format": "json"
                }
                resp = requests.post(self.endpoint, json=payload, timeout=45)
                if resp.status_code == 200:
                    text_out = resp.json().get("response", "{}")
                    parsed = json.loads(text_out)
                    return parsed.get("findings", [])

            elif self.provider == "lmstudio":
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT_AUDITOR},
                        {"role": "user", "content": prompt_user}
                    ],
                    "temperature": 0.1
                }
                resp = requests.post(self.endpoint, json=payload, timeout=45)
                if resp.status_code == 200:
                    text_out = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "{}")
                    parsed = json.loads(text_out)
                    return parsed.get("findings", [])

        except Exception:
            pass

        return []

    def analyze_traffic(self, traffic_list: List[Dict]) -> List[Dict]:
        """Procesa una lista consolidada de transacciones y unifica hallazgos agrupados por tipo."""
        consolidated = {}

        for item in traffic_list:
            static_findings = self.analyze_heuristics(item)
            for f in static_findings:
                title = f["title"]
                if title not in consolidated:
                    consolidated[title] = {
                        **f,
                        "affected_endpoints": [f["url"]]
                    }
                else:
                    if f["url"] not in consolidated[title]["affected_endpoints"]:
                        consolidated[title]["affected_endpoints"].append(f["url"])

            if self.provider in ["ollama", "lmstudio"]:
                llm_findings = self.query_local_llm(item)
                for f in llm_findings:
                    title = f.get("title", "")
                    if title and title not in consolidated:
                        consolidated[title] = {
                            **f,
                            "affected_endpoints": [f.get("url", item.get("path", ""))]
                        }

        return list(consolidated.values())


def main():
    parser = argparse.ArgumentParser(description="Analizador de Vulnerabilidades Web con LLM y Reglas OWASP")
    parser.add_argument("--input-traffic", required=True, help="Archivo JSON con peticiones de Caido")
    parser.add_argument("--llm-provider", choices=["ollama", "lmstudio", "local-rules"], default="local-rules")
    parser.add_argument("--model", default="llama3.1:8b-instruct", help="Nombre del modelo LLM")
    parser.add_argument("--out-findings", required=True, help="Archivo JSON de salida con hallazgos")

    args = parser.parse_args()

    in_file = Path(args.input_traffic)
    if not in_file.exists():
        print(f"[ERROR] Archivo de entrada no encontrado: {in_file}", file=sys.stderr)
        sys.exit(1)

    traffic_data = json.loads(in_file.read_text(encoding="utf-8"))
    analyzer = VulnerabilityAnalyzer(provider=args.llm_provider, model=args.model)
    findings = analyzer.analyze_traffic(traffic_data)

    out_file = Path(args.out_findings)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps({"findings": findings}, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[OK] Análisis completado. Se consolidaron {len(findings)} hallazgos. Guardado en: {out_file}")


if __name__ == "__main__":
    main()
