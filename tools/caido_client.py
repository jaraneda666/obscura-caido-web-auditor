"""
# Tool: caido_client.py

## Metadata
- Nombre: caido_client.py
- Versión: 1.2
- Lenguaje: Python
- Creada en proyecto: Obscura_Caido_Auditor
- Fecha de creación: 2026-10-30
- Responsable: Security Analyst
- Descripción: Cliente de integración con la API GraphQL de Caido Web Security Proxy con auto-autenticación de invitado (loginAsGuest), auto-creación/selección de proyecto activo, extracción de tráfico interceptado, filtrado por alcance y registro de hallazgos.
- Parámetros: --host, --port, --token, --action (test, list-requests, create-finding, export-traffic), --out, --target-host
- Dependencias: requests
"""

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

try:
    import requests
except ImportError:
    requests = None


class CaidoClient:
    """Cliente para interactuar con la API GraphQL de Caido Proxy."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, token: Optional[str] = None):
        self.host = host
        self.port = int(port)
        self.base_url = f"http://{self.host}:{self.port}"
        self.graphql_url = f"{self.base_url}/graphql"
        self.token = token or os.environ.get("CAIDO_API_TOKEN", "")
        self.session = requests.Session() if requests else None
        if self.session and self.token:
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def _execute_graphql(self, query: str, variables: Optional[Dict] = None, retry_auth: bool = True) -> Dict:
        if not self.session:
            raise RuntimeError("La librería 'requests' no está disponible. Ejecute: pip install requests")
        
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            resp = self.session.post(self.graphql_url, json=payload, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data and data["errors"]:
                err_str = str(data["errors"])
                if "INVALID_TOKEN" in err_str or "AUTHORIZATION" in err_str:
                    if retry_auth and self.authenticate_guest():
                        return self._execute_graphql(query, variables, retry_auth=False)
                return {"success": False, "errors": data["errors"]}
            return {"success": True, "data": data.get("data", {})}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def authenticate_guest(self) -> bool:
        """Autenticación transparente de invitado si el proxy lo permite."""
        mutation = """
        mutation LoginGuest {
            loginAsGuest {
                token {
                    accessToken
                }
                error {
                    __typename
                }
            }
        }
        """
        try:
            resp = self.session.post(self.graphql_url, json={"query": mutation}, timeout=5)
            data = resp.json()
            token = data.get("data", {}).get("loginAsGuest", {}).get("token", {}).get("accessToken")
            if token:
                self.token = token
                self.session.headers.update({"Authorization": f"Bearer {token}"})
                return True
        except Exception:
            pass
        return False

    def ensure_active_project(self, project_name: str = "Audit_Workspace") -> bool:
        """Garantiza que exista un proyecto activo seleccionado en Caido."""
        if not self.token:
            self.authenticate_guest()

        # 1. Comprobar proyectos existentes
        q_proj = "query { projects { id name } }"
        res = self._execute_graphql(q_proj)
        projs = res.get("data", {}).get("projects", [])

        target_id = None
        if projs:
            target_id = projs[0]["id"]
        else:
            # 2. Crear proyecto si no existe
            m_create = f"""
            mutation {{
                createProject(input: {{ name: "{project_name}", temporary: true }}) {{
                    project {{
                        id
                        name
                    }}
                }}
            }}
            """
            res_c = self._execute_graphql(m_create)
            target_id = res_c.get("data", {}).get("createProject", {}).get("project", {}).get("id")

        if target_id:
            m_sel = f"""
            mutation {{
                selectProject(id: "{target_id}") {{
                    currentProject {{
                        project {{
                            id
                        }}
                    }}
                }}
            }}
            """
            res_s = self._execute_graphql(m_sel)
            return res_s.get("success", False)
        return False

    def check_health(self) -> Tuple[bool, str]:
        """Comprueba disponibilidad del proxy Caido y su endpoint GraphQL."""
        if not self.token:
            self.authenticate_guest()

        self.ensure_active_project()

        query = """
        query CheckCaidoHealth {
            runtime {
                version
            }
        }
        """
        res = self._execute_graphql(query)
        if res.get("success"):
            version = res.get("data", {}).get("runtime", {}).get("version", "desconocida")
            return True, f"Caido Proxy online en {self.base_url} (Versión: {version})"
        return False, f"Fallo al conectar con Caido en {self.graphql_url}: {res.get('error') or res.get('errors')}"

    def get_requests(self, limit: int = 100, host_filter: Optional[str] = None) -> List[Dict]:
        """Obtiene las peticiones y respuestas capturadas en Caido."""
        if not self.token:
            self.authenticate_guest()

        self.ensure_active_project()

        query = """
        query GetRequests($first: Int) {
            requests(first: $first) {
                edges {
                    node {
                        id
                        host
                        port
                        path
                        query
                        method
                        raw
                        response {
                            id
                            statusCode
                            roundtripTime
                            raw
                        }
                    }
                }
            }
        }
        """
        res = self._execute_graphql(query, {"first": limit})
        if not res.get("success"):
            return []

        edges = res.get("data", {}).get("requests", {}).get("edges", [])
        items = []
        for edge in edges:
            node = edge.get("node", {})
            req_host = node.get("host", "")
            
            # Normalizar host_filter para comparar 127.0.0.1 y host.docker.internal
            if host_filter:
                hf_low = host_filter.lower()
                req_low = req_host.lower()
                match = (hf_low in req_low)
                if not match and hf_low in ["127.0.0.1", "localhost"] and "host.docker.internal" in req_low:
                    match = True
                if not match:
                    continue

            req_raw = node.get("raw", "")
            res_node = node.get("response") or {}
            res_raw = res_node.get("raw", "")

            items.append({
                "id": node.get("id"),
                "host": req_host,
                "port": node.get("port"),
                "path": node.get("path"),
                "query": node.get("query"),
                "method": node.get("method"),
                "request_raw": req_raw,
                "status_code": res_node.get("statusCode"),
                "roundtrip_ms": res_node.get("roundtripTime"),
                "response_raw": res_raw
            })
        return items

    def create_finding(self, title: str, description: str, request_id: Optional[str] = None, reporter: str = "Obscura_Caido_Auditor") -> Dict:
        """Registra un hallazgo verificado en la interfaz web de Caido."""
        if not self.token:
            self.authenticate_guest()

        mutation = """
        mutation CreateFinding($input: CreateFindingInput!) {
            createFinding(input: $input) {
                finding {
                    id
                    title
                    description
                }
            }
        }
        """
        input_data = {
            "title": title,
            "description": description,
            "reporter": reporter
        }
        if request_id:
            input_data["requestId"] = request_id

        return self._execute_graphql(mutation, {"input": input_data})


def main():
    parser = argparse.ArgumentParser(description="Cliente CLI para Caido Proxy API")
    parser.add_argument("--host", default="127.0.0.1", help="Host de Caido")
    parser.add_argument("--port", type=int, default=8080, help="Puerto de Caido (default: 8080)")
    parser.add_argument("--token", default=None, help="Token API Bearer de Caido")
    parser.add_argument("--action", choices=["test", "list-requests", "export-traffic"], default="test")
    parser.add_argument("--target-host", default=None, help="Filtrar por host objetivo")
    parser.add_argument("--limit", type=int, default=50, help="Límite de requests a extraer")
    parser.add_argument("--out", default=None, help="Archivo JSON de salida")

    args = parser.parse_args()
    client = CaidoClient(host=args.host, port=args.port, token=args.token)

    if args.action == "test":
        ok, msg = client.check_health()
        print(f"[HEALTH] {msg}")
        sys.exit(0 if ok else 1)

    elif args.action in ["list-requests", "export-traffic"]:
        reqs = client.get_requests(limit=args.limit, host_filter=args.target_host)
        print(f"[INFO] Se recuperaron {len(reqs)} peticiones desde Caido Proxy.")
        if args.out:
            out_file = Path(args.out)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(json.dumps(reqs, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[OK] Tráfico exportado a: {out_file}")
        else:
            for r in reqs[:10]:
                print(f"[{r['method']}] http://{r['host']}:{r['port']}{r['path']} -> Status: {r['status_code']}")


if __name__ == "__main__":
    main()
