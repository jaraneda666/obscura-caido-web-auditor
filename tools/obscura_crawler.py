"""
# Tool: obscura_crawler.py

## Metadata
- Nombre: obscura_crawler.py
- Versión: 1.0
- Lenguaje: Python
- Creada en proyecto: Obscura_Caido_Auditor
- Fecha de creación: 2026-10-30
- Responsable: Security Analyst
- Descripción: Rastreador y navegador web headless automatizado basado en el binario nativo Obscura en Rust, enrutando todo el tráfico HTTP/HTTPS a través de Caido Proxy para su intercepción y análisis forense.
- Parámetros: --url, --proxy, --depth, --max-pages, --obscura-bin, --allow-private, --screenshot-dir
- Dependencias: requests, beautifulsoup4 (opcional)
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def is_private_target(url: str) -> bool:
    """Detecta si la URL apunta a una dirección IP privada o localhost."""
    try:
        hostname = urlparse(url).hostname or ""
        if hostname in ["localhost", "127.0.0.1", "::1"]:
            return True
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


class ObscuraCrawler:
    """Controlador para rastreo de aplicaciones web mediante Obscura vía Caido Proxy."""

    def __init__(
        self,
        obscura_bin: Optional[str] = None,
        proxy_url: str = "http://127.0.0.1:8080",
        allow_private: bool = True,
        delay_sec: float = 1.0
    ):
        base_dir = Path(__file__).resolve().parent
        if obscura_bin:
            self.bin_path = Path(obscura_bin)
        else:
            local_bin = base_dir / "obscura.exe"
            self.bin_path = local_bin if local_bin.exists() else Path("obscura.exe")

        self.proxy_url = proxy_url
        self.allow_private = allow_private
        self.delay_sec = delay_sec
        self.visited_urls = set()

    def check_binary(self) -> bool:
        """Verifica la existencia y ejecutabilidad de obscura.exe."""
        if not self.bin_path.exists():
            print(f"[ERROR] No se encontró el binario de Obscura en: {self.bin_path}", file=sys.stderr)
            return False
        return True

    def fetch_page(self, url: str, screenshot_path: Optional[str] = None) -> Dict:
        """Navega una URL con Obscura enrutado por Caido y recupera su DOM renderizado."""
        cmd = [str(self.bin_path), "fetch", url]

        # Inyectar proxy hacia Caido
        if self.proxy_url:
            cmd.extend(["--proxy", self.proxy_url])

        # Habilitar red privada si aplica
        if self.allow_private or is_private_target(url):
            cmd.append("--allow-private-network")

        if screenshot_path:
            cmd.extend(["--screenshot", str(screenshot_path)])

        cmd.extend(["--dump", "links"])

        try:
            start_time = time.time()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30
            )
            elapsed = time.time() - start_time

            html_output = proc.stdout
            err_output = proc.stderr

            # Extraer enlaces internos para navegación profunda
            links = []
            if html_output:
                found_hrefs = re.findall(r'href=[\'"]?([^\'" >]+)', html_output, re.IGNORECASE)
                parsed_root = urlparse(url)
                for h in found_hrefs:
                    if h.startswith("javascript:") or h.startswith("mailto:") or h.startswith("#"):
                        continue
                    full_link = urljoin(url, h)
                    parsed_link = urlparse(full_link)
                    # Confinar al mismo dominio (Scope Enforcement)
                    if parsed_link.netloc == parsed_root.netloc:
                        links.append(full_link)

            return {
                "url": url,
                "success": proc.returncode == 0,
                "status_code": 200 if proc.returncode == 0 else 500,
                "elapsed_sec": round(elapsed, 2),
                "html_length": len(html_output),
                "discovered_links": list(set(links)),
                "error": err_output.strip() if proc.returncode != 0 else ""
            }

        except subprocess.TimeoutExpired:
            return {"url": url, "success": False, "error": "Timeout navegando con Obscura (>30s)"}
        except Exception as e:
            return {"url": url, "success": False, "error": str(e)}

    def crawl_target(self, start_url: str, max_pages: int = 20, screenshot_dir: Optional[str] = None) -> List[Dict]:
        """Ejecuta un rastreo recursivo contenido respetando el alcance."""
        if not self.check_binary():
            return []

        queue = [start_url]
        results = []
        parsed_target = urlparse(start_url)
        target_domain = parsed_target.netloc

        print(f"[INFO] Iniciando rastreo con Obscura sobre: {start_url}")
        print(f"[INFO] Tráfico enrutado por Caido Proxy: {self.proxy_url}")
        print(f"[SCOPE] Confinado estrictamente a dominio: {target_domain}")

        ss_dir = Path(screenshot_dir) if screenshot_dir else None
        if ss_dir:
            ss_dir.mkdir(parents=True, exist_ok=True)

        while queue and len(self.visited_urls) < max_pages:
            current_url = queue.pop(0)
            if current_url in self.visited_urls:
                continue

            self.visited_urls.add(current_url)
            print(f" -> [{len(self.visited_urls)}/{max_pages}] Navegando: {current_url}")

            ss_file = None
            if ss_dir:
                safe_name = re.sub(r'[^a-zA-Z0-9]', '_', current_url)[:60]
                ss_file = str(ss_dir / f"poc_{safe_name}.png")

            res = self.fetch_page(current_url, screenshot_path=ss_file)
            results.append(res)

            # Encolar nuevos enlaces descubiertos dentro de alcance
            for link in res.get("discovered_links", []):
                if link not in self.visited_urls and link not in queue:
                    queue.append(link)

            time.sleep(self.delay_sec)

        print(f"[OK] Rastreo finalizado. Páginas visitadas: {len(results)}. Tráfico capturado en Caido.")
        return results


def main():
    parser = argparse.ArgumentParser(description="Navegador Headless Obscura acoplado a Caido Proxy")
    parser.add_argument("--url", required=True, help="URL de inicio para la auditoría")
    parser.add_argument("--proxy", default="http://127.0.0.1:8080", help="URL del Proxy Caido")
    parser.add_argument("--max-pages", type=int, default=15, help="Máximo de páginas a recorrer")
    parser.add_argument("--delay", type=float, default=1.0, help="Espera entre peticiones en segundos")
    parser.add_argument("--screenshot-dir", default=None, help="Carpeta para almacenar capturas PoC")
    parser.add_argument("--out", default=None, help="Archivo JSON de salida con telemetría de rastreo")

    args = parser.parse_args()

    crawler = ObscuraCrawler(proxy_url=args.proxy, delay_sec=args.delay)
    data = crawler.crawl_target(args.url, max_pages=args.max_pages, screenshot_dir=args.screenshot_dir)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] Telemetría de rastreo guardada en: {out_path}")


if __name__ == "__main__":
    main()

