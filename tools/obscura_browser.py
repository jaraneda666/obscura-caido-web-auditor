# Tool: obscura_browser.py

## Metadata
# - Nombre: obscura_browser.py
# - Versión: 1.0
# - Lenguaje: Python
# - Creada en proyecto: Global Workspace
# - Fecha de creación: 2026-10-27
# - Descripción: Wrapper de automatización y control programático para Obscura Headless Browser (V8, CDP, Stealth, Render, MCP).
# - Parámetros: url, --eval, --dump, --screenshot, --stealth, --timeout, --proxy, --allow-private-network
# - Dependencias: subprocess, json, shutil, pathlib, sys, argparse

## Código
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

class ObscuraBrowser:
    """
    Controlador y cliente programático para Obscura Headless Browser.
    Permite realizar scraping ligero, evaluaciones JavaScript con V8 nativo,
    capturas de pantalla PNG, volcados de DOM/texto y bypass anti-bot vía Stealth.
    """

    def __init__(self, binary_path: Optional[str] = None):
        """
        Inicializa la instancia resolviendo la ubicación del binario de Obscura.
        """
        if binary_path and Path(binary_path).exists():
            self.binary_path = str(Path(binary_path).resolve())
        else:
            resolved = shutil.which("obscura") or shutil.which("obscura.exe")
            if resolved:
                self.binary_path = resolved
            else:
                # Búsqueda en rutas canónicas del workspace y usuario
                candidates = [
                    Path(r"C:\Users\Developer\bin\obscura.exe"),
                    Path(r"C:\Users\Developer\Documents\Antigravity projects\tools\global\obscura.exe"),
                    Path(__file__).parent / "obscura.exe",
                    Path(__file__).parent / "global" / "obscura.exe"
                ]
                found = next((str(p) for p in candidates if p.exists()), None)
                if not found:
                    raise FileNotFoundError(
                        "No se encontró el binario 'obscura.exe'. Verifique que esté en PATH o en tools/global/."
                    )
                self.binary_path = found

    def get_version(self) -> str:
        """Obtiene la versión instalada de Obscura."""
        result = subprocess.run(
            [self.binary_path, "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()

    def fetch(
        self,
        url: str,
        eval_expr: Optional[str] = None,
        dump: Optional[str] = "text",
        screenshot_path: Optional[Union[str, Path]] = None,
        stealth: bool = True,
        timeout: int = 30,
        wait_seconds: Optional[int] = None,
        wait_until: str = "load",
        allow_private_network: bool = False,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        output_file: Optional[Union[str, Path]] = None
    ) -> Dict[str, Union[str, int, bool]]:
        """
        Navega a una URL y extrae contenido, ejecuta JS o genera capturas.

        :param url: URL de destino.
        :param eval_expr: Expresión JavaScript a evaluar tras la carga.
        :param dump: Tipo de volcado ('text', 'html', 'links', 'markdown', 'original', 'assets', 'cookies').
        :param screenshot_path: Ruta del archivo PNG donde guardar captura de pantalla.
        :param stealth: Activa emulación de huella humana y bypass anti-detección.
        :param timeout: Tiempo máximo en segundos para la navegación.
        :param wait_seconds: Espera fija en segundos tras la carga.
        :param wait_until: Condición de espera ('load', 'networkidle0', etc.).
        :param allow_private_network: Permite peticiones a localhost o redes privadas RFC1918.
        :param proxy: Servidor proxy (HTTP o SOCKS5).
        :param user_agent: User-Agent personalizado.
        :param output_file: Ruta donde escribir la salida directamente.
        :return: Diccionario con status, stdout, stderr y metadatos.
        """
        cmd = [self.binary_path]

        if stealth:
            cmd.append("--stealth")
        if allow_private_network:
            cmd.append("--allow-private-network")
        if proxy:
            cmd.extend(["--proxy", proxy])
        if user_agent:
            cmd.extend(["--user-agent", user_agent])

        cmd.append("fetch")

        if dump:
            cmd.extend(["--dump", dump])
        if eval_expr:
            cmd.extend(["--eval", eval_expr])
        if screenshot_path:
            cmd.extend(["--screenshot", str(Path(screenshot_path).resolve())])
        if timeout:
            cmd.extend(["--timeout", str(timeout)])
        if wait_seconds is not None:
            cmd.extend(["--wait", str(wait_seconds)])
        if wait_until:
            cmd.extend(["--wait-until", wait_until])
        if output_file:
            cmd.extend(["--output", str(Path(output_file).resolve())])

        cmd.append(url)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 15,
                encoding="utf-8",
                errors="replace"
            )
            return {
                "success": proc.returncode == 0,
                "exit_code": proc.returncode,
                "url": url,
                "output": proc.stdout,
                "error": proc.stderr,
                "command": " ".join(cmd)
            }
        except subprocess.TimeoutExpired as e:
            return {
                "success": False,
                "exit_code": -1,
                "url": url,
                "output": "",
                "error": f"Timeout expirado ({timeout}s): {str(e)}",
                "command": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -2,
                "url": url,
                "output": "",
                "error": str(e),
                "command": " ".join(cmd)
            }

    def evaluate(self, url: str, js_code: str, stealth: bool = True, timeout: int = 30) -> str:
        """Evalúa un script JavaScript en el contexto de la página y retorna el resultado."""
        res = self.fetch(url, eval_expr=js_code, dump=None, stealth=stealth, timeout=timeout)
        if not res["success"]:
            raise RuntimeError(f"Error evaluando JS en {url}: {res['error']}")
        return res["output"].strip()

    def screenshot(self, url: str, output_path: Union[str, Path], stealth: bool = True, timeout: int = 30) -> bool:
        """Captura un pantallazo en formato PNG del sitio renderizado."""
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        res = self.fetch(url, dump=None, screenshot_path=dest, stealth=stealth, timeout=timeout)
        return res["success"] and dest.exists()


def main():
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Obscura Headless Browser CLI Wrapper")
    parser.add_argument("url", nargs="?", help="URL a navegar")
    parser.add_argument("--eval", dest="eval_expr", help="Expresión JavaScript a evaluar")
    parser.add_argument("--dump", default="text", choices=["text", "html", "links", "markdown", "original", "assets", "cookies"], help="Tipo de volcado")
    parser.add_argument("-s", "--screenshot", help="Ruta para captura de pantalla PNG")
    parser.add_argument("--no-stealth", action="store_true", help="Desactivar modo stealth")
    parser.add_argument("--allow-private", action="store_true", help="Permitir acceso a localhost y redes privadas")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en segundos")
    parser.add_argument("-v", "--version", action="store_true", help="Mostrar versión de Obscura")

    args = parser.parse_args()
    browser = ObscuraBrowser()

    if args.version:
        print(f"Obscura Wrapper v1.0 | Engine: {browser.get_version()}")
        sys.exit(0)

    if not args.url:
        parser.print_help()
        sys.exit(1)

    result = browser.fetch(
        url=args.url,
        eval_expr=args.eval_expr,
        dump=args.dump,
        screenshot_path=args.screenshot,
        stealth=not args.no_stealth,
        allow_private_network=args.allow_private,
        timeout=args.timeout
    )

    if result["success"]:
        if result["output"]:
            print(result["output"])
        if args.screenshot:
            print(f"[+] Screenshot guardado en: {args.screenshot}")
        sys.exit(0)
    else:
        print(f"[-] Error: {result['error']}", file=sys.stderr)
        sys.exit(result["exit_code"] if result["exit_code"] > 0 else 1)

if __name__ == "__main__":
    main()
