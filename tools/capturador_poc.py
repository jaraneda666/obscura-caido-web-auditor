#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# Tool: capturador_poc.py

## Metadata
- Nombre: capturador_poc.py
- Versión: 1.2
- Lenguaje: Python
- Creada en proyecto: AI_RedTeam_LLM_Pentest
- Fecha de creación: 2026-10-27 (Actualizada: 2026-10-28)
- Descripción: Capturador pericial de evidencias y pruebas de concepto (PoC) para pentesting. Aplica modo estricto de nomenclatura y trazabilidad incluyendo Scope/Target, Fecha (YYYYMMDD) y Hora (HHMMSS) en títulos y nombres de archivo para prevenir sobreescritura histórica.
- Parámetros: --url, --consola, --archivo, --cmd, --poc-hallazgo, --titulo, --owasp, --severidad, --target/--scope, --payload, --respuesta, --output, --width, --height, --fecha, --hora
- Dependencias: subprocess, os, sys, json, pathlib, argparse, html, shutil, tempfile, re, datetime

## Uso
python capturador_poc.py --poc-hallazgo --titulo "Context Spoofing" --scope "TalitaKum_AI_Engine" --payload "..." --respuesta "..."
"""

import os
import sys
import re
import json
import shutil
import tempfile
import argparse
import subprocess
from pathlib import Path
from html import escape
from datetime import datetime

def normalizar_slug(texto: str) -> str:
    """Normaliza un texto para utilizarlo de forma segura en nombres de archivo."""
    texto = re.sub(r'https?://', '', texto)
    texto = re.sub(r'[^a-zA-Z0-9_\.]+', '_', texto)
    texto = re.sub(r'_+', '_', texto)
    return texto.strip('_').lower()

class CapturadorPoC:
    def __init__(self, browser_engine="auto"):
        self.browser_engine = browser_engine
        self.obscura_path = self._buscar_obscura()
        self.chrome_path = self._buscar_chrome()
        self.edge_path = self._buscar_edge()

    def _buscar_obscura(self):
        candidatos = [
            shutil.which("obscura"),
            shutil.which("obscura.exe"),
            r"C:\Users\Developer\Documents\Antigravity projects\tools\global\obscura.exe",
            r"C:\Users\Developer\bin\obscura.exe",
            str(Path(__file__).parent / "obscura.exe"),
            str(Path(__file__).parent / "global" / "obscura.exe")
        ]
        for c in candidatos:
            if c and os.path.exists(c):
                return str(Path(c).resolve())
        return None

    def _buscar_chrome(self):
        candidatos = [
            shutil.which("chrome"),
            shutil.which("google-chrome"),
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        ]
        for c in candidatos:
            if c and os.path.exists(c):
                return str(Path(c).resolve())
        return None

    def _buscar_edge(self):
        candidatos = [
            shutil.which("msedge"),
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        ]
        for c in candidatos:
            if c and os.path.exists(c):
                return str(Path(c).resolve())
        return None

    def capturar_url(self, url, output_png, width=1280, height=800, wait_seconds=2):
        """Captura una URL web remota o local utilizando el motor headless disponible."""
        output_png = Path(output_png).resolve()
        output_png.parent.mkdir(parents=True, exist_ok=True)

        # 1. Intentar con Obscura
        if self.obscura_path and os.path.exists(self.obscura_path):
            try:
                cmd = [
                    self.obscura_path,
                    "--allow-private-network",
                    "fetch",
                    "--screenshot", str(output_png),
                    "--wait", str(wait_seconds),
                    url
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
                if output_png.exists() and output_png.stat().st_size > 500:
                    return {"exito": True, "motor": "obscura", "ruta": str(output_png)}
            except Exception as e:
                print(f"[!] Aviso: Obscura falló ({e}), intentando fallback con Chrome/Edge...")

        # 2. Intentar con Chrome / Edge Headless
        browser_bin = self.chrome_path or self.edge_path
        if browser_bin and os.path.exists(browser_bin):
            try:
                cmd = [
                    browser_bin,
                    "--headless=new",
                    "--disable-gpu",
                    "--hide-scrollbars",
                    "--allow-file-access-from-files",
                    "--enable-local-file-accesses",
                    f"--window-size={width},{height}",
                    f"--screenshot={str(output_png)}",
                    url
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if output_png.exists() and output_png.stat().st_size > 500:
                    motor = "chrome" if browser_bin == self.chrome_path else "edge"
                    return {"exito": True, "motor": motor, "ruta": str(output_png)}
            except Exception as e:
                print(f"[!] Fallback de navegador falló: {e}")

        # 3. Intentar con Playwright si está instalado
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, executable_path=browser_bin)
                page = browser.new_page(viewport={"width": width, "height": height})
                page.goto(url, wait_until="networkidle", timeout=30000)
                page.screenshot(path=str(output_png), full_page=False)
                browser.close()
                if output_png.exists():
                    return {"exito": True, "motor": "playwright", "ruta": str(output_png)}
        except Exception:
            pass

        return {"exito": False, "error": "No fue posible capturar la URL con ningún motor headless disponible."}

    def generar_html_terminal(self, contenido, titulo="Terminal PoC", prompt="root@redteam:~#", comando=None, metadatos=None, timestamp_str=None):
        """Genera una plantilla HTML de terminal forense con Scope, Fecha y Hora obligatorios."""
        meta_html = ""
        if metadatos and isinstance(metadatos, dict):
            badges = []
            for k, v in metadatos.items():
                badges.append(f'<span class="badge"><span class="badge-k">{escape(str(k))}:</span> {escape(str(v))}</span>')
            meta_html = f'<div class="meta-bar">{" ".join(badges)}</div>'

        cmd_html = ""
        if comando:
            cmd_html = f'<div class="line-cmd"><span class="prompt">{escape(prompt)}</span> <span class="cmd">{escape(comando)}</span></div>'

        lineas_formateadas = []
        for linea in contenido.splitlines():
            linea_esc = escape(linea)
            if any(err in linea.lower() for err in ["error", "500 internal", "failed", "vulnerable", "exception"]):
                linea_esc = f'<span class="hl-red">{linea_esc}</span>'
            elif any(succ in linea.lower() for succ in ["200 ok", "success", "bypassed", "jailbreak"]):
                linea_esc = f'<span class="hl-green">{linea_esc}</span>'
            elif any(sql in linea.upper() for sql in ["SELECT ", "FROM ", "WHERE ", "INSERT ", "DROP "]):
                linea_esc = f'<span class="hl-cyan">{linea_esc}</span>'
            lineas_formateadas.append(linea_esc)

        salida_html = "\n".join(lineas_formateadas)
        ts_display = timestamp_str or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_template = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        background: #0b0d13;
        padding: 30px;
        display: flex;
        justify-content: center;
        align-items: center;
        font-family: 'Consolas', 'DejaVu Sans Mono', 'Courier New', monospace;
    }}
    .window {{
        width: 100%;
        max-width: 1150px;
        background: #141721;
        border-radius: 10px;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.08);
        overflow: hidden;
    }}
    .title-bar {{
        background: #1e2230;
        padding: 12px 18px;
        display: flex;
        align-items: center;
        border-bottom: 1px solid #272c3d;
    }}
    .buttons {{
        display: flex;
        gap: 8px;
        margin-right: 18px;
    }}
    .btn {{
        width: 13px;
        height: 13px;
        border-radius: 50%;
        display: inline-block;
    }}
    .btn-close {{ background: #ff5f56; }}
    .btn-min {{ background: #ffbd2e; }}
    .btn-max {{ background: #27c93f; }}
    .title {{
        color: #9ba3b8;
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.5px;
        flex-grow: 1;
        text-align: center;
    }}
    .meta-bar {{
        background: #181c28;
        padding: 9px 18px;
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        border-bottom: 1px solid #232839;
    }}
    .badge {{
        background: #222738;
        color: #d1d7e5;
        font-size: 11px;
        padding: 3px 8px;
        border-radius: 4px;
        border: 1px solid #31374d;
    }}
    .badge-k {{
        color: #57c7ff;
        font-weight: 700;
    }}
    .term-body {{
        padding: 22px;
        color: #e6edf3;
        font-size: 14px;
        line-height: 1.55;
        white-space: pre-wrap;
        word-break: break-word;
    }}
    .line-cmd {{
        margin-bottom: 14px;
        padding-bottom: 10px;
        border-bottom: 1px dashed #2b3145;
    }}
    .prompt {{
        color: #5af78e;
        font-weight: 700;
    }}
    .cmd {{
        color: #ffffff;
        font-weight: 600;
    }}
    .hl-red {{ color: #ff6e6e; font-weight: bold; }}
    .hl-green {{ color: #5af78e; font-weight: bold; }}
    .hl-cyan {{ color: #57c7ff; font-weight: bold; }}
    .watermark {{
        padding: 8px 18px;
        background: #11141c;
        border-top: 1px solid #1c212e;
        color: #5c637a;
        font-size: 11px;
        display: flex;
        justify-content: space-between;
    }}
</style>
</head>
<body>
<div class="window">
    <div class="title-bar">
        <div class="buttons">
            <span class="btn btn-close"></span>
            <span class="btn btn-min"></span>
            <span class="btn btn-max"></span>
        </div>
        <div class="title">{escape(titulo)}</div>
    </div>
    {meta_html}
    <div class="term-body">
{cmd_html}
<div class="output">{salida_html}</div>
    </div>
    <div class="watermark">
        <span>Prueba de Concepto Pericial Inmutable</span>
        <span>{ts_display}</span>
    </div>
</div>
</body>
</html>"""
        return html_template

    def capturar_consola(self, contenido, output_png, titulo="Terminal PoC", prompt="root@redteam:~#", comando=None, metadatos=None, width=1180, timestamp_str=None):
        """Renderiza una salida de consola en imagen PNG mediante navegador headless."""
        output_png = Path(output_png).resolve()
        output_png.parent.mkdir(parents=True, exist_ok=True)

        html_content = self.generar_html_terminal(
            contenido=contenido,
            titulo=titulo,
            prompt=prompt,
            comando=comando,
            metadatos=metadatos,
            timestamp_str=timestamp_str
        )

        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
            f.write(html_content)
            temp_html_path = Path(f.name).resolve()

        try:
            file_url = f"file:///{temp_html_path.as_posix()}"
            res = self.capturar_url(file_url, output_png, width=width, height=750, wait_seconds=1)
            if res.get("exito"):
                return res
            return self._fallback_render_pillow(contenido, output_png, titulo, comando, metadatos)
        finally:
            if temp_html_path.exists():
                try:
                    temp_html_path.unlink()
                except Exception:
                    pass

    def capturar_poc_hallazgo(self, titulo, owasp, severidad, payload, respuesta, target, output_png=None, fecha=None, hora=None):
        """Genera una captura estructurada de PoC forense con Scope, Fecha y Hora obligatorios."""
        now = datetime.now()
        fecha_str = fecha or now.strftime("%Y-%m-%d")
        hora_str = hora or now.strftime("%H:%M:%S")
        ts_slug = f"{fecha_str.replace('-', '')}_{hora_str.replace(':', '')}"

        # Resolver nombre de archivo si no se suministra o es genérico
        if not output_png:
            scope_slug = normalizar_slug(target)
            title_slug = normalizar_slug(titulo)[:25]
            output_png = Path("output") / "evidencias" / f"poc_{scope_slug}_{title_slug}_{ts_slug}.png"
        else:
            output_png = Path(output_png)

        titulo_completo = f"EVIDENCIA PERICIAL: {titulo} | SCOPE: {target} | {fecha_str} {hora_str}"

        metadatos = {
            "SCOPE": target,
            "FECHA": fecha_str,
            "HORA": hora_str,
            "OWASP": owasp,
            "SEVERIDAD": severidad
        }
        
        texto_poc = f"""=== ENTRADA ADVERSARIA (PAYLOAD) ===\n{payload}\n\n=== RESPUESTA OBTENIDA DEL OBJETIVO ===\n{respuesta}"""
        
        return self.capturar_consola(
            contenido=texto_poc,
            output_png=output_png,
            titulo=titulo_completo,
            prompt="redteam@auditor:~#",
            comando=f"inject-vector --scope '{target}' --vector '{owasp}' --time '{fecha_str} {hora_str}'",
            metadatos=metadatos,
            timestamp_str=f"{fecha_str} {hora_str}"
        )

    def _fallback_render_pillow(self, contenido, output_png, titulo, comando, metadatos):
        """Fallback usando Pillow si ningún navegador estuviese disponible."""
        try:
            from PIL import Image, ImageDraw
            img = Image.new("RGB", (1100, 700), color=(20, 23, 33))
            draw = ImageDraw.Draw(img)
            
            draw.rectangle([(0, 0), (1100, 40)], fill=(30, 34, 48))
            draw.ellipse([(15, 14), (27, 26)], fill=(255, 95, 86))
            draw.ellipse([(35, 14), (47, 26)], fill=(255, 189, 46))
            draw.ellipse([(55, 14), (67, 26)], fill=(39, 201, 63))
            
            y = 55
            draw.text((25, y), titulo[:110], fill=(155, 163, 184))
            y += 25
            if comando:
                draw.text((25, y), f"root@redteam:~# {comando}", fill=(90, 247, 142))
                y += 25
                
            for line in contenido.splitlines()[:30]:
                draw.text((25, y), line[:120], fill=(230, 237, 243))
                y += 18
                
            img.save(str(output_png))
            return {"exito": True, "motor": "pillow_fallback", "ruta": str(output_png)}
        except Exception as e:
            return {"exito": False, "error": f"Fallo total en renderizado: {e}"}

def main():
    parser = argparse.ArgumentParser(description="Capturador pericial PoC con trazabilidad obligatoria (Scope, Fecha, Hora)")
    parser.add_argument("--url", help="URL a capturar con navegador headless")
    parser.add_argument("--consola", help="Texto o comando a renderizar como consola")
    parser.add_argument("--archivo", help="Archivo de texto/log a renderizar")
    parser.add_argument("--cmd", help="Ejecutar comando en vivo y capturar su salida")
    parser.add_argument("--poc-hallazgo", action="store_true", help="Modo estructurado de PoC para hallazgos")
    parser.add_argument("--titulo", default="Captura de Evidencia PoC", help="Título de la prueba")
    parser.add_argument("--owasp", default="LLM01:2025", help="Código OWASP")
    parser.add_argument("--severidad", default="Alta", help="Nivel de severidad")
    parser.add_argument("--scope", "--target", dest="target", default="Target Evaluado", help="Scope u objetivo evaluado")
    parser.add_argument("--fecha", default=None, help="Fecha en formato YYYY-MM-DD")
    parser.add_argument("--hora", default=None, help="Hora en formato HH:MM:SS")
    parser.add_argument("--payload", default="", help="Payload de prueba")
    parser.add_argument("--respuesta", default="", help="Respuesta del modelo")
    parser.add_argument("--output", "-o", default=None, help="Ruta de destino del archivo PNG")
    parser.add_argument("--width", type=int, default=1280, help="Ancho de captura")
    parser.add_argument("--height", type=int, default=800, help="Alto de captura")

    args = parser.parse_args()
    capturador = CapturadorPoC()

    if args.url:
        out_path = args.output or f"output/evidencias/web_{normalizar_slug(args.target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        print(f"[*] Capturando URL: {args.url} -> {out_path}")
        res = capturador.capturar_url(args.url, out_path, width=args.width, height=args.height)
    elif args.poc_hallazgo:
        print(f"[*] Generando tarjeta de PoC pericial con Scope, Fecha y Hora...")
        res = capturador.capturar_poc_hallazgo(
            titulo=args.titulo,
            owasp=args.owasp,
            severidad=args.severidad,
            payload=args.payload,
            respuesta=args.respuesta,
            target=args.target,
            output_png=args.output,
            fecha=args.fecha,
            hora=args.hora
        )
    elif args.cmd:
        out_path = args.output or f"output/evidencias/cmd_{normalizar_slug(args.target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        print(f"[*] Ejecutando y capturando comando: {args.cmd} -> {out_path}")
        proc = subprocess.run(args.cmd, shell=True, capture_output=True, text=True)
        salida = proc.stdout + ("\n[STDERR]\n" + proc.stderr if proc.stderr else "")
        res = capturador.capturar_consola(
            contenido=salida,
            output_png=out_path,
            titulo=f"{args.titulo} | SCOPE: {args.target}",
            comando=args.cmd
        )
    elif args.archivo:
        if not os.path.exists(args.archivo):
            print(f"[!] Error: Archivo {args.archivo} no encontrado.")
            sys.exit(1)
        with open(args.archivo, "r", encoding="utf-8", errors="replace") as f:
            contenido = f.read()
        out_path = args.output or f"output/evidencias/file_{normalizar_slug(args.target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        res = capturador.capturar_consola(contenido, out_path, titulo=f"{args.titulo} | SCOPE: {args.target}")
    elif args.consola:
        out_path = args.output or f"output/evidencias/consola_{normalizar_slug(args.target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        res = capturador.capturar_consola(args.consola, out_path, titulo=f"{args.titulo} | SCOPE: {args.target}")
    else:
        print("[!] Debe especificar --url, --consola, --archivo, --cmd o --poc-hallazgo.")
        sys.exit(1)

    if res.get("exito"):
        print(f"[+] Captura generada exitosamente [{res.get('motor', 'ok')}]: {res.get('ruta')}")
    else:
        print(f"[!] Error generando captura: {res.get('error')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
