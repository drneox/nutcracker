"""Generación de informes en consola y JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

if TYPE_CHECKING:
    from .analyzer import AnalysisResult

console = Console()

_STRENGTH_COLOR = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

_VERDICT_COLOR = {
    True: "green",
    False: "red",
}


def print_report(result: "AnalysisResult") -> None:
    """Imprime el informe completo en la terminal con formato rico."""

    # ── Encabezado ──────────────────────────────────────────────────────────
    header = Text()
    header.append("  nutcracker  ", style="bold white on dark_blue")
    console.print()
    console.print(Panel(header, expand=False))

    # ── Metadatos de la app ──────────────────────────────────────────────────
    meta = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    meta.add_column("Campo", style="dim")
    meta.add_column("Valor", style="bold")
    meta.add_row("Package", result.package)
    meta.add_row("Versión", f"{result.version_name} (código {result.version_code})")
    meta.add_row("SDK mínimo / objetivo", f"{result.min_sdk} / {result.target_sdk}")
    meta.add_row("Analizado", result.analyzed_at)
    console.print(meta)

    # ── Veredicto ────────────────────────────────────────────────────────────
    if result.protection_broken:
        dec = result.decompilation_info or {}
        method = dec.get("method", "runtime")
        dex_n = dec.get("dex_count", 0)
        verdict_text = Text("⚠  PROTECCIÓN ROTA — bypass exitoso", style="bold yellow")
        verdict_detail = (
            f"Método: {method}  |  DEX extraídos: {dex_n}  |  "
            f"{result.high_strength_count} detecciones de fortaleza alta"
        )
    elif result.protected:
        verdict_text = Text("✔  PROTEGIDA contra root", style="bold green")
        verdict_detail = (
            f"Confianza: {result.confidence.upper()}  |  "
            f"{result.high_strength_count} detecciones de fortaleza alta"
        )
    else:
        verdict_text = Text("✘  SIN PROTECCIÓN anti-root detectada", style="bold red")
        verdict_detail = "No se encontraron mecanismos anti-root conocidos."

    console.print(Panel(verdict_text, subtitle=verdict_detail, expand=False, border_style="bold"))

    # ── Tabla de resultados por detector ────────────────────────────────────
    table = Table(
        title="Resultados por detector",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Detector", style="bold", no_wrap=True)
    table.add_column("Detectado", justify="center")
    table.add_column("Fortaleza", justify="center")
    table.add_column("Evidencias encontradas", overflow="fold")

    for r in result.results:
        detected_str = (
            Text("SÍ", style="bold green") if r.detected else Text("NO", style="dim red")
        )
        strength_str = Text(
            r.strength.upper(),
            style=_STRENGTH_COLOR.get(r.strength, "white"),
        )
        details_preview = (
            "\n".join(r.details[:5]) + ("\n…y más" if len(r.details) > 5 else "")
            if r.details
            else "-"
        )
        table.add_row(r.name, detected_str, strength_str, details_preview)

    console.print(table)
    console.print()


def print_vuln_report(scan_result: "VulnScanResult", base_dir: "Path") -> None:
    """Imprime el informe de vulnerabilidades en consola."""
    from .vuln_scanner import ScanResult

    findings = scan_result.findings
    total = len(findings)

    if total == 0:
        console.print(Panel(
            Text("✔  No se encontraron vulnerabilidades conocidas", style="bold green"),
            subtitle=f"{scan_result.files_scanned} archivos analizados",
            expand=False,
            border_style="green",
        ))
        return

    # Resumen
    by_sev = scan_result.by_severity
    summary_parts = []
    colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    for sev, items in by_sev.items():
        if items:
            summary_parts.append(f"[{colors[sev]}]{len(items)} {sev.upper()}[/{colors[sev]}]")

    console.print()
    console.print(Panel(
        Text(f"⚠  {total} vulnerabilidades encontradas", style="bold red"),
        subtitle="  ".join(summary_parts) + f"  |  {scan_result.files_scanned} archivos",
        expand=False,
        border_style="red",
    ))

    # Tabla por severidad
    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev, [])
        if not items:
            continue

        sev_color = colors[sev]
        table = Table(
            title=f"[{sev_color}]{sev.upper()}[/{sev_color}] ({len(items)})",
            box=box.ROUNDED,
            show_lines=True,
            highlight=True,
        )
        table.add_column("ID", style="dim", no_wrap=True, width=8)
        table.add_column("Vulnerabilidad", style="bold", no_wrap=True)
        table.add_column("Archivo : línea", overflow="fold")
        table.add_column("Código encontrado", overflow="fold")

        for f in items:
            rel = f.relative_path(base_dir)
            # Acortar rutas largas de jadx (sources/com/...)
            parts = rel.split("/")
            short_path = "/".join(parts[-3:]) if len(parts) > 3 else rel
            table.add_row(
                f.rule_id,
                f.title,
                f"{short_path}:{f.line}",
                f.matched_text,
            )

        console.print(table)

    console.print()


def save_json_report(result: "AnalysisResult", output_path: str | Path) -> None:
    """Guarda el informe completo en formato JSON."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)

    console.print(f"[dim]Informe JSON guardado en:[/dim] [bold]{output_path}[/bold]")


def save_analysis_json(result: "AnalysisResult", reports_dir: str | Path = "./reports") -> Path:
    """Persiste el AnalysisResult en reports/<package>/<timestamp>.json.

    Convención canónica para que todos los módulos guarden en el mismo lugar.
    Debe llamarse una sola vez, cuando el resultado está completamente poblado
    (incluido decompilation_info si hubo bypass).
    """
    pkg_dir = Path(reports_dir) / result.package
    pkg_dir.mkdir(parents=True, exist_ok=True)

    ts = (result.analyzed_at or "")[:19].replace(":", "").replace("-", "").replace("T", "_")
    if not ts:
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = pkg_dir / f"{ts}.json"
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)

    console.print(f"[dim]  Análisis guardado: {json_path}[/dim]")
    return json_path


def load_osint_json(package: str):
    """Carga el resultado OSINT desde JSON guardado en reports/."""
    from .osint import OsintResult, Secret, Subdomain, PublicLeak
    osint_path = Path("./reports") / f"osint_{package}.json"
    if not osint_path.exists():
        return None
    with osint_path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return OsintResult(
        package=data.get("package", package),
        secrets=[Secret(**s) for s in data.get("secrets", [])],
        subdomains=[Subdomain(**s) for s in data.get("subdomains", [])],
        public_leaks=[PublicLeak(**l) for l in data.get("public_leaks", [])],
        dorks=data.get("dorks", {}),
        domains_scanned=data.get("domains_scanned", []),
        auth_flows=data.get("auth_flows", []),
    )
