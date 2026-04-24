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

from .i18n import t

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
    meta.add_column("Field", style="dim")
    meta.add_column("Value", style="bold")
    meta.add_row(t("package"), result.package)
    meta.add_row(t("version"), f"{result.version_name} ({result.version_code})")
    meta.add_row(t("min_sdk_target"), f"{result.min_sdk} / {result.target_sdk}")
    meta.add_row(t("analyzed_at"), result.analyzed_at)
    console.print(meta)

    # ── Veredicto ────────────────────────────────────────────────────────────
    if result.protection_broken:
        dec = result.decompilation_info or {}
        method = dec.get("method", "runtime")
        dex_n = dec.get("dex_count", 0)
        verdict_text = Text(t("verdict_protection_broken_banner"), style="bold yellow")
        verdict_detail = (
            f"{t('method_label')}: {method}  |  {t('dex_extracted')}: {dex_n}  |  "
            f"{result.high_strength_count} {t('high_strength_detections')}"
        )
    elif result.protected:
        verdict_text = Text(t("verdict_protected_banner"), style="bold green")
        verdict_detail = (
            f"{t('confidence_label')}: {result.confidence.upper()}  |  "
            f"{result.high_strength_count} {t('high_strength_detections')}"
        )
    else:
        verdict_text = Text(t("verdict_no_protection_banner"), style="bold red")
        verdict_detail = t("no_mechanisms_found")

    console.print(Panel(verdict_text, subtitle=verdict_detail, expand=False, border_style="bold"))

    # ── Tabla de resultados por detector ────────────────────────────────────
    table = Table(
        title=t("detector_results_title"),
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column(t("detector"), style="bold", no_wrap=True)
    table.add_column(t("detected"), justify="center")
    table.add_column(t("strength"), justify="center")
    table.add_column(t("evidence"), overflow="fold")

    for r in result.results:
        detected_str = (
            Text(t("yes"), style="bold green") if r.detected else Text(t("no"), style="dim red")
        )
        strength_str = Text(
            r.strength.upper(),
            style=_STRENGTH_COLOR.get(r.strength, "white"),
        )
        details_preview = (
            "\n".join(r.details[:5]) + (f"\n{t('and_more')}" if len(r.details) > 5 else "")
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

    console.print(f"[dim]{t('json_report_saved')}[/dim] [bold]{output_path}[/bold]")


def save_analysis_json(
    result: "AnalysisResult",
    reports_dir: str | Path = "./reports",
    scan_result=None,
    manifest=None,
) -> Path:
    """Persiste el AnalysisResult en reports/<package>/<timestamp>.json.

    Convención canónica para que todos los módulos guarden en el mismo lugar.
    Debe llamarse una sola vez, cuando el resultado está completamente poblado
    (incluido decompilation_info si hubo bypass).

    Args:
        result:      Resultado del análisis de protecciones.
        reports_dir: Directorio raíz donde guardar los reportes.
        scan_result: ScanResult del vuln_scanner (opcional). Si se provee,
                     se añade la sección ``masvs`` al JSON con el reporte
                     de cumplimiento MASVS v2.
    """
    pkg_dir = Path(reports_dir) / result.package
    pkg_dir.mkdir(parents=True, exist_ok=True)

    ts = (result.analyzed_at or "")[:19].replace(":", "").replace("-", "").replace("T", "_")
    if not ts:
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    data = result.to_dict()

    # Enriquecer con reporte MASVS v2 si hay datos suficientes
    try:
        from .masvs import build_masvs_report
        masvs_report = build_masvs_report(result, scan_result, manifest)
        data["masvs"] = masvs_report.to_dict()
    except Exception:
        pass  # No bloquear el guardado si el módulo falla

    json_path = pkg_dir / f"{ts}.json"
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

    console.print(f"[dim]{t('analysis_saved')} {json_path}[/dim]")
    return json_path


def print_masvs_summary(masvs_report: "MASVSReport") -> None:
    """Imprime el resumen de cumplimiento MASVS v2 en consola."""
    from .masvs import MASVSReport

    _GRADE_COLOR = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    _STATUS_ICON = {
        "pass":          ("[green]✔[/green]",          t("status_pass")),
        "fail":          ("[red]✘[/red]",               t("status_fail")),
        "bypass":        ("[yellow]⚡[/yellow]",        t("status_bypass")),
        "no_protection": ("[red]\u2718[/red]",           t("status_no_protection")),
        "not_tested":    ("[dim]–[/dim]",               t("status_not_tested")),
    }

    from .masvs import MASVS_CONTROLS as _ALL_CONTROLS
    _MASVS_TOTAL = 24  # Total de controles MASVS v2 oficial
    _covered = len(_ALL_CONTROLS)

    grade_color = _GRADE_COLOR.get(masvs_report.grade, "white")
    score_text = Text(justify="center")
    score_text.append(f"\n  {t('masvs_title')}  |  {t('score_label')}: ", style="bold white")
    score_text.append(f"{masvs_report.score}/100", style=f"bold {grade_color}")
    score_text.append(f"  |  {t('grade_label')}: ", style="bold white")
    score_text.append(masvs_report.grade, style=f"bold {grade_color}")
    score_text.append(f"  |  {t('coverage_label')}: ", style="bold white")
    score_text.append(f"{_covered}/{_MASVS_TOTAL} {t('controls')}", style="bold cyan")
    if masvs_report.bypass_confirmed:
        score_text.append(f"  |  ⚡ {t('bypass_confirmed')}", style="bold yellow")
    score_text.append("\n")

    summary = masvs_report.to_dict()["summary"]
    _fail_total = summary['fail'] + summary['no_protection']
    _stat_parts = []
    if summary['pass']:   _stat_parts.append(f"✔ {summary['pass']} {t('status_pass')}")
    if _fail_total:       _stat_parts.append(f"✘ {_fail_total} {t('status_fail')}")
    if summary['bypass']: _stat_parts.append(f"⚡ {summary['bypass']} {t('status_bypass')}")
    stats = "  ".join(_stat_parts)
    console.print()
    console.print(Panel(score_text, subtitle=stats, expand=False, border_style=grade_color))

    # Orden de visualización: peor estado primero
    _STATUS_ORDER = {"bypass": 0, "fail": 1, "no_protection": 2, "not_tested": 3, "pass": 4}

    all_controls = sorted(
        masvs_report.controls,
        key=lambda c: (_STATUS_ORDER.get(c.status, 3), -c.penalty),
    )

    table = Table(
        title=t("masvs_controls_title"),
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column(t("control"),     style="bold cyan", no_wrap=True, width=22)
    table.add_column(t("status"),      justify="center",  no_wrap=True, width=14)
    table.add_column(t("description"), overflow="fold")

    for ctrl in all_controls:
        icon, label = _STATUS_ICON.get(ctrl.status, ("?", ctrl.status))
        status_cell = Text()
        status_cell.append_text(Text.from_markup(icon))
        status_cell.append(f" {label}")

        # Filas de pass/not_tested más tenues
        row_style = "dim" if ctrl.status in ("pass", "not_tested") else ""
        table.add_row(
            ctrl.control_id,
            status_cell,
            ctrl.description,
            style=row_style,
        )

    console.print(table)
    console.print()


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
        domains_scanned=data.get("domains_scanned", []),
        auth_flows=data.get("auth_flows", []),
    )
