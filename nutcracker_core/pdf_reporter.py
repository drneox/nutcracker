"""
Generador de informes PDF — nutcracker.

Secciones:
  1. Resumen (portada + metadata + conteos)
  2. Protecciones descubiertas (estado + evidencia)
  3. Misconfigurations del Manifest
  4. Leaks
  5. Vulnerabilidades

Sin scoring ni grades artificiales — solo hechos.
Usa fpdf2 (pip install fpdf2).
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from fpdf import FPDF, XPos, YPos

if TYPE_CHECKING:
    from .analyzer import AnalysisResult
    from .manifest_analyzer import ManifestAnalysisResult, Misconfiguration
    from .osint import OsintResult
    from .vuln_scanner import ScanResult
    from .vuln_scanner import VulnFinding


# ── Paleta de colores ─────────────────────────────────────────────────────────
C = {
    "bg":           (15,  23,  42),   # azul noche — fondo del header
    "accent":       (99, 102, 241),   # índigo — líneas de acento
    "success":      (34, 197,  94),   # verde
    "danger":       (239,  68,  68),  # rojo
    "warning":      (234, 179,   8),  # amarillo
    "info":         (56,  189, 248),  # azul claro
    "low":          (148, 163, 184),  # gris azulado
    "white":        (255, 255, 255),
    "black":        (15,  23,  42),
    "text":         (30,  41,  59),
    "muted":        (100, 116, 139),
    "row_alt":      (241, 245, 249),  # fondo fila alternada
    "row_normal":   (255, 255, 255),
    "critical_bg":  (254, 226, 226),
    "high_bg":      (254, 243, 199),
    "medium_bg":    (219, 234, 254),
    "low_bg":       (240, 253, 244),
    "info_bg":      (248, 250, 252),
}

SEV_COLOR = {
    "critical": (C["danger"],    C["critical_bg"]),
    "high":     (C["warning"],   C["high_bg"]),
    "medium":   (C["info"],      C["medium_bg"]),
    "low":      (C["success"],   C["low_bg"]),
    "info":     (C["muted"],     C["info_bg"]),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

_UNICODE_SUBS = str.maketrans({
    "\u2014": "-", "\u2013": "-", "\u2012": "-",
    "\u2019": "'", "\u2018": "'",
    "\u201c": '"', "\u201d": '"',
    "\u2026": "...",
    "\u2022": "*", "\u2023": ">",
    "\u00b7": ".",
    "\u2714": "OK", "\u2718": "NO",
    "\u2192": ">", "\u2190": "<",
    "\u00b0": "deg",
})


def _safe(text: str) -> str:
    """Convierte texto a Latin-1 seguro para fuentes Helvetica de fpdf2."""
    return text.translate(_UNICODE_SUBS).encode("latin-1", errors="replace").decode("latin-1")


def _format_elapsed(seconds: float | None) -> str:
    """Formatea una duración en formato legible para el reporte."""
    if seconds is None:
        return "-"
    total_seconds = max(0, int(round(seconds)))
    minutes, secs = divmod(total_seconds, 60)
    hours, mins = divmod(minutes, 60)

    parts: list[str] = []
    if hours:
        parts.append(f"{hours}h")
    if mins or hours:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _is_leak_finding(f: "VulnFinding") -> bool:
    rid = str(getattr(f, "rule_id", "")).upper()
    if rid.startswith("AL-") or rid.startswith("HC") or rid.startswith("GL-"):
        return True
    title = str(getattr(f, "title", "")).lower()
    category = str(getattr(f, "category", "")).lower()
    leak_terms = ("secret", "token", "apikey", "api key", "password", "credential", "jwt", "private key")
    return any(t in f"{title} {category}" for t in leak_terms)


def _split_findings(scan: "ScanResult | None") -> tuple[list["VulnFinding"], list["VulnFinding"]]:
    if scan is None:
        return [], []
    leaks: list["VulnFinding"] = []
    vulns: list["VulnFinding"] = []
    for f in scan.findings:
        if _is_leak_finding(f):
            leaks.append(f)
        else:
            vulns.append(f)
    return leaks, vulns


def _protection_broken(result: "AnalysisResult") -> bool:
    return result.protection_broken


# ── PDF class ─────────────────────────────────────────────────────────────────

class APKReportPDF(FPDF):
    """PDF con header/footer personalizados."""

    def __init__(self, app_package: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app_package = app_package
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*C["bg"])
        self.rect(0, 0, 210, 10, style="F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C["white"])
        self.set_y(2)
        self.cell(0, 6, "nutcracker  ·  Security Report", align="L")
        self.set_y(2)
        self.cell(0, 6, self.app_package, align="R")
        self.set_text_color(*C["text"])
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C["muted"])
        self.cell(0, 5, f"Generado el {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}  ·  https://github.com/drneox/nutcracker",
                  align="L")
        self.cell(0, 5, f"Pagina {self.page_no()}", align="R")

    def section_title(self, text: str) -> None:
        self.ln(4)
        self.set_fill_color(*C["accent"])
        self.rect(self.l_margin, self.get_y(), 3, 7, style="F")
        self.set_x(self.l_margin + 5)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*C["bg"])
        self.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def hline(self) -> None:
        self.set_draw_color(*C["accent"])
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), 210 - self.r_margin, self.get_y())
        self.ln(3)


# ── 1. Portada + Resumen ─────────────────────────────────────────────────────

def _cover_page(
    pdf: APKReportPDF,
    result: "AnalysisResult",
    scan: "ScanResult | None" = None,
    manifest: "ManifestAnalysisResult | None" = None,
) -> None:
    # Fondo oscuro superior
    pdf.set_fill_color(*C["bg"])
    pdf.rect(0, 0, 210, 85, style="F")

    # Titulo
    pdf.set_y(20)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*C["white"])
    pdf.cell(0, 12, "nutcracker", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C["muted"])
    pdf.cell(0, 5, "https://github.com/drneox/nutcracker", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*C["info"])
    pdf.cell(0, 7, "Android Security Analysis Report", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Linea acento
    pdf.set_draw_color(*C["accent"])
    pdf.set_line_width(0.8)
    pdf.line(70, pdf.get_y() + 3, 140, pdf.get_y() + 3)
    pdf.ln(10)

    # ── Veredicto ─────────────────────────────────────────────────────────────
    protected = result.protected
    was_bypassed = _protection_broken(result)

    if not protected:
        verdict_txt = "SIN PROTECCION"
        verdict_bg  = C["danger"]
        verdict_sub = "No se detectaron mecanismos de proteccion activos."
    elif was_bypassed:
        verdict_txt = "PROTECCION ROTA"
        verdict_bg  = (220, 95, 0)
        verdict_sub = "Protecciones detectadas pero eludidas via Frida/FART."
    else:
        verdict_txt = "PROTEGIDA"
        verdict_bg  = C["success"]
        verdict_sub = "Protecciones activas detectadas."

    pdf.set_fill_color(*verdict_bg)
    pdf.set_x(45)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C["white"])
    pdf.cell(120, 12, verdict_txt, align="C", fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*C["muted"])
    pdf.cell(0, 5, _safe(verdict_sub), align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    # ── Metadata ──────────────────────────────────────────────────────────────
    pdf.set_y(max(pdf.get_y() + 2, 95))
    pdf.set_text_color(*C["text"])

    def meta_row(label: str, value: str) -> None:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["muted"])
        pdf.cell(40, 6, label, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*C["text"])
        pdf.cell(0, 6, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    meta_row("Package:", _safe(result.package))
    meta_row("Version:", _safe(f"{result.version_name}  (codigo {result.version_code})"))
    meta_row("SDK min / target:", _safe(f"{result.min_sdk} / {result.target_sdk}"))
    meta_row("Analizado:", result.analyzed_at[:19].replace("T", "  "))
    if result.elapsed_seconds is not None:
        meta_row("Duracion:", _format_elapsed(result.elapsed_seconds))

    # Decompilacion con Frida (si se realizo)
    dec = getattr(result, "decompilation_info", None)
    if dec and dec.get("method"):
        meta_row(
            "Decompilado:",
            _safe(f"{dec['method']}  ({dec.get('dex_count', 0)} DEX volcados)"),
        )
        if dec.get("source_dir"):
            meta_row("Fuentes:", _safe(str(dec["source_dir"])))

    # Motores de escaneo (vuln y leaks por separado)
    if scan is not None:
        vuln_eng = scan.scanner_engine or ""
        leak_eng = scan.leak_engine or ""

        # Vulnerabilidades
        if vuln_eng:
            vuln_label = vuln_eng.replace("regex", "regex interno")
            meta_row(
                "Escaneo vulns:",
                _safe(f"{vuln_label}  ({scan.files_scanned} archivos)"),
            )

        # Leaks
        if leak_eng:
            parts = [p.strip() for p in leak_eng.split("+") if p.strip()]
            meta_row("Escaneo leaks:", _safe(" + ".join(parts)))

    pdf.ln(6)
    pdf.hline()

    # ── Tarjetas resumen ──────────────────────────────────────────────────────
    leaks, vulns = _split_findings(scan)
    detected_count = sum(1 for d in result.results if d.detected)
    total_modules = len(result.results)
    misconfig_count = len(manifest.misconfigurations) if manifest else 0

    pdf.set_y(pdf.get_y() + 2)

    # Sub-etiqueta de estado para la tarjeta de Protecciones
    if was_bypassed:
        _prot_sub: tuple | None = ("ELUDIDA", (220, 95, 0))
    elif not protected:
        _prot_sub = ("SIN DETECT.", C["danger"])
    else:
        _prot_sub = None

    counts = [
        ("Protecciones", f"{detected_count} / {total_modules}",
         (150, 150, 150), _prot_sub),
        ("Misconfigs", str(misconfig_count),
         C["warning"] if misconfig_count else C["success"], None),
        ("Leaks", str(len(leaks)),
         C["danger"] if leaks else C["success"], None),
        ("Vulns", str(len(vulns)),
         C["danger"] if vulns else C["success"], None),
    ]

    card_w = 38
    card_h = 18
    card_gap = 4
    total_w = card_w * len(counts) + card_gap * (len(counts) - 1)
    start_x = (210 - total_w) / 2
    card_y = pdf.get_y()

    for i, (label, value, color, sub) in enumerate(counts):
        x = start_x + i * (card_w + card_gap)
        pdf.set_fill_color(*C["row_alt"])
        pdf.rect(x, card_y, card_w, card_h, style="F")
        # Barra superior de color
        pdf.set_fill_color(*color)
        pdf.rect(x, card_y, card_w, 2, style="F")
        if sub:
            sub_txt, sub_color = sub
            # Valor (fuente más pequeña para hacer espacio al indicador)
            pdf.set_xy(x, card_y + 2)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*C["text"])
            pdf.cell(card_w, 5, value, align="C")
            # Indicador de estado (ej. "ELUDIDA")
            pdf.set_xy(x, card_y + 7)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*sub_color)
            pdf.cell(card_w, 4, sub_txt, align="C")
            # Etiqueta
            pdf.set_xy(x, card_y + 12)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C["muted"])
            pdf.cell(card_w, 4, label, align="C")
        else:
            # Valor
            pdf.set_xy(x, card_y + 4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(*C["text"])
            pdf.cell(card_w, 6, value, align="C")
            # Etiqueta
            pdf.set_xy(x, card_y + 12)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C["muted"])
            pdf.cell(card_w, 4, label, align="C")

    pdf.set_y(card_y + card_h)
    pdf.set_text_color(*C["text"])


# ── 2. Protecciones descubiertas ──────────────────────────────────────────────

def _protections_section(pdf: APKReportPDF, result: "AnalysisResult") -> None:
    pdf.add_page()
    pdf.section_title("Protecciones Descubiertas")

    fw = pdf.w - pdf.l_margin - pdf.r_margin
    x0 = pdf.l_margin
    was_bypassed = _protection_broken(result)

    # Linea resumen
    detected_count = sum(1 for d in result.results if d.detected)
    total_count = len(result.results)

    if not detected_count:
        status_msg = "No se detectaron mecanismos de proteccion activos."
    elif was_bypassed:
        status_msg = (
            f"{detected_count} de {total_count} protecciones detectadas. "
            f"Las protecciones fueron eludidas via Frida/FART."
        )
    else:
        status_msg = f"{detected_count} de {total_count} protecciones detectadas."

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*C["muted"])
    pdf.cell(0, 5, _safe(status_msg), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # ── Tarjeta por detector ──────────────────────────────────────────────────
    BADGE_W = 26
    ELUD_W  = 20
    HDR_H   = 8

    for det in result.results:
        det_fg  = C["danger"] if det.detected else C["success"]
        body_bg = (252, 240, 240) if det.detected else (240, 253, 244)
        show_eluded = det.detected and was_bypassed

        if pdf.will_page_break(20):
            pdf.add_page()

        card_y = pdf.get_y()

        # ── Header oscuro ─────────────────────────────────────────────────────
        pdf.set_fill_color(*C["bg"])
        pdf.rect(x0, card_y, fw, HDR_H, style="F")

        # Badge DETECTADO / NO DETECTADO
        pdf.set_xy(x0 + 2, card_y + 1.5)
        pdf.set_fill_color(*det_fg)
        pdf.set_text_color(*C["white"])
        pdf.set_font("Helvetica", "B", 6.5)
        pdf.cell(BADGE_W, 5, "DETECTADO" if det.detected else "NO DETECTADO",
                 align="C", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Badge ELUDIDO (solo si fue detectado y luego bypassed)
        right_offset = 4
        if show_eluded:
            pdf.set_xy(x0 + fw - right_offset - ELUD_W, card_y + 1.5)
            pdf.set_fill_color(220, 95, 0)
            pdf.set_text_color(*C["white"])
            pdf.set_font("Helvetica", "B", 6.5)
            pdf.cell(ELUD_W, 5, "ELUDIDO", align="C", fill=True)
            right_offset += ELUD_W + 2

        # Nombre detector
        name_x = x0 + BADGE_W + 6
        name_w = fw - BADGE_W - right_offset - 8
        pdf.set_xy(name_x, card_y + 1.5)
        pdf.set_text_color(*C["white"])
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(name_w, 5, _safe(det.name[:52]), align="L")

        # ── Cuerpo: evidencias ────────────────────────────────────────────────
        pdf.set_y(card_y + HDR_H)

        if det.details:
            for ev in det.details:
                pdf.set_x(x0)
                pdf.set_fill_color(*body_bg)
                pdf.set_text_color(*C["muted"])
                pdf.set_font("Helvetica", "", 6.5)
                pdf.cell(7, 5, "  -", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_font("Courier", "", 6.5)
                pdf.set_text_color(*C["text"])
                pdf.multi_cell(fw - 7, 5, _safe(ev), fill=True)
        else:
            pdf.set_x(x0)
            pdf.set_fill_color(*body_bg)
            pdf.set_text_color(*C["muted"])
            pdf.set_font("Helvetica", "I", 6.5)
            msg = "  Sin evidencias registradas." if det.detected else "  Sin proteccion detectada."
            pdf.cell(fw, 5, msg, fill=True,
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Linea de acento inferior
        pdf.set_fill_color(*det_fg)
        pdf.rect(x0, pdf.get_y(), fw, 0.8, style="F")
        pdf.ln(4)

    pdf.set_text_color(*C["text"])
    pdf.ln(2)


# ── 3. Misconfigurations del Manifest ─────────────────────────────────────────

def _misconfig_section(pdf: APKReportPDF, manifest: "ManifestAnalysisResult") -> None:
    from .manifest_analyzer import Misconfiguration

    misconfigs: list[Misconfiguration] = manifest.misconfigurations

    pdf.add_page()
    pdf.section_title(f"Misconfigurations del Manifest  ({len(misconfigs)} hallazgos)")

    if not misconfigs:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(*C["success"])
        pdf.cell(0, 8, _safe("Sin misconfigurations detectadas en el manifest."),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])
        return

    # Info del manifest
    info_items = []
    if manifest.package:
        info_items.append(("Package", manifest.package))
    if manifest.min_sdk:
        info_items.append(("Min SDK", str(manifest.min_sdk)))
    if manifest.target_sdk:
        info_items.append(("Target SDK", str(manifest.target_sdk)))
    if manifest.debuggable:
        info_items.append(("Debuggable", "SI"))
    if manifest.allow_backup:
        info_items.append(("allowBackup", "true"))
    if manifest.cleartext_traffic:
        info_items.append(("Cleartext Traffic", "SI"))
    if not manifest.has_network_security_config:
        info_items.append(("Network Security Config", "NO"))

    if info_items:
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*C["muted"])
        for label, val in info_items:
            pdf.cell(40, 5, _safe(label + ":"), new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.cell(0, 5, _safe(val), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 7.5)
        pdf.ln(3)

    # Resumen por severidad
    sev_order = ["critical", "high", "medium", "info"]
    by_sev: dict[str, list[Misconfiguration]] = {s: [] for s in sev_order}
    for m in misconfigs:
        by_sev.setdefault(m.severity, []).append(m)

    pdf.set_font("Helvetica", "B", 8)
    for sev in sev_order:
        items = by_sev.get(sev, [])
        if not items:
            continue
        fg, bg = SEV_COLOR.get(sev, (C["muted"], C["row_alt"]))
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*fg)
        pdf.cell(28, 6, f"{sev.upper()}: {len(items)}", align="C", fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_x(pdf.get_x() + 2)
    pdf.ln(10)

    # Hallazgos agrupados por severidad
    for sev in sev_order:
        items = by_sev.get(sev, [])
        if not items:
            continue

        fg, bg = SEV_COLOR.get(sev, (C["muted"], C["row_alt"]))

        if pdf.will_page_break(35):
            pdf.add_page()
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*fg)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, f"  {sev.upper()}  ({len(items)} hallazgos)",
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        for j, m in enumerate(items):
            row_bg = C["row_alt"] if j % 2 == 0 else C["row_normal"]
            if pdf.will_page_break(25):
                pdf.add_page()
            _misconfig_card(pdf, m, row_bg)

        pdf.ln(3)


def _misconfig_card(pdf: APKReportPDF, m: "Misconfiguration", row_bg: tuple) -> None:
    """Renderiza una misconfiguration como tarjeta."""
    fw = pdf.w - pdf.l_margin - pdf.r_margin
    x0 = pdf.l_margin

    fg_sev, bg_sev = SEV_COLOR.get(m.severity, (C["muted"], C["row_alt"]))

    sev_w = 18
    pdf.set_fill_color(*fg_sev)
    pdf.set_text_color(*C["white"])
    pdf.set_font("Helvetica", "B", 6.5)
    pdf.set_x(x0)
    pdf.cell(sev_w, 5.5, _safe(m.severity.upper()), align="C", fill=True,
             new_x=XPos.RIGHT, new_y=YPos.TOP)

    y_row = pdf.get_y()

    title_x = x0 + sev_w + 2
    title_w = fw - sev_w - 2
    pdf.set_xy(title_x, y_row)
    pdf.set_fill_color(*row_bg)
    pdf.set_text_color(*C["text"])
    pdf.set_font("Helvetica", "B", 8)
    pdf.multi_cell(title_w, 5.5, _safe(m.title), fill=True)

    pdf.set_y(max(pdf.get_y(), y_row + 5.5))

    pdf.set_x(x0)
    pdf.set_font("Courier", "", 6.5)
    pdf.set_text_color(*C["muted"])
    pdf.set_fill_color(*row_bg)
    loc = m.location if len(m.location) <= 100 else m.location[:97] + "..."
    pdf.multi_cell(fw, 5, _safe(loc), fill=True)

    if m.description:
        pdf.set_x(x0)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C["text"])
        pdf.set_fill_color(235, 235, 235)
        pdf.multi_cell(fw, 5, _safe(m.description), fill=True)

    if m.recommendation:
        pdf.set_x(x0)
        pdf.set_font("Helvetica", "I", 6.5)
        pdf.set_text_color(*C["muted"])
        pdf.set_fill_color(*row_bg)
        pdf.multi_cell(fw, 5, _safe(f"> {m.recommendation}"), fill=True)

    pdf.set_text_color(*C["text"])
    pdf.ln(1.5)


# ── 4 / 5. Leaks y Vulnerabilidades ──────────────────────────────────────────

def _vuln_card(pdf: APKReportPDF, finding: "VulnFinding", base_dir: Path, row_bg: tuple) -> None:
    """Renderiza un hallazgo como tarjeta con texto completo."""
    fw = pdf.w - pdf.l_margin - pdf.r_margin
    x0 = pdf.l_margin

    fg_sev, bg_sev = SEV_COLOR.get(finding.severity, (C["muted"], C["row_alt"]))

    # Linea divisora
    if not pdf.will_page_break(7):
        pdf.set_fill_color(*row_bg)
        pdf.rect(x0, pdf.get_y(), fw, 0.3, style="F")

    # Fila 1: badge ID + titulo + badge severidad
    badge_w = 16
    sev_w   = 20
    pdf.set_fill_color(*bg_sev)
    pdf.set_text_color(*fg_sev)
    pdf.set_font("Helvetica", "B", 6.5)
    pdf.set_x(x0)
    pdf.cell(badge_w, 5.5, _safe(finding.rule_id), align="C", fill=True,
             new_x=XPos.RIGHT, new_y=YPos.TOP)

    y_row = pdf.get_y()

    # Badge severidad — derecha
    pdf.set_xy(x0 + fw - sev_w, y_row)
    pdf.set_fill_color(*fg_sev)
    pdf.set_text_color(*C["white"])
    pdf.set_font("Helvetica", "B", 6.5)
    pdf.cell(sev_w, 5.5, _safe(finding.severity.upper()), align="C", fill=True)

    # Titulo — centro
    title_x = x0 + badge_w + 2
    title_w = fw - badge_w - sev_w - 4
    pdf.set_xy(title_x, y_row)
    pdf.set_fill_color(*row_bg)
    pdf.set_text_color(*C["text"])
    pdf.set_font("Helvetica", "B", 8)
    pdf.multi_cell(title_w, 5.5, _safe(finding.title), fill=True)

    pdf.set_y(max(pdf.get_y(), y_row + 5.5))

    # Fila 2: categoria + ruta:linea
    rel = finding.relative_path(base_dir)
    parts = rel.replace("\\", "/").split("/")
    short_path = "/".join(parts[-4:]) if len(parts) > 4 else rel
    file_loc = _safe(f"{short_path}:{finding.line}")

    pdf.set_x(x0)
    pdf.set_font("Helvetica", "", 6.5)
    pdf.set_text_color(*C["muted"])
    pdf.set_fill_color(*row_bg)
    cat_w = fw * 0.45
    pdf.cell(cat_w, 5, _safe(finding.category), fill=True,
             new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("Courier", "", 6.5)
    pdf.set_x(x0 + cat_w)
    pdf.multi_cell(fw - cat_w, 5, file_loc, fill=True)

    # Fila 3: codigo encontrado
    code = _safe(finding.matched_text.strip())
    if code:
        pdf.set_x(x0)
        pdf.set_fill_color(235, 235, 235)
        pdf.set_text_color(*C["black"])
        pdf.set_font("Courier", "", 6.5)
        pdf.multi_cell(fw, 5, code, fill=True)

    # Fila 4: recomendacion
    pdf.set_x(x0)
    pdf.set_font("Helvetica", "I", 6.5)
    pdf.set_text_color(*C["muted"])
    pdf.set_fill_color(*row_bg)
    pdf.multi_cell(fw, 5, _safe(f"> {finding.recommendation}"), fill=True)

    pdf.set_text_color(*C["text"])
    pdf.ln(1.5)


def _findings_section(
    pdf: APKReportPDF,
    base_dir: Path,
    findings: list["VulnFinding"],
    title: str,
    empty_msg: str,
) -> None:
    pdf.add_page()
    pdf.section_title(f"{title}  ({len(findings)} hallazgos)")

    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(*C["success"])
        pdf.cell(0, 8, _safe(empty_msg), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])
        return

    # Pills de resumen por severidad
    by_sev: dict[str, list["VulnFinding"]] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    sev_order = ["critical", "high", "medium", "low", "info"]
    pdf.set_font("Helvetica", "B", 8)
    for sev in sev_order:
        items = by_sev.get(sev, [])
        if not items:
            continue
        fg, bg = SEV_COLOR.get(sev, (C["muted"], C["row_alt"]))
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*fg)
        pdf.cell(28, 6, f"{sev.upper()}: {len(items)}", align="C", fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_x(pdf.get_x() + 2)
    pdf.ln(10)

    # Hallazgos agrupados por severidad
    for sev in sev_order:
        items = by_sev.get(sev, [])
        if not items:
            continue

        fg, bg = SEV_COLOR.get(sev, (C["muted"], C["row_alt"]))

        if pdf.will_page_break(35):
            pdf.add_page()
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*fg)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, f"  {sev.upper()}  ({len(items)} hallazgos)",
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        for j, finding in enumerate(items):
            row_bg = C["row_alt"] if j % 2 == 0 else C["row_normal"]
            if pdf.will_page_break(28):
                pdf.add_page()
            _vuln_card(pdf, finding, base_dir, row_bg)

        pdf.ln(3)


def _osint_section(pdf: APKReportPDF, osint: "OsintResult") -> None:
    """Sección OSINT: dominios, subdominios y leaks públicos."""
    pdf.add_page()

    # Título con desglose por categoría
    parts: list[str] = []
    if osint.subdomains:
        parts.append(f"{len(osint.subdomains)} subdominios")
    if osint.public_leaks:
        parts.append(f"{len(osint.public_leaks)} leaks publicos")
    summary = " · ".join(parts) if parts else "sin hallazgos"
    pdf.section_title(f"OSINT  ({summary})")

    # ── Dominios y subdominios ────────────────────────────────────────────
    if osint.domains_scanned:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["accent"])
        pdf.cell(0, 6, _safe(f"Dominios propios ({len(osint.domains_scanned)})"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])
        pdf.ln(1)
        col_w = pdf.epw  # full usable width
        for idx, dom in enumerate(osint.domains_scanned):
            bg = C["row_alt"] if idx % 2 else C["row_normal"]
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.cell(col_w, 5, _safe(dom), fill=True,
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    if osint.subdomains:
        if pdf.will_page_break(20):
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["accent"])
        pdf.cell(0, 7, _safe(f"Subdominios via crt.sh ({len(osint.subdomains)})"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])
        pdf.ln(1)

        # Destacar entornos dev/qa/staging
        dev_subs = [s for s in osint.subdomains if any(
            e in s.name for e in ("dev", "qa", "uat", "test", "staging", "pre.")
        )]
        if dev_subs:
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.set_text_color(*C["warning"])
            pdf.cell(0, 5, _safe(f"Entornos dev/qa/staging expuestos: {len(dev_subs)}"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(*C["text"])
            for s in dev_subs[:10]:
                pdf.set_font("Helvetica", "", 7)
                pdf.cell(0, 4, _safe(f"  - {s.name}"),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)

        for i, sub in enumerate(osint.subdomains[:40]):
            if pdf.will_page_break(6):
                pdf.add_page()
            bg = C["row_alt"] if i % 2 else C["row_normal"]
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(90, 4, _safe(sub.name), fill=True,
                     new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "", 6.5)
            pdf.set_text_color(*C["muted"])
            pdf.cell(0, 4, _safe(sub.first_seen[:10] if sub.first_seen else ""),
                     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(*C["text"])

        if len(osint.subdomains) > 40:
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(*C["muted"])
            pdf.cell(0, 5, _safe(f"... y {len(osint.subdomains) - 40} mas"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(*C["text"])
        pdf.ln(4)

    # ── Leaks públicos ────────────────────────────────────────────────────
    if osint.public_leaks:
        if pdf.will_page_break(20):
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["danger"])
        pdf.cell(0, 7, _safe(f"Leaks publicos ({len(osint.public_leaks)})"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])
        pdf.ln(1)

        # Table header
        w_plat = 22
        w_title = pdf.epw - w_plat - 70
        w_link = 70
        row_h = 5

        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(*C["accent"])
        pdf.set_text_color(255, 255, 255)
        pdf.cell(w_plat, row_h, "Plataforma", fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(w_title, row_h, _safe("T\u00edtulo"), fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(w_link, row_h, "Link", fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])

        for idx, leak in enumerate(osint.public_leaks):
            if pdf.will_page_break(6):
                pdf.add_page()
            bg = C["row_alt"] if idx % 2 else C["row_normal"]
            pdf.set_fill_color(*bg)

            pdf.set_font("Helvetica", "B", 6.5)
            pdf.cell(w_plat, row_h, _safe(leak.source), fill=True,
                     new_x=XPos.RIGHT, new_y=YPos.TOP)

            pdf.set_font("Helvetica", "", 6.5)
            pdf.cell(w_title, row_h, _safe(leak.title[:60]), fill=True,
                     new_x=XPos.RIGHT, new_y=YPos.TOP)

            if leak.url and not leak.url.startswith("{{"):
                pdf.set_font("Helvetica", "U", 6)
                pdf.set_text_color(*C["info"])
                pdf.cell(w_link, row_h, _safe(leak.url[:55]),
                         fill=True, link=leak.url,
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(*C["text"])
            else:
                pdf.set_font("Helvetica", "I", 6)
                pdf.set_text_color(*C["muted"])
                pdf.cell(w_link, row_h, "N/A", fill=True,
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(*C["text"])

        pdf.ln(3)

    # ── Auth flows ────────────────────────────────────────────────────────
    if osint.auth_flows:
        if pdf.will_page_break(15):
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["warning"])
        pdf.cell(0, 7, _safe(f"Auth hardcodeados ({len(osint.auth_flows)})"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C["text"])
        for af in osint.auth_flows[:10]:
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(0, 4, _safe(f"  {af['type']} - {af['file']}:{af['line']}"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _leaks_section(pdf: APKReportPDF, scan: "ScanResult") -> None:
    leaks, _ = _split_findings(scan)
    _findings_section(pdf, scan.base_dir, leaks, "Leaks", "No se encontraron leaks.")


def _vuln_section(pdf: APKReportPDF, scan: "ScanResult") -> None:
    _, vulns = _split_findings(scan)
    _findings_section(pdf, scan.base_dir, vulns, "Vulnerabilidades", "No se encontraron vulnerabilidades.")


# ── Funcion publica ───────────────────────────────────────────────────────────


def generate_pdf_report(
    result: "AnalysisResult",
    output_path: Path,
    scan: "ScanResult | None" = None,
    manifest: "ManifestAnalysisResult | None" = None,
    osint: "OsintResult | None" = None,
) -> Path:
    """
    Genera un informe PDF con las secciones:
      1. Resumen (portada)
      2. Protecciones descubiertas
      3. Misconfigurations del Manifest
      4. OSINT
      5. Leaks
      6. Vulnerabilidades
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pdf = APKReportPDF(app_package=result.package, orientation="P", unit="mm", format="A4")
    pdf.set_title(f"nutcracker - {result.package}")
    pdf.set_author("nutcracker")

    # 1. Portada + Resumen
    pdf.add_page()
    _cover_page(pdf, result, scan=scan, manifest=manifest)

    # 2. Protecciones descubiertas
    _protections_section(pdf, result)

    # 3. Misconfigurations del manifest
    if manifest is not None:
        _misconfig_section(pdf, manifest)

    # 4. OSINT
    if osint is None:
        from .reporter import load_osint_json
        osint = load_osint_json(result.package)
    if osint is not None:
        _osint_section(pdf, osint)

    # 5. Leaks
    if scan is not None:
        _leaks_section(pdf, scan)

    # 6. Vulnerabilidades
    if scan is not None:
        _vuln_section(pdf, scan)

    pdf.output(str(output_path))
    return output_path


# ── Reporte batch consolidado ─────────────────────────────────────────────────

class BatchReportPDF(FPDF):
    """PDF para el reporte consolidado de batch."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*C["bg"])
        self.rect(0, 0, 210, 10, style="F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C["white"])
        self.set_y(2)
        self.cell(0, 6, "nutcracker  ·  Batch Report", align="L")
        self.set_y(2)
        self.cell(0, 6, datetime.datetime.now().strftime("%d/%m/%Y"), align="R")
        self.set_text_color(*C["text"])
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C["muted"])
        self.cell(0, 5, f"Generado el {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}  ·  https://github.com/drneox/nutcracker",
                  align="L")
        self.cell(0, 5, f"Pagina {self.page_no()}", align="R")

    def section_title(self, text: str) -> None:
        self.ln(4)
        self.set_fill_color(*C["accent"])
        self.rect(self.l_margin, self.get_y(), 3, 7, style="F")
        self.set_x(self.l_margin + 5)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*C["bg"])
        self.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)


def _batch_cover(pdf: BatchReportPDF, apps: list[dict]) -> None:
    """Portada del reporte batch."""
    # Fondo header
    pdf.set_fill_color(*C["bg"])
    pdf.rect(0, 0, 210, 100, style="F")

    # Título
    pdf.set_y(30)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*C["white"])
    pdf.cell(0, 10, "Evaluacion de Seguridad", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*C["accent"])
    pdf.cell(0, 8, "Portafolio de Aplicaciones", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Línea decorativa
    pdf.set_draw_color(*C["accent"])
    pdf.set_line_width(0.8)
    cx = 105
    pdf.line(cx - 30, pdf.get_y() + 4, cx + 30, pdf.get_y() + 4)
    pdf.ln(12)

    # Fecha
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(180, 190, 210)
    pdf.cell(0, 6, datetime.datetime.now().strftime("%d de %B de %Y"), align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Stats
    pdf.set_y(108)
    ok = [a for a in apps if "error" not in a.get("status", "")]
    errors = [a for a in apps if "error" in a.get("status", "")]
    broken = [a for a in ok if a.get("status") == "protected_broken"]
    unprotected = [a for a in ok if a.get("status") == "unprotected"]

    total_critical = sum(a.get("critical", 0) for a in ok)
    total_high = sum(a.get("high", 0) for a in ok)
    total_findings = sum(a.get("findings", 0) for a in ok)

    stats = [
        ("Apps evaluadas",     str(len(apps)),       C["accent"]),
        ("Exitosas",           str(len(ok)),          C["success"]),
        ("Errores",            str(len(errors)),      C["danger"] if errors else C["muted"]),
        ("Sin proteccion",     str(len(unprotected)), C["warning"] if unprotected else C["success"]),
        ("Proteccion rota",    str(len(broken)),      C["danger"] if broken else C["success"]),
        ("Hallazgos totales",  str(total_findings),   C["info"]),
        ("Criticos + Altos",   f"{total_critical} + {total_high}", C["danger"] if total_critical else C["warning"]),
    ]

    for label, value, color in stats:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*C["muted"])
        pdf.cell(90, 6, _safe(label), align="R")
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*color)
        pdf.cell(0, 6, f"  {value}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _batch_summary_table(pdf: BatchReportPDF, apps: list[dict]) -> None:
    """Tabla resumen con todas las apps."""
    pdf.add_page()
    pdf.section_title("Resumen Ejecutivo")

    # Separar exitosas y errores
    ok = [a for a in apps if "error" not in a.get("status", "")]
    errors = [a for a in apps if "error" in a.get("status", "")]

    # Ordenar por riesgo: critical desc, high desc, findings desc
    ok.sort(key=lambda a: (a.get("critical", 0), a.get("high", 0), a.get("findings", 0)), reverse=True)

    if ok:
        # Header de tabla
        col_w = [62, 22, 14, 14, 14, 14, 14, 20]  # package, estado, C, H, M, L, leaks, total
        headers = ["Aplicacion", "Estado", "C", "H", "M", "L", "Leaks", "Total"]

        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(*C["bg"])
        pdf.set_text_color(*C["white"])
        for i, h in enumerate(headers):
            pdf.cell(col_w[i], 6, h, border=0, fill=True, align="C" if i > 0 else "L")
        pdf.ln()

        # Filas
        for idx, a in enumerate(ok):
            if pdf.get_y() > 265:
                pdf.add_page()

            bg = C["row_alt"] if idx % 2 else C["row_normal"]
            pdf.set_fill_color(*bg)

            # Package
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C["text"])
            pkg_display = a.get("package", a.get("target", "?"))
            if len(pkg_display) > 38:
                pkg_display = pkg_display[:36] + ".."
            pdf.cell(col_w[0], 5, _safe(pkg_display), fill=True)

            # Estado
            status = a.get("status", "?")
            status_labels = {
                "protected": "Protegida",
                "unprotected": "Expuesta",
                "protected_broken": "Bypass OK",
            }
            status_colors = {
                "protected": C["success"],
                "unprotected": C["danger"],
                "protected_broken": C["warning"],
            }
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*status_colors.get(status, C["muted"]))
            pdf.cell(col_w[1], 5, status_labels.get(status, status), fill=True, align="C")

            # Severity counts
            for i, key in enumerate(["critical", "high", "medium", "low"]):
                val = a.get(key, 0)
                if val > 0:
                    sev_fg, _ = SEV_COLOR.get(key, (C["muted"], C["info_bg"]))
                    pdf.set_text_color(*sev_fg)
                    pdf.set_font("Helvetica", "B", 7)
                else:
                    pdf.set_text_color(*C["muted"])
                    pdf.set_font("Helvetica", "", 7)
                pdf.cell(col_w[2 + i], 5, str(val), fill=True, align="C")

            # Leaks
            leaks = a.get("leaks", 0)
            pdf.set_text_color(*(C["danger"] if leaks else C["muted"]))
            pdf.set_font("Helvetica", "B" if leaks else "", 7)
            pdf.cell(col_w[6], 5, str(leaks), fill=True, align="C")

            # Total
            total = a.get("findings", 0)
            pdf.set_text_color(*C["text"])
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(col_w[7], 5, str(total), fill=True, align="C")
            pdf.ln()

    # Errores al final
    if errors:
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["danger"])
        pdf.cell(0, 6, f"Apps con error ({len(errors)})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C["text"])
        for e in errors:
            if pdf.get_y() > 275:
                pdf.add_page()
            target = e.get("target", "?")
            err_msg = e.get("error", "desconocido")[:80]
            pdf.cell(0, 4, _safe(f"  - {target}: {err_msg}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _batch_common_findings(pdf: BatchReportPDF, apps: list[dict]) -> None:
    """Hallazgos comunes — vulnerabilidades que aparecen en múltiples apps."""
    ok = [a for a in apps if "error" not in a.get("status", "")]
    if not ok:
        return

    # Agrupar por rule_id
    rule_count: dict[str, dict] = {}
    for a in ok:
        for rule_id, title, sev in a.get("top_findings", []):
            if rule_id not in rule_count:
                rule_count[rule_id] = {"title": title, "severity": sev, "apps": set()}
            rule_count[rule_id]["apps"].add(a.get("package", "?"))

    # Solo mostrar los que aparecen en >1 app
    common = {k: v for k, v in rule_count.items() if len(v["apps"]) > 1}
    if not common:
        return

    pdf.add_page()
    pdf.section_title("Hallazgos Comunes")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*C["muted"])
    pdf.cell(0, 5, _safe("Vulnerabilidades que se repiten en multiples aplicaciones"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Ordenar por cantidad de apps afectadas desc
    sorted_common = sorted(common.items(), key=lambda x: len(x[1]["apps"]), reverse=True)

    col_w = [20, 80, 18, 56]  # rule_id, title, severity, apps count + names
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_fill_color(*C["bg"])
    pdf.set_text_color(*C["white"])
    for i, h in enumerate(["Regla", "Hallazgo", "Severidad", "Apps afectadas"]):
        pdf.cell(col_w[i], 6, h, fill=True, align="C" if i > 1 else "L")
    pdf.ln()

    for idx, (rule_id, info) in enumerate(sorted_common):
        if pdf.get_y() > 270:
            pdf.add_page()

        bg = C["row_alt"] if idx % 2 else C["row_normal"]
        pdf.set_fill_color(*bg)

        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*C["text"])
        pdf.cell(col_w[0], 5, _safe(rule_id), fill=True)

        pdf.set_font("Helvetica", "", 7)
        title_text = info["title"][:50]
        pdf.cell(col_w[1], 5, _safe(title_text), fill=True)

        sev = info["severity"]
        sev_fg, _ = SEV_COLOR.get(sev, (C["muted"], C["info_bg"]))
        pdf.set_text_color(*sev_fg)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(col_w[2], 5, sev.upper(), fill=True, align="C")

        pdf.set_text_color(*C["text"])
        pdf.set_font("Helvetica", "", 7)
        apps_text = f"{len(info['apps'])} apps"
        pdf.cell(col_w[3], 5, apps_text, fill=True, align="C")
        pdf.ln()


def _batch_app_cards(pdf: BatchReportPDF, apps: list[dict]) -> None:
    """Mini-ficha de cada app (resumida)."""
    ok = [a for a in apps if "error" not in a.get("status", "")]
    if not ok:
        return

    # Ordenar por riesgo
    ok.sort(key=lambda a: (a.get("critical", 0), a.get("high", 0), a.get("findings", 0)), reverse=True)

    pdf.add_page()
    pdf.section_title("Detalle por Aplicacion")

    for a in ok:
        if pdf.get_y() > 240:
            pdf.add_page()

        pkg = a.get("package", "?")
        status = a.get("status", "?")
        critical = a.get("critical", 0)
        high = a.get("high", 0)
        medium = a.get("medium", 0)
        low = a.get("low", 0)
        leaks = a.get("leaks", 0)
        total = a.get("findings", 0)

        # Card background
        pdf.set_fill_color(248, 250, 252)
        y_start = pdf.get_y()
        pdf.rect(pdf.l_margin, y_start, 174, 22, style="F")

        # Accent bar izquierda según riesgo
        if critical > 0:
            bar_color = C["danger"]
        elif high > 0:
            bar_color = C["warning"]
        elif total > 0:
            bar_color = C["info"]
        else:
            bar_color = C["success"]
        pdf.set_fill_color(*bar_color)
        pdf.rect(pdf.l_margin, y_start, 2.5, 22, style="F")

        # Package name
        pdf.set_x(pdf.l_margin + 5)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C["bg"])
        pdf.cell(100, 5, _safe(pkg), new_y=YPos.TOP)

        # Status badge
        status_labels = {
            "protected": "Protegida",
            "unprotected": "Expuesta",
            "protected_broken": "Bypass OK",
        }
        status_colors = {
            "protected": C["success"],
            "unprotected": C["danger"],
            "protected_broken": C["warning"],
        }
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*status_colors.get(status, C["muted"]))
        pdf.cell(0, 5, status_labels.get(status, status), align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Línea de hallazgos
        pdf.set_x(pdf.l_margin + 5)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C["muted"])
        parts = []
        if critical:
            parts.append(f"{critical} criticos")
        if high:
            parts.append(f"{high} altos")
        if medium:
            parts.append(f"{medium} medios")
        if low:
            parts.append(f"{low} bajos")
        if leaks:
            parts.append(f"{leaks} leaks")
        summary = " · ".join(parts) if parts else "Sin hallazgos"
        pdf.cell(0, 4, _safe(summary), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Top findings
        top = a.get("top_findings", [])
        if top:
            pdf.set_x(pdf.l_margin + 5)
            pdf.set_font("Helvetica", "", 6)
            top_display = top[:3]  # Max 3 para la card
            for rule_id, title, sev in top_display:
                sev_fg, _ = SEV_COLOR.get(sev, (C["muted"], C["info_bg"]))
                pdf.set_text_color(*sev_fg)
                line_text = f"[{sev.upper()}] {rule_id}: {title}"[:70]
                pdf.cell(0, 3.5, _safe(line_text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_x(pdf.l_margin + 5)

        pdf.set_y(y_start + 24)


def _batch_comparative_table(pdf: BatchReportPDF, apps: list[dict]) -> None:
    """Tabla comparativa de estado de protección de todas las apps."""
    ok = [a for a in apps if "error" not in a.get("status", "")]
    if not ok:
        return

    # Agrupar por estado
    groups: dict[str, list[dict]] = {
        "unprotected": [],
        "protected_broken": [],
        "protected": [],
    }
    for a in ok:
        s = a.get("status", "")
        if s in groups:
            groups[s].append(a)

    pdf.add_page()
    pdf.section_title("Tabla Comparativa — Estado de Proteccion")

    # Resumen visual con barras
    total = len(ok)
    bar_w = 174  # ancho disponible
    bar_y = pdf.get_y()
    bar_h = 10

    status_meta = [
        ("unprotected",      "Sin proteccion",    C["danger"]),
        ("protected_broken", "Proteccion rota",   C["warning"]),
        ("protected",        "Con proteccion",    C["success"]),
    ]

    # Barra proporcional
    x = pdf.l_margin
    for key, _label, color in status_meta:
        count = len(groups[key])
        if count == 0:
            continue
        w = max(bar_w * count / total, 8)  # mínimo visible
        pdf.set_fill_color(*color)
        pdf.rect(x, bar_y, w, bar_h, style="F")
        # Número centrado en la barra
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C["white"])
        pdf.set_xy(x, bar_y + 1)
        pdf.cell(w, bar_h - 2, str(count), align="C")
        x += w

    pdf.set_y(bar_y + bar_h + 3)

    # Leyenda de la barra
    pdf.set_font("Helvetica", "", 7)
    for key, label, color in status_meta:
        count = len(groups[key])
        pdf.set_fill_color(*color)
        pdf.rect(pdf.get_x(), pdf.get_y() + 1, 3, 3, style="F")
        pdf.set_x(pdf.get_x() + 5)
        pdf.set_text_color(*C["text"])
        pct = f"{count * 100 // total}%" if total else "0%"
        pdf.cell(50, 5, _safe(f"{label}: {count} ({pct})"))
    pdf.ln(10)

    # Tabla detallada por grupo
    col_w = [70, 28, 16, 16, 16, 16, 12]
    headers = ["Aplicacion", "Proteccion", "C", "H", "M", "L", "Total"]

    for key, group_label, color in status_meta:
        apps_in_group = groups[key]
        if not apps_in_group:
            continue

        # Ordenar por hallazgos desc
        apps_in_group.sort(key=lambda a: a.get("findings", 0), reverse=True)

        if pdf.get_y() > 240:
            pdf.add_page()

        # Título del grupo
        pdf.ln(2)
        pdf.set_fill_color(*color)
        pdf.rect(pdf.l_margin, pdf.get_y(), 3, 6, style="F")
        pdf.set_x(pdf.l_margin + 5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*color)
        pdf.cell(0, 6, _safe(f"{group_label} ({len(apps_in_group)})"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        # Header de tabla
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(*C["bg"])
        pdf.set_text_color(*C["white"])
        for i, h in enumerate(headers):
            pdf.cell(col_w[i], 6, h, fill=True, align="C" if i > 0 else "L")
        pdf.ln()

        # Filas
        for idx, a in enumerate(apps_in_group):
            if pdf.get_y() > 270:
                pdf.add_page()

            bg = C["row_alt"] if idx % 2 else C["row_normal"]
            pdf.set_fill_color(*bg)

            # Package
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C["text"])
            pkg = a.get("package", a.get("target", "?"))
            if len(pkg) > 42:
                pkg = pkg[:40] + ".."
            pdf.cell(col_w[0], 5, _safe(pkg), fill=True)

            # Estado
            status_short = {
                "unprotected": "Sin proteccion",
                "protected_broken": "Bypass logrado",
                "protected": "Protegida",
            }
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*color)
            pdf.cell(col_w[1], 5, status_short.get(key, "?"), fill=True, align="C")

            # Severity counts
            for i, sev_key in enumerate(["critical", "high", "medium", "low"]):
                val = a.get(sev_key, 0)
                if val > 0:
                    sev_fg, _ = SEV_COLOR.get(sev_key, (C["muted"], C["info_bg"]))
                    pdf.set_text_color(*sev_fg)
                    pdf.set_font("Helvetica", "B", 7)
                else:
                    pdf.set_text_color(*C["muted"])
                    pdf.set_font("Helvetica", "", 7)
                pdf.cell(col_w[2 + i], 5, str(val), fill=True, align="C")

            # Total
            pdf.set_text_color(*C["text"])
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(col_w[6], 5, str(a.get("findings", 0)), fill=True, align="C")
            pdf.ln()


def generate_batch_report(
    apps: list[dict],
    output_path: Path,
) -> Path:
    """
    Genera un PDF consolidado con el resumen de todas las apps del batch.

    Cada dict en `apps` debe tener:
      - target: str
      - package: str (si exitoso)
      - status: "protected"|"unprotected"|"protected_broken"|"error_*"
      - findings: int (total de hallazgos)
      - critical, high, medium, low: int (conteos por severidad)
      - leaks: int
      - top_findings: list[tuple[rule_id, title, severity]]  (top 5 hallazgos)
      - error: str (si hubo error)
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pdf = BatchReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_title("nutcracker - Batch Report")
    pdf.set_author("nutcracker")

    # 1. Portada
    pdf.add_page()
    _batch_cover(pdf, apps)

    # 2. Tabla resumen ejecutivo
    _batch_summary_table(pdf, apps)

    # 3. Tabla comparativa OWASP
    _batch_comparative_table(pdf, apps)

    # 4. Hallazgos comunes
    _batch_common_findings(pdf, apps)

    # 5. Detalle por app
    _batch_app_cards(pdf, apps)

    pdf.output(str(output_path))
    return output_path
