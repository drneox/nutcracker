#!/usr/bin/env python3
"""Genera docs/owasp-mas-coverage.md desde el registry de checks (Fase 2.3 del
plan): matriz MASVS × MASWE × CWE cubierta / pendiente por nutcracker.

Uso:
    python tools/gen_owasp_coverage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nutcracker_core import checks
from nutcracker_core.masvs import MASVS_CONTROLS, MASWE_CATALOG

OUTPUT_PATH = Path(__file__).parent.parent / "docs" / "owasp-mas-coverage.md"


def main() -> None:
    checks.load_registry()
    all_checks = checks.all_checks()

    # control_id -> lista de checks que lo cubren
    by_control: dict[str, list] = {cid: [] for cid in MASVS_CONTROLS}
    maswe_covered: set[str] = set()
    for check in all_checks:
        for cid in check.meta.masvs:
            by_control.setdefault(cid, []).append(check)
        maswe_covered.update(check.meta.maswe)

    covered_controls = sorted(cid for cid, checks_ in by_control.items() if checks_)
    uncovered_controls = sorted(cid for cid in MASVS_CONTROLS if not by_control.get(cid))

    lines: list[str] = []
    lines.append("# Cobertura OWASP MAS de nutcracker")
    lines.append("")
    lines.append(
        "Generado automáticamente por `tools/gen_owasp_coverage.py` desde "
        "`nutcracker_core/checks/` (Fase 2 del plan). No editar a mano — "
        "regenerar tras cambios en `masvs.py` o en los checks."
    )
    lines.append("")
    lines.append(
        f"**Resumen:** {len(covered_controls)}/{len(MASVS_CONTROLS)} controles MASVS v2.1 "
        f"con al menos un check · {len(all_checks)} checks totales "
        f"({len(checks.static_checks())} estáticos, {len(checks.dynamic_checks())} dinámicos) · "
        f"{len(maswe_covered)}/{len(MASWE_CATALOG)} debilidades MASWE referenciadas."
    )
    lines.append("")

    lines.append("## Cobertura por control MASVS")
    lines.append("")
    lines.append("| Control | Descripción | Checks | MASWE |")
    lines.append("|---|---|---|---|")
    for cid, desc in MASVS_CONTROLS.items():
        checks_for_ctrl = by_control.get(cid, [])
        check_ids = ", ".join(f"`{c.meta.id}`" for c in checks_for_ctrl) or "—"
        maswe_ids = sorted({m for c in checks_for_ctrl for m in c.meta.maswe})
        maswe_str = ", ".join(maswe_ids) or "—"
        lines.append(f"| `{cid}` | {desc} | {check_ids} | {maswe_str} |")
    lines.append("")

    lines.append("## Controles sin cobertura hoy (gap honesto, no una promesa)")
    lines.append("")
    if uncovered_controls:
        for cid in uncovered_controls:
            lines.append(f"- `{cid}` — {MASVS_CONTROLS[cid]}")
    else:
        lines.append("(ninguno)")
    lines.append("")

    lines.append("## Checks registrados")
    lines.append("")
    lines.append("| ID | Kind | Fuente | Severidad | MASVS | MASWE | CWE |")
    lines.append("|---|---|---|---|---|---|---|")
    for c in sorted(all_checks, key=lambda c: (c.meta.kind, c.meta.source, c.meta.id)):
        masvs_str = ", ".join(c.meta.masvs) or "—"
        maswe_str = ", ".join(c.meta.maswe) or "—"
        cwe_str = ", ".join(c.meta.cwe) or "—"
        lines.append(
            f"| `{c.meta.id}` | {c.meta.kind} | {c.meta.source} | {c.meta.severity} "
            f"| {masvs_str} | {maswe_str} | {cwe_str} |"
        )
    lines.append("")

    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"✔ Escrito {OUTPUT_PATH} ({len(covered_controls)}/{len(MASVS_CONTROLS)} controles cubiertos)")


if __name__ == "__main__":
    main()
