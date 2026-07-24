"""Grupo Click principal de nutcracker.

Los comandos viven en módulos separados (scan.py, analyze.py, launch.py,
setup_token.py, batch.py, regen_pdf.py) que se registran sobre el grupo
``cli`` definido aquí. La orquestación real (helpers compartidos, estado de
sesión) vive en ``nutcracker_core.orchestrator`` — CLI, daemon y dashboard la
reusan sin duplicar lógica (Fase 0.2 del plan).
"""

from __future__ import annotations

import click

from nutcracker_core import __version__ as _VERSION
from nutcracker_core.plugins import load_plugins
from nutcracker_core.store import install_persistence


def _print_banner() -> None:
    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
    from rich.console import Group

    from nutcracker_core.orchestrator import console

    # ── Mapa de colores ───────────────────────────────────────────────────
    _COLORS = {
        ".": None,
        "G": "#444444",   # gris oscuro (sombrero)
        "Y": "#FFD700",   # dorado (hombreras)
        "K": "#2A2A2A",   # cara
        "W": "#EEEEEE",   # blanco
        "r": "#FF1111",   # ojos rojos
        "B": "#996633",   # barba
        "L": "#555555",   # contorno
    }
    _SPECIAL_CHARS = {"S": ("★", "#44CC44")}

    _PIXELS = [
        "......GGGG......",
        ".....GGGGGG.....",
        ".....GGGGGG.....",
        ".....GGGSGG.....",
        ".....GGGGGG.....",
        "...WLKKKKKKLW...",
        "...WLrrKKrrLW...",
        "...WWWWWWWWWW...",
        "...WLWKKKKWLW...",
        "...WLBBBBBBLW...",
        "YYY.LBBBBBBL.YYY",
        ".YY..LBBBBL..YY.",
        ".....LBBBBL.....",
        "......LBBL......",
    ]

    w = len(_PIXELS[0])
    lines: list[Text] = []
    for y in range(0, len(_PIXELS), 2):
        top, bot = _PIXELS[y], _PIXELS[y + 1]
        line = Text()
        for x in range(w):
            ts = _SPECIAL_CHARS.get(top[x])
            bs = _SPECIAL_CHARS.get(bot[x])
            if ts or bs:
                ch, col = ts or bs
                other = _COLORS.get(bot[x] if ts else top[x])
                line.append(ch, style=f"{col} on {other}" if other else col)
                continue
            tc = _COLORS.get(top[x])
            bc = _COLORS.get(bot[x])
            if tc is None and bc is None:
                line.append(" ")
            elif tc == bc:
                line.append("█", style=tc)
            elif tc and bc is None:
                line.append("▀", style=tc)
            elif tc is None and bc:
                line.append("▄", style=bc)
            else:
                line.append("▀", style=f"{tc} on {bc}")
        lines.append(line)

    n = len(lines)
    name_rows = [
        "╔╗╔╦ ╦╔╦╗╔═╗╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗",
        "║║║║ ║ ║ ║  ╠╦╝╠═╣║  ╠╩╗║╣ ╠╦╝",
        "╝╚╝╚═╝ ╩ ╚═╝╩╚═╩ ╩╚═╝╩ ╩╚═╝╩╚═",
    ]

    right: list[Text | None] = [None] * n
    for i, row in enumerate(name_rows):
        rt = Text()
        rt.append(row, style="bold red")
        right[1 + i] = rt

    tag = Text()
    tag.append("★ ", style="bold green")
    tag.append("Mobile Security & Offensive Threat Intelligence", style="bold white")
    tag.append(" ★", style="bold green")
    right[min(4, n - 1)] = tag

    ver = Text()
    ver.append(f"v{_VERSION}", style="dim green")
    ver.append(" · ", style="dim")
    ver.append("nutcracker.sh", style="dim red link https://nutcracker.sh")
    right[min(5, n - 1)] = ver

    combined = Text()
    gap = "   "
    for i, sl in enumerate(lines):
        combined.append_text(sl)
        combined.append(gap)
        if right[i] is not None:
            combined.append_text(right[i])
        combined.append("\n")

    content = Align.center(combined)
    console.print(Panel(content, border_style="red", padding=(1, 2)))
    console.print()


# ── Grupo de comandos ──────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option("0.1.0", prog_name="nutcracker")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """nutcracker: detects anti-root protections in Android applications (APK)."""
    _print_banner()
    if ctx.invoked_subcommand is None:
        click.echo("usage: python nutcracker.py scan 'https://play.google.com/store/apps/details?id=...'")
        ctx.exit(0)


# Importar los módulos de comando registra cada @cli.command() sobre este grupo.
from . import scan as _scan  # noqa: E402,F401
from . import analyze as _analyze  # noqa: E402,F401
from . import launch as _launch  # noqa: E402,F401
from . import setup_token as _setup_token  # noqa: E402,F401
from . import batch as _batch  # noqa: E402,F401
from . import regen_pdf as _regen_pdf  # noqa: E402,F401
from . import queue_cmd as _queue_cmd  # noqa: E402,F401  — Fase 1: `nutcracker queue add|ls`
from . import schedule_cmd as _schedule_cmd  # noqa: E402,F401  — Fase 1: `nutcracker schedule set|ls`
from . import serve as _serve  # noqa: E402,F401  — Fase 1: `nutcracker serve` (daemon cola+scheduler)

install_persistence()
load_plugins(cli)
