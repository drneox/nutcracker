"""Comando `nutcracker regen-pdf`: regenera el PDF de un paquete desde su JSON guardado."""

from __future__ import annotations

from pathlib import Path

import click

from nutcracker_core.i18n import t
from nutcracker_core import orchestrator as orch
from nutcracker_core.orchestrator import console

from . import cli


@cli.command("regen-pdf")
@click.argument("package")
def regen_pdf(package: str) -> None:
    """Regenerate the PDF for a package from its saved JSON in reports/.

    PACKAGE is the package name, e.g.: com.example.myapp
    """
    result = orch._load_analysis_json(package)
    if result is None:
        console.print(f"[red]{t('cli_regen_pdf_not_found', package=package)}[/red]")
        raise SystemExit(1)
    console.print(f"[dim]{t('cli_regen_pdf_loaded', package=result.package, analyzed_at=result.analyzed_at)}[/dim]")

    # Cargar vuln scan si existe
    vuln_scan = orch._load_vuln_json(package)
    if vuln_scan is not None:
        console.print(f"[dim]{t('cli_regen_pdf_findings', count=len(vuln_scan.findings))}[/dim]")

    # Cargar manifest si existe
    manifest = None
    try:
        from nutcracker_core.manifest_analyzer import analyze_decompiled_dir as _addir
        # Detectar directorio decompilado disponible
        for candidate in [
            Path("./decompiled") / f"runtime_dump_{package}" / "source",
            Path("./decompiled") / package,
        ]:
            if candidate.exists():
                # Buscar APK para fallback de manifest (runtime dump no tiene manifest)
                apk_dir = Path("./downloads") / package
                _apk = next(iter(sorted(apk_dir.glob(f"{package}.apk"))), None) if apk_dir.exists() else None
                if _apk is None and apk_dir.exists():
                    _apk = next(iter(sorted(apk_dir.glob("*.apk"))), None)
                manifest = _addir(candidate, apk_path=_apk)
                console.print(f"[dim]{t('cli_manifest_loaded', path=candidate)}[/dim]")
                break
    except Exception:  # noqa: BLE001
        pass

    orch._MANIFEST_ANALYSIS = manifest

    # Cargar OSINT si existe
    orch._OSINT_RESULT = None
    # Nueva ubicación: reports/<package>/osint.json
    # Fallback: reports/osint_<package>.json (formato legacy)
    osint_path = Path("./reports") / package / "osint.json"
    if not osint_path.exists():
        osint_path = Path("./reports") / f"osint_{package}.json"
    if osint_path.exists():
        try:
            import json as _json
            from nutcracker_core.osint import OsintResult, PublicLeak, Secret, Subdomain
            raw = _json.loads(osint_path.read_text(encoding="utf-8"))
            orch._OSINT_RESULT = OsintResult(
                package=raw.get("package", package),
                secrets=[
                    Secret(name=s["name"], value=s["value"], file=s.get("file", ""),
                           line=s.get("line", 0), service=s.get("service", ""))
                    for s in raw.get("secrets", [])
                ],
                subdomains=[
                    Subdomain(name=s["name"], first_seen=s.get("first_seen", ""),
                              is_wildcard=s.get("is_wildcard", False))
                    for s in raw.get("subdomains", [])
                ],
                public_leaks=[
                    PublicLeak(source=l["source"], query=l.get("query", ""),
                               url=l.get("url", ""), title=l.get("title", ""),
                               snippet=l.get("snippet", ""), vulns=l.get("vulns", []),
                               vulns_cvss=l.get("vulns_cvss", {}))
                    for l in raw.get("public_leaks", [])
                ],
                domains_scanned=raw.get("domains_scanned", []),
                auth_flows=raw.get("auth_flows", []),
            )
            console.print(f"[dim]{t('cli_osint_loaded', path=osint_path)}[/dim]")
        except Exception:  # noqa: BLE001
            pass

    _vuln_enabled = orch._feature_enabled("sast_scan", default=True)
    orch._generate_pdf(result, vuln_scan, vuln_scan_enabled=_vuln_enabled)
