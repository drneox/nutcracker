"""Regresión: generate_batch_report() crasheaba con FPDFUnicodeEncodingException
al renderizar 'Comparative Table — Protection Status' (em-dash \\u2014, fuente
Helvetica no-Unicode) — encontrado corriendo `nutcracker batch` real contra
hardware (2026-07-25), no relacionado con la migración de batch.py al motor
de cola, pero bloqueaba su paso final (el PDF consolidado)."""

from __future__ import annotations

from nutcracker_core.pdf_reporter import generate_batch_report


def test_generate_batch_report_does_not_crash_on_unicode_font_encoding(tmp_path):
    apps = [
        {
            "target": "com.example.one", "package": "com.example.one",
            "status": "protected", "findings": 2,
            "critical": 0, "high": 1, "medium": 1, "low": 0,
            "leaks": 0, "top_findings": [("HC001", "API key", "high")],
            "categories": {"M1": "high"},
        },
        {
            "target": "com.example.two", "package": "com.example.two",
            "status": "unprotected", "findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "leaks": 0, "top_findings": [], "categories": {},
        },
    ]
    out = generate_batch_report(apps, tmp_path / "batch_report.pdf")
    assert out.exists()
    assert out.stat().st_size > 0
