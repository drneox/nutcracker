"""Tests de nutcracker_core/detectors/certificate_pinning.py.

Bug encontrado en vivo (job 2822/sh.nutcracker.nutbank, 2026-08-04): la app
tiene un método dummy `NetworkClient.disableCertificatePinning()` que solo
loguea (usa `HttpsURLConnection`, no OkHttp de verdad para pinning), pero el
detector marcaba `detected=True` de todos modos -- porque la clase
`okhttp3.CertificatePinner` está en el classpath (dependencia transitiva de
OkHttp) y el detector solo miraba si el NOMBRE de la clase existía en el APK,
sin verificar si había evidencia de un pin real configurado. El agente LLM
de aipwn perdió ~3 iteraciones descartando este falso positivo a mano.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from nutcracker_core.detectors.certificate_pinning import CertificatePinningDetector


def _apk_no_xml_matches():
    apk = MagicMock()
    apk.get_files.return_value = []
    return apk


def test_okhttp_certificate_pinner_class_alone_is_not_detected():
    """El caso real del job 2822: la clase okhttp3.CertificatePinner está
    presente (dependencia transitiva de OkHttp) pero no hay ningún hash de
    pin real -- no debe marcarse como pinning detectado."""
    detector = CertificatePinningDetector()
    all_classes = {"Lokhttp3/CertificatePinner;", "Lsh/nutcracker/nutbank/NetworkClient;"}
    all_strings = {"some unrelated string", "https://api.nutcracker.sh"}

    result = detector.detect(_apk_no_xml_matches(), None, all_strings, all_classes)

    assert result.detected is False
    assert result.details == []


def test_okhttp_certificate_pinner_with_real_pin_hash_is_detected():
    """Si la clase okhttp3.CertificatePinner SÍ viene acompañada de un hash
    de pin real (sha256/...), ahí sí es evidencia genuina."""
    detector = CertificatePinningDetector()
    all_classes = {"Lokhttp3/CertificatePinner;"}
    all_strings = {"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}

    result = detector.detect(_apk_no_xml_matches(), None, all_strings, all_classes)

    assert result.detected is True
    assert any("CertificatePinner" in d for d in result.details)
    assert any("sha256" in d for d in result.details)


def test_trustkit_class_alone_is_detected_without_needing_pin_hash():
    """TrustKit (y los demás indicadores "fuertes") son evidencia suficiente
    por sí solos -- a diferencia de okhttp3.CertificatePinner, no son clases
    que aparezcan por casualidad como dependencia transitiva."""
    detector = CertificatePinningDetector()
    all_classes = {"Lcom/datatheorem/android/trustkit/TrustKit;"}
    all_strings = {"nothing relevant here"}

    result = detector.detect(_apk_no_xml_matches(), None, all_strings, all_classes)

    assert result.detected is True
    assert any("TrustKit" in d for d in result.details)


def test_network_security_config_pin_set_is_detected():
    apk = MagicMock()
    apk.get_files.return_value = ["res/xml/network_security_config.xml"]
    apk.get_file.return_value = b"<network-security-config><pin-set>...</pin-set></network-security-config>"

    detector = CertificatePinningDetector()
    result = detector.detect(apk, None, set(), set())

    assert result.detected is True
    assert any("NSC" in d for d in result.details)


def test_nsc_pin_set_also_makes_ambiguous_class_indicator_count():
    """Si el hash real vino de la Network Security Config (no de un string
    suelto), el indicador ambiguo de OkHttp también debe contar."""
    apk = MagicMock()
    apk.get_files.return_value = ["res/xml/network_security_config.xml"]
    apk.get_file.return_value = b"<network-security-config><pin-set>sha256/xxx</pin-set></network-security-config>"

    detector = CertificatePinningDetector()
    all_classes = {"Lokhttp3/CertificatePinner;"}

    result = detector.detect(apk, None, set(), all_classes)

    assert result.detected is True
    assert any("CertificatePinner" in d for d in result.details)
    assert any("NSC" in d for d in result.details)


def test_no_evidence_at_all_is_not_detected():
    detector = CertificatePinningDetector()
    result = detector.detect(_apk_no_xml_matches(), None, {"hello"}, {"Lcom/example/Foo;"})

    assert result.detected is False
    assert result.details == []


def test_details_capped_at_eight():
    """El cap es por RESULTADO final, no por indicador -- cada indicador solo
    aporta como máximo una entrada (primer match), así que hace falta
    suficiente variedad de indicadores distintos para superar el tope de 8."""
    detector = CertificatePinningDetector()
    all_classes = {
        "Lcom/datatheorem/android/trustkit/TrustKit;",
        "Lcom/example/TrustKitConfiguration;",
        "Lcom/example/PinningTrustManager;",
        "Lcom/example/PublicKeyPinning;",
        "Lcom/example/CustomCertificatePin;",
        "Lokhttp3/CertificatePinner;",
    }
    all_strings = {
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "sha1/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "<pin-set expiration=...",
        "trustkit config key here",
        "kTSKPublicKeyHashes",
        "kTSKEnforcePinning",
    }

    result = detector.detect(_apk_no_xml_matches(), None, all_strings, all_classes)

    assert len(result.details) <= 8
