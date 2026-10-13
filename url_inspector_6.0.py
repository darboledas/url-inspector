#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URL Inspector 6.0

Ejemplos:
  python url_inspector_6.0.py URL
  python url_inspector_6.0.py URL --full
  python url_inspector_6.0.py URL --full --json informe.json --html informe.html --pdf-executive ejecutivo.pdf --pdf-forensic forense.pdf
  python url_inspector_6.0.py URL --screenshot evidencia.png
  python url_inspector_6.0.py URL --full --no-screenshot
  python url_inspector_6.0.py URL --brands-file dominios_referencia.txt

Novedades 6.0:
- Typosquatting: distancia de Levenshtein frente a una lista prioritaria y,
  cuando está disponible, 5.000 dominios populares de referencia.
- Homoglifos Unicode/Punycode y detección básica de mezcla de escrituras.
- TLS: clasificación DV/OV/EV/IV cuando el certificado aporta evidencia
  suficiente, OID de políticas y edad del certificado.
- Reputación: URLhaus, PhishStats, OpenPhish Community, PhishTank, Google Safe Browsing,
  AbuseIPDB y VirusTotal enriquecido (URL, dominio, IP, ASN y popularidad).
- PhishStats se integra como reputación externa y no modifica la puntuación
  heurística calibrada. Desde 1.15.1, los registros históricos de baja confianza
  se muestran como antecedente y no como alerta negativa actual por sí solos.
- Veredicto operativo separado del score heurístico y cobertura reputacional
  independiente de la cobertura técnica. Las coincidencias reputacionales
  negativas se resaltan de forma prioritaria en consola, HTML y PDF.
- Captura PNG opcional mediante Chrome/Edge/Chromium headless como evidencia visual.
- Protección SSRF: bloqueo de localhost/redes privadas/link-local/reservadas,
  validación de cada redirección y fijación DNS a IP públicas validadas frente a DNS rebinding.
- Desde 1.15.2, la verificación del peer es adicional y no depende de detalles internos
  de requests/urllib3; la defensa primaria contra rebinding es el DNS fijado por conexión.
- Desde 1.16, el proyecto incorpora una suite automática offline y CI para detectar
  regresiones de seguridad, reputación, scoring y benchmark sin visitar URLs objetivo.
- Exportación JSON, HTML autocontenido, PDF ejecutivo y PDF forense técnico.

El modo --full añade DNS avanzado, cabeceras HTTP, HTML, CDN/proxy y
reputación. Desde el endurecimiento 1.15, la captura headless requiere
--screenshot explícito y nunca se activa automáticamente con --full.

Claves opcionales por variable de entorno:
  URLHAUS_AUTH_KEY
  PHISHSTATS_API_KEY  (opcional; la API permite cuota anónima)
  VIRUSTOTAL_API_KEY
  GOOGLE_SAFE_BROWSING_API_KEY
  ABUSEIPDB_API_KEY
  PHISHTANK_APP_KEY

ADVERTENCIA:
El programa contacta realmente con la URL analizada y con servicios externos.
Una URL potencialmente maliciosa puede ejecutar contenido activo al realizar
la captura headless. Los servicios consultados pueden registrar la IP pública
y los indicadores enviados. La puntuación es heurística y no constituye una
prueba forense concluyente.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import ssl
import sys
import html as html_lib
import shutil
import subprocess
import tempfile
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

MISSING: list[tuple[str, str]] = []

try:
    import requests
except ModuleNotFoundError:
    requests = None  # type: ignore[assignment]
    MISSING.append(("requests", "requests"))

try:
    import tldextract
except ModuleNotFoundError:
    tldextract = None  # type: ignore[assignment]
    MISSING.append(("tldextract", "tldextract"))

try:
    import dns.flags
    import dns.resolver
except ModuleNotFoundError:
    dns = None  # type: ignore[assignment]
    MISSING.append(("dns", "dnspython"))

try:
    from bs4 import BeautifulSoup
except ModuleNotFoundError:
    BeautifulSoup = None  # type: ignore[assignment]
    MISSING.append(("bs4", "beautifulsoup4"))

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ModuleNotFoundError:
    x509 = None  # type: ignore[assignment]
    NameOID = None  # type: ignore[assignment]
    hashes = serialization = ec = rsa = None  # type: ignore[assignment]
    MISSING.append(("cryptography", "cryptography"))


VERSION = "6.0"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/120.0 Safari/537.36 URL-Inspector/{VERSION}"
)
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 15
MAX_REDIRECTS = 15
MAX_HTML_BYTES = 1_048_576
SCREENSHOT_TIMEOUT = 35

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

REFERENCE_DOMAINS_URL = "https://raw.githubusercontent.com/1xyz/tranco/main/data/tranco_top_5K.txt"
OPENPHISH_COMMUNITY_FEED_URL = "https://openphish.com/feed.txt"
PHISHTANK_CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
CACHE_DIR = Path.home() / ".url_inspector_cache"
REFERENCE_CACHE_FILE = CACHE_DIR / "reference_domains_5000.txt"
OPENPHISH_CACHE_FILE = CACHE_DIR / "openphish_feed.txt"
OPENPHISH_CACHE_MAX_AGE_SECONDS = 6 * 3600
PHISHSTATS_API_URL = "https://api.phishstats.info/api/phishing"
PHISHSTATS_CACHE_FILE = CACHE_DIR / "phishstats_reputation_cache_v2.json"
PHISHSTATS_CACHE_MAX_AGE_SECONDS = 90 * 60
PHISHSTATS_OPERATIONAL_RECENT_DAYS = 90
PHISHSTATS_HIGH_CONFIDENCE_SCORE = 5.0
RDAP_BOOTSTRAP_CACHE_FILE = CACHE_DIR / "rdap_dns_bootstrap.json"
RDAP_BOOTSTRAP_CACHE_MAX_AGE_SECONDS = 7 * 86400

# Dominios de alto valor especialmente útiles para España y para marcas
# frecuentemente suplantadas. La lista dinámica de 5.000 dominios amplía esta base.
CORE_REFERENCE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "amazon.es",
    "paypal.com", "facebook.com", "instagram.com", "linkedin.com", "x.com",
    "whatsapp.com", "netflix.com", "spotify.com", "adobe.com", "dropbox.com",
    "github.com", "openai.com", "chatgpt.com", "office.com", "office365.com",
    "outlook.com", "live.com", "icloud.com", "ebay.com", "booking.com",
    "santander.com", "bbva.es", "caixabank.es", "bankinter.com", "sabadell.com",
    "ing.es", "unicajabanco.es", "kutxabank.es", "abanca.com",
    "agenciatributaria.gob.es", "agenciatributaria.es", "aeat.es",
    "seg-social.es", "clave.gob.es", "administracion.gob.es", "correos.es",
    "dgt.es", "renfe.com", "iberia.com", "telefonica.com", "movistar.es",
    "orange.es", "vodafone.es", "endesa.com", "iberdrola.es", "naturgy.es",
}

# Marcas prioritarias para detectar suplantación fuera de dominios oficiales.
# Las coincidencias se usan como indicios contextuales: una marca en una URL
# de terceros no basta por sí sola para afirmar phishing.
PRIORITY_BRANDS: dict[str, set[str]] = {
    "google": {"google.com"}, "microsoft": {"microsoft.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com", "amazon.es", "amazonaws.com"},
    "paypal": {"paypal.com"}, "facebook": {"facebook.com"},
    "instagram": {"instagram.com"}, "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"}, "netflix": {"netflix.com"},
    "spotify": {"spotify.com"}, "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"}, "github": {"github.com", "github.io"},
    "openai": {"openai.com"}, "chatgpt": {"chatgpt.com"},
    "office": {"office.com", "office365.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "icloud": {"icloud.com", "apple.com"}, "ebay": {"ebay.com"},
    "booking": {"booking.com"}, "santander": {"santander.com"},
    "bbva": {"bbva.es"}, "caixabank": {"caixabank.es"},
    "bankinter": {"bankinter.com"}, "sabadell": {"sabadell.com"},
    "unicaja": {"unicajabanco.es"}, "kutxabank": {"kutxabank.es"},
    "abanca": {"abanca.com"}, "correos": {"correos.es"},
    "renfe": {"renfe.com"}, "iberia": {"iberia.com"},
    "movistar": {"movistar.es", "telefonica.com"},
    "vodafone": {"vodafone.es", "vodafone.com"},
    "endesa": {"endesa.com"}, "iberdrola": {"iberdrola.es"},
    "naturgy": {"naturgy.es"}, "kucoin": {"kucoin.com"},
    "binance": {"binance.com"}, "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"}, "ledger": {"ledger.com"},
    "trezor": {"trezor.io"}, "docusign": {"docusign.com"},
    "onedrive": {"onedrive.com", "microsoft.com"},
    "allegro": {"allegro.pl"},
}

# Servicios de publicación/hosting multiusuario. El uso de uno de ellos no es
# malicioso; solo refuerza otras señales (marca ajena, credenciales, subdominio
# aleatorio o vocabulario de autenticación).
SHARED_HOSTING_DOMAINS = {
    "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "github.io", "r2.dev", "weebly.com", "weeblysite.com", "wixsite.com",
    "wixstudio.com", "blogspot.com", "framer.ai", "framer.app",
    "b12sites.com", "start.page", "webflow.io", "yourwebs.app",
    "4everland.app", "plesk.page", "netlify.app", "glitch.me",
    "replit.app", "carrd.co", "godaddysites.com",
}

CREDENTIAL_HINT_RE = re.compile(
    r"(?:user(?:name)?|email|e-mail|login|signin|account|password|passcode|passwd|pwd|"
    r"otp|one[-_ ]?time|pin|verification[-_ ]?code|security[-_ ]?code|token)",
    re.IGNORECASE,
)
OTP_HINT_RE = re.compile(r"(?:otp|one[-_ ]?time|pin|verification[-_ ]?code|security[-_ ]?code)", re.IGNORECASE)

# Confusables frecuentes en ataques de homógrafos. No pretende sustituir UTS #39;
# prioriza caracteres que visualmente imitan letras latinas en dominios.
CONFUSABLES = {
    "а":"a", "ɑ":"a", "α":"a", "е":"e", "ε":"e", "ё":"e", "о":"o", "ο":"o",
    "р":"p", "ρ":"p", "с":"c", "ϲ":"c", "х":"x", "χ":"x", "у":"y", "ү":"y",
    "і":"i", "ӏ":"l", "ⅼ":"l", "Ι":"i", "ј":"j", "к":"k", "κ":"k", "м":"m",
    "м":"m", "н":"h", "һ":"h", "в":"b", "Ь":"b", "ԁ":"d", "ԛ":"q", "ԝ":"w",
    "ѕ":"s", "ԍ":"g", "ո":"n", "տ":"s", "ց":"g", "０":"0", "１":"1", "５":"5",
}

CABF_POLICY_OIDS = {
    "2.23.140.1.1": "EV",
    "2.23.140.1.2.1": "DV",
    "2.23.140.1.2.2": "OV",
    "2.23.140.1.2.3": "IV",
}


SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "link", "live", "shop", "store", "site",
    "online", "icu", "buzz", "monster", "quest", "cam", "rest", "zone",
}

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "bank", "wallet", "password", "credential",
    "invoice", "payment", "parcel", "delivery", "tracking", "refund",
    "support", "auth", "session", "unlock", "kyc", "webmail", "mailbox",
    "otp", "pin", "validate", "validation", "recovery", "restore",
    "suspended", "suspension", "expired", "billing",
    "acceso", "verificar", "verificacion", "seguro", "cuenta", "actualizar",
    "confirmar", "banco", "contrasena", "contraseña", "pago", "paquete",
    "entrega", "reembolso", "factura", "facturacion", "recuperar",
    "bloqueado", "suspendido",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}

CDN_HINTS = {
    "cloudflare": "Cloudflare",
    "cloudfront": "Amazon CloudFront",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "akamaiedge": "Akamai",
    "edgesuite": "Akamai",
    "azurefd": "Azure Front Door",
    "azureedge": "Azure CDN",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "bunny": "Bunny CDN",
    "stackpath": "StackPath",
    "sucuri": "Sucuri",
    "googleusercontent": "Google Cloud CDN",
    "gvt1": "Google",
}

RANDOM_LABEL_RE = re.compile(
    r"^(?=.{10,}$)(?=.*[a-z])(?=.*\d)[a-z0-9-]+$",
    re.IGNORECASE,
)
OBFUSCATION_RE = re.compile(
    r"(eval\s*\(|unescape\s*\(|fromCharCode\s*\(|atob\s*\(|"
    r"document\.write\s*\(|\\x[0-9a-fA-F]{2}|"
    r"[A-Za-z0-9+/]{180,}={0,2})"
)


@dataclass
class RedirectStep:
    url: str
    status: int
    kind: str
    destination: str | None = None
    server: str | None = None
    blocked_reason: str | None = None


@dataclass
class TLSResult:
    available: bool
    valid: bool
    host: str
    port: int
    tls_version: str | None = None
    cipher: Any = None
    subject: str | None = None
    issuer: str | None = None
    issuer_common_name: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    certificate_age_days: int | None = None
    validation_type: str | None = None
    validation_type_basis: str | None = None
    policy_oids: list[str] = field(default_factory=list)
    subject_organization: str | None = None
    hostname_verified: bool | None = None
    trusted_ca: bool | None = None
    sans: list[Any] | None = None
    signature_algorithm: str | None = None
    public_key_type: str | None = None
    public_key_bits: int | None = None
    sha256_fingerprint: str | None = None
    ocsp_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class HTTPAnalysis:
    status_code: int | None = None
    http_version: str | None = None
    server: str | None = None
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, dict[str, Any]] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class HTMLAnalysis:
    available: bool = False
    title: str | None = None
    forms: int = 0
    post_forms: int = 0
    external_action_forms: int = 0
    external_credential_forms: int = 0
    password_fields: int = 0
    email_fields: int = 0
    otp_fields: int = 0
    credential_fields: int = 0
    brand_mentions: list[str] = field(default_factory=list)
    iframes: int = 0
    hidden_iframes: int = 0
    external_scripts: int = 0
    inline_scripts: int = 0
    obfuscation_hits: int = 0
    meta_refresh: str | None = None
    auto_downloads: int = 0
    external_domains: list[str] = field(default_factory=list)
    suspicious_findings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class IdentityAnalysis:
    unicode_host: str
    ascii_host: str
    registered_domain: str
    unicode_registered_domain: str | None = None
    punycode: bool = False
    scripts: list[str] = field(default_factory=list)
    mixed_scripts: bool = False
    confusable_characters: list[str] = field(default_factory=list)
    confusable_skeleton: str | None = None
    reference_source: str | None = None
    reference_count: int = 0
    closest_reference_domain: str | None = None
    closest_reference_label: str | None = None
    levenshtein_distance: int | None = None
    compared_token: str | None = None
    typo_suspected: bool = False
    priority_reference: bool = False
    exact_reference: bool = False
    error: str | None = None


@dataclass
class ScreenshotResult:
    requested: bool = False
    available: bool = False
    path: str | None = None
    engine: str | None = None
    error: str | None = None


@dataclass
class RiskFactor:
    points: int
    description: str


def check_dependencies() -> None:
    if not MISSING:
        return
    print("\nERROR: faltan dependencias necesarias.\n")
    for module, package in MISSING:
        print(f"  - módulo: {module} | paquete: {package}")
    packages = " ".join(package for _, package in MISSING)
    print("\nInstálelas con:")
    print(f"  python -m pip install {packages}")
    raise SystemExit(3)


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def heading(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("La URL está vacía.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Solo se admiten URL HTTP o HTTPS.")
    if not parsed.hostname:
        raise ValueError("No se ha podido identificar el host.")
    return value


def hostname_from_url(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise ValueError(f"No se pudo extraer el host de {url!r}")
    return host.encode("idna").decode("ascii")


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class TargetSafetyError(RuntimeError):
    """Bloqueo preventivo de destinos no públicos o ambiguos."""


class TargetResolutionError(TargetSafetyError):
    """No fue posible resolver el host para prevalidar una conexión."""


_BLOCKED_HOST_SUFFIXES = (
    ".localhost", ".local", ".localdomain", ".internal", ".lan", ".home",
)
_BLOCKED_HOST_EXACT = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


def _ip_is_public_target(value: str) -> bool:
    """Devuelve True solo para direcciones globalmente encaminables.

    Además de ``is_global``, se revisan mecanismos IPv6 que pueden encapsular
    IPv4 para impedir que una dirección aparentemente global termine alcanzando
    loopback, espacio privado o reservado.
    """
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if not ip.is_global:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None and not mapped.is_global:
            return False
        try:
            embedded_6to4 = ip.sixtofour
        except Exception:
            embedded_6to4 = None
        if embedded_6to4 is not None and not embedded_6to4.is_global:
            return False
        try:
            teredo = ip.teredo
        except Exception:
            teredo = None
        if teredo is not None:
            server, client = teredo
            if not server.is_global or not client.is_global:
                return False
    return True


def validate_public_target(url: str, *, resolve: bool = True) -> list[str]:
    """Valida que una URL HTTP(S) apunte exclusivamente a red pública.

    Se bloquean localhost, nombres locales frecuentes, literales no globales y
    nombres DNS que resuelvan a *cualquier* dirección no global. La política es
    deliberadamente fail-closed: si no se puede resolver el host, no se realiza
    la conexión de destino.
    """
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetSafetyError("Solo se permiten destinos HTTP o HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetSafetyError("Se bloquean URL con credenciales embebidas en el destino.")
    if "\\" in parsed.netloc or any(ord(ch) < 32 for ch in url):
        raise TargetSafetyError("La URL contiene caracteres ambiguos o de control.")
    host = parsed.hostname
    if not host:
        raise TargetSafetyError("No se ha podido identificar el host del destino.")
    host_ascii = host.encode("idna").decode("ascii").lower().rstrip(".")
    if host_ascii in _BLOCKED_HOST_EXACT or any(host_ascii.endswith(s) for s in _BLOCKED_HOST_SUFFIXES):
        raise TargetSafetyError(f"Destino local/interno bloqueado por política: {host_ascii}")

    if is_ip_literal(host_ascii):
        if not _ip_is_public_target(host_ascii):
            raise TargetSafetyError(f"Dirección IP no pública bloqueada: {host_ascii}")
        return [host_ascii]

    if not resolve:
        return []
    try:
        infos = socket.getaddrinfo(host_ascii, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetResolutionError(f"No se pudo resolver de forma segura el destino {host_ascii}: {exc}") from exc
    addresses = sorted({item[4][0].split("%", 1)[0] for item in infos})
    if not addresses:
        raise TargetResolutionError(f"El destino {host_ascii} no resolvió a ninguna dirección IP.")
    blocked = [ip for ip in addresses if not _ip_is_public_target(ip)]
    if blocked:
        raise TargetSafetyError(
            f"El host {host_ascii} resuelve a direcciones no públicas y ha sido bloqueado: {', '.join(blocked)}"
        )
    return addresses


def _new_target_session() -> Any:
    assert requests is not None
    session = requests.Session()
    # No se heredan proxies del entorno para las conexiones al objetivo. Así la
    # verificación del peer refleja el destino real y se reduce superficie SSRF.
    session.trust_env = False
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
    })
    return session


def _response_peer_ip(response: Any) -> str | None:
    """Intenta obtener la IP del socket conectado antes de consumir el body.

    urllib3/requests no exponen el socket de forma estable entre versiones. Por
    ello esta comprobación es una defensa adicional: la protección primaria de
    DNS rebinding se realiza fijando la resolución a las IP públicas que ya han
    sido validadas antes de abrir la conexión.
    """
    candidates = []
    try:
        candidates.append(getattr(getattr(response.raw, "_connection", None), "sock", None))
    except Exception:
        pass
    try:
        candidates.append(response.raw._fp.fp.raw._sock)  # type: ignore[attr-defined]
    except Exception:
        pass
    for sock_obj in candidates:
        if sock_obj is None:
            continue
        try:
            return str(sock_obj.getpeername()[0]).split("%", 1)[0]
        except Exception:
            continue
    return None


@contextmanager
def _pin_target_resolution(host: str, port: int, addresses: list[str]):
    """Fija temporalmente el DNS del host a las IP públicas ya validadas.

    requests conserva el hostname original, de modo que HTTPS mantiene SNI y la
    verificación del certificado contra el nombre solicitado. Solo se sustituye
    la resolución de ese host durante la apertura de la conexión. El inspector
    es monohilo durante estas peticiones de destino.
    """
    original_getaddrinfo = socket.getaddrinfo
    host_ascii = host.encode("idna").decode("ascii").lower().rstrip(".")
    pinned = [str(ipaddress.ip_address(item.split("%", 1)[0])) for item in addresses]

    def pinned_getaddrinfo(
        query_host: Any, query_port: Any, family: int = 0, type: int = 0,
        proto: int = 0, flags: int = 0
    ) -> list[Any]:
        try:
            if isinstance(query_host, bytes):
                qhost = query_host.decode("ascii", errors="ignore")
            else:
                qhost = str(query_host)
            qhost = qhost.encode("idna").decode("ascii").lower().rstrip(".")
        except Exception:
            qhost = str(query_host).lower().rstrip(".")

        if qhost != host_ascii:
            return original_getaddrinfo(query_host, query_port, family, type, proto, flags)

        effective_type = type or socket.SOCK_STREAM
        effective_proto = proto or (socket.IPPROTO_TCP if effective_type == socket.SOCK_STREAM else 0)
        results: list[Any] = []
        for ip_text in pinned:
            ip_obj = ipaddress.ip_address(ip_text)
            af = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
            if family not in (0, socket.AF_UNSPEC, af):
                continue
            sockaddr = (ip_text, port, 0, 0) if af == socket.AF_INET6 else (ip_text, port)
            results.append((af, effective_type, effective_proto, "", sockaddr))
        if not results:
            raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "No hay IP fijada compatible con la familia solicitada")
        return results

    socket.getaddrinfo = pinned_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]


def _safe_target_get(session: Any, url: str, **kwargs: Any) -> Any:
    """GET al objetivo con validación previa y DNS fijado a IP públicas.

    La fijación elimina la ventana de DNS rebinding entre la validación y el
    connect(). La lectura del peer se mantiene como comprobación adicional, pero
    no se trata como error cuando requests/urllib3 no exponen el socket.
    """
    addresses = validate_public_target(url, resolve=True)
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        raise TargetSafetyError("No se ha podido identificar el host del destino.")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    kwargs.setdefault("allow_redirects", False)
    kwargs.setdefault("timeout", (CONNECT_TIMEOUT, READ_TIMEOUT))
    kwargs.setdefault("stream", True)
    kwargs.setdefault("verify", True)
    with _pin_target_resolution(host, port, addresses):
        response = session.get(url, **kwargs)

    peer = _response_peer_ip(response)
    if peer is not None:
        if not _ip_is_public_target(peer):
            response.close()
            raise TargetSafetyError(f"DNS rebinding/SSRF bloqueado: la conexión terminó en la IP no pública {peer}.")
        try:
            peer_obj = ipaddress.ip_address(peer)
            allowed = {ipaddress.ip_address(item) for item in addresses}
            if peer_obj not in allowed:
                response.close()
                raise TargetSafetyError(
                    f"DNS rebinding/SSRF bloqueado: la conexión terminó en una IP no fijada ({peer})."
                )
        except ValueError:
            response.close()
            raise TargetSafetyError(f"No se pudo validar la IP remota de la conexión: {peer}")
    return response


_TLD_EXTRACTOR = None

def _get_tld_extractor():
    """Devuelve una única instancia local de TLDExtract.

    Crear TLDExtract repetidamente es costoso, especialmente dentro del bucle
    de comparación contra miles de dominios de referencia. La instancia usa
    exclusivamente la Public Suffix List incluida en el paquete, sin red.
    """
    global _TLD_EXTRACTOR
    assert tldextract is not None
    if _TLD_EXTRACTOR is None:
        _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
    return _TLD_EXTRACTOR


def registered_domain(host: str) -> str:
    if is_ip_literal(host):
        return host
    extractor = _get_tld_extractor()
    result = extractor(host)
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}"
    return result.domain or host



def utc_iso_from_epoch(value: Any) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def canonicalize_url_for_lookup(url: str) -> str:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        port = f":{parsed.port}" if parsed.port and parsed.port not in {80, 443} else ""
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}{port}{path}{query}"
    except Exception:
        return url.strip()


def unicode_hostname(host: str) -> str:
    labels: list[str] = []
    for label in host.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna"))
        except Exception:
            labels.append(label)
    return ".".join(labels)


def unicode_script(ch: str) -> str | None:
    if ch.isdigit() or ch in "-_.":
        return None
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "CJK", "HIRAGANA", "KATAKANA", "HANGUL"):
        if script in name:
            return script.title()
    if ch.isalpha():
        return "Other"
    return None


def confusable_skeleton(text: str) -> tuple[str, list[str]]:
    normalized = unicodedata.normalize("NFKC", text).lower()
    changed: list[str] = []
    out: list[str] = []
    for ch in normalized:
        repl = CONFUSABLES.get(ch, ch)
        if repl != ch:
            changed.append(f"{ch}->{repl}")
        out.append(repl)
    return "".join(out), changed


def normalize_reference_label(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]", "", text)


def levenshtein_bounded(a: str, b: str, max_distance: int = 2) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if len(a) > len(b):
        a, b = b, a
    previous = list(range(len(a) + 1))
    for i, cb in enumerate(b, start=1):
        current = [i]
        row_min = i
        for j, ca in enumerate(a, start=1):
            value = min(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + (ca != cb),
            )
            current.append(value)
            row_min = min(row_min, value)
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def _read_reference_file(path: Path) -> list[str]:
    domains: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            # Admite CSV sencillos: selecciona la primera columna con aspecto de dominio/URL.
            parts = [part.strip() for part in line.split(",")]
            candidates = [part for part in parts if "." in part and " " not in part]
            if not candidates:
                continue
            line = candidates[0]
        if "://" in line:
            try:
                line = registered_domain(hostname_from_url(line))
            except Exception:
                continue
        line = line.strip(". ")
        if "." in line and " " not in line:
            domains.append(line)
    return domains


def _host_belongs_to_domain(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def is_shared_hosting(host: str) -> tuple[bool, str | None]:
    for domain in SHARED_HOSTING_DOMAINS:
        if _host_belongs_to_domain(host, domain):
            return True, domain
    return False, None


def _brand_token_match(token: str, brand: str) -> bool:
    token = normalize_reference_label(token)
    brand = normalize_reference_label(brand)
    if not token or not brand:
        return False
    if token == brand:
        return True
    # Las concatenaciones son frecuentes en phishing (p.ej. kucoinapps), pero
    # se restringen a marcas suficientemente largas y a prefijo para reducir
    # colisiones léxicas como "pineapple" -> "apple".
    return len(brand) >= 5 and token.startswith(brand) and len(token) <= len(brand) + 24


def detect_brand_mentions(text: str, host: str | None = None, *, fuzzy: bool = False) -> list[str]:
    decoded = unquote(text or "").lower()
    tokens = re.findall(r"[a-z0-9]+", decoded)
    host_l = (host or "").lower().rstrip(".")
    found: list[str] = []
    for brand, official_domains in PRIORITY_BRANDS.items():
        if host_l and any(_host_belongs_to_domain(host_l, d) for d in official_domains):
            continue
        matched = any(_brand_token_match(token, brand) for token in tokens)
        if not matched and fuzzy and len(brand) >= 5:
            for token in tokens:
                norm = normalize_reference_label(token)
                if len(norm) >= 4 and norm[0] == brand[0] and abs(len(norm) - len(brand)) <= 1:
                    if levenshtein_bounded(norm, brand, 1) == 1:
                        matched = True
                        break
        if matched:
            found.append(brand)
    return sorted(set(found))


def load_reference_domains(custom_path: str | None = None) -> tuple[list[str], str, str | None]:
    domains = set(CORE_REFERENCE_DOMAINS)
    source = "lista interna prioritaria"
    error: str | None = None
    candidate: Path | None = Path(custom_path).expanduser() if custom_path else None

    if candidate:
        try:
            domains.update(_read_reference_file(candidate))
            source = f"archivo local: {candidate}"
        except Exception as exc:
            error = f"No se pudo leer la lista indicada: {exc}"
    else:
        try:
            if REFERENCE_CACHE_FILE.exists():
                age = datetime.now().timestamp() - REFERENCE_CACHE_FILE.stat().st_mtime
                # La lista de referencia no necesita refresco diario; 30 días es suficiente.
                if age <= 30 * 86400:
                    domains.update(_read_reference_file(REFERENCE_CACHE_FILE))
                    source = f"Tranco Top 5000 en caché: {REFERENCE_CACHE_FILE}"
            if len(domains) < 1000:
                assert requests is not None
                response = requests.get(
                    REFERENCE_DOMAINS_URL,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    headers={"User-Agent": USER_AGENT},
                )
                response.raise_for_status()
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                REFERENCE_CACHE_FILE.write_text(response.text, encoding="utf-8")
                domains.update(_read_reference_file(REFERENCE_CACHE_FILE))
                source = "Tranco Top 5000 + lista interna prioritaria"
        except Exception as exc:
            error = f"No se pudo actualizar la lista de 5.000 dominios: {exc}"
            source = "lista interna prioritaria (fallback)"

    return sorted(domains), source, error


def analyze_identity(host_ascii: str, registered_ascii: str, custom_reference_path: str | None = None) -> IdentityAnalysis:
    uhost = unicode_hostname(host_ascii)
    try:
        uregistered = unicode_hostname(registered_ascii)
    except Exception:
        uregistered = registered_ascii
    result = IdentityAnalysis(
        unicode_host=uhost,
        ascii_host=host_ascii,
        registered_domain=registered_ascii,
        unicode_registered_domain=uregistered,
        punycode=("xn--" in host_ascii.lower()),
    )

    scripts = sorted({s for ch in uhost for s in [unicode_script(ch)] if s})
    result.scripts = scripts
    result.mixed_scripts = len(scripts) > 1
    skeleton, confusables = confusable_skeleton(uhost)
    result.confusable_skeleton = skeleton
    result.confusable_characters = confusables

    references, source, load_error = load_reference_domains(custom_reference_path)
    result.reference_source = source
    result.reference_count = len(references)
    if load_error:
        result.error = load_error

    # IMPORTANTE: reutilizar una única instancia de TLDExtract. En la versión
    # anterior se construía una instancia nueva por cada dominio de referencia
    # (y otra vez para el esqueleto Unicode), lo que podía consumir decenas de
    # segundos con listas de miles de dominios y provocar timeouts del benchmark.
    try:
        extractor = _get_tld_extractor()
        ext = extractor(registered_ascii)
        candidate_label_raw = ext.domain or registered_ascii.split(".")[0]
    except Exception:
        extractor = None
        candidate_label_raw = registered_ascii.split(".")[0]

    candidate_label = normalize_reference_label(candidate_label_raw)
    candidate_parts = [normalize_reference_label(p) for p in re.split(r"[-_.]+", candidate_label_raw)]
    candidate_parts = [p for p in candidate_parts if len(p) >= 4]
    tokens = list(dict.fromkeys([candidate_label] + candidate_parts))

    core_set = {d.lower() for d in CORE_REFERENCE_DOMAINS}
    best: tuple[int, str, str, str] | None = None
    normalized_registered = registered_ascii.lower().rstrip(".")
    exact_reference = normalized_registered in {d.lower().rstrip(".") for d in references}
    result.exact_reference = exact_reference

    # Calcula una sola vez la etiqueta de cada referencia y la reutiliza también
    # en la segunda pasada de homoglifos.
    reference_labels: list[tuple[str, str]] = []
    for ref_domain in references:
        if ref_domain.lower().rstrip(".") == normalized_registered:
            continue
        try:
            if extractor is not None:
                ext = extractor(ref_domain)
                ref_label_raw = ext.domain or ref_domain.split(".")[0]
            else:
                ref_label_raw = ref_domain.split(".")[0]
        except Exception:
            ref_label_raw = ref_domain.split(".")[0]
        ref_label = normalize_reference_label(ref_label_raw)
        if len(ref_label) < 4:
            continue
        reference_labels.append((ref_domain, ref_label))

        for token in tokens:
            if len(token) < 4 or abs(len(token) - len(ref_label)) > 2:
                continue
            d = levenshtein_bounded(token, ref_label, 2)
            is_priority = ref_domain.lower().rstrip(".") in core_set
            if is_priority:
                suspicious = (d == 1 and len(ref_label) >= 4) or (d == 2 and len(ref_label) >= 6)
                # Coincidencia exacta de una marca prioritaria dentro de otro dominio
                # (p.ej. microsoft-login.example) también es relevante.
                if d == 0 and token != candidate_label:
                    suspicious = True
            else:
                # Para referencias genéricas de Tranco, distancia 2 producía
                # numerosas colisiones casuales. Se conserva solo distancia 1.
                suspicious = d == 1 and len(ref_label) >= 5
            if suspicious and (best is None or d < best[0] or (d == best[0] and len(ref_label) > len(best[2]))):
                best = (d, ref_domain, ref_label, token)

    # Repite la comparación sobre el esqueleto Unicode si se modificaron caracteres.
    if confusables:
        try:
            skel_reg = unicode_hostname(registered_ascii)
            skel_reg, _ = confusable_skeleton(skel_reg)
            if extractor is not None:
                ext = extractor(skel_reg)
                skel_label = normalize_reference_label(ext.domain or skel_reg.split(".")[0])
            else:
                skel_label = normalize_reference_label(skel_reg.split(".")[0])
        except Exception:
            skel_label = normalize_reference_label(skeleton.split(".")[0])
        for ref_domain, ref_label in reference_labels:
            if skel_label == ref_label and ref_domain.lower() != registered_ascii.lower():
                best = (0, ref_domain, ref_label, skel_label)
                break

    if best:
        result.levenshtein_distance = best[0]
        result.closest_reference_domain = best[1]
        result.closest_reference_label = best[2]
        result.compared_token = best[3]
        result.typo_suspected = True
        result.priority_reference = best[1].lower().rstrip(".") in core_set
    return result


def default_screenshot_path(domain: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", domain)[:80] or "url"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path.cwd() / f"{safe}_{stamp}_screenshot.png"


def find_chromium_browser() -> str | None:
    names = ["msedge", "chrome", "google-chrome", "chromium", "chromium-browser"]
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        roots = [os.getenv("PROGRAMFILES"), os.getenv("PROGRAMFILES(X86)"), os.getenv("LOCALAPPDATA")]
        suffixes = [
            Path("Microsoft/Edge/Application/msedge.exe"),
            Path("Google/Chrome/Application/chrome.exe"),
            Path("Chromium/Application/chrome.exe"),
        ]
        for root in roots:
            if not root:
                continue
            for suffix in suffixes:
                candidate = Path(root) / suffix
                if candidate.exists():
                    return str(candidate)
    return None


def capture_screenshot(url: str, output_path: str | None, domain: str) -> ScreenshotResult:
    result = ScreenshotResult(requested=True)
    try:
        validate_public_target(url, resolve=True)
    except TargetSafetyError as exc:
        result.error = f"Captura bloqueada por seguridad: {exc}"
        return result
    browser = find_chromium_browser()
    if not browser:
        result.error = "No se encontró Chrome, Edge o Chromium para realizar la captura."
        return result
    path = Path(output_path).expanduser().resolve() if output_path else default_screenshot_path(domain).resolve()
    profile = tempfile.mkdtemp(prefix="url_inspector_browser_")
    process: subprocess.Popen[bytes] | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--incognito",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-sync",
            "--disable-background-networking",
            "--window-size=1440,1200",
            f"--user-data-dir={profile}",
            f"--screenshot={path}",
            url,
        ]
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.insert(1, "--no-sandbox")

        stderr_path = Path(profile) / "browser_stderr.log"
        popen_kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": None,  # se sustituye por el manejador abierto abajo
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True

        with stderr_path.open("wb") as err_handle:
            popen_kwargs["stderr"] = err_handle
            process = subprocess.Popen(cmd, **popen_kwargs)
            try:
                return_code = process.wait(timeout=SCREENSHOT_TIMEOUT)
            except subprocess.TimeoutExpired:
                # Chrome/Edge crean varios procesos. Se termina el árbol/grupo para
                # que un sitio problemático no deje procesos headless en segundo plano.
                try:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=8,
                            check=False,
                        )
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                try:
                    process.wait(timeout=5)
                except Exception:
                    pass
                result.error = f"El navegador superó el tiempo máximo de {SCREENSHOT_TIMEOUT} s para la captura."
                return result

        if return_code != 0 or not path.exists() or path.stat().st_size == 0:
            try:
                detail = stderr_path.read_text(encoding="utf-8", errors="ignore")[-500:].strip()
            except Exception:
                detail = ""
            result.error = detail or f"El navegador terminó con código {return_code}."
            return result

        result.available = True
        result.path = str(path)
        result.engine = Path(browser).name
        return result
    except Exception as exc:
        result.error = str(exc)
        return result
    finally:
        # La limpieza es deliberadamente tolerante: en algunos sistemas el navegador
        # puede tardar unos instantes en liberar ficheros del perfil temporal.
        shutil.rmtree(profile, ignore_errors=True)


def trace_url(start_url: str) -> tuple[str, list[RedirectStep]]:
    assert requests is not None
    session = _new_target_session()
    current = start_url
    seen: set[str] = set()
    chain: list[RedirectStep] = []

    for _ in range(MAX_REDIRECTS + 1):
        canonical = canonicalize_url_for_lookup(current)
        if canonical in seen:
            raise RuntimeError(f"Bucle de redirección detectado: {current}")
        seen.add(canonical)

        response = _safe_target_get(session, current)
        server = response.headers.get("Server")

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            if not location:
                chain.append(RedirectStep(response.url, response.status_code, "final", server=server))
                final_url = response.url
                response.close()
                return final_url, chain
            next_url = urljoin(response.url, location)
            # Bloqueo antes de seguir cualquier redirección HTTP. La evidencia
            # del salto se conserva, pero nunca se conecta al destino interno.
            try:
                validate_public_target(next_url, resolve=True)
            except TargetSafetyError as exc:
                chain.append(RedirectStep(
                    response.url, response.status_code, "HTTP-BLOQUEADO",
                    destination=next_url, server=server, blocked_reason=str(exc)
                ))
                final_url = response.url
                response.close()
                return final_url, chain
            chain.append(RedirectStep(
                response.url, response.status_code, "HTTP",
                destination=next_url, server=server
            ))
            response.close()
            current = next_url
            continue

        content_type = response.headers.get("Content-Type", "").lower()
        meta_target = None
        if "html" in content_type:
            data = response.raw.read(MAX_HTML_BYTES, decode_content=True)
            soup = BeautifulSoup(data, "html.parser")
            meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
            if meta and meta.get("content"):
                match = re.search(r"url\s*=\s*(.+)$", str(meta["content"]), re.I)
                if match:
                    meta_target = urljoin(response.url, match.group(1).strip(" '\""))

        if meta_target:
            try:
                validate_public_target(meta_target, resolve=True)
            except TargetSafetyError as exc:
                chain.append(RedirectStep(
                    response.url, response.status_code, "META-BLOQUEADO",
                    destination=meta_target, server=server, blocked_reason=str(exc)
                ))
                final_url = response.url
                response.close()
                return final_url, chain
            chain.append(RedirectStep(
                response.url, response.status_code, "META",
                destination=meta_target, server=server
            ))
            response.close()
            current = meta_target
            continue

        chain.append(RedirectStep(response.url, response.status_code, "final", server=server))
        final_url = response.url
        response.close()
        return final_url, chain

    raise RuntimeError(f"Se superó el máximo de {MAX_REDIRECTS} redirecciones.")


def resolve_ips(host: str) -> list[str]:
    results: set[str] = set()
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        results.add(item[4][0])
    return sorted(results, key=lambda value: (":" in value, value))


def get_ip_geolocation(ip: str) -> dict[str, Any]:
    assert requests is not None
    response = requests.get(
        f"https://ipwho.is/{ip}",
        timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(data.get("message", "La consulta geográfica falló."))
    return data


def dns_query(name: str, record_type: str) -> list[str]:
    try:
        answer = dns.resolver.resolve(name, record_type, lifetime=READ_TIMEOUT)
        return [item.to_text().strip() for item in answer]
    except Exception:
        return []


def inspect_dns(host: str, domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"):
        result[record_type] = dns_query(host if record_type in {"A", "AAAA", "CNAME"} else domain, record_type)

    result["SPF"] = [
        item for item in result["TXT"]
        if "v=spf1" in item.lower()
    ]
    result["DMARC"] = dns_query(f"_dmarc.{domain}", "TXT")
    result["DNSKEY"] = dns_query(domain, "DNSKEY")
    result["dnssec_published"] = bool(result["DNSKEY"])
    return result


def detect_cdn(
    host: str,
    dns_data: dict[str, Any],
    headers: dict[str, str],
    geo: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    evidence: list[str] = []
    haystack_parts = [host]
    for key in ("CNAME", "NS"):
        haystack_parts.extend(dns_data.get(key, []))
    for key, value in headers.items():
        haystack_parts.append(f"{key}:{value}")
    for item in geo.values():
        connection = item.get("connection") or {}
        haystack_parts.extend([
            str(connection.get("org", "")),
            str(connection.get("isp", "")),
            str(connection.get("domain", "")),
        ])
    haystack = " ".join(haystack_parts).lower()

    detected: list[str] = []
    for hint, provider in CDN_HINTS.items():
        if hint in haystack and provider not in detected:
            detected.append(provider)
            evidence.append(f"Coincidencia «{hint}»")

    special_headers = {
        "cf-ray": "Cloudflare",
        "x-amz-cf-id": "Amazon CloudFront",
        "x-served-by": "Fastly",
        "x-cache": None,
        "x-akamai-transformed": "Akamai",
        "x-iinfo": "Imperva",
    }
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header, provider in special_headers.items():
        if header in lower_headers:
            evidence.append(f"Cabecera {header}")
            if provider and provider not in detected:
                detected.append(provider)

    return {
        "detected": bool(detected),
        "providers": detected,
        "evidence": evidence,
        "anycast_or_proxy_likely": bool(detected),
    }


def get_rdap_server(domain: str) -> str:
    """Devuelve el servidor RDAP del TLD usando el bootstrap IANA con caché local.

    El bootstrap cambia con poca frecuencia; cachearlo evita una consulta adicional
    por cada URL analizada y hace el análisis más robusto ante caídas temporales de
    data.iana.org. Si la actualización falla, se acepta una caché antigua antes de
    recurrir al fallback RDAP general.
    """
    assert requests is not None
    tld = domain.rsplit(".", 1)[-1].lower()
    data: dict[str, Any] | None = None

    try:
        if RDAP_BOOTSTRAP_CACHE_FILE.exists():
            age = datetime.now().timestamp() - RDAP_BOOTSTRAP_CACHE_FILE.stat().st_mtime
            if age <= RDAP_BOOTSTRAP_CACHE_MAX_AGE_SECONDS:
                loaded = json.loads(RDAP_BOOTSTRAP_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
    except Exception:
        data = None

    if data is None:
        try:
            response = requests.get(
                "https://data.iana.org/rdap/dns.json",
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            response.raise_for_status()
            loaded = response.json()
            if not isinstance(loaded, dict):
                raise RuntimeError("El bootstrap RDAP de IANA no es un objeto JSON válido.")
            data = loaded
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                RDAP_BOOTSTRAP_CACHE_FILE.write_text(
                    json.dumps(data, ensure_ascii=False), encoding="utf-8"
                )
            except OSError:
                pass
        except Exception:
            # Una caché antigua sigue siendo preferible a repetir fallos de red.
            try:
                loaded = json.loads(RDAP_BOOTSTRAP_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:
                data = None
            if data is None:
                raise

    for service in data.get("services", []):
        if isinstance(service, list) and len(service) == 2:
            tlds, servers = service
            if tld in [str(item).lower() for item in tlds] and servers:
                return str(servers[0])
    raise RuntimeError(f"IANA no publica un servidor RDAP para .{tld}.")


def request_rdap_url(url: str) -> dict[str, Any]:
    assert requests is not None
    response = requests.get(
        url,
        timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
        allow_redirects=True,
    )
    if response.status_code == 404:
        raise RuntimeError("El servidor RDAP no encontró el dominio.")
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("La respuesta RDAP no es un objeto JSON válido.")
    return data


def get_rdap(domain: str) -> tuple[dict[str, Any], str]:
    try:
        server = get_rdap_server(domain)
    except Exception as bootstrap_error:
        try:
            return request_rdap_url(f"https://rdap.org/domain/{domain}"), "fallback: rdap.org"
        except Exception as fallback_error:
            raise RuntimeError(
                "No se pudo resolver RDAP mediante IANA ni mediante el servicio "
                f"alternativo. IANA: {bootstrap_error}. Alternativo: {fallback_error}"
            ) from fallback_error
    url = urljoin(server.rstrip("/") + "/", f"domain/{domain}")
    return request_rdap_url(url), f"IANA bootstrap: {server}"


def rdap_event(data: dict[str, Any], actions: set[str]) -> str | None:
    normalized = {item.lower() for item in actions}
    for event in data.get("events", []):
        if str(event.get("eventAction", "")).strip().lower() in normalized:
            return event.get("eventDate")
    return None


def rdap_creation_date(data: dict[str, Any]) -> str | None:
    return rdap_event(data, {
        "registration", "registered", "created", "creation",
        "domain registration", "registration date",
    })


def rdap_update_date(data: dict[str, Any]) -> str | None:
    return rdap_event(data, {
        "last changed", "last update of rdap database",
        "updated", "update", "last modified",
    })


def rdap_expiration_date(data: dict[str, Any]) -> str | None:
    return rdap_event(data, {"expiration", "expiry", "expires", "expiration date"})


def flatten_cert_name(items: Any) -> str:
    if not items:
        return ""
    return ", ".join(f"{key}={value}" for group in items for key, value in group)


def cert_name_value(items: Any, searched_key: str) -> str | None:
    if not items:
        return None
    for group in items:
        for key, value in group:
            if key == searched_key:
                return str(value)
    return None


def days_until(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(not_after)
    except (ValueError, TypeError):
        return None
    return max(0, int((timestamp - datetime.now(timezone.utc).timestamp()) // 86400))


def format_fingerprint(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in raw)



def classify_certificate_validation(parsed: Any) -> tuple[str, str, list[str], str | None]:
    policy_oids: list[str] = []
    try:
        policies = parsed.extensions.get_extension_for_class(x509.CertificatePolicies).value
        policy_oids = [policy.policy_identifier.dotted_string for policy in policies]
    except Exception:
        pass

    for oid in ("2.23.140.1.1", "2.23.140.1.2.2", "2.23.140.1.2.1", "2.23.140.1.2.3"):
        if oid in policy_oids:
            return CABF_POLICY_OIDS[oid], f"OID CA/B Forum {oid}", policy_oids, _certificate_subject_org(parsed)

    organization = _certificate_subject_org(parsed)
    try:
        subject_oids = {attr.oid.dotted_string for attr in parsed.subject}
    except Exception:
        subject_oids = set()
    # EV puede usar un OID propio de la CA. Los atributos siguientes son típicos
    # del perfil EV, pero sin resolver el OID contra la CPS de la CA no son prueba concluyente.
    ev_subject_markers = {"2.5.4.15", "1.3.6.1.4.1.311.60.2.1.3"}  # businessCategory, jurisdictionCountryName
    if organization and ev_subject_markers.issubset(subject_oids):
        return "EV (probable)", "heurística de sujeto EV; el OID de política no es uno de los OID genéricos CA/B", policy_oids, organization
    if organization:
        return "OV/EV (indeterminado)", "hay identidad de organización, pero el OID de política no permite distinguir OV de EV", policy_oids, organization
    if {"2.5.4.42", "2.5.4.4"} & subject_oids:  # givenName / surname
        return "IV (probable)", "heurística: atributos personales en el sujeto, sin OID CA/B explícito", policy_oids, organization
    return "DV (probable)", "heurística: sin identidad de organización ni OID CA/B explícito", policy_oids, organization


def _certificate_subject_org(parsed: Any) -> str | None:
    if NameOID is None:
        return None
    try:
        attrs = parsed.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def certificate_age_days(parsed: Any) -> int | None:
    try:
        start = getattr(parsed, "not_valid_before_utc", None)
        if start is None:
            start = parsed.not_valid_before
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - start.astimezone(timezone.utc)
        return max(0, delta.days)
    except Exception:
        return None


def inspect_tls(host: str, port: int = 443) -> TLSResult:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        scheme = "https"
        approved = validate_public_target(f"{scheme}://{host}:{port}/", resolve=True)
        # La conexión TLS se fija a una IP pública ya validada, conservando el
        # hostname original para SNI y verificación del certificado. Esto evita
        # una segunda resolución susceptible de DNS rebinding entre validación y
        # conexión. Si hay varias IP públicas, se usa la primera de forma
        # determinista; un fallo se informa sin probar destinos no validados.
        connect_ip = approved[0]
        with socket.create_connection((connect_ip, port), timeout=READ_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                cert = secure.getpeercert()
                der = secure.getpeercert(binary_form=True)
                result = TLSResult(
                    available=True,
                    valid=True,
                    host=host,
                    port=port,
                    tls_version=secure.version(),
                    cipher=secure.cipher(),
                    subject=flatten_cert_name(cert.get("subject")),
                    issuer=flatten_cert_name(cert.get("issuer")),
                    issuer_common_name=cert_name_value(cert.get("issuer"), "commonName"),
                    serial_number=cert.get("serialNumber"),
                    not_before=cert.get("notBefore"),
                    not_after=cert.get("notAfter"),
                    days_remaining=days_until(cert.get("notAfter")),
                    hostname_verified=True,
                    trusted_ca=True,
                    sans=list(cert.get("subjectAltName", [])),
                )

                if der and x509 is not None:
                    parsed = x509.load_der_x509_certificate(der)
                    validation_type, validation_basis, policy_oids, subject_org = classify_certificate_validation(parsed)
                    result.validation_type = validation_type
                    result.validation_type_basis = validation_basis
                    result.policy_oids = policy_oids
                    result.subject_organization = subject_org
                    result.certificate_age_days = certificate_age_days(parsed)
                    result.signature_algorithm = (
                        parsed.signature_hash_algorithm.name
                        if parsed.signature_hash_algorithm else None
                    )
                    public_key = parsed.public_key()
                    if rsa is not None and isinstance(public_key, rsa.RSAPublicKey):
                        result.public_key_type = "RSA"
                        result.public_key_bits = public_key.key_size
                    elif ec is not None and isinstance(public_key, ec.EllipticCurvePublicKey):
                        result.public_key_type = f"EC ({public_key.curve.name})"
                        result.public_key_bits = public_key.key_size
                    else:
                        result.public_key_type = type(public_key).__name__
                        result.public_key_bits = getattr(public_key, "key_size", None)

                    result.sha256_fingerprint = format_fingerprint(
                        parsed.fingerprint(hashes.SHA256())
                    )

                    try:
                        aia = parsed.extensions.get_extension_for_class(
                            x509.AuthorityInformationAccess
                        ).value
                        result.ocsp_urls = [
                            str(item.access_location.value)
                            for item in aia
                            if item.access_method == x509.AuthorityInformationAccessOID.OCSP
                        ]
                    except x509.ExtensionNotFound:
                        pass

                    try:
                        crl = parsed.extensions.get_extension_for_class(
                            x509.CRLDistributionPoints
                        ).value
                        for point in crl:
                            if point.full_name:
                                result.crl_urls.extend(
                                    str(name.value) for name in point.full_name
                                )
                    except x509.ExtensionNotFound:
                        pass

                return result

    except TargetSafetyError as exc:
        return TLSResult(
            available=False, valid=False, host=host, port=port,
            hostname_verified=None, trusted_ca=None, error=f"Bloqueado por seguridad: {exc}"
        )
    except ssl.SSLCertVerificationError as exc:
        return TLSResult(
            available=True, valid=False, host=host, port=port,
            hostname_verified=False, trusted_ca=False, error=str(exc)
        )
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as exc:
        return TLSResult(
            available=False, valid=False, host=host, port=port,
            hostname_verified=None, trusted_ca=None, error=str(exc)
        )


def inspect_http(url: str) -> tuple[HTTPAnalysis, bytes]:
    assert requests is not None
    analysis = HTTPAnalysis()
    session = _new_target_session()
    current = url
    seen: set[str] = set()
    response = None
    try:
        for _ in range(MAX_REDIRECTS + 1):
            canonical = canonicalize_url_for_lookup(current)
            if canonical in seen:
                raise RuntimeError(f"Bucle de redirección HTTP detectado: {current}")
            seen.add(canonical)
            response = _safe_target_get(
                session, current,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
            )
            if 300 <= response.status_code < 400 and response.headers.get("Location"):
                next_url = urljoin(response.url, response.headers["Location"])
                validate_public_target(next_url, resolve=True)
                response.close()
                response = None
                current = next_url
                continue
            break
        else:
            raise RuntimeError(f"Se superó el máximo de {MAX_REDIRECTS} redirecciones HTTP.")

        assert response is not None
        analysis.status_code = response.status_code
        analysis.server = response.headers.get("Server")
        analysis.content_type = response.headers.get("Content-Type")
        analysis.headers = dict(response.headers)

        raw_version = getattr(response.raw, "version", None)
        analysis.http_version = {
            10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2",
        }.get(raw_version, str(raw_version) if raw_version else None)

        lower = {k.lower(): v for k, v in response.headers.items()}
        for header, label in SECURITY_HEADERS.items():
            value = lower.get(header)
            analysis.security_headers[label] = {
                "present": value is not None,
                "value": value,
            }

        set_cookie = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
        analysis.cookies = list(set_cookie)
        body = response.raw.read(MAX_HTML_BYTES, decode_content=True)
        response.close()
        return analysis, body
    except Exception as exc:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        analysis.error = str(exc)
        return analysis, b""


def analyze_html(url: str, body: bytes, content_type: str | None) -> HTMLAnalysis:
    result = HTMLAnalysis()
    if not body or not content_type or "html" not in content_type.lower():
        result.error = "El contenido no es HTML o no pudo descargarse."
        return result

    try:
        soup = BeautifulSoup(body, "html.parser")
        result.available = True
        result.title = soup.title.get_text(" ", strip=True) if soup.title else None
        base_domain = registered_domain(hostname_from_url(url))
        base_host = hostname_from_url(url)
        external_domains: set[str] = set()

        all_inputs = soup.find_all("input")
        for inp in all_inputs:
            input_type = str(inp.get("type", "text")).lower()
            attrs = " ".join(str(inp.get(k, "")) for k in ("name", "id", "placeholder", "autocomplete", "aria-label"))
            if input_type == "password":
                result.password_fields += 1
            if input_type == "email" or re.search(r"(?:^|[^a-z])e?-?mail(?:$|[^a-z])", attrs, re.I):
                result.email_fields += 1
            if OTP_HINT_RE.search(attrs):
                result.otp_fields += 1
            if input_type in {"password", "email"} or CREDENTIAL_HINT_RE.search(attrs):
                result.credential_fields += 1

        forms = soup.find_all("form")
        result.forms = len(forms)
        for form in forms:
            method = str(form.get("method", "get")).lower()
            if method == "post":
                result.post_forms += 1

            form_has_credentials = False
            for inp in form.find_all("input"):
                input_type = str(inp.get("type", "text")).lower()
                attrs = " ".join(str(inp.get(k, "")) for k in ("name", "id", "placeholder", "autocomplete", "aria-label"))
                if input_type in {"password", "email"} or CREDENTIAL_HINT_RE.search(attrs):
                    form_has_credentials = True
                    break

            action_domain = None
            action = form.get("action")
            if action:
                absolute = urljoin(url, str(action))
                try:
                    action_domain = registered_domain(hostname_from_url(absolute))
                    if action_domain != base_domain:
                        result.external_action_forms += 1
                        external_domains.add(action_domain)
                except Exception:
                    pass
            if form_has_credentials and action_domain and action_domain != base_domain:
                result.external_credential_forms += 1

        iframes = soup.find_all("iframe")
        result.iframes = len(iframes)
        for iframe in iframes:
            style = str(iframe.get("style", "")).replace(" ", "").lower()
            width = str(iframe.get("width", "")).lower()
            height = str(iframe.get("height", "")).lower()
            hidden = iframe.has_attr("hidden") or "display:none" in style or "visibility:hidden" in style
            hidden = hidden or width in {"0", "1", "0px", "1px"} or height in {"0", "1", "0px", "1px"}
            if hidden:
                result.hidden_iframes += 1

        scripts = soup.find_all("script")
        script_texts: list[str] = []
        for script in scripts:
            src = script.get("src")
            if src:
                absolute = urljoin(url, str(src))
                try:
                    script_domain = registered_domain(hostname_from_url(absolute))
                    if script_domain != base_domain:
                        result.external_scripts += 1
                        external_domains.add(script_domain)
                except Exception:
                    pass
            else:
                result.inline_scripts += 1
                script_texts.append(script.get_text(" ", strip=False))

        combined_scripts = "\n".join(script_texts)
        result.obfuscation_hits = len(OBFUSCATION_RE.findall(combined_scripts))

        meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if meta and meta.get("content"):
            result.meta_refresh = str(meta.get("content"))

        result.auto_downloads = len(soup.find_all(attrs={"download": True}))
        result.external_domains = sorted(external_domains)

        # Busca marcas prioritarias en título y texto visible. Se limita el texto
        # para mantener coste y memoria acotados en páginas grandes.
        visible_text = soup.get_text(" ", strip=True)[:50000]
        brand_text = " ".join(x for x in (result.title or "", visible_text) if x)
        result.brand_mentions = detect_brand_mentions(brand_text, base_host)

        if result.password_fields:
            result.suspicious_findings.append(f"Hay {result.password_fields} campo(s) de contraseña.")
        if result.credential_fields:
            result.suspicious_findings.append(f"Hay {result.credential_fields} campo(s) relacionados con credenciales o identidad.")
        if result.external_credential_forms:
            result.suspicious_findings.append(f"Hay {result.external_credential_forms} formulario(s) de credenciales que envían datos a otro dominio.")
        elif result.external_action_forms:
            result.suspicious_findings.append(f"Hay {result.external_action_forms} formulario(s) que envían datos a otro dominio.")
        if result.brand_mentions:
            result.suspicious_findings.append("La página menciona marcas prioritarias fuera de su dominio oficial: " + ", ".join(result.brand_mentions[:6]))
        if result.hidden_iframes:
            result.suspicious_findings.append(f"Hay {result.hidden_iframes} iframe(s) oculto(s) o casi invisibles.")
        if result.obfuscation_hits:
            result.suspicious_findings.append(f"Se detectaron {result.obfuscation_hits} indicios de JavaScript ofuscado.")
        if result.meta_refresh:
            result.suspicious_findings.append("La página contiene una redirección meta refresh.")
        if result.auto_downloads:
            result.suspicious_findings.append(f"Hay {result.auto_downloads} enlace(s) con descarga automática declarada.")
        return result
    except Exception as exc:
        result.error = str(exc)
        return result

def reputation_urlhaus(url: str) -> dict[str, Any]:
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        return {
            "available": False,
            "configured": False,
            "error": "no configurado; falta URLHAUS_AUTH_KEY",
        }
    assert requests is not None
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            headers={"Auth-Key": auth_key, "User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        data = response.json()
        status = data.get("query_status")
        return {
            "available": True,
            "configured": True,
            "listed": status == "ok",
            "status": status,
            "threat": data.get("threat"),
            "url_status": data.get("url_status"),
            "tags": data.get("tags"),
        }
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        if status_code in {401, 403}:
            message = "servicio no disponible o acceso no autorizado"
        elif status_code == 429:
            message = "límite temporal de consultas alcanzado"
        elif status_code:
            message = f"servicio no disponible (HTTP {status_code})"
        else:
            message = "servicio no disponible"
        return {
            "available": False,
            "error": message,
            "http_status": status_code,
        }
    except Exception:
        return {
            "available": False,
            "error": "servicio no disponible",
        }


def _phishstats_rows(payload: Any) -> list[dict[str, Any]]:
    """Normaliza la respuesta JSON de PhishStats a una lista de registros."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "rows"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _load_phishstats_cache() -> dict[str, Any]:
    try:
        if PHISHSTATS_CACHE_FILE.exists():
            data = json.loads(PHISHSTATS_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_phishstats_cache(cache: dict[str, Any]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        PHISHSTATS_CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception:
        pass


def reputation_phishstats(url: str) -> dict[str, Any]:
    """Consulta PhishStats para una coincidencia exacta de la URL.

    La consulta read-only puede realizarse sin clave. Si existe
    PHISHSTATS_API_KEY se envía como X-API-Key. Los resultados se almacenan
    durante 90 minutos para reducir consumo de cuota y evitar sondeo repetido.

    IMPORTANTE: esta fuente se presenta como inteligencia/reputación externa y
    no añade puntos a la puntuación heurística calibrada de URL Inspector 6.0.
    """
    assert requests is not None
    target = canonicalize_url_for_lookup(url)
    cache_key = hashlib.sha256(target.encode("utf-8", errors="ignore")).hexdigest()
    cache = _load_phishstats_cache()
    cached = cache.get(cache_key)
    now_ts = datetime.now(timezone.utc).timestamp()
    if isinstance(cached, dict):
        checked_ts = cached.get("checked_ts")
        result = cached.get("result")
        if isinstance(checked_ts, (int, float)) and isinstance(result, dict):
            if now_ts - float(checked_ts) <= PHISHSTATS_CACHE_MAX_AGE_SECONDS:
                out = dict(result)
                out["cached"] = True
                return out

    headers = {"User-Agent": USER_AGENT}
    api_key = os.getenv("PHISHSTATS_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        # PhishStats expone el SHA-256 exacto de la URL en el campo ``hash``.
        # Consultar por hash evita problemas de sintaxis en ``_where`` cuando la URL
        # contiene paréntesis, comas u otros caracteres significativos para el parser
        # de filtros. Después se confirma localmente la URL canónica para mantener
        # una coincidencia estrictamente exacta.
        response = requests.get(
            PHISHSTATS_API_URL,
            params={"_where": f"(hash,eq,{cache_key})", "_sort": "-id", "_size": 20},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            headers=headers,
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            result = {
                "available": False,
                "configured": bool(api_key),
                "error": "límite temporal de consultas alcanzado",
                "http_status": 429,
                "retry_after": retry_after,
            }
            return result
        response.raise_for_status()
        rows = _phishstats_rows(response.json())
        matched: dict[str, Any] | None = None
        for row in rows:
            candidate = str(row.get("url") or row.get("URL") or "").strip()
            if candidate and canonicalize_url_for_lookup(candidate) == target:
                matched = row
                break

        result = {
            "available": True,
            "configured": bool(api_key),
            "listed": matched is not None,
            "matched_url": (str(matched.get("url")) if matched else None),
            "record_id": (str(matched.get("id")) if matched and matched.get("id") is not None else None),
            "date": (matched.get("date") if matched else None),
            "date_update": (matched.get("date_update") if matched else None),
            "score": (matched.get("score") if matched else None),
            "title": (matched.get("title") if matched else None),
            "host": (matched.get("host") if matched else None),
            "domain": (matched.get("domain") if matched else None),
            "source": "PhishStats",
            "cached": False,
        }
        cache[cache_key] = {"checked_ts": now_ts, "result": result}
        # Acotamos el crecimiento del fichero de caché.
        if len(cache) > 500:
            ordered = sorted(
                cache.items(),
                key=lambda kv: float(kv[1].get("checked_ts", 0)) if isinstance(kv[1], dict) else 0,
                reverse=True,
            )[:500]
            cache = dict(ordered)
        _save_phishstats_cache(cache)
        return result
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        return {
            "available": False,
            "configured": bool(api_key),
            "error": f"servicio no disponible (HTTP {status_code})" if status_code else "servicio no disponible",
            "http_status": status_code,
        }
    except Exception as exc:
        return {
            "available": False,
            "configured": bool(api_key),
            "error": f"servicio no disponible ({exc})",
        }


def _parse_reputation_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def phishstats_operational_assessment(source: dict[str, Any] | None) -> dict[str, Any]:
    """Clasifica una coincidencia PhishStats para el veredicto operativo.

    PhishStats conserva registros históricos. URL Inspector no considera una
    coincidencia histórica y de baja confianza como reputación negativa actual
    por sí sola. La coincidencia sigue mostrándose como antecedente.

    Política local de URL Inspector (no altera el score heurístico):
    - registro de hasta 90 días: alerta reputacional actual;
    - phishscore >= 5: alerta aunque el registro sea más antiguo;
    - registro > 90 días y phishscore < 5: antecedente histórico a verificar.
    Si fecha o score no pueden interpretarse, se adopta el criterio conservador
    y la coincidencia se mantiene como alerta actual.
    """
    src = source or {}
    listed = bool(src.get("listed"))
    if not listed:
        return {"listed": False, "negative": False, "advisory": False, "age_days": None, "score": None}

    score_value = src.get("score")
    score: float | None = None
    if score_value not in (None, ""):
        try:
            score = float(score_value)
        except (TypeError, ValueError):
            score = None

    # date_update, cuando existe, representa una observación más reciente.
    dt = _parse_reputation_datetime(src.get("date_update")) or _parse_reputation_datetime(src.get("date"))
    age_days: int | None = None
    if dt is not None:
        age_days = max(0, (datetime.now(timezone.utc) - dt).days)

    if age_days is None:
        negative = True
        reason = "fecha no interpretable; criterio conservador"
    elif age_days <= PHISHSTATS_OPERATIONAL_RECENT_DAYS:
        negative = True
        reason = f"registro reciente ({age_days} días)"
    elif score is None:
        negative = True
        reason = "registro histórico sin phishscore interpretable; criterio conservador"
    elif score >= PHISHSTATS_HIGH_CONFIDENCE_SCORE:
        negative = True
        reason = f"phishscore {score:g} >= {PHISHSTATS_HIGH_CONFIDENCE_SCORE:g}"
    else:
        negative = False
        reason = (
            f"registro histórico ({age_days} días) y phishscore {score:g} < "
            f"{PHISHSTATS_HIGH_CONFIDENCE_SCORE:g}"
        )

    return {
        "listed": True,
        "negative": negative,
        "advisory": not negative,
        "age_days": age_days,
        "score": score,
        "reason": reason,
    }


def _vt_request(path: str) -> dict[str, Any]:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return {"available": False, "configured": False}
    assert requests is not None
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/{path.lstrip('/')}",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
        if response.status_code == 404:
            return {"available": False, "configured": True, "not_found": True}
        response.raise_for_status()
        return {"available": True, "configured": True, "data": response.json().get("data", {})}
    except Exception as exc:
        return {"available": False, "configured": True, "error": str(exc)}


def reputation_virustotal(url: str) -> dict[str, Any]:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    raw = _vt_request(f"urls/{url_id}")
    if not raw.get("available"):
        return raw
    attributes = raw.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    categories = attributes.get("categories", {}) or {}
    engines_total = sum(int(stats.get(k, 0) or 0) for k in ("harmless", "malicious", "suspicious", "undetected", "timeout"))
    return {
        "available": True,
        "configured": True,
        "stats": stats,
        "engines_total": engines_total,
        "harmless": int(stats.get("harmless", 0) or 0),
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "last_analysis_date": utc_iso_from_epoch(attributes.get("last_analysis_date")),
        "first_submission_date": utc_iso_from_epoch(attributes.get("first_submission_date")),
        "last_submission_date": utc_iso_from_epoch(attributes.get("last_submission_date")),
        "times_submitted": attributes.get("times_submitted"),
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes") or {},
        "categories": categories,
        "category_values": sorted({str(v) for v in categories.values() if v}),
        "tags": attributes.get("tags") or [],
        "main_brand": attributes.get("main_brand"),
        "targeted_brand": attributes.get("targeted_brand") or {},
        "title": attributes.get("title"),
        "last_final_url": attributes.get("last_final_url"),
    }


def reputation_virustotal_domain(domain: str) -> dict[str, Any]:
    raw = _vt_request(f"domains/{domain}")
    if not raw.get("available"):
        return raw
    a = raw.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {}) or {}
    popularity = a.get("popularity_ranks", {}) or {}
    ranked = sorted(
        [
            {"source": name, "rank": info.get("rank"), "timestamp": utc_iso_from_epoch(info.get("timestamp"))}
            for name, info in popularity.items() if isinstance(info, dict) and isinstance(info.get("rank"), int)
        ],
        key=lambda item: item["rank"],
    )
    return {
        "available": True,
        "configured": True,
        "stats": stats,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "reputation": a.get("reputation"),
        "categories": a.get("categories") or {},
        "popularity_ranks": ranked,
        "best_popularity_rank": ranked[0] if ranked else None,
        "last_analysis_date": utc_iso_from_epoch(a.get("last_analysis_date")),
        "creation_date": utc_iso_from_epoch(a.get("creation_date")),
        "registrar": a.get("registrar"),
        "tags": a.get("tags") or [],
        "total_votes": a.get("total_votes") or {},
    }


def reputation_virustotal_ips(ips: list[str]) -> dict[str, Any]:
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        return {"available": False, "configured": False, "results": {}}
    results: dict[str, Any] = {}
    for ip in ips[:4]:
        raw = _vt_request(f"ip_addresses/{ip}")
        if not raw.get("available"):
            results[ip] = {k: v for k, v in raw.items() if k != "data"}
            continue
        a = raw.get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {}) or {}
        results[ip] = {
            "available": True,
            "asn": a.get("asn"),
            "as_owner": a.get("as_owner"),
            "reputation": a.get("reputation"),
            "last_analysis_date": utc_iso_from_epoch(a.get("last_analysis_date")),
            "stats": stats,
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "total_votes": a.get("total_votes") or {},
            "tags": a.get("tags") or [],
            "network": a.get("network"),
            "country": a.get("country"),
        }
    return {"available": any(v.get("available") for v in results.values()), "configured": True, "results": results}


def reputation_openphish(url: str) -> dict[str, Any]:
    assert requests is not None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        use_cache = False
        if OPENPHISH_CACHE_FILE.exists():
            age = datetime.now().timestamp() - OPENPHISH_CACHE_FILE.stat().st_mtime
            use_cache = age <= OPENPHISH_CACHE_MAX_AGE_SECONDS
        if not use_cache:
            response = requests.get(
                OPENPHISH_COMMUNITY_FEED_URL,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
            )
            response.raise_for_status()
            OPENPHISH_CACHE_FILE.write_text(response.text, encoding="utf-8")
        target = canonicalize_url_for_lookup(url)
        matched: str | None = None
        count = 0
        for raw in OPENPHISH_CACHE_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            candidate = raw.strip()
            if not candidate:
                continue
            count += 1
            if canonicalize_url_for_lookup(candidate) == target:
                matched = candidate
                break
        return {
            "available": True,
            "listed": matched is not None,
            "matched_url": matched,
            "feed_entries_checked": count,
            "feed": "OpenPhish Community",
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def _truthy_api(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def reputation_phishtank(url: str) -> dict[str, Any]:
    assert requests is not None
    key = os.getenv("PHISHTANK_APP_KEY")
    payload: dict[str, Any] = {"url": url, "format": "json"}
    if key:
        payload["app_key"] = key
    try:
        response = requests.post(
            PHISHTANK_CHECK_URL,
            data=payload,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            headers={"User-Agent": f"URL-Inspector/{VERSION}"},
        )
        response.raise_for_status()
        data = response.json()
        item = data.get("results") or {}
        in_database = _truthy_api(item.get("in_database"))
        verified = _truthy_api(item.get("verified"))
        valid = _truthy_api(item.get("valid"))
        return {
            "available": True,
            "configured": bool(key),
            "in_database": in_database,
            "verified": verified,
            "valid": valid,
            "listed": in_database and verified and valid,
            "phish_id": item.get("phish_id"),
            "phish_detail_page": item.get("phish_detail_page"),
            "verified_at": item.get("verified_at"),
            "submitted_at": item.get("submitted_at"),
            "rate_limit": {
                "limit": response.headers.get("X-Request-Limit"),
                "count": response.headers.get("X-Request-Count"),
                "interval": response.headers.get("X-Request-Limit-Interval"),
            },
        }
    except Exception as exc:
        return {"available": False, "configured": bool(key), "error": str(exc)}



def reputation_google_safe_browsing(url: str) -> dict[str, Any]:
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return {"available": False, "configured": False}
    assert requests is not None
    try:
        payload = {
            "client": {"clientId": "url-inspector", "clientVersion": VERSION},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=payload,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        matches = response.json().get("matches", [])
        return {
            "available": True,
            "configured": True,
            "listed": bool(matches),
            "matches": matches,
        }
    except Exception as exc:
        return {"available": False, "configured": True, "error": str(exc)}


def reputation_abuseipdb(ips: list[str]) -> dict[str, Any]:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return {"available": False, "configured": False}
    assert requests is not None
    results: dict[str, Any] = {}
    for ip in ips:
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": key, "Accept": "application/json", "User-Agent": USER_AGENT},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            results[ip] = {
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
            }
        except Exception as exc:
            results[ip] = {"error": str(exc)}
    return {"available": True, "configured": True, "results": results}


URL_REPUTATION_KEYS: tuple[str, ...] = (
    "urlhaus",
    "phishstats",
    "openphish",
    "phishtank",
    "virustotal",
    "google_safe_browsing",
)


def inspect_url_reputation(url: str) -> dict[str, Any]:
    """Evalúa exclusivamente fuentes reputacionales a nivel de URL.

    Esta función se usa para comprobar tanto la URL introducida como la URL
    final observada después de redirecciones. La puntuación heurística sigue
    utilizando la reputación de la URL final, tal como se calibró; las
    coincidencias adicionales de la URL introducida alimentan únicamente el
    veredicto operativo y los informes.
    """
    return {
        "urlhaus": reputation_urlhaus(url),
        "phishstats": reputation_phishstats(url),
        "openphish": reputation_openphish(url),
        "phishtank": reputation_phishtank(url),
        "virustotal": reputation_virustotal(url),
        "google_safe_browsing": reputation_google_safe_browsing(url),
    }


def inspect_reputation(url: str, ips: list[str], domain: str) -> dict[str, Any]:
    result = inspect_url_reputation(url)
    result.update({
        "virustotal_domain": reputation_virustotal_domain(domain),
        "virustotal_ips": reputation_virustotal_ips(ips),
        "abuseipdb": reputation_abuseipdb(ips),
    })
    result["_scope"] = {
        "operational_urls_checked": [url],
        "heuristic_score_url": url,
    }
    return result


def _url_reputation_negative(key: str, source: dict[str, Any]) -> bool:
    if not isinstance(source, dict):
        return False
    if key == "phishstats":
        return bool(phishstats_operational_assessment(source).get("negative"))
    if key in {"urlhaus", "openphish", "phishtank", "google_safe_browsing"}:
        return bool(source.get("listed"))
    if key == "virustotal":
        return bool(source.get("available") and int(source.get("malicious", 0) or 0) > 0)
    return False


def merge_operational_reputation(
    scoring_reputation: dict[str, Any],
    input_url_reputation: dict[str, Any] | None,
    *,
    initial_url: str,
    final_url: str,
) -> dict[str, Any]:
    """Combina reputación de URL inicial/final sin alterar la base del score.

    Si una fuente marca cualquiera de las dos URLs, se conserva la coincidencia
    para el veredicto operativo. En ausencia de coincidencia se prefiere una
    respuesta evaluable frente a una no disponible. Los resultados de dominio e
    IP proceden siempre del análisis de la URL final.
    """
    merged = dict(scoring_reputation or {})
    initial_canonical = canonicalize_url_for_lookup(initial_url)
    final_canonical = canonicalize_url_for_lookup(final_url)
    checked = [initial_url]
    if final_canonical != initial_canonical:
        checked.append(final_url)

    if input_url_reputation:
        for key in URL_REPUTATION_KEYS:
            final_source = dict((scoring_reputation or {}).get(key, {}) or {})
            input_source = dict(input_url_reputation.get(key, {}) or {})
            final_negative = _url_reputation_negative(key, final_source)
            input_negative = _url_reputation_negative(key, input_source)

            if input_negative and not final_negative:
                chosen = input_source
                matched_scope = "input_url"
                matched_url = initial_url
            elif final_negative:
                chosen = final_source
                matched_scope = "final_url"
                matched_url = final_url
            elif _reputation_source_evaluated(key, final_source):
                chosen = final_source
                matched_scope = "final_url"
                matched_url = final_url
            elif _reputation_source_evaluated(key, input_source):
                chosen = input_source
                matched_scope = "input_url"
                matched_url = initial_url
            else:
                chosen = final_source if final_source else input_source
                matched_scope = None
                matched_url = None

            chosen = dict(chosen or {})
            chosen["checked_urls"] = checked
            if matched_scope:
                chosen["result_scope"] = matched_scope
                chosen["result_url"] = matched_url
            merged[key] = chosen

    merged["_scope"] = {
        "operational_urls_checked": checked,
        "heuristic_score_url": final_url,
        "note": (
            "El veredicto operativo considera la URL introducida y la URL final; "
            "la puntuación heurística conserva como base reputacional la URL final calibrada."
        ),
    }
    return merged


def http_response_is_restricted(http: HTTPAnalysis | None) -> bool:
    """Indica si la respuesta parece un bloqueo, desafío o limitación de acceso."""
    return bool(
        http
        and http.status_code in {401, 403, 407, 429, 451, 503}
    )


REPUTATION_COVERAGE_SOURCES: tuple[tuple[str, str], ...] = (
    ("urlhaus", "URLhaus"),
    ("phishstats", "PhishStats"),
    ("openphish", "OpenPhish"),
    ("phishtank", "PhishTank"),
    ("virustotal", "VirusTotal URL"),
    ("google_safe_browsing", "Google Safe Browsing"),
    ("abuseipdb", "AbuseIPDB"),
)


def _reputation_source_evaluated(key: str, source: dict[str, Any]) -> bool:
    """Indica si una fuente reputacional produjo una respuesta utilizable."""
    if not isinstance(source, dict):
        return False
    if key == "virustotal":
        # Un 404 consultable significa que la fuente sí se evaluó, aunque no exista
        # un objeto de URL en VirusTotal.
        return bool(source.get("available") or (source.get("configured") and source.get("not_found")))
    if key == "abuseipdb":
        if not source.get("available"):
            return False
        results = source.get("results") or {}
        return any(
            isinstance(item, dict) and "error" not in item
            for item in results.values()
        )
    return source.get("available") is True


def reputation_coverage_summary(reputation: dict[str, Any] | None) -> dict[str, Any]:
    """Cobertura de fuentes reputacionales, independiente de la cobertura técnica."""
    rep = reputation or {}
    evaluated: list[str] = []
    unavailable: list[str] = []
    for key, label in REPUTATION_COVERAGE_SOURCES:
        if _reputation_source_evaluated(key, rep.get(key, {}) or {}):
            evaluated.append(label)
        else:
            unavailable.append(label)
    total = len(REPUTATION_COVERAGE_SOURCES)
    count = len(evaluated)
    percent = round((count / total) * 100) if total else 0
    return {
        "evaluated_count": count,
        "total_sources": total,
        "coverage_percent": percent,
        "evaluated_sources": evaluated,
        "unavailable_sources": unavailable,
        "text": f"{count}/{total} fuentes evaluadas",
    }


def negative_reputation_findings(reputation: dict[str, Any] | None) -> list[dict[str, str]]:
    """Devuelve coincidencias URL-level que constituyen reputación externa negativa."""
    rep = reputation or {}
    findings: list[dict[str, str]] = []

    if (rep.get("urlhaus") or {}).get("listed"):
        threat = (rep.get("urlhaus") or {}).get("threat")
        detail = "URL LISTADA EN URLHAUS" + (f" ({str(threat).upper()})" if threat else "")
        findings.append({"source": "URLhaus", "detail": detail})

    phishstats = rep.get("phishstats") or {}
    ps_assessment = phishstats_operational_assessment(phishstats)
    if ps_assessment.get("negative"):
        findings.append({"source": "PhishStats", "detail": "URL LISTADA COMO PHISHING EN PHISHSTATS"})

    if (rep.get("openphish") or {}).get("listed"):
        findings.append({"source": "OpenPhish", "detail": "URL LISTADA EN OPENPHISH"})

    if (rep.get("phishtank") or {}).get("listed"):
        findings.append({"source": "PhishTank", "detail": "PHISHING VERIFICADO Y VIGENTE EN PHISHTANK"})

    vt = rep.get("virustotal") or {}
    vt_malicious = int(vt.get("malicious", 0) or 0)
    if vt.get("available") and vt_malicious > 0:
        findings.append({
            "source": "VirusTotal",
            "detail": f"VIRUSTOTAL: {vt_malicious} MOTOR(ES) MARCAN LA URL COMO MALICIOSA",
        })

    if (rep.get("google_safe_browsing") or {}).get("listed"):
        findings.append({"source": "Google Safe Browsing", "detail": "COINCIDENCIA EN GOOGLE SAFE BROWSING"})

    return findings


def reputation_advisory_findings(reputation: dict[str, Any] | None) -> list[dict[str, str]]:
    """Antecedentes reputacionales que requieren contexto pero no alerta roja actual."""
    rep = reputation or {}
    findings: list[dict[str, str]] = []
    phishstats = rep.get("phishstats") or {}
    ps = phishstats_operational_assessment(phishstats)
    if ps.get("advisory"):
        parts = ["ANTECEDENTE HISTÓRICO EN PHISHSTATS"]
        if ps.get("age_days") is not None:
            parts.append(f"{ps['age_days']} DÍAS")
        if ps.get("score") is not None:
            parts.append(f"PHISHSCORE {ps['score']:g}")
        findings.append({"source": "PhishStats", "detail": " — ".join(parts)})
    return findings


def operational_verdict(
    reputation: dict[str, Any] | None, score: int, level: int
) -> dict[str, Any]:
    """Veredicto operativo separado de la puntuación heurística calibrada."""
    negative = negative_reputation_findings(reputation)
    advisory = reputation_advisory_findings(reputation)
    coverage = reputation_coverage_summary(reputation)
    if negative:
        return {
            "code": "REPUTATION_ALERT",
            "label": "ALERTA DE REPUTACIÓN",
            "message": "REPUTACIÓN NEGATIVA CONFIRMADA: " + " | ".join(item["detail"] for item in negative),
            "reputation_alert": True,
            "negative_sources": [item["source"] for item in negative],
            "technical_score": score,
            "technical_level": level,
            "reputation_coverage": coverage,
            "reputation_advisory": False,
        }

    if advisory:
        message = " | ".join(item["detail"] for item in advisory)
        return {
            "code": "REPUTATION_ADVISORY",
            "label": "ANTECEDENTE REPUTACIONAL — VERIFICAR",
            "message": message,
            "reputation_alert": False,
            "reputation_advisory": True,
            "negative_sources": [],
            "advisory_sources": [item["source"] for item in advisory],
            "technical_score": score,
            "technical_level": level,
            "reputation_coverage": coverage,
        }

    if level >= 5:
        label = "NO INTERACTUAR — RIESGO TÉCNICO CRÍTICO"
    elif level == 4:
        label = "NO INTERACTUAR SIN VERIFICACIÓN — RIESGO TÉCNICO MUY ALTO"
    elif level == 3:
        label = "CAUTELA REFORZADA — RIESGO TÉCNICO ALTO"
    elif level == 2:
        label = "CAUTELA — RIESGO TÉCNICO MODERADO"
    else:
        label = "SIN INDICIOS TÉCNICOS SUFICIENTES PARA ELEVAR EL RIESGO"

    return {
        "code": "TECHNICAL_ASSESSMENT",
        "label": label,
        "message": label,
        "reputation_alert": False,
        "reputation_advisory": False,
        "negative_sources": [],
        "advisory_sources": [],
        "technical_score": score,
        "technical_level": level,
        "reputation_coverage": coverage,
    }


def reputation_has_valid_result(reputation: dict[str, Any] | None) -> bool:
    """Comprueba si al menos una fuente de reputación produjo un resultado utilizable."""
    if not reputation:
        return False

    for key in ("urlhaus", "phishstats", "openphish", "phishtank", "virustotal", "virustotal_domain", "google_safe_browsing"):
        if reputation.get(key, {}).get("available"):
            return True

    abuse = reputation.get("abuseipdb", {})
    if abuse.get("available"):
        return any(
            isinstance(item, dict) and "error" not in item
            for item in abuse.get("results", {}).values()
        )
    return False


def parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def entropy(text: str) -> float:
    if not text:
        return 0.0
    frequencies = {char: text.count(char) / len(text) for char in set(text)}
    return -sum(prob * math.log2(prob) for prob in frequencies.values())


def calculate_risk(
    initial_url: str,
    final_url: str,
    chain: list[RedirectStep],
    resolution_error: str | None,
    rdap_data: dict[str, Any] | None,
    tls: TLSResult,
    identity: IdentityAnalysis | None = None,
    html: HTMLAnalysis | None = None,
    reputation: dict[str, Any] | None = None,
) -> tuple[int, int, list[RiskFactor]]:
    factors: list[RiskFactor] = []
    initial = urlsplit(initial_url)
    final = urlsplit(final_url)
    host = final.hostname or ""
    labels = host.split(".")
    tld = labels[-1].lower() if labels else ""
    decoded_url = unquote(final_url).lower()

    if initial.scheme.lower() == "http":
        factors.append(RiskFactor(10, "La URL inicial utiliza HTTP sin cifrado."))
    if final.scheme.lower() == "http":
        factors.append(RiskFactor(15, "La URL final utiliza HTTP sin cifrado."))
    if not tls.available:
        # La ausencia de TLS se observó también con frecuencia en referencias
        # benignas; se conserva como indicio menor y, sobre todo, de cobertura.
        factors.append(RiskFactor(4, "No se pudo establecer una conexión TLS."))
    elif not tls.valid:
        factors.append(RiskFactor(8, "El certificado TLS no supera la validación."))

    redirects = [step for step in chain if step.destination]
    if len(redirects) >= 5:
        factors.append(RiskFactor(4, f"Se detectaron {len(redirects)} redirecciones."))
    elif len(redirects) >= 3:
        factors.append(RiskFactor(2, f"Se detectaron {len(redirects)} redirecciones."))
    elif len(redirects) == 2:
        factors.append(RiskFactor(1, "Se detectaron dos redirecciones."))

    domains: set[str] = set()
    for step in chain:
        for candidate in (step.url, step.destination):
            if candidate:
                try:
                    domains.add(registered_domain(hostname_from_url(candidate)))
                except Exception:
                    pass
    if len(domains) >= 4:
        factors.append(RiskFactor(5, f"La cadena atraviesa {len(domains)} dominios distintos."))
    elif len(domains) == 3:
        factors.append(RiskFactor(3, "La cadena atraviesa tres dominios distintos."))
    elif len(domains) == 2:
        factors.append(RiskFactor(1, "La redirección cambia de dominio registrable."))

    if is_ip_literal(host):
        factors.append(RiskFactor(18, "La URL utiliza una dirección IP en vez de un dominio."))
    if "@" in final.netloc:
        factors.append(RiskFactor(20, "La URL contiene el carácter @."))
    if host.startswith("xn--") or ".xn--" in host:
        factors.append(RiskFactor(8, "El dominio utiliza Punycode."))

    if identity:
        if identity.confusable_characters:
            detail = ", ".join(identity.confusable_characters[:6])
            points = 25 if identity.mixed_scripts else 15
            factors.append(RiskFactor(points, f"Se detectaron homoglifos Unicode/confusables en el dominio: {detail}."))
        if identity.typo_suspected and not identity.exact_reference:
            distance = identity.levenshtein_distance
            if identity.priority_reference:
                if distance == 0:
                    points = 30
                    reason = "una marca/dominio prioritario aparece incrustado en otro dominio"
                elif distance == 1:
                    points = 28
                    reason = "distancia de Levenshtein 1 frente a referencia prioritaria"
                else:
                    points = 18
                    reason = "distancia de Levenshtein 2 frente a referencia prioritaria"
            else:
                points = 12
                reason = "distancia de Levenshtein 1 frente a referencia genérica"
            factors.append(RiskFactor(
                points,
                f"Posible typosquatting frente a {identity.closest_reference_domain} ({reason}; token: {identity.compared_token})."
            ))
    if len(final_url) > 200:
        factors.append(RiskFactor(10, "La URL es excepcionalmente larga."))
    elif len(final_url) > 120:
        factors.append(RiskFactor(5, "La URL es larga."))
    if len(labels) >= 6:
        factors.append(RiskFactor(8, "El host contiene numerosos niveles de subdominio."))
    elif len(labels) == 5:
        factors.append(RiskFactor(5, "El host contiene varios niveles de subdominio."))
    if tld in SUSPICIOUS_TLDS:
        factors.append(RiskFactor(4, f"El TLD .{tld} es frecuente en registros baratos o efímeros."))

    hits = sorted(word for word in SUSPICIOUS_WORDS if word in decoded_url)
    if len(hits) >= 3:
        factors.append(RiskFactor(12, "La URL contiene varios términos sensibles: " + ", ".join(hits[:6])))
    elif hits:
        factors.append(RiskFactor(5, "La URL contiene términos sensibles: " + ", ".join(hits[:4])))

    random_labels = [
        label for label in labels[:-2]
        if RANDOM_LABEL_RE.match(label) and entropy(label) >= 3.2
    ]
    if random_labels:
        factors.append(RiskFactor(10, "Subdominios aparentemente automáticos: " + ", ".join(random_labels[:3])))

    host_brand_mentions = detect_brand_mentions(host, host, fuzzy=True)
    path_brand_mentions = detect_brand_mentions((final.path or "") + "?" + (final.query or ""), host)
    if host_brand_mentions:
        factors.append(RiskFactor(22, "El host contiene una marca prioritaria fuera de su dominio oficial: " + ", ".join(host_brand_mentions[:4]) + "."))
    elif path_brand_mentions:
        factors.append(RiskFactor(8, "La ruta o consulta menciona una marca prioritaria fuera de su dominio oficial: " + ", ".join(path_brand_mentions[:4]) + "."))

    shared_hosting, shared_domain = is_shared_hosting(host)
    if shared_hosting and (random_labels or hits or host_brand_mentions or path_brand_mentions):
        factors.append(RiskFactor(12, f"La URL usa hosting multiusuario ({shared_domain}) combinado con otros indicios de phishing."))

    if final.port and final.port not in {80, 443}:
        factors.append(RiskFactor(5, f"La URL utiliza un puerto no habitual: {final.port}."))

    creation_dt = parse_iso_datetime(rdap_creation_date(rdap_data or {}))
    if creation_dt:
        age_days = (datetime.now(timezone.utc) - creation_dt).days
        if age_days < 0:
            factors.append(RiskFactor(8, "La fecha de creación RDAP es anómala o futura."))
        elif age_days < 7:
            factors.append(RiskFactor(25, "El dominio fue creado hace menos de 7 días."))
        elif age_days < 30:
            factors.append(RiskFactor(20, "El dominio fue creado hace menos de 30 días."))
        elif age_days < 180:
            factors.append(RiskFactor(12, "El dominio fue creado hace menos de 6 meses."))
        elif age_days < 365:
            factors.append(RiskFactor(7, "El dominio fue creado hace menos de un año."))

    if html:
        if html.external_credential_forms:
            factors.append(RiskFactor(35, "Un formulario de credenciales envía datos a otro dominio."))
        elif html.external_action_forms:
            factors.append(RiskFactor(8, "Un formulario envía información a otro dominio."))

        # Las credenciales bajo HTTPS siguen siendo relevantes cuando aparecen
        # junto a identidad ajena, hosting multiusuario o dominio reciente.
        credential_context = bool(host_brand_mentions or path_brand_mentions or html.brand_mentions or shared_hosting)
        if html.password_fields and final.scheme.lower() != "https":
            factors.append(RiskFactor(25, "Solicita contraseñas sin HTTPS."))
        elif html.password_fields:
            factors.append(RiskFactor(4, "La página solicita contraseña mediante HTTPS."))
        if html.credential_fields and credential_context:
            factors.append(RiskFactor(16, "Solicita credenciales en un contexto con indicios de suplantación o hosting multiusuario."))
        if html.otp_fields and credential_context:
            factors.append(RiskFactor(8, "Solicita código OTP/PIN en un contexto sospechoso."))
        if html.brand_mentions and not host_brand_mentions and (html.credential_fields or shared_hosting):
            factors.append(RiskFactor(6, "El contenido menciona marcas prioritarias fuera de sus dominios oficiales en un contexto sensible: " + ", ".join(html.brand_mentions[:4]) + "."))
        if shared_hosting and html.credential_fields:
            factors.append(RiskFactor(10, f"El sitio solicita credenciales desde una plataforma multiusuario ({shared_domain})."))

        # En el benchmark 1.6 estas señales aisladas aparecieron también con
        # frecuencia en sitios legítimos; quedan como indicios menores.
        if html.hidden_iframes:
            factors.append(RiskFactor(2, "La página contiene iframes ocultos."))
        if html.obfuscation_hits >= 3:
            factors.append(RiskFactor(4, "Se detectó JavaScript potencialmente ofuscado."))
        elif html.obfuscation_hits:
            factors.append(RiskFactor(1, "Hay indicios menores de JavaScript ofuscado."))
        if html.meta_refresh:
            factors.append(RiskFactor(1, "La página usa meta refresh."))

    if reputation:
        urlhaus = reputation.get("urlhaus", {})
        if urlhaus.get("listed"):
            factors.append(RiskFactor(45, "La URL aparece listada en URLhaus."))
        openphish = reputation.get("openphish", {})
        if openphish.get("listed"):
            factors.append(RiskFactor(50, "La URL aparece en el feed Community de OpenPhish."))
        phishtank = reputation.get("phishtank", {})
        if phishtank.get("listed"):
            factors.append(RiskFactor(50, "PhishTank la identifica como phishing verificado y vigente."))
        vt = reputation.get("virustotal", {})
        malicious = int(vt.get("malicious", 0) or 0)
        suspicious = int(vt.get("suspicious", 0) or 0)
        if malicious >= 3:
            factors.append(RiskFactor(50, f"VirusTotal: {malicious} motores la marcan como maliciosa."))
        elif malicious:
            factors.append(RiskFactor(30, f"VirusTotal: {malicious} motor(es) la marcan como maliciosa."))
        elif suspicious:
            factors.append(RiskFactor(15, f"VirusTotal: {suspicious} motor(es) la consideran sospechosa."))
        vt_domain = reputation.get("virustotal_domain", {})
        if not malicious and int(vt_domain.get("malicious", 0) or 0) >= 3:
            factors.append(RiskFactor(20, "VirusTotal detecta señales maliciosas a nivel de dominio."))
        vt_ips = reputation.get("virustotal_ips", {})
        if any(int(v.get("malicious", 0) or 0) >= 5 for v in vt_ips.get("results", {}).values() if isinstance(v, dict)):
            factors.append(RiskFactor(10, "VirusTotal detecta una reputación técnica negativa en al menos una IP del alojamiento."))
        gsb = reputation.get("google_safe_browsing", {})
        if gsb.get("listed"):
            factors.append(RiskFactor(50, "Google Safe Browsing ha devuelto una coincidencia."))
        abuse = reputation.get("abuseipdb", {})
        for ip_data in abuse.get("results", {}).values():
            score = ip_data.get("abuse_confidence_score")
            if isinstance(score, int) and score >= 75:
                factors.append(RiskFactor(20, f"Una IP tiene AbuseIPDB {score}/100."))
                break

    score = min(100, sum(item.points for item in factors))
    level = 1 if score <= 7 else 2 if score <= 19 else 3 if score <= 29 else 4 if score <= 49 else 5
    return score, level, factors


def print_geolocation(ips: list[str], geo: dict[str, dict[str, Any]]) -> None:
    heading("DIRECCIONES IP Y GEOLOCALIZACIÓN APROXIMADA")
    for ip in ips:
        print(f"\nIP: {ip}")
        data = geo.get(ip)
        if not data:
            print("  No se obtuvieron datos geográficos.")
            continue
        connection = data.get("connection") or {}
        timezone_data = data.get("timezone") or {}
        fields = [
            ("Tipo", data.get("type")), ("Continente", data.get("continent")),
            ("País", data.get("country")), ("Código de país", data.get("country_code")),
            ("Región", data.get("region")), ("Ciudad", data.get("city")),
            ("Código postal", data.get("postal")), ("Latitud", data.get("latitude")),
            ("Longitud", data.get("longitude")), ("Zona horaria", timezone_data.get("id")),
            ("ASN", connection.get("asn")), ("Organización", connection.get("org")),
            ("Proveedor", connection.get("isp")), ("Dominio de red", connection.get("domain")),
        ]
        for label, value in fields:
            if value not in (None, ""):
                print(f"  {label}: {value}")


def print_dns(data: dict[str, Any]) -> None:
    heading("CONFIGURACIÓN DNS")
    for key in ("A", "AAAA", "CNAME", "MX", "NS", "SPF", "DMARC", "CAA"):
        values = data.get(key, [])
        print(f"\n{key}:")
        if values:
            for value in values:
                print(f"  - {value}")
        else:
            print("  no disponible")
    print("\nDNSSEC:")
    if data.get("dnssec_published"):
        print(f"  {GREEN}●{RESET} El dominio publica registros DNSKEY.")
        print("  Nota: esto no equivale a una validación completa de toda la cadena DNSSEC.")
    else:
        print(f"  {YELLOW}●{RESET} No se detectaron registros DNSKEY.")


def print_rdap(domain: str, data: dict[str, Any] | None, source: str | None = None) -> None:
    heading(f"RDAP DEL DOMINIO: {domain}")
    if not data:
        print("No se han obtenido datos RDAP.")
        return
    if source:
        print(f"Fuente RDAP: {source}")
    print(f"Dominio: {data.get('ldhName', domain)}")
    if data.get("handle"):
        print(f"Identificador: {data['handle']}")
    for label, value in [
        ("Fecha de creación", rdap_creation_date(data)),
        ("Última actualización", rdap_update_date(data)),
        ("Fecha de expiración", rdap_expiration_date(data)),
    ]:
        print(f"{label}: {value or 'no disponible en la respuesta RDAP'}")
    if data.get("status"):
        print("Estados:")
        for status in data["status"]:
            print(f"  - {status}")
    if data.get("nameservers"):
        print("Servidores DNS:")
        for item in data["nameservers"]:
            name = item.get("ldhName") or item.get("unicodeName")
            if name:
                print(f"  - {name}")



def print_identity(result: IdentityAnalysis) -> None:
    heading("IDENTIDAD DEL DOMINIO: TYPOSQUATTING Y HOMOGLIFOS")
    print(f"Host ASCII/IDNA: {result.ascii_host}")
    print(f"Host Unicode: {result.unicode_host}")
    print(f"Dominio registrable: {result.registered_domain}")
    if result.unicode_registered_domain and result.unicode_registered_domain != result.registered_domain:
        print(f"Dominio Unicode: {result.unicode_registered_domain}")
    print(f"Punycode: {'sí' if result.punycode else 'no'}")
    print(f"Scripts observados: {', '.join(result.scripts) if result.scripts else 'solo ASCII/no aplicable'}")
    print(f"Mezcla de scripts: {'sí' if result.mixed_scripts else 'no'}")
    if result.confusable_characters:
        print(f"{YELLOW}●{RESET} Homoglifos/confusables: {', '.join(result.confusable_characters)}")
        print(f"  Esqueleto visual aproximado: {result.confusable_skeleton}")
    else:
        print(f"{GREEN}●{RESET} No se detectaron homoglifos de la tabla de confusables aplicada.")

    print(f"\nLista de referencia: {result.reference_source or 'no disponible'}")
    print(f"Dominios de referencia cargados: {result.reference_count}")
    if result.error:
        print(f"{YELLOW}●{RESET} Aviso de lista de referencia: {result.error}")
    if result.exact_reference:
        print(f"{GREEN}●{RESET} El dominio coincide exactamente con una entrada de referencia.")
    elif result.typo_suspected:
        print(f"{RED}●{RESET} Posible typosquatting/impersonación.")
        print(f"  Referencia más próxima: {result.closest_reference_domain}")
        print(f"  Token comparado: {result.compared_token}")
        print(f"  Distancia de Levenshtein: {result.levenshtein_distance}")
    else:
        print(f"{GREEN}●{RESET} No se detectó una similitud de distancia 0-2 considerada sospechosa.")


def print_tls(result: TLSResult) -> None:
    heading(f"TLS/SSL: {result.host}:{result.port}")
    if not result.available:
        print(f"{YELLOW}●{RESET} No se pudo comprobar el certificado TLS.")
        print(f"Motivo: {result.error}")
        return
    if not result.valid:
        print(f"{RED}●{RESET} Certificado TLS no válido o no confiable.")
        print(f"Motivo: {result.error}")
        return

    print(f"{GREEN}●{RESET} Certificado TLS válido y confiable para la URL analizada.")
    print("  [OK] Periodo de vigencia comprobado.")
    print("  [OK] Cadena emitida por una AC confiable.")
    print(f"  [OK] Nombre del host verificado: {result.host}")
    if result.days_remaining is not None:
        print(f"  [INFO] Quedan {result.days_remaining} días hasta la caducidad.")
    if result.certificate_age_days is not None:
        print(f"  [INFO] Certificado emitido hace aproximadamente {result.certificate_age_days} día(s).")

    print("\nResumen del certificado:")
    print(f"  Tipo de validación: {result.validation_type or 'no determinable'}")
    if result.validation_type_basis:
        print(f"  Base de clasificación: {result.validation_type_basis}")
    if result.policy_oids:
        print(f"  OID de políticas: {', '.join(result.policy_oids)}")
    if result.subject_organization:
        print(f"  Organización validada declarada: {result.subject_organization}")
    print(f"  Autoridad certificadora: {result.issuer_common_name or result.issuer}")
    print(f"  Válido desde: {result.not_before}")
    print(f"  Válido hasta: {result.not_after}")
    print(f"  Versión TLS: {result.tls_version}")
    print(f"  Cifrado: {result.cipher}")
    print(f"  Algoritmo de firma: {result.signature_algorithm or 'no disponible'}")
    key = result.public_key_type or "no disponible"
    if result.public_key_bits:
        key += f", {result.public_key_bits} bits"
    print(f"  Clave pública: {key}")
    print(f"  Huella SHA-256: {result.sha256_fingerprint or 'no disponible'}")
    print(f"  Sujeto: {result.subject}")
    print(f"  Emisor completo: {result.issuer}")
    print(f"  Número de serie: {result.serial_number}")
    if result.sans:
        print("  Nombres alternativos (SAN):")
        for san_type, san_value in result.sans:
            print(f"    - {san_type}: {san_value}")
    if result.ocsp_urls:
        print("  Puntos OCSP publicados:")
        for url in result.ocsp_urls:
            print(f"    - {url}")
    if result.crl_urls:
        print("  Listas de revocación publicadas:")
        for url in result.crl_urls:
            print(f"    - {url}")
    print("  Nota: se muestran los puntos OCSP/CRL publicados; no se realiza una validación de revocación activa.")


def print_http(result: HTTPAnalysis) -> None:
    heading("HTTP Y CABECERAS DE SEGURIDAD")
    if result.error:
        print(f"No se pudo analizar HTTP: {result.error}")
        return
    print(f"Estado HTTP: {result.status_code}")
    print(f"Versión observada: {result.http_version or 'no disponible'}")
    print(f"Servidor declarado: {result.server or 'no declarado'}")
    print(f"Tipo de contenido: {result.content_type or 'no declarado'}")
    if http_response_is_restricted(result):
        print(
            f"\n{YELLOW}●{RESET} La respuesta HTTP {result.status_code} indica un posible "
            "bloqueo, desafío anti-bot o restricción de acceso."
        )
        print(
            "  Las cabeceras y el contenido analizados pueden pertenecer a esa respuesta "
            "intermedia y no representar necesariamente la página real."
        )
    print("\nCabeceras de seguridad:")
    for label, item in result.security_headers.items():
        if item["present"]:
            print(f"  {GREEN}●{RESET} {label}: {item['value']}")
        else:
            print(f"  {YELLOW}●{RESET} {label}: ausente")
    if result.cookies:
        secure_count = sum("secure" in item.lower() for item in result.cookies)
        httponly_count = sum("httponly" in item.lower() for item in result.cookies)
        samesite_count = sum("samesite" in item.lower() for item in result.cookies)
        print("\nCookies recibidas:")
        print(f"  Total: {len(result.cookies)}")
        print(f"  Secure: {secure_count}")
        print(f"  HttpOnly: {httponly_count}")
        print(f"  SameSite: {samesite_count}")


def print_html(result: HTMLAnalysis, http: HTTPAnalysis | None = None) -> None:
    heading("ANÁLISIS HEURÍSTICO DEL HTML")
    if not result.available:
        print(f"No se pudo analizar HTML: {result.error}")
        return
    if http_response_is_restricted(http):
        print(
            f"{YELLOW}●{RESET} El HTML procede de una respuesta HTTP {http.status_code}; "
            "puede corresponder a una página de bloqueo o desafío."
        )
        print("  No puede confirmarse que sea el HTML real del sitio solicitado.\n")
    print(f"Título: {result.title or 'no disponible'}")
    print(f"Formularios: {result.forms}")
    print(f"Formularios POST: {result.post_forms}")
    print(f"Formularios hacia otro dominio: {result.external_action_forms}")
    print(f"Campos de contraseña: {result.password_fields}")
    print(f"Campos de email: {result.email_fields}")
    print(f"Campos OTP/PIN: {result.otp_fields}")
    print(f"Campos relacionados con credenciales: {result.credential_fields}")
    print(f"Formularios de credenciales a dominio externo: {result.external_credential_forms}")
    if result.brand_mentions:
        print("Marcas prioritarias mencionadas fuera de dominio oficial: " + ", ".join(result.brand_mentions))
    print(f"Iframes: {result.iframes}")
    print(f"Iframes ocultos: {result.hidden_iframes}")
    print(f"Scripts externos: {result.external_scripts}")
    print(f"Scripts en línea: {result.inline_scripts}")
    print(f"Indicios de ofuscación: {result.obfuscation_hits}")
    print(f"Meta refresh: {result.meta_refresh or 'no'}")
    print(f"Enlaces de descarga declarados: {result.auto_downloads}")
    if result.external_domains:
        print("Dominios externos observados:")
        for domain in result.external_domains[:25]:
            print(f"  - {domain}")
    if result.suspicious_findings:
        print("\nHallazgos que requieren revisión:")
        for finding in result.suspicious_findings:
            print(f"  {YELLOW}●{RESET} {finding}")
    else:
        print(f"\n{GREEN}●{RESET} No se detectaron patrones HTML especialmente anómalos.")


def print_cdn(result: dict[str, Any]) -> None:
    heading("INFRAESTRUCTURA Y CDN")
    if result.get("detected"):
        print(f"{GREEN}●{RESET} Se detectó infraestructura CDN/proxy.")
        print("Proveedor(es): " + ", ".join(result.get("providers", [])))
        if result.get("evidence"):
            print("Evidencias:")
            for item in result["evidence"]:
                print(f"  - {item}")
    else:
        print(f"{YELLOW}●{RESET} No se identificó un CDN mediante las heurísticas disponibles.")
    print(
        "Nota: la detección es orientativa; una red puede ocultar o compartir "
        "infraestructura y no siempre revela su proveedor."
    )


def print_reputation(result: dict[str, Any]) -> None:
    heading("REPUTACIÓN")
    negative = negative_reputation_findings(result)
    advisory = reputation_advisory_findings(result)
    if negative:
        alert_text = "REPUTACIÓN NEGATIVA CONFIRMADA: " + " | ".join(item["detail"] for item in negative)
        print(f"{RED}{'!' * 78}")
        print(f"!!! ALERTA DE REPUTACIÓN: {alert_text} !!!")
        print(f"{'!' * 78}{RESET}\n")
    elif advisory:
        advisory_text = " | ".join(item["detail"] for item in advisory)
        print(f"{YELLOW}{'!' * 78}")
        print(f"!!! AVISO REPUTACIONAL: {advisory_text} !!!")
        print(f"{'!' * 78}{RESET}\n")
    urlhaus = result.get("urlhaus", {})
    if urlhaus.get("available"):
        if urlhaus.get("listed"):
            print(f"{RED}●{RESET} URLhaus: URL listada. Amenaza={urlhaus.get('threat')}; estado={urlhaus.get('url_status')}")
        else:
            print(f"{GREEN}●{RESET} URLhaus: sin coincidencia.")
    else:
        print(f"{YELLOW}●{RESET} URLhaus: {urlhaus.get('error', 'servicio no disponible')}.")

    phishstats = result.get("phishstats", {})
    if phishstats.get("available"):
        ps_assessment = phishstats_operational_assessment(phishstats)
        if phishstats.get("listed"):
            if ps_assessment.get("negative"):
                print(f"{RED}●{RESET} PhishStats: URL listada como phishing (alerta reputacional actual).")
            else:
                print(f"{YELLOW}●{RESET} PhishStats: antecedente histórico; no se eleva por sí solo a alerta roja actual.")
            details = []
            if phishstats.get("record_id"):
                details.append(f"ID={phishstats.get('record_id')}")
            if phishstats.get("date"):
                details.append(f"fecha={phishstats.get('date')}")
            if phishstats.get("score") is not None:
                details.append(f"score fuente={phishstats.get('score')}")
            if ps_assessment.get("age_days") is not None:
                details.append(f"antigüedad={ps_assessment.get('age_days')} días")
            if details:
                print("  " + " | ".join(details))
            if ps_assessment.get("negative"):
                print(f"  {YELLOW}Alerta de reputación externa: no modifica la puntuación heurística calibrada.{RESET}")
            else:
                print(f"  {YELLOW}Motivo: {ps_assessment.get('reason')}. Se conserva como antecedente para revisión.{RESET}")
        else:
            print(f"{GREEN}●{RESET} PhishStats: sin coincidencia exacta.")
        if phishstats.get("cached"):
            print("  Resultado reutilizado desde caché local (máx. 90 min).")
    else:
        extra = ""
        if phishstats.get("http_status") == 429 and phishstats.get("retry_after"):
            extra = f"; Retry-After={phishstats.get('retry_after')}"
        print(f"{YELLOW}●{RESET} PhishStats: no evaluado ({phishstats.get('error', 'sin detalle')}{extra}).")

    openphish = result.get("openphish", {})
    if openphish.get("available"):
        color = RED if openphish.get("listed") else GREEN
        text = "coincidencia exacta" if openphish.get("listed") else "sin coincidencia exacta"
        print(f"{color}●{RESET} OpenPhish Community: {text}.")
        if openphish.get("matched_url"):
            print(f"  Coincidencia: {openphish['matched_url']}")
    else:
        print(f"{YELLOW}●{RESET} OpenPhish: no evaluado ({openphish.get('error', 'sin detalle')}).")

    pt = result.get("phishtank", {})
    if pt.get("available"):
        color = RED if pt.get("listed") else GREEN
        text = "phishing verificado y vigente" if pt.get("listed") else "sin phishing verificado vigente"
        print(f"{color}●{RESET} PhishTank: {text}.")
        if not pt.get("configured"):
            print("  Consulta sin PHISHTANK_APP_KEY; el límite de peticiones es menor.")
        if pt.get("phish_id"):
            print(f"  ID: {pt.get('phish_id')} | verificado: {pt.get('verified')} | válido: {pt.get('valid')}")
    else:
        print(f"{YELLOW}●{RESET} PhishTank: no evaluado ({pt.get('error', 'sin detalle')}).")

    vt = result.get("virustotal", {})
    if not vt.get("configured", True):
        print(f"{YELLOW}●{RESET} VirusTotal: no configurado; falta VIRUSTOTAL_API_KEY.")
    elif not vt.get("available"):
        text = "URL no presente en el conjunto consultable" if vt.get("not_found") else vt.get("error", "sin detalle")
        print(f"{YELLOW}●{RESET} VirusTotal URL: {text}.")
    else:
        color = RED if vt.get("malicious") or vt.get("suspicious") else GREEN
        print(f"{color}●{RESET} VirusTotal URL:")
        print(f"  Motores analizados: {vt.get('engines_total', 0)}")
        print(f"  Maliciosos: {vt.get('malicious', 0)}")
        print(f"  Sospechosos: {vt.get('suspicious', 0)}")
        print(f"  Inofensivos: {vt.get('harmless', 0)}")
        print(f"  Sin detección: {vt.get('undetected', 0)}")
        print(f"  Último análisis: {vt.get('last_analysis_date') or 'no disponible'}")
        print(f"  Reputación comunitaria: {vt.get('reputation')}")
        if vt.get("category_values"):
            print(f"  Categorías: {', '.join(vt['category_values'][:8])}")
        if vt.get("main_brand"):
            print(f"  Marca principal/identidad: {vt['main_brand']}")
        if vt.get("targeted_brand"):
            print(f"  Marca objetivo reportada: {vt['targeted_brand']}")

    vtd = result.get("virustotal_domain", {})
    if vtd.get("available"):
        print("\nVirusTotal dominio:")
        print(f"  Reputación: {vtd.get('reputation')}")
        print(f"  Maliciosos: {vtd.get('malicious', 0)} | sospechosos: {vtd.get('suspicious', 0)}")
        best = vtd.get("best_popularity_rank")
        if best:
            print(f"  Mejor ranking de popularidad: {best.get('source')} #{best.get('rank')}")

    gsb = result.get("google_safe_browsing", {})
    if not gsb.get("configured", True):
        print(f"{YELLOW}●{RESET} Google Safe Browsing: no configurado.")
    elif gsb.get("available"):
        color = RED if gsb.get("listed") else GREEN
        text = "coincidencia detectada" if gsb.get("listed") else "sin coincidencias"
        print(f"{color}●{RESET} Google Safe Browsing: {text}.")
    else:
        print(f"{YELLOW}●{RESET} Google Safe Browsing: no evaluado ({gsb.get('error', 'sin detalle')}).")

    abuse = result.get("abuseipdb", {})
    if not abuse.get("configured", True):
        print(f"{YELLOW}●{RESET} AbuseIPDB: no configurado.")
    elif abuse.get("available"):
        print("\nAbuseIPDB por IP:")
        for ip, ip_data in abuse.get("results", {}).items():
            if "error" in ip_data:
                print(f"  {ip}: error ({ip_data['error']})")
            else:
                print(f"  {ip}: abuso={ip_data.get('abuse_confidence_score')}/100; reportes={ip_data.get('total_reports')}")

    vt_ips = result.get("virustotal_ips", {})
    if vt_ips.get("configured"):
        print("\nASN / reputación de IP (VirusTotal):")
        for ip, item in vt_ips.get("results", {}).items():
            if not item.get("available"):
                print(f"  {ip}: no evaluado")
                continue
            print(
                f"  {ip}: AS{item.get('asn')} {item.get('as_owner') or ''}; "
                f"reputación={item.get('reputation')}; maliciosos={item.get('malicious', 0)}; "
                f"sospechosos={item.get('suspicious', 0)}"
            )
        print("  Nota: la reputación mostrada corresponde a las IP observadas, no a una condena global del ASN/proveedor.")



def print_risk(score: int, level: int, factors: list[RiskFactor]) -> None:
    heading("ESTIMACIÓN HEURÍSTICA DE RIESGO DE PHISHING")
    descriptions = {
        1: "riesgo heurístico bajo",
        2: "riesgo heurístico moderado",
        3: "riesgo heurístico alto",
        4: "riesgo heurístico muy alto",
        5: "riesgo heurístico crítico",
    }
    print(f"Resultado: {level}/5 — {descriptions[level]}")
    print(f"Puntuación técnica interna: {score}/100")
    if factors:
        print("\nIndicios que han influido:")
        for factor in sorted(factors, key=lambda item: item.points, reverse=True):
            print(f"  +{factor.points:02d}  {factor.description}")
    else:
        print("\nNo se detectaron indicios técnicos significativos.")
    print(
        "\nAdvertencia: esta escala es heurística. Un resultado bajo no garantiza "
        "que una página sea legítima y uno alto no constituye por sí solo una prueba forense."
    )


def executive_summary(
    domain: str,
    resolution_error: str | None,
    rdap_data: dict[str, Any] | None,
    tls: TLSResult,
    identity: IdentityAnalysis | None,
    dns_data: dict[str, Any] | None,
    http: HTTPAnalysis | None,
    html: HTMLAnalysis | None,
    cdn: dict[str, Any] | None,
    reputation: dict[str, Any] | None,
    score: int,
    level: int,
) -> dict[str, Any]:
    restricted_response = http_response_is_restricted(http)

    # 1.14: la cobertura técnica excluye por completo las fuentes reputacionales.
    # Se conservan los pesos técnicos históricos (80 puntos) y se normalizan a 100.
    coverage_components = {
        "url_resolution": resolution_error is None,
        "rdap": rdap_data is not None,
        "tls": bool(tls.available),
        "http": bool(http is not None and not http.error),
        "html": bool(html is not None and html.available and not restricted_response),
    }
    coverage_weights = {
        "url_resolution": 20, "rdap": 15, "tls": 15,
        "http": 15, "html": 15,
    }
    raw_technical = sum(coverage_weights[k] for k, ok in coverage_components.items() if ok)
    technical_total = sum(coverage_weights.values())
    coverage = round((raw_technical / technical_total) * 100) if technical_total else 0

    rep_coverage = reputation_coverage_summary(reputation)
    verdict = operational_verdict(reputation, score, level)
    negative = negative_reputation_findings(reputation)
    advisory = reputation_advisory_findings(reputation)

    tls_status = "correcto" if tls.valid else "no válido" if tls.available else "indeterminado"
    dns_status = "analizado" if dns_data else "no analizado"
    headers_present = 0
    headers_total = 0
    if http:
        headers_total = len(http.security_headers)
        headers_present = sum(1 for item in http.security_headers.values() if item.get("present"))

    if restricted_response:
        html_status = f"respuesta HTTP {http.status_code}; HTML real no confirmado"
    elif not html or not html.available:
        html_status = "no analizado"
    elif html.suspicious_findings:
        html_status = f"{len(html.suspicious_findings)} hallazgo(s) a revisar"
    else:
        html_status = "sin anomalías destacadas"

    if negative:
        reputation_status = "REPUTACIÓN NEGATIVA: " + " | ".join(item["detail"] for item in negative)
    elif advisory:
        reputation_status = "ANTECEDENTE REPUTACIONAL: " + " | ".join(item["detail"] for item in advisory)
    elif rep_coverage["evaluated_count"]:
        reputation_status = (
            "sin coincidencias negativas en las fuentes evaluadas; cobertura parcial"
            if rep_coverage["evaluated_count"] < rep_coverage["total_sources"]
            else "sin coincidencias negativas en las fuentes evaluadas"
        )
    else:
        reputation_status = "no evaluada"

    return {
        "domain": domain,
        "tls": tls_status,
        "tls_validation_type": tls.validation_type or "no determinable",
        "tls_certificate_age_days": tls.certificate_age_days,
        "identity": (
            f"posible typosquatting de {identity.closest_reference_domain}"
            if identity and identity.typo_suspected and not identity.exact_reference
            else "homoglifos Unicode detectados"
            if identity and identity.confusable_characters
            else "sin coincidencias sospechosas"
            if identity
            else "no analizada"
        ),
        "dns": dns_status,
        "security_headers": (
            f"{headers_present}/{headers_total} (respuesta restringida)"
            if headers_total and restricted_response
            else f"{headers_present}/{headers_total}"
            if headers_total
            else "no analizadas"
        ),
        "http_restricted": restricted_response,
        "html": html_status,
        "cdn": ", ".join((cdn or {}).get("providers", [])) or "no identificado",
        "reputation": reputation_status,
        "reputation_alert": bool(negative),
        "reputation_alert_sources": [item["source"] for item in negative],
        "reputation_alert_text": verdict["message"] if negative else None,
        "reputation_advisory": bool(advisory),
        "reputation_advisory_sources": [item["source"] for item in advisory],
        "reputation_advisory_text": verdict["message"] if advisory else None,
        "reputation_coverage_evaluated": rep_coverage["evaluated_count"],
        "reputation_coverage_total": rep_coverage["total_sources"],
        "reputation_coverage_percent": rep_coverage["coverage_percent"],
        "reputation_coverage_sources": rep_coverage["evaluated_sources"],
        "reputation_unavailable_sources": rep_coverage["unavailable_sources"],
        "operational_verdict": verdict["label"],
        "operational_verdict_code": verdict["code"],
        "phishing_level": level,
        "phishing_score": score,
        "analysis_coverage_score": coverage,
        "analysis_coverage_components": coverage_components,
        # Alias de compatibilidad: desde 1.14 equivale exclusivamente a la
        # cobertura técnica normalizada, sin reputación.
        "confidence_score": coverage,
    }


def print_summary(summary: dict[str, Any]) -> None:
    heading("RESUMEN EJECUTIVO")
    coverage = summary.get("analysis_coverage_score", summary.get("confidence_score", 0))
    color = GREEN if coverage >= 80 else YELLOW if coverage >= 50 else RED
    print(f"Dominio: {summary['domain']}")
    print(f"TLS: {summary['tls']} | validación: {summary.get('tls_validation_type')}")
    if summary.get("tls_certificate_age_days") is not None:
        print(f"Edad del certificado TLS: {summary['tls_certificate_age_days']} día(s)")
    print(f"Identidad del dominio: {summary.get('identity')}")
    print(f"DNS: {summary['dns']}")
    print(f"Cabeceras de seguridad presentes: {summary['security_headers']}")
    print(f"HTML: {summary['html']}")
    print(f"CDN/proxy: {summary['cdn']}")
    if summary.get("reputation_alert"):
        rep_text = str(summary["reputation"])
        if rep_text.upper().startswith("REPUTACIÓN NEGATIVA: "):
            rep_text = rep_text[len("REPUTACIÓN NEGATIVA: "):]
        print(f"{RED}REPUTACIÓN: {rep_text.upper()}{RESET}")
        print(f"{RED}{'!' * 78}")
        print(f"VEREDICTO OPERATIVO: ALERTA DE REPUTACIÓN")
        print(f"{str(summary.get('reputation_alert_text') or '').upper()}")
        print(f"{'!' * 78}{RESET}")
    elif summary.get("reputation_advisory"):
        print(f"{YELLOW}Reputación: {summary['reputation']}{RESET}")
        print(f"{YELLOW}Veredicto operativo: {summary.get('operational_verdict')}{RESET}")
        print(f"{YELLOW}{summary.get('reputation_advisory_text') or ''}{RESET}")
    else:
        print(f"Reputación: {summary['reputation']}")
        print(f"Veredicto operativo: {summary.get('operational_verdict')}")
    print(f"Riesgo heurístico de phishing: {summary['phishing_level']}/5 ({summary.get('phishing_score')}/100)")
    print(f"Cobertura técnica del análisis: {color}{coverage}/100{RESET}")
    rep_count = summary.get("reputation_coverage_evaluated", 0)
    rep_total = summary.get("reputation_coverage_total", 0)
    rep_pct = summary.get("reputation_coverage_percent", 0)
    rep_color = GREEN if rep_count == rep_total and rep_total else YELLOW if rep_count else RED
    print(f"Cobertura reputacional: {rep_color}{rep_count}/{rep_total} fuentes evaluadas ({rep_pct}%){RESET}")
    if summary.get("http_restricted"):
        print(
            f"\n{YELLOW}●{RESET} Cobertura limitada: el servidor devolvió una respuesta "
            "de bloqueo, desafío o restricción, por lo que no se verificó el contenido real."
        )
    print(
        "\nLa cobertura técnica y la reputacional son métricas distintas y ninguna equivale a legitimidad. "
        "La puntuación heurística debe contrastarse con las alertas de reputación, el contexto, el contenido y la identidad declarada."
    )


def build_output(
    *,
    full_mode: bool,
    initial_url: str,
    final_url: str,
    chain: list[RedirectStep],
    resolution_error: str | None,
    final_host: str,
    domain: str,
    ips: list[str],
    geo: dict[str, dict[str, Any]],
    dns_data: dict[str, Any] | None,
    rdap_data: dict[str, Any] | None,
    rdap_source: str | None,
    rdap_error: str | None,
    tls_result: TLSResult,
    identity_result: IdentityAnalysis,
    http_result: HTTPAnalysis | None,
    html_result: HTMLAnalysis | None,
    cdn_result: dict[str, Any] | None,
    reputation_result: dict[str, Any] | None,
    screenshot_result: ScreenshotResult | None,
    score: int,
    level: int,
    factors: list[RiskFactor],
    summary: dict[str, Any],
) -> dict[str, Any]:
    creation = parse_iso_datetime(rdap_creation_date(rdap_data or {}))
    domain_age_days = None
    if creation:
        domain_age_days = max(0, (datetime.now(timezone.utc) - creation).days)
    return {
        "program_version": VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "full_mode": full_mode,
        "input_url": initial_url,
        "final_url": final_url,
        "url_resolution": {
            "complete": resolution_error is None,
            "error": resolution_error,
        },
        "redirect_chain": [asdict(step) for step in chain],
        "final_host": final_host,
        "registered_domain": domain,
        "identity_analysis": asdict(identity_result),
        "ips": ips,
        "geolocation": geo,
        "dns": dns_data,
        "rdap": {
            "available": rdap_data is not None,
            "source": rdap_source,
            "error": rdap_error,
            "domain_age_days": domain_age_days,
            "response": rdap_data,
        },
        "tls": asdict(tls_result),
        "http": asdict(http_result) if http_result else None,
        "html": asdict(html_result) if html_result else None,
        "cdn": cdn_result,
        "reputation": reputation_result,
        "screenshot": asdict(screenshot_result) if screenshot_result else None,
        "phishing_assessment": {
            "level_1_to_5": level,
            "score_0_to_100": score,
            "factors": [asdict(item) for item in factors],
            "warning": "Estimación heurística; no constituye una prueba concluyente.",
        },
        "executive_summary": summary,
    }


def _html_kv_table(items: list[tuple[str, Any]]) -> str:
    rows = []
    for key, value in items:
        display = "no disponible" if value in (None, "") else value
        rows.append(
            f"<tr><th>{html_lib.escape(str(key))}</th><td>{html_lib.escape(str(display))}</td></tr>"
        )
    return "<table>" + "".join(rows) + "</table>"


def export_html_report(output: dict[str, Any], path: str) -> None:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    summary = output.get("executive_summary", {})
    identity = output.get("identity_analysis", {})
    tls = output.get("tls", {})
    assessment = output.get("phishing_assessment", {})
    reputation = output.get("reputation") or {}
    screenshot = output.get("screenshot") or {}
    screenshot_html = ""
    shot_path = screenshot.get("path")
    if screenshot.get("available") and shot_path and Path(shot_path).exists():
        try:
            encoded = base64.b64encode(Path(shot_path).read_bytes()).decode("ascii")
            screenshot_html = '<h2>Captura de pantalla</h2><img class="shot" src="data:image/png;base64,' + encoded + '" alt="Captura de la URL analizada">'
        except Exception:
            pass

    factors = assessment.get("factors", [])
    factor_html = "".join(
        f"<li><strong>+{int(item.get('points', 0)):02d}</strong> {html_lib.escape(str(item.get('description', '')))}</li>"
        for item in factors
    ) or "<li>No se registraron factores de riesgo.</li>"

    vt = reputation.get("virustotal", {})
    ps = reputation.get("phishstats", {})
    pt = reputation.get("phishtank", {})
    op = reputation.get("openphish", {})
    vt_ips = reputation.get("virustotal_ips", {}).get("results", {})
    geo = output.get("geolocation") or {}
    network_rows: list[tuple[str, Any]] = []
    for ip in output.get("ips") or []:
        connection = (geo.get(ip) or {}).get("connection") or {}
        vt_ip = vt_ips.get(ip) or {}
        asn = vt_ip.get("asn") or connection.get("asn")
        owner = vt_ip.get("as_owner") or connection.get("org") or connection.get("isp")
        vt_rep = vt_ip.get("reputation")
        malicious = vt_ip.get("malicious")
        network_rows.append((
            ip,
            f"AS{asn} {owner or ''}; reputación VT IP={vt_rep if vt_rep is not None else 'no evaluada'}; "
            f"motores maliciosos={malicious if malicious is not None else 'no evaluado'}"
            if asn else
            f"ASN no disponible; reputación VT IP={vt_rep if vt_rep is not None else 'no evaluada'}"
        ))
    network_html = _html_kv_table(network_rows or [("IP/ASN", "no disponible")])
    reputation_alert_html = ""
    if summary.get("reputation_alert"):
        alert = html_lib.escape(str(summary.get("reputation_alert_text") or "ALERTA DE REPUTACIÓN").upper())
        reputation_alert_html = f'<div class="rep-alert"><strong>⚠ ALERTA DE REPUTACIÓN</strong><br>{alert}</div>'
    elif summary.get("reputation_advisory"):
        advisory = html_lib.escape(str(summary.get("reputation_advisory_text") or "ANTECEDENTE REPUTACIONAL"))
        reputation_alert_html = f'<div class="rep-advisory"><strong>⚠ AVISO REPUTACIONAL</strong><br>{advisory}</div>'
    rep_count = summary.get("reputation_coverage_evaluated", 0)
    rep_total = summary.get("reputation_coverage_total", 0)
    html_doc = f'''<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>URL Inspector {VERSION} - Informe</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:0;background:#f5f7fa;color:#18202a}}main{{max-width:1050px;margin:auto;padding:32px}}
h1{{margin-bottom:4px}}h2{{border-bottom:1px solid #ccd3db;padding-bottom:6px;margin-top:30px}}.muted{{color:#5d6875}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card{{background:white;border:1px solid #d8dee6;border-radius:8px;padding:14px}}
.rep-alert{{margin:14px 0 18px;background:#fee2e2;color:#991b1b;border:2px solid #dc2626;border-radius:8px;padding:14px;font-size:1.05rem;line-height:1.45}}
.rep-advisory{{margin:14px 0 18px;background:#fef3c7;color:#92400e;border:2px solid #d97706;border-radius:8px;padding:14px;font-size:1.05rem;line-height:1.45}}
.alert-card{{border:2px solid #dc2626;background:#fff1f2;color:#991b1b;font-weight:700}}
.advisory-card{{border:2px solid #d97706;background:#fffbeb;color:#92400e;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:white}}th,td{{text-align:left;vertical-align:top;border:1px solid #d8dee6;padding:8px}}th{{width:30%;background:#eef2f6}}
pre{{white-space:pre-wrap;word-break:break-word;background:#111827;color:#e5e7eb;padding:14px;border-radius:8px;max-height:720px;overflow:auto}}.shot{{max-width:100%;border:1px solid #ccd3db}}
li{{margin:6px 0}}@media print{{body{{background:white}}main{{padding:0}}pre{{max-height:none}}}}
</style></head><body><main>
<h1>URL Inspector {VERSION}</h1><p class="muted">Informe técnico generado {html_lib.escape(str(output.get('generated_at_utc')))}</p>
{reputation_alert_html}
<div class="cards"><div class="card"><b>Dominio</b><br>{html_lib.escape(str(output.get('registered_domain')))}</div>
<div class="card"><b>Riesgo heurístico</b><br>{assessment.get('level_1_to_5')}/5 - {assessment.get('score_0_to_100')}/100</div>
<div class="card"><b>TLS</b><br>{html_lib.escape(str(summary.get('tls')))} / {html_lib.escape(str(summary.get('tls_validation_type')))}</div>
<div class="card {'alert-card' if summary.get('reputation_alert') else 'advisory-card' if summary.get('reputation_advisory') else ''}"><b>Reputación</b><br>{html_lib.escape(str(summary.get('reputation')).upper() if summary.get('reputation_alert') else str(summary.get('reputation')))}</div>
<div class="card"><b>Veredicto operativo</b><br>{html_lib.escape(str(summary.get('operational_verdict')))}</div>
<div class="card"><b>Cobertura técnica</b><br>{summary.get('analysis_coverage_score', summary.get('confidence_score'))}/100</div>
<div class="card"><b>Cobertura reputacional</b><br>{rep_count}/{rep_total} fuentes evaluadas</div></div>
<h2>Resumen ejecutivo</h2>{_html_kv_table([(k, v) for k, v in summary.items()])}
<h2>Identidad, typosquatting y homoglifos</h2>{_html_kv_table([
('Host Unicode', identity.get('unicode_host')), ('Punycode', identity.get('punycode')), ('Scripts', ', '.join(identity.get('scripts') or [])),
('Homoglifos', ', '.join(identity.get('confusable_characters') or [])), ('Referencia más próxima', identity.get('closest_reference_domain')),
('Distancia Levenshtein', identity.get('levenshtein_distance')), ('Lista de referencia', identity.get('reference_source')), ('Entradas', identity.get('reference_count'))])}
<h2>Certificado TLS</h2>{_html_kv_table([
('Válido', tls.get('valid')), ('Tipo', tls.get('validation_type')), ('Base de clasificación', tls.get('validation_type_basis')), ('Edad del certificado (días)', tls.get('certificate_age_days')),
('Edad del dominio (días)', (output.get('rdap') or {}).get('domain_age_days')), ('Válido desde', tls.get('not_before')), ('Válido hasta', tls.get('not_after')),
('Emisor', tls.get('issuer_common_name') or tls.get('issuer')), ('Huella SHA-256', tls.get('sha256_fingerprint'))])}
<h2>Red, IP y ASN</h2>{network_html}<p class="muted">La reputación VT indicada es la de la IP observada. No se interpreta como reputación global del ASN o de su proveedor.</p>
<h2>Fuentes de reputación</h2>{_html_kv_table([
('PhishStats', ('ALERTA ACTUAL' if phishstats_operational_assessment(ps).get('negative') else 'ANTECEDENTE HISTÓRICO') if ps.get('listed') else 'sin coincidencia' if ps.get('available') else 'no evaluado'),
('OpenPhish', 'LISTADA' if op.get('listed') else 'sin coincidencia' if op.get('available') else 'no evaluado'),
('PhishTank', 'LISTADA' if pt.get('listed') else 'sin coincidencia' if pt.get('available') else 'no evaluado'),
('VirusTotal motores', vt.get('engines_total')), ('VirusTotal maliciosos', vt.get('malicious')), ('VirusTotal sospechosos', vt.get('suspicious')),
('VirusTotal inofensivos', vt.get('harmless')), ('VirusTotal sin detección', vt.get('undetected')), ('VirusTotal último análisis', vt.get('last_analysis_date')), ('VirusTotal reputación', vt.get('reputation'))])}
<h2>Factores de riesgo</h2><ul>{factor_html}</ul>
{screenshot_html}
<h2>Anexo técnico JSON</h2><pre>{html_lib.escape(json.dumps(output, ensure_ascii=False, indent=2))}</pre>
<p class="muted">La puntuación es heurística y no constituye por sí sola una conclusión forense.</p>
</main></body></html>'''
    target.write_text(html_doc, encoding="utf-8")


def _pdf_runtime():
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            Image, PageBreak, Preformatted, KeepTogether,
        )
    except ModuleNotFoundError as exc:
        raise RuntimeError("Para exportar PDF instale reportlab: python -m pip install reportlab") from exc

    regular_font = "Helvetica"
    bold_font = "Helvetica-Bold"
    font_candidates = [
        ("URLInspectorSans", "URLInspectorSans-Bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("URLInspectorSans", "URLInspectorSans-Bold", r"C:\\Windows\\Fonts\\arial.ttf", r"C:\\Windows\\Fonts\\arialbd.ttf"),
        ("URLInspectorSans", "URLInspectorSans-Bold", "/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
    ]
    for regular_name, bold_name, regular_path, bold_path in font_candidates:
        if Path(regular_path).exists():
            try:
                pdfmetrics.registerFont(TTFont(regular_name, regular_path))
                regular_font = regular_name
                if Path(bold_path).exists():
                    pdfmetrics.registerFont(TTFont(bold_name, bold_path))
                    bold_font = bold_name
                else:
                    bold_font = regular_name
                break
            except Exception:
                pass

    return {
        "colors": colors,
        "TA_CENTER": TA_CENTER,
        "A4": A4,
        "getSampleStyleSheet": getSampleStyleSheet,
        "ParagraphStyle": ParagraphStyle,
        "cm": cm,
        "SimpleDocTemplate": SimpleDocTemplate,
        "Paragraph": Paragraph,
        "Spacer": Spacer,
        "Table": Table,
        "TableStyle": TableStyle,
        "Image": Image,
        "PageBreak": PageBreak,
        "Preformatted": Preformatted,
        "KeepTogether": KeepTogether,
        "regular_font": regular_font,
        "bold_font": bold_font,
    }


def _pdf_text(value: Any) -> str:
    if value in (None, ""):
        return "no disponible"
    if isinstance(value, bool):
        return "sí" if value else "no"
    return str(value)


def _pdf_source_status(source: dict[str, Any], *, configured_key: bool = True) -> str:
    if configured_key and source.get("configured") is False:
        return "no configurado"
    if source.get("available") is not True:
        return "no evaluado"
    if source.get("listed") is True:
        return "COINCIDENCIA"
    if source.get("listed") is False:
        return "sin coincidencia"
    return "evaluado"


def _executive_conclusion(output: dict[str, Any]) -> tuple[str, str]:
    assessment = output.get("phishing_assessment") or {}
    summary = output.get("executive_summary") or {}
    level = int(assessment.get("level_1_to_5", 3) or 3)
    score = int(assessment.get("score_0_to_100", 0) or 0)
    restricted = bool(summary.get("http_restricted"))

    if summary.get("reputation_alert"):
        sources = ", ".join(summary.get("reputation_alert_sources") or [])
        conclusion = (
            "ALERTA DE REPUTACIÓN EXTERNA. La URL presenta una coincidencia negativa confirmada "
            + (f"en {sources}. " if sources else "en una fuente reputacional. ")
            + "Esta alerta es independiente de la puntuación heurística calibrada."
        )
        action = "No introducir credenciales, no descargar archivos y no continuar la interacción hasta verificar la URL por un canal independiente."
        return f"{conclusion} Puntuación heurística: {score}/100 (nivel {level}/5).", action

    if summary.get("reputation_advisory"):
        conclusion = (
            "Existe un antecedente reputacional histórico que no cumple por sí solo los criterios "
            "de alerta negativa actual de URL Inspector. Debe conservarse como contexto y verificarse "
            "con fuentes adicionales antes de atribuir riesgo operativo."
        )
        action = "Revisar la fecha, el phishscore y buscar corroboración actual en otras fuentes antes de elevar el veredicto."
        return f"{conclusion} Puntuación heurística: {score}/100 (nivel {level}/5).", action

    if level >= 5:
        conclusion = "Riesgo técnico crítico. Se ha observado evidencia heurística muy fuerte compatible con una URL potencialmente maliciosa o de phishing."
        action = "No introducir credenciales, no descargar archivos y no continuar la interacción hasta verificar la identidad por un canal independiente."
    elif level == 4:
        conclusion = "Riesgo técnico muy alto. Se ha observado evidencia fuerte que justifica tratar la URL como sospechosa."
        action = "Evitar introducir datos o ejecutar descargas hasta completar una verificación independiente del dominio y del remitente/origen."
    elif level == 3:
        conclusion = "Riesgo técnico alto. Existen indicios significativos de comportamiento sospechoso."
        action = "Revisar manualmente la identidad declarada, el contexto de recepción y los indicadores técnicos antes de interactuar con la página."
    elif level == 2:
        conclusion = "Riesgo técnico moderado. Existen indicios que justifican cautela, aunque por sí solos no demuestran actividad maliciosa."
        action = "Aplicar controles reforzados y confirmar el contexto si la URL solicita credenciales, pagos, descargas o información sensible."
    else:
        conclusion = "No se han obtenido indicios suficientes para elevar el nivel de riesgo con las comprobaciones realizadas."
        action = "El resultado no certifica legitimidad. Mantener los controles habituales y verificar el contexto cuando exista una operación sensible."
    if restricted:
        conclusion += " La confianza está limitada porque el servidor devolvió una respuesta de bloqueo, desafío o restricción y no pudo verificarse plenamente el contenido real."
    return f"{conclusion} Puntuación heurística: {score}/100 (nivel {level}/5).", action


def _pdf_integrity_manifest(output: dict[str, Any]) -> list[tuple[str, Any]]:
    canonical = json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    rows: list[tuple[str, Any]] = [
        ("SHA-256 del conjunto de resultados", hashlib.sha256(canonical).hexdigest()),
        ("Fecha/hora de generación UTC", output.get("generated_at_utc")),
        ("Versión de URL Inspector", output.get("program_version")),
        ("URL de entrada", output.get("input_url")),
        ("URL final", output.get("final_url")),
    ]
    screenshot = output.get("screenshot") or {}
    shot_path = screenshot.get("path")
    if screenshot.get("available") and shot_path and Path(shot_path).exists():
        try:
            rows.append(("SHA-256 de la captura", hashlib.sha256(Path(shot_path).read_bytes()).hexdigest()))
            rows.append(("Archivo de captura", str(Path(shot_path).resolve())))
        except OSError:
            rows.append(("SHA-256 de la captura", "no calculable"))
    tls = output.get("tls") or {}
    if tls.get("sha256_fingerprint"):
        rows.append(("Huella SHA-256 del certificado TLS", tls.get("sha256_fingerprint")))
    return rows


def _pdf_styles(rt: dict[str, Any]):
    styles = rt["getSampleStyleSheet"]()
    regular = rt["regular_font"]
    bold = rt["bold_font"]
    for name in ("Normal", "BodyText", "Italic", "Code"):
        if name in styles:
            styles[name].fontName = regular
    for name in ("Title", "Heading1", "Heading2", "Heading3"):
        if name in styles:
            styles[name].fontName = bold
    styles.add(rt["ParagraphStyle"](
        name="URLITitle", parent=styles["Title"], alignment=rt["TA_CENTER"],
        fontName=bold, fontSize=19, leading=23, spaceAfter=8,
    ))
    styles.add(rt["ParagraphStyle"](
        name="URLISubtitle", parent=styles["Normal"], alignment=rt["TA_CENTER"],
        fontName=regular, fontSize=9.5, leading=12, spaceAfter=12,
    ))
    styles.add(rt["ParagraphStyle"](
        name="URLICompact", parent=styles["BodyText"], fontName=regular,
        fontSize=8.5, leading=10.5, spaceAfter=2,
    ))
    styles.add(rt["ParagraphStyle"](
        name="URLISmall", parent=styles["BodyText"], fontName=regular,
        fontSize=7.5, leading=9.2, spaceAfter=1,
    ))
    styles.add(rt["ParagraphStyle"](
        name="URLICallout", parent=styles["BodyText"], fontName=bold,
        fontSize=10, leading=13, borderWidth=0.6, borderPadding=8,
        spaceBefore=5, spaceAfter=10,
    ))
    styles.add(rt["ParagraphStyle"](
        name="URLIReputationAlert", parent=styles["BodyText"], fontName=bold,
        fontSize=11.5, leading=15, textColor=rt["colors"].HexColor("#991b1b"),
        backColor=rt["colors"].HexColor("#fee2e2"),
        borderColor=rt["colors"].HexColor("#dc2626"), borderWidth=1.2,
        borderPadding=9, spaceBefore=5, spaceAfter=10,
    ))
    styles.add(rt["ParagraphStyle"](
        name="URLIReputationAdvisory", parent=styles["BodyText"], fontName=bold,
        fontSize=10.5, leading=14, textColor=rt["colors"].HexColor("#92400e"),
        backColor=rt["colors"].HexColor("#fef3c7"),
        borderColor=rt["colors"].HexColor("#d97706"), borderWidth=1.0,
        borderPadding=8, spaceBefore=5, spaceAfter=10,
    ))
    return styles


def _pdf_table(rt: dict[str, Any], styles: Any, rows: list[tuple[str, Any]], widths: tuple[float, float] | None = None):
    colors = rt["colors"]
    cm = rt["cm"]
    Paragraph = rt["Paragraph"]
    Table = rt["Table"]
    TableStyle = rt["TableStyle"]
    data = [[Paragraph("Campo", styles["BodyText"]), Paragraph("Valor", styles["BodyText"])]]
    for key, value in rows:
        data.append([
            Paragraph(html_lib.escape(str(key)), styles["URLICompact"]),
            Paragraph(html_lib.escape(_pdf_text(value)), styles["URLICompact"]),
        ])
    col_widths = list(widths) if widths else [5.0*cm, 12.0*cm]
    table = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#aab2bd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9eef3")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _pdf_footer_factory(rt: dict[str, Any], report_label: str):
    colors = rt["colors"]
    A4 = rt["A4"]
    regular = rt["regular_font"]
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#c8ced6"))
        canvas.setLineWidth(0.35)
        canvas.line(doc.leftMargin, 28, A4[0] - doc.rightMargin, 28)
        canvas.setFont(regular, 7)
        canvas.setFillColor(colors.HexColor("#5f6975"))
        canvas.drawString(doc.leftMargin, 17, f"URL Inspector {VERSION} - {report_label}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 17, f"Página {doc.page}")
        canvas.restoreState()
    return footer


def export_pdf_executive_report(output: dict[str, Any], path: str) -> None:
    rt = _pdf_runtime()
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    cm = rt["cm"]
    Paragraph, Spacer, SimpleDocTemplate = rt["Paragraph"], rt["Spacer"], rt["SimpleDocTemplate"]
    styles = _pdf_styles(rt)
    doc = SimpleDocTemplate(
        str(target), pagesize=rt["A4"], rightMargin=1.7*cm, leftMargin=1.7*cm,
        topMargin=1.55*cm, bottomMargin=1.45*cm,
        title=f"URL Inspector {VERSION} - Informe ejecutivo",
        author="URL Inspector",
        subject="Evaluación ejecutiva de una URL",
    )
    summary = output.get("executive_summary") or {}
    assessment = output.get("phishing_assessment") or {}
    identity = output.get("identity_analysis") or {}
    tls = output.get("tls") or {}
    rdap = output.get("rdap") or {}
    rep = output.get("reputation") or {}
    conclusion, action = _executive_conclusion(output)

    story: list[Any] = [
        Paragraph(f"URL Inspector {VERSION}", styles["URLITitle"]),
        Paragraph("Informe ejecutivo de evaluación de URL", styles["URLISubtitle"]),
    ]
    if summary.get("reputation_alert"):
        story.extend([
            Paragraph(
                "⚠ ALERTA DE REPUTACIÓN — " + html_lib.escape(str(summary.get("reputation_alert_text") or "").upper()),
                styles["URLIReputationAlert"],
            ),
            Spacer(1, 4),
        ])
    elif summary.get("reputation_advisory"):
        story.extend([
            Paragraph(
                "⚠ AVISO REPUTACIONAL — " + html_lib.escape(str(summary.get("reputation_advisory_text") or "")),
                styles["URLIReputationAdvisory"],
            ),
            Spacer(1, 4),
        ])
    story.extend([
        _pdf_table(rt, styles, [
            ("URL analizada", output.get("input_url")),
            ("URL final", output.get("final_url")),
            ("Dominio registrable", output.get("registered_domain")),
            ("Fecha/hora UTC", output.get("generated_at_utc")),
        ]),
        Spacer(1, 10),
        Paragraph("Conclusión ejecutiva", styles["Heading2"]),
        Paragraph(html_lib.escape(conclusion), styles["URLICallout"]),
        Paragraph("Recomendación operativa", styles["Heading2"]),
        Paragraph(html_lib.escape(action), styles["BodyText"]),
        Spacer(1, 7),
        Paragraph("Indicadores principales", styles["Heading2"]),
        _pdf_table(rt, styles, [
            ("Nivel de riesgo", f"{assessment.get('level_1_to_5')}/5"),
            ("Puntuación heurística", f"{assessment.get('score_0_to_100')}/100"),
            ("Cobertura técnica del análisis", f"{summary.get('analysis_coverage_score', summary.get('confidence_score'))}/100"),
            ("Cobertura reputacional", f"{summary.get('reputation_coverage_evaluated', 0)}/{summary.get('reputation_coverage_total', 0)} fuentes evaluadas ({summary.get('reputation_coverage_percent', 0)}%)"),
            ("Veredicto operativo", summary.get("operational_verdict")),
            ("TLS", f"{summary.get('tls')} - {summary.get('tls_validation_type')}"),
            ("Edad del certificado TLS", f"{tls.get('certificate_age_days')} días" if tls.get('certificate_age_days') is not None else None),
            ("Edad del dominio", f"{rdap.get('domain_age_days')} días" if rdap.get('domain_age_days') is not None else None),
            ("Identidad / suplantación", summary.get("identity")),
            ("Reputación", summary.get("reputation")),
        ]),
        Spacer(1, 10),
        Paragraph("Hallazgos que más influyen", styles["Heading2"]),
    ])

    factors = sorted(assessment.get("factors") or [], key=lambda x: int(x.get("points", 0) or 0), reverse=True)[:6]
    if factors:
        for item in factors:
            story.append(Paragraph(
                f"<b>+{int(item.get('points', 0) or 0):02d}</b> - {html_lib.escape(str(item.get('description', '')))}",
                styles["BodyText"],
            ))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No se registraron factores técnicos de riesgo significativos.", styles["BodyText"]))

    coverage_table = _pdf_table(rt, styles, [
        ("URLhaus", _pdf_source_status(rep.get("urlhaus") or {}, configured_key=False)),
        ("PhishStats", ("ALERTA ACTUAL" if phishstats_operational_assessment(rep.get("phishstats") or {}).get("negative") else "ANTECEDENTE HISTÓRICO") if (rep.get("phishstats") or {}).get("listed") else _pdf_source_status(rep.get("phishstats") or {}, configured_key=False)),
        ("OpenPhish", _pdf_source_status(rep.get("openphish") or {}, configured_key=False)),
        ("PhishTank", _pdf_source_status(rep.get("phishtank") or {})),
        ("VirusTotal", "evaluado" if (rep.get("virustotal") or {}).get("available") else "no configurado" if (rep.get("virustotal") or {}).get("configured") is False else "no evaluado"),
        ("Google Safe Browsing", _pdf_source_status(rep.get("google_safe_browsing") or {})),
        ("AbuseIPDB", "evaluado" if (rep.get("abuseipdb") or {}).get("available") else "no configurado" if (rep.get("abuseipdb") or {}).get("configured") is False else "no evaluado"),
    ])
    story.extend([
        Spacer(1, 8),
        rt["KeepTogether"]([Paragraph("Cobertura de fuentes", styles["Heading2"]), coverage_table]),
        Spacer(1, 9),
        rt["KeepTogether"]([
            Paragraph("Alcance y limitaciones", styles["Heading2"]),
            Paragraph(
                "Este informe resume indicadores técnicos observados en el momento del análisis. "
                "La puntuación es heurística: un resultado bajo no certifica legitimidad y un resultado alto no constituye, por sí solo, una conclusión pericial. "
                "Las fuentes no configuradas o no disponibles se muestran como no evaluadas, nunca como resultado limpio. Para trazabilidad y detalle técnico debe consultarse el informe forense.",
                styles["URLISmall"],
            ),
        ]),
    ])
    footer = _pdf_footer_factory(rt, "Informe ejecutivo")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def export_pdf_forensic_report(output: dict[str, Any], path: str) -> None:
    rt = _pdf_runtime()
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    cm = rt["cm"]
    Paragraph, Spacer = rt["Paragraph"], rt["Spacer"]
    PageBreak, Image, Preformatted = rt["PageBreak"], rt["Image"], rt["Preformatted"]
    SimpleDocTemplate = rt["SimpleDocTemplate"]
    styles = _pdf_styles(rt)
    doc = SimpleDocTemplate(
        str(target), pagesize=rt["A4"], rightMargin=1.5*cm, leftMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.45*cm,
        title=f"URL Inspector {VERSION} - Informe forense técnico",
        author="URL Inspector",
        subject="Documentación técnica y evidencias de análisis de URL",
    )
    summary = output.get("executive_summary") or {}
    story: list[Any] = [
        Paragraph(f"URL Inspector {VERSION}", styles["URLITitle"]),
        Paragraph("Informe forense técnico de análisis de URL", styles["URLISubtitle"]),
    ]
    if summary.get("reputation_alert"):
        story.extend([
            Paragraph(
                "⚠ ALERTA DE REPUTACIÓN — " + html_lib.escape(str(summary.get("reputation_alert_text") or "").upper()),
                styles["URLIReputationAlert"],
            ),
            Spacer(1, 4),
        ])
    elif summary.get("reputation_advisory"):
        story.extend([
            Paragraph(
                "⚠ AVISO REPUTACIONAL — " + html_lib.escape(str(summary.get("reputation_advisory_text") or "")),
                styles["URLIReputationAdvisory"],
            ),
            Spacer(1, 4),
        ])
    story.extend([
        _pdf_table(rt, styles, [
            ("URL introducida", output.get("input_url")),
            ("URL final observada", output.get("final_url")),
            ("Host final", output.get("final_host")),
            ("Dominio registrable", output.get("registered_domain")),
            ("Fecha/hora de generación UTC", output.get("generated_at_utc")),
            ("Modo completo", output.get("full_mode")),
            ("Versión", output.get("program_version")),
        ]),
        Spacer(1, 10),
        Paragraph("Objeto y alcance", styles["Heading2"]),
        Paragraph(
            "El presente documento registra los resultados técnicos obtenidos por URL Inspector sobre la URL indicada, incluyendo resolución y redirecciones, identidad del dominio, RDAP/DNS, TLS, HTTP/HTML, infraestructura, reputación y evidencias disponibles. "
            "El análisis representa un estado temporal y no acredita por sí solo autoría, intención, identidad jurídica ni cadena de custodia externa.",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph("Metodología", styles["Heading2"]),
        Paragraph(
            "La herramienta contacta con la URL y, cuando procede, con servicios externos de reputación. La puntuación de phishing combina reglas heurísticas documentadas en la salida. "
            "Una fuente no configurada, no disponible o bloqueada se registra como no evaluada y no se interpreta como resultado negativo.",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph("Manifest de integridad", styles["Heading2"]),
        _pdf_table(rt, styles, _pdf_integrity_manifest(output)),
        Spacer(1, 8),
    ])

    assessment = output.get("phishing_assessment") or {}
    conclusion, action = _executive_conclusion(output)
    story.extend([
        Paragraph("Valoración técnica", styles["Heading2"]),
        _pdf_table(rt, styles, [
            ("Nivel de riesgo", f"{assessment.get('level_1_to_5')}/5"),
            ("Puntuación", f"{assessment.get('score_0_to_100')}/100"),
            ("Cobertura técnica del análisis", f"{summary.get('analysis_coverage_score', summary.get('confidence_score'))}/100"),
            ("Cobertura reputacional", f"{summary.get('reputation_coverage_evaluated', 0)}/{summary.get('reputation_coverage_total', 0)} fuentes evaluadas ({summary.get('reputation_coverage_percent', 0)}%)"),
            ("Veredicto operativo", summary.get("operational_verdict")),
            ("Conclusión resumida", conclusion),
            ("Recomendación operativa", action),
        ]),
        Spacer(1, 10),
    ])

    def section(title: str, rows: list[tuple[str, Any]]) -> None:
        story.append(Paragraph(title, styles["Heading2"]))
        story.append(_pdf_table(rt, styles, rows))
        story.append(Spacer(1, 10))

    identity = output.get("identity_analysis") or {}
    section("Identidad, typosquatting y homoglifos", [
        ("Host ASCII/IDNA", identity.get("ascii_host")),
        ("Host Unicode", identity.get("unicode_host")),
        ("Dominio registrable", identity.get("registered_domain")),
        ("Punycode", identity.get("punycode")),
        ("Scripts observados", ", ".join(identity.get("scripts") or [])),
        ("Mezcla de scripts", identity.get("mixed_scripts")),
        ("Homoglifos/confusables", ", ".join(identity.get("confusable_characters") or [])),
        ("Esqueleto visual", identity.get("confusable_skeleton")),
        ("Referencia más próxima", identity.get("closest_reference_domain")),
        ("Distancia Levenshtein", identity.get("levenshtein_distance")),
        ("Typosquatting sospechado", identity.get("typo_suspected")),
        ("Fuente de referencia", identity.get("reference_source")),
        ("Dominios de referencia cargados", identity.get("reference_count")),
    ])

    if output.get("redirect_chain"):
        section("Cadena de redirecciones", [
            (str(i + 1), f"[{item.get('status')}] {item.get('url')} -> {item.get('destination') or 'final'} ({item.get('kind') or 'respuesta'})")
            for i, item in enumerate(output.get("redirect_chain") or [])
        ])

    rdap = output.get("rdap") or {}
    rdap_response = rdap.get("response") or {}
    section("RDAP y antigüedad del dominio", [
        ("Disponible", rdap.get("available")),
        ("Fuente", rdap.get("source")),
        ("Error", rdap.get("error")),
        ("Edad del dominio (días)", rdap.get("domain_age_days")),
        ("Fecha de creación", rdap_creation_date(rdap_response)),
        ("Última actualización", rdap_update_date(rdap_response)),
        ("Expiración", rdap_expiration_date(rdap_response)),
        ("Estados", ", ".join(rdap_response.get("status") or [])),
    ])

    dns_data = output.get("dns") or {}
    if dns_data:
        section("DNS", [
            (key, "; ".join(map(str, dns_data.get(key) or [])) or "no disponible")
            for key in ("A", "AAAA", "CNAME", "MX", "NS", "SPF", "DMARC", "CAA", "DNSKEY")
        ] + [("DNSSEC publicado", dns_data.get("dnssec_published"))])

    tls = output.get("tls") or {}
    section("Certificado y sesión TLS", [
        ("Disponible", tls.get("available")), ("Válido", tls.get("valid")),
        ("Host", tls.get("host")), ("Puerto", tls.get("port")),
        ("Tipo DV/OV/EV/IV", tls.get("validation_type")),
        ("Base de clasificación", tls.get("validation_type_basis")),
        ("OID de políticas", ", ".join(tls.get("policy_oids") or [])),
        ("Edad del certificado (días)", tls.get("certificate_age_days")),
        ("Válido desde", tls.get("not_before")), ("Válido hasta", tls.get("not_after")),
        ("Días restantes", tls.get("days_remaining")),
        ("Emisor", tls.get("issuer_common_name") or tls.get("issuer")),
        ("Sujeto", tls.get("subject_common_name") or tls.get("subject")),
        ("SAN", ", ".join(tls.get("san") or [])),
        ("Algoritmo de firma", tls.get("signature_algorithm")),
        ("Clave pública", tls.get("public_key")),
        ("Hostname verificado", tls.get("hostname_verified")),
        ("CA de confianza", tls.get("trusted_ca")),
        ("Huella SHA-256", tls.get("sha256_fingerprint")),
        ("Error", tls.get("error")),
    ])

    rep = output.get("reputation") or {}
    vt_ip_results = (rep.get("virustotal_ips") or {}).get("results", {})
    geo = output.get("geolocation") or {}
    network_rows: list[tuple[str, Any]] = []
    for ip in output.get("ips") or []:
        connection = (geo.get(ip) or {}).get("connection") or {}
        vti = vt_ip_results.get(ip) or {}
        asn = vti.get("asn") or connection.get("asn")
        owner = vti.get("as_owner") or connection.get("org") or connection.get("isp")
        network_rows.extend([
            (f"IP {ip}", f"AS{asn} {owner or ''}" if asn else "ASN no disponible"),
            (f"País/ciudad {ip}", f"{(geo.get(ip) or {}).get('country') or ''} / {(geo.get(ip) or {}).get('city') or ''}"),
            (f"VirusTotal reputación IP {ip}", vti.get("reputation")),
            (f"VirusTotal maliciosos IP {ip}", vti.get("malicious")),
            (f"VirusTotal sospechosos IP {ip}", vti.get("suspicious")),
        ])
    section("Red, IP y ASN", network_rows or [("IP/ASN", "no disponible")])
    story.append(Paragraph(
        "Nota: las métricas de reputación se atribuyen a las IP observadas. No se extrapolan automáticamente al conjunto del ASN ni al proveedor.",
        styles["URLISmall"],
    ))
    story.append(Spacer(1, 8))

    vt = rep.get("virustotal") or {}
    vtd = rep.get("virustotal_domain") or {}
    section("Fuentes de reputación", [
        ("URLhaus", _pdf_source_status(rep.get("urlhaus") or {}, configured_key=False)),
        ("PhishStats", ("ALERTA ACTUAL" if phishstats_operational_assessment(rep.get("phishstats") or {}).get("negative") else "ANTECEDENTE HISTÓRICO") if (rep.get("phishstats") or {}).get("listed") else _pdf_source_status(rep.get("phishstats") or {}, configured_key=False)),
        ("OpenPhish", _pdf_source_status(rep.get("openphish") or {}, configured_key=False)),
        ("PhishTank", _pdf_source_status(rep.get("phishtank") or {})),
        ("Google Safe Browsing", _pdf_source_status(rep.get("google_safe_browsing") or {})),
        ("AbuseIPDB", "evaluado" if (rep.get("abuseipdb") or {}).get("available") else "no configurado" if (rep.get("abuseipdb") or {}).get("configured") is False else "no evaluado"),
        ("VirusTotal URL disponible", vt.get("available")),
        ("VirusTotal motores analizados", vt.get("engines_total")),
        ("VirusTotal maliciosos", vt.get("malicious")),
        ("VirusTotal sospechosos", vt.get("suspicious")),
        ("VirusTotal inofensivos", vt.get("harmless")),
        ("VirusTotal sin detección", vt.get("undetected")),
        ("VirusTotal último análisis", vt.get("last_analysis_date")),
        ("VirusTotal reputación", vt.get("reputation")),
        ("VirusTotal categorías", json.dumps(vt.get("categories") or {}, ensure_ascii=False)),
        ("VirusTotal dominio reputación", vtd.get("reputation")),
        ("VirusTotal dominio maliciosos", vtd.get("malicious")),
    ])

    http_data = output.get("http") or {}
    if http_data:
        security_headers = http_data.get("security_headers") or {}
        security_summary = "; ".join(
            f"{k}={'presente' if (v or {}).get('present') else 'ausente'}"
            for k, v in security_headers.items()
        )
        section("HTTP y cabeceras", [
            ("Estado", http_data.get("status_code")), ("Servidor", http_data.get("server")),
            ("Tipo de contenido", http_data.get("content_type")), ("Versión HTTP", http_data.get("http_version")),
            ("Cabeceras de seguridad", security_summary),
            ("Cookies recibidas", len(http_data.get("cookies") or [])),
            ("Error", http_data.get("error")),
        ])

    html_data = output.get("html") or {}
    if html_data:
        section("Análisis heurístico del HTML", [
            ("Disponible", html_data.get("available")), ("Título", html_data.get("title")),
            ("Formularios", html_data.get("forms")), ("Formularios POST", html_data.get("post_forms")),
            ("Formularios hacia otro dominio", html_data.get("external_action_forms")),
            ("Campos password", html_data.get("password_fields")),
            ("Campos email", html_data.get("email_fields")),
            ("Campos OTP/PIN", html_data.get("otp_fields")),
            ("Campos de credenciales", html_data.get("credential_fields")),
            ("Formularios de credenciales externos", html_data.get("external_credential_forms")),
            ("Marcas mencionadas", ", ".join(html_data.get("brand_mentions") or []) or None),
            ("Iframes", html_data.get("iframes")),
            ("Iframes ocultos", html_data.get("hidden_iframes")),
            ("Scripts externos", html_data.get("external_scripts")), ("Scripts inline", html_data.get("inline_scripts")),
            ("Indicios de ofuscación", html_data.get("obfuscation_hits")),
            ("Meta refresh", html_data.get("meta_refresh")),
            ("Dominios externos", ", ".join(html_data.get("external_domains") or [])),
            ("Hallazgos", "; ".join(html_data.get("suspicious_findings") or []) or "ninguno"),
            ("Error", html_data.get("error")),
        ])

    if output.get("cdn"):
        cdn = output.get("cdn") or {}
        section("CDN / proxy", [
            ("Detectado", cdn.get("detected")),
            ("Proveedores", ", ".join(cdn.get("providers") or [])),
            ("Evidencias", "; ".join(cdn.get("evidence") or [])),
        ])

    story.append(Paragraph("Factores de riesgo y trazabilidad de la puntuación", styles["Heading2"]))
    factors = assessment.get("factors") or []
    if factors:
        for item in sorted(factors, key=lambda x: int(x.get("points", 0) or 0), reverse=True):
            story.append(Paragraph(
                f"<b>+{int(item.get('points', 0) or 0):02d}</b> - {html_lib.escape(str(item.get('description', '')))}",
                styles["BodyText"],
            ))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No se registraron factores de riesgo.", styles["BodyText"]))

    screenshot = output.get("screenshot") or {}
    shot_path = screenshot.get("path")
    if screenshot.get("available") and shot_path and Path(shot_path).exists():
        story.extend([PageBreak(), Paragraph("Evidencia visual: captura de pantalla", styles["Heading2"]), Spacer(1, 6)])
        story.append(Paragraph(
            f"Archivo: {html_lib.escape(str(Path(shot_path).resolve()))}<br/>"
            f"Motor: {html_lib.escape(str(screenshot.get('engine') or 'no disponible'))}",
            styles["URLISmall"],
        ))
        story.append(Spacer(1, 6))
        img = Image(shot_path)
        max_w, max_h = 17*cm, 22.3*cm
        scale = min(max_w / img.imageWidth, max_h / img.imageHeight, 1.0)
        img.drawWidth = img.imageWidth * scale
        img.drawHeight = img.imageHeight * scale
        story.append(img)

    story.extend([PageBreak(), Paragraph("Anexo técnico completo (JSON)", styles["Heading2"])])
    story.append(Paragraph(
        "Este anexo contiene el conjunto estructurado de resultados del análisis. El SHA-256 de su serialización canónica figura en el manifest de integridad.",
        styles["URLISmall"],
    ))
    story.append(Spacer(1, 5))
    mono_style = rt["ParagraphStyle"](
        name="TechnicalJSON", parent=styles["Code"], fontName=rt["regular_font"],
        fontSize=5.2, leading=6.2, spaceAfter=0,
    )
    technical_json = json.dumps(output, ensure_ascii=False, indent=2, default=str)
    story.append(Preformatted(technical_json, mono_style, maxLineLength=112, splitChars=" ,/:_-"))
    story.extend([
        Spacer(1, 10),
        Paragraph(
            "Advertencia pericial: este documento automatiza la adquisición y presentación de indicadores técnicos. No sustituye la preservación formal de evidencias, la documentación de cadena de custodia ni el análisis humano cuando sean exigibles.",
            styles["URLISmall"],
        ),
    ])
    footer = _pdf_footer_factory(rt, "Informe forense técnico")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def export_pdf_report(output: dict[str, Any], path: str) -> None:
    """Compatibilidad con 6.0 inicial: --pdf genera el informe forense técnico."""
    export_pdf_forensic_report(output, path)

def domain_age_days_from_rdap(rdap_data: dict[str, Any] | None) -> int | None:
    creation = parse_iso_datetime(rdap_creation_date(rdap_data or {}))
    if not creation:
        return None
    return max(0, (datetime.now(timezone.utc) - creation).days)


def print_age_comparison(rdap_data: dict[str, Any] | None, tls: TLSResult) -> None:
    domain_age = domain_age_days_from_rdap(rdap_data)
    if domain_age is None and tls.certificate_age_days is None:
        return
    heading("ANTIGÜEDAD: DOMINIO FRENTE A CERTIFICADO TLS")
    print(f"Antigüedad del dominio: {domain_age if domain_age is not None else 'no disponible'} día(s)" if domain_age is not None else "Antigüedad del dominio: no disponible")
    print(f"Edad del certificado TLS: {tls.certificate_age_days if tls.certificate_age_days is not None else 'no disponible'} día(s)" if tls.certificate_age_days is not None else "Edad del certificado TLS: no disponible")
    if domain_age is not None and tls.certificate_age_days is not None:
        if domain_age > 365 and tls.certificate_age_days <= 7:
            print("Observación: dominio antiguo con certificado emitido recientemente. Esto es habitual tras una renovación y no implica por sí mismo phishing.")
        elif domain_age <= 30 and tls.certificate_age_days <= 30:
            print("Observación: tanto el dominio como el certificado son recientes; debe valorarse junto con el resto de indicadores.")


def print_screenshot(result: ScreenshotResult) -> None:
    heading("CAPTURA DE PANTALLA COMO EVIDENCIA")
    if result.available:
        print(f"{GREEN}●{RESET} Captura guardada: {result.path}")
        print(f"Motor: {result.engine}")
        print("Nota: la captura es opt-in y ejecuta un navegador headless; úsela preferentemente en un entorno aislado.")
    else:
        print(f"{YELLOW}●{RESET} No se pudo generar la captura: {result.error or 'sin detalle'}")



def _safe_report_stem(domain: str) -> str:
    """Devuelve un nombre de archivo seguro y reconocible para los informes."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", domain or "url").strip("._-")
    return cleaned or "url"


def prompt_report_menu(domain: str) -> dict[str, str]:
    """Menú interactivo para elegir informes cuando no se indicaron por CLI.

    Se ejecuta únicamente en terminal interactivo. Los nombres se generan
    automáticamente en el directorio actual para no obligar al usuario a
    recordar opciones ni rutas.
    """
    heading("GENERACIÓN DE INFORMES")
    print("No se ha solicitado ningún formato de salida en la línea de comandos.")
    print("Elige qué informe(s) deseas generar:")
    print("  1. PDF ejecutivo")
    print("  2. PDF forense")
    print("  3. Ambos PDF (opción por defecto)")
    print("  4. HTML técnico")
    print("  5. JSON")
    print("  6. Todos: JSON + HTML + PDF ejecutivo + PDF forense")
    print("  0. No generar informes")
    print("También puedes combinar opciones separadas por comas, por ejemplo: 1,4,5")

    try:
        raw = input("\nSelección [3]: " ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nNo se generarán informes.")
        return {}

    if not raw:
        raw = "3"

    tokens = {token.strip() for token in raw.split(",") if token.strip()}
    if "0" in tokens:
        return {}

    valid = {"1", "2", "3", "4", "5", "6"}
    invalid = sorted(tokens - valid)
    if invalid:
        print(f"Selección no válida ({', '.join(invalid)}). No se generarán informes.")
        return {}

    if "6" in tokens:
        tokens = {"1", "2", "4", "5"}
    elif "3" in tokens:
        tokens.discard("3")
        tokens.update({"1", "2"})

    try:
        folder_raw = input("Carpeta de salida [directorio actual]: " ).strip()
    except (EOFError, KeyboardInterrupt):
        folder_raw = ""

    output_dir = Path(folder_raw).expanduser() if folder_raw else Path.cwd()
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"No se pudo crear la carpeta de salida: {exc}")
        return {}

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"url_inspector_{_safe_report_stem(domain)}_{stamp}"
    selected: dict[str, str] = {}
    if "1" in tokens:
        selected["pdf_executive"] = str(output_dir / f"{base}_ejecutivo.pdf")
    if "2" in tokens:
        selected["pdf_forensic"] = str(output_dir / f"{base}_forense.pdf")
    if "4" in tokens:
        selected["html"] = str(output_dir / f"{base}.html")
    if "5" in tokens:
        selected["json"] = str(output_dir / f"{base}.json")
    return selected

def main() -> int:
    enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="URL Inspector 6.0: análisis técnico, reputación, typosquatting, TLS y evidencias."
    )
    parser.add_argument("url", help="URL que se desea analizar")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Activa DNS avanzado, HTTP, HTML, CDN, reputación y resumen ejecutivo. La captura headless requiere --screenshot explícito.",
    )
    parser.add_argument("--json", dest="json_path", help="Guarda los resultados en JSON.")
    parser.add_argument("--html", dest="html_path", help="Guarda un informe técnico autocontenido en HTML.")
    parser.add_argument("--pdf", dest="pdf_path", help="Compatibilidad: guarda el informe forense técnico en PDF (requiere reportlab).")
    parser.add_argument("--pdf-executive", dest="pdf_executive_path", help="Guarda un informe PDF ejecutivo y conciso (requiere reportlab).")
    parser.add_argument("--pdf-forensic", dest="pdf_forensic_path", help="Guarda un informe PDF forense técnico completo (requiere reportlab).")
    parser.add_argument(
        "--no-menu",
        action="store_true",
        help="No muestra el menú interactivo de informes cuando no se indicó ningún formato de salida.",
    )
    parser.add_argument(
        "--screenshot",
        dest="screenshot_path",
        nargs="?",
        const="",
        default=None,
        help="Genera una captura PNG. Si no se indica ruta, crea un nombre automático.",
    )
    parser.add_argument(
        "--no-screenshot",
        action="store_true",
        help="Compatibilidad: impide cualquier captura aunque se haya indicado --screenshot.",
    )
    parser.add_argument(
        "--brands-file",
        dest="brands_file",
        help="Lista local adicional/sustitutiva de dominios de referencia para typosquatting.",
    )
    parser.add_argument(
        "--debug-rdap",
        dest="debug_rdap_path",
        help="Guarda el diagnóstico RDAP completo en JSON.",
    )
    args = parser.parse_args()
    check_dependencies()

    try:
        initial_url = normalize_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    heading("RESOLUCIÓN DE LA URL")
    print(f"URL introducida: {initial_url}")
    resolution_error: str | None = None
    try:
        final_url, chain = trace_url(initial_url)
    except TargetResolutionError as exc:
        # Una URL caída o no resoluble sigue siendo analizable mediante señales
        # léxicas y fuentes externas; no se intenta ninguna conexión al objetivo
        # mientras no pueda validarse que resuelve exclusivamente a IP públicas.
        resolution_error = str(exc)
        final_url = initial_url
        chain = []
        print(f"\nNo se pudo completar la resolución HTTP: {resolution_error}")
        print("Se continúa sin conectar al objetivo y con las fuentes disponibles.")
    except TargetSafetyError as exc:
        heading("BLOQUEO DE SEGURIDAD DEL DESTINO")
        print(f"OBJETIVO BLOQUEADO: {exc}")
        print("No se realizará ninguna conexión al destino ni captura headless.")
        return 4
    except Exception as exc:
        # Una URL caída o retirada sigue siendo analizable en sus componentes
        # y fuentes de reputación, siempre que el destino haya superado la
        # política de red pública.
        resolution_error = str(exc)
        final_url = initial_url
        chain = []
        print(f"\nNo se pudo completar la resolución HTTP: {resolution_error}")
        print("Se continúa con la URL introducida y las fuentes disponibles.")

    print("\nCadena de redirecciones:")
    for index, step in enumerate(chain, start=1):
        server = f" | servidor: {step.server}" if step.server else ""
        print(f"{index:02d}. [{step.status}] {step.url}{server}")
        if step.destination:
            print(f"    └─ {step.kind} → {step.destination}")
        if step.blocked_reason:
            print(f"       {RED}BLOQUEADO POR SEGURIDAD:{RESET} {step.blocked_reason}")

    print(f"\nURL final: {final_url}")
    final_host = hostname_from_url(final_url)
    domain = registered_domain(final_host)
    print(f"Host final: {final_host}")
    print(f"Dominio registrable: {domain}")

    if is_ip_literal(domain):
        identity_result = IdentityAnalysis(
            unicode_host=final_host,
            ascii_host=final_host,
            registered_domain=domain,
            reference_source="no aplicable a IP literal",
        )
    else:
        identity_result = analyze_identity(final_host, domain, args.brands_file)
    print_identity(identity_result)

    try:
        ips = resolve_ips(final_host)
    except socket.gaierror as exc:
        ips = []
        print(f"No se pudo resolver el host a IP: {exc}")

    geo: dict[str, dict[str, Any]] = {}
    for ip in ips:
        try:
            geo[ip] = get_ip_geolocation(ip)
        except Exception:
            geo[ip] = {}
    if ips:
        print_geolocation(ips, geo)

    dns_data: dict[str, Any] | None = None
    if args.full and not is_ip_literal(domain):
        dns_data = inspect_dns(final_host, domain)
        print_dns(dns_data)

    rdap_data: dict[str, Any] | None = None
    rdap_source: str | None = None
    rdap_error: str | None = None
    if is_ip_literal(domain):
        rdap_error = "El destino es una dirección IP literal; no existe un dominio registrable."
        heading("RDAP DEL DOMINIO")
        print(rdap_error)
    else:
        try:
            rdap_data, rdap_source = get_rdap(domain)
        except Exception as exc:
            rdap_error = str(exc)
            heading(f"RDAP DEL DOMINIO: {domain}")
            print("No se pudo obtener información RDAP.")
            print(f"Motivo: {rdap_error}")
        else:
            print_rdap(domain, rdap_data, rdap_source)

    if args.debug_rdap_path:
        payload = {
            "domain": domain,
            "available": rdap_data is not None,
            "source": rdap_source,
            "error": rdap_error,
            "response": rdap_data,
        }
        try:
            with open(args.debug_rdap_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            print(f"\nDiagnóstico RDAP guardado en: {args.debug_rdap_path}")
        except OSError as exc:
            print(f"\nNo se pudo guardar el diagnóstico RDAP: {exc}")

    parsed_final = urlsplit(final_url)
    tls_port = parsed_final.port or 443
    tls_result = inspect_tls(final_host, tls_port)
    print_tls(tls_result)
    print_age_comparison(rdap_data, tls_result)

    http_result: HTTPAnalysis | None = None
    html_result: HTMLAnalysis | None = None
    cdn_result: dict[str, Any] | None = None
    reputation_result: dict[str, Any] | None = None
    reputation_scoring_result: dict[str, Any] | None = None

    if args.full:
        http_result, body = inspect_http(final_url)
        print_http(http_result)

        html_result = analyze_html(final_url, body, http_result.content_type)
        print_html(html_result, http_result)

        cdn_result = detect_cdn(
            final_host,
            dns_data or {},
            http_result.headers,
            geo,
        )
        print_cdn(cdn_result)

        # La base reputacional del score se mantiene sobre la URL final para no
        # alterar la calibración. El veredicto operativo comprueba además la URL
        # introducida, porque redirecciones dinámicas pueden cambiar la ruta y
        # ocultar una coincidencia exacta conocida (p. ej. tokens de sesión).
        reputation_scoring_result = inspect_reputation(final_url, ips, domain)
        input_url_reputation: dict[str, Any] | None = None
        if canonicalize_url_for_lookup(initial_url) != canonicalize_url_for_lookup(final_url):
            input_url_reputation = inspect_url_reputation(initial_url)
        reputation_result = merge_operational_reputation(
            reputation_scoring_result,
            input_url_reputation,
            initial_url=initial_url,
            final_url=final_url,
        )
        print_reputation(reputation_result)

    screenshot_result: ScreenshotResult | None = None
    # Desde 1.15 la captura headless es siempre opt-in. --full ya no abre un
    # navegador automáticamente: una página hostil puede intentar alcanzar
    # recursos locales desde el contexto del navegador.
    capture_requested = args.screenshot_path is not None and not args.no_screenshot
    if capture_requested:
        screenshot_result = capture_screenshot(
            final_url,
            args.screenshot_path or None,
            domain,
        )
        print_screenshot(screenshot_result)

    score, level, factors = calculate_risk(
        initial_url, final_url, chain, resolution_error, rdap_data, tls_result,
        identity=identity_result, html=html_result, reputation=reputation_scoring_result,
    )
    print_risk(score, level, factors)

    summary = executive_summary(
        domain, resolution_error, rdap_data, tls_result, identity_result, dns_data, http_result, html_result,
        cdn_result, reputation_result, score, level,
    )
    if args.full:
        print_summary(summary)

    output = build_output(
        full_mode=args.full,
        initial_url=initial_url,
        final_url=final_url,
        chain=chain,
        resolution_error=resolution_error,
        final_host=final_host,
        domain=domain,
        ips=ips,
        geo=geo,
        dns_data=dns_data,
        rdap_data=rdap_data,
        rdap_source=rdap_source,
        rdap_error=rdap_error,
        tls_result=tls_result,
        identity_result=identity_result,
        http_result=http_result,
        html_result=html_result,
        cdn_result=cdn_result,
        reputation_result=reputation_result,
        screenshot_result=screenshot_result,
        score=score,
        level=level,
        factors=factors,
        summary=summary,
    )

    report_option_given = any((
        args.json_path,
        args.html_path,
        args.pdf_path,
        args.pdf_executive_path,
        args.pdf_forensic_path,
    ))
    if not report_option_given and not args.no_menu and sys.stdin.isatty():
        menu_paths = prompt_report_menu(domain)
        args.json_path = menu_paths.get("json")
        args.html_path = menu_paths.get("html")
        args.pdf_executive_path = menu_paths.get("pdf_executive")
        args.pdf_forensic_path = menu_paths.get("pdf_forensic")

    if args.json_path:
        try:
            target = Path(args.json_path).expanduser().resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\nResultados JSON guardados en: {target}")
        except OSError as exc:
            print(f"\nNo se pudo guardar el JSON: {exc}")

    if args.html_path:
        try:
            export_html_report(output, args.html_path)
            print(f"Informe HTML guardado en: {Path(args.html_path).expanduser().resolve()}")
        except Exception as exc:
            print(f"No se pudo guardar el HTML: {exc}")

    if args.pdf_executive_path:
        try:
            export_pdf_executive_report(output, args.pdf_executive_path)
            print(f"Informe PDF ejecutivo guardado en: {Path(args.pdf_executive_path).expanduser().resolve()}")
        except Exception as exc:
            print(f"No se pudo guardar el PDF ejecutivo: {exc}")

    forensic_target = args.pdf_forensic_path or args.pdf_path
    if forensic_target:
        try:
            export_pdf_forensic_report(output, forensic_target)
            print(f"Informe PDF forense guardado en: {Path(forensic_target).expanduser().resolve()}")
        except Exception as exc:
            print(f"No se pudo guardar el PDF forense: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
