#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Benchmark reproducible para URL Inspector 6.0.

Objetivos:
  1) Construir un corpus etiquetado de referencia:
       - benign_reference: Tranco (por defecto 300)
       - phishing: PhishStats API pública (100, sin clave)
       - phishing: OpenPhish Community (100)
       - phishing: PhishTank online-valid (opcional; por defecto 0 porque su feed
         público puede devolver HTTP 429 y no siempre admite nuevas altas)
       - malware: URLhaus recent.csv (100; requiere URLHAUS_AUTH_KEY)
  2) Ejecutar URL Inspector en tres modalidades:
       - normal: todas las fuentes configuradas
       - leave-one-out: neutraliza la fuente que suministró la muestra maliciosa
       - heuristic-only: neutraliza todas las fuentes externas de reputación
  3) Calcular matriz de confusión y métricas para múltiples umbrales sin modificar
     los umbrales internos de URL Inspector.
  4) Añadir análisis científico reproducible: IC95 % de Wilson, desgloses por
     fuente/categoría, prevalencia, solapamiento y soporte de comparación temporal.

SEGURIDAD
--------
El subcomando build NO visita las URLs del corpus; solo descarga listas de IOC y
Tranco. El subcomando run SÍ puede contactar URLs maliciosas. Debe ejecutarse en
una máquina virtual desechable/aislada. Se desactiva la captura de pantalla para
reducir superficie de exposición, pero URL Inspector seguirá realizando conexiones
HTTP/TLS/DNS según su diseño.
"""

from __future__ import annotations

import argparse
import bz2
import contextlib
import csv
import hashlib
import io
import json
import math
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import requests
except ModuleNotFoundError:
    requests = None

VERSION = "1.18"
USER_AGENT = f"URL-Inspector-Benchmark/{VERSION}"
DEFAULT_SEED = 20261010
TRanco_URL = "https://tranco-list.eu/top-1m.csv.zip"
OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHTANK_BASE = "https://data.phishtank.com/data"
PHISHSTATS_API = "https://api.phishstats.info/api/phishing"
URLHAUS_EXPORT_BASE = "https://urlhaus-api.abuse.ch/v2/files/exports"


@dataclass
class Sample:
    sample_id: str
    url: str
    label: int                 # 0 benign_reference, 1 malicious
    category: str              # benign_reference | phishing | malware
    source: str                # tranco | phishtank | phishstats | openphish | urlhaus
    source_record_id: str | None = None
    target: str | None = None
    source_timestamp: str | None = None
    rank: int | None = None
    notes: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_requests() -> None:
    if requests is None:
        raise SystemExit("Falta 'requests'. Instale las dependencias de URL Inspector.")


def get_bytes(url: str, *, timeout: int = 60) -> bytes:
    require_requests()
    r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.content


def get_text(url: str, *, timeout: int = 60) -> str:
    return get_bytes(url, timeout=timeout).decode("utf-8", errors="replace")


def source_bytes(url: str, local_path: str | None = None, *, timeout: int = 60) -> bytes:
    if local_path:
        return Path(local_path).expanduser().resolve().read_bytes()
    return get_bytes(url, timeout=timeout)


def source_text(url: str, local_path: str | None = None, *, timeout: int = 60) -> str:
    return source_bytes(url, local_path, timeout=timeout).decode("utf-8", errors="replace")


def canonical_key(url: str) -> str:
    """Clave prudente de deduplicación; conserva path/query, elimina fragmento."""
    try:
        p = urllib.parse.urlsplit(url.strip())
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = host if not port or default_port else f"{host}:{port}"
        path = p.path or "/"
        return urllib.parse.urlunsplit((scheme, netloc, path, p.query, ""))
    except Exception:
        return url.strip()


def host_key(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def load_exclusion_sets(paths: list[str] | None) -> tuple[set[str], set[str], list[dict[str, Any]]]:
    """Carga corpus previos y devuelve URL canónicas y hosts que deben quedar fuera.

    Acepta tanto corpus de build (clave ``samples``) como resultados de benchmark
    (clave ``results``), para facilitar auditorías y validaciones independientes.
    """
    keys: set[str] = set()
    hosts: set[str] = set()
    provenance: list[dict[str, Any]] = []
    for raw_path in paths or []:
        path = Path(raw_path).expanduser().resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("samples") or data.get("results") or []
        before_k, before_h = len(keys), len(hosts)
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            keys.add(canonical_key(url))
            h = host_key(url)
            if h:
                hosts.add(h)
        provenance.append({
            "path": str(path),
            "sha256": sha256_file(path),
            "rows_seen": len(rows),
            "new_url_keys": len(keys) - before_k,
            "new_hosts": len(hosts) - before_h,
        })
    return keys, hosts, provenance


def sample_deterministic(items: list[Any], n: int, rng: random.Random) -> list[Any]:
    if len(items) <= n:
        return list(items)
    return rng.sample(items, n)


def fetch_phishtank(
    n: int,
    rng: random.Random,
    local_path: str | None = None,
    *,
    exclude_keys: set[str] | None = None,
    exclude_hosts: set[str] | None = None,
) -> list[Sample]:
    key = os.getenv("PHISHTANK_APP_KEY")
    feed_url = (
        f"{PHISHTANK_BASE}/{key}/online-valid.csv.bz2"
        if key else f"{PHISHTANK_BASE}/online-valid.csv.bz2"
    )
    raw = source_bytes(feed_url, local_path)
    try:
        text = bz2.decompress(raw).decode("utf-8", errors="replace")
    except OSError:
        # Algunos proxies pueden descomprimir automáticamente.
        text = raw.decode("utf-8", errors="replace")
    rows = list(csv.DictReader(io.StringIO(text)))
    valid = []
    seen = set(exclude_keys or set())
    seen_hosts = set(exclude_hosts or set())
    for row in rows:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        k = canonical_key(url)
        h = host_key(url)
        if k in seen or (h and h in seen_hosts):
            continue
        seen.add(k)
        if h:
            seen_hosts.add(h)
        valid.append(row)
    chosen = sample_deterministic(valid, n, rng)
    return [
        Sample(
            sample_id="",
            url=row["url"].strip(),
            label=1,
            category="phishing",
            source="phishtank",
            source_record_id=row.get("phish_id"),
            target=(row.get("target") or None),
            source_timestamp=(row.get("verification_time") or row.get("submission_time") or None),
            notes="PhishTank online-valid: verificado y online en el momento del feed.",
        )
        for row in chosen
    ]



def _phishstats_rows(payload: Any) -> list[dict[str, Any]]:
    """Normaliza respuestas JSON de PhishStats en una lista de registros."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "rows"):
            value = payload.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    return []


def fetch_phishstats(
    n: int,
    rng: random.Random,
    local_path: str | None = None,
    *,
    exclude_keys: set[str] | None = None,
    exclude_hosts: set[str] | None = None,
    max_pages: int = 10,
) -> list[Sample]:
    """Obtiene phishing reciente desde la API pública read-only de PhishStats.

    La API anónima no requiere clave. Se solicitan páginas de 100 registros y se
    detiene en cuanto hay suficientes URL/hosts nuevos para el corpus. Esto suele
    consumir muy pocas peticiones y queda holgadamente por debajo de la cuota
    anónima documentada de 50 peticiones/día por IP.
    """
    seen = set(exclude_keys or set())
    seen_hosts = set(exclude_hosts or set())
    candidates: list[dict[str, Any]] = []

    if local_path:
        payload = json.loads(Path(local_path).expanduser().resolve().read_text(encoding="utf-8"))
        pages = [_phishstats_rows(payload)]
    else:
        require_requests()
        pages = []
        for page in range(max_pages):
            params = {"_sort": "-id", "_p": page, "_size": 100}
            r = requests.get(PHISHSTATS_API, params=params, timeout=60, headers={"User-Agent": USER_AGENT})
            if r.status_code == 429:
                raise RuntimeError("PhishStats devolvió HTTP 429 (cuota anónima agotada temporalmente).")
            r.raise_for_status()
            rows = _phishstats_rows(r.json())
            pages.append(rows)
            if not rows:
                break
            # No cortamos aquí: la deduplicación/exclusión se aplica abajo y puede
            # dejar menos de n registros útiles.
            useful = 0
            tmp_keys = set(seen)
            tmp_hosts = set(seen_hosts)
            for row in rows:
                url = str(row.get("url") or row.get("URL") or "").strip()
                if not url:
                    continue
                k = canonical_key(url)
                h = host_key(url)
                if k in tmp_keys or (h and h in tmp_hosts):
                    continue
                tmp_keys.add(k)
                if h:
                    tmp_hosts.add(h)
                useful += 1
            if len(candidates) + useful >= n:
                # Aun así procesaremos esta página completa en el bucle siguiente.
                break

    for rows in pages:
        for row in rows:
            url = str(row.get("url") or row.get("URL") or "").strip()
            if not url:
                continue
            k = canonical_key(url)
            h = host_key(url)
            if k in seen or (h and h in seen_hosts):
                continue
            seen.add(k)
            if h:
                seen_hosts.add(h)
            candidates.append(row)

    # Preferimos una selección determinista si sobran registros; la API ya viene
    # ordenada por id descendente, pero el muestreo evita depender del orden exacto.
    chosen = sample_deterministic(candidates, n, rng)
    out: list[Sample] = []
    for row in chosen:
        url = str(row.get("url") or row.get("URL") or "").strip()
        rid = row.get("id") or row.get("ID")
        ts = row.get("date") or row.get("created_at") or row.get("timestamp") or row.get("Date")
        out.append(Sample(
            sample_id="",
            url=url,
            label=1,
            category="phishing",
            source="phishstats",
            source_record_id=(str(rid) if rid is not None else None),
            source_timestamp=(str(ts) if ts is not None else None),
            notes="PhishStats API pública read-only: URL clasificada como phishing por PhishStats.",
        ))
    return out


def fetch_openphish(
    n: int,
    rng: random.Random,
    local_path: str | None = None,
    *,
    exclude_keys: set[str] | None = None,
    exclude_hosts: set[str] | None = None,
) -> list[Sample]:
    lines = [x.strip() for x in source_text(OPENPHISH_URL, local_path).splitlines() if x.strip() and not x.startswith("#")]
    seen = set(exclude_keys or set())
    seen_hosts = set(exclude_hosts or set())
    urls = []
    for url in lines:
        k = canonical_key(url)
        h = host_key(url)
        if k in seen or (h and h in seen_hosts):
            continue
        seen.add(k)
        if h:
            seen_hosts.add(h)
        urls.append(url)
    chosen = sample_deterministic(urls, n, rng)
    return [
        Sample(
            sample_id="",
            url=url,
            label=1,
            category="phishing",
            source="openphish",
            notes="OpenPhish Community Feed; feed limitado y actualizado periódicamente.",
        )
        for url in chosen
    ]


def _parse_urlhaus_csv(text: str) -> list[dict[str, str]]:
    # Los exports suelen incluir comentarios '#'. Eliminarlos antes de DictReader.
    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return []
    # Algunas versiones usan cabecera con comillas; csv lo gestiona.
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = []
    for row in reader:
        # Normalización tolerante a distintas cabeceras.
        norm = {str(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        rows.append(norm)
    return rows


def fetch_urlhaus(
    n: int,
    rng: random.Random,
    local_path: str | None = None,
    *,
    exclude_keys: set[str] | None = None,
    exclude_hosts: set[str] | None = None,
) -> list[Sample]:
    auth = os.getenv("URLHAUS_AUTH_KEY")
    if not auth and not local_path:
        raise RuntimeError(
            "URLhaus requiere URLHAUS_AUTH_KEY para descargar el export oficial. "
            "Obtenga una Auth-Key gratuita en abuse.ch y defina la variable de entorno."
        )
    url = f"{URLHAUS_EXPORT_BASE}/{auth}/recent.csv" if auth else "local://urlhaus"
    text = source_text(url, local_path, timeout=90)
    rows = _parse_urlhaus_csv(text)
    candidates: list[dict[str, str]] = []
    seen = set(exclude_keys or set())
    seen_hosts = set(exclude_hosts or set())
    for row in rows:
        candidate = row.get("url") or row.get("malware_url") or row.get("urlhaus_url") or ""
        # Algunos dumps históricos usan columnas posicionales con nombres '# id,dateadded,url,...'.
        if not candidate:
            for value in row.values():
                if value.startswith("http://") or value.startswith("https://"):
                    candidate = value
                    break
        if not candidate:
            continue
        k = canonical_key(candidate)
        h = host_key(candidate)
        if k in seen or (h and h in seen_hosts):
            continue
        seen.add(k)
        if h:
            seen_hosts.add(h)
        row["_url"] = candidate
        candidates.append(row)
    chosen = sample_deterministic(candidates, n, rng)
    out = []
    for row in chosen:
        out.append(
            Sample(
                sample_id="",
                url=row["_url"],
                label=1,
                category="malware",
                source="urlhaus",
                source_record_id=row.get("id") or row.get("urlhaus_id") or None,
                source_timestamp=row.get("dateadded") or row.get("date_added") or None,
                notes="URLhaus recent export: URL asociada a distribución de malware según URLhaus.",
            )
        )
    return out


def fetch_tranco_candidates(pool: int, local_path: str | None = None) -> list[tuple[int, str]]:
    raw = source_bytes(TRanco_URL, local_path, timeout=90)
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            if not names:
                raise RuntimeError("ZIP de Tranco vacío")
            text = zf.read(names[0]).decode("utf-8", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rank_s, domain = line.split(",", 1)
            rank = int(rank_s)
        except Exception:
            continue
        if rank > pool:
            break
        domain = domain.strip().lower().rstrip(".")
        if domain:
            out.append((rank, domain))
    return out


def fetch_tranco(
    n: int,
    rng: random.Random,
    malicious_hosts: set[str],
    pool: int,
    local_path: str | None = None,
    *,
    exclude_hosts: set[str] | None = None,
) -> list[Sample]:
    candidates = fetch_tranco_candidates(pool, local_path)
    blocked_hosts = set(malicious_hosts) | set(exclude_hosts or set())
    # Evitar cualquier host usado previamente y cualquier host malicioso del corpus actual.
    candidates = [(rank, dom) for rank, dom in candidates if dom not in blocked_hosts]
    chosen = sample_deterministic(candidates, n, rng)
    return [
        Sample(
            sample_id="",
            url=f"https://{domain}/",
            label=0,
            category="benign_reference",
            source="tranco",
            rank=rank,
            notes="Referencia legítima aproximada: dominio popular de Tranco; no equivale a garantía absoluta de benignidad.",
        )
        for rank, domain in chosen
    ]


def write_corpus(samples: list[Sample], path: Path, metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "benchmark_version": VERSION,
        "created_at_utc": utc_now(),
        "metadata": metadata,
        "counts": dict(Counter(s.source for s in samples)),
        "samples": [asdict(s) for s in samples],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_path = path.with_suffix(".csv")
    fields = list(asdict(samples[0]).keys()) if samples else list(Sample.__dataclass_fields__.keys())
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for sample in samples:
            writer.writerow(asdict(sample))
    path.with_suffix(path.suffix + ".sha256").write_text(sha256_file(path) + "  " + path.name + "\n", encoding="ascii")


def cmd_build(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    malicious: list[Sample] = []
    errors: list[str] = []
    fallback_notes: list[str] = []

    try:
        excluded_keys, excluded_hosts, exclusion_sources = load_exclusion_sets(args.exclude_corpus)
    except Exception as exc:
        print(f"ERROR cargando corpus de exclusión: {exc}", flush=True)
        return 2

    print("Construyendo corpus sin visitar las URLs objetivo...", flush=True)
    if exclusion_sources:
        print(
            f"  Exclusión independiente: {len(excluded_keys)} URL(s) y {len(excluded_hosts)} host(s) previos bloqueados.",
            flush=True,
        )

    # Objetivo total de phishing. Para validación independiente se recomienda
    # PhishStats + OpenPhish. PhishTank queda opcional porque su feed público puede
    # responder 429 y actualmente no siempre permite obtener nuevas app-keys.
    phishing_target = max(0, args.phishtank) + max(0, args.phishstats) + max(0, args.openphish)

    phishtank_samples: list[Sample] = []
    if args.phishtank:
        try:
            phishtank_samples = fetch_phishtank(
                args.phishtank, rng, args.phishtank_file,
                exclude_keys=excluded_keys, exclude_hosts=excluded_hosts,
            )
            malicious.extend(phishtank_samples)
            print(f"  PhishTank: {len(phishtank_samples)}", flush=True)
            if len(phishtank_samples) < args.phishtank:
                msg = f"PhishTank solo aportó {len(phishtank_samples)}/{args.phishtank} tras exclusión/deduplicación."
                errors.append(msg)
                print(f"  AVISO - {msg}", flush=True)
                if args.require_all_sources:
                    return 2
        except Exception as exc:
            errors.append(f"PhishTank: {exc}")
            print(f"  PhishTank: ERROR - {exc}", flush=True)
            if args.require_all_sources:
                return 2

    prior_keys = excluded_keys | {canonical_key(s.url) for s in malicious}
    prior_hosts = excluded_hosts | {host_key(s.url) for s in malicious if host_key(s.url)}
    phishstats_samples: list[Sample] = []
    if args.phishstats:
        try:
            phishstats_samples = fetch_phishstats(
                args.phishstats, rng, args.phishstats_file,
                exclude_keys=prior_keys, exclude_hosts=prior_hosts,
            )
            malicious.extend(phishstats_samples)
            print(f"  PhishStats: {len(phishstats_samples)}", flush=True)
            if len(phishstats_samples) < args.phishstats:
                msg = f"PhishStats solo aportó {len(phishstats_samples)}/{args.phishstats} tras exclusión/deduplicación."
                errors.append(msg)
                print(f"  AVISO - {msg}", flush=True)
                if args.require_all_sources:
                    return 2
        except Exception as exc:
            errors.append(f"PhishStats: {exc}")
            print(f"  PhishStats: ERROR - {exc}", flush=True)
            if args.require_all_sources:
                return 2

    prior_keys = excluded_keys | {canonical_key(s.url) for s in malicious}
    prior_hosts = excluded_hosts | {host_key(s.url) for s in malicious if host_key(s.url)}
    openphish_samples: list[Sample] = []
    if args.openphish:
        try:
            openphish_samples = fetch_openphish(
                args.openphish, rng, args.openphish_file,
                exclude_keys=prior_keys, exclude_hosts=prior_hosts,
            )
            malicious.extend(openphish_samples)
            print(f"  OpenPhish: {len(openphish_samples)}", flush=True)
            if len(openphish_samples) < args.openphish:
                msg = f"OpenPhish solo aportó {len(openphish_samples)}/{args.openphish} tras exclusión/deduplicación."
                errors.append(msg)
                print(f"  AVISO - {msg}", flush=True)
                if args.require_all_sources:
                    return 2
        except Exception as exc:
            errors.append(f"OpenPhish: {exc}")
            print(f"  OpenPhish: ERROR - {exc}", flush=True)
            if args.require_all_sources:
                return 2

    if args.urlhaus:
        try:
            prior_keys = excluded_keys | {canonical_key(s.url) for s in malicious}
            prior_hosts = excluded_hosts | {host_key(s.url) for s in malicious if host_key(s.url)}
            got = fetch_urlhaus(
                args.urlhaus, rng, args.urlhaus_file,
                exclude_keys=prior_keys, exclude_hosts=prior_hosts,
            )
            malicious.extend(got)
            print(f"  URLhaus: {len(got)}", flush=True)
            if len(got) < args.urlhaus:
                msg = f"URLhaus solo aportó {len(got)}/{args.urlhaus} tras exclusión/deduplicación."
                errors.append(msg)
                print(f"  AVISO - {msg}", flush=True)
                if args.require_all_sources:
                    return 2
        except Exception as exc:
            errors.append(f"URLhaus: {exc}")
            print(f"  URLhaus: ERROR - {exc}", flush=True)
            if args.require_all_sources:
                return 2

    # Deduplicación global por URL y host: una sola muestra por host en el corpus nuevo.
    deduped: list[Sample] = []
    seen = set(excluded_keys)
    seen_hosts = set(excluded_hosts)
    for s in malicious:
        k = canonical_key(s.url)
        h = host_key(s.url)
        if k in seen or (h and h in seen_hosts):
            continue
        seen.add(k)
        if h:
            seen_hosts.add(h)
        deduped.append(s)
    malicious = deduped

    malicious_hosts = {host_key(s.url) for s in malicious if host_key(s.url)}
    try:
        benign = fetch_tranco(
            args.benign, rng, malicious_hosts, args.tranco_pool, args.tranco_file,
            exclude_hosts=excluded_hosts,
        )
    except Exception as exc:
        print(f"  Tranco: ERROR - {exc}", flush=True)
        return 2
    print(f"  Tranco benign_reference: {len(benign)}", flush=True)
    if len(benign) < args.benign:
        print(
            f"  Tranco: ERROR - solo {len(benign)}/{args.benign} referencias tras exclusión; aumente --tranco-pool.",
            flush=True,
        )
        return 2

    samples = benign + malicious

    # Auditoría obligatoria de independencia frente a los corpus suministrados.
    new_keys = {canonical_key(s.url) for s in samples}
    new_hosts = {host_key(s.url) for s in samples if host_key(s.url)}
    overlap_keys = sorted(new_keys & excluded_keys)
    overlap_hosts = sorted(new_hosts & excluded_hosts)
    host_counts = Counter(host_key(s.url) for s in samples if host_key(s.url))
    duplicate_hosts = sorted(h for h, c in host_counts.items() if c > 1)
    if overlap_keys or overlap_hosts or duplicate_hosts:
        print("ERROR: la auditoría de independencia/deduplicación no es cero; se aborta el corpus.", flush=True)
        print(f"  Solapamiento URL: {len(overlap_keys)} | hosts previos: {len(overlap_hosts)} | hosts duplicados internos: {len(duplicate_hosts)}", flush=True)
        return 2
    rng.shuffle(samples)
    for i, s in enumerate(samples, 1):
        s.sample_id = f"U{i:04d}"

    source_counts = Counter(s.source for s in malicious)
    phishing_count = sum(1 for s in malicious if s.category == "phishing")
    malware_count = sum(1 for s in malicious if s.category == "malware")
    metadata = {
        "seed": args.seed,
        "tranco_pool": args.tranco_pool,
        "independence_exclusion": {
            "enabled": bool(exclusion_sources),
            "sources": exclusion_sources,
            "excluded_url_keys": len(excluded_keys),
            "excluded_hosts": len(excluded_hosts),
            "audit_overlap_url_keys": len(overlap_keys),
            "audit_overlap_hosts": len(overlap_hosts),
            "audit_duplicate_hosts_inside_new_corpus": len(duplicate_hosts),
        },
        "requested": {
            "benign": args.benign,
            "phishtank": args.phishtank,
            "phishstats": args.phishstats,
            "openphish": args.openphish,
            "urlhaus": args.urlhaus,
            "phishing_total": phishing_target,
        },
        "effective": {
            "phishtank": source_counts.get("phishtank", 0),
            "phishstats": source_counts.get("phishstats", 0),
            "openphish": source_counts.get("openphish", 0),
            "urlhaus": source_counts.get("urlhaus", 0),
            "phishing_total": phishing_count,
            "malware_total": malware_count,
            "benign_total": len(benign),
        },
        "source_errors": errors,
        "local_sources": {
            "tranco": args.tranco_file, "phishtank": args.phishtank_file,
            "phishstats": args.phishstats_file, "openphish": args.openphish_file,
            "urlhaus": args.urlhaus_file,
        },
        "warning": (
            "La clase benign_reference procede de Tranco y debe interpretarse como referencia de sitios populares, "
            "no como una demostración absoluta de ausencia de compromiso."
        ),
    }
    out = Path(args.output).expanduser().resolve()
    write_corpus(samples, out, metadata)
    print(f"\nCorpus JSON: {out}")
    print(f"Corpus CSV:  {out.with_suffix('.csv')}")
    print(f"SHA-256:     {sha256_file(out)}")
    print(
        f"Total: {len(samples)} | benign_reference={len(benign)} | malicious={len(malicious)} "
        f"(phishing={phishing_count}, malware={malware_count})"
    )
    if exclusion_sources:
        print(
            "Auditoría de independencia: "
            f"URL solapadas=0 | hosts previos solapados=0 | hosts duplicados internos=0"
        )
    if fallback_notes:
        print("Fallback aplicado:")
        for note in fallback_notes:
            print(f"  - {note}")
    if errors:
        print("Fuentes no disponibles/avisos:")
        for error in errors:
            print(f"  - {error}")
    return 0


def load_corpus(path: Path) -> list[Sample]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Sample(**item) for item in data.get("samples", [])]




def _trace_stage(path: Path | None, message: str) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", errors="replace") as fh:
            fh.write(f"{time.monotonic():.3f} {message}\n")
            fh.flush()
    except Exception:
        pass


def _bounded_call(stage: str, func, timeout_s: float, *, trace_path: Path | None = None, timeout_value=None, timeout_exc: Exception | None = None):
    """Ejecuta una etapa en hilo daemon y limita su tiempo real.

    Es deliberadamente un hilo daemon: en Windows algunas resoluciones DNS dentro
    de requests/socket pueden ignorar el timeout de conexión. Si una etapa se
    atasca, el worker continúa y el proceso puede finalizar sin esperar a ese hilo.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = func()
        except BaseException as exc:  # conservar la excepción original
            box["exc"] = exc

    _trace_stage(trace_path, f"START {stage} timeout={timeout_s:.1f}s")
    t = threading.Thread(target=target, name=f"urlinspector-{stage}", daemon=True)
    started = time.monotonic()
    t.start()
    t.join(max(0.1, float(timeout_s)))
    elapsed = time.monotonic() - started
    if t.is_alive():
        _trace_stage(trace_path, f"TIMEOUT {stage} elapsed={elapsed:.3f}s")
        if timeout_exc is not None:
            raise timeout_exc
        return timeout_value() if callable(timeout_value) else timeout_value
    if "exc" in box:
        exc = box["exc"]
        _trace_stage(trace_path, f"ERROR {stage} elapsed={elapsed:.3f}s type={type(exc).__name__}: {exc}")
        raise exc
    _trace_stage(trace_path, f"OK {stage} elapsed={elapsed:.3f}s")
    return box.get("value")


def _unavailable_reputation_payload(reason: str) -> dict[str, Any]:
    base = {"available": False, "configured": False, "benchmark_timeout": True, "error": reason}
    return {
        "urlhaus": dict(base),
        "phishstats": dict(base),
        "openphish": dict(base),
        "phishtank": dict(base),
        "virustotal": dict(base),
        "virustotal_domain": dict(base),
        "virustotal_ips": {**base, "results": {}},
        "google_safe_browsing": dict(base),
        "abuseipdb": {**base, "results": {}},
    }

def _neutral_unavailable(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return {"available": False, "configured": False, "benchmark_disabled": True}


def _neutral_abuse(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return {"available": False, "configured": False, "results": {}, "benchmark_disabled": True}


def _load_inspector(path: Path):
    import importlib.util
    name = f"url_inspector_bench_{os.getpid()}_{time.time_ns()}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _apply_reputation_mask(module: Any, mode: str, source: str) -> None:
    if mode == "normal":
        return
    if mode == "heuristic-only":
        module.reputation_urlhaus = _neutral_unavailable
        module.reputation_phishstats = _neutral_unavailable
        module.reputation_openphish = _neutral_unavailable
        module.reputation_phishtank = _neutral_unavailable
        module.reputation_virustotal = _neutral_unavailable
        module.reputation_virustotal_domain = _neutral_unavailable
        module.reputation_virustotal_ips = lambda *a, **k: {
            "available": False, "configured": False, "results": {}, "benchmark_disabled": True
        }
        module.reputation_google_safe_browsing = _neutral_unavailable
        module.reputation_abuseipdb = _neutral_abuse
        return
    if mode == "leave-one-out":
        mapping = {
            "phishtank": "reputation_phishtank",
            "phishstats": "reputation_phishstats",
            "openphish": "reputation_openphish",
            "urlhaus": "reputation_urlhaus",
        }
        fn = mapping.get(source)
        if fn:
            setattr(module, fn, _neutral_unavailable)
        return
    raise ValueError(f"Modo desconocido: {mode}")



def _benchmark_trace_factory(module: Any, max_redirects: int):
    """Traza solo redirecciones HTTP en el benchmark.

    Evita descargar el cuerpo una primera vez únicamente para buscar meta-refresh;
    el HTML se descarga después por inspect_http/analyze_html, donde el meta-refresh
    sigue contando como factor heurístico. Así se elimina una lectura duplicada que
    podía quedar bloqueada en servidores lentos.
    """
    def _trace(start_url: str):
        session = module._new_target_session()
        current = start_url
        seen: set[str] = set()
        chain = []
        for _ in range(max_redirects + 1):
            if current in seen:
                raise RuntimeError(f"Bucle de redirección detectado: {current}")
            seen.add(current)
            response = module._safe_target_get(
                session,
                current,
                allow_redirects=False,
                timeout=(module.CONNECT_TIMEOUT, module.READ_TIMEOUT),
                stream=True,
                verify=True,
            )
            try:
                server = response.headers.get("Server")
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location")
                    if not location:
                        chain.append(module.RedirectStep(response.url, response.status_code, "final", server=server))
                        return response.url, chain
                    next_url = module.urljoin(response.url, location)
                    try:
                        module.validate_public_target(next_url, resolve=True)
                    except module.TargetSafetyError as exc:
                        chain.append(module.RedirectStep(
                            response.url, response.status_code, "HTTP-BLOQUEADO",
                            destination=next_url, server=server, blocked_reason=str(exc),
                        ))
                        return response.url, chain
                    chain.append(module.RedirectStep(
                        response.url, response.status_code, "HTTP",
                        destination=next_url, server=server,
                    ))
                    current = next_url
                    continue
                chain.append(module.RedirectStep(response.url, response.status_code, "final", server=server))
                return response.url, chain
            finally:
                response.close()
        raise RuntimeError(f"Se superó el máximo de {max_redirects} redirecciones en el perfil benchmark.")
    return _trace


def _bounded_resolver_factory(module: Any, lifetime: int):
    """Resolver A/AAAA con lifetime explícito para evitar bloqueos de getaddrinfo."""
    def _resolve(host: str) -> list[str]:
        if module.is_ip_literal(host):
            return [host]
        results: set[str] = set()
        try:
            resolver = module.dns.resolver.Resolver(configure=True)
            resolver.timeout = max(1.0, min(3.0, float(lifetime)))
            resolver.lifetime = max(1.0, float(lifetime))
            for rtype in ("A", "AAAA"):
                try:
                    answer = resolver.resolve(host, rtype, lifetime=max(1.0, float(lifetime)))
                    for item in answer:
                        value = getattr(item, "address", None) or str(item).strip()
                        if value:
                            results.add(str(value))
                except Exception:
                    pass
        except Exception:
            return []
        return sorted(results, key=lambda value: (":" in value, value))
    return _resolve


def _cached_reference_factory(module: Any):
    """Usa solo lista interna + caché local; nunca descarga una lista por cada worker."""
    def _load(custom_path: str | None = None):
        if custom_path:
            try:
                values = set(module.CORE_REFERENCE_DOMAINS)
                values.update(module._read_reference_file(Path(custom_path).expanduser()))
                return sorted(values), f"archivo local: {custom_path}", None
            except Exception as exc:
                return sorted(module.CORE_REFERENCE_DOMAINS), "lista interna prioritaria", str(exc)
        values = set(module.CORE_REFERENCE_DOMAINS)
        source = "lista interna prioritaria (benchmark)"
        err = None
        try:
            if module.REFERENCE_CACHE_FILE.exists():
                values.update(module._read_reference_file(module.REFERENCE_CACHE_FILE))
                source = f"caché local + lista interna: {module.REFERENCE_CACHE_FILE}"
            else:
                err = "caché Tranco 5000 no disponible; no se descarga dentro del worker"
        except Exception as exc:
            err = f"no se pudo leer la caché de referencias: {exc}"
        return sorted(values), source, err
    return _load


def _cached_openphish_factory(module: Any):
    """Consulta el feed OpenPhish ya cacheado; evita una descarga por worker."""
    def _check(url: str) -> dict[str, Any]:
        path = module.OPENPHISH_CACHE_FILE
        if not path.exists():
            return {
                "available": False,
                "configured": False,
                "benchmark_disabled": True,
                "error": "feed OpenPhish no presente en caché local del benchmark",
            }
        try:
            target = module.canonicalize_url_for_lookup(url)
            matched = None
            count = 0
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                candidate = raw.strip()
                if not candidate:
                    continue
                count += 1
                if module.canonicalize_url_for_lookup(candidate) == target:
                    matched = candidate
                    break
            return {
                "available": True,
                "listed": matched is not None,
                "matched_url": matched,
                "feed_entries_checked": count,
                "feed": "OpenPhish Community (caché benchmark)",
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}
    return _check


def _direct_rdap_factory(module: Any):
    """Una sola consulta RDAP por dominio durante benchmark; evita bootstrap repetido."""
    def _get(domain: str):
        return module.request_rdap_url(f"https://rdap.org/domain/{domain}"), "benchmark: rdap.org"
    return _get


def _terminate_process_tree(proc: subprocess.Popen[Any]) -> None:
    """Termina el worker y sus descendientes sin depender de pipes abiertos."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except Exception:
            pass
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    try:
        proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def worker_run(args: argparse.Namespace) -> int:
    inspector_path = Path(args.inspector).resolve()
    output_path = Path(args.output).resolve()
    module = _load_inspector(inspector_path)
    _apply_reputation_mask(module, args.mode, args.source)

    # Perfil de calibración. Mantiene calculate_risk() intacto, pero limita las
    # operaciones auxiliares que pueden bloquear una muestra durante minutos.
    module.CONNECT_TIMEOUT = int(args.connect_timeout)
    module.READ_TIMEOUT = int(args.read_timeout)
    module.MAX_REDIRECTS = int(args.max_redirects)
    module.MAX_HTML_BYTES = int(args.max_html_bytes)

    module.get_ip_geolocation = lambda *a, **k: {}
    module.inspect_dns = lambda *a, **k: {
        "A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [],
        "SPF": [], "DMARC": [], "CAA": [], "DNSKEY": [],
        "dnssec_published": False, "benchmark_skipped": True,
    }
    module.detect_cdn = lambda *a, **k: {
        "detected": False, "providers": [], "evidence": [],
        "anycast_or_proxy_likely": False, "benchmark_skipped": True,
    }
    module.resolve_ips = _bounded_resolver_factory(module, int(args.read_timeout))
    module.trace_url = _benchmark_trace_factory(module, int(args.max_redirects))
    module.get_rdap = _direct_rdap_factory(module)
    module.load_reference_domains = _cached_reference_factory(module)

    trace_path = Path(args.trace_log).resolve() if getattr(args, "trace_log", None) else None
    stage_timeout = max(1.0, float(args.stage_timeout))
    http_timeout = max(stage_timeout, float(args.http_stage_timeout))
    reputation_timeout = max(stage_timeout, float(args.reputation_stage_timeout))

    # Timeouts duros por etapa. requests/socket pueden quedarse en getaddrinfo en
    # Windows más allá de sus timeouts internos; el hilo daemon evita que una
    # sola fase consuma todo el worker.
    # La identidad/typosquatting es una etapa local, pero se registra y limita
    # para detectar regresiones de rendimiento. En 1.5 era precisamente el
    # cuello de botella: se recreaba TLDExtract miles de veces.
    orig_analyze_identity = module.analyze_identity
    def bounded_identity(host_ascii: str, registered_ascii: str, custom_reference_path: str | None = None):
        return _bounded_call(
            "identity",
            lambda: orig_analyze_identity(host_ascii, registered_ascii, custom_reference_path),
            min(stage_timeout, 8.0),
            trace_path=trace_path,
            timeout_exc=TimeoutError(f"benchmark: identidad excedió {min(stage_timeout, 8.0):.0f} s"),
        )
    module.analyze_identity = bounded_identity

    orig_resolve_ips = module.resolve_ips
    module.resolve_ips = lambda host: _bounded_call(
        "resolve_ips", lambda: orig_resolve_ips(host), min(stage_timeout, max(3.0, float(args.read_timeout) + 1.0)),
        trace_path=trace_path, timeout_value=[],
    )

    orig_trace_url = module.trace_url
    module.trace_url = lambda url: _bounded_call(
        "trace_url", lambda: orig_trace_url(url), stage_timeout, trace_path=trace_path,
        timeout_exc=TimeoutError(f"benchmark: trace_url excedió {stage_timeout:.0f} s"),
    )

    orig_get_rdap = module.get_rdap
    module.get_rdap = lambda domain: _bounded_call(
        "rdap", lambda: orig_get_rdap(domain), stage_timeout, trace_path=trace_path,
        timeout_exc=TimeoutError(f"benchmark: RDAP excedió {stage_timeout:.0f} s"),
    )

    orig_inspect_tls = module.inspect_tls
    def bounded_tls(host: str, port: int = 443):
        return _bounded_call(
            "tls", lambda: orig_inspect_tls(host, port), stage_timeout, trace_path=trace_path,
            timeout_value=lambda: module.TLSResult(
                available=False, valid=False, host=host, port=port,
                hostname_verified=None, trusted_ca=None,
                error=f"benchmark: TLS excedió {stage_timeout:.0f} s",
            ),
        )
    module.inspect_tls = bounded_tls

    orig_inspect_http = module.inspect_http
    def bounded_http(url: str):
        return _bounded_call(
            "http", lambda: orig_inspect_http(url), http_timeout, trace_path=trace_path,
            timeout_value=lambda: (module.HTTPAnalysis(error=f"benchmark: HTTP excedió {http_timeout:.0f} s"), b""),
        )
    module.inspect_http = bounded_http

    # OpenPhish se consulta desde caché local para no descargar el mismo feed por
    # cada URL. Si leave-one-out ya lo neutralizó, no se vuelve a activar.
    if not (args.mode == "leave-one-out" and args.source == "openphish") and args.mode != "heuristic-only":
        module.reputation_openphish = _cached_openphish_factory(module)

    # Sin app-key, la API individual de PhishTank tiende a aplicar rate limits.
    # En benchmark se considera no evaluada esa fuente en vez de gastar varios
    # segundos por muestra en una consulta que previsiblemente será 429.
    if not os.getenv("PHISHTANK_APP_KEY") and not (
        args.mode == "leave-one-out" and args.source == "phishtank"
    ):
        module.reputation_phishtank = _neutral_unavailable

    orig_inspect_reputation = module.inspect_reputation
    module.inspect_reputation = lambda url, ips, domain: _bounded_call(
        "reputation", lambda: orig_inspect_reputation(url, ips, domain), reputation_timeout,
        trace_path=trace_path,
        timeout_value=lambda: _unavailable_reputation_payload(
            f"benchmark: reputación excedió {reputation_timeout:.0f} s"
        ),
    )

    argv = [
        str(inspector_path), args.url, "--full", "--no-screenshot", "--no-menu", "--json", str(output_path)
    ]
    old_argv = sys.argv[:]
    sys.argv = argv
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                rc = module.main()
        return int(rc or 0)
    except Exception as exc:
        print(f"worker_exception={type(exc).__name__}: {exc}", file=sys.stderr)
        return 97
    finally:
        sys.argv = old_argv


def run_one(
    script: Path,
    inspector: Path,
    sample: Sample,
    mode: str,
    temp_dir: Path,
    timeout: int,
    connect_timeout: int,
    read_timeout: int,
    max_redirects: int,
    max_html_bytes: int,
    stage_timeout: int,
    http_stage_timeout: int,
    reputation_stage_timeout: int,
) -> dict[str, Any]:
    out_json = temp_dir / f"{sample.sample_id}_{mode}.json"
    stdout_log = temp_dir / f"{sample.sample_id}_{mode}.stdout.log"
    stderr_log = temp_dir / f"{sample.sample_id}_{mode}.stderr.log"
    trace_log = temp_dir / f"{sample.sample_id}_{mode}.stages.log"
    cmd = [
        sys.executable, str(script), "_worker",
        "--inspector", str(inspector),
        "--url", sample.url,
        "--source", sample.source,
        "--mode", mode,
        "--output", str(out_json),
        "--connect-timeout", str(connect_timeout),
        "--read-timeout", str(read_timeout),
        "--max-redirects", str(max_redirects),
        "--max-html-bytes", str(max_html_bytes),
        "--stage-timeout", str(stage_timeout),
        "--http-stage-timeout", str(http_stage_timeout),
        "--reputation-stage-timeout", str(reputation_stage_timeout),
        "--trace-log", str(trace_log),
    ]
    started = time.monotonic()
    proc: subprocess.Popen[Any] | None = None
    try:
        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True
        with stdout_log.open("w", encoding="utf-8", errors="replace") as out_fh, \
             stderr_log.open("w", encoding="utf-8", errors="replace") as err_fh:
            proc = subprocess.Popen(cmd, stdout=out_fh, stderr=err_fh, text=True, **popen_kwargs)
            # Bucle de deadline explícito. En alguna ejecución Windows, wait(timeout=...)
            # devolvió mucho después del límite solicitado; el polling evita esa
            # dependencia y hace que el límite global sea realmente duro.
            deadline = started + max(1.0, float(timeout))
            while proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.10)
            if proc.poll() is None:
                _terminate_process_tree(proc)
                duration = time.monotonic() - started
                diagnostic_parts = []
                for log in (trace_log, stderr_log):
                    try:
                        txt = log.read_text(encoding="utf-8", errors="replace").strip().replace("\n", " | ")
                        if txt:
                            diagnostic_parts.append(txt)
                    except Exception:
                        pass
                diagnostic = " || ".join(diagnostic_parts)
                return {
                    **asdict(sample), "mode": mode, "status": "timeout", "duration_s": round(duration, 3),
                    "score": None, "level": None,
                    "error": f"timeout>{timeout}s" + (f"; stages={diagnostic[-1200:]}" if diagnostic else ""),
                }
            return_code = int(proc.returncode or 0)

        duration = time.monotonic() - started
        if return_code != 0 or not out_json.exists():
            diagnostic_parts = []
            for log in (trace_log, stderr_log, stdout_log):
                try:
                    text_log = log.read_text(encoding="utf-8", errors="replace").strip()
                    if text_log:
                        diagnostic_parts.append(text_log)
                except Exception:
                    pass
            diagnostic = " | ".join(diagnostic_parts).replace("\n", " | ")
            if len(diagnostic) > 1200:
                diagnostic = diagnostic[-1200:]
            error = f"worker_returncode={return_code}"
            if diagnostic:
                error += f"; {diagnostic}"
            return {
                **asdict(sample), "mode": mode, "status": "error", "duration_s": round(duration, 3),
                "score": None, "level": None, "error": error,
            }
        data = json.loads(out_json.read_text(encoding="utf-8"))
        assessment = data.get("phishing_assessment") or {}
        factors = assessment.get("factors") or []
        return {
            **asdict(sample),
            "mode": mode,
            "status": "ok",
            "duration_s": round(duration, 3),
            "score": assessment.get("score_0_to_100"),
            "level": assessment.get("level_1_to_5"),
            "final_url": data.get("final_url"),
            "final_host": data.get("final_host"),
            "factor_count": len(factors),
            "factor_points": sum(int(f.get("points", 0) or 0) for f in factors if isinstance(f, dict)),
            "factors": factors,
            "analysis_coverage": {
                "url_resolution_complete": bool((data.get("url_resolution") or {}).get("complete")),
                "rdap_available": bool((data.get("rdap") or {}).get("available")),
                "tls_available": bool((data.get("tls") or {}).get("available")),
                "http_available": bool(data.get("http") and not (data.get("http") or {}).get("error")),
                "html_available": bool(data.get("html") and (data.get("html") or {}).get("available")),
                "reputation_any": bool(data.get("reputation")),
            },
            "error": None,
        }
    except Exception as exc:
        if proc is not None:
            _terminate_process_tree(proc)
        duration = time.monotonic() - started
        return {
            **asdict(sample), "mode": mode, "status": "error", "duration_s": round(duration, 3),
            "score": None, "level": None, "error": f"{type(exc).__name__}: {exc}",
        }


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def cmd_run(args: argparse.Namespace) -> int:
    if not args.acknowledge_risk:
        print(
            "ERROR: este comando puede contactar URLs de phishing/malware. "
            "Ejecútelo únicamente en una VM desechable/aislada y añada --acknowledge-risk.",
            file=sys.stderr,
        )
        return 2

    corpus_path = Path(args.corpus).expanduser().resolve()
    inspector = Path(args.inspector).expanduser().resolve()
    if not inspector.exists():
        print(f"No existe URL Inspector: {inspector}", file=sys.stderr)
        return 2
    samples = load_corpus(corpus_path)
    if args.limit:
        samples = samples[: args.limit]

    modes = [args.mode] if args.mode != "all" else ["normal", "leave-one-out", "heuristic-only"]
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, Any]] = []
    completed: set[tuple[str, str]] = set()
    if args.resume and output.exists():
        old = json.loads(output.read_text(encoding="utf-8"))
        existing = list(old.get("results", []))
        completed = {(str(r.get("sample_id")), str(r.get("mode"))) for r in existing}
        print(f"Reanudación: {len(existing)} resultados ya presentes.")

    results = existing
    script = Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix="urlinspector_bench_") as td:
        temp_dir = Path(td)
        total = len(samples) * len(modes)
        done = len(existing)
        for sample in samples:
            for mode in modes:
                if (sample.sample_id, mode) in completed:
                    continue
                done += 1
                print(
                    f"[{done}/{total}] {sample.sample_id} {sample.category}/{sample.source} "
                    f"mode={mode}",
                    flush=True,
                )
                row = run_one(
                    script, inspector, sample, mode, temp_dir, args.timeout,
                    args.connect_timeout, args.read_timeout,
                    args.max_redirects, args.max_html_bytes,
                    args.stage_timeout, args.http_stage_timeout, args.reputation_stage_timeout,
                )
                results.append(row)
                if row.get("status") == "ok":
                    print(
                        f"       -> OK {row.get('duration_s')} s | score={row.get('score')} | level={row.get('level')}",
                        flush=True,
                    )
                else:
                    err = str(row.get("error") or "")
                    if len(err) > 180:
                        err = err[:177] + "..."
                    print(
                        f"       -> {str(row.get('status')).upper()} {row.get('duration_s')} s | {err}",
                        flush=True,
                    )
                atomic_write_json(
                    output,
                    {
                        "benchmark_version": VERSION,
                        "updated_at_utc": utc_now(),
                        "corpus": str(corpus_path),
                        "inspector": str(inspector),
                        "inspector_sha256": sha256_file(inspector),
                        "results": results,
                    },
                )

    print(f"\nResultados guardados en: {output}")
    return 0


def safe_div(a: float, b: float) -> float | None:
    return a / b if b else None


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    """Intervalo de Wilson bilateral (95 % por defecto) para una proporción binomial."""
    if total <= 0:
        return None, None
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    half = (z / denom) * math.sqrt((p * (1.0 - p) / total) + (z2 / (4.0 * total * total)))
    return max(0.0, center - half), min(1.0, center + half)


def _metric_with_ci(successes: int, total: int) -> tuple[float | None, float | None, float | None]:
    value = safe_div(successes, total)
    low, high = wilson_interval(successes, total)
    return value, low, high


def metric_row(results: list[dict[str, Any]], threshold: int) -> dict[str, Any]:
    evals = [r for r in results if r.get("status") == "ok" and isinstance(r.get("score"), (int, float))]
    tp = tn = fp = fn = 0
    for r in evals:
        y = int(r["label"])
        pred = 1 if float(r["score"]) >= threshold else 0
        if y == 1 and pred == 1:
            tp += 1
        elif y == 0 and pred == 0:
            tn += 1
        elif y == 0 and pred == 1:
            fp += 1
        elif y == 1 and pred == 0:
            fn += 1

    precision, precision_lo, precision_hi = _metric_with_ci(tp, tp + fp)
    recall, recall_lo, recall_hi = _metric_with_ci(tp, tp + fn)
    specificity, specificity_lo, specificity_hi = _metric_with_ci(tn, tn + fp)
    accuracy, accuracy_lo, accuracy_hi = _metric_with_ci(tp + tn, tp + tn + fp + fn)

    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)
    f1 = (
        safe_div(2 * precision * recall, precision + recall)
        if precision is not None and recall is not None and (precision + recall)
        else None
    )
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else None

    # Los IC de FPR/FNR se obtienen por complemento de especificidad/sensibilidad.
    fpr_lo = (1.0 - specificity_hi) if specificity_hi is not None else None
    fpr_hi = (1.0 - specificity_lo) if specificity_lo is not None else None
    fnr_lo = (1.0 - recall_hi) if recall_hi is not None else None
    fnr_hi = (1.0 - recall_lo) if recall_lo is not None else None

    return {
        "threshold": threshold,
        "n_evaluable": len(evals),
        "n_positive": tp + fn,
        "n_negative": tn + fp,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "precision_ci95_low": precision_lo,
        "precision_ci95_high": precision_hi,
        "recall_sensitivity": recall,
        "recall_ci95_low": recall_lo,
        "recall_ci95_high": recall_hi,
        "specificity": specificity,
        "specificity_ci95_low": specificity_lo,
        "specificity_ci95_high": specificity_hi,
        "false_positive_rate": fpr,
        "false_positive_rate_ci95_low": fpr_lo,
        "false_positive_rate_ci95_high": fpr_hi,
        "false_negative_rate": fnr,
        "false_negative_rate_ci95_low": fnr_lo,
        "false_negative_rate_ci95_high": fnr_hi,
        "accuracy": accuracy,
        "accuracy_ci95_low": accuracy_lo,
        "accuracy_ci95_high": accuracy_hi,
        "f1": f1,
        "balanced_accuracy": balanced,
        "mcc": mcc,
    }


def category_recall_row(results: list[dict[str, Any]], category: str, threshold: int) -> dict[str, Any]:
    evals = [
        r for r in results
        if r.get("status") == "ok" and r.get("category") == category
        and isinstance(r.get("score"), (int, float))
    ]
    detected = sum(1 for r in evals if float(r["score"]) >= threshold)
    recall, lo, hi = _metric_with_ci(detected, len(evals))
    return {
        "category": category,
        "threshold": threshold,
        "n_evaluable": len(evals),
        "detected": detected,
        "missed": len(evals) - detected,
        "recall": recall,
        "recall_ci95_low": lo,
        "recall_ci95_high": hi,
    }


def score_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scores = sorted(float(r["score"]) for r in rows if r.get("status") == "ok" and isinstance(r.get("score"), (int, float)))
    if not scores:
        return {"n": 0}

    def pct(p: float) -> float:
        idx = (len(scores) - 1) * p
        lo, hi = math.floor(idx), math.ceil(idx)
        if lo == hi:
            return scores[lo]
        return scores[lo] * (hi - idx) + scores[hi] * (idx - lo)

    return {
        "n": len(scores),
        "min": min(scores),
        "p25": pct(.25),
        "median": pct(.5),
        "p75": pct(.75),
        "max": max(scores),
        "mean": sum(scores) / len(scores),
    }


def best_thresholds(table: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [r for r in table if r.get("recall_sensitivity") is not None and r.get("specificity") is not None]
    best_f1 = max(usable, key=lambda r: (r.get("f1") if r.get("f1") is not None else -1), default=None)
    best_youden = max(usable, key=lambda r: r["recall_sensitivity"] + r["specificity"] - 1, default=None)
    constraints = {}
    for cap in (0.01, 0.02, 0.05, 0.10):
        candidates = [r for r in usable if r.get("false_positive_rate") is not None and r["false_positive_rate"] <= cap]
        if candidates:
            constraints[f"fpr_le_{int(cap * 100)}pct"] = max(
                candidates,
                key=lambda r: (r["recall_sensitivity"], -r["threshold"]),
            )
    return {"best_f1": best_f1, "best_youden": best_youden, **constraints}


def fmt_pct(v: Any) -> str:
    return "n/d" if v is None else f"{100 * float(v):.1f}%"


def fmt_ci_pct(value: Any, low: Any, high: Any) -> str:
    if value is None:
        return "n/d"
    if low is None or high is None:
        return fmt_pct(value)
    return f"{fmt_pct(value)} [IC95% {fmt_pct(low)}–{fmt_pct(high)}]"


def write_metrics_csv(path: Path, table: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not table:
        path.write_text("", encoding="utf-8-sig")
        return
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(table[0].keys()))
        writer.writeheader()
        writer.writerows(table)


def write_results_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    # Factores se guardan como JSON compacto dentro de una celda.
    fields = [
        "sample_id", "url", "label", "category", "source", "mode", "status", "duration_s", "score", "level",
        "final_url", "final_host", "factor_count", "factor_points", "error", "rank", "target", "source_record_id", "source_timestamp", "factors"
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            r = dict(row)
            if isinstance(r.get("factors"), (list, dict)):
                r["factors"] = json.dumps(r["factors"], ensure_ascii=False, separators=(",", ":"))
            writer.writerow(r)


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _parse_reference_time(value: str | None) -> datetime:
    if value:
        dt = _parse_datetime(value)
        if dt is None:
            raise ValueError("--reference-time debe ser una fecha ISO-8601 válida, por ejemplo 2026-10-13T00:00:00Z")
        return dt
    return datetime.now(timezone.utc)


def _parse_prevalences(value: str | None) -> list[float]:
    raw = value or "0.001,0.01,0.05,0.10,0.50"
    vals: list[float] = []
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            p = float(piece)
        except ValueError as exc:
            raise ValueError(f"Prevalencia inválida: {piece}") from exc
        if not (0.0 < p < 1.0):
            raise ValueError(f"La prevalencia debe estar entre 0 y 1: {piece}")
        vals.append(p)
    if not vals:
        raise ValueError("Debe indicarse al menos una prevalencia.")
    return sorted(set(vals))


def prevalence_adjusted_values(sensitivity: float | None, specificity: float | None, prevalence: float) -> dict[str, Any]:
    """PPV/NPV teóricos para una prevalencia asumida, usando Se/Sp medidos."""
    if sensitivity is None or specificity is None:
        return {
            "prevalence": prevalence,
            "adjusted_ppv": None,
            "adjusted_npv": None,
            "expected_tp_per_10000": None,
            "expected_fp_per_10000": None,
            "expected_tn_per_10000": None,
            "expected_fn_per_10000": None,
        }
    p = prevalence
    se = float(sensitivity)
    sp = float(specificity)
    ppv = safe_div(se * p, se * p + (1.0 - sp) * (1.0 - p))
    npv = safe_div(sp * (1.0 - p), (1.0 - se) * p + sp * (1.0 - p))
    n = 10000.0
    return {
        "prevalence": p,
        "adjusted_ppv": ppv,
        "adjusted_npv": npv,
        "expected_tp_per_10000": n * p * se,
        "expected_fp_per_10000": n * (1.0 - p) * (1.0 - sp),
        "expected_tn_per_10000": n * (1.0 - p) * sp,
        "expected_fn_per_10000": n * p * (1.0 - se),
    }


def _unique_sample_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Elimina duplicados debidos a ejecutar la misma muestra en varios modos."""
    seen: dict[str, dict[str, Any]] = {}
    for row in rows:
        sample_id = str(row.get("sample_id") or "")
        key = sample_id or canonical_key(str(row.get("url") or "")) or repr(row)
        if key not in seen:
            seen[key] = row
    return list(seen.values())


def corpus_overlap_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Audita duplicados y solapamiento de URL/host entre fuentes del propio conjunto."""
    unique = _unique_sample_rows(rows)
    url_sources: dict[str, set[str]] = defaultdict(set)
    host_sources: dict[str, set[str]] = defaultdict(set)
    url_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    for row in unique:
        url = str(row.get("url") or "")
        src = str(row.get("source") or "unknown")
        ck = canonical_key(url)
        hk = host_key(url)
        if ck:
            url_sources[ck].add(src)
            url_counts[ck] += 1
        if hk:
            host_sources[hk].add(src)
            host_counts[hk] += 1

    cross_url = sorted((u, sorted(s)) for u, s in url_sources.items() if len(s) > 1)
    cross_host = sorted((h, sorted(s)) for h, s in host_sources.items() if len(s) > 1)
    duplicate_urls = sorted(u for u, n in url_counts.items() if n > 1)
    duplicate_hosts = sorted(h for h, n in host_counts.items() if n > 1)
    return {
        "n_unique_samples": len(unique),
        "cross_source_url_overlap_count": len(cross_url),
        "cross_source_host_overlap_count": len(cross_host),
        "duplicate_url_count": len(duplicate_urls),
        "duplicate_host_count": len(duplicate_hosts),
        "cross_source_url_examples": [
            {"url": u, "sources": s} for u, s in cross_url[:20]
        ],
        "cross_source_host_examples": [
            {"host": h, "sources": s} for h, s in cross_host[:20]
        ],
        "duplicate_url_examples": duplicate_urls[:20],
        "duplicate_host_examples": duplicate_hosts[:20],
        "note": (
            "Esta auditoría mide solapamiento dentro del corpus/resultados aportados. "
            "No prueba que una URL no figure simultáneamente en feeds externos no usados como fuente de esa muestra."
        ),
    }


def _group_metric_rows(rows: list[dict[str, Any]], field: str, thresholds: Iterable[int]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    values = sorted({str(r.get(field) or "unknown") for r in rows})
    for value in values:
        subset = [r for r in rows if str(r.get(field) or "unknown") == value]
        cats = sorted({str(r.get("category") or "unknown") for r in subset})
        for threshold in thresholds:
            m = metric_row(subset, threshold)
            out.append({
                "group_field": field,
                "group_value": value,
                "categories": ";".join(cats),
                **m,
            })
    return out


def _age_bin(age_days: float | None) -> str:
    if age_days is None:
        return "unknown"
    if age_days <= 7:
        return "0-7d"
    if age_days <= 30:
        return "8-30d"
    if age_days <= 90:
        return "31-90d"
    if age_days <= 180:
        return "91-180d"
    if age_days <= 365:
        return "181-365d"
    return ">365d"


def temporal_profile(rows: list[dict[str, Any]], reference_time: datetime, thresholds: Iterable[int]) -> dict[str, Any]:
    """Describe antigüedad de muestras maliciosas y detección por ventanas temporales."""
    malicious = [
        r for r in rows
        if r.get("status") == "ok" and int(r.get("label", 0) or 0) == 1
        and isinstance(r.get("score"), (int, float))
    ]
    enriched: list[tuple[dict[str, Any], float | None, str]] = []
    ages: list[float] = []
    future_timestamps = 0
    for row in malicious:
        dt = _parse_datetime(row.get("source_timestamp"))
        age: float | None = None
        if dt is not None:
            age = (reference_time - dt).total_seconds() / 86400.0
            if age < 0:
                future_timestamps += 1
                age = 0.0
            ages.append(age)
        enriched.append((row, age, _age_bin(age)))

    bins_order = ["0-7d", "8-30d", "31-90d", "91-180d", "181-365d", ">365d", "unknown"]
    bin_rows: list[dict[str, Any]] = []
    for bin_name in bins_order:
        subset = [r for r, _age, b in enriched if b == bin_name]
        if not subset:
            continue
        for threshold in thresholds:
            detected = sum(1 for r in subset if float(r["score"]) >= threshold)
            rate, lo, hi = _metric_with_ci(detected, len(subset))
            bin_rows.append({
                "age_bin": bin_name,
                "threshold": threshold,
                "n_evaluable": len(subset),
                "detected": detected,
                "missed": len(subset) - detected,
                "detection_rate": rate,
                "detection_rate_ci95_low": lo,
                "detection_rate_ci95_high": hi,
            })

    ages_sorted = sorted(ages)
    median_age = None
    if ages_sorted:
        mid = len(ages_sorted) // 2
        median_age = ages_sorted[mid] if len(ages_sorted) % 2 else (ages_sorted[mid - 1] + ages_sorted[mid]) / 2.0
    return {
        "reference_time_utc": reference_time.isoformat(),
        "n_malicious_evaluable": len(malicious),
        "n_with_source_timestamp": len(ages),
        "timestamp_coverage": safe_div(len(ages), len(malicious)),
        "median_source_age_days": round(median_age, 1) if median_age is not None else None,
        "min_source_age_days": round(min(ages), 1) if ages else None,
        "max_source_age_days": round(max(ages), 1) if ages else None,
        "future_timestamp_count": future_timestamps,
        "bins": bin_rows,
        "interpretation_note": (
            "Este bloque describe la frescura de las muestras y el rendimiento por antigüedad. "
            "No sustituye una validación temporal longitudinal: para ello debe construirse y ejecutar un corpus nuevo en una fecha posterior."
        ),
    }


def _prevalence_rows(table_by_threshold: dict[int, dict[str, Any]], prevalences: Iterable[float]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for threshold, m in sorted(table_by_threshold.items()):
        for prevalence in prevalences:
            vals = prevalence_adjusted_values(m.get("recall_sensitivity"), m.get("specificity"), prevalence)
            out.append({
                "threshold": threshold,
                "sensitivity": m.get("recall_sensitivity"),
                "specificity": m.get("specificity"),
                **vals,
            })
    return out


def _load_results_payload(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = list(payload.get("results", []))
    if not rows:
        raise ValueError(f"No hay resultados en {path}")
    return payload, rows


def cmd_report(args: argparse.Namespace) -> int:
    source = Path(args.results).expanduser().resolve()
    try:
        data, rows = _load_results_payload(source)
        reference_time = _parse_reference_time(args.reference_time)
        prevalences = _parse_prevalences(args.prevalence)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_results_csv(out_dir / "benchmark_individual_results.csv", rows)

    selected_threshold_values = (8, 10, 12, 15, 18, 19, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80)
    scientific_thresholds = (8, 20, 30, 40, 50)
    overlap = corpus_overlap_audit(rows)
    (out_dir / "overlap_audit.json").write_text(json.dumps(overlap, ensure_ascii=False, indent=2), encoding="utf-8")

    report: dict[str, Any] = {
        "benchmark_version": VERSION,
        "generated_at_utc": utc_now(),
        "reference_time_utc": reference_time.isoformat(),
        "source_results": str(source),
        "source_results_benchmark_version": data.get("benchmark_version"),
        "inspector_sha256": data.get("inspector_sha256"),
        "modes": {},
        "corpus_overlap_audit": overlap,
        "prevalence_scenarios": prevalences,
        "interpretation_note": (
            "Las puntuaciones 0-100 son heurísticas. Las métricas evalúan el comportamiento frente al corpus de referencia; "
            "no transforman la puntuación en una probabilidad de malicia. La precisión/PPV empírica depende de la prevalencia del corpus; "
            "por eso se incluyen escenarios de PPV/NPV ajustados a prevalencias hipotéticas."
        ),
    }

    for mode in sorted({str(r.get("mode")) for r in rows}):
        mr = [r for r in rows if r.get("mode") == mode]
        table = [metric_row(mr, t) for t in range(0, 101)]
        write_metrics_csv(out_dir / f"thresholds_{mode}.csv", table)
        table_map = {int(r["threshold"]): r for r in table}

        status_counts = Counter(str(r.get("status")) for r in mr)
        by_category: dict[str, Any] = {}
        for category in sorted({str(r.get("category")) for r in mr}):
            by_category[category] = score_summary([r for r in mr if r.get("category") == category])

        selected = {str(t): table_map[t] for t in selected_threshold_values}
        category_recalls = {
            category: {str(t): category_recall_row(mr, category, t) for t in selected_threshold_values}
            for category in ("phishing", "malware")
            if any(r.get("category") == category for r in mr)
        }

        source_metrics = _group_metric_rows(mr, "source", scientific_thresholds)
        category_metrics = _group_metric_rows(mr, "category", scientific_thresholds)
        write_metrics_csv(out_dir / f"source_metrics_{mode}.csv", source_metrics)
        write_metrics_csv(out_dir / f"category_metrics_{mode}.csv", category_metrics)

        temporal = temporal_profile(mr, reference_time, scientific_thresholds)
        write_metrics_csv(out_dir / f"temporal_metrics_{mode}.csv", list(temporal.get("bins", [])))

        prevalence_rows = _prevalence_rows({t: table_map[t] for t in scientific_thresholds}, prevalences)
        write_metrics_csv(out_dir / f"prevalence_adjusted_{mode}.csv", prevalence_rows)

        n_ok = int(status_counts.get("ok", 0))
        evaluable_fraction = (n_ok / len(mr)) if mr else 0.0
        report["modes"][mode] = {
            "n_total": len(mr),
            "n_evaluable": n_ok,
            "evaluable_fraction": evaluable_fraction,
            "status_counts": dict(status_counts),
            "score_distribution_by_category": by_category,
            "selected_thresholds": selected,
            "recall_by_malicious_category": category_recalls,
            "metrics_by_source": source_metrics,
            "metrics_by_category": category_metrics,
            "temporal_profile": temporal,
            "prevalence_adjusted": prevalence_rows,
            "empirical_candidates": best_thresholds(table),
        }

    json_path = out_dir / "benchmark_summary.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    txt_lines: list[str] = []
    txt_lines.append("URL INSPECTOR 6.0 - BENCHMARK SUMMARY")
    txt_lines.append("=" * 48)
    txt_lines.append(f"Generado: {report['generated_at_utc']}")
    txt_lines.append(f"Referencia temporal: {report['reference_time_utc']}")
    txt_lines.append(
        "Auditoría interna de solapamiento: "
        f"URL entre fuentes={overlap['cross_source_url_overlap_count']} | "
        f"hosts entre fuentes={overlap['cross_source_host_overlap_count']} | "
        f"duplicados URL={overlap['duplicate_url_count']} | hosts={overlap['duplicate_host_count']}"
    )
    txt_lines.append("")

    for mode, item in report["modes"].items():
        txt_lines.append(f"MODO: {mode}")
        txt_lines.append(f"  Total: {item['n_total']} | estados: {item['status_counts']}")
        txt_lines.append(
            f"  Evaluables: {item['n_evaluable']}/{item['n_total']} "
            f"({item['evaluable_fraction'] * 100:.1f}%)"
        )
        if item["evaluable_fraction"] < 0.80:
            txt_lines.append("  ADVERTENCIA: cobertura insuficiente (<80%); no interpretar las métricas como validación.")

        for t in (8, 20, 30, 40, 50, 60, 65, 80):
            m = item["selected_thresholds"][str(t)]
            ph = (item.get("recall_by_malicious_category", {}).get("phishing", {}).get(str(t), {}) or {}).get("recall")
            mw = (item.get("recall_by_malicious_category", {}).get("malware", {}).get(str(t), {}) or {}).get("recall")
            txt_lines.append(
                f"  >= {t:2d}: recall={fmt_ci_pct(m['recall_sensitivity'], m['recall_ci95_low'], m['recall_ci95_high'])}  "
                f"phishing={fmt_pct(ph)}  malware={fmt_pct(mw)}  "
                f"specificity={fmt_ci_pct(m['specificity'], m['specificity_ci95_low'], m['specificity_ci95_high'])}  "
                f"precision(emp.)={fmt_pct(m['precision'])}  FPR={fmt_pct(m['false_positive_rate'])}  F1={fmt_pct(m['f1'])}"
            )

        # Desglose por fuente en el umbral operativo principal (8).
        src_t8 = [r for r in item.get("metrics_by_source", []) if int(r.get("threshold", -1)) == 8]
        if src_t8:
            txt_lines.append("  Por fuente @>=8:")
            for row in src_t8:
                if int(row.get("n_positive", 0) or 0) > 0:
                    detail = fmt_ci_pct(row.get("recall_sensitivity"), row.get("recall_ci95_low"), row.get("recall_ci95_high"))
                    txt_lines.append(f"    - {row['group_value']}: sensibilidad={detail} (n={row['n_positive']})")
                elif int(row.get("n_negative", 0) or 0) > 0:
                    detail = fmt_ci_pct(row.get("specificity"), row.get("specificity_ci95_low"), row.get("specificity_ci95_high"))
                    txt_lines.append(f"    - {row['group_value']}: especificidad={detail} (n={row['n_negative']})")

        temporal = item.get("temporal_profile", {})
        if temporal:
            txt_lines.append(
                "  Frescura maliciosas: timestamps="
                f"{temporal.get('n_with_source_timestamp', 0)}/{temporal.get('n_malicious_evaluable', 0)} "
                f"({fmt_pct(temporal.get('timestamp_coverage'))}); "
                f"mediana={temporal.get('median_source_age_days') if temporal.get('median_source_age_days') is not None else 'n/d'} días"
            )

        # PPV/NPV ajustados para el umbral 8, que es el límite calibrado de detección.
        prev_t8 = [r for r in item.get("prevalence_adjusted", []) if int(r.get("threshold", -1)) == 8]
        if prev_t8:
            txt_lines.append("  PPV/NPV modelados @>=8 según prevalencia asumida (no son precisión empírica):")
            for row in prev_t8:
                txt_lines.append(
                    f"    - prevalencia {fmt_pct(row['prevalence'])}: PPV={fmt_pct(row['adjusted_ppv'])}, NPV={fmt_pct(row['adjusted_npv'])}"
                )

        c = item["empirical_candidates"]
        if c.get("best_f1"):
            txt_lines.append(f"  Mejor F1 observado: umbral {c['best_f1']['threshold']}")
        if c.get("best_youden"):
            txt_lines.append(f"  Mejor Youden observado: umbral {c['best_youden']['threshold']}")
        txt_lines.append("")

    txt_lines.append(
        "NOTA: los IC95% son intervalos de Wilson para proporciones binomiales. "
        "Los PPV/NPV ajustados dependen de la prevalencia asumida y de que sensibilidad/especificidad sean transportables al entorno real."
    )
    txt_lines.append(
        "NOTA TEMPORAL: la antigüedad de las muestras no sustituye una validación longitudinal. "
        "Para medir deriva temporal debe ejecutarse el mismo inspector sobre un corpus nuevo recogido posteriormente y sin solapamientos."
    )
    txt_lines.append("NOTA: estos umbrales son candidatos empíricos; no se aplican automáticamente a URL Inspector.")
    (out_dir / "benchmark_summary.txt").write_text("\n".join(txt_lines), encoding="utf-8")

    print("\n".join(txt_lines))
    print(f"\nArchivos en: {out_dir}")
    return 0


def _dataset_overlap_between(baseline_rows: list[dict[str, Any]], candidate_rows: list[dict[str, Any]]) -> dict[str, Any]:
    b = _unique_sample_rows(baseline_rows)
    c = _unique_sample_rows(candidate_rows)
    b_urls = {canonical_key(str(r.get("url") or "")) for r in b}
    c_urls = {canonical_key(str(r.get("url") or "")) for r in c}
    b_hosts = {host_key(str(r.get("url") or "")) for r in b}
    c_hosts = {host_key(str(r.get("url") or "")) for r in c}
    b_urls.discard("")
    c_urls.discard("")
    b_hosts.discard("")
    c_hosts.discard("")
    url_overlap = sorted(b_urls & c_urls)
    host_overlap = sorted(b_hosts & c_hosts)
    return {
        "baseline_unique_samples": len(b),
        "candidate_unique_samples": len(c),
        "url_overlap_count": len(url_overlap),
        "host_overlap_count": len(host_overlap),
        "url_overlap_examples": url_overlap[:20],
        "host_overlap_examples": host_overlap[:20],
        "independent_by_url_and_host": not url_overlap and not host_overlap,
    }


def cmd_compare(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline).expanduser().resolve()
    candidate_path = Path(args.candidate).expanduser().resolve()
    try:
        baseline_payload, baseline_rows = _load_results_payload(baseline_path)
        candidate_payload, candidate_rows = _load_results_payload(candidate_path)
        thresholds = [int(x.strip()) for x in str(args.thresholds).split(",") if x.strip()]
        if not thresholds or any(t < 0 or t > 100 for t in thresholds):
            raise ValueError("--thresholds debe contener enteros entre 0 y 100.")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    overlap = _dataset_overlap_between(baseline_rows, candidate_rows)
    common_modes = sorted(
        {str(r.get("mode")) for r in baseline_rows}
        & {str(r.get("mode")) for r in candidate_rows}
    )
    delta_rows: list[dict[str, Any]] = []
    comparison_modes: dict[str, Any] = {}
    for mode in common_modes:
        b_mode = [r for r in baseline_rows if str(r.get("mode")) == mode]
        c_mode = [r for r in candidate_rows if str(r.get("mode")) == mode]
        mode_rows: list[dict[str, Any]] = []
        for threshold in thresholds:
            bm = metric_row(b_mode, threshold)
            cm = metric_row(c_mode, threshold)
            row = {
                "mode": mode,
                "threshold": threshold,
                "baseline_n": bm["n_evaluable"],
                "candidate_n": cm["n_evaluable"],
                "baseline_recall": bm["recall_sensitivity"],
                "candidate_recall": cm["recall_sensitivity"],
                "delta_recall": (
                    cm["recall_sensitivity"] - bm["recall_sensitivity"]
                    if cm["recall_sensitivity"] is not None and bm["recall_sensitivity"] is not None else None
                ),
                "baseline_specificity": bm["specificity"],
                "candidate_specificity": cm["specificity"],
                "delta_specificity": (
                    cm["specificity"] - bm["specificity"]
                    if cm["specificity"] is not None and bm["specificity"] is not None else None
                ),
                "baseline_f1": bm["f1"],
                "candidate_f1": cm["f1"],
                "delta_f1": (cm["f1"] - bm["f1"] if cm["f1"] is not None and bm["f1"] is not None else None),
                "baseline_fpr": bm["false_positive_rate"],
                "candidate_fpr": cm["false_positive_rate"],
                "delta_fpr": (
                    cm["false_positive_rate"] - bm["false_positive_rate"]
                    if cm["false_positive_rate"] is not None and bm["false_positive_rate"] is not None else None
                ),
            }
            mode_rows.append(row)
            delta_rows.append(row)
        comparison_modes[mode] = mode_rows

    write_metrics_csv(out_dir / "temporal_threshold_deltas.csv", delta_rows)
    payload = {
        "benchmark_version": VERSION,
        "generated_at_utc": utc_now(),
        "baseline": {
            "path": str(baseline_path),
            "benchmark_version": baseline_payload.get("benchmark_version"),
            "updated_at_utc": baseline_payload.get("updated_at_utc"),
            "inspector_sha256": baseline_payload.get("inspector_sha256"),
        },
        "candidate": {
            "path": str(candidate_path),
            "benchmark_version": candidate_payload.get("benchmark_version"),
            "updated_at_utc": candidate_payload.get("updated_at_utc"),
            "inspector_sha256": candidate_payload.get("inspector_sha256"),
        },
        "dataset_independence_audit": overlap,
        "same_inspector_sha256": (
            bool(baseline_payload.get("inspector_sha256"))
            and baseline_payload.get("inspector_sha256") == candidate_payload.get("inspector_sha256")
        ),
        "thresholds": thresholds,
        "modes": comparison_modes,
        "interpretation_note": (
            "Esta comparación facilita validación temporal entre dos ejecuciones. "
            "Una comparación longitudinal fuerte requiere corpus recogidos en fechas distintas, sin solapamiento de URL/host y, "
            "si se pretende medir deriva de datos y no cambios del algoritmo, el mismo inspector (mismo SHA-256)."
        ),
    }
    (out_dir / "temporal_comparison.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "URL INSPECTOR 6.0 - COMPARACIÓN TEMPORAL",
        "=" * 48,
        f"Baseline:  {baseline_path}",
        f"Candidate: {candidate_path}",
        f"Solapamiento URL={overlap['url_overlap_count']} | host={overlap['host_overlap_count']} | independiente URL/host={overlap['independent_by_url_and_host']}",
        f"Mismo inspector SHA-256: {payload['same_inspector_sha256']}",
        "",
    ]
    if not overlap["independent_by_url_and_host"]:
        lines.append("ADVERTENCIA: existen URL/hosts repetidos entre ambos conjuntos; no tratar la comparación como validación independiente.")
    if not payload["same_inspector_sha256"]:
        lines.append("ADVERTENCIA: cambia el SHA-256 del inspector; la diferencia puede reflejar cambios del algoritmo además de deriva temporal.")
    for mode, mode_rows in comparison_modes.items():
        lines.append(f"MODO: {mode}")
        for row in mode_rows:
            lines.append(
                f"  >= {row['threshold']:2d}: recall {fmt_pct(row['baseline_recall'])} -> {fmt_pct(row['candidate_recall'])} "
                f"(Δ {fmt_pct(row['delta_recall']) if row['delta_recall'] is not None else 'n/d'}); "
                f"specificity {fmt_pct(row['baseline_specificity'])} -> {fmt_pct(row['candidate_specificity'])} "
                f"(Δ {fmt_pct(row['delta_specificity']) if row['delta_specificity'] is not None else 'n/d'}); "
                f"F1 {fmt_pct(row['baseline_f1'])} -> {fmt_pct(row['candidate_f1'])}"
            )
        lines.append("")
    lines.append("NOTA: los deltas son descriptivos; no constituyen por sí solos una prueba de significación estadística.")
    (out_dir / "temporal_comparison.txt").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nArchivos en: {out_dir}")
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Benchmark reproducible para URL Inspector 6.0")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="Construye el corpus sin visitar las URLs objetivo.")
    b.add_argument("--output", default="benchmark_corpus.json")
    b.add_argument("--benign", type=int, default=300)
    b.add_argument("--phishtank", type=int, default=0, help="Muestras PhishTank (opcional; por defecto 0).")
    b.add_argument("--phishstats", type=int, default=100, help="Muestras PhishStats vía API pública anónima.")
    b.add_argument("--openphish", type=int, default=100)
    b.add_argument("--urlhaus", type=int, default=100)
    b.add_argument("--tranco-pool", type=int, default=5000, help="Pool de rangos Tranco del que muestrear.")
    b.add_argument("--seed", type=int, default=DEFAULT_SEED)
    b.add_argument("--tranco-file", help="CSV/ZIP local de Tranco; evita descargarlo.")
    b.add_argument("--phishtank-file", help="CSV/BZ2 local de PhishTank online-valid.")
    b.add_argument("--phishstats-file", help="JSON local exportado de PhishStats; evita consultar la API.")
    b.add_argument("--openphish-file", help="TXT local del Community Feed de OpenPhish.")
    b.add_argument("--urlhaus-file", help="CSV local exportado de URLhaus; evita requerir Auth-Key durante build.")
    b.add_argument(
        "--exclude-corpus", action="append", default=[], metavar="JSON",
        help=(
            "Corpus o resultados previos que deben quedar fuera del corpus nuevo. "
            "Puede repetirse. Se excluyen tanto la URL canónica como el host exacto."
        ),
    )
    b.add_argument("--require-all-sources", action="store_true")
    b.set_defaults(func=cmd_build)

    r = sub.add_parser("run", help="Ejecuta URL Inspector contra el corpus (PELIGRO: contacta URLs).")
    r.add_argument("--corpus", default="benchmark_corpus.json")
    r.add_argument("--inspector", default="url_inspector_6.0.py")
    r.add_argument("--output", default="benchmark_results.json")
    r.add_argument("--mode", choices=["normal", "leave-one-out", "heuristic-only", "all"], default="leave-one-out")
    r.add_argument("--timeout", type=int, default=75, help="Timeout global máximo por URL y modo (por defecto: 75 s).")
    r.add_argument("--connect-timeout", type=int, default=3, help="Timeout de conexión usado dentro del perfil benchmark.")
    r.add_argument("--read-timeout", type=int, default=5, help="Timeout de lectura usado dentro del perfil benchmark.")
    r.add_argument("--max-redirects", type=int, default=5, help="Máximo de redirecciones HTTP seguidas en el perfil benchmark.")
    r.add_argument("--max-html-bytes", type=int, default=262144, help="Máximo de bytes HTML descargados por muestra durante benchmark.")
    r.add_argument("--stage-timeout", type=int, default=10, help="Timeout duro por etapa de red (DNS/RDAP/TLS/traza), por defecto 10 s.")
    r.add_argument("--http-stage-timeout", type=int, default=12, help="Timeout duro para la descarga HTTP/HTML, por defecto 12 s.")
    r.add_argument("--reputation-stage-timeout", type=int, default=15, help="Timeout duro para el bloque de reputación, por defecto 15 s.")
    r.add_argument("--limit", type=int, default=0, help="Limita muestras para una prueba corta.")
    r.add_argument("--resume", action="store_true")
    r.add_argument("--acknowledge-risk", action="store_true", help="Confirma ejecución en VM aislada.")
    r.set_defaults(func=cmd_run)

    q = sub.add_parser("report", help="Calcula métricas, IC95%%, desgloses, prevalencia y perfil temporal.")
    q.add_argument("--results", default="benchmark_results.json")
    q.add_argument("--output-dir", default="benchmark_report")
    q.add_argument(
        "--reference-time",
        help="Fecha ISO-8601 usada para calcular antigüedad de las muestras. Por defecto: hora UTC actual.",
    )
    q.add_argument(
        "--prevalence",
        default="0.001,0.01,0.05,0.10,0.50",
        help="Prevalencias hipotéticas separadas por comas para PPV/NPV ajustados (fracciones entre 0 y 1).",
    )
    q.set_defaults(func=cmd_report)

    c = sub.add_parser(
        "compare",
        help="Compara dos resultados independientes para apoyar una validación temporal/longitudinal.",
    )
    c.add_argument("--baseline", required=True, help="JSON de resultados de referencia.")
    c.add_argument("--candidate", required=True, help="JSON de resultados posteriores.")
    c.add_argument("--output-dir", default="benchmark_temporal_comparison")
    c.add_argument("--thresholds", default="8,20,30,40,50")
    c.set_defaults(func=cmd_compare)

    w = sub.add_parser("_worker", help=argparse.SUPPRESS)
    w.add_argument("--inspector", required=True)
    w.add_argument("--url", required=True)
    w.add_argument("--source", required=True)
    w.add_argument("--mode", choices=["normal", "leave-one-out", "heuristic-only"], required=True)
    w.add_argument("--output", required=True)
    w.add_argument("--connect-timeout", type=int, default=3)
    w.add_argument("--read-timeout", type=int, default=5)
    w.add_argument("--max-redirects", type=int, default=5)
    w.add_argument("--max-html-bytes", type=int, default=262144)
    w.add_argument("--stage-timeout", type=int, default=10)
    w.add_argument("--http-stage-timeout", type=int, default=12)
    w.add_argument("--reputation-stage-timeout", type=int, default=15)
    w.add_argument("--trace-log")
    w.set_defaults(func=worker_run)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
