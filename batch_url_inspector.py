#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""URL Inspector 6.0 - procesamiento batch seguro y reproducible.

El batch NO modifica la lógica del inspector. Ejecuta una instancia aislada de
``url_inspector_6.0.py`` por URL, recoge su JSON estructurado y construye un
resumen tabular. No genera capturas headless salvo que el usuario ejecute el
inspector individualmente con --screenshot.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

VERSION = "1.18.1"
DEFAULT_TIMEOUT = 90
URL_COLUMN_CANDIDATES = ("url", "uri", "link", "target", "address")


@dataclass
class BatchRow:
    index: int
    input_url: str
    status: str
    elapsed_seconds: float
    final_url: str | None = None
    registered_domain: str | None = None
    score_0_to_100: int | None = None
    level_1_to_5: int | None = None
    operational_verdict: str | None = None
    reputation_alert: bool | None = None
    reputation_alert_text: str | None = None
    technical_coverage: int | None = None
    reputation_coverage_evaluated: int | None = None
    reputation_coverage_total: int | None = None
    reputation_coverage_percent: int | None = None
    result_json: str | None = None
    error: str | None = None


def _clean_url(value: Any) -> str:
    return str(value or "").strip().lstrip("\ufeff")


def read_txt_urls(path: Path) -> list[str]:
    urls: list[str] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        urls.append(value)
    return urls


def _choose_url_column(fieldnames: list[str], requested: str | None = None) -> str:
    if requested:
        for name in fieldnames:
            if name.casefold() == requested.casefold():
                return name
        raise ValueError(f"La columna solicitada {requested!r} no existe en el CSV.")
    lower = {name.casefold(): name for name in fieldnames}
    for candidate in URL_COLUMN_CANDIDATES:
        if candidate in lower:
            return lower[candidate]
    raise ValueError(
        "No se encontró una columna de URL. Use --url-column. "
        f"Columnas disponibles: {', '.join(fieldnames) or 'ninguna'}"
    )


def read_csv_urls(path: Path, url_column: str | None = None) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("El CSV no contiene cabecera.")
        column = _choose_url_column(list(reader.fieldnames), url_column)
        return [_clean_url(row.get(column)) for row in reader if _clean_url(row.get(column))]


def read_input_urls(path: Path, url_column: str | None = None) -> list[str]:
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        return read_csv_urls(path, url_column)
    if suffix in {".txt", ".list", ".urls"}:
        return read_txt_urls(path)
    raise ValueError("Formato de entrada no soportado. Use .txt, .list, .urls o .csv.")


def deduplicate_urls(urls: Iterable[str]) -> tuple[list[str], int]:
    seen: set[str] = set()
    unique: list[str] = []
    duplicates = 0
    for url in urls:
        key = url.strip()
        if not key:
            continue
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(key)
    return unique, duplicates


def _safe_stem(url: str, index: int) -> str:
    host = (urlsplit(url if "://" in url else "https://" + url).hostname or "url").lower()
    host = re.sub(r"[^a-z0-9._-]+", "_", host).strip("._-") or "url"
    digest = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{index:05d}_{host[:60]}_{digest}"


def _load_result(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_result(index: int, input_url: str, elapsed: float, result_path: Path, payload: dict[str, Any]) -> BatchRow:
    assessment = payload.get("phishing_assessment") or {}
    summary = payload.get("executive_summary") or {}
    return BatchRow(
        index=index,
        input_url=input_url,
        status="ok",
        elapsed_seconds=round(elapsed, 3),
        final_url=payload.get("final_url"),
        registered_domain=payload.get("registered_domain"),
        score_0_to_100=assessment.get("score_0_to_100"),
        level_1_to_5=assessment.get("level_1_to_5"),
        operational_verdict=summary.get("operational_verdict"),
        reputation_alert=bool(summary.get("reputation_alert")),
        reputation_alert_text=summary.get("reputation_alert_text"),
        technical_coverage=summary.get("analysis_coverage_score", summary.get("confidence_score")),
        reputation_coverage_evaluated=summary.get("reputation_coverage_evaluated"),
        reputation_coverage_total=summary.get("reputation_coverage_total"),
        reputation_coverage_percent=summary.get("reputation_coverage_percent"),
        result_json=str(result_path.resolve()),
    )


def _read_existing_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = payload.get("results") if isinstance(payload, dict) else None
    return rows if isinstance(rows, list) else []


def _write_csv(path: Path, rows: list[BatchRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(BatchRow.__dataclass_fields__.keys())
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def _write_json(path: Path, *, input_file: Path, inspector: Path, rows: list[BatchRow], duplicate_count: int) -> None:
    status_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row.status] = status_counts.get(row.status, 0) + 1
    payload = {
        "batch_version": VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file.resolve()),
        "inspector": str(inspector.resolve()),
        "inspector_sha256": hashlib.sha256(inspector.read_bytes()).hexdigest(),
        "duplicates_removed": duplicate_count,
        "counts": {"total": len(rows), "status": status_counts},
        "results": [asdict(row) for row in rows],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_command(inspector: Path, url: str, result_path: Path, *, full: bool, brands_file: str | None) -> list[str]:
    cmd = [sys.executable, str(inspector), url, "--json", str(result_path), "--no-menu", "--no-screenshot"]
    if full:
        cmd.append("--full")
    if brands_file:
        cmd.extend(["--brands-file", brands_file])
    return cmd


def run_batch(args: argparse.Namespace) -> int:
    input_path = Path(args.input).expanduser().resolve()
    inspector = Path(args.inspector).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    if not input_path.is_file():
        raise SystemExit(f"No existe el archivo de entrada: {input_path}")
    if not inspector.is_file():
        raise SystemExit(f"No existe el inspector: {inspector}")

    try:
        urls, duplicate_count = deduplicate_urls(read_input_urls(input_path, args.url_column))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.limit is not None:
        urls = urls[: args.limit]
    if not urls:
        raise SystemExit("No se encontraron URLs para analizar.")

    print(f"URLs únicas: {len(urls)} | duplicadas omitidas: {duplicate_count}")
    if args.dry_run:
        print("DRY-RUN: no se realizará ninguna conexión ni se ejecutará URL Inspector.")
        for idx, url in enumerate(urls, 1):
            print(f"{idx:05d}  {url}")
        return 0

    if not args.acknowledge_risk:
        raise SystemExit(
            "El modo batch puede contactar URLs hostiles. Repita con --acknowledge-risk "
            "solo en un entorno adecuado y aislado."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    individual_dir = output_dir / "individual"
    individual_dir.mkdir(parents=True, exist_ok=True)
    aggregate_json = output_dir / "batch_results.json"
    aggregate_csv = output_dir / "batch_results.csv"

    prior_rows = _read_existing_rows(aggregate_json) if args.resume else []
    prior_by_url = {str(row.get("input_url")): row for row in prior_rows if row.get("input_url")}
    rows: list[BatchRow] = []

    for index, url in enumerate(urls, 1):
        if args.resume and url in prior_by_url:
            old = prior_by_url[url]
            try:
                rows.append(BatchRow(**{k: old.get(k) for k in BatchRow.__dataclass_fields__}))
                print(f"[{index}/{len(urls)}] RESUME {url}")
                continue
            except TypeError:
                pass

        result_path = individual_dir / f"{_safe_stem(url, index)}.json"
        cmd = build_command(inspector, url, result_path, full=args.full, brands_file=args.brands_file)
        started = time.monotonic()
        try:
            child_env = os.environ.copy()
            # En Windows, un proceso Python con stdout redirigido a PIPE puede
            # heredar cp1252 aunque la consola interactiva acepte Unicode.
            # Forzamos UTF-8 solo en el hijo para que símbolos del inspector
            # (p. ej. ●) no provoquen UnicodeEncodeError antes de escribir JSON.
            child_env["PYTHONIOENCODING"] = "utf-8"
            child_env["PYTHONUTF8"] = "1"
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=args.timeout,
                env=child_env,
            )
            elapsed = time.monotonic() - started
            if result_path.exists():
                try:
                    payload = _load_result(result_path)
                    row = summarize_result(index, url, elapsed, result_path, payload)
                    if proc.returncode != 0:
                        row.status = f"exit_{proc.returncode}"
                        row.error = (proc.stdout or "")[-1000:] or f"Código de salida {proc.returncode}"
                except Exception as exc:
                    row = BatchRow(index, url, "invalid_json", round(elapsed, 3), error=str(exc), result_json=str(result_path))
            else:
                status = "blocked" if proc.returncode == 4 else f"exit_{proc.returncode}"
                row = BatchRow(index, url, status, round(elapsed, 3), error=(proc.stdout or "")[-1500:] or "Sin JSON de salida")
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - started
            out = exc.stdout or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", errors="replace")
            row = BatchRow(index, url, "timeout", round(elapsed, 3), error=str(out)[-1500:] or f"Timeout de {args.timeout}s")
        except Exception as exc:
            elapsed = time.monotonic() - started
            row = BatchRow(index, url, "error", round(elapsed, 3), error=str(exc))

        rows.append(row)
        score = "-" if row.score_0_to_100 is None else row.score_0_to_100
        verdict = row.operational_verdict or "-"
        print(f"[{index}/{len(urls)}] {row.status.upper():12s} score={score!s:>3} | {verdict} | {url}")

        _write_csv(aggregate_csv, rows)
        _write_json(aggregate_json, input_file=input_path, inspector=inspector, rows=rows, duplicate_count=duplicate_count)
        if args.delay > 0 and index < len(urls):
            time.sleep(args.delay)

    ok = sum(1 for row in rows if row.status == "ok")
    blocked = sum(1 for row in rows if row.status == "blocked")
    timeouts = sum(1 for row in rows if row.status == "timeout")
    rep_alerts = sum(1 for row in rows if row.reputation_alert)
    print("\nRESUMEN BATCH")
    print(f"Total={len(rows)} | ok={ok} | bloqueadas={blocked} | timeout={timeouts} | alertas reputacionales={rep_alerts}")
    print(f"CSV:  {aggregate_csv}")
    print(f"JSON: {aggregate_json}")
    return 0 if ok + blocked == len(rows) else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="URL Inspector 6.0 - análisis batch de listas TXT/CSV con resumen CSV/JSON."
    )
    parser.add_argument("input", help="Archivo .txt/.list/.urls (una URL por línea) o .csv.")
    parser.add_argument("--inspector", default="url_inspector_6.0.py", help="Ruta a url_inspector_6.0.py.")
    parser.add_argument("--output-dir", default="batch_output", help="Directorio de salida.")
    parser.add_argument("--url-column", help="Nombre de la columna URL si el CSV no usa url/uri/link/target/address.")
    parser.add_argument("--full", action=argparse.BooleanOptionalAction, default=True, help="Ejecuta análisis completo (por defecto: sí).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout por URL en segundos (por defecto {DEFAULT_TIMEOUT}).")
    parser.add_argument("--delay", type=float, default=0.5, help="Pausa entre URLs en segundos (por defecto 0.5).")
    parser.add_argument("--limit", type=int, help="Procesa solo las primeras N URLs únicas.")
    parser.add_argument("--resume", action="store_true", help="Reutiliza resultados ya presentes en batch_results.json.")
    parser.add_argument("--brands-file", help="Lista local de referencia para typosquatting que se pasa al inspector.")
    parser.add_argument("--dry-run", action="store_true", help="Valida y enumera la entrada sin visitar ninguna URL.")
    parser.add_argument(
        "--acknowledge-risk",
        action="store_true",
        help="Confirma que el batch puede contactar URLs hostiles. Obligatorio salvo con --dry-run.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout debe ser mayor que 0")
    if args.delay < 0:
        parser.error("--delay no puede ser negativo")
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit debe ser mayor que 0")
    return run_batch(args)


if __name__ == "__main__":
    raise SystemExit(main())
