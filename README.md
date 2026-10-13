# URL Inspector 6.0

URL Inspector 6.0 es una herramienta defensiva de análisis de URLs orientada a inspección técnica, reputacional y forense. Resuelve redirecciones, analiza identidad de dominio, DNS/RDAP, TLS, infraestructura, HTML y reputación externa, y genera resultados en JSON, HTML y PDF.

La versión estable distribuida aquí es **1.18.1**. El motor calibrado `url_inspector_6.0.py` mantiene congeladas sus heurísticas, pesos y umbrales desde la validación independiente. Las revisiones posteriores han añadido endurecimiento de seguridad, pruebas automáticas, análisis científico del benchmark y modo batch sin recalibrar el score.

## Instalación

Requiere Python 3.11 o superior.

```bash
python -m pip install -r requirements_v6.txt
```

## Uso rápido

Análisis individual:

```bash
python url_inspector_6.0.py https://example.com --full
```

Pruebas automáticas offline:

```bat
run_tests.bat
```

Validación de una lista sin realizar conexiones:

```bash
python batch_url_inspector.py batch_urls_ejemplo.txt --dry-run
```

Ejecución batch activa:

```bash
python batch_url_inspector.py urls.txt --acknowledge-risk
```

El modo batch puede contactar URLs hostiles. Debe ejecutarse en un entorno apropiado y aislado cuando se analicen indicadores maliciosos.

## Escala de riesgo

La puntuación 0–100 es una puntuación heurística calibrada y **no una probabilidad de phishing o malware**. La escala adoptada es:

| Score | Nivel |
|---:|---|
| 0–7 | 1 — Bajo |
| 8–19 | 2 — Moderado |
| 20–29 | 3 — Alto |
| 30–49 | 4 — Muy alto |
| 50–100 | 5 — Crítico |

En la validación independiente de 600 URLs, el umbral 8 obtuvo sensibilidad 84,3 %, especificidad 91,3 % y F1 87,4 %. Consulte `CALIBRACION_ESCALA_RIESGO.md` y `docs/VALIDACION_INDEPENDIENTE_600.md` para el detalle y las limitaciones metodológicas.

## Seguridad

El inspector bloquea destinos locales/no públicos y valida redirecciones para reducir el riesgo de SSRF. Las capturas headless son opt-in mediante `--screenshot`. La reputación negativa se presenta separada del score heurístico para evitar que un score bajo se interprete como garantía de seguridad.

El corpus de regresión incluido contiene indicadores históricos potencialmente maliciosos. **No abra ni visite manualmente esas URLs.** Consulte `SECURITY.md`.

## Estructura principal

- `url_inspector_6.0.py`: inspector individual.
- `batch_url_inspector.py`: procesamiento batch TXT/CSV.
- `benchmark_url_inspector.py`: construcción, ejecución y análisis del benchmark.
- `tests/`: suite offline de regresión.
- `.github/workflows/ci.yml`: CI para Windows/Linux.
- `CALIBRACION_ESCALA_RIESGO.md`: justificación de la escala.
- `README_URL_Inspector_6.0.md`: manual técnico completo.
- `README_BENCHMARK.md`: metodología del benchmark.
- `README_TESTS.md`: alcance de las pruebas automáticas.

## Reproducibilidad

El repositorio incluye el corpus histórico de regresión y su SHA-256. Ese corpus sirvió para desarrollo/regresión y **no debe reutilizarse como única validación independiente** de cambios futuros en heurísticas, pesos o umbrales.

Cualquier cambio en la lógica de puntuación debe acompañarse de una nueva validación independiente sobre un corpus fresco sin solapamiento de URL ni host.

## Claves y secretos

Las credenciales se cargan mediante variables de entorno. No se incluyen claves en esta distribución. `.gitignore` excluye `APIKEY.txt`, `.env`, claves privadas y salidas locales.

## Licencia

Este proyecto se distribuye bajo la **licencia MIT**. Consulte el archivo `LICENSE`. La licencia permite usar, copiar, modificar, distribuir y sublicenciar el software, incluso con fines comerciales, siempre que se conserve el aviso de copyright y la licencia. El software se proporciona sin garantía.
