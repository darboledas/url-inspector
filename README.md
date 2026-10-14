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

## Complemento opcional de informes UNE 197001:2019

Se incluye un generador de borradores periciales estructurados con arreglo a la UNE 197001:2019 y de informes ejecutivos sin modificar el motor calibrado. Consulte [INFORMES_UNE_197001.md](INFORMES_UNE_197001.md) para uso, campos pendientes y límites. Para abrir el **menú guiado** use `ejecutar_url_inspector_INFORMES_UNE.bat` en Windows o `./ejecutar_url_inspector_INFORMES_UNE.sh` en Linux. Ambos permiten **(1) inspeccionar una URL y conservar su JSON, o (2) crear PDF desde un JSON anterior sin nueva inspección**. Requieren Python 3.11+, crean `.venv/` si es necesario y documentan la instalación y los comandos avanzados en [INFORMES_UNE_197001.md](INFORMES_UNE_197001.md). El informe pericial es un **borrador automatizado** pendiente de revisión y firma.


### Complemento UNE de informes 1.2

Consulte [`REVISION_INFORMES_1.2.md`](REVISION_INFORMES_1.2.md) para las correcciones de presentación de PDFs (ejecutivo, tablas y reputación), instrucciones de reexportación sin red y límites periciales. La versión del motor sigue siendo 1.18.1.

### Complemento de informes periciales y ejecutivos 1.3

Módulos opcionales independientes del motor validado. El informe pericial se genera en
PDF y HTML, con todos los resultados estructurados, los errores y el registro real
de stdout/stderr cuando haya sido capturado. El ejecutivo resume el nivel operativo
sin presentarlo como probabilidad estadística. Documentación detallada en
`REVISION_INFORMES_1.3.md`. Los resultados y registros de consola de casos reales
son privados y no deben incorporarse al repositorio público.

## Complemento de informes 1.3.2 (motor 1.18.1)

Sin modificar la calibración del motor, el generador `informes_une_197001.py` exporta informe pericial PDF y HTML completo, e informe ejecutivo PDF. La versión 1.3.2 aclara que la cobertura técnica está ponderada sobre cinco componentes del motor (URL, RDAP, TLS, HTTP y HTML), no equivale a seguridad ni incluye todas las comprobaciones posibles. También simplifica el índice PDF sin excluir campos de resultados.

Para lanzar el menú interactivo desde Windows, use `ejecutar_url_inspector_INFORMES_UNE.bat`; desde Linux, `./ejecutar_url_inspector_INFORMES_UNE.sh` (con permisos de ejecución). La opción 2 genera informes offline desde JSON anterior, sin nueva inspección. Consulte `INFORMES_UNE_197001.md` y `REVISION_INFORMES_1.3.2.md`.
