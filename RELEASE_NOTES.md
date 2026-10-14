# Release estable 1.18.1

## Estado

Versión validada en Windows dentro del entorno Python del proyecto.

- Suite offline: 40/40 pruebas superadas.
- Compilación: correcta.
- Smoke tests de CLI: correctos.
- Prueba batch real: 2/2 URLs de ejemplo procesadas correctamente.
- CI incluido para Windows/Linux con Python 3.11 y 3.13.

## Licencia

La distribución pública 1.18.1 se publica bajo licencia MIT. Copyright (c) 2026 David Arboledas.

## Motor calibrado

`url_inspector_6.0.py` no cambia respecto a las revisiones 1.16–1.18.1 en la lógica de puntuación. SHA-256 del motor estable:

`30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a`

## 1.18.1

Hotfix del modo batch para Windows. El proceso hijo del inspector fuerza UTF-8 mediante `PYTHONIOENCODING=utf-8` y `PYTHONUTF8=1`, evitando `UnicodeEncodeError` cuando la salida estándar se redirige a `PIPE`.

## 1.18

Se incorpora procesamiento batch de listas TXT/CSV con deduplicación, `--dry-run`, `--resume`, timeout por URL, salidas CSV/JSON e informes JSON individuales. La ejecución activa requiere `--acknowledge-risk`.

## Validación independiente

La escala permanece basada en una campaña independiente de 600 URLs sin solapamiento de URL ni host con el corpus de desarrollo. El umbral 8 fue el mejor por F1 e índice de Youden. Véase `docs/VALIDACION_INDEPENDIENTE_600.md`.


## Complemento de informes UNE 197001:2019 — 1.2 (2026-10-13)

- Corrección de paginación en muestras ejecutivas BOE y AMTSO (1 página por informe).
- Representación legible de diccionarios y listas, más desglose de DNS.
- Disponibilidad real de proveedores reputacionales priorizada frente al indicador `configured` y distinción de errores de consulta.
- Incluye la segunda corrección del iniciador Windows.
- Motor 1.18.1 sin modificaciones; JSON de adquisición sin cambios en reexportación offline.
- Validación local: 58 pruebas (no equivale a nueva validación de CI Windows).



## Informes 1.3.2 — revisión de presentación (motor 1.18.1)

- El PDF ejecutivo, el pericial PDF y el pericial HTML explican los límites de la cobertura técnica ponderada de cinco componentes. La cobertura reputacional se presenta por separado. La cifra de cobertura no es una probabilidad de legitimidad.
- Índice general del pericial PDF limitado a capítulos, declaraciones/firma y anejos. Se mantiene el desarrollo técnico completo y todos los campos del JSON/registro de consola en los anejos.
- Sin cambios en `url_inspector_6.0.py`, heurísticas, reputación ni puntuaciones. Regeneración offline compatible con los JSON anteriores.
- Pruebas de regresión adicionales para cobertura e índice. Antes de publicar, repetir CI Windows/Ubuntu, Python 3.11/3.13.
