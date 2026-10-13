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
