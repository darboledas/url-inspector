# Revisión de presentación de informes 1.2 — 13/10/2026

**Base:** URL Inspector 6.0 FINAL_PUBLIC 1.18.1. La huella del motor (`url_inspector_6.0.py`) se mantiene en `30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a`.

## Cambios respecto del complemento 1.1

1. **Informe ejecutivo PDF:** estilos tipográficos y espaciado adaptados para que los casos BOE y AMTSO examinados produzcan una página completa, incluidas conclusiones, fuentes y limitaciones. Los informes con resultados más extensos pueden necesitar varias páginas: no se elimina información únicamente para forzar una página.
2. **Presentación de estructuras:** valores de listas y diccionarios presentados con campos legibles y abreviación explícita. Los registros DNS aparecen separados por tipo. El JSON asociado al informe pericial conserva los datos de origen completos, incluidos los omitidos o abreviados en el PDF.
3. **Disponibilidad de reputación:** cuando una fuente indica `available=true`, se muestra el resultado de la consulta aunque `configured=false`. Si una consulta produjo un error, se diferencia de una fuente no configurada. Los metadatos originales se conservan inalterados en el anejo JSON. Ninguna ausencia de coincidencias se interpreta como garantía de seguridad.
4. **Windows:** el paquete completo incluye la segunda corrección del lanzador `.bat` probada en el equipo del usuario (entorno Anaconda `cientifico`), sin modificar el ejecutable Python del motor.

## Reexportación sin nuevas inspecciones

Ejecute desde la carpeta del programa (en Windows, usando el entorno Python adecuado; en Linux, desde el entorno donde estén instaladas las dependencias):

```bash
python informes_une_197001.py original.json --pericial pericial.pdf --ejecutivo ejecutivo.pdf
```

La ejecución offline solo lee `original.json`. No repite consultas externas ni modifica el resultado heurístico. Guarde el JSON de entrada original separado del `pericial_datos.json` exportado y preserve su huella SHA-256 si forma parte de un expediente.

## Validación y límites

La estructura del informe pericial se basa en **UNE 197001:2019**; no certifica conformidad ni constituye por sí misma un dictamen firmado. Son obligatorias revisión profesional, individualización, identificación y firma, y, cuando proceda, documentación de las actuaciones y custodia. Una huella SHA-256 solo comprueba integridad entre dos copias, no autenticidad de las evidencias en origen.

Los dos casos proceden de análisis reales aportados para ensayo de presentación. La web AMTSO utilizada es una simulación de phishing y no demuestra la sensibilidad de detección frente a una URL maliciosa real. La nueva validación en GitHub Actions debe realizarse después de subir el complemento 1.2.
