# URL Inspector 6.0 — Corrección documental de informes 1.3.1

**Motor:** 1.18.1 sin modificar; SHA-256 esperado `30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a`.

Esta versión cambia solo `informes_une_197001.py`, añade pruebas a `tests/test_reports_une.py` y actualiza la documentación. El motor no se recalibra, no cambia la puntuación de riesgo y no se repite la inspección de la URL al generar los informes.

## Cambios

1. **Transcripción de consola en HTML.** Se evita la traducción automática de finales de línea en Windows escribiendo bytes UTF-8. Para su presentación, los finales de línea del registro se normalizan a LF (no se insertan líneas adicionales). La reproducción visual no sustituye al archivo original `.consola.txt`, que conserva sus bytes originales y está identificado por SHA-256.
2. **Identificadores y huellas sin espacios insertados.** El formateador ya no utiliza `textwrap.wrap()` sobre valores escalares que puedan incluir identificadores criptográficos. Las huellas hexadecimales del resumen principal se maquetan con estilo tipográfico ajustado. La fuente exacta de comparación continúa siendo el JSON original.
3. **Trazabilidad temporal de la exportación.** Los informes periciales PDF y HTML identifican la fecha y hora UTC de generación técnica del borrador y la versión `1.3.1` del generador documental. Es distinta de la fecha de análisis del motor y de la fecha de emisión y firma del perito, que queda pendiente hasta su cumplimentación.
4. **Copia fiel del JSON.** Si se proporciona un fichero original existente y su contenido JSON coincide con los datos exportados, el archivo `*_datos.json` es una copia binaria exacta del original, con SHA-256 idéntico. Si no hay archivo original verificable, se crea una serialización derivada y se identifica como tal; nunca se afirma igualdad binaria sin comprobarla. En ningún caso se modifica el JSON fuente.

## Ejecución para regenerar informes sin consultar la URL

Abrir el terminal en la carpeta del programa y ejecutar (una sola línea en Windows):

```cmd
python informes_une_197001.py "ruta\resultados.json" --registro-consola "ruta\resultados.consola.txt" --pericial-html "ruta\pericial.html" --pericial "ruta\pericial.pdf" --ejecutivo "ruta\ejecutivo.pdf"
```

En el menú compartido Windows y Linux también puede elegir la opción 2 (informes desde JSON anterior), indicando la ruta del archivo y los tipos de informe a crear.

## Prueba de regresión: BOE del 14/10/2026

Fuente: JSON y consola aportados por el usuario en `BOE_revision_informes_1_3.zip`. La comprobación es documental, **no** una nueva consulta a www.boe.es.

- Se conservan los 22 campos de primer nivel y los 257 campos terminales registrados del resultado original.
- El HTML reproduce las 214 líneas físicas de consola (normalizadas a LF) sin duplicar líneas; el `.consola.txt` original permanece intacto.
- La huella original del JSON es `e11e567d4f2a1535c0d89b4356307ee2f618d4e2d0da2eaa4240cfd112590529`; la huella de la copia asociada es idéntica.
- La huella del certificado TLS en la tabla principal se presenta sin espacios añadidos entre caracteres.
- El pericial PDF corregido contiene 23 páginas; el ejecutivo mantiene una página. Las fechas de creación documental no sustituyen fecha de firma ni sellado de tiempo de tercero.

## Alcance y limitaciones

Las nuevas pruebas automáticas no sustituyen la prueba del lanzador BAT en el ordenador del usuario ni una nueva CI de GitHub Actions. Los informes son borradores de presentación sujetos a revisión y firma del perito. La conformidad con UNE 197001:2019 no queda certificada por la sola estructura documental. La salida HTML normaliza los saltos de línea solo a efectos de lectura; para una transcripción literalmente byte a byte debe conservarse y contrastarse el `.consola.txt` original y su SHA-256.
