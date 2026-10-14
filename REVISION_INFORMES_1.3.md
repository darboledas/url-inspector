# URL Inspector 6.0 — complemento de informes 1.3

Base: motor FINAL_PUBLIC 1.18.1, sin modificaciones. SHA-256 original: `30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a`.

## Objetivo de la versión

- El **pericial PDF** mantiene la estructura basada en la UNE 197001:2019 y añade un anexo exhaustivo con **todos los campos del JSON** (incluidos geolocalización, DNS, RDAP, TLS, HTTP, HTML, infraestructura/CDN, reputación y errores). Ninguna lista ni valor se abrevia en ese anexo. El original JSON se conserva, y se muestra su SHA-256 si se conoce su ruta.
- Se añade el **pericial HTML**, autocontenido, imprimible desde el navegador, con los ocho capítulos, la transcripción literal de consola cuando esté disponible y todos los campos completos del JSON. Para archivos extensos, HTML puede ser más útil que PDF.
- Las nuevas inspecciones realizadas a través de `url_inspector_informes_une.py` con `--json` generan automáticamente `nombre.consola.txt`, un registro real de stdout y stderr tal como los emite el motor. El menú genera los informes después desde el mismo JSON y asocia ese registro. No se repite la conexión con la URL.
- Si se invoca el programa directamente con `--pdf-forensic`, la capa del complemento actualiza el PDF al acabar la inspección, para añadir el registro ya completado sin repetir ningún análisis.
- El ejecutivo incorpora un **resultado principal categórico**: riesgo bajo, moderado, alto, muy alto, crítico o alerta de reputación externa. Es una clasificación operativa, **no una probabilidad estadística** de malignidad o legitimidad, y respeta íntegramente el score y nivel originales.

## Limitación retrospectiva fundamental

Los JSON de BOE y AMTSO obtenidos el 13/10/2026 **no guardaron un registro literal de consola**. Por tanto, los informes reexportados contienen todos los datos estructurados, pero identifican el registro de consola como no disponible. No se simula ni reconstruye una supuesta salida de consola. Para obtener ese documento en próximas inspecciones deben guardarse los `*.consola.txt` junto a sus JSON.

## Ejecución Windows / Linux

Abra respectivamente `ejecutar_url_inspector_INFORMES_UNE.bat` o `./ejecutar_url_inspector_INFORMES_UNE.sh` (Linux), sin argumentos:

1. Analizar una nueva URL y conservar JSON + registro de consola, y luego elegir PDF/HTML de informes.
2. Generar informes offline desde un JSON guardado, con la transcripción de consola si existe el archivo homónimo `.consola.txt`.

Elegir informes: **1** pericial PDF + HTML; **2** ejecutivo PDF; **3** pericial PDF + HTML + ejecutivo PDF; **4** solo pericial HTML; **0** conservar solo JSON.

Para producir los tres informes desde un JSON anterior, sin red:

```bash
python informes_une_197001.py resultados.json \
  --pericial informe_pericial.pdf \
  --pericial-html informe_pericial.html \
  --ejecutivo informe_ejecutivo.pdf
```

Si el registro de consola está en otro fichero, agregar `--registro-consola ruta/al/registro.txt`.

También puede iniciar una inspección directa en Windows o Linux:

```bash
python url_inspector_informes_une.py https://example.com --full --no-menu \
  --json resultados.json --pdf-forensic pericial.pdf \
  --pdf-executive ejecutivo.pdf --pericial-html pericial.html
```

No modificar ni borrar `url_inspector_6.0.py`. La presentación y captura están íntegramente en módulos externos.

## Precauciones periciales y privacidad

- La transcripción recoge stdout/stderr y **no equivale a un registro de tráfico de red** ni a un sellado de tiempo externo. No registra lo escrito por el usuario en stdin. No acredita cadena de custodia por sí sola.
- El JSON y el registro de consola pueden incluir URL con identificadores, cabeceras u otros datos reservados; deben revisarse y custodiarse fuera de GitHub público.
- La estructura UNE no significa conformidad certificada. El borrador requiere identificación y firma del perito, revisión de fuentes, errores, alcance y evidencia independiente.
- La puntuación heurística 0-100 **no es una probabilidad porcentual de phishing**. Riesgo bajo no certifica que una página sea confiable.
- Para los informes HTML se recomienda conservar también el JSON original y su SHA-256. Si imprime el HTML como PDF desde navegador, compruebe paginación y contenido antes de incorporarlo a un expediente.

## Validación

Pruebas offline y reexportación desde los resultados originales de BOE y AMTSO. La integración continua de GitHub Actions para esta versión deberá ejecutarse tras su publicación. No se declara todavía que el nuevo registro de consola haya sido verificado en Windows real.
