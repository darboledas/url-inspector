# Complemento de informes PDF — UNE 197001:2019

**Base:** URL Inspector 6.0 FINAL_PUBLIC 1.18.1. El archivo `url_inspector_6.0.py` no se modifica ni se recalibra. Este complemento cambia **únicamente la presentación de los informes PDF**; conserva los análisis y la clasificación original.

## Dos salidas

- **Informe pericial técnico**: borrador con estructura basada en la norma española **UNE 197001:2019** (no se trata de una norma ISO). Incluye identificación, declaraciones condicionadas, índice paginado, los ocho capítulos del cuerpo, anejos, fecha y firma pendientes. Adjunta como fichero separado `*_datos.json` con todos los resultados originales y su SHA-256 documentado. El PDF también muestra la huella de la serialización canónica de los datos. En todas sus páginas aparece la referencia provisional y la numeración `Página X de Y`.
- **Informe ejecutivo**: resumen dirigido a no especialistas, con resultado operativo, señales principales, fuentes y limitaciones. No afirma conformidad con UNE ni constituye una declaración pericial.

La UNE se utiliza como **referencia de estructura**, no como certificación del documento. Los hechos del análisis proceden de la salida de URL Inspector. Los campos introducidos manualmente por un profesional no son verificados por el programa. El documento automático NO constituye un dictamen pericial final, NO suple cadena de custodia y requiere revisión, contextualización y firma.

**No se distribuye el PDF de la norma UNE**: está sujeto a derechos de autor.

## Uso tradicional integrado (Windows)

En la carpeta del programa, desde una consola de Windows:

```bat
ejecutar_url_inspector_INFORMES_UNE.bat https://example.com --full
```

Tras el análisis, se mostrará el menú original para elegir informes; **Enter** genera ambos PDF. La interfaz original, pruebas y programas `batch` / `benchmark` siguen intactos.

Para personalizar los campos judiciales y profesionales, copie `datos_pericia_plantilla.json` a un archivo propio fuera del repositorio, edítelo y ejecute:

```bat
ejecutar_url_inspector_INFORMES_UNE.bat https://example.com --full --datos-pericia "C:\ruta\datos_privados.json"
```

También puede elegir destinos explícitos con la misma CLI del motor:

```bat
python url_inspector_informes_une.py https://example.com --full --pdf-forensic informe_pericial.pdf --pdf-executive informe_ejecutivo.pdf --json resultados.json
```

**Atención:** el análisis activo contacta direcciones y proveedores externos. Mantenga las precauciones habituales en URLs maliciosas; las capturas headless son opcionales y potencialmente peligrosas.

## Generación desde resultados existentes (sin acceso a Internet)

Con un archivo JSON ya producido por URL Inspector:

```bat
python informes_une_197001.py resultados.json --pericial informe_pericial.pdf --ejecutivo informe_ejecutivo.pdf --datos-pericia "C:\ruta\datos_privados.json"
```

Esto no visita la URL ni recalcula el nivel/score. Es útil para preparar una nueva presentación y cumplimentar metadatos sin volver a adquirir evidencias. **Conserve la copia original** de los resultados y registre toda edición posterior. La fecha `generated_at_utc` es la hora informada por la herramienta, no un sellado temporal cualificado.

## Pautas profesionales

1. Proporcione datos reales de perito, solicitante, encargo, antecedentes y cuestiones formuladas.
2. Revise individualmente hallazgos, fuentes no evaluadas, limitaciones y valor probatorio de los indicadores.
3. Añada la documentación de adquisición, custodia, captura, fuentes y sello de tiempo cuando exista.
4. Complete el dictamen propio, las declaraciones procedentes, la referencia definitiva, fecha y firma; no trate los campos pendientes como certificaciones.
5. Una vez emitido y firmado, preserve el informe sin alteraciones. Calcule y archive su SHA-256 **fuera del propio PDF** si necesita documentar su integridad.

Los campos de ejemplo no incluyen ninguna información personal; deben mantenerse fuera del repositorio si se cumplimentan. Los JSON de análisis pueden contener datos sensibles del caso y **no deben publicarse** en el repositorio.

## Limitaciones y aspectos no probados

- El PDF generado verifica la estructura, no que un profesional haya aplicado todos los requisitos materiales y procesales de la pericia.
- El archivo JSON contiguo recoge los datos completos. Si se distribuye el PDF, debe entregarse también el JSON y preservarse el vínculo criptográfico indicado.
- El SHA-256 del conjunto de datos no prueba autoría, hora de origen ni custodia previa; solo sirve para comparar contenido.
- La ausencia de alertas en un servicio externo no demuestra seguridad; un proveedor no disponible queda como no evaluado.
- Las puntuaciones existentes no representan probabilidades estadísticas de delito o phishing.

## Archivos añadidos

- `informes_une_197001.py`: generador y CLI offline.
- `url_inspector_informes_une.py`: lanzador que importa el motor original y sustituye en memoria solo las dos funciones de exportación PDF.
- `ejecutar_url_inspector_INFORMES_UNE.bat`: menú de Windows y acceso CLI.
- `ejecutar_url_inspector_INFORMES_UNE.sh`: menú de Linux y acceso CLI.
- `menu_url_inspector.py`: interfaz de consola compartida (nuevo análisis o informes offline).
- `datos_pericia_plantilla.json`: plantilla sin información personal.
- `tests/test_reports_une.py`: pruebas offline del complemento.

En `.github/workflows/ci.yml` se incluyen `actions/checkout@v7`, `actions/setup-python@v7` y las variables `PYTHONUTF8=1` y `PYTHONIOENCODING=utf-8`, manteniendo la matriz Windows/Linux. La nueva CI tendrá que verificarse después de publicar este complemento.

## Menú simplificado multiplataforma — complemento 1.1

**Windows (doble clic):** `ejecutar_url_inspector_INFORMES_UNE.bat`.

**Linux (terminal):**

```bash
chmod +x ejecutar_url_inspector_INFORMES_UNE.sh   # una sola vez si se perdieron los permisos
./ejecutar_url_inspector_INFORMES_UNE.sh
```

Ambos lanzadores usan el mismo programa `menu_url_inspector.py`, con las mismas preguntas:

```text
URL INSPECTOR 6.0 — INFORMES
  1. Analizar una URL nueva
  2. Generar informes desde un JSON anterior
  0. Salir
```

### Opción 1: analizar una nueva URL y después preparar sus PDF

1. Introduzca una URL absoluta que comience por `https://` o `http://`.
2. Elija análisis completo (opción por defecto) o abreviado.
3. Confirme que autoriza la conexión a la dirección y, cuando corresponda, a fuentes externas de reputación. Sin confirmación no se realiza la inspección.
4. Elija una carpeta de salida, o pulse **Enter** para utilizar `informes_locales/` dentro del programa.
5. Se ejecuta **una sola inspección** con el motor intacto. Se conserva el resultado completo en **JSON** antes de preguntar por los informes.
6. Elija: **1** pericial, **2** ejecutivo, **3** ambos, **0** ninguno. En los casos 1 y 3 puede indicar un archivo de datos periciales, o dejarlo sin cumplimentar.
7. Los PDF se generan **desde el JSON obtenido**, sin repetir la inspección. Se muestra la ruta de cada archivo.

Si la inspección falla o no produce un JSON, el menú no intenta crear informes automáticamente. La decisión de crear PDFs desde el JSON no cambia el resultado técnico ni el score. Por seguridad y trazabilidad, el complemento utiliza nombres nuevos con fecha, hora y microsegundos para evitar sobrescribir informes anteriores.

### Opción 2: generar PDF desde un análisis anterior

1. Indique la ruta del JSON original producido por URL Inspector (puede estar fuera de la carpeta del programa).
2. Indique la carpeta de destino para los PDF; por defecto `informes_locales/`.
3. Elija informe pericial, ejecutivo, ambos o ninguno y, si procede, el JSON privado de datos periciales.
4. Se generan archivos PDF nuevos. El **JSON de entrada no se modifica** y no se inspecciona ninguna URL: no se contacta con el sitio ni con fuentes externas de reputación.

**Nota sobre Internet:** «sin inspección» significa que la aplicación no hace consultas de red para producir esos informes; si es la primera ejecución y todavía no hay dependencias instaladas, el lanzador puede necesitar Internet para instalarlas en `.venv`. Consulte el apartado siguiente. La ruta del JSON y la de los PDF pueden contener espacios.

### Instalación de dependencias: Windows y Linux

Se requiere **Python 3.11 o superior**, `venv`, `pip` y conexión a Internet para instalar por primera vez las dependencias del archivo `requirements_v6.txt`. Ambos lanzadores crean, en la carpeta del programa, un **entorno virtual `.venv/`** y descargan los paquetes en ese entorno solamente si no están disponibles. No instalan las bibliotecas en el Python global.

- **Windows:** abra el `.bat` desde el Explorador o desde PowerShell/CMD. Si no se detecta Python, instálelo y habilite su disponibilidad desde la terminal. El lanzador busca primero `py -3` y, en su defecto, `python`.
- **Linux:** ejecute el `.sh` desde un terminal. Si `venv` no está disponible, instale el paquete correspondiente a su distribución (en sistemas Debian/Ubuntu suele llamarse `python3-venv`). Si el archivo no tiene permiso de ejecución, utilice `bash ejecutar_url_inspector_INFORMES_UNE.sh` o `chmod +x ...`.
- **Sin Internet:** cree previamente `.venv` y cargue las dependencias desde una fuente interna autorizada. No se descargan modelos ni se envían datos de caso para generar PDF; las inspecciones nuevas sí realizan conexiones de red.

La instalación automática usa los requisitos de la versión 1.18.1 y depende de que su índice de paquetes sea accesible. Se recomienda un entorno aislado cuando se analicen sitios potencialmente maliciosos.

### Uso directo en terminal (sin menú inicial)

Los dos lanzadores siguen aceptando argumentos. En ese caso, los transmiten al inspector compatible; **no** se muestra el menú inicial de selección 1/2. Ejemplos:

```bat
REM Windows
 ejecutar_url_inspector_INFORMES_UNE.bat https://example.com --full
```

```bash
# Linux
./ejecutar_url_inspector_INFORMES_UNE.sh https://example.com --full
```

Este modo respeta las opciones CLI existentes del motor y puede mostrar su propio menú de exportación al terminar si no se indicó un destino y se ejecuta en un terminal interactivo. Para generar nuevos PDF a partir de un JSON sin usar el menú inicial:

```bash
# Mismo comando en Windows (con python) y Linux (con python3)
python informes_une_197001.py resultados.json --pericial pericial.pdf --ejecutivo ejecutivo.pdf
```

Si utiliza el entorno virtual del lanzador, ejecute el comando anterior con `.venv/bin/python` en Linux o `.venv\Scripts\python.exe` en Windows. Para añadir los datos profesionales reales, agregue `--datos-pericia ruta_a_datos.json`.

### Trazabilidad, privacidad y seguridad

- Conserve el **JSON inicial inalterado**, los PDF, los ficheros auxiliares y sus huellas SHA-256 según los procedimientos de custodia aplicables. Un PDF nuevo no modifica ni autentica retrospectivamente las evidencias.
- `informes_locales/` y `.venv/` están excluidos de Git mediante `.gitignore`; si escoge otro directorio, debe verificar personalmente que su contenido privado no vaya al repositorio.
- El informe pericial mantiene la **estructura documental basada en UNE 197001:2019**, pero es un **borrador**. Requiere evaluación, conclusiones independientes, identificación y firma del perito; su generación no acredita conformidad certificada.
- No entregue las claves API ni documentos personales en el repositorio público. `datos_pericia_plantilla.json` es solo un formulario vacío.
- No active capturas de navegador de sitios hostiles fuera de un entorno aislado. El menú inicial no solicita capturas headless y el motor sigue requiriendo `--screenshot` explícito si se utilizan opciones avanzadas.

### Comprobación de integridad del motor

El archivo `url_inspector_6.0.py` mantiene el SHA-256 validado:

`30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a`

El menú (`menu_url_inspector.py`), los lanzadores `.bat`/`.sh` y los exportadores son componentes externos. El informe offline lee el JSON existente, sin volver a realizar análisis técnico.

## Complemento 1.2 — revisión de los PDF

Se ha corregido la paginación de los ejecutivos en los dos casos de prueba reales (BOE y AMTSO),
la presentación de campos estructurados y la descripción de fuentes reputacionales con
indicadores `available` y `configured` divergentes. Los datos técnicos y las
puntuaciones del motor no se alteran. Véase `REVISION_INFORMES_1.2.md` para
las pruebas, el procedimiento de reexportación offline y las limitaciones.

## Complemento 1.3 — pericial íntegro y salida HTML

**Esta sección prevalece sobre los nombres de opciones anteriores del menú.** Se mantiene el motor 1.18.1 sin alteraciones.

- Opciones del menú: `1` pericial PDF y HTML, `2` ejecutivo PDF, `3` los tres, `4` solo pericial HTML, `0` únicamente JSON.
- El pericial PDF incluye anejos con todos los valores del JSON, sin recortes. El pericial HTML reproduce íntegros los campos estructurados, y resulta más cómodo para datos extensos. Ambos identifican los errores y las pruebas no ejecutadas cuando así constan.
- Las nuevas inspecciones guardan automáticamente `resultados.consola.txt` cuando se ejecutan con `--json` desde el lanzador del complemento. El PDF/HTML incluye dicha transcripción si existe, con su SHA-256. Es el registro real de stdout/stderr, no un registro de comunicaciones de red.
- Los JSON anteriores sin registro de consola siguen siendo válidos como entrada, pero **no es posible reconstruir literalmente** los mensajes de consola a partir de sus campos. Se indicará expresamente esa ausencia.
- El ejecutivo dice con claridad la clasificación operativa del motor. No se habla de «probabilidad de phishing» como porcentaje, porque el score 0-100 no está calibrado como probabilidad.

Ejemplo offline (Windows y Linux):

```bash
python informes_une_197001.py resultados.json --pericial pericial.pdf --pericial-html pericial.html --ejecutivo ejecutivo.pdf
```

Para un registro de consola guardado con otro nombre, añadir `--registro-consola log_original.txt`.

Véase `REVISION_INFORMES_1.3.md` para la documentación completa, limitaciones, privacidad y validación.


## Complemento 1.3.1 — Correcciones de trazabilidad y presentación

Se corrigen los saltos duplicados de consola en HTML en Windows (finales de línea de presentación normalizados a LF; original conservado por separado); las huellas criptográficas ya no reciben espacios artificiales al maquetarse. El PDF y el HTML indican la **fecha técnica UTC de exportación** y la versión del **generador 1.3.1**; la fecha de emisión y firma del perito sigue siendo independiente y no se rellena automáticamente.

El JSON de datos asociado se copia con bytes idénticos al original si existe y se verifica que ambos contenidos son equivalentes. Si se reconstruye desde los datos disponibles, se informa de que es una serialización derivada, no una copia binaria acreditada. **No se vuelve a inspeccionar la URL.** Véase `REVISION_INFORMES_1.3.1.md` para la prueba documental del BOE y las limitaciones.

## Complemento 1.3.2 — Cobertura e índice pericial

- **Cobertura técnica:** el informe explica que se calcula a partir de cinco componentes ponderados (resolución URL 25 %, RDAP/TLS/HTTP/HTML 18,75 % cada uno), siguiendo el motor 1.18.1. El módulo detallado de registros DNS, la geolocalización, la reputación y las capturas no se computan en ese índice. La resolución de URL sí puede utilizar DNS como mecanismo subyacente. El 100 % de cobertura no acredita exhaustividad ni legitimidad de la web; la cobertura de fuentes reputacionales se muestra por separado. No se recalculan los valores originales.
- **Índice PDF pericial:** se limita a capítulos principales, declaraciones, firma y anejos con paginación. Las subsecciones técnicas 7.x y los campos íntegros del anejo 3 siguen en el documento, sin recortes, pero no llenan el índice de decenas de entradas. El HTML mantiene toda la información.
- **Integridad:** motor 1.18.1 con SHA-256 invariable y generación offline desde JSON previo, con registro de consola original si se facilitó. Las huellas de salida no se reutilizan entre exportaciones nuevas; se calculan para cada fichero generado.
- Consulte `REVISION_INFORMES_1.3.2.md` para validación, límites y procedimiento de publicación.
