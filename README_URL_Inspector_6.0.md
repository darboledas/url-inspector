> **Nota 1.18.1:** hotfix del modo batch para Windows. El proceso hijo de `url_inspector_6.0.py` se ejecuta con `PYTHONIOENCODING=utf-8` y `PYTHONUTF8=1`, evitando `UnicodeEncodeError` cuando `stdout` está redirigido a `PIPE`. El motor calibrado permanece sin cambios.

> **Nota 1.18:** se añade un modo batch operativo para listas TXT/CSV mediante `batch_url_inspector.py`. El motor calibrado `url_inspector_6.0.py` permanece byte a byte idéntico a 1.17/1.16; no cambian heurísticas, pesos ni umbrales.

> **Nota 1.17:** no cambia el motor de URL Inspector. La revisión afecta exclusivamente al benchmark: IC95 % de Wilson, desgloses por fuente/categoría, auditoría de solapamiento, análisis temporal, escenarios de prevalencia y comparación longitudinal entre campañas. Heurísticas, pesos y umbrales permanecen congelados.

> **Nota 1.16:** se incorpora una suite automática de regresión y CI sin acceso a URLs objetivo. Las pruebas cubren seguridad SSRF/DNS pinning, reputación, separación score/veredicto, máscaras del benchmark, CLI y protección básica de secretos mediante `.gitignore`. Se corrige además una delegación interna de `getaddrinfo` en el contexto de DNS pinning y una repetición cosmética en el resumen ejecutivo. No cambian heurísticas, pesos ni umbrales calibrados.

> **Nota 1.15.2:** corrección de compatibilidad en la mitigación de DNS rebinding. La conexión al objetivo fija temporalmente la resolución del hostname a las IP públicas ya validadas, manteniendo SNI y verificación TLS. La lectura de la IP remota del socket queda como comprobación adicional y ya no bloquea una URL pública cuando la versión de requests/urllib3 no expone el socket. No cambia heurísticas, pesos ni umbrales.

> **Nota 1.15.1:** ajuste de presentación reputacional para evitar falsos positivos operativos por registros históricos de PhishStats. PhishStats conserva registros antiguos y expone un `score` de confianza. URL Inspector mantiene una coincidencia como alerta roja actual cuando el registro tiene hasta 90 días, cuando el `phishscore` es igual o superior a 5, o cuando no puede interpretarse fecha/score. Una coincidencia de más de 90 días con `phishscore < 5` se conserva como **antecedente reputacional histórico** en amarillo y no eleva por sí sola el veredicto a alerta roja. Este criterio no altera el score heurístico calibrado.

# URL Inspector 6.0

> **Nota 1.15:** endurecimiento de seguridad del analizador frente a SSRF y destinos locales. Se bloquean `localhost`, redes privadas, loopback, link-local, direcciones reservadas/no globales y nombres locales frecuentes; cada redirección HTTP/meta se valida antes de seguirla y la resolución de cada conexión se fija a IP públicas previamente validadas para mitigar DNS rebinding; cuando el socket es accesible, su peer se comprueba además como defensa adicional. Las conexiones TLS se fijan a una IP pública previamente validada conservando SNI/hostname. Las peticiones al objetivo no heredan proxies del entorno. La captura headless deja de activarse automáticamente con `--full` y pasa a requerir `--screenshot` explícito. Estos cambios no modifican heurísticas, pesos ni umbrales calibrados.

> **Nota 1.14.1:** corrección de reputación ante redirecciones dinámicas. El veredicto operativo comprueba tanto la URL introducida como la URL final observada, de modo que una ruta reescrita por un token de sesión no oculte una coincidencia reputacional exacta. Para preservar la calibración, la puntuación heurística continúa usando la base reputacional de la URL final.


> **Nota 1.14:** se añade un **veredicto operativo** separado de la puntuación heurística y una **cobertura reputacional** independiente de la cobertura técnica. Cualquier coincidencia reputacional negativa a nivel de URL se muestra de forma prioritaria, EN MAYÚSCULAS y en rojo cuando el formato lo permite (consola, HTML y PDF). Estas alertas no alteran por sí mismas la calibración heurística; PhishStats continúa sin sumar puntos al score.
>
> **Nota 1.13:** la consulta exacta de PhishStats se realiza por el SHA-256 de la URL y se verifica después localmente. Esto evita falsos negativos provocados por caracteres especiales de la URL en la sintaxis `_where`. La integración sigue siendo solo reputacional y no modifica el score heurístico.


Analizador defensivo de URLs con resolución de redirecciones, DNS/RDAP, TLS, HTML, reputación, detección de suplantación de identidad y generación de evidencias.

## Instalación

Python 3.11 o superior recomendado.

```bash
python -m pip install -r requirements_v6.txt
```

Para la captura de pantalla debe existir en el equipo Microsoft Edge, Google Chrome o Chromium. No requiere Selenium: URL Inspector invoca el navegador instalado en modo headless.

## Uso básico

```bash
python url_inspector_6.0.py https://ejemplo.com
python url_inspector_6.0.py https://ejemplo.com --full
```

Si no se indica `--json`, `--html`, `--pdf`, `--pdf-executive` ni `--pdf-forensic`, al terminar el análisis aparece un **menú interactivo de informes**. No es necesario memorizar las opciones de exportación. El menú permite generar PDF ejecutivo, PDF forense, ambos PDF, HTML, JSON, todos los formatos o una combinación de varias opciones.

Pulsar **Enter** en el menú genera por defecto **ambos PDF**. Los nombres de archivo se crean automáticamente con el dominio y la fecha/hora; también se puede indicar la carpeta de salida. Para ejecuciones automatizadas o scripts se puede impedir el menú con `--no-menu`.

Exportación simultánea mediante opciones de línea de comandos:

```bash
python url_inspector_6.0.py https://ejemplo.com --full --json informe.json --html informe.html --pdf-executive informe_ejecutivo.pdf --pdf-forensic informe_forense.pdf
```

Por seguridad, `--full` **no abre un navegador**. La captura PNG es opt-in y debe pedirse explícitamente:

```bash
python url_inspector_6.0.py https://ejemplo.com --screenshot evidencia.png
```

La captura headless tiene una superficie de ataque mayor que el análisis HTTP controlado; se recomienda ejecutarla en un entorno aislado cuando la URL sea potencialmente maliciosa. `--no-screenshot` se conserva por compatibilidad y anula cualquier captura solicitada.

## Política de seguridad de destino (1.15)

Antes de conectar con la URL objetivo, URL Inspector exige que el destino sea HTTP/HTTPS y que el host resuelva exclusivamente a direcciones globalmente encaminables. Se bloquean de forma preventiva:

- `localhost` y nombres locales habituales (`.local`, `.internal`, `.lan`, etc.);
- IPv4/IPv6 privadas, loopback, link-local, multicast, no especificadas o reservadas/no globales;
- redirecciones HTTP o `meta refresh` que intenten saltar a destinos no públicos;
- URL con credenciales embebidas o sintaxis ambigua;
- conexiones cuya resolución intente cambiar hacia direcciones no públicas; cada conexión queda fijada a IP públicas previamente validadas (mitigación de DNS rebinding).

Las conexiones HTTP al objetivo ignoran proxies heredados del entorno para que la verificación de la IP remota represente el destino real. La comprobación TLS usa una IP pública previamente validada y mantiene el hostname original para SNI y validación del certificado. Si una redirección intenta alcanzar una red interna, el salto se registra como bloqueado y no se sigue.

Esta política afecta solo a las conexiones hacia la URL analizada. Las consultas a fuentes de reputación, RDAP o geolocalización siguen usando sus endpoints fijos.

## Fuentes opcionales mediante API

Defina solo las claves que tenga disponibles:

```text
URLHAUS_AUTH_KEY
VIRUSTOTAL_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY
ABUSEIPDB_API_KEY
PHISHTANK_APP_KEY
```

URLhaus requiere `URLHAUS_AUTH_KEY` (Auth-Key de abuse.ch) y la envía en la cabecera `Auth-Key`. OpenPhish Community no requiere clave. PhishTank puede consultarse sin `app_key`, aunque el propio servicio puede aplicar límites o rechazar consultas no autenticadas.

Si una fuente no está configurada o no responde, URL Inspector la marca como **no evaluada**; no la interpreta como resultado limpio.

## Typosquatting y homoglifos

La herramienta incorpora una lista prioritaria de dominios de marcas/servicios de alto valor y trata de ampliar la comparación con 5.000 dominios populares de referencia, almacenándolos en caché. Si esa descarga no está disponible, el análisis continúa con la lista interna.

Puede aportarse una lista local propia, una entrada por línea:

```bash
python url_inspector_6.0.py https://ejemplo.com --brands-file mis_dominios.txt
```

Acepta dominios simples y ficheros CSV sencillos en los que el dominio figure en la última columna.

## TLS DV / OV / EV

La clasificación utiliza los OID de política CA/B Forum cuando están presentes. Si el OID no permite una clasificación inequívoca, la herramienta no fuerza un resultado: puede mostrar `DV (probable)`, `EV (probable)` u `OV/EV (indeterminado)`, indicando siempre la base de la inferencia. Esto evita clasificar como OV un certificado EV que use un OID propio de la CA. No debe interpretarse DV, OV o EV como indicador aislado de legitimidad.

## ASN y reputación

Se muestra el ASN y la organización asociados a las IP observadas. Cuando VirusTotal está configurado, se incorpora la reputación y las detecciones de esas IP. La herramienta no traslada automáticamente la reputación de una IP a todo el ASN/proveedor, para evitar atribuciones incorrectas.

## Informes

- JSON: estructura completa para tratamiento automatizado.
- HTML: informe técnico autocontenido y anexo JSON completo.
- PDF ejecutivo (`--pdf-executive`): documento breve orientado a decisión, con conclusión, recomendación operativa, nivel/puntuación de riesgo, indicadores principales, hallazgos determinantes, cobertura de fuentes y limitaciones.
- PDF forense (`--pdf-forensic`): documento técnico completo con objeto y alcance, metodología, manifest de integridad, SHA-256 del conjunto de resultados y de la captura cuando existe, redirecciones, identidad/typosquatting/homoglifos, RDAP/DNS, TLS, IP/ASN, reputación, HTTP/HTML, factores de riesgo, captura y anexo JSON completo.

La opción histórica `--pdf informe.pdf` se mantiene por compatibilidad y genera el **informe forense**. Si se especifica cualquiera de las opciones de exportación en la línea de comandos, el menú no se muestra y se respetan directamente esas rutas. Para generar ambos de forma no interactiva:

```bash
python url_inspector_6.0.py https://ejemplo.com --full --pdf-executive ejecutivo.pdf --pdf-forensic forense.pdf
```

## Advertencias operativas

URL Inspector contacta con la URL analizada y con los servicios externos necesarios. Estos servicios pueden registrar la IP pública y los indicadores consultados. La captura de pantalla ejecuta un navegador headless contra la URL analizada, por lo que debe utilizarse en un entorno adecuado cuando se investiguen sitios potencialmente hostiles.

La puntuación de phishing es heurística: sirve para priorizar y documentar indicios, no constituye por sí sola una conclusión forense.

## Benchmark de calibración

El paquete incluye `benchmark_url_inspector.py`, `benchmark_url_inspector.bat` y `README_BENCHMARK.md`. Esta herramienta permite construir un corpus reproducible de referencia, ejecutar URL Inspector en modo normal, *leave-one-out* o solo heurísticas, y calcular matrices de confusión y métricas para todos los umbrales 0–100 sin modificar todavía la escala interna de la versión 6.0.

La construcción del corpus no visita las URLs objetivo. Si PhishTank no está disponible, el benchmark compensa automáticamente con OpenPhish para conservar el objetivo de 300 referencias benignas + 300 maliciosas (200 phishing + 100 malware). La fase de ejecución contra URLs maliciosas debe realizarse únicamente en una VM desechable/aislada. Consulte `README_BENCHMARK.md` antes de ejecutarla.

- Benchmark 1.4: corrige el timeout real en Windows, evita descargas repetidas por worker, limita operaciones de red durante la calibración y continúa analizando IOC caídos sin abortar.


### Benchmark 1.5

La herramienta de calibración limita de forma independiente las etapas de red para evitar que una resolución DNS bloqueada en Windows inutilice una muestra completa. El programa normal de URL Inspector no cambia sus tiempos ni su lógica por esta medida de laboratorio.


### Benchmark 1.6

Se optimiza la detección de typosquatting reutilizando una única instancia de TLDExtract durante el análisis de identidad. Esto elimina una penalización de rendimiento que podía provocar timeouts al comparar contra miles de dominios de referencia, sin cambiar la puntuación ni los criterios heurísticos.

### Benchmark / heurísticas 1.7

La revisión 1.7 se centra en el fallo de sensibilidad observado para phishing en el benchmark de 600 muestras. Se amplía la detección de suplantación a hostname completo, subdominios, ruta y contenido; se añaden señales contextuales de formularios de credenciales y hosting multiusuario; y se reduce el peso de indicadores que en la prueba anterior aparecieron con frecuencia en sitios benignos (iframes ocultos, ofuscación JavaScript, meta-refresh, redirecciones y ausencia de TLS aislada).

La comparación de typosquatting contra referencias genéricas de Tranco ya no usa distancia 2. Las marcas prioritarias mantienen reglas específicas más sensibles.

El resumen ejecutivo ya no calcula «confianza» como `100 - riesgo`. Muestra una **cobertura técnica del análisis** independiente, construida a partir de las fases técnicas que pudieron completarse (resolución, RDAP, TLS, HTTP y HTML). La cobertura reputacional se informa por separado. El campo JSON `confidence_score` se conserva temporalmente por compatibilidad y equivale ahora a esa cobertura.

Los niveles 1–5 siguen siendo provisionales hasta completar una validación nueva. La puntuación 0–100 no debe interpretarse como probabilidad matemática de phishing.


### Benchmark 1.8: validación independiente

La heurística de URL Inspector no cambia respecto a la revisión 1.7. El benchmark 1.8 añade exclusión verificable de corpus previos por URL canónica y host exacto para construir una batería nueva sin reutilizar las 600 muestras de ajuste. El corpus histórico se entrega como `benchmark_corpus_regression.json`; la validación final debe construirse como `benchmark_corpus_validation.json` con una extracción/semilla nuevas y auditoría de solapamiento igual a cero.


### Benchmark 1.9
La validación independiente sustituye PhishTank por PhishStats como segunda fuente de phishing, debido a los límites 429 del feed público de PhishTank y a que no siempre es posible registrar nuevas cuentas. Las heurísticas de URL Inspector 6.0 permanecen idénticas a la revisión 1.7.


## Escala de riesgo calibrada

La escala interna de URL Inspector 6.0 quedó calibrada mediante una validación independiente de 600 muestras sin solapamiento de URL ni host con el corpus de desarrollo. Los niveles adoptados son: `0–7` bajo, `8–19` moderado, `20–29` alto, `30–49` muy alto y `50–100` crítico.

La puntuación es heurística y no representa una probabilidad. Un valor bajo no certifica que una URL sea legítima. La metodología, métricas y justificación de los cortes se documentan en [`CALIBRACION_ESCALA_RIESGO.md`](CALIBRACION_ESCALA_RIESGO.md).
## Pruebas automáticas y CI (1.16)

La carpeta `tests/` contiene una suite de `unittest` diseñada para ejecutarse sin visitar URLs objetivo. En Windows puede lanzarse con:

```bat
run_tests.bat
```

GitHub Actions está preparado en `.github/workflows/ci.yml` para ejecutar compilación, pruebas offline y smoke tests de CLI en Windows/Linux con Python 3.11 y 3.13. Consulte [`README_TESTS.md`](README_TESTS.md) para el detalle de invariantes y alcance.

La suite protege frente a regresiones, pero no sustituye la validación empírica independiente si en el futuro se modifican heurísticas, pesos o umbrales.


## Modo batch (paquete 1.18)

El paquete 1.18 añade `batch_url_inspector.py` para analizar listas de URLs sin modificar el motor calibrado `url_inspector_6.0.py`.

Entrada admitida:

- TXT/LIST/URLS: una URL por línea; se ignoran líneas vacías y comentarios que empiecen por `#`.
- CSV: detecta automáticamente columnas `url`, `uri`, `link`, `target` o `address`; para otro nombre use `--url-column`.

Primero puede validar la lista sin realizar conexiones:

```bat
python batch_url_inspector.py urls.txt --dry-run
```

Para ejecutar el análisis completo:

```bat
python batch_url_inspector.py urls.txt --output-dir batch_output --acknowledge-risk
```

El modo batch contacta las URLs objetivo y puede incluir destinos hostiles. Debe ejecutarse en un entorno adecuado y aislado. `--acknowledge-risk` es obligatorio salvo con `--dry-run`.

Salidas principales:

- `batch_output\batch_results.csv`: tabla agregada para revisión o importación en una hoja de cálculo.
- `batch_output\batch_results.json`: manifiesto estructurado con SHA-256 del inspector usado.
- `batch_output\individual\*.json`: resultado técnico completo de cada URL.

La tabla incluye URL de entrada/final, dominio, estado, score 0–100, nivel 1–5, veredicto operativo, alerta reputacional, coberturas técnica/reputacional, duración y ruta al JSON individual. Use `--resume` para continuar una ejecución interrumpida sin repetir URLs ya registradas.

El batch no solicita ni genera capturas headless. Para evidencia visual use el inspector individual con `--screenshot` de forma explícita.
