> **Nota 1.18:** el benchmark científico de 1.17 se conserva; el paquete añade el modo batch operativo. El motor calibrado no cambia.

> **Nota 1.17:** se amplía únicamente la metodología del benchmark. El informe añade intervalos de confianza de Wilson al 95 %, métricas desglosadas por fuente y categoría, auditoría de solapamiento interno URL/host, perfil temporal de las muestras, PPV/NPV modelados para distintas prevalencias y un subcomando `compare` para comparar dos campañas de validación independientes. No se modifican heurísticas, pesos ni umbrales de URL Inspector.

> **Nota 1.16:** el benchmark no cambia su metodología de calibración; se añade cobertura automática de sus máscaras reputacionales para garantizar que `leave-one-out` neutraliza la fuente de origen (incluido PhishStats) y que `heuristic-only` desactiva las fuentes externas. El campo interno `benchmark_version` pasa a `1.16`.

> Nota 1.15.2: el perfil activo mantiene la protección SSRF pero deja de depender de que requests/urllib3 expongan internamente el socket. Cada conexión al objetivo usa DNS fijado a las IP públicas validadas; el peer, si está disponible, se valida adicionalmente. No cambia etiquetas ni puntuación.

> Nota 1.15.1: la política operativa de PhishStats distingue alertas actuales de antecedentes históricos de baja confianza. Este ajuste afecta solo al veredicto/presentación del inspector; no modifica etiquetas, score heurístico ni neutralizaciones `leave-one-out`/`heuristic-only`.

# Benchmark de URL Inspector 6.0

> Nota 1.15: el perfil activo del benchmark hereda las protecciones SSRF del inspector: valida cada destino/redirección, bloquea IP no públicas y fija la resolución de cada conexión a IP públicas validadas; el peer se comprueba cuando está disponible. Esto no cambia la definición de etiquetas ni la puntuación; solo impide que una muestra redirija el benchmark hacia redes locales.
>
> Nota 1.14: el inspector separa la cobertura técnica de la reputacional y añade un veredicto operativo de presentación. Como PhishStats ya está integrado en el inspector, el modo `leave-one-out` neutraliza también `reputation_phishstats` cuando la muestra procede de PhishStats, evitando fuga directa de etiqueta. El modo `heuristic-only` neutraliza igualmente PhishStats.
>
> Nota 1.13: PhishStats se consulta por el SHA-256 exacto de la URL y se verifica localmente, corrigiendo falsos negativos de la consulta por URL cuando aparecen caracteres especiales. Sigue siendo una fuente de reputación externa y no modifica la puntuación heurística calibrada.
>
> Nota 1.11: la consulta de reputación URLhaus del inspector usa `URLHAUS_AUTH_KEY` mediante la cabecera `Auth-Key`, conforme al API actual.

`benchmark_url_inspector.py` valida empíricamente la puntuación 0–100 sin cambiar todavía los umbrales internos de URL Inspector.

## Diseño del corpus por defecto

- 300 referencias benignas aproximadas: dominios populares de Tranco.
- 100 phishing: PhishStats mediante su API pública read-only, sin clave.
- 100 phishing: OpenPhish Community Feed.
- PhishTank queda como fuente opcional (`--phishtank N`), pero por defecto se desactiva porque el feed público puede devolver HTTP 429 y actualmente no siempre es posible obtener una app-key nueva.
- 100 malware: URLhaus `recent.csv`.

Total objetivo de validación: 600 muestras: 300 `benign_reference` + 100 PhishStats + 100 OpenPhish + 100 URLhaus. Las URLs y hosts se deduplican y se excluyen los utilizados en el corpus de regresión.

**Importante:** `benign_reference` significa «referencia presumiblemente legítima/popular», no prueba matemática de que el dominio no haya sido comprometido. Esa limitación queda registrada en el corpus.

## Tres modalidades de evaluación

1. `normal`: URL Inspector funciona con todas sus fuentes configuradas.
2. `leave-one-out`: para cada muestra maliciosa se neutraliza únicamente la fuente integrada en URL Inspector que la suministró. Para PhishStats, OpenPhish, PhishTank y URLhaus se desactiva esa misma reputación cuando corresponda. Es la modalidad recomendada para evitar fuga directa de etiqueta.
3. `heuristic-only`: neutraliza URLhaus, PhishStats, OpenPhish, PhishTank, VirusTotal, Google Safe Browsing y AbuseIPDB. Mide el comportamiento de las heurísticas propias (URL, identidad, TLS, antigüedad, HTTP/HTML, etc.).

La neutralización se aplica solo en el proceso temporal del benchmark. **No modifica `url_inspector_6.0.py`.**

## Fase 1 — construir el corpus (segura)

Esta fase descarga listas y guarda URLs como datos; no abre las URLs objetivo.

```bat
python benchmark_url_inspector.py build --output benchmark_corpus.json
```

Para las 100 muestras de URLhaus, el export oficial actual requiere una Auth-Key de abuse.ch:

```bat
set URLHAUS_AUTH_KEY=SU_CLAVE
python benchmark_url_inspector.py build --output benchmark_corpus.json
```

PhishTank es opcional. Para la validación independiente se usa PhishStats, cuya API read-only permite acceso anónimo sin registro. La cuota anónima documentada es suficiente para construir una batería de 100 muestras con pocas peticiones:

```bat
set PHISHTANK_APP_KEY=SU_CLAVE
```

Para desactivar expresamente esta compensación (por ejemplo, para reproducir un corpus antiguo), use `--no-phishing-fallback`.

La salida del `build` guarda en los metadatos los recuentos solicitados y efectivos por fuente. Cada muestra conserva su `source`.

También pueden usarse snapshots locales para reproducibilidad o trabajo sin conexión:

```bat
python benchmark_url_inspector.py build ^
  --tranco-file tranco.csv ^
  --phishtank-file online-valid.csv.bz2 ^
  --openphish-file feed.txt ^
  --urlhaus-file recent.csv ^
  --output benchmark_corpus.json
```

Se generan `benchmark_corpus.json`, `benchmark_corpus.csv` y un fichero `.sha256`.

## Fase 2 — ejecutar el benchmark (solo VM aislada)

Esta fase **sí contacta** las URLs. URL Inspector se ejecuta siempre con `--no-screenshot` y `--no-menu`, pero sigue realizando conexiones de red y puede descargar hasta el límite de inspección configurado. No debe ejecutarse contra el corpus malicioso desde el equipo de trabajo habitual.

Primero haga una prueba corta en una VM desechable:

```bat
python benchmark_url_inspector.py run ^
  --corpus benchmark_corpus.json ^
  --inspector url_inspector_6.0.py ^
  --mode leave-one-out ^
  --limit 10 ^
  --output benchmark_results.json ^
  --acknowledge-risk
```

Después, la prueba completa recomendada:

```bat
python benchmark_url_inspector.py run ^
  --corpus benchmark_corpus.json ^
  --inspector url_inspector_6.0.py ^
  --mode leave-one-out ^
  --output benchmark_results.json ^
  --resume ^
  --acknowledge-risk
```

`--resume` permite continuar si se interrumpe el ensayo. Cada URL se ejecuta en un proceso separado y tiene timeout propio.

Para medir el sistema completo:

```bat
python benchmark_url_inspector.py run --mode normal --corpus benchmark_corpus.json --output benchmark_normal.json --resume --acknowledge-risk
```

Para medir solo heurísticas internas:

```bat
python benchmark_url_inspector.py run --mode heuristic-only --corpus benchmark_corpus.json --output benchmark_heuristics.json --resume --acknowledge-risk
```

`--mode all` ejecuta las tres modalidades y, con 600 muestras, supone 1.800 análisis. No se recomienda como primera ejecución.

## Fase 3 — calcular métricas

```bat
python benchmark_url_inspector.py report --results benchmark_results.json --output-dir benchmark_report
```

Se generan:

- `benchmark_individual_results.csv`: resultado URL por URL.
- `benchmark_summary.json`: resumen científico estructurado.
- `benchmark_summary.txt`: resumen legible.
- `thresholds_<modo>.csv`: métricas para cada umbral entero de 0 a 100.
- `source_metrics_<modo>.csv`: rendimiento por fuente en los umbrales 8, 20, 30, 40 y 50.
- `category_metrics_<modo>.csv`: rendimiento por categoría (`benign_reference`, `phishing`, `malware`).
- `temporal_metrics_<modo>.csv`: rendimiento según la antigüedad de la muestra maliciosa.
- `prevalence_adjusted_<modo>.csv`: PPV/NPV modelados para prevalencias hipotéticas.
- `overlap_audit.json`: auditoría de duplicados y solapamiento URL/host entre fuentes dentro del corpus evaluado.

Las métricas incluyen TP, TN, FP, FN, sensibilidad/recall, especificidad, precisión, tasa de falsos positivos, tasa de falsos negativos, accuracy, balanced accuracy, F1 y MCC. La sensibilidad, especificidad, precisión, accuracy, FPR y FNR incorporan **intervalos de confianza de Wilson al 95 %** cuando existe denominador binomial.

La precisión empírica del corpus no debe extrapolarse directamente a Internet real porque depende de la prevalencia. Por ello el informe modela PPV y NPV para prevalencias de 0,1 %, 1 %, 5 %, 10 % y 50 % por defecto. Se pueden cambiar con `--prevalence`, por ejemplo:

```bat
python benchmark_url_inspector.py report --results benchmark_results.json --output-dir benchmark_report --prevalence 0.001,0.01,0.05,0.10
```

Para que el perfil de antigüedad sea reproducible puede fijarse una fecha de referencia:

```bat
python benchmark_url_inspector.py report --results benchmark_results.json --output-dir benchmark_report --reference-time 2026-10-13T00:00:00Z
```

El perfil temporal describe la frescura de las muestras; **no equivale por sí solo a una validación longitudinal**. Para medir deriva temporal hace falta un corpus nuevo recogido posteriormente y sin solapamientos.

El informe destaca también candidatos empíricos (mejor F1, mejor índice de Youden y umbrales que cumplen determinados límites de falsos positivos), pero **no modifica automáticamente URL Inspector**.

## Comparación temporal entre campañas

La 1.17 añade un subcomando para comparar dos campañas de resultados:

```bat
python benchmark_url_inspector.py compare ^
  --baseline benchmark_results_validation_2026-10.json ^
  --candidate benchmark_results_validation_2027-01.json ^
  --output-dir benchmark_comparacion_temporal
```

La comparación genera `temporal_comparison.json`, `temporal_comparison.txt` y `temporal_threshold_deltas.csv`, audita solapamiento de URL/host entre ambos conjuntos y compara sensibilidad, especificidad, FPR y F1 en los umbrales 8, 20, 30, 40 y 50. Si cambia el SHA-256 del inspector, el informe lo advierte porque ya no puede atribuirse cualquier diferencia únicamente a deriva temporal. Los deltas son descriptivos y no se presentan como prueba de significación estadística.

## Objetivo de calibración

El umbral 50 se evaluará como hipótesis operativa, no como dato asumido. Tras el ensayo se compararán, entre otros, 40, 50, 60, 65, 70 y 80. Solo entonces conviene redefinir los niveles de riesgo y sustituir la actual «confianza = 100 - riesgo» por una medida independiente de cobertura del análisis.


## Robustez de ejecución (benchmark 1.5)

La versión 1.5 incorpora las correcciones de 1.4 y añade límites duros por etapa tras comprobar que `heuristic-only` también agotaba el timeout global en 9 de 10 muestras:

- URL Inspector podía alcanzar el final del análisis de una URL caída y fallar al construir el JSON porque `build_output()` no aceptaba todavía `resolution_error`. Esa incoherencia de firma está corregida.
- En Windows, `subprocess.run(..., timeout=...)` podía superar ampliamente el límite si el worker o alguno de sus descendientes mantenía abiertos los pipes. El runner usa ahora un proceso/grupo independiente, ficheros de log y terminación explícita del árbol de procesos. El timeout global vuelve a ser realmente efectivo.

El perfil de benchmark usa por defecto `--connect-timeout 3`, `--read-timeout 5` y `--timeout 75`. Además limita las redirecciones HTTP a 5 y el cuerpo HTML a 262144 bytes. A esto se añaden timeouts duros por etapa: 10 s para resolución/traza/RDAP/TLS, 12 s para HTTP/HTML y 15 s para reputación. Si una llamada de Windows queda bloqueada en resolución DNS y no respeta el timeout de `requests` o `socket`, esa etapa se ejecuta en un hilo daemon, se marca como no disponible y el análisis continúa. Estos límites pertenecen solo al benchmark; el uso normal de URL Inspector conserva sus valores habituales.

Cada worker mantiene además un `stages.log` temporal con START/OK/ERROR/TIMEOUT por fase. Si aun así se alcanza el timeout global, el runner incorpora las últimas etapas al diagnóstico, de modo que el siguiente fallo deja de ser opaco.

Para reducir esperas que no aportan puntos a `calculate_risk()`, durante la calibración se omiten geolocalización, DNS ampliado y detección de CDN. La resolución A/AAAA se hace con `dnspython` y un `lifetime` explícito. RDAP se consulta directamente mediante `rdap.org` para evitar descargar el bootstrap IANA en cada worker. La traza del benchmark sigue redirecciones HTTP sin descargar el cuerpo una primera vez solo para buscar `meta refresh`; el HTML final se analiza después y conserva la detección de `meta refresh` como factor heurístico.

OpenPhish se consulta desde su caché local durante el benchmark. La lista de referencia de typosquatting usa la caché Tranco de URL Inspector si existe y, en caso contrario, la lista interna prioritaria; el worker no intenta descargar esa lista repetidamente. Si no existe `PHISHTANK_APP_KEY`, las consultas individuales a PhishTank se consideran no evaluadas en el benchmark para evitar rate limits 429 por cada muestra. Las muestras cuyo origen es PhishTank siguen correctamente neutralizadas en `leave-one-out`.

Después de cada muestra el runner muestra `OK`, `ERROR` o `TIMEOUT`, la duración y, cuando existe, la puntuación. Los resultados parciales se escriben de forma atómica después de cada muestra, por lo que `--resume` permite continuar tras una interrupción.

El informe muestra el porcentaje de muestras evaluables. Si es inferior al 80 %, las métricas se marcan expresamente como insuficientes para validación.



## Corrección de rendimiento 1.6

La prueba real de 10 muestras con benchmark 1.5 mostró que 9 trabajadores agotaban el timeout global después de completar `trace_url`. El diagnóstico permitió aislar el bloqueo en la etapa local de identidad/typosquatting: `analyze_identity()` creaba una instancia nueva de `tldextract.TLDExtract` para cada dominio de la lista de referencia y repetía el proceso para homoglifos. Con miles de referencias, ese patrón podía consumir decenas de segundos por URL.

La versión 1.6 reutiliza una única instancia local de TLDExtract, calcula una sola vez las etiquetas normalizadas de la lista de referencia y las reutiliza en la segunda pasada. Además, el benchmark registra explícitamente la etapa `identity` y le aplica un límite duro de 8 s para detectar regresiones. La lógica de puntuación y los criterios de typosquatting no se modifican.

## Revisión 1.7: sensibilidad de phishing y validación por categoría

El benchmark 1.6 completó 600/600 muestras en `leave-one-out`, pero mostró una asimetría importante: el malware se separaba mucho mejor que el phishing. La revisión 1.7 no adopta automáticamente un umbral nuevo; primero modifica las señales que habían demostrado poca capacidad discriminante y añade contexto específico de suplantación.

Cambios de URL Inspector incluidos en este paquete:

- La comparación genérica contra Tranco deja de considerar distancia de Levenshtein 2. Para referencias genéricas solo se conserva distancia 1 y con menor peso. Las marcas prioritarias mantienen reglas más sensibles.
- Se buscan marcas prioritarias también en hostname completo, subdominios, ruta y contenido HTML, distinguiendo los dominios oficiales para evitar penalizarlos.
- Se reconocen plataformas de hosting multiusuario (por ejemplo, Vercel, Cloudflare Pages/Workers, Firebase, GitHub Pages, Weebly, Wix, Blogspot, Framer y similares) únicamente como factor contextual. Estar alojado en una de ellas no suma puntos por sí solo.
- El análisis HTML distingue campos de contraseña, email, OTP/PIN y otros campos de credenciales; identifica formularios de credenciales que envían datos a otro dominio.
- Las solicitudes de credenciales bajo HTTPS dejan de considerarse inocuas cuando coinciden con marca ajena, hosting multiusuario u otros indicios.
- `iframe` oculto, JavaScript aparentemente ofuscado, `meta refresh` y redirecciones se reducen a señales menores cuando aparecen solas, porque el benchmark 1.6 mostró que también eran frecuentes en referencias benignas.
- La ausencia de TLS se reduce como factor de riesgo y se refleja principalmente en la cobertura del análisis.
- La antigua «confianza = 100 - riesgo» desaparece conceptualmente: el resumen muestra una **cobertura técnica del análisis** independiente del score de riesgo. El campo JSON histórico `confidence_score` se conserva como alias de compatibilidad, pero ahora contiene esa cobertura, no el complemento del riesgo.

Cambios del propio benchmark:

- El informe muestra sensibilidad separada para `phishing` y `malware` en los umbrales principales, además de la sensibilidad global.
- Se añaden 19, 20, 25 y 30 a los umbrales destacados del JSON para estudiar la zona en la que el benchmark anterior encontraba el mejor compromiso.
- El timeout global usa un deadline con polling explícito, en vez de depender exclusivamente de `Popen.wait(timeout=...)`, después de observar una muestra que declaró 110 s pese a haberse solicitado 75 s.

### Evitar sobreajuste

El corpus histórico de 600 se incluye como `benchmark_corpus_regression.json` para reproducibilidad y pruebas de regresión, pero ya ha sido utilizado para diagnosticar y rediseñar las heurísticas. **No debe utilizarse como única validación final de la 1.7.** La secuencia correcta es:

1. ejecutar una prueba corta sobre el corpus incluido para confirmar estabilidad;
2. construir un corpus nuevo con otra extracción/fecha y, preferiblemente, otra semilla;
3. ejecutar `leave-one-out` sobre ese corpus nuevo;
4. analizar por separado phishing y malware;
5. solo entonces fijar los nuevos niveles de riesgo.

En particular, las plataformas multiusuario necesitan controles benignos comparables: la mera presencia de `vercel.app`, `pages.dev`, `github.io`, etc. no debe interpretarse como evidencia de phishing.


## Revisión 1.8: corpus de validación independiente

La revisión 1.8 **no modifica las heurísticas de URL Inspector 6.0**. Su objetivo es construir la batería de validación independiente de la 1.7 sin reutilizar las 600 muestras que sirvieron para ajustar el detector.

El subcomando `build` admite ahora `--exclude-corpus JSON` (repetible). Para cada corpus previo se excluyen:

- la URL canónica completa;
- el host exacto, por lo que no se admiten otras rutas o variantes de URL del mismo host;
- duplicados de host dentro del propio corpus nuevo.

El build termina con una auditoría obligatoria. Un corpus de validación aceptable debe indicar:

```text
Auditoría de independencia: URL solapadas=0 | hosts previos solapados=0 | hosts duplicados internos=0
```

La batería recomendada mantiene 600 muestras: 300 referencias benignas Tranco, 100 PhishStats, 100 OpenPhish y 100 URLhaus. Para construirla a partir de una extracción nueva y con una semilla distinta:

```bat
python benchmark_url_inspector.py build --output benchmark_corpus_validation.json --benign 300 --phishtank 0 --phishstats 100 --openphish 100 --urlhaus 100 --tranco-pool 10000 --seed 20261011 --exclude-corpus benchmark_corpus_regression.json --require-all-sources
```

`build` no visita las URLs objetivo: descarga/lee los feeds y Tranco, filtra y guarda sus direcciones. `run` sí contacta los objetivos y continúa requiriendo una VM desechable/aislada y `--acknowledge-risk`.

Si `--require-all-sources` falla porque una fuente no aporta 100 hosts nuevos, no debe rellenarse manualmente ni reutilizar hosts del corpus anterior. Puede reintentarse más tarde con una extracción nueva. Para la validación final se exige que PhishStats, OpenPhish y URLhaus aporten sus 100 muestras nuevas y que la auditoría de independencia sea cero.


## Revisión 1.9: sustitución de PhishTank en la validación

Debido a los HTTP 429 del feed público de PhishTank y a la imposibilidad práctica de obtener una app-key nueva cuando no se admiten altas, la validación independiente usa PhishStats como segunda fuente de phishing. PhishStats dispone de API pública read-only sin clave. El constructor pagina de 100 en 100, deduplica por URL y host y se detiene tras reunir suficientes muestras nuevas. PhishTank se mantiene solo como opción manual con `--phishtank N`.

> **Hotfix 1.14.1:** el veredicto reputacional del inspector evalúa URL introducida y URL final tras redirecciones, pero el score conserva la reputación de la URL final. Las neutralizaciones del benchmark siguen actuando sobre las funciones de fuente y, por tanto, cubren ambas consultas sin introducir fuga de etiqueta.

## Paquete 1.18

El benchmark científico de 1.17 se conserva sin cambios metodológicos. El paquete 1.18 añade el modo batch de uso operativo mediante `batch_url_inspector.py`; el motor calibrado de URL Inspector permanece sin cambios.
