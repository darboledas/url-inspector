# Pruebas automáticas — URL Inspector 6.0

La revisión 1.16 incorporó la suite automática de regresión y CI. La 1.17 la amplió a 32 pruebas para cubrir la metodología científica del benchmark. La 1.18 la amplió a 39 pruebas e incorporó el modo batch operativo. La 1.18.1 añade una prueba de regresión específica para la codificación UTF-8 del proceso hijo en Windows (40 pruebas).

## Principio de seguridad

Las pruebas son **offline respecto a las URLs objetivo**: no visitan sitios de phishing, malware ni dominios de prueba. Las resoluciones DNS, respuestas reputacionales y escenarios SSRF relevantes se simulan mediante *mocks*. El CI tampoco necesita claves API.

## Ejecutar en Windows

Desde la carpeta del proyecto:

```bat
run_tests.bat
```

O directamente:

```bat
python -m py_compile url_inspector_6.0.py benchmark_url_inspector.py
python -m unittest discover -s tests -p "test_*.py" -v
```

## Qué se comprueba

La suite cubre, entre otros, estos invariantes:

- normalización y canonicalización básica de URL;
- rechazo de esquemas no HTTP/HTTPS;
- bloqueo de loopback, redes privadas, nombres locales y credenciales embebidas;
- bloqueo de un hostname que resuelva simultáneamente a una IP pública y otra privada;
- fijación DNS de la conexión a las IP públicas previamente validadas;
- sesión HTTP al objetivo sin proxies heredados del entorno;
- clasificación PhishStats entre alerta actual y antecedente histórico;
- separación entre reputación externa y score heurístico calibrado;
- conservación de reputación negativa de la URL inicial cuando una redirección dinámica cambia la URL final;
- cobertura reputacional independiente;
- neutralización de PhishStats y demás fuentes en los modos de benchmark `leave-one-out` y `heuristic-only`;
- arranque correcto de las CLI mediante `--help`;
- presencia de reglas `.gitignore` para impedir publicar `APIKEY.txt` y ficheros `.env`;
- intervalos de confianza de Wilson al 95 %;
- PPV/NPV ajustados por prevalencia;
- métricas por fuente/categoría y perfil temporal;
- auditoría de solapamiento de URL/host;
- generación de los nuevos informes científicos y comparación temporal entre campañas.

## CI de GitHub

El archivo `.github/workflows/ci.yml` ejecuta la suite en Windows y Linux con Python 3.11 y 3.13 en cada `push` y `pull_request`.

No se almacenan secretos en el workflow. `APIKEY.txt`, `.env`, claves privadas y salidas locales de prueba están excluidos mediante `.gitignore`.

## Regla de calibración

La 1.17 tampoco modifica heurísticas, pesos ni umbrales. Si en una versión futura se cambia la lógica que determina el score, estas pruebas deben seguir ejecutándose, pero **no sustituyen** la validación independiente del benchmark: cualquier modificación del modelo heurístico requiere una nueva validación empírica.

## Pruebas del modo batch (1.18/1.18.1)

La suite incluye pruebas offline para lectura TXT/CSV, selección de columna, deduplicación, `--dry-run`, exigencia de `--acknowledge-risk`, ejecución con inspector simulado, agregación CSV/JSON y reanudación con `--resume`. Ninguna de estas pruebas visita URLs reales.
