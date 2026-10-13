# Seguridad operativa

URL Inspector es una herramienta defensiva, pero algunas funciones realizan conexiones reales a destinos potencialmente hostiles.

## Reglas de uso

- No abra manualmente las URLs contenidas en corpus de phishing/malware.
- Ejecute campañas activas contra indicadores maliciosos en una VM desechable o entorno aislado.
- No habilite capturas headless salvo necesidad expresa; `--screenshot` abre una superficie de ataque mayor que el análisis HTTP controlado.
- No almacene claves API en el repositorio. Use variables de entorno o un almacén local de secretos.
- No publique `APIKEY.txt`, `.env`, archivos de claves privadas, salidas con datos sensibles ni el backup privado maestro.

## Protección de destino

La versión estable bloquea `localhost`, redes privadas, loopback, link-local, multicast, direcciones reservadas/no globales y nombres locales habituales. Cada redirección HTTP/meta se valida antes de seguirla. La resolución de cada conexión se fija a IP públicas previamente validadas para mitigar DNS rebinding.

Estas protecciones reducen riesgo, pero no convierten el análisis activo de URLs maliciosas en una operación inocua.

## Corpus de benchmark

`benchmark_corpus_regression.json` y `.csv` pueden contener URLs maliciosas históricas. Se incluyen para reproducibilidad y regresión. No deben tratarse como enlaces de navegación ni abrirse manualmente.
