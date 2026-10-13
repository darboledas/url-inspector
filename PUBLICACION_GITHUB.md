# Lista de comprobación para publicación en GitHub

La carpeta `URL_Inspector_6.0_FINAL_PUBLIC_1.18.1` está preparada como base pública: no contiene `APIKEY.txt`, `.env`, archivos `.key/.pem`, cachés Python ni salidas batch locales.

Antes de crear un repositorio público:

1. Confirmar que `LICENSE` está presente. Esta distribución utiliza la licencia MIT.
2. Ejecutar `run_tests.bat` y confirmar que toda la suite termina en `OK`.
3. Revisar `SHA256SUMS.txt` y conservarlo junto a la release publicada.
4. Confirmar con `git status` que no aparecen secretos ni carpetas privadas antes de cada commit.
5. No copiar `URL_Inspector_MASTER_PRIVATE`, `APIKEY.txt`, `.env` ni credenciales al repositorio.
6. Tratar `benchmark_corpus_regression.*` como datos de investigación que pueden contener indicadores maliciosos; no hacer clic en sus URLs.

Inicialización típica:

```bash
git init
git add .
git status
git commit -m "URL Inspector 6.0 stable release 1.18.1"
```

La publicación remota debe hacerse solo después de revisar el contenido de `git status` y el diff del primer commit.
