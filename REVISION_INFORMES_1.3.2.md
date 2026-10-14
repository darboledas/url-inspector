# URL Inspector 6.0 — Revisión de informes 1.3.2

**Base:** motor calibrado 1.18.1 sin modificar (SHA-256: `30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a`). La versión 1.3.2 afecta exclusivamente al generador de informes, sus pruebas y la documentación.

## Cambios

1. **Definición explícita de cobertura técnica.** Valor calculado por el motor a partir de resolución URL (peso 20), RDAP (15), TLS (15), HTTP (15) y HTML (15), normalizados respecto a 80. Los pesos equivalen a 25 % y cuatro veces 18,75 %. El módulo de registros DNS detallados, la geolocalización, la reputación externa y las capturas de pantalla no integran este indicador, aunque la resolución de URL pueda utilizar DNS como mecanismo subyacente. La presencia/ausencia de un componente no acredita que el resultado sea correcto ni que la web sea legítima. No se recalcula ninguna puntuación en el generador.
2. **Separación de cobertura reputacional.** Se mantiene la relación fuentes evaluadas/total, independiente del índice técnico.
3. **Índice general simplificado.** El pericial PDF mantiene índice con páginas de los ocho capítulos principales y anejos, además de las declaraciones y la firma. Las subsecciones 7.x y los campos del anejo exhaustivo siguen en el cuerpo del informe, sin aparecer uno por uno en el índice. El archivo JSON asociado y el registro de consola se mantienen íntegros.

## Verificación offline realizada (14/10/2026)

- Compilación del generador de informes y **73/73 pruebas locales** mediante `unittest`.
- Regeneración offline sobre los JSON reales del **BOE** y **AMTSO** ya conservados. Se han verificado copias binarias idénticas del JSON original en los archivos asociados y la conservación de los registros de consola (214 y 236 líneas físicas, respectivamente).
- PDF pericial: 22 páginas para BOE y 24 para AMTSO; el índice ocupa una página en ambos casos. Ejecutivo: una página en ambos casos. El HTML sigue reproduciendo todos los campos del JSON y los registros disponibles.
- En los índices se identifican los ocho capítulos principales y los cuatro anejos; no aparecen entradas por cada campo técnico, aunque esos campos siguen en el cuerpo del PDF.
- Sin nuevas consultas HTTP a las páginas durante la regeneración. SHA-256 del motor inalterado.

## Verificación pendiente

Este complemento se prueba localmente de forma offline con datos previamente adquiridos. No debe confundirse la validación local con una ejecución de GitHub Actions tras publicar cambios. La exportación y las pruebas CI para Windows y Linux deben confirmarse en el repositorio actualizado y el entorno del usuario.

## Regeneración sin conexión a la URL

```cmd
python informes_une_197001.py "informes_locales\resultado.json" --pericial "informes_locales\pericial_132.pdf" --pericial-html "informes_locales\pericial_132.html" --ejecutivo "informes_locales\ejecutivo_132.pdf"
```

Si existe un archivo `resultado.consola.txt`, el generador lo incorpora automáticamente. Conservar siempre los JSON y registros originales. El informe sigue siendo borrador automatizado sujeto a individualización, revisión y firma del perito; la mención UNE 197001:2019 no certifica conformidad.

## Trazabilidad SHA-256 del corpus
Formato almacenado en Git: LF.
SHA-256 LF: 07f6a3405f2725463cb3d2464a48cf1b9cea96d1beb1d5b907432d949e24efc8
SHA-256 historico CRLF: 6bbfde299f1f95d8ffbdae5168b1353f1e67cab7e67e06d9d4ef799a1fdcf964
Diferencia exclusiva de finales de linea. Muestras sin cambios.
