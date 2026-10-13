> **Mantenimiento 1.17:** la escala calibrada no cambia. La versión 1.17 mejora únicamente el análisis estadístico del benchmark: intervalos de confianza, desgloses por fuente/categoría, prevalencia, solapamiento y soporte para validación temporal posterior.

# Calibración de la escala de riesgo de URL Inspector 6.0

## Objetivo

La escala de riesgo de URL Inspector 6.0 se calibró empíricamente para que los niveles reflejen el comportamiento observado del sistema sobre un conjunto independiente de URLs benignas y maliciosas.

La puntuación **no representa una probabilidad** de que una URL sea maliciosa. Es una puntuación heurística acumulativa basada en señales técnicas, de identidad, infraestructura, contenido y reputación.

## Metodología

La calibración final se realizó sobre un corpus independiente de **600 URLs**:

- 300 referencias benignas procedentes de Tranco.
- 100 URLs de phishing procedentes de PhishStats.
- 100 URLs de phishing procedentes de OpenPhish.
- 100 URLs asociadas a malware procedentes de URLhaus.

El corpus de validación no reutilizó URLs ni hosts del corpus empleado durante el desarrollo de las heurísticas:

- Solapamiento de URLs: **0**
- Solapamiento de hosts: **0**
- Hosts duplicados internos: **0**

La evaluación se realizó en modo **leave-one-out**, neutralizando la fuente que había aportado cada muestra maliciosa para evitar que la propia fuente del corpus resolviera directamente la clasificación.

Las 600 muestras fueron evaluables correctamente.

## Resultado principal

El mejor compromiso empírico entre sensibilidad y especificidad apareció en el umbral **8**, que fue además el mejor valor observado tanto por **F1** como por **índice de Youden**.

Con `score >= 8`:

- Verdaderos positivos: **253**
- Falsos negativos: **47**
- Verdaderos negativos: **274**
- Falsos positivos: **26**
- Sensibilidad: **84,3 %**
- Especificidad: **91,3 %**
- Precisión: **90,7 %**
- F1: **≈ 87,4 %**

A medida que aumenta la puntuación, disminuye la sensibilidad pero aumenta la fuerza de la evidencia:

| Umbral | Sensibilidad | Especificidad | Precisión |
|---:|---:|---:|---:|
| >= 8 | 84,3 % | 91,3 % | 90,7 % |
| >= 20 | 71,0 % | 95,0 % | 93,4 % |
| >= 30 | 52,0 % | 99,0 % | 98,1 % |
| >= 40 | 42,3 % | 99,7 % | 99,2 % |
| >= 50 | 38,3 % | 100,0 % | 100,0 % |

## Escala adoptada

| Puntuación | Nivel | Interpretación |
|---:|---|---|
| **0–7** | 1 — Bajo | No se han obtenido indicios suficientes de riesgo. |
| **8–19** | 2 — Moderado | Existen indicios que justifican cautela. |
| **20–29** | 3 — Alto | Existe evidencia significativa de comportamiento sospechoso. |
| **30–49** | 4 — Muy alto | Existe evidencia fuerte; no debe confiarse en la URL sin verificación adicional. |
| **50–100** | 5 — Crítico | Existe evidencia técnica muy fuerte de comportamiento malicioso. |

## Interpretación correcta

Una puntuación de **0–7 no significa que la URL sea segura**. Significa únicamente que URL Inspector no ha encontrado suficientes indicios con las técnicas y fuentes disponibles.

Del mismo modo, una puntuación de 50 no significa “50 % de probabilidad de malware o phishing”. La escala es una medida heurística ordinal calibrada empíricamente.

La cobertura técnica del análisis se informa por separado y no debe confundirse con la puntuación de riesgo.

## Estado de la calibración

La escala quedó fijada después de:

1. una fase de desarrollo y regresión sobre un corpus de 600 muestras;
2. una validación independiente posterior sobre otras 600 muestras sin solapamiento de URL ni host;
3. la confirmación del umbral 8 como mejor compromiso empírico por F1 e índice de Youden.

Los pesos heurísticos y los umbrales quedan congelados tras esta validación. Cambios futuros en las heurísticas deberán acompañarse de una nueva validación independiente.


## Nota sobre la versión 1.12

La versión 1.12 amplía únicamente la capa de reputación con PhishStats. Esta integración se presenta como alerta externa y **no modifica los pesos, las heurísticas ni los umbrales calibrados**. Por tanto, la calibración descrita en este documento permanece referida al modelo congelado en 1.11.


## Nota sobre la versión 1.13

La versión 1.13 corrige únicamente el mecanismo de consulta exacta de PhishStats: usa el SHA-256 de la URL como clave de búsqueda y confirma la URL canónica de forma local. No modifica heurísticas, pesos ni umbrales; por tanto, la calibración de la 1.11 permanece intacta.


## Nota sobre la versión 1.14

La versión 1.14 no modifica heurísticas, pesos ni umbrales. Añade una capa de **veredicto operativo** y separa la **cobertura técnica** de la **cobertura reputacional**. Las coincidencias negativas de reputación se presentan de forma prioritaria y visualmente destacada, pero la puntuación heurística conserva exactamente la escala calibrada. Además, el benchmark neutraliza PhishStats en `leave-one-out` y `heuristic-only` para impedir fuga directa de etiqueta en ejecuciones futuras.


## Nota sobre la versión 1.15

La versión 1.15 endurece exclusivamente la seguridad de red del inspector (protección SSRF, validación de destinos/redirecciones y mitigación de DNS rebinding) y hace que la captura headless sea opt-in. **No modifica heurísticas, pesos ni umbrales de riesgo**, por lo que no requiere recalibrar la escala.
## Control de regresiones desde la revisión 1.16

La revisión 1.16 añade pruebas automáticas y CI para detectar cambios accidentales en seguridad, reputación, separación entre score y veredicto y neutralización de fuentes en el benchmark. Estas pruebas no modifican ni recalibran la escala. Los umbrales y pesos permanecen congelados; cualquier cambio futuro en la lógica de puntuación exigirá una nueva validación independiente.


## Reanálisis estadístico 1.17

La campaña independiente de 600 muestras se reanalizó posteriormente con intervalos de Wilson al 95 %. En `score >= 8`, la sensibilidad fue **84,3 % [79,8–88,0 %]** y la especificidad **91,3 % [87,6–94,0 %]**, con F1 **87,4 %**. El umbral 8 siguió siendo el mejor valor observado tanto por F1 como por índice de Youden.

El detalle por fuente, prevalencia modelada y limitaciones temporales se resume en `docs/VALIDACION_INDEPENDIENTE_600.md`. Este reanálisis no modifica la escala ni los pesos del inspector.
