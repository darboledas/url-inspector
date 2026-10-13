# Validación independiente de 600 URLs

## Diseño

La escala de riesgo se validó sobre un corpus independiente de 600 muestras:

- 300 referencias benignas de Tranco.
- 100 phishing de PhishStats.
- 100 phishing de OpenPhish.
- 100 malware de URLhaus.

La auditoría confirmó 0 solapamientos de URL, 0 solapamientos de host con el corpus previo y 0 hosts duplicados internos. Las 600 muestras fueron evaluables. La modalidad principal fue `leave-one-out`, neutralizando la fuente que había aportado cada muestra maliciosa para impedir fuga directa de etiqueta.

## Resultados principales

| Umbral | Sensibilidad | IC95 % sensibilidad | Especificidad | IC95 % especificidad | Precisión empírica | FPR | F1 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| >= 8 | 84,3 % | 79,8–88,0 % | 91,3 % | 87,6–94,0 % | 90,7 % | 8,7 % | 87,4 % |
| >= 20 | 71,0 % | 65,6–75,8 % | 95,0 % | 91,9–96,9 % | 93,4 % | 5,0 % | 80,7 % |
| >= 30 | 52,0 % | 46,4–57,6 % | 99,0 % | 97,1–99,7 % | 98,1 % | 1,0 % | 68,0 % |
| >= 40 | 42,3 % | 36,9–48,0 % | 99,7 % | 98,1–99,9 % | 99,2 % | 0,3 % | 59,3 % |
| >= 50 | 38,3 % | 33,0–43,9 % | 100,0 % | 98,7–100,0 % | 100,0 % | 0,0 % | 55,4 % |

El umbral 8 fue el mejor valor observado tanto por F1 como por índice de Youden.

## Rendimiento por fuente en score >= 8

- OpenPhish: sensibilidad 82,0 % [IC95 % 73,3–88,3 %], n=100.
- PhishStats: sensibilidad 72,0 % [IC95 % 62,5–79,9 %], n=100.
- URLhaus: sensibilidad 99,0 % [IC95 % 94,6–99,8 %], n=100.
- Tranco: especificidad 91,3 % [IC95 % 87,6–94,0 %], n=300.

Por categoría, la sensibilidad global en score >= 8 fue 77,0 % para phishing y 99,0 % para malware.

## Prevalencia

La precisión empírica del 90,7 % corresponde al corpus de validación, cuya prevalencia maliciosa es del 50 %. No debe trasladarse sin ajuste a entornos con prevalencias distintas.

PPV/NPV modelados para score >= 8:

| Prevalencia asumida | PPV | NPV |
|---:|---:|---:|
| 0,1 % | 1,0 % | 100,0 % |
| 1 % | 8,9 % | 99,8 % |
| 5 % | 33,9 % | 99,1 % |
| 10 % | 52,0 % | 98,1 % |
| 50 % | 90,7 % | 85,4 % |

Estos valores dependen de que sensibilidad y especificidad sean transportables al entorno real. No convierten el score en una probabilidad.

## Limitación temporal

Solo 100 de las 300 muestras maliciosas disponían de timestamp utilizable en la campaña analizada; la mediana observada para esas muestras fue de 3,5 días. Esta cobertura temporal del 33,3 % no sustituye una validación longitudinal.

Para estudiar deriva temporal debe repetirse la campaña con el mismo inspector congelado, un corpus fresco sin solapamientos y comparación mediante el subcomando `compare`.
