# Tabla 7 – Resultados en el conjunto de prueba NSL-KDD (n=4000)

Generado por `python -m app.motor.experimentos` el 2026-10-15T02:05:49 (semilla 42, 45 variables de entrada).
Recall, Precisión y F1 en promedio macro. Columnas de clase = Recall por clase.

| Modelo | Recall ↑ | Precisión | F1-Score | Accuracy | DoS | NORMAL | Probe | R2L | U2R |
|---|---|---|---|---|---|---|---|---|---|
| MLP Nemesis (Deep Learning) | 99.99% | 99.94% | 99.96% | 99.98% | 100.00% | 99.95% | 100.00% | 100.00% | 100.00% |
| RNN/LSTM Nemesis (Deep Learning) | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| Random Forest (Tradicional) | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| Gradient Boosting (Tradicional) | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| SVM (Tradicional) | 99.88% | 99.99% | 99.93% | 99.98% | 100.00% | 100.00% | 100.00% | 100.00% | 99.38% |
| KNN (Tradicional) | 98.27% | 99.64% | 98.94% | 99.35% | 99.78% | 100.00% | 100.00% | 93.44% | 98.12% |

Evaluadas: MLP/tradicionales 4000; RNN 3991 ventanas.

> Las ventanas se etiquetan con la clase del último evento (coherente con la inferencia). El dataset sintético no tiene orden temporal entre registros, así que el contexto de los 9 eventos previos no aporta información: ver 5.5.
