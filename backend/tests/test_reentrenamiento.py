"""Sección 4.2 (etapa 4): el reentrenamiento publica los modelos nuevos SIN interrumpir el servicio:
si falla a mitad, los modelos en producción quedan intactos."""
import os

import numpy as np
import pytest

from app.motor import reentrenamiento as rt


@pytest.fixture
def modelos(tmp_path, monkeypatch):
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "Nemesis_MLP.keras").write_text("VIEJO")
    (tmp_path / "models" / "scaler.pkl").write_text("VIEJO")
    monkeypatch.setattr(rt, "DIRECTORIO_BACKEND", str(tmp_path))
    monkeypatch.setattr(rt, "obtener_capturas_etiquetadas", lambda: [])
    monkeypatch.setattr(rt, "preparar_datos_con_reales_y_base",
                        lambda reales: {"n_muestras_reales": 0, "n_muestras_base": 15000})
    monkeypatch.setattr(rt, "guardar_metricas", lambda *a, **k: None)
    recarga = []

    class ProcesadorFalso:
        def cargar_modelos(self):
            recarga.append(True)
    monkeypatch.setattr(rt, "obtener_procesador", lambda: ProcesadorFalso())
    return tmp_path / "models", recarga


def test_si_el_entrenamiento_falla_los_modelos_en_servicio_quedan_intactos(modelos, monkeypatch):
    carpeta, recarga = modelos

    def entrenar_roto(datos, destino, epochs, callback_progreso=None):
        with open(os.path.join(destino, "scaler.pkl"), "w") as f:
            f.write("NUEVO-A-MEDIAS")
        raise RuntimeError("se cayó a mitad")
    monkeypatch.setattr(rt, "entrenar_modelos_nemesis", entrenar_roto)
    g = rt.GestorReentrenamiento()
    g._ejecutar(1)
    assert "se cayó" in g.error and g.resultado is None
    assert (carpeta / "scaler.pkl").read_text() == "VIEJO" and (carpeta / "Nemesis_MLP.keras").read_text() == "VIEJO"
    assert not [n for n in os.listdir(carpeta) if n.startswith(".reentrenando_")], "quedó basura de preparación"
    assert recarga == []


def test_si_todo_sale_bien_se_publican_los_archivos_y_se_recarga_en_caliente(modelos, monkeypatch):
    carpeta, recarga = modelos
    metricas = {"recall": 0.99, "precision": 0.99, "f1_score": 0.99}

    def entrenar_ok(datos, destino, epochs, callback_progreso=None):
        for nombre in ("Nemesis_MLP.keras", "scaler.pkl", "config.json"):
            with open(os.path.join(destino, nombre), "w") as f:
                f.write("NUEVO")
        return {"metricas_mlp": metricas, "metricas_rnn": metricas}
    monkeypatch.setattr(rt, "entrenar_modelos_nemesis", entrenar_ok)
    g = rt.GestorReentrenamiento()
    g._ejecutar(1)
    assert g.error is None and g.resultado["n_muestras_base"] == 15000
    assert (carpeta / "scaler.pkl").read_text() == "NUEVO" and (carpeta / "config.json").exists()
    assert recarga == [True]
    assert not [n for n in os.listdir(carpeta) if n.startswith(".reentrenando_")]


def test_el_entrenamiento_compartido_guarda_modelos_metricas_y_artefactos(tmp_path):
    """Entrenamiento real (1 época, subconjunto pequeño): produce todo lo que la inferencia necesita."""
    from app.motor.entrenamiento import entrenar_modelos_nemesis
    from app.motor.preparacion_datos import preparar_datos_con_reales_y_base
    d = preparar_datos_con_reales_y_base([])
    chico = dict(d, X_train=d["X_train"][:700], y_train=d["y_train"][:700], X_val=d["X_val"][:250],
                 y_val=d["y_val"][:250], X_test=d["X_test"][:400], y_test=d["y_test"][:400])
    r = entrenar_modelos_nemesis(chico, str(tmp_path), epochs=1)
    for archivo in ("Nemesis_MLP.keras", "Nemesis_RNN.keras", "Nemesis_MLP_metricas.json", "Nemesis_RNN_metricas.json",
                    "scaler.pkl", "encoders.pkl", "le_target.pkl", "config.json"):
        assert (tmp_path / archivo).exists(), archivo
    assert r["ventanas_test"][0].shape == (391, 10, 45)   # 400 - 10 + 1 ventanas de 10 eventos
