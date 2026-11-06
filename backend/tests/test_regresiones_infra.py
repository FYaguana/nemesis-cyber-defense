"""Regresiones de los errores de despliegue que ya ocurrieron (Docker, nginx, frontend)."""
import os
import re

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRONT = os.path.join(RAIZ, "frontend")


def leer(*ruta):
    with open(os.path.join(RAIZ, *ruta), encoding="utf-8") as f:
        return f.read()


def test_url_base_api_no_trata_la_cadena_vacia_como_falsa():
    """'window.NEMESIS_API_URL || "http://localhost:8000"' ignoraba el valor "" (ruta relativa)
    y el frontend desplegado seguía llamando a localhost."""
    archivos = [f for f in os.listdir(FRONT) if f.endswith(".html")] + ["js/cliente_recomendaciones_ia.js"]
    for nombre in archivos:
        texto = leer("frontend", nombre)
        assert "window.NEMESIS_API_URL ||" not in texto, nombre
        if "URL_BASE_API" in texto:
            assert 'typeof window.NEMESIS_API_URL !== "undefined"' in texto, nombre


def test_las_paginas_cargan_config_js_antes_de_usar_la_url():
    for nombre in os.listdir(FRONT):
        if nombre.endswith(".html") and "URL_BASE_API" in leer("frontend", nombre):
            assert 'src="config.js"' in leer("frontend", nombre), nombre
    assert 'window.NEMESIS_API_URL = ""' in leer("frontend", "config.js")


def test_nginx_envia_sni_y_el_host_del_backend():
    """Sin SNI el handshake TLS contra Render fallaba (alert 40) y todo daba 502."""
    conf = leer("frontend", "nginx.conf.template")
    assert "proxy_ssl_server_name on;" in conf
    assert "proxy_set_header Host ${NEMESIS_API_HOST};" in conf
    assert "proxy_pass ${NEMESIS_API_URL}/api/;" in conf


def test_dockerignore_no_excluye_archivos_que_el_dockerfile_copia():
    """Un .dockerignore que excluía el entrypoint rompía el build ('not found'): .dockerignore
    se aplica a TODO el contexto, no solo a un COPY."""
    ignorados = {l.strip() for l in leer("frontend", ".dockerignore").splitlines() if l.strip()}
    copiados = [c for c in re.findall(r"^COPY\s+(\S+)\s", leer("frontend", "Dockerfile"), re.M) if c != "."]
    assert "docker-entrypoint-nemesis.sh" in copiados and "nginx.conf.template" in copiados
    assert not ignorados & set(copiados), ignorados & set(copiados)


def test_los_scripts_de_contenedor_usan_saltos_de_linea_lf():
    for ruta in (("frontend", "docker-entrypoint-nemesis.sh"), ("frontend", "nginx.conf.template")):
        with open(os.path.join(RAIZ, *ruta), "rb") as f:
            assert b"\r\n" not in f.read(), f"{ruta[-1]} tiene CRLF y fallará dentro del contenedor Linux"


def test_gitignore_protege_los_secretos():
    gi = leer(".gitignore").splitlines()
    for secreto in ("backend/data/config_email.json", "backend/data/sesiones.json", "backend/data/nemesis.db"):
        assert secreto in gi, secreto


def test_workflow_ci_coincide_con_lo_que_describe_la_tesis():
    """Secciones 3.10 y 4.9: py_compile + flake8 (backend) y node --check (frontend), en paralelo;
    despues, imagenes Docker en GHCR y despliegue. Se agrega pytest como verificacion adicional."""
    wf = leer(".github", "workflows", "ci-cd.yml")
    for paso in ("compileall", "flake8", "node --check", "pytest", "tr '[:upper:]' '[:lower:]'", "ghcr.io"):
        assert paso in wf, paso
    assert "pull_request" in wf and "push:" in wf
    import yaml
    jobs = yaml.safe_load(wf)["jobs"]
    assert set(jobs) == {"backend-test", "frontend-lint", "docker-build-push", "deploy"}  # los 4 trabajos de la Ilustracion 8
    assert set(jobs["docker-build-push"]["needs"]) == {"backend-test", "frontend-lint"}


def test_dashboard_etiqueta_la_alerta_correcta_aunque_la_lista_este_filtrada():
    """Regresion: alHTML recibia el indice de la lista FILTRADA y etiquetarDeteccion lo usaba sobre
    la lista completa, asi que 'Confirmar' podia etiquetar otra alerta y contaminar el reentrenamiento."""
    html = leer("frontend", "dashboard.html")
    assert "f.map(a=>alHTML(a,alertas.indexOf(a)))" in html
    assert "alertas.slice(0,5).map(a=>alHTML(a,alertas.indexOf(a)))" in html
    assert "verPlanIA" in html and "tiempo_respuesta_objetivo" in html


def test_el_rotulo_de_origen_del_plan_usa_los_campos_que_envia_el_backend():
    """Regresion: el dashboard leia rec._ia_meta (que el backend nunca envia) y rotulaba SIEMPRE el plan
    como 'plantilla', incluso cuando lo habia generado la IA (Seccion 4.8: trazabilidad del origen)."""
    html = leer("frontend", "dashboard.html")
    assert "rec.generado_por_ia" in html and "rec.motivo_uso_plantilla" in html
    assert "rec._ia_meta ||" not in html
