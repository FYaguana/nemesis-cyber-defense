"""
configuracion.py -- Valores de configuración leídos del entorno, en un
solo lugar en vez de repetir os.environ.get(...) por todo el código.
"""

import os

# URL pública donde vive el FRONTEND (no el backend) -- se usa para armar
# los links que se mandan por correo (activación, recuperación, reset de MFA),
# porque esas páginas (activar.html, recuperar.html, etc.) las sirve el
# frontend, no este servidor.
URL_FRONTEND = os.environ.get("URL_FRONTEND_PUBLICA", "http://localhost:5173")
