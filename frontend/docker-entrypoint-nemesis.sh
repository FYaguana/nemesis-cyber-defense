#!/bin/sh
set -e

# Si no seteaste NEMESIS_API_URL, cae a localhost:8000 (útil para correr
# el backend suelto en desarrollo, fuera de docker-compose).
: "${NEMESIS_API_URL:=http://localhost:8000}"

# Extrae solo el hostname (sin esquema ni barra final) para el header Host
# que se manda al backend real -- ver comentario en nginx.conf.template.
NEMESIS_API_HOST=$(echo "$NEMESIS_API_URL" | sed -E 's#^[a-zA-Z]+://##' | sed -E 's#/.*$##')
export NEMESIS_API_HOST

# Genera la config real de nginx con el backend correcto ya embebido
# (proxy inverso de /api/*, ver nginx.conf.template).
envsubst '${NEMESIS_API_URL} ${NEMESIS_API_HOST}' \
    < /etc/nginx/templates/nginx.conf.template \
    > /etc/nginx/conf.d/default.conf

echo "[nemesis-frontend] Proxy /api/* -> ${NEMESIS_API_URL} (Host: ${NEMESIS_API_HOST})"

exec nginx -g 'daemon off;'
