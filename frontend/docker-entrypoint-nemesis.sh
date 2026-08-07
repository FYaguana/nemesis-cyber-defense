#!/bin/sh
set -e

# Si no seteaste NEMESIS_API_URL, cae a localhost:8000 (útil para correr
# el backend suelto en desarrollo, fuera de docker-compose).
: "${NEMESIS_API_URL:=http://localhost:8000}"

# Genera la config real de nginx con el backend correcto ya embebido
# (proxy inverso de /api/*, ver nginx.conf.template).
envsubst '${NEMESIS_API_URL}' \
    < /etc/nginx/templates/nginx.conf.template \
    > /etc/nginx/conf.d/default.conf

echo "[nemesis-frontend] Proxy /api/* -> ${NEMESIS_API_URL}"

exec nginx -g 'daemon off;'
