#!/bin/sh
set -e

# Si Render (u otra plataforma) no seteó NEMESIS_API_URL, cae a localhost
# para que siga funcionando en desarrollo local sin Docker.
: "${NEMESIS_API_URL:=http://localhost:8000}"

envsubst '${NEMESIS_API_URL}' \
    < /usr/share/nginx/html/config.template.js \
    > /usr/share/nginx/html/config.js

echo "[nemesis-frontend] NEMESIS_API_URL=${NEMESIS_API_URL}"

exec nginx -g 'daemon off;'
