# Frontend Nemesis Cyber Defense -- archivos estáticos servidos por Nginx
FROM nginx:1.27-alpine

# gettext trae envsubst, usado para generar config.js desde variables
# de entorno en tiempo de arranque (ver docker-entrypoint-nemesis.sh).
RUN apk add --no-cache gettext

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY . /usr/share/nginx/html
COPY docker-entrypoint-nemesis.sh /docker-entrypoint-nemesis.sh
RUN chmod +x /docker-entrypoint-nemesis.sh

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint-nemesis.sh"]
