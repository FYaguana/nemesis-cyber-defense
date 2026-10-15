# Frontend Nemesis Cyber Defense -- archivos estáticos servidos por Nginx,
# que además hace de proxy inverso hacia el backend (ver nginx.conf.template).
FROM nginx:1.27-alpine

# gettext trae envsubst, usado para generar la config real de nginx desde
# variables de entorno en tiempo de arranque (ver docker-entrypoint-nemesis.sh).
RUN apk add --no-cache gettext

# Va a /etc/nginx/templates/ (no a conf.d/) porque el ENTRYPOINT la procesa
# él mismo con envsubst antes de arrancar nginx.
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY . /usr/share/nginx/html
COPY docker-entrypoint-nemesis.sh /docker-entrypoint-nemesis.sh
RUN chmod +x /docker-entrypoint-nemesis.sh

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint-nemesis.sh"]
