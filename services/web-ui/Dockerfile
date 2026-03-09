FROM nginx:1.27-alpine

ARG WEB_UI_API_BASE=http://localhost:8080/api/v1

COPY services/web-ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY services/web-ui/index.html /usr/share/nginx/html/index.html
COPY services/web-ui/app.js /usr/share/nginx/html/app.js
COPY services/web-ui/styles.css /usr/share/nginx/html/styles.css

RUN sed -i "s|__API_BASE__|${WEB_UI_API_BASE}|g" /usr/share/nginx/html/app.js
