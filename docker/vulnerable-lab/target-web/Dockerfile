# Target web — plants CWE-319 plaintext HTTP + CWE-1004 missing httponly +
# exposes /admin without auth.
FROM nginx:1.27-alpine

RUN rm -f /etc/nginx/conf.d/default.conf
COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY admin.html /usr/share/nginx/html/admin.html

EXPOSE 80
