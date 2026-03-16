FROM nginx:alpine

COPY index.html /usr/share/nginx/html/
COPY profile.html /usr/share/nginx/html/
COPY config.js /usr/share/nginx/html/

RUN sed -i 's/listen       80;/listen       8080;/' /etc/nginx/conf.d/default.conf

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]