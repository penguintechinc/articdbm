# Stage 1: Build
FROM node:20-slim AS build

WORKDIR /app

COPY package.json package-lock.json* yarn.lock* ./

RUN npm install --ci --production=false

COPY . .

RUN npm run build

# Stage 2: Production
FROM nginx:alpine

# Create writable directories and fix permissions for non-root execution
RUN mkdir -p /var/cache/nginx/client_temp && \
    mkdir -p /var/cache/nginx/proxy_temp && \
    mkdir -p /var/cache/nginx/scgi_temp && \
    mkdir -p /var/cache/nginx/uwsgi_temp && \
    mkdir -p /var/run/nginx && \
    mkdir -p /tmp/nginx && \
    chmod -R 777 /var/cache/nginx && \
    chmod -R 777 /var/run/nginx && \
    chmod -R 777 /tmp/nginx && \
    chmod 777 /var/log/nginx

COPY --from=build /app/dist /usr/share/nginx/html

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 3000

USER nginx

CMD ["nginx", "-g", "daemon off;"]
