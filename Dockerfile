FROM node:22-alpine

# docker CLI only (no daemon) — used to talk to a REMOTE Docker Engine over
# TLS-verified TCP via DOCKER_HOST/DOCKER_TLS_VERIFY/DOCKER_CERT_PATH, for
# GET /api/docker/containers and /api/docker/logs/:name.
RUN apk add --no-cache docker-cli

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 8443 3000

CMD ["node", "mqtt.js"]
