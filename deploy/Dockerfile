FROM rust:1.80 AS daemon-builder
WORKDIR /usr/src/app
COPY daemon/ ./
RUN apt-get update && apt-get install -y libclang-dev
RUN cargo build --release --features pq-hybrid-1024

FROM node:20-slim AS web-builder
WORKDIR /usr/src/app
COPY web/package*.json ./
RUN npm ci --strict-peer-deps
COPY web/ ./
RUN npm run build

FROM gcr.io/distroless/cc-debian12 AS daemon
COPY --from=daemon-builder /usr/src/app/target/release/vault-daemon /usr/local/bin/vault-daemon
ENTRYPOINT ["/usr/local/bin/vault-daemon", "--socket", "/run/vault-daemon/vault.sock"]

FROM gcr.io/distroless/nodejs20-debian12 AS server
WORKDIR /app
COPY --from=web-builder /usr/src/app/package*.json ./
COPY --from=web-builder /usr/src/app/node_modules ./node_modules
COPY --from=web-builder /usr/src/app/dist ./dist
COPY --from=web-builder /usr/src/app/server.js ./
COPY --from=web-builder /usr/src/app/auth.js ./
ENTRYPOINT ["/nodejs/bin/node", "server.js"]
