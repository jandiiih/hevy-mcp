# syntax=docker/dockerfile:1

FROM node:24-alpine AS build

WORKDIR /app

COPY package.json package-lock.json tsconfig.base.json tsconfig.json ./
COPY packages/hevy-client/package.json packages/hevy-client/package.json
COPY packages/operations/package.json packages/operations/package.json
COPY packages/core/package.json packages/core/package.json
COPY packages/node/package.json packages/node/package.json
COPY packages/worker/package.json packages/worker/package.json
RUN npm ci

COPY packages/hevy-client/ ./packages/hevy-client/
COPY packages/operations/ ./packages/operations/
COPY packages/core/ ./packages/core/
COPY packages/node/ ./packages/node/
RUN npm run build:standalone --workspace hevy-mcp

FROM node:24-alpine AS runtime

ENV NODE_ENV=production
WORKDIR /app

# su-exec drops privileges after the entrypoint has prepared the writable
# volume, so the server itself never runs as root.
RUN apk add --no-cache su-exec

COPY --from=build --chown=node:node /app/packages/node/dist/standalone.mjs ./standalone.mjs
COPY entrypoint.sh ./entrypoint.sh

RUN chmod +x ./entrypoint.sh

# Deliberately no USER directive: the entrypoint starts as root only long
# enough to make an attached volume writable, then execs the server as the
# unprivileged "node" user. Hosted platforms mount volumes as root, so a
# container that starts unprivileged cannot use one at all.
ENTRYPOINT ["./entrypoint.sh"]

