# Pinned to the immutable manifest digest of node:22-alpine.
# Refresh with: docker pull node:22-alpine && \
#               docker inspect --format='{{index .RepoDigests 0}}' node:22-alpine

# ----------------------------------------------------------------------
# Development stage: hot reload with volume mounts. Stays root so the
# bind-mounted host source is always readable inside the container.
# ----------------------------------------------------------------------
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS dev
WORKDIR /app
COPY package*.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]

# ----------------------------------------------------------------------
# Builder stage: compile the Next.js standalone bundle.
# ----------------------------------------------------------------------
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS builder
WORKDIR /app
COPY package*.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

# ----------------------------------------------------------------------
# Production stage: minimal runtime, drops privileges to a dedicated
# non-root user.
# ----------------------------------------------------------------------
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS production

ARG GIT_COMMIT=unknown
ARG APP_VERSION=unknown
LABEL org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/fabriziosalmi/nis2-public" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
WORKDIR /app

RUN addgroup --system --gid 1001 nodejs && \
    adduser  --system --uid 1001 --ingroup nodejs --shell /sbin/nologin nextjs

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs
EXPOSE 3000
ENV PORT=3000 HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
