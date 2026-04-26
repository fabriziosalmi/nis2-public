# Pinned to the immutable manifest digest of node:20.18.0-alpine3.20.
# Refresh with: docker pull node:20.18.0-alpine3.20 && \
#               docker inspect --format='{{index .RepoDigests 0}}' node:20.18.0-alpine3.20

# ----------------------------------------------------------------------
# Development stage: hot reload with volume mounts. Stays root so the
# bind-mounted host source is always readable inside the container.
# ----------------------------------------------------------------------
FROM node:20.18.0-alpine3.20@sha256:b1e0880c3af955867bc2f1944b49d20187beb7afa3f30173e15a97149ab7f5f1 AS dev
WORKDIR /app
COPY package*.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]

# ----------------------------------------------------------------------
# Builder stage: compile the Next.js standalone bundle.
# ----------------------------------------------------------------------
FROM node:20.18.0-alpine3.20@sha256:b1e0880c3af955867bc2f1944b49d20187beb7afa3f30173e15a97149ab7f5f1 AS builder
WORKDIR /app
COPY package*.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

# ----------------------------------------------------------------------
# Production stage: minimal runtime, drops privileges to a dedicated
# non-root user.
# ----------------------------------------------------------------------
FROM node:20.18.0-alpine3.20@sha256:b1e0880c3af955867bc2f1944b49d20187beb7afa3f30173e15a97149ab7f5f1 AS production
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
