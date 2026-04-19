# ════════════════════════════════════════════════════════════
# TenantOS — Dockerfile
# Multi-stage: development → builder → production
# ════════════════════════════════════════════════════════════

# ── Base ──────────────────────────────────────────────────────
FROM node:20-alpine AS base
WORKDIR /app

RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init curl && \
    rm -rf /var/cache/apk/*

RUN addgroup -g 1001 -S nodejs && \
    adduser  -u 1001 -S tenantOS -G nodejs

COPY package*.json ./

# ── Development ───────────────────────────────────────────────
FROM base AS development
ENV NODE_ENV=development

RUN npm install

COPY --chown=tenantOS:nodejs . .

USER tenantOS
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/ready || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "run", "dev"]

# ── Builder (production deps only) ────────────────────────────
FROM base AS builder
ENV NODE_ENV=production

RUN npm ci --only=production && npm cache clean --force

# ── Production ────────────────────────────────────────────────
FROM node:20-alpine AS production
WORKDIR /app
ENV NODE_ENV=production

RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init curl && \
    rm -rf /var/cache/apk/*

RUN addgroup -g 1001 -S nodejs && \
    adduser  -u 1001 -S tenantOS -G nodejs

COPY --from=builder --chown=tenantOS:nodejs /app/node_modules ./node_modules
COPY --chown=tenantOS:nodejs . .

USER tenantOS
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/ready || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]
