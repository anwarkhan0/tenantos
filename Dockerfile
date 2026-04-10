# ─── Base ─────────────────────────────────────────────────────
FROM node:20-alpine AS base
WORKDIR /app

# Install security updates
RUN apk update && apk upgrade && apk add --no-cache \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S tenantOS -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# ─── Development ──────────────────────────────────────────────
FROM base AS development
ENV NODE_ENV=development

RUN npm install

COPY --chown=tenantOS:nodejs . .

USER tenantOS
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "run", "dev"]

# ─── Builder ──────────────────────────────────────────────────
FROM base AS builder
ENV NODE_ENV=production

RUN npm ci --only=production && npm cache clean --force

# ─── Production ───────────────────────────────────────────────
FROM node:20-alpine AS production
WORKDIR /app

ENV NODE_ENV=production

RUN apk update && apk upgrade && apk add --no-cache \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S tenantOS -u 1001 -G nodejs

# Copy production deps and source
COPY --from=builder --chown=tenantOS:nodejs /app/node_modules ./node_modules
COPY --chown=tenantOS:nodejs . .

USER tenantOS
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]
