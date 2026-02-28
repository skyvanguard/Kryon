# =============================================================================
# KRYON Dashboard - Multi-stage build
# =============================================================================

FROM node:20-alpine AS builder

WORKDIR /app

COPY dashboard/package*.json ./
RUN npm ci --production=false

COPY dashboard/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Runtime — serve static build with nginx
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine

COPY --from=builder /app/build /usr/share/nginx/html
COPY docker/nginx/dashboard.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/health || exit 1
