# syntax=docker/dockerfile:1.7

# =============================================================================
# Kryon Dashboard — Next.js 16 multi-stage build
# =============================================================================
# Produces a small production image (~180 MB) with Next.js standalone output.
# Build from the dashboard/ directory or from the repo root with
# `-f dashboard/Dockerfile dashboard/` as the context.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — deps: install production dependencies only
# -----------------------------------------------------------------------------
FROM node:20-alpine AS deps
WORKDIR /app

# Alpine needs libc6-compat for Next.js binaries and openssl for pnpm.
RUN apk add --no-cache libc6-compat

# Install pnpm globally (matches Corepack-managed version used in CI).
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile


# -----------------------------------------------------------------------------
# Stage 2 — builder: compile Next.js with standalone output
# -----------------------------------------------------------------------------
FROM node:20-alpine AS builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
RUN apk add --no-cache libc6-compat

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Telemetry opt-out — we prefer not to share build stats externally.
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

RUN pnpm build


# -----------------------------------------------------------------------------
# Stage 3 — runner: minimal production image
# -----------------------------------------------------------------------------
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Non-root user for the runtime — Next.js never needs root.
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 --ingroup nodejs nextjs

# Copy public assets and the standalone server. The `.next/static` directory
# is deliberately copied separately because Next.js standalone output does
# not bundle it (it's served from the filesystem at runtime).
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

# Default host 0.0.0.0 so Docker port forwarding works; Next.js standalone
# respects the HOSTNAME env var.
CMD ["node", "server.js"]
