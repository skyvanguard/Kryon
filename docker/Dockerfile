# =============================================================================
# KRYON - Autonomous Cybersecurity Intelligence Platform
# Production Dockerfile (Multi-stage build)
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder - compile dependencies
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy only dependency files first for better caching
COPY pyproject.toml ./
COPY src/ ./src/

# Install kryon with all extras into a virtual environment
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache ".[rag,tracing,viz]"

# ---------------------------------------------------------------------------
# Stage 2: Security tools (optional, controlled via ARG)
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS security-tools

ARG INSTALL_SECURITY_TOOLS=false

RUN if [ "$INSTALL_SECURITY_TOOLS" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        dnsutils \
        netcat-openbsd \
        openssh-client \
        curl \
        wget \
        whois \
        nikto \
        dirb \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# Stage 3: Runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL maintainer="kryon-security"
LABEL description="KRYON - Autonomous Cybersecurity Intelligence Platform"

# Install tini for proper signal handling and minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Copy optional security tools from stage 2
ARG INSTALL_SECURITY_TOOLS=false
COPY --from=security-tools /usr/bin/nmap /usr/bin/nmap* 2>/dev/null || true
COPY --from=security-tools /usr/bin/dig /usr/bin/dig* 2>/dev/null || true

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN groupadd -r kryon && useradd -r -g kryon -m -s /bin/bash kryon

# Create required directories
RUN mkdir -p /workspace /logs /home/kryon/.kryon && \
    chown -R kryon:kryon /workspace /logs /home/kryon

# Set environment
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KRYON_DEBUG=0 \
    KRYON_TRACING=false \
    KRYON_TELEMETRY=false

# Copy application source
COPY --chown=kryon:kryon src/ /opt/venv/lib/python3.11/site-packages/

WORKDIR /workspace

USER kryon

# Health check - KRYON is a CLI, not HTTP, so we use exec-based checks
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import kryon; print('OK')" || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["kryon"]
