# Joern CPGQL server — separate service for F7 data-flow analysis.
# Built separately so heavy Scala/sbt footprint (~1.6 GB) does not bloat the
# kryon agent image. The kryon container talks to it over the mgmt network
# via cpgqls-client (WebSocket).

FROM eclipse-temurin:21-jre-jammy

ARG JOERN_VERSION=v4.0.520
ENV JOERN_HOME=/opt/joern \
    PATH="/opt/joern/joern-cli:${PATH}" \
    JAVA_OPTS="-Xmx6g"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Joern. --without-plugins keeps the image ~400 MB smaller.
RUN curl -fsSL "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-install.sh" \
      -o /tmp/joern-install.sh \
    && chmod +x /tmp/joern-install.sh \
    && /tmp/joern-install.sh --install-dir=${JOERN_HOME} --version=${JOERN_VERSION} \
    && rm /tmp/joern-install.sh \
    && rm -f ${JOERN_HOME}/joern-cli.zip 2>/dev/null || true

# Shared scratch for CPGs + source trees mounted from kryon.
RUN mkdir -p /work/cpgs /work/src \
    && useradd -m -u 1000 -s /bin/bash joern \
    && chown -R joern:joern /work ${JOERN_HOME}

USER joern
WORKDIR /work

EXPOSE 8080

# Server mode: listen on 0.0.0.0:8080 so the kryon container can reach it
# over the mgmt network. No auth because the network is internal-only.
CMD ["joern", "--server", "--server-host", "0.0.0.0", "--server-port", "8080"]
