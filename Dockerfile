# syntax=docker/dockerfile:1.7
#
# QueryForge MCP Server - Docker Image
#
# This Dockerfile builds an image optimized for Amazon ECS and other container orchestration platforms.
# The server runs in SSE (Server-Sent Events) mode by default, exposing an HTTP endpoint on port 8080.
#
# Key features:
# - Runs as non-root user (UID 10001) for security
# - HTTP server on port 8080 with /sse endpoint
# - Health checks to ensure server responsiveness
# - Pre-loaded schema caches for instant startup
#
# ECS Deployment:
# 1. Build: docker build -t queryforge .
# 2. Tag: docker tag queryforge:latest <ecr-repo>:latest
# 3. Push: docker push <ecr-repo>:latest
# 4. In ECS Task Definition:
#    - Container port: 8080
#    - Health check: HTTP GET /sse on port 8080
#    - Environment variables (optional overrides):
#      * MCP_TRANSPORT (default: sse)
#      * MCP_HOST (default: 0.0.0.0)
#      * MCP_PORT (default: 8080)
#
FROM python:3.12-slim

# Core Python and app configuration
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_USER=app \
    APP_UID=10001 \
    APP_GID=10001 \
    APP_HOME=/app \
    CACHE_DIR=/app/.cache

# MCP Server configuration for ECS/Docker deployment
# Default to SSE (Server-Sent Events) mode for HTTP-based communication
# This ensures the container stays running in ECS environments
ENV MCP_TRANSPORT=sse \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git socat \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g ${APP_GID} ${APP_USER} \
 && useradd -m -u ${APP_UID} -g ${APP_GID} -s /usr/sbin/nologin ${APP_USER} \
 && mkdir -p ${APP_HOME} ${CACHE_DIR}

WORKDIR ${APP_HOME}

COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    python - <<'PY'
import fastmcp, pydantic
print("Deps OK. FastMCP:", getattr(fastmcp, "__version__", "unknown"))
PY

COPY server*.py entrypoint.sh ./
COPY cbc ./cbc
COPY cortex ./cortex
COPY kql ./kql
COPY s1 ./s1
COPY shared ./shared

# Copy pre-generated embeddings cache for instant startup
COPY .cache ${CACHE_DIR}

RUN chmod +x entrypoint.sh && \
    chown -R ${APP_UID}:${APP_GID} ${APP_HOME}

USER ${APP_UID}:${APP_GID}

# Healthcheck verifies the HTTP server is responsive
# For ECS deployments, ensure your task definition health check targets HTTP:8080/sse
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "-m", "server"]
