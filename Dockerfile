# syntax=docker/dockerfile:1
# Policy Studio: React frontend + FastAPI backend (policy_studio) in one Cloud Run image.
# Build context = the repo root (deploy.sh: gcloud builds submit .).
#   docker build -t policy-studio .
# Runtime: Application Default Credentials (the Cloud Run service account); generate mode by default.
# Optional env: STUDIO_PROJECT / STUDIO_REGION (defaults shown in the Context step).

# ---------- 1. frontend ----------
FROM node:22-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

# ---------- 2. backend ----------
# Dependencies are installed exactly as locked in backend/uv.lock (uv sync --frozen: fails if the lock is out of date
# with pyproject.toml). The package itself isn't installed: it runs from /app/backend (PYTHONPATH), so no build
# backend is fetched at build time.
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.13 /uv /usr/local/bin/uv
ENV PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock ./backend/
RUN uv sync --frozen --no-dev --no-install-project --project backend
COPY backend/policy_studio ./backend/policy_studio
COPY --from=frontend /src/dist ./static
# STUDIO_CONTAINER=1: generate mode by default (the image listens on 0.0.0.0); STUDIO_MODE=apply overrides off Cloud Run
ENV PATH=/app/.venv/bin:$PATH PYTHONPATH=/app/backend STUDIO_FRONTEND_DIST=/app/static STUDIO_CONTAINER=1
# Run as an unprivileged user: /app (code, .venv, static) stays root-owned and read-only to it.
RUN useradd --system --create-home app && chmod -R a+rX /app
USER app
EXPOSE 8080
CMD ["sh", "-c", "uvicorn policy_studio.app:app --host 0.0.0.0 --port ${PORT:-8080}"]
