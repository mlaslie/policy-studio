# syntax=docker/dockerfile:1
# Policy Studio: React frontend + FastAPI backend (policy_studio) in one Cloud Run image.
# Build context = studio/ (self-contained: nothing from the rest of the repo is needed).
#   docker build -t policy-studio studio/
# Runtime: Application Default Credentials (the Cloud Run service account). P1/P2 are read-only.
# Optional env: STUDIO_PROJECT / STUDIO_REGION (defaults shown in the Context step).

# ---------- 1. frontend ----------
FROM node:22-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

# ---------- 2. backend ----------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/pyproject.toml ./backend/pyproject.toml
COPY backend/policy_studio ./backend/policy_studio
RUN pip install ./backend
COPY --from=frontend /src/dist ./static
ENV STUDIO_FRONTEND_DIST=/app/static
EXPOSE 8080
CMD ["sh", "-c", "uvicorn policy_studio.app:app --host 0.0.0.0 --port ${PORT:-8080}"]
