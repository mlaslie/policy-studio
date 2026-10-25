"""Standalone Policy Studio server: the API router plus the built UI (frontend/dist) with SPA fallback.

  uvicorn policy_studio.app:app --app-dir backend --port 8090
Env: STUDIO_PROJECT / STUDIO_REGION (served by /api/studio/defaults), STUDIO_FRONTEND_DIST (UI build dir; default
frontend/dist in the repo), STUDIO_CORS (extra origins, comma-separated), STUDIO_IAP_AUDIENCE (Cloud Run: iap.py).
On Cloud Run (K_SERVICE set) every /api/* request except health must carry a valid IAP signed header (iap.py).
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import __version__
from .api import router
from .iap import IapMiddleware

DEFAULT_STATIC = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def static_dir() -> Path:
    return Path(os.environ.get("STUDIO_FRONTEND_DIST") or os.environ.get("STUDIO_STATIC") or DEFAULT_STATIC)


def create_app() -> FastAPI:
    app = FastAPI(title="Policy Studio", version=__version__)
    # local UIs: the Vite dev server (5174), vite preview (4173), the app itself (8090)
    origins = [f"http://{h}:{p}" for p in (5174, 4173, 8090) for h in ("localhost", "127.0.0.1")]
    origins += [o.strip() for o in os.environ.get("STUDIO_CORS", "").split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"])
    app.add_middleware(IapMiddleware)          # outermost; a no-op unless K_SERVICE is set
    app.include_router(router)

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "not found")
        root = static_dir()
        index = root / "index.html"
        if not index.is_file():
            return JSONResponse({"detail": "UI not built: run `cd frontend && npm install && npm run build`, "
                                           "or use the Vite dev server on :5174.", "api": "/api/studio/health"},
                                status_code=404)
        target = (root / path).resolve()
        if path and target.is_file() and root.resolve() in target.parents:
            return FileResponse(target)
        return FileResponse(index)

    return app


app = create_app()
