"""
CyberAI FastAPI server.

REST + SSE interface for listing scan sessions and serving reports.
Sessions are read from disk (config.output_dir / session_<id>.json),
the same artifacts the CLI `replay` command consumes.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from cyberai.core.config import CyberAIConfig
from cyberai.web.routes.report import router as report_router
from cyberai.web.routes.session import router as session_router
from cyberai.web.routes.bench import router as bench_router
from cyberai.web.routes.lab import router as lab_router

logger = logging.getLogger("cyberai.web")

_TEMPLATES = Path(__file__).parent / "templates"


def create_app(config: CyberAIConfig | None = None) -> FastAPI:
    """Build the FastAPI app. Pass a config to override the sessions dir."""
    app = FastAPI(title="CyberAI API", version="0.5.0")
    app.state.config = config or CyberAIConfig()

    app.include_router(session_router, prefix="/api")
    app.include_router(report_router, prefix="/api")
    app.include_router(bench_router, prefix="/api")
    app.include_router(lab_router, prefix="/api")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": "CyberAI API"}

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        index = _TEMPLATES / "dashboard.html"
        if not index.exists():
            return "<h1>CyberAI</h1><p>dashboard.html missing</p>"
        return index.read_text()

    logger.info("CyberAI FastAPI app created")
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("cyberai.web.app:app", host="127.0.0.1", port=8888, reload=False)
