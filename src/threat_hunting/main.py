"""FastAPI application entrypoint."""

from __future__ import annotations

from pathlib import Path

import uvicorn
from fastapi import FastAPI, Response, status
from fastapi.staticfiles import StaticFiles

from threat_hunting import __version__
from threat_hunting.health import HealthResponse, check_readiness


def create_app() -> FastAPI:
    """Create the HTTP application without performing migrations or external calls."""

    application = FastAPI(title="Threat Hunting MVP", version=__version__)

    @application.get("/health/live", response_model=HealthResponse, tags=["health"])
    def liveness() -> HealthResponse:
        return HealthResponse(status="live")

    @application.get("/health/ready", response_model=HealthResponse, tags=["health"])
    def readiness(response: Response) -> HealthResponse:
        result = check_readiness()
        if result.status != "ready":
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return result

    frontend_dist = Path("frontend/dist")
    if frontend_dist.is_dir():
        application.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")

    return application


app = create_app()


def run() -> None:
    """Run the API using the stable container/runtime entrypoint."""

    uvicorn.run("threat_hunting.main:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    run()
