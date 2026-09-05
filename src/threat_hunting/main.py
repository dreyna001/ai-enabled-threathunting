"""FastAPI application entrypoint."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Response, status
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine, create_engine

from threat_hunting import __version__
from threat_hunting.api.workflow import configure_workflow_service, router as workflow_router
from threat_hunting.health import HealthResponse, check_readiness
from threat_hunting.services.workflow import WorkflowService


def create_app(
    engine: Engine | None = None, *, local_demo: bool | None = None, demo_password: str | None = None,
) -> FastAPI:
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

    configured_url = os.getenv("THREAT_HUNTING_DATABASE_URL")
    if engine is None and configured_url:
        engine = create_engine(configured_url, pool_pre_ping=True)
    if local_demo is None:
        local_demo = os.getenv("THREAT_HUNTING_LOCAL_DEMO", "").casefold() in {"1", "true", "yes"}
    if demo_password is None:
        demo_password = os.getenv("THREAT_HUNTING_DEMO_PASSWORD")
    if engine is not None:
        service = WorkflowService(engine, local_demo=local_demo, demo_password=demo_password)
        service.initialize_demo()
        configure_workflow_service(service)
        application.include_router(workflow_router)

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
