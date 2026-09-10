"""FastAPI application entrypoint."""

from __future__ import annotations

import os
import logging
import time
from uuid import uuid4
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response, status
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from sqlalchemy import Engine, create_engine

from threat_hunting import __version__
from threat_hunting.config import CONFIG_ENV, ConfigurationError, RuntimeSettings
from threat_hunting.api.workflow import configure_workflow_service, router as workflow_router
from threat_hunting.health import HealthResponse, check_readiness
from threat_hunting.services.runtime import build_production_service
from threat_hunting.services.workflow import WorkflowService


def _cookie_secure_override() -> bool | None:
    """Read the optional development-only cookie transport override."""

    value = os.getenv("THREAT_HUNTING_COOKIE_SECURE", "").casefold()
    if not value:
        return None
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    raise ConfigurationError("THREAT_HUNTING_COOKIE_SECURE must be true or false")


def create_app(
    engine: Engine | None = None, *, local_demo: bool | None = None, demo_password: str | None = None, cookie_secure: bool | None = None,
) -> FastAPI:
    """Create the HTTP application without performing migrations or external calls."""

    owns_engine = engine is None
    service: WorkflowService | None = None

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        try:
            yield
        finally:
            try:
                if service is not None:
                    await run_in_threadpool(service.close)
            finally:
                if owns_engine and engine is not None:
                    await run_in_threadpool(engine.dispose)

    application = FastAPI(title="Threat Hunting MVP", version=__version__, lifespan=lifespan)

    @application.middleware("http")
    async def request_diagnostics(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = str(uuid4())
        request.state.request_id = request_id
        began = time.monotonic()
        code = 500
        try:
            response = await call_next(request)
            code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            route = getattr(request.scope.get("route"), "path", "unmatched")
            logging.getLogger(__name__).info(
                "http request request_id=%s method=%s route=%s status=%d duration_ms=%.1f",
                request_id, request.method, route, code, (time.monotonic() - began) * 1000,
            )

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
    if engine is None and not configured_url:
        secret_path = os.getenv("THREAT_HUNTING_DATABASE_URL_FILE")
        if secret_path:
            try:
                configured_url = Path(secret_path).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                configured_url = None
    if engine is None and configured_url:
        engine = create_engine(configured_url, pool_pre_ping=True)
    if local_demo is None:
        local_demo = os.getenv("THREAT_HUNTING_LOCAL_DEMO", "").casefold() in {"1", "true", "yes"}
    if demo_password is None:
        demo_password = os.getenv("THREAT_HUNTING_DEMO_PASSWORD")
    runtime_settings: RuntimeSettings | None = None
    if engine is not None:
        if not local_demo and os.getenv(CONFIG_ENV):
            # Production composition is explicit and fail-closed.  A missing
            # or invalid provider secret must prevent a misleading demo path.
            runtime_settings = RuntimeSettings.load()
            service = build_production_service(engine, runtime_settings)
        else:
            service = WorkflowService(engine, local_demo=local_demo, demo_password=demo_password)
        if cookie_secure is None:
            cookie_secure = _cookie_secure_override()
        if runtime_settings is not None and runtime_settings.environment == "production" and cookie_secure is False:
            raise ConfigurationError("production session cookies require HTTPS")
        if cookie_secure is not None:
            service.cookie_secure = cookie_secure
        service.initialize_demo()
        configure_workflow_service(application, service)
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
