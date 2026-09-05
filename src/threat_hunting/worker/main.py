"""Background worker heartbeat loop for the application foundation."""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError

from threat_hunting.config import RuntimeSettings, load_database_url
from threat_hunting.db import Database
from threat_hunting.health import worker_id_from_environment
from threat_hunting.services.jobs import JobConflict, JobLease, JobService
from threat_hunting.services.runtime import build_production_service, build_worker_handler

LOGGER = logging.getLogger(__name__)
HEARTBEAT_INTERVAL_SECONDS = 15
JOB_POLL_INTERVAL_SECONDS = 0.5


def process_one(
    job_service: JobService,
    worker_id: str,
    *,
    handler: Callable[[JobLease], None] | None = None,
    now: datetime | None = None,
) -> bool:
    """Claim and process one job while renewing its fenced lease."""
    job_service.recover_expired(now=now)
    lease = job_service.claim(worker_id, now=now)
    if lease is None:
        return False
    outcome: dict[str, BaseException | None] = {"error": None}

    def invoke() -> None:
        try:
            if handler is None:
                raise RuntimeError("production execution adapter is not configured")
            handler(lease)
        except BaseException as exc:  # propagate into the controlled completion path
            outcome["error"] = exc

    thread = threading.Thread(target=invoke, name=f"hunt-job-{lease.job_id}", daemon=True)
    thread.start()
    fenced = False
    interval = max(0.1, job_service.lease_seconds / 3)
    while thread.is_alive():
        thread.join(timeout=interval)
        if not thread.is_alive():
            break
        try:
            lease = job_service.heartbeat(lease)
        except JobConflict:
            fenced = True
    thread.join()
    if fenced:
        return True
    error = outcome["error"]
    try:
        if error is not None:
            job_service.complete(lease, status="failed", error=str(error)[:500], now=now)
        else:
            job_service.complete(lease, status="completed", now=now)
    except JobConflict:
        # Cancellation or a replacement worker won the race.
        pass
    return True


def run() -> None:
    """Publish worker health until the process receives a termination signal."""

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    settings = RuntimeSettings.load()
    database = Database.connect(
        load_database_url(),
        connect_timeout_seconds=settings.database.connect_timeout_seconds,
    )
    worker_id = worker_id_from_environment()
    try:
        database.require_current_migration()
        LOGGER.info("worker started", extra={"worker_id": worker_id})
        service = build_production_service(database.engine, settings)
        handler = build_worker_handler(service)
        jobs = service.jobs
        while not stop.is_set():
            database.publish_worker_heartbeat(worker_id)
            try:
                process_one(jobs, worker_id, handler=handler)
            except SQLAlchemyError:
                # A worker remains healthy while a deployment is rolling out
                # the queue migration; readiness still reports migration state.
                LOGGER.exception("durable job poll failed", extra={"worker_id": worker_id})
            stop.wait(JOB_POLL_INTERVAL_SECONDS)
    finally:
        database.dispose()
        LOGGER.info("worker stopped", extra={"worker_id": worker_id})


if __name__ == "__main__":
    run()

