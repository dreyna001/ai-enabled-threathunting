"""Background worker heartbeat loop for the application foundation."""

from __future__ import annotations

import logging
import signal
import threading

from threat_hunting.config import RuntimeSettings, load_database_url
from threat_hunting.db import Database
from threat_hunting.health import worker_id_from_environment

LOGGER = logging.getLogger(__name__)
HEARTBEAT_INTERVAL_SECONDS = 15


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
        while not stop.is_set():
            database.publish_worker_heartbeat(worker_id)
            stop.wait(HEARTBEAT_INTERVAL_SECONDS)
    finally:
        database.dispose()
        LOGGER.info("worker stopped", extra={"worker_id": worker_id})


if __name__ == "__main__":
    run()

