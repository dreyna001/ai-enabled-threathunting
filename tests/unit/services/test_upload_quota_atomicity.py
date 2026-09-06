from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import create_engine, select

from threat_hunting.services.uploads import (
    UploadError,
    UploadLimits,
    UploadService,
    metadata,
    upload_quotas,
)


class ConcurrentUploadService(UploadService):
    def __init__(self, *args, barrier: threading.Barrier, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.barrier = barrier

    def _reserve_quota(self, connection, owner_id: str, hunt_id: str, byte_size: int) -> None:
        self.barrier.wait(timeout=5)
        super()._reserve_quota(connection, owner_id, hunt_id, byte_size)


def test_concurrent_uploads_cannot_both_consume_last_quota_slot(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'uploads.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    metadata.create_all(engine)
    service = ConcurrentUploadService(
        engine,
        tmp_path / "storage",
        limits=UploadLimits(per_file_bytes=100, file_count=1, total_bytes=100),
        barrier=threading.Barrier(2),
    )

    def upload(name: str):
        try:
            return service.save("owner", "hunt", name, b"bounded content")
        except UploadError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(upload, ("one.txt", "two.txt")))

    successes = [item for item in outcomes if isinstance(item, dict)]
    failures = [item for item in outcomes if isinstance(item, UploadError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert str(failures[0]) == "upload quota exceeded"
    assert len(service.list("owner", "hunt")) == 1
    assert len(list((tmp_path / "storage").rglob("*.bin"))) == 1
    with engine.connect() as connection:
        quota = connection.execute(select(upload_quotas)).mappings().one()
    assert quota["file_count"] == 1
    assert quota["total_bytes"] == len(b"bounded content")


def test_total_byte_quota_is_enforced_by_atomic_counter(tmp_path: Path) -> None:
    engine = create_engine("sqlite+pysqlite://")
    metadata.create_all(engine)
    service = UploadService(
        engine,
        tmp_path,
        limits=UploadLimits(per_file_bytes=10, file_count=2, total_bytes=10),
    )

    service.save("owner", "hunt", "one.txt", b"123456")

    try:
        service.save("owner", "hunt", "two.txt", b"12345")
    except UploadError as exc:
        assert str(exc) == "upload quota exceeded"
    else:
        raise AssertionError("total-byte quota was not enforced")
    assert len(service.list("owner", "hunt")) == 1
