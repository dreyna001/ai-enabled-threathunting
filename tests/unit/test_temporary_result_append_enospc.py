from __future__ import annotations

from pathlib import Path

import pytest

from threat_hunting.services.temporary_results import TemporaryResultError, TemporaryResultStore


def test_append_translates_write_enospc_and_removes_partial_temp_file(tmp_path: Path) -> None:
    store = TemporaryResultStore(tmp_path / "temporary")
    writer = store.open_writer("owner-1", "hunt-1", "query-1")
    stream = writer._stream

    class FailOnSecondWrite:
        def __init__(self) -> None:
            self.writes = 0

        def write(self, value: str) -> int:
            self.writes += 1
            if self.writes == 2:
                raise OSError("no space left on device")
            return stream.write(value)

        def close(self) -> None:
            stream.close()

    writer._stream = FailOnSecondWrite()  # type: ignore[assignment]

    with pytest.raises(TemporaryResultError, match="persist"):
        writer.append({"host": "synthetic"})

    assert writer._aborted is True
    assert not list((tmp_path / "temporary").rglob("*.tmp"))
