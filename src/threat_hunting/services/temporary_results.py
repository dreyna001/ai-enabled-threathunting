"""Owner/hunt-scoped temporary storage for bounded Splunk query result rows."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")


class TemporaryResultError(RuntimeError):
    """Raised when a temporary result file cannot be read, written, or verified."""


def _safe_segment(value: str) -> str:
    cleaned = _SAFE_SEGMENT.sub("_", value.strip())
    if not cleaned:
        raise TemporaryResultError("storage segment must not be empty")
    return cleaned


def _row_size(row: Mapping[str, Any]) -> int:
    try:
        encoded = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        encoded = json.dumps({"value": str(row)}, separators=(",", ":"))
    return len(encoded.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class TemporaryResultBatch:
    """Loaded bounded rows from one persisted temporary result file."""

    location: str
    rows: tuple[Mapping[str, Any], ...]
    row_count: int
    byte_count: int


class TemporaryResultWriter:
    """Stream rows to a temporary file and atomically publish on commit."""

    def __init__(self, store: TemporaryResultStore, relative: str) -> None:
        self._store = store
        self.relative = relative
        target = store._path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".query-result-", suffix=".tmp", dir=target.parent)
        self._temporary = Path(temporary)
        self._stream = os.fdopen(fd, "w", encoding="utf-8")
        self._rows = 0
        self._bytes = 0
        self._committed = False
        self._aborted = False

    @property
    def row_count(self) -> int:
        return self._rows

    @property
    def byte_count(self) -> int:
        return self._bytes

    def append(self, row: Mapping[str, Any]) -> None:
        if self._committed or self._aborted:
            raise TemporaryResultError("result writer is closed")
        payload = dict(row)
        size = _row_size(payload)
        try:
            self._stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))
            self._stream.write("\n")
        except OSError as exc:
            self.abort()
            raise TemporaryResultError("could not persist query result batch") from exc
        self._rows += 1
        self._bytes += size

    def commit(self) -> str:
        if self._committed or self._aborted:
            raise TemporaryResultError("result writer is closed")
        try:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
            target = self._store._path(self.relative)
            os.replace(self._temporary, target)
            self._committed = True
            return self.relative
        except OSError as exc:
            self.abort()
            raise TemporaryResultError("could not persist query result batch") from exc

    def abort(self) -> None:
        if self._committed:
            return
        self._aborted = True
        try:
            self._stream.close()
        except OSError:
            pass
        try:
            self._temporary.unlink(missing_ok=True)
        except OSError:
            pass


class TemporaryResultStore:
    """Write, read, and delete hunt-local temporary Splunk result batches."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def relative_path(self, owner_user_id: str, hunt_id: str, query_id: str) -> str:
        return "/".join(
            (
                _safe_segment(owner_user_id),
                _safe_segment(hunt_id),
                "queries",
                f"{_safe_segment(query_id)}.jsonl",
            )
        )

    def _path(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        if path != self.root and self.root not in path.parents:
            raise TemporaryResultError("result path escapes storage root")
        return path

    def open_writer(self, owner_user_id: str, hunt_id: str, query_id: str) -> TemporaryResultWriter:
        return TemporaryResultWriter(self, self.relative_path(owner_user_id, hunt_id, query_id))

    def exists(self, relative: str) -> bool:
        return self._path(relative).is_file()

    def delete(self, relative: str) -> None:
        try:
            self._path(relative).unlink(missing_ok=True)
        except OSError as exc:
            raise TemporaryResultError("could not delete temporary result batch") from exc

    def load_rows(
        self,
        relative: str,
        *,
        max_rows: int | None = None,
        max_bytes: int | None = None,
    ) -> TemporaryResultBatch:
        path = self._path(relative)
        if not path.is_file():
            raise TemporaryResultError("temporary result batch is missing")
        rows: list[Mapping[str, Any]] = []
        byte_count = 0
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError as exc:
                        raise TemporaryResultError(
                            f"temporary result batch is corrupt at line {line_number}"
                        ) from exc
                    if not isinstance(parsed, Mapping):
                        raise TemporaryResultError(
                            f"temporary result batch row {line_number} is not an object"
                        )
                    row = dict(parsed)
                    size = _row_size(row)
                    if max_rows is not None and len(rows) + 1 > max_rows:
                        raise TemporaryResultError("temporary result batch exceeds row limit")
                    if max_bytes is not None and byte_count + size > max_bytes:
                        raise TemporaryResultError("temporary result batch exceeds byte limit")
                    rows.append(row)
                    byte_count += size
        except OSError as exc:
            raise TemporaryResultError("temporary result batch is unreadable") from exc
        return TemporaryResultBatch(relative, tuple(rows), len(rows), byte_count)

    def iter_rows(self, relative: str) -> Iterator[Mapping[str, Any]]:
        return iter(self.load_rows(relative).rows)


__all__ = [
    "TemporaryResultBatch",
    "TemporaryResultError",
    "TemporaryResultStore",
    "TemporaryResultWriter",
]
