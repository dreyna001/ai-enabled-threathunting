"""Bounded, owner-scoped upload validation, extraction, and storage."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from sqlalchemy import JSON, Column, DateTime, Integer, MetaData, String, Table, Text, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

metadata = MetaData()
uploads = Table(
    "uploads", metadata,
    Column("upload_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False, index=True),
    Column("hunt_id", String(36), nullable=False, index=True),
    Column("original_filename", String(500), nullable=False),
    Column("detected_type", String(100), nullable=False),
    Column("byte_size", Integer, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("uploader_id", String(36), nullable=False),
    Column("uploaded_at_utc", DateTime(timezone=True), nullable=False),
    Column("parser_version", String(50), nullable=False),
    Column("extraction_status", String(32), nullable=False),
    Column("extraction_error", String(2000), nullable=True),
    Column("storage_path", String(1000), nullable=False),
    Column("extracted_text", Text, nullable=False, default=""),
    Column("metadata", JSON, nullable=True),
)
upload_quotas = Table(
    "upload_quotas", metadata,
    Column("owner_id", String(36), primary_key=True),
    Column("hunt_id", String(36), primary_key=True),
    Column("file_count", Integer, nullable=False, default=0),
    Column("total_bytes", Integer, nullable=False, default=0),
)

SUPPORTED_TYPES = {".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".csv": "text/csv", ".tsv": "text/tab-separated-values", ".txt": "text/plain", ".md": "text/markdown", ".json": "application/json", ".yaml": "application/yaml", ".yml": "application/yaml"}

class UploadError(ValueError):
    """A safe, user-facing upload rejection."""

@dataclass(frozen=True, slots=True)
class UploadLimits:
    per_file_bytes: int = 25 * 1024 * 1024
    file_count: int = 10
    total_bytes: int = 100 * 1024 * 1024
    extracted_text_characters: int = 2_000_000
    max_zip_entries: int = 2000
    max_uncompressed_bytes: int = 100 * 1024 * 1024

class UploadService:
    """Persist uploads under generated IDs after complete bounded validation."""

    def __init__(self, engine: Engine, root: Path, *, limits: UploadLimits | None = None) -> None:
        self.engine = engine
        self.root = root.resolve()
        self.limits = limits or UploadLimits()
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _quota_insert(connection: Any):
        if connection.dialect.name == "postgresql":
            return postgresql_insert(upload_quotas)
        if connection.dialect.name == "sqlite":
            return sqlite_insert(upload_quotas)
        raise RuntimeError("upload quotas require PostgreSQL or SQLite")

    def _reserve_quota(self, connection: Any, owner_id: str, hunt_id: str, byte_size: int) -> None:
        connection.execute(
            self._quota_insert(connection)
            .values(
                owner_id=owner_id,
                hunt_id=hunt_id,
                file_count=0,
                total_bytes=0,
            )
            .on_conflict_do_nothing(index_elements=[upload_quotas.c.owner_id, upload_quotas.c.hunt_id])
        )
        reserved = connection.execute(
            update(upload_quotas)
            .where(
                upload_quotas.c.owner_id == owner_id,
                upload_quotas.c.hunt_id == hunt_id,
                upload_quotas.c.file_count < self.limits.file_count,
                upload_quotas.c.total_bytes + byte_size <= self.limits.total_bytes,
            )
            .values(
                file_count=upload_quotas.c.file_count + 1,
                total_bytes=upload_quotas.c.total_bytes + byte_size,
            )
        )
        if reserved.rowcount != 1:
            raise UploadError("upload quota exceeded")

    def save(self, owner_id: str, hunt_id: str, filename: str, content: bytes, *, content_type: str | None = None) -> dict[str, Any]:
        suffix = Path(filename).suffix.casefold()
        self._validate_filename(filename, suffix)
        if suffix not in SUPPORTED_TYPES:
            raise UploadError("unsupported upload type")
        if len(content) > self.limits.per_file_bytes:
            raise UploadError("upload exceeds the per-file size limit")
        detected, text, metadata = self._extract(suffix, content, content_type)
        if len(text) > self.limits.extracted_text_characters:
            raise UploadError("extracted text exceeds the configured limit")
        upload_id, now = str(uuid4()), datetime.now(timezone.utc)
        relative = f"uploads/{owner_id}/{upload_id}.bin"
        target = (self.root / relative).resolve()
        if self.root not in target.parents:
            raise UploadError("unsafe storage path")
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            values = {"upload_id": upload_id, "owner_id": owner_id, "hunt_id": hunt_id, "original_filename": filename, "detected_type": detected, "byte_size": len(content), "sha256": hashlib.sha256(content).hexdigest(), "uploader_id": owner_id, "uploaded_at_utc": now, "parser_version": "builtin-1", "extraction_status": "complete", "extraction_error": None, "storage_path": relative, "extracted_text": text, "metadata": metadata}
            with self.engine.begin() as connection:
                self._reserve_quota(connection, owner_id, hunt_id, len(content))
                connection.execute(uploads.insert().values(**values))
        except Exception:
            target.unlink(missing_ok=True)
            raise
        return {key: value for key, value in values.items() if key not in {"extracted_text"}}

    def list(self, owner_id: str, hunt_id: str) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(select(uploads).where(uploads.c.owner_id == owner_id, uploads.c.hunt_id == hunt_id).order_by(uploads.c.uploaded_at_utc)).mappings().all()
        return [{key: value for key, value in row.items() if key != "extracted_text"} for row in rows]

    def path_for(self, owner_id: str, hunt_id: str, upload_id: str) -> tuple[Path, str]:
        with self.engine.connect() as connection:
            row = connection.execute(select(uploads).where(uploads.c.owner_id == owner_id, uploads.c.hunt_id == hunt_id, uploads.c.upload_id == upload_id)).mappings().first()
        if row is None:
            raise UploadError("upload not found")
        target = (self.root / str(row["storage_path"])).resolve()
        if self.root not in target.parents or not target.is_file():
            raise UploadError("upload content is unavailable")
        return target, str(row["original_filename"])

    @staticmethod
    def _validate_filename(filename: str, suffix: str) -> None:
        if not filename or len(filename) > 500 or any(char in filename for char in ("/", "\\", "\x00")) or any(ord(char) < 32 for char in filename):
            raise UploadError("filename is invalid")
        if suffix != Path(filename).suffix.casefold():
            raise UploadError("filename extension is invalid")

    def _extract(self, suffix: str, content: bytes, declared_type: str | None) -> tuple[str, str, dict[str, Any]]:
        expected = SUPPORTED_TYPES[suffix]
        if suffix == ".pdf":
            if not content.startswith(b"%PDF-"):
                raise UploadError("file content does not match its extension")
            # Keep only printable PDF text fragments; image-only PDFs are explicit failures.
            text = " ".join(re.findall(rb"\(([^()]*)\)", content).decode("utf-8", "ignore") if False else [item.decode("utf-8", "ignore") for item in re.findall(rb"\(([^()]*)\)", content)])
            if not text.strip():
                raise UploadError("PDF contains no extractable text")
            return expected, text, {"format": "pdf"}
        if suffix in {".docx", ".xlsx"}:
            if not content.startswith(b"PK"):
                raise UploadError("file content does not match its extension")
            return expected, self._extract_zip_text(content, suffix), {"format": suffix[1:]}
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UploadError("text upload must be valid UTF-8") from exc
        if suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                raise UploadError("JSON is malformed") from exc
        elif suffix in {".yaml", ".yml"}:
            try:
                yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise UploadError("YAML is malformed") from exc
        if declared_type and declared_type not in {expected, "application/octet-stream", "text/plain"} and not declared_type.startswith("text/"):
            raise UploadError("declared content type does not match the extension")
        return expected, text, {"format": suffix[1:]}

    def _extract_zip_text(self, content: bytes, suffix: str) -> str:
        try:
            archive = zipfile.ZipFile(io.BytesIO(content))
        except zipfile.BadZipFile as exc:
            raise UploadError("document archive is malformed") from exc
        if len(archive.infolist()) > self.limits.max_zip_entries:
            raise UploadError("document contains too many archive entries")
        total = 0
        chunks: list[str] = []
        for info in archive.infolist():
            if info.is_dir() or info.filename.startswith(("/", "\\")) or ".." in Path(info.filename).parts:
                raise UploadError("document contains an unsafe archive path")
            if info.filename.lower().endswith(("vbaProject.bin", ".exe", ".dll")):
                raise UploadError("active document content is not supported")
            total += info.file_size
            if total > self.limits.max_uncompressed_bytes or (info.compress_size and info.file_size > info.compress_size * 1000):
                raise UploadError("document decompression limit exceeded")
            if info.filename.endswith(("document.xml", "sharedStrings.xml", "sheet1.xml")):
                chunks.append(archive.read(info).decode("utf-8", "ignore"))
        text = re.sub(r"<[^>]+>", " ", " ".join(chunks))
        if not text.strip():
            raise UploadError("document contains no extractable text")
        return text

__all__ = ["UploadError", "UploadLimits", "UploadService", "SUPPORTED_TYPES", "metadata", "uploads"]
