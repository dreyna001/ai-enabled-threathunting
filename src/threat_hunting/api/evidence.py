"""Owner-scoped selected-evidence list and download endpoints."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from sqlalchemy import text


router = APIRouter(tags=["evidence"])
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class EvidenceAccessError(RuntimeError):
    """An evidence lookup failed or crossed an ownership boundary."""


class EvidenceAccessService(Protocol):
    def list(self, *, hunt_id: str, owner_id: str) -> Sequence[Mapping[str, Any]]: ...
    def download(self, *, hunt_id: str, evidence_id: str, owner_id: str) -> bytes: ...


def configure_evidence_service(application: FastAPI, service: EvidenceAccessService) -> None:
    """Bind the service to one application instance."""
    application.state.evidence_service = service


def get_evidence_service(request: Request) -> EvidenceAccessService:
    service = getattr(request.app.state, "evidence_service", None)
    if service is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="evidence service is not configured")
    return service


def current_user_id(request: Request) -> str:
    value = getattr(request.state, "user_id", None)
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return value


class SqlEvidenceAccessService:
    """Read-only selected-evidence adapter; every query includes owner scope."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    def list(self, *, hunt_id: str, owner_id: str) -> Sequence[Mapping[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(text("SELECT evidence_id, query_id, evidence_kind, index, sourcetype, event_time_utc, collected_at_utc, source_event_ref, selected_result, sha256, truncation FROM evidence_records WHERE hunt_id=:hunt_id AND owner_id=:owner_id ORDER BY collected_at_utc, evidence_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().all()
        return [dict(row) for row in rows]

    def download(self, *, hunt_id: str, evidence_id: str, owner_id: str) -> bytes:
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT evidence_id, hunt_id, query_id, evidence_kind, index, sourcetype, event_time_utc, collected_at_utc, source_event_ref, selected_result, sha256, truncation FROM evidence_records WHERE evidence_id=:evidence_id AND hunt_id=:hunt_id AND owner_id=:owner_id"), {"evidence_id": evidence_id, "hunt_id": hunt_id, "owner_id": owner_id}).mappings().first()
        if row is None:
            raise EvidenceAccessError("evidence not found")
        return json.dumps(dict(row), ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")


@router.get("/hunts/{hunt_id}/evidence")
def list_evidence(hunt_id: str, user_id: str = Depends(current_user_id), service: EvidenceAccessService = Depends(get_evidence_service)) -> Sequence[Mapping[str, Any]]:
    try:
        return service.list(hunt_id=hunt_id, owner_id=user_id)
    except EvidenceAccessError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found") from exc


@router.get("/hunts/{hunt_id}/evidence/{evidence_id}/download")
def download_evidence(hunt_id: str, evidence_id: str, user_id: str = Depends(current_user_id), service: EvidenceAccessService = Depends(get_evidence_service)) -> Response:
    try:
        content = service.download(hunt_id=hunt_id, evidence_id=evidence_id, owner_id=user_id)
    except EvidenceAccessError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found") from exc
    safe_id = _SAFE.sub("-", evidence_id).strip(".-")[:120] or "evidence"
    return Response(content=content, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{safe_id}.json"'})


__all__ = ["EvidenceAccessError", "EvidenceAccessService", "SqlEvidenceAccessService", "configure_evidence_service", "get_evidence_service", "router"]
