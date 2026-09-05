"""Owner-scoped report workspace and finalized PDF endpoints."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from threat_hunting.services.reports import (
    ReportConflict,
    ReportForbidden,
    ReportLocked,
    ReportNotFound,
    ReportRenderError,
    ReportService,
    ReportValidationError,
)


router = APIRouter(tags=["reports"])
_service: ReportService | None = None


class ReportDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt = Field(ge=1)
    content: dict[str, Any]


class FinalizeReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: StrictInt | None = Field(default=None, ge=1)


def configure_report_service(service: ReportService) -> None:
    """Set the application service during composition/startup."""

    global _service
    _service = service


def get_report_service() -> ReportService:
    if _service is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="report service is not configured")
    return _service


def current_user_id(request: Request) -> str:
    """Read the authenticated principal set by the application auth middleware."""

    value = getattr(request.state, "user_id", None)
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return value


def _raise(exc: Exception) -> None:
    if isinstance(exc, ReportNotFound):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found") from exc
    if isinstance(exc, ReportForbidden):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found") from exc
    if isinstance(exc, ReportConflict):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, ReportLocked):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, ReportValidationError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if isinstance(exc, ReportRenderError):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="PDF rendering is temporarily unavailable") from exc
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="report operation failed") from exc


@router.get("/hunts/{hunt_id}/report")
def report_preview(hunt_id: str, user_id: str = Depends(current_user_id), service: ReportService = Depends(get_report_service)) -> Mapping[str, Any]:
    try:
        preview = service.preview(hunt_id=hunt_id, owner_id=user_id)
    except Exception as exc:
        _raise(exc)
    return {"hunt_id": preview.hunt_id, "report_id": preview.report_id, "version": preview.version, "state": preview.state, "content": preview.content, "html": preview.html}


@router.put("/hunts/{hunt_id}/report")
def save_report_draft(hunt_id: str, request: ReportDraftRequest, user_id: str = Depends(current_user_id), service: ReportService = Depends(get_report_service)) -> Mapping[str, Any]:
    try:
        preview = service.save_draft(hunt_id=hunt_id, owner_id=user_id, content=request.content, expected_version=request.expected_version)
    except Exception as exc:
        _raise(exc)
    return {"hunt_id": preview.hunt_id, "report_id": preview.report_id, "version": preview.version, "state": preview.state, "content": preview.content}


@router.post("/hunts/{hunt_id}/report/finalize")
def finalize_report(hunt_id: str, request: FinalizeReportRequest | None = None, user_id: str = Depends(current_user_id), service: ReportService = Depends(get_report_service)) -> Mapping[str, Any]:
    try:
        expected = request.expected_version if request is not None else service.preview(hunt_id=hunt_id, owner_id=user_id).version
        result = service.finalize(hunt_id=hunt_id, owner_id=user_id, expected_version=expected)
    except Exception as exc:
        _raise(exc)
    return {"hunt_id": result.hunt_id, "report_id": result.report_id, "version": result.version, "state": result.state, "pdf_sha256": result.pdf_sha256, "finalized_at_utc": result.finalized_at_utc.isoformat().replace("+00:00", "Z")}


@router.get("/hunts/{hunt_id}/report/pdf")
def download_report_pdf(hunt_id: str, user_id: str = Depends(current_user_id), service: ReportService = Depends(get_report_service)) -> Response:
    try:
        artifact = service.download_pdf(hunt_id=hunt_id, owner_id=user_id)
    except Exception as exc:
        _raise(exc)
    return Response(content=artifact.content, media_type=artifact.media_type, headers={"Content-Disposition": f'attachment; filename="{artifact.filename}"'})


__all__ = ["FinalizeReportRequest", "ReportDraftRequest", "configure_report_service", "current_user_id", "get_report_service", "router"]
