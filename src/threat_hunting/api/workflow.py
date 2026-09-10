"""HTTP contract for the persisted threat-hunt vertical slice."""

from __future__ import annotations
import ipaddress

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.auth.service import AccountService, CSRF_COOKIE, SESSION_COOKIE
from threat_hunting.services.uploads import UploadError, UploadService
from threat_hunting.services.workflow import Conflict, IntegrationUnavailable, NotFound, Validation, WorkflowService, users as service_users


router = APIRouter(prefix="/api", tags=["workflow"])


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictRequest):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def _login_client_key(request: Request) -> str:
    """Return a validated proxy-supplied or direct client address."""

    candidates = (request.headers.get("x-real-ip"), request.client.host if request.client else None)
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            return ipaddress.ip_address(candidate.strip()).compressed
        except ValueError:
            continue
    return "unknown"


class CreateHuntRequest(StrictRequest):
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field(min_length=1, max_length=4000)
    objective: str = Field(min_length=1, max_length=4000)
    threat_intelligence: str = Field(default="", max_length=50_000)
    synthetic_data: str = Field(default="", max_length=50_000)


class HuntSummary(BaseModel):
    hunt_id: UUID
    title: str
    hypothesis: str
    state: str
    created_at_utc: datetime
    updated_at_utc: datetime


class SavePlanRequest(StrictRequest):
    expected_version: int = Field(ge=1)
    plan: dict[str, Any]


class RevisePlanRequest(StrictRequest):
    instruction: str = Field(min_length=1, max_length=2000)


class ApprovalRequest(StrictRequest):
    analyst_note: str | None = Field(default=None, max_length=2000)


class RejectionRequest(StrictRequest):
    analyst_note: str = Field(min_length=1, max_length=2000)


class SaveReportRequest(StrictRequest):
    expected_version: int = Field(ge=1)
    content: dict[str, Any]


class FinalizeReportRequest(StrictRequest):
    expected_version: int = Field(ge=1)


def configure_workflow_service(application: FastAPI, service: WorkflowService) -> None:
    """Bind shared dependencies to this application, never module globals."""
    from pathlib import Path
    import os
    application.state.workflow_service = service
    application.state.auth_service = AccountService(service.engine)
    application.state.upload_service = UploadService(
        service.engine,
        Path(os.getenv("THREAT_HUNTING_UPLOAD_ROOT", "runtime/uploads")),
        limits=service.upload_limits,
    )


def workflow_service(request: Request) -> WorkflowService:
    service = getattr(request.app.state, "workflow_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="workflow service is not configured")
    return service


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, NotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, Conflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, Validation):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, IntegrationUnavailable):
        return HTTPException(status_code=503, detail=str(exc))
    return HTTPException(status_code=500, detail="workflow operation failed")


def auth_service(request: Request) -> AccountService:
    service = getattr(request.app.state, "auth_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="authentication service is not configured")
    return service


def current_user_id(
    request: Request,
    authorization: str | None = Header(default=None),
    session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    service: WorkflowService = Depends(workflow_service),
    auth: AccountService = Depends(auth_service),
) -> str:
    token = session_cookie
    bearer = False
    if service.local_demo and authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        bearer = True
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    try:
        if bearer:
            return service.authenticate(token)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                raise HTTPException(status_code=403, detail="CSRF validation failed")
        return auth.authenticate(token, csrf_token=csrf_cookie if request.method not in {"GET", "HEAD", "OPTIONS"} else None)
    except HTTPException:
        raise
    except (Validation, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED if not isinstance(exc, PermissionError) else 403, detail=str(exc)) from exc


@router.post("/auth/login")
def login(payload: LoginRequest, response: Response, http_request: Request, service: WorkflowService = Depends(workflow_service), auth: AccountService = Depends(auth_service)) -> dict[str, Any]:
    try:
        session, user = auth.login(payload.username, payload.password, client_key=_login_client_key(http_request))
    except PermissionError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except (Validation, ValueError) as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        raise _translate(exc) from exc
    secure = bool(getattr(service, "cookie_secure", not service.local_demo))
    max_age = max(1, int((session.expires_at - datetime.now(timezone.utc)).total_seconds()))
    response.set_cookie(SESSION_COOKIE, session.token, httponly=True, secure=secure, samesite="lax", max_age=max_age, path="/")
    response.set_cookie(CSRF_COOKIE, session.csrf_token, httponly=False, secure=secure, samesite="lax", max_age=max_age, path="/")
    result: dict[str, Any] = {"user": user, "csrf_token": session.csrf_token, "expires_at": session.expires_at.isoformat()}
    if service.local_demo:
        result.update({"access_token": session.token, "token_type": "bearer"})
    return result


@router.get("/auth/me")
def me(user_id: str = Depends(current_user_id), csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    with service.engine.connect() as connection:
        from sqlalchemy import select
        row = connection.execute(select(service_users).where(service_users.c.user_id == user_id)).mappings().first()
    if row is None:
        raise HTTPException(status_code=401, detail="authentication required")
    payload = {key: value for key, value in row.items() if key != "password_hash"}
    if csrf_cookie:
        payload["csrf_token"] = csrf_cookie
    return payload


@router.post("/auth/logout")
def logout(response: Response, user_id: str = Depends(current_user_id), session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE), service: WorkflowService = Depends(workflow_service), auth: AccountService = Depends(auth_service)) -> dict[str, str]:
    if session_cookie:
        auth.logout(session_cookie)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "logged_out"}


@router.get("/hunts", response_model=list[HuntSummary])
def list_hunts(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: UUID | None = Query(default=None),
    user_id: str = Depends(current_user_id),
    service: WorkflowService = Depends(workflow_service),
) -> list[dict[str, Any]]:
    try:
        return service.list_hunts(user_id, limit=limit, cursor=str(cursor) if cursor else None)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts", status_code=201)
def create_hunt(request: CreateHuntRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.create_hunt(
            user_id, title=request.title, hypothesis=request.hypothesis, objective=request.objective,
            threat_intelligence=request.threat_intelligence, synthetic_data=request.synthetic_data,
        )
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/hunts/{hunt_id}")
def get_hunt(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.get_hunt(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/cancel")
def cancel(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.cancel(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


def upload_service(request: Request) -> UploadService:
    service = getattr(request.app.state, "upload_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="upload service is not configured")
    return service


@router.get("/hunts/{hunt_id}/uploads")
def list_uploads(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service), uploads: UploadService = Depends(upload_service)) -> list[dict[str, Any]]:
    try:
        service.get_hunt(user_id, hunt_id)
        return uploads.list(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


async def _read_bounded_upload(request: Request, max_bytes: int) -> bytes:
    """Read a raw upload stream without trusting or requiring Content-Length."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError:
            declared_size = None
        if declared_size is not None and declared_size > max_bytes:
            raise UploadError("upload exceeds the per-file size limit")
    body = bytearray()
    async for chunk in request.stream():
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > max_bytes:
            raise UploadError("upload exceeds the per-file size limit")
    return bytes(body)


@router.post("/hunts/{hunt_id}/uploads", status_code=201)
async def create_upload(hunt_id: str, request: Request, filename: str | None = None, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service), uploads: UploadService = Depends(upload_service)) -> dict[str, Any]:
    try:
        await run_in_threadpool(service.get_hunt, user_id, hunt_id)
        supplied_name = filename or request.headers.get("X-Filename")
        if not supplied_name:
            raise UploadError("filename is required")
        body = await _read_bounded_upload(request, uploads.limits.per_file_bytes)
        return await run_in_threadpool(uploads.save, user_id, hunt_id, supplied_name, body, content_type=request.headers.get("content-type"))
    except Exception as exc:
        if isinstance(exc, UploadError):
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        raise _translate(exc) from exc


@router.get("/hunts/{hunt_id}/uploads/{upload_id}")
def download_upload(hunt_id: str, upload_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service), uploads: UploadService = Depends(upload_service)) -> Response:
    try:
        service.get_hunt(user_id, hunt_id)
        path, filename = uploads.path_for(user_id, hunt_id, upload_id)
        return Response(content=path.read_bytes(), media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{filename.replace(chr(34), "_")}"'})
    except Exception as exc:
        if isinstance(exc, UploadError):
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/discover")
def discover(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.discover(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.put("/hunts/{hunt_id}/plan")
def save_plan(hunt_id: str, request: SavePlanRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.save_plan(user_id, hunt_id, expected_version=request.expected_version, plan=request.plan)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/plan/revise")
def revise_plan(hunt_id: str, request: RevisePlanRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.revise_plan(user_id, hunt_id, request.instruction)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/plan/approve")
def approve_plan(hunt_id: str, request: ApprovalRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.approve(user_id, hunt_id, request.analyst_note)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/plan/reject")
def reject_plan(hunt_id: str, request: RejectionRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.reject(user_id, hunt_id, request.analyst_note)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/execute")
def execute(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.execute(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/hunts/{hunt_id}/job")
def job_status(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.job_status(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/hunts/{hunt_id}/results")
def results(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.results(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/hunts/{hunt_id}/report")
def report(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.report(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.put("/hunts/{hunt_id}/report")
def save_report(hunt_id: str, request: SaveReportRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.save_report(user_id, hunt_id, expected_version=request.expected_version, content=request.content)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/hunts/{hunt_id}/report/finalize")
def finalize_report(hunt_id: str, request: FinalizeReportRequest, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.finalize_report(user_id, hunt_id, expected_version=request.expected_version)
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/hunts/{hunt_id}/report/pdf")
def download_pdf(hunt_id: str, user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> Response:
    try:
        content = service.pdf(user_id, hunt_id)
    except Exception as exc:
        raise _translate(exc) from exc
    return Response(content=content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="hunt-{hunt_id}.pdf"'})


__all__ = ["configure_workflow_service", "router"]
