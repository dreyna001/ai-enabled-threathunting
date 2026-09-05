"""HTTP contract for the persisted threat-hunt vertical slice."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.services.workflow import Conflict, IntegrationUnavailable, NotFound, Validation, WorkflowService


router = APIRouter(prefix="/api", tags=["workflow"])
_service: WorkflowService | None = None


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictRequest):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class CreateHuntRequest(StrictRequest):
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field(min_length=1, max_length=4000)
    objective: str = Field(min_length=1, max_length=4000)
    threat_intelligence: str = Field(default="", max_length=50_000)
    synthetic_data: str = Field(default="", max_length=50_000)


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


def configure_workflow_service(service: WorkflowService) -> None:
    global _service
    _service = service


def workflow_service() -> WorkflowService:
    if _service is None:
        raise HTTPException(status_code=503, detail="workflow service is not configured")
    return _service


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


def current_user_id(
    authorization: str | None = Header(default=None),
    service: WorkflowService = Depends(workflow_service),
) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer authentication required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer authentication required")
    try:
        return service.authenticate(token)
    except Validation as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@router.post("/auth/login")
def login(request: LoginRequest, service: WorkflowService = Depends(workflow_service)) -> dict[str, Any]:
    try:
        return service.login(request.username, request.password)
    except Validation as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/hunts")
def list_hunts(user_id: str = Depends(current_user_id), service: WorkflowService = Depends(workflow_service)) -> list[dict[str, Any]]:
    return service.list_hunts(user_id)


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
