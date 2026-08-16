from datetime import datetime
from typing import Annotated, Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from auth_core.boundary.http.registration import request_id
from auth_core.boundary.http.session import access_claims
from auth_core.control.privacy import AuditQueryControl
from auth_core.entity.privacy import AuditRecord, AuditSearchFilter, PrivacyError
from auth_core.entity.session import SessionError
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.privacy_repository import (
    SqlAlchemyAuditRepository,
)

router = APIRouter(prefix="/api/v1", tags=["privacy and auditing"])
audit_control = AuditQueryControl(SqlAlchemyAuditRepository(session_factory))


class AuditRecordResponse(BaseModel):
    audit_id: UUID
    actor_user_id: UUID | None
    subject_user_id: UUID | None
    org_id: UUID | None
    event_type: str
    outcome: Literal["success", "failure", "denied"]
    correlation_id: UUID
    metadata: dict[str, Any]
    occurred_at: datetime


class AuditPageResponse(BaseModel):
    items: list[AuditRecordResponse]
    next_cursor: str | None


def problem(
    request: Request,
    error: PrivacyError | SessionError,
    correlation_id: UUID,
) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
            "title": "The privacy or audit action could not be completed",
            "status": error.status_code,
            "detail": error.message,
            "instance": request.url.path,
            "code": error.code.value,
            "request_id": str(correlation_id),
        },
    )


@router.get("/admin/audit-logs", response_model=AuditPageResponse)
async def search_audit_logs(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
    subject_user_id: UUID | None = None,
    event_type: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    outcome: Literal["success", "failure", "denied"] | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    cursor: Annotated[str | None, Query(min_length=8, max_length=256)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AuditPageResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        page = await audit_control.search(
            claims,
            AuditSearchFilter(
                subject_user_id,
                event_type,
                outcome,
                occurred_from,
                occurred_to,
            ),
            cursor,
            limit,
            correlation_id,
        )
    except (PrivacyError, SessionError) as error:
        return problem(request, error, correlation_id)
    return AuditPageResponse(
        items=[audit_model(record) for record in page.items],
        next_cursor=page.next_cursor,
    )


def audit_model(record: AuditRecord) -> AuditRecordResponse:
    return AuditRecordResponse(
        audit_id=record.audit_id,
        actor_user_id=record.actor_user_id,
        subject_user_id=record.subject_user_id,
        org_id=record.org_id,
        event_type=record.event_type,
        outcome=cast(Literal["success", "failure", "denied"], record.outcome),
        correlation_id=record.correlation_id,
        metadata=record.metadata,
        occurred_at=record.occurred_at,
    )
