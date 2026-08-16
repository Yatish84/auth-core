from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from auth_core.boundary.http.registration import request_id as correlation_request_id
from auth_core.boundary.http.session import access_claims, session_control
from auth_core.config import get_settings
from auth_core.control.privacy import AuditQueryControl, GDPRControl
from auth_core.entity.privacy import (
    AuditRecord,
    AuditSearchFilter,
    PrivacyError,
    PrivacyRequestRecord,
)
from auth_core.entity.session import SessionError
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.privacy_repository import (
    SqlAlchemyAuditRepository,
    SqlAlchemyPrivacyRepository,
)
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

router = APIRouter(prefix="/api/v1", tags=["privacy and auditing"])
audit_control = AuditQueryControl(SqlAlchemyAuditRepository(session_factory))
settings = get_settings()
gdpr_control = GDPRControl(
    SqlAlchemyPrivacyRepository(session_factory),
    LocalAESGCMSecretCipher(settings.local_data_encryption_key),
    settings.privacy_idempotency_hmac_secret.encode(),
    session_control,
    timedelta(hours=settings.privacy_export_ttl_hours),
    timedelta(days=settings.privacy_backup_purge_days),
)


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


class PrivacyRequestResponse(BaseModel):
    request_id: UUID
    request_type: Literal["export", "erasure"]
    state: Literal["requested", "processing", "completed", "failed", "cancelled"]
    requested_at: datetime
    completed_at: datetime | None
    artifact_expires_at: datetime | None
    failure_code: str | None
    backup_purge_due_at: datetime | None


class ErasureRequest(BaseModel):
    confirmation: Literal["ERASE_MY_ACCOUNT"]


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
    correlation_id = correlation_request_id(x_request_id)
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


@router.post("/privacy/exports", response_model=PrivacyRequestResponse, status_code=202)
async def request_privacy_export(
    request: Request,
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=8, max_length=128)
    ],
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> PrivacyRequestResponse | JSONResponse:
    correlation_id = correlation_request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        record = await gdpr_control.request_export(
            claims, idempotency_key, correlation_id
        )
    except (PrivacyError, SessionError) as error:
        return problem(request, error, correlation_id)
    return privacy_request_model(record)


@router.get(
    "/privacy/requests/{request_id}", response_model=PrivacyRequestResponse
)
async def get_privacy_request(
    request_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> PrivacyRequestResponse | JSONResponse:
    correlation_id = correlation_request_id(None)
    try:
        claims = await access_claims(authorization)
        record = await gdpr_control.get_request(claims, request_id)
    except (PrivacyError, SessionError) as error:
        return problem(request, error, correlation_id)
    return privacy_request_model(record)


@router.get("/privacy/exports/{request_id}/download")
async def download_privacy_export(
    request_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    correlation_id = correlation_request_id(None)
    try:
        claims = await access_claims(authorization)
        download = await gdpr_control.download_export(claims, request_id)
    except (PrivacyError, SessionError) as error:
        return problem(request, error, correlation_id)
    return Response(
        content=download.content,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="vittavaan-data-export-{download.request_id}.json"'
            ),
            "X-Artifact-Expires-At": download.expires_at.isoformat(),
        },
    )


def privacy_request_model(record: PrivacyRequestRecord) -> PrivacyRequestResponse:
    return PrivacyRequestResponse(
        request_id=record.request_id,
        request_type=cast(Literal["export", "erasure"], record.request_type),
        state=cast(
            Literal["requested", "processing", "completed", "failed", "cancelled"],
            record.state,
        ),
        requested_at=record.requested_at,
        completed_at=record.completed_at,
        artifact_expires_at=record.artifact_expires_at,
        failure_code=record.failure_code,
        backup_purge_due_at=record.backup_purge_due_at,
    )


@router.post("/privacy/erasures", response_model=PrivacyRequestResponse, status_code=202)
async def request_account_erasure(
    payload: ErasureRequest,
    request: Request,
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=8, max_length=128)
    ],
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> PrivacyRequestResponse | JSONResponse:
    del payload
    correlation_id = correlation_request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        record = await gdpr_control.request_erasure(
            claims, idempotency_key, correlation_id
        )
    except (PrivacyError, SessionError) as error:
        return problem(request, error, correlation_id)
    return privacy_request_model(record)
