import uuid
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def log_action(
    db: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Create an audit log entry.

    Args:
        db: Database session
        org_id: Organization ID
        user_id: ID of the user who performed the action
        action: Action description (e.g., "created", "updated", "deleted")
        resource_type: Type of resource (e.g., "scan", "finding", "asset")
        resource_id: ID of the affected resource
        details: Additional details as a JSON-serializable dict
        request: FastAPI request object for extracting IP and user agent
    """
    ip_address: str | None = None
    user_agent: str | None = None

    if request:
        # Extract client IP (supports X-Forwarded-For for reverse proxies)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        elif request.client:
            ip_address = request.client.host

        user_agent = request.headers.get("user-agent")

    audit_entry = AuditLog(
        organization_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent[:512] if user_agent else None,
    )
    db.add(audit_entry)
    await db.flush()

    return audit_entry
