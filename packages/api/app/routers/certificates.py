# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Certificate Intelligence API Router.
Deep certificate analysis and monitoring.
"""

import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.dependencies import get_current_org, require_role
from app.models.membership import Membership
from app.models.user import User
from app.routers.auth import limiter  # share the single Limiter instance
from app.utils.target_validator import (
    TargetValidationError,
    ValidationResult,
    validate_domain_pinned,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/certificates", tags=["certificates"])

# Certificate analysis only makes sense against a TLS endpoint. Restricting the
# port to known implicit-TLS service ports stops these endpoints from being used
# as a general internal port scanner (e.g. probing 22/3306/6379/RDP) — a
# defense-in-depth layer on top of the public-IP-only domain validation below.
ALLOWED_TLS_PORTS = frozenset(
    {443, 8443, 9443, 10443, 4443, 993, 995, 465, 636, 990, 5061}
)


class CertificateCheckRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=512)
    port: int = Field(default=443, ge=1, le=65535)


class CertificateBulkRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=50)
    port: int = Field(default=443, ge=1, le=65535)


def _require_tls_port(port: int) -> None:
    """Reject non-TLS ports before any outbound connection is attempted."""
    if port not in ALLOWED_TLS_PORTS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported port {port}: only TLS service ports may be analyzed.",
        )


async def _validate_cert_target(domain: str) -> ValidationResult:
    """SSRF guard for the certificate endpoints.

    Mirrors the asset-creation pin (assets.py): resolve the domain, reject
    private/reserved/blocked/malformed hosts BEFORE any outbound connection,
    and return the IP pinned at validation time so the analyzer connects to
    *that* IP — closing the DNS-rebinding TOCTOU window. The validation detail
    is logged but never echoed back (it is an internal-network oracle).
    """
    try:
        return await validate_domain_pinned(domain)
    except TargetValidationError:
        logger.warning("Certificate target rejected: %s", domain)
        raise HTTPException(status_code=422, detail="Invalid or disallowed target.")


@router.post("/check", dependencies=[Depends(require_role("admin", "auditor"))])
@limiter.limit("20/minute")
async def check_certificate(
    request: Request,
    payload: CertificateCheckRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Deep certificate analysis for a single domain."""
    from nis2scan.certificate import CertificateAnalyzer

    _require_tls_port(payload.port)
    validation = await _validate_cert_target(payload.domain)

    analyzer = CertificateAnalyzer(timeout=10)
    try:
        info = await analyzer.analyze(
            validation.target_value, payload.port, pinned_ip=validation.pinned_ip
        )
        return analyzer.to_dict(info)
    except Exception:
        # Generic message to the caller; full detail server-side only.
        logger.exception(
            "Certificate analysis failed for %s:%s",
            validation.target_value,
            payload.port,
        )
        raise HTTPException(status_code=422, detail="Certificate analysis failed.")


@router.post("/bulk-check", dependencies=[Depends(require_role("admin", "auditor"))])
@limiter.limit("5/minute")
async def bulk_check_certificates(
    request: Request,
    payload: CertificateBulkRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Analyze certificates for multiple domains at once."""
    import asyncio

    from nis2scan.certificate import CertificateAnalyzer

    _require_tls_port(payload.port)

    analyzer = CertificateAnalyzer(timeout=10)

    async def _check(domain: str):
        # Validate/pin every domain up front; an invalid one gets a generic
        # per-item error and is never connected to.
        try:
            validation = await validate_domain_pinned(domain)
        except TargetValidationError:
            logger.warning("Bulk certificate target rejected: %s", domain)
            return {"domain": domain, "error": "Invalid or disallowed target", "score": 0}
        try:
            info = await analyzer.analyze(
                validation.target_value, payload.port, pinned_ip=validation.pinned_ip
            )
            return analyzer.to_dict(info)
        except Exception:
            logger.exception(
                "Bulk certificate analysis failed for %s", validation.target_value
            )
            return {"domain": domain, "error": "Certificate analysis failed", "score": 0}

    tasks = [_check(d) for d in payload.domains]
    results = await asyncio.gather(*tasks)

    # Summary
    scores = [r.get("score", 0) for r in results]
    expiring = [
        r for r in results if r.get("validity", {}).get("expiry_risk", "OK") != "OK"
    ]

    return {
        "results": results,
        "summary": {
            "total": len(results),
            "average_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "expiring_soon": len(expiring),
            "lowest_score": min(scores) if scores else 0,
        },
    }


@router.get(
    "/ct-logs/{domain}", dependencies=[Depends(require_role("admin", "auditor"))]
)
@limiter.limit("30/minute")
async def get_ct_logs(
    request: Request,
    domain: str,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Query Certificate Transparency logs for a domain via crt.sh."""
    import aiohttp

    # crt.sh is a fixed external host (no SSRF surface — we never connect to
    # `domain` itself), but the user-supplied value is interpolated into the
    # query string, so URL-encode it.
    try:
        url = f"https://crt.sh/?q={quote(domain, safe='')}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    return {
                        "domain": domain,
                        "entries": [],
                        "error": "crt.sh unavailable",
                    }
                data = await resp.json(content_type=None)
                # Deduplicate and sort
                seen = set()
                unique = []
                for entry in data or []:
                    cert_id = entry.get("id")
                    if cert_id not in seen:
                        seen.add(cert_id)
                        unique.append(
                            {
                                "id": cert_id,
                                "issuer": entry.get("issuer_name", ""),
                                "common_name": entry.get("common_name", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                                "serial": entry.get("serial_number", ""),
                            }
                        )
                unique.sort(key=lambda x: x.get("not_before", ""), reverse=True)
                return {"domain": domain, "total": len(unique), "entries": unique[:50]}
    except Exception:
        logger.exception("CT-log lookup failed for %s", domain)
        return {"domain": domain, "entries": [], "error": "CT-log lookup failed"}
