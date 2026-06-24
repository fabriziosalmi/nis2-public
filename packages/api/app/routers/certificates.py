# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Certificate Intelligence API Router.
Deep certificate analysis and monitoring.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import get_current_org
from app.models.membership import Membership
from app.models.user import User

router = APIRouter(prefix="/certificates", tags=["certificates"])


class CertificateCheckRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=512)
    port: int = Field(default=443, ge=1, le=65535)


class CertificateBulkRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=50)
    port: int = Field(default=443, ge=1, le=65535)


@router.post("/check")
async def check_certificate(
    payload: CertificateCheckRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Deep certificate analysis for a single domain."""
    from nis2scan.certificate import CertificateAnalyzer

    analyzer = CertificateAnalyzer(timeout=10)
    try:
        info = await analyzer.analyze(payload.domain, payload.port)
        return analyzer.to_dict(info)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Certificate analysis failed: {e}")


@router.post("/bulk-check")
async def bulk_check_certificates(
    payload: CertificateBulkRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Analyze certificates for multiple domains at once."""
    import asyncio
    from nis2scan.certificate import CertificateAnalyzer

    analyzer = CertificateAnalyzer(timeout=10)
    results = []

    async def _check(domain: str):
        try:
            info = await analyzer.analyze(domain, payload.port)
            return analyzer.to_dict(info)
        except Exception as e:
            return {"domain": domain, "error": str(e), "score": 0}

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


@router.get("/ct-logs/{domain}")
async def get_ct_logs(
    domain: str,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Query Certificate Transparency logs for a domain via crt.sh."""
    import aiohttp

    try:
        url = f"https://crt.sh/?q={domain}&output=json"
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
    except Exception as e:
        return {"domain": domain, "entries": [], "error": str(e)}
